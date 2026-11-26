"""
Fast path for Python agents: allow/deny decided in-process from the signed policy, audit sent in the background.
Same design and guarantees as src/executor/fast-path.ts (see docs/FAST-PATH.md):
  - the bundle is checked once (Ed25519 signature with the pinned service key, agent binding, expiry, no rollback);
  - require_approval actions and anything the local engine cannot decide go to the service;
  - a background thread sends decisions in batches; the service re-evaluates each and alerts on any disagreement;
  - every 2 s a tiny policy-state check picks up policy changes; a 401/403 drops the bundle at once;
  - if the audit queue is full, actions are refused rather than run unrecorded.
Needs the `cryptography` package for signature checks (pip install "kenuxa-heimdall[fast]").
"""
from __future__ import annotations

import base64
import collections
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from ._canon import canonical_json
from .client import HeimdallClient, HeimdallError
from .policy import NEEDS_SERVER, evaluate

_AUTH_CODES = {"CREDENTIAL_REVOKED", "CREDENTIAL_INVALID", "AGENT_REVOKED", "UNAUTHORIZED", "FORBIDDEN"}


def _is_auth_refusal(e: BaseException) -> bool:
    return isinstance(e, HeimdallError) and (e.status in (401, 403) or e.code in _AUTH_CODES)


def _ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _verify_ed25519(public_key_pem: str, data: bytes, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


class FastPath:
    def __init__(
        self,
        client: HeimdallClient,
        *,
        public_key_pem: Optional[str] = None,
        agent_id: Optional[str] = None,
        refresh_s: float = 30.0,
        check_s: float = 2.0,
        flush_s: float = 0.25,
        max_queue: int = 50_000,
        max_batch: int = 500,
        on_error: Optional[Callable[[str, BaseException], None]] = None,
        now: Callable[[], float] = time.time,
    ):
        self.client = client
        self._key = public_key_pem
        self._agent = agent_id
        self.refresh_s, self.check_s, self.flush_s = refresh_s, check_s, flush_s
        self.max_queue, self.max_batch = max_queue, min(max_batch, 500)
        self._on_error = on_error
        self._now = now
        self._lock = threading.Lock()
        self._bundle: Optional[dict] = None
        self._highest: Optional[tuple] = None
        self._state = "starting"
        self._queue: collections.deque = collections.deque()
        self._permits: "collections.OrderedDict[str, None]" = collections.OrderedDict()
        self._allow_times: collections.deque = collections.deque()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._flush_lock = threading.Lock()
        self.stats_ = {"decisions": 0, "sent": 0, "mismatches": 0, "refused_queue_full": 0}

    # ---------------- lifecycle

    def start(self) -> str:
        """Loads the first bundle and starts background threads (daemon threads: they never keep the process alive)."""
        self.refresh()
        for name, every, fn in (("refresh", self.refresh_s, self.refresh), ("check", self.check_s, self.check_state), ("flush", self.flush_s, self.flush)):
            t = threading.Thread(target=self._loop, args=(every, fn), name=f"heimdall-{name}", daemon=True)
            t.start()
            self._threads.append(t)
        return self.state

    def stop(self) -> None:
        """Stops the threads and sends everything still queued. Call it on shutdown."""
        self._stop.set()
        self.flush()
        self._state = "stopped"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def _loop(self, every: float, fn: Callable[[], Any]) -> None:
        while not self._stop.wait(every):
            try:
                fn()
            except Exception as e:  # pragma: no cover - background safety net
                self._err("background", e)

    def _err(self, where: str, e: BaseException) -> None:
        if self._on_error:
            try:
                self._on_error(where, e)
            except Exception:
                pass

    # ---------------- bundle

    def check(self, signed: dict) -> tuple[bool, str]:
        b = signed.get("bundle") if isinstance(signed, dict) else None
        sig = signed.get("signature") if isinstance(signed, dict) else None
        if not self._key:
            return False, "NO_PINNED_KEY"
        if not isinstance(b, dict) or not isinstance(sig, str) or b.get("v") != 1:
            return False, "BAD_FORMAT"
        if not _verify_ed25519(self._key, canonical_json(b).encode("utf-8"), sig):
            return False, "BAD_SIGNATURE"
        if self._agent and b.get("agent_id") != self._agent:
            return False, "WRONG_BINDING"
        if self._now() >= _ts(b["expires_at"]):
            return False, "EXPIRED"
        h = self._highest
        if h and h[0] == b.get("policy_id"):
            v = b.get("policy_version") or 0
            if (h[1] or 0) > v or (h[1] == b.get("policy_version") and h[2] > _ts(b["issued_at"])):
                return False, "ROLLBACK"
        return True, "OK"

    def accept(self, signed: dict) -> tuple[bool, str]:
        ok, code = self.check(signed)
        if not ok:
            return ok, code
        b = signed["bundle"]
        with self._lock:
            self._bundle = b
            self._agent = self._agent or b.get("agent_id")
            self._highest = (b.get("policy_id"), b.get("policy_version"), _ts(b["issued_at"]))
            self._state = "ready" if b.get("document") else "no_policy_bundle"
        return True, "OK"

    def refresh(self) -> str:
        if self._state == "stopped":
            return self._state
        try:
            if not self._key:
                self._key = self.client.get_signing_key()["public_key_pem"]
            ok, code = self.accept(self.client.get_policy_bundle())
            if not ok:
                self._err("refresh", HeimdallError(code, f"Policy bundle refused: {code}"))
        except Exception as e:
            if _is_auth_refusal(e):
                self.revoke()
            self._err("refresh", e)
        return self.state

    def check_state(self) -> str:
        if self._state == "stopped":
            return self._state
        try:
            cur = self.client.get_policy_state()
            b = self._bundle
            if not b or cur.get("policy_id") != b.get("policy_id") or cur.get("policy_version") != b.get("policy_version") or cur.get("enforcement_mode") != b.get("enforcement_mode"):
                self.refresh()
        except Exception as e:
            if _is_auth_refusal(e):
                self.revoke()
        return self.state

    def revoke(self) -> None:
        with self._lock:
            self._bundle = None
            self._state = "revoked"

    @property
    def state(self) -> str:
        b = self._bundle
        if self._state == "ready" and b and self._now() >= _ts(b["expires_at"]):
            self._state = "expired"
        return self._state

    # ---------------- hot path (no I/O)

    def decide(self, action: dict) -> dict:
        """{'kind': 'decided'|'needs_approval'|'not_ready', ...}. Synchronous, no network, no disk."""
        b = self._bundle
        if self.state != "ready" or not b or not b.get("document"):
            return {"kind": "not_ready", "reason": self.state}
        doc = b["document"]
        used = self._allowed_in_window(doc["budget"]["window_seconds"]) if doc.get("budget") else 0
        d = evaluate(doc, action, used, False)
        if d is NEEDS_SERVER:
            return {"kind": "not_ready", "reason": "needs_server"}
        self.stats_["decisions"] += 1
        if d["decision"] == "require_approval":
            return {"kind": "needs_approval", "decision": d}
        policy_decision = d["decision"]
        if b.get("enforcement_mode") == "monitor" and policy_decision != "allow":
            d = {**d, "decision": "allow", "reason_code": "MONITOR_ONLY", "explanation": f"Monitor mode (advisory): {d['explanation']}"}
        return {"kind": "decided", "decision": d, "policy_decision": policy_decision, "bundle": b}

    def note_allowed(self) -> None:
        self._allow_times.append(self._now())

    def _allowed_in_window(self, window_s: float) -> int:
        cutoff = self._now() - window_s
        while self._allow_times and self._allow_times[0] < cutoff:
            self._allow_times.popleft()
        return len(self._allow_times)

    def used(self, request_id: str) -> bool:
        return request_id in self._permits

    def permit(self, request_id: str) -> bool:
        with self._lock:
            if request_id in self._permits:
                return False
            if len(self._permits) >= 200_000:
                self._permits.popitem(last=False)
            self._permits[request_id] = None
            return True

    def has_room(self) -> bool:
        return len(self._queue) < self.max_queue

    def note_queue_full(self) -> None:
        self.stats_["refused_queue_full"] += 1

    def record(self, rec: dict) -> bool:
        if len(self._queue) >= self.max_queue:
            self.stats_["refused_queue_full"] += 1
            return False
        self._queue.append({**rec, "source": "local_fast"})
        return True

    # ---------------- background audit

    def flush(self) -> None:
        if not self._flush_lock.acquire(blocking=False):
            return
        try:
            while self._queue:
                batch, size = [], 0
                while self._queue and len(batch) < self.max_batch:
                    n = len(canonical_json(self._queue[0]))
                    if batch and size + n > 3 * 1024 * 1024:
                        break
                    batch.append(self._queue.popleft())
                    size += n
                try:
                    res = self.client.sync(batch)
                    self.stats_["sent"] += len(batch)
                    self.stats_["mismatches"] += sum(1 for r in res.get("results", []) if r.get("status") == "mismatch")
                except Exception as e:
                    if _is_auth_refusal(e):
                        self.revoke()
                    room = max(0, self.max_queue - len(self._queue))
                    self._queue.extendleft(reversed(batch[:room]))
                    self._err("flush", e)
                    return
        finally:
            self._flush_lock.release()

    def stats(self) -> dict:
        b = self._bundle
        return {"state": self.state, "policy_version": b.get("policy_version") if b else None, "queued": len(self._queue), **self.stats_}
