"""
ProtectedExecutor: the only way an agent's tool should run. Authorize, then execute exactly the authorized action.

    executor = ProtectedExecutor(client, fast_path=fast)            # fast_path optional
    r = executor.run({"tool": "documents", "operation": "read", "resource": "docs/a.txt"}, handler=read_file)
    r.executed, r.status, r.reason_code, r.result

Online path (no fast path, an approval, or no valid bundle): authorize, wait for a person if required, one-time claim bound
to the action digest, run, report the outcome. Every failure to reach the service fails closed: the handler does not run.
"""
from __future__ import annotations

import asyncio
import copy
import inspect
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Union

from ._canon import action_digest, to_wire
from .client import HeimdallClient, HeimdallError
from .fastpath import FastPath

Handler = Callable[[dict], Union[Any, Awaitable[Any]]]
OPERATIONS = ("read", "create", "update", "delete", "external_transfer", "command_execution")


class ExecutorRefusal(Exception):
    """Raise from a verify() hook (or a handler) to refuse: the executor reports it as refused, never as run."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class RunResult:
    status: str  # executed | denied | pending_approval | not_authorized | execution_failed
    request_id: str
    executed: bool = False
    result: Any = None
    reason_code: Optional[str] = None
    explanation: Optional[str] = None
    approval_id: Optional[str] = None
    local: bool = False
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def message(self) -> str:
        """A short sentence an LLM can act on."""
        if self.status == "executed":
            return "Executed."
        if self.status == "pending_approval":
            return f"Not run yet: this action needs a person's approval in Heimdall (request {self.request_id}). Ask the user to approve it, then retry."
        if self.status == "execution_failed":
            return f"The tool failed: {self.error}"
        return f"Blocked by Heimdall ({self.reason_code}): {self.explanation or self.error or 'not permitted'}"


class ProtectedExecutor:
    def __init__(
        self,
        client: HeimdallClient,
        tools: Optional[dict[str, Handler]] = None,
        *,
        fast_path: Optional[FastPath] = None,
        verify: Optional[Callable[[dict], None]] = None,
        execution_timeout_s: Optional[float] = None,
    ):
        self.client = client
        self.tools = tools or {}
        self.fast_path = fast_path
        self.verify = verify
        self.execution_timeout_s = execution_timeout_s

    # ---------------- public API

    def run(self, action: dict, handler: Optional[Handler] = None, *, request_id: Optional[str] = None, wait_for_approval_s: float = 0, poll_s: float = 1.0) -> RunResult:
        """Synchronous. A coroutine handler is run to completion (use arun() inside an event loop)."""
        prep = self._prepare(action, handler, request_id)
        if isinstance(prep, RunResult):
            return prep
        gate = self._gate(prep, wait_for_approval_s, poll_s)
        if isinstance(gate, RunResult):
            return gate
        try:
            out = self._call_handler(prep)
            if inspect.isawaitable(out):
                out = asyncio.run(_await(out))
        except BaseException as e:  # noqa: BLE001 - reported, then re-raised for KeyboardInterrupt etc.
            return self._finish_failed(prep, gate, e)
        return self._finish_ok(prep, gate, out)

    async def arun(self, action: dict, handler: Optional[Handler] = None, *, request_id: Optional[str] = None, wait_for_approval_s: float = 0, poll_s: float = 1.0) -> RunResult:
        """Async. Network calls run in a worker thread; on the fast path there are none before the handler."""
        prep = self._prepare(action, handler, request_id)
        if isinstance(prep, RunResult):
            return prep
        local = self._try_fast(prep)
        gate = local if local is not None else await asyncio.to_thread(self._gate_online, prep, wait_for_approval_s, poll_s)
        if isinstance(gate, RunResult):
            return gate
        try:
            out = self._call_handler(prep)
            if inspect.isawaitable(out):
                out = await out
        except BaseException as e:  # noqa: BLE001
            return await asyncio.to_thread(self._finish_failed, prep, gate, e)
        if gate.get("local"):
            return self._finish_ok(prep, gate, out)
        return await asyncio.to_thread(self._finish_ok, prep, gate, out)

    # ---------------- internals

    def _prepare(self, action: dict, handler: Optional[Handler], request_id: Optional[str]):
        rid = request_id or f"req_{uuid.uuid4()}"
        h = handler or self.tools.get(action.get("tool", ""))
        if h is None:
            return RunResult("not_authorized", rid, reason_code="NO_HANDLER", explanation=f"No executor is registered for tool '{action.get('tool')}'")
        if action.get("operation") not in OPERATIONS:
            return RunResult("not_authorized", rid, reason_code="INVALID_ACTION", explanation=f"operation must be one of {', '.join(OPERATIONS)}")
        snap = {k: v for k, v in to_wire(action).items() if k in ("tool", "operation", "resource", "destination", "data_classification", "args") and v is not None}
        return {"rid": rid, "snap": snap, "digest": action_digest(snap), "handler": h}

    def _try_fast(self, prep: dict):
        """A local decision, or None when the online path must decide (approval, no bundle, unusual destination)."""
        fp = self.fast_path
        if not fp:
            return None
        fast = fp.decide(prep["snap"])
        if fast["kind"] != "decided":
            return None
        rid, snap, d = prep["rid"], prep["snap"], fast["decision"]
        base = {
            "request_id": rid, "action": snap, "action_digest": prep["digest"], "policy_version": fast["bundle"].get("policy_version"),
            "decided_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "decision": fast["policy_decision"], "reason_code": d["reason_code"],
        }
        if not fp.has_room():
            fp.note_queue_full()
            return RunResult("not_authorized", rid, reason_code="AUDIT_QUEUE_FULL", explanation="The audit queue is full (the service has been unreachable for a while). The action was not run so that nothing runs unrecorded.")
        if fp.used(rid):
            return RunResult("denied", rid, reason_code="ALREADY_USED", explanation="This request id was already used; each permit executes at most once.", local=True)
        if d["decision"] != "allow":
            fp.record({**base, "outcome": {"status": "refused", "error_code": d["reason_code"]}})
            return RunResult("denied", rid, reason_code=d["reason_code"], explanation=d["explanation"], local=True)
        refused = self._run_verify(snap)
        if refused:
            fp.record({**base, "outcome": {"status": "refused", "error_code": refused[0]}})
            return RunResult("denied", rid, reason_code=refused[0], explanation=refused[1], local=True)
        if not fp.permit(rid):
            return RunResult("denied", rid, reason_code="ALREADY_USED", explanation="This request id was already used; each permit executes at most once.", local=True)
        if fast["policy_decision"] == "allow":
            fp.note_allowed()
        return {"local": True, "base": base}

    def _gate(self, prep: dict, wait_s: float, poll_s: float):
        local = self._try_fast(prep)
        return local if local is not None else self._gate_online(prep, wait_s, poll_s)

    def _gate_online(self, prep: dict, wait_s: float, poll_s: float):
        rid, snap, digest = prep["rid"], prep["snap"], prep["digest"]
        try:
            view = self.client.authorize(rid, snap)
        except HeimdallError as e:
            return RunResult("not_authorized", rid, reason_code=e.code, explanation=str(e))
        if view["action_digest"] != digest:
            return RunResult("not_authorized", rid, reason_code="DIGEST_MISMATCH", explanation="The service bound a different action than the one submitted")
        deadline = time.monotonic() + wait_s
        while view["decision"] == "require_approval" and (view.get("approval") or {}).get("status") == "pending":
            if time.monotonic() >= deadline:
                return RunResult("pending_approval", rid, reason_code="APPROVAL_REQUIRED", explanation=view.get("explanation"), approval_id=view["approval"]["id"])
            time.sleep(poll_s)
            try:
                view = self.client.get_action(rid)
            except HeimdallError as e:
                return RunResult("not_authorized", rid, reason_code=e.code, explanation=str(e))
        approved = view["decision"] == "require_approval" and (view.get("approval") or {}).get("status") == "approved"
        if view["decision"] == "deny" or (view["decision"] == "require_approval" and not approved):
            reason = view["reason_code"] if view["decision"] == "deny" else f"APPROVAL_{((view.get('approval') or {}).get('status') or 'unavailable').upper()}"
            self._try_report(rid, {"status": "refused", "error_code": reason})
            return RunResult("denied", rid, reason_code=reason, explanation=view.get("explanation"))
        refused = self._run_verify(snap)
        if refused:
            self._try_report(rid, {"status": "refused", "error_code": refused[0]})
            return RunResult("denied", rid, reason_code=refused[0], explanation=refused[1])
        try:
            claim = self.client.claim(rid, digest)
        except HeimdallError as e:
            return RunResult("not_authorized", rid, reason_code=e.code, explanation=str(e))
        if not claim["permitted"]:
            self._try_report(rid, {"status": "refused", "error_code": claim.get("code")})
            return RunResult("denied", rid, reason_code=claim.get("code") or "CLAIM_REFUSED", explanation=claim.get("message"))
        return {"local": False}

    def _run_verify(self, snap: dict):
        if not self.verify:
            return None
        try:
            self.verify(copy.deepcopy(snap))
        except ExecutorRefusal as e:
            return (f"EXECUTOR_{e.code}", str(e))
        except Exception as e:  # noqa: BLE001
            return ("EXECUTOR_VERIFY_FAILED", str(e))
        return None

    def _call_handler(self, prep: dict):
        # The handler receives a private copy: mutating it cannot change what was authorized or recorded.
        out = prep["handler"](copy.deepcopy(prep["snap"]))
        if self.execution_timeout_s and inspect.isawaitable(out):
            return asyncio.wait_for(_await(out), self.execution_timeout_s)
        return out

    def _finish_ok(self, prep: dict, gate: dict, out: Any) -> RunResult:
        rid = prep["rid"]
        if gate.get("local"):
            self.fast_path.record({**gate["base"], "outcome": {"status": "succeeded"}})
            return RunResult("executed", rid, executed=True, result=out, local=True)
        reported = self._try_report(rid, {"status": "succeeded"})
        return RunResult("executed", rid, executed=True, result=out, extra={"outcome_reported": reported})

    def _finish_failed(self, prep: dict, gate: dict, e: BaseException) -> RunResult:
        rid = prep["rid"]
        code = f"EXECUTOR_REFUSED_{e.code}" if isinstance(e, ExecutorRefusal) else "EXECUTION_TIMEOUT" if isinstance(e, (asyncio.TimeoutError, TimeoutError)) else "HANDLER_ERROR"
        if gate.get("local"):
            self.fast_path.record({**gate["base"], "outcome": {"status": "failed", "error_code": code}})
        else:
            self._try_report(rid, {"status": "failed", "error_code": code})
        if not isinstance(e, Exception):
            raise e
        return RunResult("execution_failed", rid, executed=True, error=str(e), reason_code=code, local=bool(gate.get("local")))

    def _try_report(self, rid: str, outcome: dict) -> bool:
        try:
            self.client.report_outcome(rid, outcome)
            return True
        except HeimdallError:
            return False


async def _await(x):
    return await x
