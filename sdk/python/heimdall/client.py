"""HTTP client for the Heimdall integration API (/v1). Standard library only. Every failure is a HeimdallError."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ._canon import to_wire


class HeimdallError(Exception):
    def __init__(self, code: str, message: str, status: int = 0, body: Any = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # never follow redirects with an API key attached
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class HeimdallClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 5.0, max_retries: int = 2, demo: bool = False, adapter: Optional[dict] = None):
        if not base_url or not api_key:
            raise ValueError("base_url and api_key are required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.demo = demo
        self.adapter = adapter or {"name": "heimdall-sdk-python", "version": __import__("heimdall").__version__}

    def _call(self, method: str, path: str, body: Any = None, retry: bool = False) -> tuple[int, Any]:
        attempts = self.max_retries + 1 if retry else 1
        last: Optional[HeimdallError] = None
        for i in range(attempts):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(self.base_url + path, data=data, method=method)
            req.add_header("authorization", f"Bearer {self.api_key}")
            req.add_header("accept", "application/json")
            if data is not None:
                req.add_header("content-type", "application/json")
            try:
                with _opener.open(req, timeout=self.timeout) as r:
                    status, raw = r.status, r.read()
            except urllib.error.HTTPError as e:
                status, raw = e.code, e.read()
            except Exception as e:  # network error, timeout, refused redirect
                last = HeimdallError("UNAVAILABLE", f"Could not reach the authorization service: {e}")
                if i < attempts - 1:
                    time.sleep(0.2 * 2**i)
                    continue
                raise last
            try:
                parsed = json.loads(raw.decode() or "null")
            except ValueError:
                raise HeimdallError("MALFORMED_RESPONSE", "The authorization service returned a non-JSON response", status)
            if status >= 500 and i < attempts - 1:
                last = HeimdallError("SERVER_ERROR", f"Server error {status}", status)
                time.sleep(0.2 * 2**i)
                continue
            return status, parsed
        raise last or HeimdallError("UNAVAILABLE", "Authorization service unavailable")

    @staticmethod
    def _fail(status: int, body: Any, default: str) -> HeimdallError:
        err = (body or {}).get("error", {}) if isinstance(body, dict) else {}
        return HeimdallError(err.get("code", default), err.get("message", default), status, body)

    def whoami(self) -> dict:
        s, b = self._call("GET", "/v1/whoami", retry=True)
        if s != 200:
            raise self._fail(s, b, "WHOAMI_FAILED")
        return b

    def authorize(self, request_id: str, action: dict) -> dict:
        payload = {"request_id": request_id, **to_wire(action), "adapter": self.adapter}
        if self.demo:
            payload["demo"] = True
        s, b = self._call("POST", "/v1/authorize", payload, retry=True)
        if s != 200:
            raise self._fail(s, b, "AUTHORIZATION_FAILED")
        return _validate(b, s)

    def get_action(self, request_id: str) -> dict:
        s, b = self._call("GET", f"/v1/actions/{urllib.parse.quote(request_id, safe='')}", retry=True)
        if s != 200:
            raise self._fail(s, b, "LOOKUP_FAILED")
        return _validate(b, s)

    def claim(self, request_id: str, digest: str) -> dict:
        # Never retried: a claim is the one-time execution permit. Anything but an explicit yes is a no.
        s, b = self._call("POST", f"/v1/actions/{urllib.parse.quote(request_id, safe='')}/claim", {"action_digest": digest})
        if s == 200 and isinstance(b, dict) and b.get("permitted") is True:
            return {"permitted": True}
        err = (b or {}).get("error", {}) if isinstance(b, dict) else {}
        return {"permitted": False, "code": err.get("code", "CLAIM_REFUSED"), "message": err.get("message", "Execution was not permitted")}

    def report_outcome(self, request_id: str, outcome: dict) -> None:
        s, b = self._call("POST", f"/v1/actions/{urllib.parse.quote(request_id, safe='')}/outcome", outcome, retry=True)
        if s != 200:
            raise self._fail(s, b, "OUTCOME_FAILED")

    def get_policy_bundle(self) -> dict:
        s, b = self._call("GET", "/v1/policy-bundle", retry=True)
        if s != 200:
            raise self._fail(s, b, "BUNDLE_FAILED")
        return b

    def get_policy_state(self) -> dict:
        s, b = self._call("GET", "/v1/policy-state")
        if s != 200:
            raise self._fail(s, b, "STATE_FAILED")
        return b

    def get_signing_key(self) -> dict:
        s, b = self._call("GET", "/v1/signing-key", retry=True)
        if s != 200:
            raise self._fail(s, b, "KEY_FAILED")
        return b

    def sync(self, records: list) -> dict:
        s, b = self._call("POST", "/v1/offline-sync", {"records": records}, retry=True)
        if s != 200:
            raise self._fail(s, b, "SYNC_FAILED")
        return b


def _validate(b: Any, status: int) -> dict:
    import re

    ok = (
        isinstance(b, dict)
        and b.get("decision") in ("allow", "deny", "require_approval")
        and isinstance(b.get("action_digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", b["action_digest"]) is not None
        and isinstance(b.get("request_id"), str)
        and isinstance(b.get("reason_code"), str)
    )
    if not ok:
        raise HeimdallError("MALFORMED_RESPONSE", "The authorization service returned an unexpected response", status)
    return b
