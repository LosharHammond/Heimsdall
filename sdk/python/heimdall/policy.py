"""
The Heimdall policy engine, ported from src/shared/policy.ts. Same inputs, same decision, reason code and matched rule.
tests/test_policy_parity.py runs both engines over a few thousand generated cases and requires them to agree.

One deliberate difference: destinations. The server parses them with the WHATWG URL parser, which has many corner cases
(numeric IPv4 forms, punycode, backslashes...). Rather than imitate it, this module only decides destinations whose host is a
plain DNS name; for anything else evaluate() returns NEEDS_SERVER and the fast path sends the action to the service instead.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Any, Optional

LEVEL_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class _NeedsServer:
    def __repr__(self) -> str:  # pragma: no cover
        return "NEEDS_SERVER"


NEEDS_SERVER = _NeedsServer()

_CTRL = re.compile(r"[\u0000-\u001f]")
_ENCODED = re.compile(r"%2e|%2f|%5c|%00|%25", re.I)
_BAD_CHARS = re.compile(r'[<>"|?*]')
_WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)", re.I)
_SHORT_NAME = re.compile(r"~[0-9]")


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def normalize_resource(raw: str) -> Optional[str]:
    if not isinstance(raw, str) or _CTRL.search(raw) or _ENCODED.search(raw):
        return None
    if unicodedata.normalize("NFKC", raw) != raw:
        return None
    if _BAD_CHARS.search(raw):
        return None
    v = re.sub(r"/{2,}", "/", raw.replace("\\", "/"))
    while v.startswith("./"):
        v = v[2:]
    if not v or v.startswith("/"):
        return None
    for seg in v.split("/"):
        if seg in ("..", "."):
            return None
        if ":" in seg or seg.endswith((".", " ")) or _WIN_RESERVED.search(seg) or _SHORT_NAME.search(seg) or _utf16_len(seg) > 255:
            return None
    return v


_SIMPLE_URL = re.compile(r"^(?:(https?)://)?([a-z0-9.-]+)(?::([0-9]{1,5}))?(?:[/?#][\x21-\x5b\x5d-\x7e]*)?$", re.I)
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.I)


def normalize_destination(raw: str):
    """(host) for a plain DNS name, None for an invalid destination, NEEDS_SERVER when only the server's parser can say."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or re.search(r"[\u0000-\u001f\s]", s):
        return None
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", s, re.I)
    if m and m.group(1).lower() not in ("http", "https"):
        return None
    m = _SIMPLE_URL.match(s)
    if not m:
        return NEEDS_SERVER
    host = m.group(2).lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return NEEDS_SERVER
    if m.group(3) and int(m.group(3)) > 65535:
        return NEEDS_SERVER
    labels = [l for l in host.split(".")]
    if any(l == "" for l in labels) or _NUMERIC_LABEL.match(labels[-1]) or any(l.startswith("xn--") for l in labels):
        return NEEDS_SERVER
    return host


@lru_cache(maxsize=4096)
def _glob(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 1
            else:
                out.append("[^/]*")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))


def resource_matches(pattern: str, resource: str) -> bool:
    return _glob(pattern).fullmatch(resource) is not None


def domain_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    return host == pattern


def effective_classification(policy: dict, resource: str, declared: Optional[str]) -> dict:
    cls = policy.get("classifications") or []
    if cls:
        best = None
        for c in cls:
            if any(resource_matches(r, resource) for r in c["resources"]) and (best is None or LEVEL_RANK[c["level"]] > LEVEL_RANK[best]):
                best = c["level"]
        if best is None:
            return {"level": "unclassified", "source": "policy"}
        if declared and LEVEL_RANK[declared] > LEVEL_RANK[best]:
            return {"level": declared, "source": "policy_raised_by_agent"}
        return {"level": best, "source": "policy"}
    return {"level": declared, "source": "declared"} if declared else {"level": "unclassified", "source": "none"}


def _rule_matches(rule: dict, p: dict, ignore_destinations: bool = False) -> bool:
    m = rule["match"]
    if m.get("tools") and not any(t == "*" or t == p["tool"] for t in m["tools"]):
        return False
    if m.get("operations") and p["operation"] not in m["operations"]:
        return False
    if m.get("resources") and not any(resource_matches(r, p["resource"]) for r in m["resources"]):
        return False
    if m.get("destination_domains") and not ignore_destinations:
        if not p["host"]:
            return False
        if not any(domain_matches(d, p["host"]) for d in m["destination_domains"]):
            return False
    if m.get("data_classifications"):
        c = p["cls"]
        if c == "unclassified":
            if rule["effect"] == "allow":
                return False
        elif c not in m["data_classifications"]:
            return False
    return True


def _deny(code: str, explanation: str) -> dict:
    return {"decision": "deny", "reason_code": code, "explanation": explanation, "matched_rule_id": None}


def evaluate(policy: dict, action: dict, allowed_in_window: int = 0, has_valid_approval: bool = False):
    """Same precedence as the server: explicit deny, approval, allow, default deny; the budget can turn an allow into a deny."""
    raw_resource = action.get("resource", "")
    norm = normalize_resource(raw_resource)
    cls = effective_classification(policy, norm if norm is not None else raw_resource, action.get("data_classification"))
    inner = _evaluate_inner(policy, action, allowed_in_window, has_valid_approval, cls, norm)
    if inner is NEEDS_SERVER:
        return NEEDS_SERVER
    inner["classification"] = cls
    return inner


def _evaluate_inner(policy, action, allowed_in_window, has_valid_approval, cls, norm):
    if norm is None:
        return _deny("INVALID_RESOURCE", "The resource path is not a valid namespace path (absolute paths, '..' and encoded separators are refused).")
    host = None
    if action.get("destination"):
        d = normalize_destination(action["destination"])
        if d is NEEDS_SERVER:
            return NEEDS_SERVER
        if d is None:
            return _deny("INVALID_DESTINATION", "The destination is not a valid http(s) host (credentials in URLs and other schemes are refused).")
        host = d
    elif action.get("operation") == "external_transfer":
        return _deny("INVALID_DESTINATION", "External transfers must declare a destination.")
    p = {"tool": action["tool"], "operation": action["operation"], "resource": norm, "host": host, "cls": cls["level"]}
    rules = policy.get("rules", [])

    for r in rules:
        if r["effect"] == "deny" and _rule_matches(r, p):
            return {"decision": "deny", "reason_code": "EXPLICIT_DENY", "explanation": f"Denied by rule '{r['id']}'" + (f": {r['description']}" if r.get("description") else "."), "matched_rule_id": r["id"]}

    budget = policy.get("budget")
    exceeded = bool(budget) and allowed_in_window >= budget["max_allowed_actions"]

    def budget_deny():
        return _deny("BUDGET_EXCEEDED", f"The action budget ({budget['max_allowed_actions']} allowed actions per {budget['window_seconds']}s) is used up.")

    for r in rules:
        if r["effect"] == "require_approval" and _rule_matches(r, p):
            appr = r.get("approval") or {}
            if has_valid_approval:
                if exceeded:
                    return budget_deny()
                return {"decision": "allow", "reason_code": "APPROVAL_GRANTED", "explanation": f"Rule '{r['id']}' requires approval and a valid one-time approval for exactly this action was presented.", "matched_rule_id": r["id"]}
            role = appr.get("required_role", "admin")
            return {
                "decision": "require_approval", "reason_code": "APPROVAL_REQUIRED",
                "explanation": f"Rule '{r['id']}' requires a human {role} to approve this exact action.",
                "matched_rule_id": r["id"], "approval": {"required_role": role, "ttl_seconds": appr.get("ttl_seconds", 900)},
            }

    for r in rules:
        if r["effect"] == "allow" and _rule_matches(r, p):
            if exceeded:
                return budget_deny()
            return {"decision": "allow", "reason_code": "ALLOWED_BY_RULE", "explanation": f"Allowed by rule '{r['id']}'" + (f": {r['description']}" if r.get("description") else "."), "matched_rule_id": r["id"]}

    if host:
        for r in rules:
            if r["effect"] != "deny" and r["match"].get("destination_domains") and _rule_matches(r, p, ignore_destinations=True):
                return {"decision": "deny", "reason_code": "DESTINATION_NOT_APPROVED", "explanation": f"The destination '{host}' is not on the approved destination list of rule '{r['id']}'.", "matched_rule_id": r["id"]}
    return _deny("NO_MATCHING_RULE", "No rule permits this action; the default is to deny.")
