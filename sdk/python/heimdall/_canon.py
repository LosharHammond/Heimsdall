"""Canonical JSON and the action digest, byte-for-byte identical to src/shared/action.ts (JavaScript JSON.stringify rules)."""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        elif 0xD800 <= ord(ch) <= 0xDFFF:  # lone surrogate: JSON.stringify escapes it
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _js_number(x: float | int) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) < 10**21:
            return str(x)
        x = float(x)
    if math.isnan(x) or math.isinf(x):
        return "null"
    if x == 0:
        return "0"
    if x.is_integer() and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)  # shortest round-trip, like JavaScript; only the exponent spelling differs
    if "e" in r:
        mant, exp = r.split("e")
        sign = "-" if exp.startswith("-") else "+"
        exp = exp.lstrip("+-").lstrip("0") or "0"
        n = int(exp) * (-1 if sign == "-" else 1)
        if -7 < n < 21:  # JavaScript writes these without an exponent
            t = format(Decimal(r), "f")
            return t.rstrip("0").rstrip(".") if "." in t else t
        return f"{mant}e{sign}{exp}"
    return r


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _js_number(value)
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(k for k, v in value.items() if v is not _UNDEFINED)
        # JavaScript sorts keys by UTF-16 code units; Python by code points. Identical for the BMP, which covers real keys.
        return "{" + ",".join(f"{_js_string(k)}:{canonical_json(value[k])}" for k in keys) + "}"
    raise TypeError(f"Cannot canonicalize {type(value).__name__}")


class _Undefined:
    pass


_UNDEFINED = _Undefined()


def action_digest(action: dict[str, Any]) -> str:
    """SHA-256 over the canonical action: what will run, not who asked or when. Matches actionDigest() on the server."""
    return hashlib.sha256(
        canonical_json(
            {
                "tool": action["tool"],
                "operation": action["operation"],
                "resource": action["resource"],
                "destination": action.get("destination"),
                "data_classification": action.get("data_classification"),
                "args": action.get("args") or {},
            }
        ).encode("utf-8")
    ).hexdigest()


def to_wire(value: Any) -> Any:
    """Round-trips through JSON so callers cannot mutate what was authorized (a deep, frozen-in-effect copy)."""
    return json.loads(json.dumps(value))
