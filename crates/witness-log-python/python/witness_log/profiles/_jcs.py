"""RFC 8785 JSON Canonicalization Scheme (JCS), pure Python.

``witness_log.canonical_json`` is the project's own payload encoding
(sorted keys, no whitespace, Python ``repr`` for the odd value). It is
not RFC 8785: Python sorts keys by code point where JCS sorts by UTF-16
code unit, escapes non-ASCII where JCS emits it literally, and prints
``1.0``, ``1e-07`` and ``1e+20`` where JCS prints ``1``, ``1e-7`` and
``100000000000000000000``. A mandate hashed on two sides written in two
languages must agree byte for byte, so the commerce profiles hash JCS
bytes, which every RFC 8785 implementation reproduces.

Scope: the I-JSON subset JCS is defined over. Numbers must be finite
and representable as IEEE-754 doubles; ``NaN``/``Infinity`` raise
``ValueError``. Keys must be strings. Anything that is not a JSON value
(``bytes``, a dataclass) raises ``TypeError`` rather than being guessed.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "dumps"]

_MAX_SAFE = 2**53


def dumps(value: Any) -> str:
    """The canonical JSON text of ``value`` as a ``str``."""
    out: list = []
    _write(value, out)
    return "".join(out)


def canonicalize(value: Any) -> bytes:
    """The canonical JSON text of ``value`` as UTF-8 bytes (what is hashed)."""
    return dumps(value).encode("utf-8")


def _write(v: Any, out: list) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, int):
        out.append(_number(float(v)) if abs(v) >= _MAX_SAFE else str(v))
    elif isinstance(v, float):
        out.append(_number(v))
    elif isinstance(v, dict):
        out.append("{")
        first = True
        for k in v.keys():
            if not isinstance(k, str):
                raise TypeError(f"JCS object keys must be strings, got {type(k).__name__}")
        for k in sorted(v.keys(), key=_utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_string(k))
            out.append(":")
            _write(v[k], out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise TypeError(f"not a JSON value: {type(v).__name__}")


def _utf16_key(s: str) -> bytes:
    # RFC 8785 §3.2.3: sort by UTF-16 code units. Big-endian UTF-16 bytes
    # compare in exactly that order (a surrogate pair sorts as D8xx..).
    return s.encode("utf-16-be")


_SHORT = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\"}


def _string(s: str) -> str:
    # RFC 8785 §3.2.2.2: escape only `"`, `\` and U+0000..U+001F; the
    # five with a short form use it, the rest `\u00xx` lowercase. Every
    # other character, non-ASCII included, is emitted literally.
    parts = ['"']
    for ch in s:
        if ch in _SHORT:
            parts.append(_SHORT[ch])
        elif ch < " ":
            parts.append("\\u%04x" % ord(ch))
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _number(x: float) -> str:
    """ECMAScript ``Number::toString`` (RFC 8785 §3.2.2.3) for a finite double."""
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS cannot represent NaN or Infinity")
    if x == 0:
        return "0"  # -0 serialises as 0
    sign = "-" if x < 0 else ""
    # repr gives the shortest digit string that round-trips, which is the
    # digit string ES6 requires; Decimal just parses it exactly.
    _s, tup, exp = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(str(d) for d in tup).lstrip("0") or "0"
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exp  # value = digits * 10^(n-k), ES6's n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        exp_s = ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + exp_s
    return sign + body
