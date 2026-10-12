"""RFC 8785 (JCS) for the commerce profiles: a strict front over
``witness_log.canonical_json``.

``witness_log.canonical_json`` is RFC 8785 and never raises: a value that
is not JSON is made encodable so an audit leaf is always written. A
mandate is different. It is hashed on two sides written in two languages,
and a value that only one side can encode must be refused, not guessed.
So this module validates that the value is in the I-JSON subset JCS is
defined over (string keys, finite doubles, no ``bytes`` or objects) and
then encodes it with the package's one canonicaliser, so the two can
never drift.
"""

from __future__ import annotations

import math
from typing import Any

from .. import canonical_json

__all__ = ["canonicalize", "dumps"]


def _check(v: Any, depth: int = 0) -> None:
    if depth > 500:
        raise ValueError("JSON value too deeply nested")
    if v is None or isinstance(v, (bool, str, int)):
        return
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("JCS numbers must be finite")
        return
    if isinstance(v, dict):
        for k, item in v.items():
            if not isinstance(k, str):
                raise TypeError(f"JCS object keys must be strings, got {type(k).__name__}")
            _check(item, depth + 1)
        return
    if isinstance(v, (list, tuple)):
        for item in v:
            _check(item, depth + 1)
        return
    raise TypeError(f"not a JSON value: {type(v).__name__}")


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 text of ``value`` as UTF-8 bytes (what is hashed).
    Raises ``TypeError`` / ``ValueError`` for anything outside I-JSON."""
    _check(value)
    return canonical_json(value)


def dumps(value: Any) -> str:
    """The RFC 8785 text of ``value`` as a ``str``."""
    return canonicalize(value).decode("utf-8")
