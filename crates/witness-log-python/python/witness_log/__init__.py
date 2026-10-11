"""witness-log: witnessed, not trusted.

A cryptographically verifiable audit trail for autonomous agents. The
core (Merkle log, Ed25519 identity, salted redaction, witness protocol,
offline verification) is Rust, exposed here as ``witness_log._core``.
This module adds the conveniences an agent loop wants:

    import witness_log
    log = witness_log.open("agent.jsonl")        # create or resume

    @witness_log.step(log)                       # one line per tool
    def search(query: str) -> dict: ...

    print(log.to_dossier_json())                 # hand to anyone to verify

Every call to a decorated function appends two leaves: an *intent* before
the call (tool name + arguments) and a *result* after it (tool name +
return value, or the exception). Both are hashed with a per-leaf salt, so
any single entry can later be erased for GDPR with ``log.forget(index)``
without breaking the proofs around it.
"""

from __future__ import annotations

import functools
import json
import os
import time
from typing import Any, Callable, Optional

from ._core import *  # noqa: F401,F403  -- the Rust core's public surface
from ._core import JournaledLog, WitnessLog  # explicit, for type checkers

__all__ = [
    # Rust core
    "WitnessLog",
    "JournaledLog",
    "WitnessService",
    "verify_dossier_json",
    "verify_inclusion",
    "verify_handoff_binding",
    "verify_authorization_binding",
    "select_diverse_witnesses",
    "select_witnesses",
    "witness_entry_independent",
    "witness_entry_project_operated",
    "WitnessLogError",
    "SignatureError",
    "ContinuityError",
    "MalformedError",
    # Python layer
    "open",
    "step",
    "canonical_json",
]

__version__ = "0.3.5"


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON bytes for a payload: sorted keys, no whitespace,
    UTF-8. This is the *payload* encoding used by :func:`step`; it is not
    the wire format (SPEC.md §3 defines that, and it is binary). Values
    that are not JSON-serialisable fall back to ``repr``."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr).encode(
        "utf-8"
    )


def open(  # noqa: A001
    path: str, identity_seed: Optional[bytes] = None, *, seal: bool = False
) -> JournaledLog:
    """Create or resume a journaled log at ``path``.

    If the journal exists it is resumed (a torn last line from a crash is
    healed and reported on the log's ``resume`` path). If it does not, a
    new log is created: with ``identity_seed`` (32 bytes, from
    ``log.identity_bytes()`` of an earlier log, or from your KMS) the
    identity persists across machines; without it a fresh identity is
    generated and stored in the journal header, so the same path resumes
    the same identity.

    ``seal=True`` keeps the seed OUT of the journal: the header then holds
    only the public key and ``identity_seed`` is required on every call,
    create and resume alike. Use it when the journal file may be readable
    by more parties than the key should be (shared volumes, log shippers,
    backups), and keep the seed where you keep secrets.
    """
    if seal and identity_seed is None:
        raise ValueError("seal=True requires identity_seed (the seed is not stored in a sealed journal)")
    if os.path.exists(path):
        if identity_seed is not None:
            log, _dropped = JournaledLog.resume_with_identity(path, identity_seed)
        else:
            log, _dropped = JournaledLog.resume(path)
        return log
    if seal:
        return JournaledLog.create_sealed(path, identity_seed)
    if identity_seed is not None:
        return JournaledLog.create(path, identity_seed)
    return JournaledLog.create_ephemeral(path)


def step(
    log: Any,
    name: Optional[str] = None,
    *,
    record_result: bool = True,
    sync: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: record every call of a function as an intent leaf before
    it runs and a result leaf after.

    ``log`` is a :class:`JournaledLog` (durable) or :class:`WitnessLog`
    (in-memory). ``name`` defaults to the function's qualified name.
    ``record_result=False`` records only the intent (for results that are
    large or sensitive -- the result leaf then carries only the outcome).
    ``sync=True`` fsyncs the journal after each call; the default lets
    the OS batch writes, and ``log.sync()`` can be called at checkpoints.

    Works with sync functions and coroutines. Exceptions are recorded as
    results of kind ``"error"`` and re-raised unchanged.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool = name or getattr(fn, "__qualname__", getattr(fn, "__name__", "tool"))

        def before(args: tuple, kwargs: dict) -> int:
            payload = {"tool": tool, "args": list(args), "kwargs": kwargs, "t": time.time()}
            return log.append_intent(canonical_json(payload))

        def after(intent_index: int, outcome: str, value: Any) -> int:
            payload = {"tool": tool, "intent_index": intent_index, "outcome": outcome}
            if record_result or outcome == "error":
                payload["value"] = value
            idx = log.append_result(canonical_json(payload))
            if sync and hasattr(log, "sync"):
                log.sync()
            return idx

        if _is_coroutine_function(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                i = before(args, kwargs)
                try:
                    out = await fn(*args, **kwargs)
                except BaseException as e:  # noqa: BLE001 -- recorded, then re-raised
                    after(i, "error", f"{type(e).__name__}: {e}")
                    raise
                after(i, "ok", out)
                return out

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            i = before(args, kwargs)
            try:
                out = fn(*args, **kwargs)
            except BaseException as e:  # noqa: BLE001
                after(i, "error", f"{type(e).__name__}: {e}")
                raise
            after(i, "ok", out)
            return out

        return wrapper

    return decorate


def _is_coroutine_function(fn: Any) -> bool:
    import inspect

    return inspect.iscoroutinefunction(fn)
