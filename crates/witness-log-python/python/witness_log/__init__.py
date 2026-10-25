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

Disclosure (SPEC §8): a leaf commits to ``SHA256(bucket_pad(payload) ||
salt || index)``. ``log.disclose(i)`` hands out the leaf, its salt and
(with ``store_payloads=True``) the payload; ``verify_disclosure`` lets a
third party check them against the leaf without trusting the log.

Identity: by default the identity seed is stored in the journal header
(mode 0600). Set ``WITNESS_LOG_IDENTITY_SEED_ENV`` to the NAME of an
environment variable holding a 32-byte hex seed and ``open()`` seals
every journal it creates or resumes, so the seed never touches the
journal file. Do this for anything that is not a demo.
"""

from __future__ import annotations

import asyncio
import functools
import json
import math
import os
import time
import weakref
from typing import Any, Callable, Dict, List, Optional, Union

from ._core import *  # noqa: F401,F403  -- the Rust core's public surface
from ._core import JournaledLog, WitnessLog  # explicit, for type checkers

__all__ = [
    # Rust core
    "WitnessLog",
    "JournaledLog",
    "WitnessService",
    "verify_dossier_json",
    "prove_silence_json",
    "verify_inclusion",
    "verify_handoff_binding",
    "verify_authorization_binding",
    "handoff_binding_error",
    "witnessed_dossier",
    "authorization_binding_error",
    "select_diverse_witnesses",
    "select_witnesses",
    "witness_entry_independent",
    "witness_entry_project_operated",
    "payload_hash",
    "normalize_label",
    "WitnessLogError",
    "SignatureError",
    "ContinuityError",
    "MalformedError",
    # Python layer. `open` is deliberately NOT here: `from witness_log
    # import *` would shadow the builtin, and the next `open("notes.txt")`
    # would create a journal (0.3.5 did this). Call `witness_log.open`.
    "step",
    "canonical_json",
    "sorted_json",
    "verify_disclosure",
    "prove_silence",
    "identity_seed_from_env",
    "IDENTITY_SEED_ENV",
    "Witnesser",
    "WitnessStatus",
    "submit_round",
]

__version__ = "0.7.0"

from . import _core  # noqa: E402
from .witnessing import Witnesser, WitnessStatus, submit_round, witnessed_dossier  # noqa: E402

#: The environment variable that names the environment variable holding
#: the identity seed (32 bytes as 64 hex characters). Indirection so the
#: secret itself can live under whatever name your secrets manager
#: injects it as: ``WITNESS_LOG_IDENTITY_SEED_ENV=AGENT_KEY`` then
#: ``AGENT_KEY=<64 hex>``.
IDENTITY_SEED_ENV = "WITNESS_LOG_IDENTITY_SEED_ENV"


# ------------------------------------------------------------ canonical JSON


def sorted_json(value: Any) -> bytes:
    """The payload encoding ``canonical_json`` produced before 0.4.0:
    ``json.dumps(sort_keys=True, separators=(",", ":"))`` with non-ASCII
    escaped as ``\\uXXXX`` and Python's number formatting. Kept so a
    verifier can recompute the payload hash of a leaf written by an older
    release. Never raises; see :func:`canonical_json` for the fallbacks."""
    try:
        out = json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=repr, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError):
        out = json.dumps(
            _jsonable(value, set(), 0),
            sort_keys=True,
            separators=(",", ":"),
            default=repr,
            allow_nan=False,
        )
    return out.encode("utf-8")


def canonical_json(value: Any) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme) bytes for a payload: object
    keys sorted by UTF-16 code units, no whitespace, numbers in ECMAScript
    ``Number::toString`` form (``10.0`` -> ``10``, ``1e21`` -> ``1e+21``,
    ``0.000001`` -> ``0.000001``, ``1e-7`` -> ``1e-7``), strings with only
    ``"``, ``\\`` and control characters escaped (``\\n``, ``\\u001f``) and
    everything else as literal UTF-8. This is the *payload* encoding used
    by :func:`step`; it is not the wire format (SPEC.md §3 defines that,
    and it is binary). Any JCS implementation in any language produces
    the same bytes for the same JSON value, which is what lets a verifier
    recompute a disclosed payload's hash.

    Never raises. Values ``json`` cannot encode become encodable the way
    0.3.6 did: non-string keys become strings (``1`` -> ``"1"``), a cycle
    becomes ``"<cycle>"``, NaN and infinities become the strings ``"nan"``,
    ``"inf"``, ``"-inf"`` (JCS has no spelling for them), other objects
    become ``repr(obj)``. Python integers outside IEEE 754 double range
    become ``repr`` strings too; integers above 2**53 are formatted as the
    nearest double, as RFC 8785 requires of every number.

    Before 0.4.0 this function was :func:`sorted_json`; payloads written
    by older releases hash under that encoding."""
    if _plain_json(value, 0):
        # Fast path, the common tool-call payload: strings, bools, None and
        # small integers under ASCII keys. For these the C encoder's output
        # is byte-identical to JCS (code-point order equals UTF-16 order on
        # ASCII keys; integers below 2**53 print the same; the escapes
        # coincide), at a quarter of the cost of the Python encoder.
        try:
            return json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
        except UnicodeEncodeError:
            pass  # a lone surrogate in a string; the full encoder escapes it
    out: list = []
    _jcs(value, out, set(), 0)
    return "".join(out).encode("utf-8")


_SAFE_INT = 1 << 53


def _plain_json(v: Any, depth: int) -> bool:
    """True when ``json.dumps(sort_keys=True)`` of ``v`` is already RFC 8785:
    no floats, no integers at or beyond 2**53, string keys that are ASCII,
    and nothing that is not a JSON value. Shallow and cheap; any doubt is
    False and the full encoder runs."""
    if v is None or v is True or v is False or isinstance(v, str):
        return True
    t = type(v)
    if t is int:
        return -_SAFE_INT < v < _SAFE_INT
    if depth > 64:
        return False
    if t is dict:
        for k, item in v.items():
            if type(k) is not str or not k.isascii() or not _plain_json(item, depth + 1):
                return False
        return True
    if t is list:
        for item in v:
            if not _plain_json(item, depth + 1):
                return False
        return True
    return False


def _jcs(v: Any, out: list, seen: set, depth: int) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_jcs_string(v))
    elif isinstance(v, bool):  # pragma: no cover - handled above; bool subclasses
        out.append("true" if v else "false")
    elif isinstance(v, int):
        out.append(_jcs_int(v))
    elif isinstance(v, float):
        out.append(_jcs_float(v))
    elif isinstance(v, (dict, list, tuple)):
        if depth > 200:
            out.append('"<too deep>"')
            return
        if id(v) in seen:
            out.append('"<cycle>"')
            return
        seen = seen | {id(v)}
        if isinstance(v, dict):
            items: Dict[str, Any] = {}
            for k, val in v.items():
                items[_json_key(k)] = val
            out.append("{")
            first = True
            for k in sorted(items, key=lambda s: s.encode("utf-16-be", "surrogatepass")):
                if not first:
                    out.append(",")
                first = False
                out.append(_jcs_string(k))
                out.append(":")
                _jcs(items[k], out, seen, depth + 1)
            out.append("}")
        else:
            out.append("[")
            for i, item in enumerate(v):
                if i:
                    out.append(",")
                _jcs(item, out, seen, depth + 1)
            out.append("]")
    else:
        out.append(_jcs_string(repr(v)))


def _jcs_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate has no UTF-8 form; escape it like json does.
        return json.dumps(s, ensure_ascii=True)
    # json's escaping with ensure_ascii=False is exactly JCS's: only `"`,
    # `\` and U+0000..U+001F are escaped, short forms for \b \t \n \f \r,
    # lowercase \u00xx otherwise.
    return json.dumps(s, ensure_ascii=False)


def _jcs_int(n: int) -> str:
    if -(2**53) <= n <= 2**53:
        return str(int(n))
    try:
        return _jcs_float(float(n))
    except OverflowError:
        return _jcs_string(repr(n))


def _jcs_float(f: float) -> str:
    """ECMAScript ``Number::toString`` for a finite double; non-finite
    values become their ``repr`` as a string (``"nan"``, ``"inf"``)."""
    if math.isnan(f) or math.isinf(f):
        return _jcs_string(repr(f))
    if f == 0:
        return "0"
    r = repr(f)  # shortest round-trip digits, like ES6's digit selection
    sign = ""
    if r[0] == "-":
        sign, r = "-", r[1:]
    if "e" in r:
        mant, exp = r.split("e")
        e = int(exp)
    else:
        mant, e = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    # value = 0.<digits> * 10^n   with n = len(ip) + e, adjusted for leading zeros
    n = len(ip) + e - (len(ip + fp) - len((ip + fp).lstrip("0")))
    digits = digits.rstrip("0")
    if not digits:  # pragma: no cover - zero handled above
        return "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e10 = n - 1
        es = ("+" if e10 >= 0 else "-") + str(abs(e10))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


def _json_key(k: Any) -> str:
    """The string ``json.dumps`` would have used for a key (``1`` ->
    ``"1"``, ``None`` -> ``"null"``), or ``repr`` for keys it rejects."""
    if isinstance(k, str):
        return k
    if k is None or isinstance(k, (bool, int, float)):
        return json.dumps(k) if not isinstance(k, float) or k == k else repr(k)
    return repr(k)


def _jsonable(value: Any, seen: set, depth: int) -> Any:
    """Convert ``value`` into something ``json.dumps(sort_keys=True,
    allow_nan=False)`` accepts. Only used when the fast path fails."""
    if depth > 200:
        return "<too deep>"
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else repr(value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, (dict, list, tuple)):
        if id(value) in seen:
            return "<cycle>"
        seen = seen | {id(value)}
        if isinstance(value, dict):
            return {_json_key(k): _jsonable(v, seen, depth + 1) for k, v in value.items()}
        return [_jsonable(v, seen, depth + 1) for v in value]
    return repr(value)


# -------------------------------------------------------------- disclosure


def verify_disclosure(leaf_json: Union[str, Dict[str, Any]], payload: bytes, salt_hex: str) -> bool:
    """Check a disclosed ``(payload, salt)`` against a leaf (SPEC §8):
    ``payload_hash(payload, salt, leaf["index"]) == leaf["payload_hash"]``.
    ``leaf_json`` is one element of a dossier's ``leaves`` (or of
    ``leaves_json()``), as a JSON string or a dict. Returns False, never
    raises, on malformed input: a hostile dossier must not stop a
    verifier loop. This proves the payload is what the log committed to
    at that index; whether the *leaf* is in a witnessed tree is the
    dossier verifier's job (``verify_dossier_json``, ``verify_inclusion``)."""
    try:
        leaf = json.loads(leaf_json) if isinstance(leaf_json, str) else leaf_json
        index = int(leaf["index"])
        want = str(leaf["payload_hash"]).lower()
        salt = bytes.fromhex(salt_hex)
        if index < 0 or len(salt) != 32 or len(want) != 64:
            return False
        return _core.payload_hash(bytes(payload), salt, index) == want
    except (KeyError, TypeError, ValueError, AttributeError, _core.WitnessLogError):
        return False


# ---------------------------------------------------------- silence proofs


def prove_silence(
    receipt_json: Union[str, Dict[str, Any]],
    dossiers_json: List[Union[str, Dict[str, Any]]],
    directory_json: Union[str, Dict[str, Any], List[Any]],
    min_checkpoints: int = 2,
    subject_org: Optional[str] = None,
    expected_identity: Optional[str] = None,
    revocations_json: Union[str, Dict[str, Any], List[Any], None] = None,
) -> Dict[str, Any]:
    """Check a write receipt against a log's witnessed dossiers (SPEC §9.4),
    offline: is the event it names in the history the witnesses cosigned,
    at the index the receipt promised, or provably left out of it? The
    counterparty's half of ``JournaledLog.write_receipt_json``; the same
    check and the same object as ``witness-log prove-silence --json``, with
    dossier indices where the CLI has paths.

    A dossier counts only when its checkpoint is signed by the receipt's key
    and verifies, is larger than the receipt's ``tree_size``, was cosigned by
    witnesses from at least two independent operators in ``directory_json``
    (yours, never a dossier's; ``subject_org``'s witnesses never count), and
    its leaves reproduce that checkpoint; any other is used for nothing
    (``dossiers[i]["status"]`` says why). The leaves come from the largest
    counted dossier and must reproduce every counted checkpoint. Inputs are
    JSON strings or the parsed objects. ``revocations_json`` (one statement
    or a list) is applied with the revocations counted dossiers carry: a v2
    revocation of the receipt's key (``revoke_json(..., as_of_index=N,
    experimental=True)``) whose index a counted checkpoint has reached
    leaves the receipt proving nothing. v1 statements, and v2 ones no
    witnessed checkpoint has reached, are not applied
    (``revocations_not_in_effect`` counts them): the accused log could sign
    one for free.

    ``result`` is ``"present"`` (the event is leaf ``leaf_index`` =
    ``promised_index`` of the witnessed history, bound to
    ``bound_tree_size``/``bound_root_hash``), ``"inconclusive"``
    (``reason`` says what is missing; never an accusation), ``"censored"``
    (at least ``min_checkpoints`` witnessed checkpoints after the receipt,
    whose leaves omit the event) or ``"misplaced"`` (the event is leaf
    ``leaf_index`` of the witnessed history, not ``promised_index``: the log
    broke the position it signed for; ``witnessed_checkpoints_without``
    counts the witnessed checkpoints that lacked it entirely).

    Raises ``MalformedError`` for input that does not parse,
    ``SignatureError`` for a receipt, or a revocation of its key, that does
    not verify, and ``ValueError`` for a receipt not signed by
    ``expected_identity``, an empty ``dossiers_json``, ``min_checkpoints``
    below 1 or another bad argument."""

    def text(v: Any) -> str:
        return v if isinstance(v, str) else json.dumps(v)

    if isinstance(dossiers_json, (str, bytes, dict)):
        raise TypeError("dossiers_json is a list of dossiers (JSON strings or dicts), not one dossier")
    if isinstance(min_checkpoints, bool) or not isinstance(min_checkpoints, int) or min_checkpoints < 1:
        raise ValueError(f"min_checkpoints must be an integer of at least 1, got {min_checkpoints!r}")
    report: Dict[str, Any] = json.loads(
        _core.prove_silence_json(
            text(receipt_json),
            [text(d) for d in dossiers_json],
            text(directory_json),
            min_checkpoints,
            subject_org,
            expected_identity,
            None if revocations_json is None else text(revocations_json),
        )
    )
    return report


def _disclose(self: JournaledLog, index: int) -> Dict[str, Any]:
    """Everything a third party needs to check what leaf ``index``
    committed to: ``{"index", "leaf", "payload_hash", "salt"}`` plus
    ``"payload"`` (bytes) when the journal keeps payloads
    (``open(..., store_payloads=True)``). Hand it, with the payload, to
    someone running :func:`verify_disclosure`; after ``forget(index)``
    this raises ``ValueError`` because the salt is gone, which is the
    point of forgetting.

    Raises ``IndexError`` for a leaf that does not exist and
    ``ValueError`` for one with nothing to disclose (a redaction marker,
    a forgotten leaf, or a leaf from a journal written before salts were
    persisted)."""
    if index < 0:
        raise IndexError(f"no leaf at index {index}")
    leaf = self.leaf_json(index)
    if leaf is None:
        raise IndexError(f"no leaf at index {index} (tree size {self.tree_size()})")
    salt = self.salt_hex(index)
    if salt is None:
        raise ValueError(
            f"leaf {index} has no salt to disclose: it was forgotten, carries no payload, "
            "or predates the salt sidecar"
        )
    doc = json.loads(leaf)
    out: Dict[str, Any] = {"index": index, "leaf": doc, "payload_hash": doc["payload_hash"], "salt": salt}
    payload = self.payload(index)
    if payload is not None:
        out["payload"] = payload
    return out


# ------------------------------------------------------------- witnessing


def _submit(
    self: Any,
    directory: Any,
    want: Optional[int] = None,
    min: Optional[int] = None,  # noqa: A002 -- the documented keyword
    *,
    timeout: float = 10.0,
    state_path: Optional[str] = None,
    subject_org: Optional[str] = None,
) -> Dict[str, Any]:
    """One synchronous witnessing round for the current head: contact up
    to ``want`` diversity-selected witnesses from ``directory`` (a dict,
    JSON text, a list of entries, or a path to a JSON file), follow 409
    resyncs, honour ``Retry-After``, keep the cosignatures that verify,
    and return ``{"dossier": dict, "verdict": str, "cosignatures": n,
    "contacted": n, "tree_size": n, "outcomes": [...]}``. The verdict is
    what a verifier holding ``directory`` reaches, with ``min`` as the
    minimum cosignature count (default 2; WITNESSED also needs two
    independent operators; ``subject_org``, the organisation that operates
    this log, keeps its own witnesses from counting as independent of it).
    Blocks for up to roughly
    ``timeout * attempts``; use :class:`Witnesser` to witness in the
    background or ``await log.asubmit(...)`` from asyncio.

    Witnessing state goes to ``<journal>.witnesses.json`` (the CLI's
    file) for a :class:`JournaledLog`; an in-memory :class:`WitnessLog`
    needs ``state_path``. Raises ``RuntimeError`` when the refuse-to-
    equivocate rule stops the round (the journal does not extend what
    witnesses already cosigned for this identity) and ``ValueError`` for
    a directory nothing can be submitted to; per-witness network failures
    are reported in ``outcomes``, not raised."""
    if isinstance(directory, str) and not directory.lstrip().startswith(("{", "[")):
        with _builtin_open(directory, encoding="utf-8") as f:
            directory = json.load(f)
    if state_path is None:
        path = getattr(self, "path", None)
        if path is None:
            raise ValueError("an in-memory WitnessLog needs state_path= so witnessing state persists")
        state_path = f"{path()}.witnesses.json"
    max_witnesses = 8 if want is None else int(want)
    min_cosigs = 2 if min is None else int(min)
    if max_witnesses < 1 or min_cosigs < 1:
        raise ValueError("want and min must be at least 1")
    r = submit_round(self, directory, state_path, max_witnesses=max_witnesses, timeout=timeout)
    if r.refused:
        raise RuntimeError(r.refused)
    if r.contacted == 0:
        raise ValueError("directory has no independent witnesses to contact")
    doc = json.loads(r.dossier_json or "{}")
    report = json.loads(
        _core.verify_dossier_json(
            json.dumps(doc),
            0.66,
            self.identity_pubkey_hex(),
            json.dumps(doc.get("witness_directory")),
            min_cosigs,
            subject_org=subject_org,
        )
    )
    return {
        "dossier": doc,
        "verdict": report.get("verdict"),
        "cosignatures": r.cosignatures,
        "contacted": r.contacted,
        "tree_size": r.tree_size,
        "outcomes": r.outcomes,
    }


async def _asubmit(self: Any, directory: Any, want: Optional[int] = None, min: Optional[int] = None, **kw: Any) -> Dict[str, Any]:  # noqa: A002,E501
    """``submit`` for asyncio code: runs the round in a worker thread so
    the event loop keeps serving."""
    return await asyncio.to_thread(functools.partial(_submit, self, directory, want, min, **kw))


# The Rust classes get their Python-level conveniences here, so a caller
# sees one object with one surface. `_core.pyi` lists them too.
JournaledLog.disclose = _disclose  # type: ignore[attr-defined]
JournaledLog.submit = _submit  # type: ignore[attr-defined]
JournaledLog.asubmit = _asubmit  # type: ignore[attr-defined]


def _witnessed_dossier_json(self: Any, state_path: Optional[str] = None) -> Optional[str]:
    """The dossier for the latest head witnesses cosigned, with those
    cosignatures (rebuilt from ``<journal>.witnesses.json``); ``None`` before
    the first successful ``submit``. See :func:`witnessed_dossier`."""
    return witnessed_dossier(self, state_path)


JournaledLog.witnessed_dossier_json = _witnessed_dossier_json  # type: ignore[attr-defined]
WitnessLog.submit = _submit  # type: ignore[attr-defined]
WitnessLog.asubmit = _asubmit  # type: ignore[attr-defined]


# ------------------------------------------------------------------- open

_builtin_open = open

# Every JournaledLog this process opened, by absolute path, while it is
# alive: `open(path, session="reuse")` returns it instead of resuming the
# journal again (a resume mints a new session key and takes ~1 ms).
_open_logs: "weakref.WeakValueDictionary[str, JournaledLog]" = weakref.WeakValueDictionary()


def identity_seed_from_env(environ: Optional[Dict[str, str]] = None) -> Optional[bytes]:
    """The identity seed configured through :data:`IDENTITY_SEED_ENV`, or
    None when it is unset. ``WITNESS_LOG_IDENTITY_SEED_ENV`` holds the
    NAME of the variable with the seed; that variable must hold exactly
    64 hex characters. A name that points at a missing or malformed
    variable raises ``ValueError`` rather than silently falling back to
    an unsealed journal."""
    env = os.environ if environ is None else environ
    name = env.get(IDENTITY_SEED_ENV)
    if not name:
        return None
    raw = env.get(name)
    if raw is None:
        raise ValueError(f"{IDENTITY_SEED_ENV}={name!r} but {name} is not set")
    try:
        seed = bytes.fromhex(raw.strip())
    except ValueError:
        seed = b""
    if len(seed) != 32:
        raise ValueError(f"{name} must hold the identity seed as 64 hex characters (32 bytes)")
    return seed


def open(  # noqa: A001
    path: str,
    identity_seed: Optional[bytes] = None,
    *,
    seal: bool = False,
    store_payloads: bool = False,
    session: str = "new",
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
    backups), and keep the seed where you keep secrets. Setting the
    environment variable ``WITNESS_LOG_IDENTITY_SEED_ENV`` to the name of
    a variable holding the seed as 64 hex characters does the same for
    every ``open()`` without a seed argument: the journal is sealed and
    the seed comes from that variable. An unsealed journal is a key file;
    the default stays unsealed only so a first ``pip install`` works
    without ceremony.

    ``store_payloads=True`` keeps every payload appended through this
    object in ``<path>.payloads`` (mode 0600) so ``log.disclose(i)`` can
    return the payload with its salt; ``forget(i)`` removes and
    zero-overwrites its record. The tree never holds payloads; this
    sidecar does, so protect it like the journal.

    ``session="reuse"`` returns the log object this process already has
    open at ``path`` instead of resuming the journal again, which would
    mint a new session key, append a new key binding, and take about a
    millisecond. A session key lives only in process memory, so reuse is
    in-process: when nothing in this process has ``path`` open, the
    journal is resumed as with ``"new"``.
    """
    if session not in ("new", "reuse"):
        raise ValueError(f'session must be "new" or "reuse", got {session!r}')
    if identity_seed is None:
        env_seed = identity_seed_from_env()
        if env_seed is not None:
            identity_seed, seal = env_seed, True
    if seal and identity_seed is None:
        raise ValueError("seal=True requires identity_seed (the seed is not stored in a sealed journal)")
    key = os.path.abspath(path)
    if session == "reuse":
        existing = _open_logs.get(key)
        if existing is not None and not existing.is_closed():
            if store_payloads and existing.payload_store_path() is None:
                existing.enable_payload_store()
            return existing
    if os.path.exists(path):
        if identity_seed is not None:
            log, _dropped = JournaledLog.resume_with_identity(path, identity_seed)
        else:
            log, _dropped = JournaledLog.resume(path)
    elif seal:
        log = JournaledLog.create_sealed(path, identity_seed)
    elif identity_seed is not None:
        log = JournaledLog.create(path, identity_seed)
    else:
        log = JournaledLog.create_ephemeral(path)
    if store_payloads:
        log.enable_payload_store()
    _open_logs[key] = log
    return log


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
            # t_ms: integer milliseconds. An integer keeps the payload on the
            # fast JCS path and avoids float formatting differences across
            # languages; before 0.4.0 this was "t": float seconds.
            payload = {"tool": tool, "args": list(args), "kwargs": kwargs, "t_ms": time.time_ns() // 1_000_000}
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
