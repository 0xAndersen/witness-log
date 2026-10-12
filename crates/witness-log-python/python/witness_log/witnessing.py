"""Getting a journal cosigned by witnesses, from Python, without blocking
the agent.

Two layers:

* :func:`submit_round` -- one synchronous round: send the head to each
  selected witness over ``c2sp.org/tlog-witness``, follow ``409`` resyncs,
  honour ``Retry-After`` on ``429``/``503``, keep only cosignatures that
  verify, persist what each witness has cosigned. The same logic as
  ``witness-log witness submit``, and the same state file
  (``<journal>.witnesses.json``), so the CLI and Python can take turns on
  one journal.
* :class:`Witnesser` -- runs rounds in a background thread. ``request()``
  never blocks and never raises into the agent's call path; ``status()``
  says how far witnessing has got and what last went wrong; ``flush()``
  waits (bounded) for the current head to be cosigned. ``await
  aflush()`` is the asyncio form.

Safety rule shared with the CLI: once witnesses have cosigned size ``N``
with root ``R`` for this identity, a journal that does not extend
``(N, R)`` (restored from an old backup, or copied and appended to
elsewhere) is never submitted. Witnesses would refuse it and keep the two
signed heads as proof this identity equivocated.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _core

__all__ = ["Witnesser", "WitnessStatus", "RoundResult", "submit_round", "load_state", "save_state"]

# Same bound the CLI applies to a witness's Retry-After (its enrollment
# windows are a minute).
MAX_RETRY_AFTER_S = 60
ATTEMPTS_PER_WITNESS = 6

Post = Callable[[str, str, float], Tuple[int, str, int]]


def _post(url: str, body: str, timeout: float) -> Tuple[int, str, int]:
    """POST ``body`` to ``<url>/add-checkpoint``. Returns
    ``(status, response_text, retry_after_seconds)``. Only http(s): a
    directory entry is caller-supplied, and ``urllib`` would otherwise
    happily read ``file://`` URLs (found by the 0.3.5 hostile-input
    evaluation against the MCP server, which returned the file's first
    200 bytes to the caller)."""
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"witness url must be http:// or https://, got {url!r}")
    req = urllib.request.Request(
        url.rstrip("/") + "/add-checkpoint",
        data=body.encode(),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 -- scheme checked above
            return r.status, r.read(1 << 20).decode("utf-8", "replace"), 0
    except urllib.error.HTTPError as e:
        try:
            retry = int(e.headers.get("Retry-After") or 0)
        except ValueError:
            retry = 0
        return e.code, e.read(1 << 16).decode("utf-8", "replace"), retry


# ------------------------------------------------------------------ state


def load_state(path: str) -> Dict[str, Any]:
    """The CLI's client state: ``{"sizes": {witness_pubkey: size},
    "cosigned_size": N, "cosigned_root": hex}``. Missing or unreadable is
    an empty state (a 409 from each witness rebuilds ``sizes``).
    Pre-0.3.6 MCP servers wrote a bare ``{pubkey: size}`` map to the same
    path; that is read as ``sizes``."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    if "sizes" in raw and isinstance(raw.get("sizes"), dict):
        sizes = raw["sizes"]
    else:  # legacy MCP format
        sizes = {k: v for k, v in raw.items() if isinstance(v, int) and len(k) == 64}
    return {
        "sizes": {str(k).lower(): int(v) for k, v in sizes.items() if isinstance(v, int) and v >= 0},
        "cosigned_size": int(raw.get("cosigned_size") or 0) if isinstance(raw.get("cosigned_size", 0), int) else 0,
        "cosigned_root": str(raw.get("cosigned_root") or ""),
    }


def save_state(path: str, state: Dict[str, Any]) -> None:
    """Atomic write (temp file, fsync, rename), mode 0600."""
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.{threading.get_ident()}.tmp")
    data = json.dumps(
        {
            "sizes": dict(sorted(state["sizes"].items())),
            "cosigned_size": state["cosigned_size"],
            "cosigned_root": state["cosigned_root"],
        },
        indent=2,
    ).encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ------------------------------------------------------------------ round


@dataclass
class RoundResult:
    """What one submission round did."""

    tree_size: int
    cosignatures: int
    contacted: int
    outcomes: List[Dict[str, Any]]
    dossier_json: Optional[str]
    refused: Optional[str] = None  # set when the safety rule stopped the round

    @property
    def ok(self) -> bool:
        return self.refused is None and self.cosignatures > 0


def _parse_directory(directory: Any) -> Dict[str, Any]:
    if isinstance(directory, str):
        directory = json.loads(directory)
    if isinstance(directory, list):
        directory = {"witnesses": directory}
    if not isinstance(directory, dict) or not isinstance(directory.get("witnesses"), list):
        raise ValueError('directory must be {"witnesses": [...]} or a list of witness entries')
    return directory


def submit_round(
    log: Any,
    directory: Any,
    state_path: str,
    *,
    max_witnesses: int = 8,
    timeout: float = 10.0,
    max_wait: float = MAX_RETRY_AFTER_S,
    post: Post = _post,
    sleep: Callable[[float], None] = time.sleep,
) -> RoundResult:
    """One round: pin the current head, ask up to ``max_witnesses``
    diversity-selected witnesses to cosign it, return a dossier for that
    head carrying every cosignature that verifies. Raises only on bad
    arguments (``ValueError``); network failures are per-witness
    ``outcomes``."""
    directory = _parse_directory(directory)
    if max_witnesses < 1:
        raise ValueError("max_witnesses must be at least 1")
    ident = log.identity_pubkey_hex()
    picks = json.loads(_core.select_witnesses(json.dumps(directory), ident, max_witnesses, False))
    size = log.tree_size()
    state = load_state(state_path)

    # The safety rule. root_hex_at(N) is None when the journal is shorter.
    if state["cosigned_size"] > 0:
        have = log.root_hex_at(state["cosigned_size"])
        if have is None or have != state["cosigned_root"].lower():
            msg = (
                f"refusing to submit: witnesses already cosigned size {state['cosigned_size']} "
                f"for this identity and this journal (size {size}) does not extend it; "
                "submitting would get the identity recorded as equivocating. Restore the "
                f"journal that was witnessed (state: {state_path})"
            )
            return RoundResult(size, 0, 0, [], None, refused=msg)

    def one(w: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Tuple[str, str]]]:
        pk = str(w.get("pubkey", "")).lower()
        name = w.get("name")
        old = state["sizes"].get(pk, 0)
        if old > size:
            old = 0
        waited = 0.0
        status, text = 0, ""
        for _ in range(ATTEMPTS_PER_WITNESS):
            try:
                body = log.add_checkpoint_body_at(size, old)
                status, text, retry = post(str(w.get("url", "")), body, timeout)
            except (OSError, ValueError, urllib.error.URLError) as e:
                return {"witness": name, "status": 0, "error": str(e)}, None
            if status == 200:
                return {"witness": name, "status": 200}, (pk, text)
            if status == 409:
                try:
                    theirs = int(text.strip())
                except ValueError:
                    return {"witness": name, "status": 409, "error": f"unparseable 409 body {text.strip()[:80]!r}"}, None
                if theirs > size:
                    return {
                        "witness": name,
                        "status": 409,
                        "error": f"witness already cosigned size {theirs} but this journal has {size} leaves "
                        "(truncated journal, or a fork)",
                    }, None
                old = theirs
                continue
            if status in (429, 503) and 0 < retry <= MAX_RETRY_AFTER_S and waited + retry <= max_wait:
                sleep(retry)
                waited += retry
                continue
            break
        err = text.strip()[:200]
        if status == 422:
            err = "REFUSED (422): not consistent with what this witness already cosigned: " + err
        return {"witness": name, "status": status, "error": err}, None

    outcomes: List[Dict[str, Any]] = []
    responses: List[Tuple[str, str]] = []
    if picks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(picks), 16)) as ex:
            for outcome, resp in ex.map(one, picks):
                outcomes.append(outcome)
                if resp is not None:
                    responses.append(resp)

    dossier_json, n = log.dossier_from_responses_at(size, responses)
    doc = json.loads(dossier_json)
    accepted = {str(r.get("witness_pubkey", "")).lower() for r in doc.get("witness_receipts", [])}
    for o, w in zip(outcomes, picks):
        pk = str(w.get("pubkey", "")).lower()
        if o.get("status") == 200 and pk not in accepted:
            o["status"] = 0
            o["error"] = "HTTP 200 but no valid cosignature from the expected key"
    for pk in accepted:
        state["sizes"][pk] = size
    if n > 0 and size >= state["cosigned_size"]:
        state["cosigned_size"] = size
        state["cosigned_root"] = log.root_hex_at(size) or ""
    try:
        save_state(state_path, state)
    except OSError as e:
        outcomes.append({"witness": None, "status": 0, "error": f"could not save {state_path}: {e}"})
    doc["witness_directory"] = directory
    return RoundResult(size, n, len(picks), outcomes, json.dumps(doc))


# -------------------------------------------------------------- Witnesser


@dataclass
class WitnessStatus:
    """A snapshot of a :class:`Witnesser`. ``witnessed_size`` is the
    largest head with at least ``min_cosignatures`` verified cosignatures
    from the last successful round; ``last_error`` is structured:
    ``{"time", "kind", "message", "outcomes"}`` with ``kind`` one of
    ``"refused"`` (the safety rule), ``"no_cosignatures"``, ``"too_few"``,
    ``"exception"``."""

    running: bool
    requested_size: int
    witnessed_size: int
    cosignatures: int
    rounds: int
    failures_in_a_row: int
    next_attempt_in_s: float
    last_error: Optional[Dict[str, Any]] = None
    last_outcomes: List[Dict[str, Any]] = field(default_factory=list)


class Witnesser:
    """Background witnessing for one journal.

    ::

        log = witness_log.open("agent.jsonl")
        w = witness_log.Witnesser(log, "trusted.json", "agent.jsonl")
        ...                                  # agent appends as usual
        w.request()                          # cheap; never blocks, never raises
        ...
        if w.flush(timeout=30):              # bounded wait for the current head
            open("dossier.json", "w").write(w.dossier())
        print(w.status())
        w.close()

    ``directory`` is the witness directory *you* trust (dict, JSON text,
    a list of entries, or a path to a JSON file). ``path`` is the journal
    path the log was opened with; state goes to ``<path>.witnesses.json``
    (the CLI's file) unless ``state_path`` is given. ``interval`` > 0
    also submits on a timer. Failures back off exponentially (with
    jitter) up to ``backoff_max`` seconds; ``Retry-After`` is honoured
    inside a round. Nothing here is ever raised into the caller except
    from the constructor (bad arguments).
    """

    def __init__(
        self,
        log: Any,
        directory: Any,
        path: Optional[str] = None,
        *,
        state_path: Optional[str] = None,
        max_witnesses: int = 8,
        min_cosignatures: int = 2,
        interval: float = 0.0,
        timeout: float = 10.0,
        backoff_initial: float = 1.0,
        backoff_max: float = 60.0,
        start: bool = True,
        _post: Post = _post,
    ) -> None:
        if isinstance(directory, str) and not directory.lstrip().startswith(("{", "[")):
            with open(directory, encoding="utf-8") as f:
                directory = json.load(f)
        self._directory = _parse_directory(directory)
        if state_path is None:
            if path is None:
                raise ValueError("pass the journal path (or state_path) so witnessing state persists")
            state_path = f"{path}.witnesses.json"
        if min_cosignatures < 1 or max_witnesses < 1:
            raise ValueError("min_cosignatures and max_witnesses must be at least 1")
        self._log = log
        self._state_path = state_path
        self._max_witnesses = max_witnesses
        self._min = min_cosignatures
        self._interval = interval
        self._timeout = timeout
        self._b0 = backoff_initial
        self._bmax = backoff_max
        self._post = _post
        self._cv = threading.Condition()
        self._requested = 0
        self._witnessed = 0
        self._cosigs = 0
        self._rounds = 0
        self._fails = 0
        self._next_at = 0.0
        self._last_error: Optional[Dict[str, Any]] = None
        self._last_outcomes: List[Dict[str, Any]] = []
        self._dossier: Optional[str] = None
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        if start:
            self.start()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        with self._cv:
            if self._thread is not None:
                return
            self._stop = False
            self._thread = threading.Thread(target=self._run, name="witness-log-witnesser", daemon=True)
            self._thread.start()

    def close(self, timeout: float = 5.0) -> None:
        """Stop the background thread (waits at most ``timeout``)."""
        with self._cv:
            self._stop = True
            self._cv.notify_all()
            t = self._thread
        if t is not None:
            t.join(timeout)
        with self._cv:
            self._thread = None

    def __enter__(self) -> "Witnesser":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- the non-blocking API ------------------------------------------------

    def request(self) -> None:
        """Ask for the current head to be witnessed. Returns immediately;
        never raises (a closed or broken log is reported in ``status``)."""
        try:
            size = self._log.tree_size()
        except Exception as e:  # noqa: BLE001 -- never raise into the agent
            self._record_error("exception", f"{type(e).__name__}: {e}", [])
            return
        with self._cv:
            if size > self._requested:
                self._requested = size
                self._next_at = min(self._next_at, time.monotonic()) if self._fails == 0 else self._next_at
            self._cv.notify_all()

    def status(self) -> WitnessStatus:
        with self._cv:
            return WitnessStatus(
                running=self._thread is not None and self._thread.is_alive(),
                requested_size=self._requested,
                witnessed_size=self._witnessed,
                cosignatures=self._cosigs,
                rounds=self._rounds,
                failures_in_a_row=self._fails,
                next_attempt_in_s=max(0.0, self._next_at - time.monotonic()),
                last_error=dict(self._last_error) if self._last_error else None,
                last_outcomes=list(self._last_outcomes),
            )

    @property
    def last_error(self) -> Optional[Dict[str, Any]]:
        return self.status().last_error

    def dossier(self) -> Optional[str]:
        """The dossier for the largest witnessed head (JSON), with its
        cosignatures and the directory; ``None`` before the first
        successful round."""
        with self._cv:
            return self._dossier

    def flush(self, timeout: float = 30.0) -> bool:
        """Request the current head and wait up to ``timeout`` seconds for
        it to be witnessed. ``True`` if it was; ``False`` on timeout (see
        ``status().last_error``). Never raises."""
        self.request()
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cv:
            target = self._requested
            # A flush is an explicit "try now": skip any backoff wait.
            self._next_at = time.monotonic()
            self._cv.notify_all()
            while self._witnessed < target:
                left = deadline - time.monotonic()
                if left <= 0 or self._thread is None:
                    return False
                self._cv.wait(min(left, 0.5))
            return True

    async def aflush(self, timeout: float = 30.0) -> bool:
        """``flush`` for asyncio code: waits in a worker thread, so the
        event loop keeps running."""
        return await asyncio.to_thread(self.flush, timeout)

    def submit_now(self) -> RoundResult:
        """Run one round in the caller's thread (blocking). For scripts and
        tests; agents should use ``request``/``flush``."""
        return self._round()

    # -- internals -----------------------------------------------------------

    def _record_error(self, kind: str, message: str, outcomes: List[Dict[str, Any]]) -> None:
        with self._cv:
            self._last_error = {"time": time.time(), "kind": kind, "message": message, "outcomes": outcomes}

    def _round(self) -> RoundResult:
        r = submit_round(
            self._log,
            self._directory,
            self._state_path,
            max_witnesses=self._max_witnesses,
            timeout=self._timeout,
            post=self._post,
        )
        with self._cv:
            self._rounds += 1
            self._last_outcomes = r.outcomes
            if r.refused:
                self._last_error = {"time": time.time(), "kind": "refused", "message": r.refused, "outcomes": []}
            elif r.cosignatures >= self._min:
                if r.tree_size >= self._witnessed:
                    self._witnessed = r.tree_size
                    self._cosigs = r.cosignatures
                    self._dossier = r.dossier_json
                self._last_error = None
            else:
                kind = "no_cosignatures" if r.cosignatures == 0 else "too_few"
                self._last_error = {
                    "time": time.time(),
                    "kind": kind,
                    "message": f"{r.cosignatures}/{r.contacted} witnesses cosigned size {r.tree_size}; "
                    f"need {self._min}",
                    "outcomes": r.outcomes,
                }
            self._cv.notify_all()
        return r

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._stop:
                    now = time.monotonic()
                    if self._interval > 0 and now >= self._next_at and self._requested <= self._witnessed:
                        # Timer tick: pick up whatever the agent appended.
                        try:
                            self._requested = max(self._requested, self._log.tree_size())
                        except Exception as e:  # noqa: BLE001
                            self._last_error = {
                                "time": time.time(),
                                "kind": "exception",
                                "message": f"{type(e).__name__}: {e}",
                                "outcomes": [],
                            }
                        if self._requested <= self._witnessed:
                            self._next_at = now + self._interval
                    if self._requested > self._witnessed and now >= self._next_at:
                        break
                    pending = self._requested > self._witnessed or self._interval > 0
                    wait = max(0.01, min(self._next_at - now, 1.0)) if pending else None
                    self._cv.wait(wait)
                if self._stop:
                    return
            try:
                r = self._round()
                ok = r.refused is None and r.cosignatures >= self._min
            except Exception as e:  # noqa: BLE001 -- the thread must survive anything
                self._record_error("exception", f"{type(e).__name__}: {e}", [])
                ok = False
            with self._cv:
                if ok:
                    self._fails = 0
                    self._next_at = time.monotonic() + self._interval
                else:
                    self._fails += 1
                    delay = min(self._bmax, self._b0 * (2 ** min(self._fails - 1, 16)))
                    self._next_at = time.monotonic() + delay * (0.5 + random.random() / 2)
                self._cv.notify_all()
