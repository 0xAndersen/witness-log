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
import functools
import http.client
import ipaddress
import json
import os
import queue
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _core

__all__ = ["Witnesser", "WitnessStatus", "RoundResult", "submit_round", "load_state", "save_state"]

# Same bound the CLI applies to a witness's Retry-After (its enrollment
# windows are a minute).
MAX_RETRY_AFTER_S = 60
ATTEMPTS_PER_WITNESS = 6

Post = Callable[..., Tuple[int, str, int]]
#: ``guard(host, port)`` vets where a witness URL may be sent: it returns
#: the resolved addresses the connection may use, or raises ``ValueError``.
Guard = Callable[[str, int], List[Tuple[Any, ...]]]

# Addresses that are never a witness, whoever supplied the directory entry:
# cloud instance-metadata services, reached over a link-local or provider
# address, hand out credentials to whatever asks.
METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, ...
        "169.254.170.2",  # AWS ECS task metadata
        "fd00:ec2::254",  # AWS IPv6
        "fd20:ce::254",  # GCP IPv6
        "100.100.100.200",  # Alibaba Cloud
        "168.63.129.16",  # Azure WireServer (a public address, reachable only from inside Azure)
    )
)
# Never a witness, whatever the operator allows: the local-use NAT64 prefix
# (RFC 8215) carries an IPv4 address at a position this host cannot know,
# so it could be link-local or metadata; site-local (fec0::/10) is
# deprecated, and Python counts it as global.
NEVER_WITNESS_NETWORKS = (ipaddress.ip_network("64:ff9b:1::/48"),)
NOT_PUBLIC_NETWORKS = (ipaddress.ip_network("fec0::/10"),)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A witness answers ``add-checkpoint`` itself. urllib follows a 301,
    302 or 303 to a POST with a GET to wherever ``Location`` points, which
    lets a directory entry bounce the client to an address no entry could
    name directly; a redirect is a failure for that witness instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001,D102
        return None


def _pinned_connection(base: type, addresses: List[Tuple[Any, ...]]) -> type:
    """An ``http.client`` connection class that connects only to
    ``addresses`` (what the guard vetted), never resolving the host again:
    a second lookup could answer differently (DNS rebinding). TLS still
    verifies the certificate against the host name."""

    def create(address: Tuple[str, int], timeout: Any = socket._GLOBAL_DEFAULT_TIMEOUT, source_address: Any = None) -> socket.socket:
        err: Optional[OSError] = None
        for family, socktype, proto, _canon, sockaddr in addresses:
            s = socket.socket(family, socktype, proto)
            try:
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    s.settimeout(timeout)
                if source_address:
                    s.bind(source_address)
                s.connect(sockaddr)
                return s
            except OSError as e:
                err = e
                s.close()
        raise err or OSError(f"no address to connect to for {address[0]}")

    class Pinned(base):  # type: ignore[valid-type,misc]
        def __init__(self, *a: Any, **kw: Any) -> None:
            super().__init__(*a, **kw)
            self._create_connection = create

    return Pinned


#: The operator's switch that lets a caller-supplied directory name
#: loopback and private addresses (a local testnet). Link-local and
#: metadata addresses stay refused.
ALLOW_PRIVATE_ENV = "WITNESS_LOG_ALLOW_PRIVATE_WITNESSES"


_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")  # RFC 4291, deprecated
_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")  # RFC 2765 (SIIT)


def _embedded_ipv4(ip: Any) -> List[Any]:
    """The IPv4 addresses an IPv6 address carries and a translator or
    tunnel would deliver to: IPv4-mapped, IPv4-compatible, SIIT-translated,
    NAT64 (64:ff9b::/96), 6to4 and both Teredo addresses."""
    if ip.version != 6:
        return []
    out: List[Any] = []
    low32 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.ipv4_mapped is not None:
        out.append(ip.ipv4_mapped)
    if ip in _NAT64_WELL_KNOWN or ip in _IPV4_TRANSLATED or (ip in _IPV4_COMPATIBLE and int(ip) > 1):
        out.append(low32)
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    return out


def witness_address_guard(allow_private: bool = False) -> Guard:
    """A guard for witness URLs from a directory nobody vetted (one an MCP
    caller passed). Resolves the host and refuses it if ANY address is
    link-local (169.254.0.0/16, fe80::/10), a cloud metadata address,
    unspecified or multicast; and, unless ``allow_private``, if any is
    loopback, private or otherwise not globally routable. Returns the
    addresses, which :func:`_post` then connects to without resolving
    again."""

    def guard(host: str, port: int) -> List[Tuple[Any, ...]]:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            raise ValueError(f"witness host {host!r} does not resolve: {e}") from e
        for info in infos:
            resolved = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
            # An IPv6 address can carry an IPv4 one (mapped, compatible,
            # NAT64, 6to4, Teredo): a NAT64 gateway turns 64:ff9b::a9fe:a9fe
            # into 169.254.169.254. Every address it names must pass.
            named = [resolved, *_embedded_ipv4(resolved)]
            if any(
                ip in METADATA_ADDRESSES
                or ip.is_link_local
                or ip.is_unspecified
                or ip.is_multicast
                or any(ip in n for n in NEVER_WITNESS_NETWORKS if n.version == ip.version)
                for ip in named
            ):
                raise ValueError(
                    f"witness host {host!r} resolves to {resolved}, a link-local, metadata or otherwise "
                    "non-routable address; refused for a directory passed in a tool call"
                )
            if not allow_private and not all(
                ip.is_global and not any(ip in n for n in NOT_PUBLIC_NETWORKS if n.version == ip.version) for ip in named
            ):
                raise ValueError(
                    f"witness host {host!r} resolves to {resolved}, a loopback or private address; refused for "
                    f"a directory passed in a tool call (pin the directory with WITNESS_LOG_TRUSTED_DIRECTORY, "
                    f"or set {ALLOW_PRIVATE_ENV}=1 for a local testnet)"
                )
        return infos

    return guard


def _uses_proxy(scheme: str, host: str) -> bool:
    proxies = urllib.request.getproxies()
    return scheme in proxies and not urllib.request.proxy_bypass(host)


def _post(url: str, body: str, timeout: float, guard: Optional[Guard] = None) -> Tuple[int, str, int]:
    """POST ``body`` to ``<url>/add-checkpoint``. Returns
    ``(status, response_text, retry_after_seconds)``. Only http(s): a
    directory entry is caller-supplied, and ``urllib`` would otherwise
    happily read ``file://`` URLs (found by the 0.3.5 hostile-input
    evaluation against the MCP server, which returned the file's first
    200 bytes to the caller). Redirects are not followed (a 3xx is
    returned as the status). With a ``guard``, the host is vetted first
    and, unless a proxy carries the request, the connection goes only to
    the addresses the guard returned."""
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"witness url must be http:// or https://, got {url!r}")
    handlers: List[Any] = [_NoRedirect()]
    if guard is not None:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        addresses = guard(host, parts.port or (443 if parts.scheme == "https" else 80))
        if not _uses_proxy(parts.scheme, host):
            pinned_http = _pinned_connection(http.client.HTTPConnection, addresses)
            pinned_https = _pinned_connection(http.client.HTTPSConnection, addresses)

            class PinnedHTTP(urllib.request.HTTPHandler):
                def http_open(self, req):  # noqa: ANN001,D102
                    return self.do_open(pinned_http, req)

            class PinnedHTTPS(urllib.request.HTTPSHandler):
                def https_open(self, req):  # noqa: ANN001,D102
                    kw: Dict[str, Any] = {"context": self._context}
                    if hasattr(self, "_check_hostname"):  # Python < 3.12
                        kw["check_hostname"] = self._check_hostname
                    return self.do_open(pinned_https, req, **kw)

            handlers += [PinnedHTTP(), PinnedHTTPS()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url.rstrip("/") + "/add-checkpoint",
        data=body.encode(),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310 -- scheme checked above
            return r.status, r.read(1 << 20).decode("utf-8", "replace"), 0
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return e.code, "redirect not followed: a witness must answer add-checkpoint itself", 0
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
    last = raw.get("last_round")
    if not (isinstance(last, dict) and isinstance(last.get("size"), int) and isinstance(last.get("responses"), list)):
        last = None
    return {
        "sizes": {str(k).lower(): int(v) for k, v in sizes.items() if isinstance(v, int) and v >= 0},
        "cosigned_size": int(raw.get("cosigned_size") or 0) if isinstance(raw.get("cosigned_size", 0), int) else 0,
        "cosigned_root": str(raw.get("cosigned_root") or ""),
        "last_round": last,
    }


def save_state(path: str, state: Dict[str, Any]) -> None:
    """Atomic write (temp file, fsync, rename), mode 0600."""
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.{threading.get_ident()}.tmp")
    doc: Dict[str, Any] = {
        "sizes": dict(sorted(state["sizes"].items())),
        "cosigned_size": state["cosigned_size"],
        "cosigned_root": state["cosigned_root"],
    }
    if state.get("last_round"):
        # The raw witness responses of the latest successful round, so a
        # dossier with its cosignatures can be rebuilt later (``witnessed_dossier``)
        # without another round. The CLI ignores this field.
        doc["last_round"] = state["last_round"]
    data = json.dumps(doc, indent=2).encode()
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
    url_guard: Optional[Guard] = None,
) -> RoundResult:
    """One round: pin the current head, ask up to ``max_witnesses``
    diversity-selected witnesses to cosign it, return a dossier for that
    head carrying every cosignature that verifies. Raises only on bad
    arguments (``ValueError``); network failures are per-witness
    ``outcomes``. ``url_guard`` (see :func:`witness_address_guard`) vets
    each witness URL before anything is sent to it; a refused one is an
    outcome with status 0 and the reason."""
    directory = _parse_directory(directory)
    if url_guard is not None:
        post = functools.partial(post, guard=url_guard)
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
        state["last_round"] = {"size": size, "responses": [[pk, body] for pk, body in responses], "directory": directory}
    try:
        save_state(state_path, state)
    except OSError as e:
        outcomes.append({"witness": None, "status": 0, "error": f"could not save {state_path}: {e}"})
    doc["witness_directory"] = directory
    return RoundResult(size, n, len(picks), outcomes, json.dumps(doc))


def witnessed_dossier(log: Any, state_path: Optional[str] = None) -> Optional[str]:
    """The dossier for the latest head this log got cosigned, rebuilt from
    the responses ``submit``/``Witnesser`` saved in ``<journal>.witnesses.json``,
    with the cosignatures and the directory of that round. ``None`` when no
    round has succeeded. The head may be older than the current tree size:
    that dossier still verifies WITNESSED for what it covers.

    ``to_dossier_json()`` alone never carries receipts (the Rust log does
    not hold them), which is how exports taken after a successful submit
    came out CONSISTENT-UNWITNESSED in a 100,000-agent run."""
    if state_path is None:
        path = getattr(log, "path", None)
        if path is None:
            return None
        state_path = f"{path()}.witnesses.json"
    last = load_state(state_path).get("last_round")
    if not last:
        return None
    try:
        dossier_json, n = log.dossier_from_responses_at(int(last["size"]), [(pk, body) for pk, body in last["responses"]])
    except Exception:  # noqa: BLE001 -- the journal was rewritten or truncated; nothing to rebuild
        return None
    if n == 0:
        return None
    doc = json.loads(dossier_json)
    if last.get("directory") is not None:
        doc["witness_directory"] = last["directory"]
    return json.dumps(doc)


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
        # Wakes the background thread. request() only puts to it, so it
        # never contends for `_cv` with a thread that may be waiting for
        # the GIL while holding it.
        self._wakeups: "queue.SimpleQueue[None]" = queue.SimpleQueue()
        self._requested = 0
        # Set by request(); the background thread reads the log's size, so
        # request() itself never calls into the log.
        self._want_latest = False
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
        self._wakeups.put_nowait(None)
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
        never raises (a closed or broken log is reported in ``status``).

        It does not call into the log: the background thread reads the
        log's size. Before 0.5.0 it did, and could wait behind another
        thread's call on the same log (0.8% of calls took over 50 ms in
        the 100,000-agent swarm). It takes no lock either: a flag and a
        wakeup, so it cannot queue behind the background thread."""
        self._want_latest = True
        self._wakeups.put_nowait(None)

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
        try:
            size = self._log.tree_size()
        except Exception as e:  # noqa: BLE001 -- never raise into the agent
            self._record_error("exception", f"{type(e).__name__}: {e}", [])
            return False
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cv:
            self._requested = max(self._requested, size)
            target = self._requested
            # A flush is an explicit "try now": skip any backoff wait.
            self._next_at = time.monotonic()
            self._cv.notify_all()
            self._wakeups.put_nowait(None)
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

    def _resolve_latest(self, tick: bool) -> None:
        """Read the log's size (outside ``_cv``: the read can wait behind
        the agent's own calls on the log) and request it."""
        try:
            size: Optional[int] = self._log.tree_size()
        except Exception as e:  # noqa: BLE001
            self._record_error("exception", f"{type(e).__name__}: {e}", [])
            size = None
        with self._cv:
            if size is not None:
                self._requested = max(self._requested, size)
            if tick and self._requested <= self._witnessed:
                self._next_at = time.monotonic() + self._interval
            self._cv.notify_all()

    def _run(self) -> None:
        while True:
            resolve = tick = False
            wait: Optional[float] = -1.0  # -1: do not wait, act now
            with self._cv:
                if self._stop:
                    return
                now = time.monotonic()
                if self._want_latest:
                    self._want_latest = False
                    if self._fails == 0:
                        self._next_at = min(self._next_at, now)
                    resolve = True
                elif self._interval > 0 and now >= self._next_at and self._requested <= self._witnessed:
                    # Timer tick: pick up whatever the agent appended.
                    resolve = tick = True
                elif not (self._requested > self._witnessed and now >= self._next_at):
                    pending = self._requested > self._witnessed or self._interval > 0
                    wait = max(0.01, min(self._next_at - now, 1.0)) if pending else None
            if wait is None or wait >= 0:
                try:
                    self._wakeups.get(timeout=wait)
                except queue.Empty:
                    pass
                continue
            if resolve:
                self._resolve_latest(tick)
                continue
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
