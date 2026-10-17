"""Framework adapters: an intent leaf before every tool call and a result
leaf after it, wired to each framework's own hook. Each submodule imports
its framework lazily, so ``import witness_log`` never needs them.

* ``witness_log.integrations.langchain`` -- ``WitnessLogCallbackHandler``
  (LangChain callbacks; ``pip install "witness-log[langchain]"``)
* ``witness_log.integrations.langgraph`` -- ``WitnessLogGraphHandler``
  (LangGraph: same callbacks plus ``Command(goto=...)`` handoffs;
  ``pip install "witness-log[langgraph]"``)
* ``witness_log.integrations.openai_agents`` -- ``WitnessLogAudit`` /
  ``WitnessLogHooks`` (OpenAI Agents SDK ``RunHooks`` and a
  ``TracingProcessor``; ``pip install "witness-log[openai-agents]"``)
* ``witness_log.integrations.google_adk`` -- ``WitnessLogPlugin``
  (Google ADK ``BasePlugin``; ``pip install "witness-log[google-adk]"``)
* ``witness_log.integrations.pydantic_ai`` -- ``WitnessLogToolset``
  (pydantic-ai ``WrapperToolset``; ``pip install "witness-log[pydantic-ai]"``)
* ``witness_log.integrations.autogen`` -- ``WitnessLogAutoGen``
  (AutoGen AgentChat event stream; ``pip install "witness-log[autogen]"``)
* ``witness_log.integrations.llamaindex`` -- ``WitnessLogLlamaIndex``
  (LlamaIndex workflow events + instrumentation handler;
  ``pip install "witness-log[llamaindex]"``)
* ``witness_log.integrations.crewai`` -- ``witness_crewai`` (CrewAI global
  tool-call hooks; ``pip install "witness-log[crewai]"``)
* ``witness_log.integrations.claude_agent_sdk`` -- ``witness_hooks`` /
  ``WitnessLogClaudeHooks`` (Claude Agent SDK ``PreToolUse`` /
  ``PostToolUse`` / ``PostToolUseFailure`` hooks;
  ``pip install "witness-log[claude-agent-sdk]"``)

Payload shapes match :func:`witness_log.step`: the intent commits to
``{"tool", "args", "t", ...}``, the result to ``{"tool", "intent_index",
"outcome", "value"}``. The Claude Agent SDK adapter is the exception: it
writes the Claude Code hook's ``hook.claude-code v1`` payloads (results
add ``intent_index``), so its records read like ``witness-log-hook``'s. A
failure to append is never raised into the framework unless
``raise_on_error=True``; it is kept in ``.errors``. (The Claude Agent SDK
adapter never raises; its ``strict=True`` denies the tool call instead.)

Two building blocks are shared by every adapter and usable on their own:
:class:`Recorder` (the two leaves on one log, payloads kept for later
disclosure) and :class:`AgentJournals` (one journal per agent identity
under a directory, with handoff leaves written on both sides).
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import witness_log

__all__ = ["Recorder", "AgentJournals", "Sink", "handoff_state"]


class Recorder:
    """The shared part of every adapter: append the two leaves.

    ``payloads`` keeps the exact bytes appended, by leaf index, so a leaf
    can later be disclosed (``witness_log.profiles.ap2.dispute_export``
    takes this mapping). Set ``keep_payloads=False`` to not retain them.
    """

    def __init__(
        self,
        log: Any,
        *,
        record_output: bool = True,
        raise_on_error: bool = False,
        keep_payloads: bool = True,
    ) -> None:
        self.log = log
        self.record_output = record_output
        self.raise_on_error = raise_on_error
        self.keep_payloads = keep_payloads
        self.errors: List[str] = []
        self.payloads: Dict[int, bytes] = {}

    def _append(self, kind: str, payload: dict) -> Optional[int]:
        try:
            fn = self.log.append_intent if kind == "intent" else self.log.append_result
            data = witness_log.canonical_json(payload)
            idx = fn(data)
            if self.keep_payloads:
                self.payloads[idx] = data
            return idx
        except Exception as e:  # noqa: BLE001 -- never break the agent unless asked
            self.errors.append(f"{kind}: {type(e).__name__}: {e}")
            if self.raise_on_error:
                raise
            return None

    def intent(self, tool: str, args: Any, **extra: Any) -> Optional[int]:
        return self._append("intent", {"tool": tool, "args": args, "t_ms": time.time_ns() // 1_000_000, **extra})

    def result(self, tool: str, intent_index: Optional[int], value: Any, outcome: str = "ok", **extra: Any) -> Optional[int]:
        payload = {"tool": tool, "intent_index": intent_index, "outcome": outcome, **extra}
        if self.record_output or outcome == "error":
            payload["value"] = value
        return self._append("result", payload)


def handoff_state(from_agent: str, to_agent: str, **content: Any) -> bytes:
    """The bytes both sides of a handoff commit to (``handoff_state_hash``
    is their unsalted SHA-256). Deterministic: the same arguments give the
    same bytes on both sides."""
    return witness_log.canonical_json({"from": from_agent, "to": to_agent, **content})


_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _filename(agent: str) -> str:
    name = _SAFE.sub("_", str(agent)).strip("._") or "agent"
    return name + ".jsonl"


class AgentJournals:
    """One journal per agent identity, under ``directory``.

    ::

        journals = AgentJournals("audit/", seed_for=my_kms.seed_for, sealed=True)
        log = journals.log("triage")                   # <directory>/triage.jsonl, created or resumed
        journals.handoff("triage", "billing", state)   # Sent leaf in triage's journal, Received in billing's

    ``seed_for(agent_name) -> bytes`` supplies each agent's 32-byte
    identity seed (from your KMS); with ``sealed=True`` the seed is kept
    out of the journal and is needed on every resume. Without
    ``seed_for`` every journal gets a fresh identity stored in its own
    header (and ``sealed`` must be false). An existing file is resumed.

    All methods are safe to call from several threads; the per-agent
    :class:`Recorder` is shared, so leaves from one agent's parallel tool
    calls land in that agent's journal in append order.
    """

    def __init__(
        self,
        directory: str,
        *,
        seed_for: Optional[Callable[[str], bytes]] = None,
        sealed: Optional[bool] = None,
        record_output: bool = True,
        raise_on_error: bool = False,
    ) -> None:
        if sealed is None:
            sealed = seed_for is not None
        if sealed and seed_for is None:
            raise ValueError("sealed=True needs seed_for: a sealed journal stores no seed, so one must be supplied")
        self.directory = directory
        self.seed_for = seed_for
        self.sealed = sealed
        self.record_output = record_output
        self.raise_on_error = raise_on_error
        self._logs: Dict[str, Any] = {}
        self._recorders: Dict[str, Recorder] = {}
        self._lock = threading.RLock()
        os.makedirs(directory, exist_ok=True)

    # -- journals -------------------------------------------------------

    def path(self, agent: str) -> str:
        return os.path.join(self.directory, _filename(agent))

    def names(self) -> List[str]:
        with self._lock:
            return list(self._logs)

    def log(self, agent: str) -> Any:
        """The agent's :class:`~witness_log.JournaledLog`, opened on first use."""
        with self._lock:
            log = self._logs.get(agent)
            if log is None:
                seed = self.seed_for(agent) if self.seed_for is not None else None
                log = witness_log.open(self.path(agent), seed, seal=self.sealed)
                self._logs[agent] = log
            return log

    def recorder(self, agent: str) -> Recorder:
        with self._lock:
            rec = self._recorders.get(agent)
            if rec is None:
                rec = Recorder(self.log(agent), record_output=self.record_output, raise_on_error=self.raise_on_error)
                self._recorders[agent] = rec
            return rec

    def identity(self, agent: str) -> str:
        return self.log(agent).identity_pubkey_hex()

    @property
    def errors(self) -> List[str]:
        with self._lock:
            out: List[str] = []
            for name, rec in self._recorders.items():
                out.extend(f"{name}: {e}" for e in rec.errors)
            return out

    # -- cross-agent leaves ---------------------------------------------

    def handoff(self, from_agent: str, to_agent: str, state: bytes) -> Tuple[Optional[int], Optional[int]]:
        """A HandoffAttestation on both sides: ``Sent`` in ``from_agent``'s
        journal naming ``to_agent``'s identity, ``Received`` in
        ``to_agent``'s naming ``from_agent``'s. Both commit to
        ``SHA-256(state)``, so ``verify_handoff_binding`` matches them.
        Returns the two leaf indices (``None`` where an append failed and
        ``raise_on_error`` is off; the failure is in ``.errors``)."""
        sent = recv = None
        try:
            src, dst = self.log(from_agent), self.log(to_agent)
            sent = src.append_handoff_sent(state, dst.identity_pubkey_hex())
            recv = dst.append_handoff_received(state, src.identity_pubkey_hex())
        except Exception as e:  # noqa: BLE001
            self.recorder(from_agent).errors.append(f"handoff {from_agent}->{to_agent}: {type(e).__name__}: {e}")
            if self.raise_on_error:
                raise
        return sent, recv

    # -- after the run ---------------------------------------------------

    def sync(self) -> None:
        with self._lock:
            for log in self._logs.values():
                log.sync()

    def export_dossiers(self, write: bool = True) -> Dict[str, str]:
        """``{agent: dossier_json}`` for every journal opened so far; with
        ``write`` each is also written to ``<directory>/<agent>.dossier.json``."""
        out: Dict[str, str] = {}
        with self._lock:
            for name, log in self._logs.items():
                log.sync()
                doc = log.to_dossier_json()
                out[name] = doc
                if write:
                    with open(os.path.join(self.directory, _filename(name)[:-6] + ".dossier.json"), "w", encoding="utf-8") as f:
                        f.write(doc)
        return out

    def witness(self, directory: Any, *, max_witnesses: int = 8, timeout: float = 10.0) -> Dict[str, Any]:
        """One synchronous witnessing round per journal
        (:func:`witness_log.submit_round`), returning ``{agent:
        RoundResult}``. ``directory`` is the trusted witness directory
        (path, JSON text or dict). Each round's dossier, when any witness
        cosigned, is written to ``<directory>/<agent>.dossier.json``."""
        from ..witnessing import submit_round

        out: Dict[str, Any] = {}
        with self._lock:
            items = list(self._logs.items())
        for name, log in items:
            log.sync()
            r = submit_round(log, directory, self.path(name) + ".witnesses.json", max_witnesses=max_witnesses, timeout=timeout)
            out[name] = r
            if r.dossier_json is not None and r.cosignatures > 0:
                with open(os.path.join(self.directory, _filename(name)[:-6] + ".dossier.json"), "w", encoding="utf-8") as f:
                    f.write(r.dossier_json)
        return out

    def _one(self, agent: Optional[str]) -> str:
        if agent is not None:
            return agent
        names = self.names()
        if len(names) != 1:
            raise ValueError(f"agent= is required when there is not exactly one journal (have {names})")
        return names[0]

    def disclose(self, index: int, agent: Optional[str] = None) -> Dict[str, Any]:
        """Selective disclosure of one leaf: ``{leaf, payload, salt,
        verified}`` from this process's kept payloads and the journal's
        salt sidecar (see :mod:`witness_log.profiles._disclose`). A leaf
        whose payload this process did not append, or that was forgotten,
        comes back with ``complete: False``."""
        import json

        from ..profiles import _disclose

        agent = self._one(agent)
        log = self.log(agent)
        log.sync()
        leaves = json.loads(log.leaves_json())
        if not 0 <= index < len(leaves):
            raise IndexError(f"leaf {index} is not in {agent}'s journal (tree size {len(leaves)})")
        salts = _disclose.read_salts(self.path(agent))
        return _disclose.disclosure(leaves[index], self.recorder(agent).payloads.get(index), salts.get(index))

    def forget(self, index: int, agent: Optional[str] = None) -> bool:
        """Erase one leaf's content (``JournaledLog.forget``) and drop the
        kept payload. True if something was erased."""
        agent = self._one(agent)
        ok = self.log(agent).forget(index)
        self.recorder(agent).payloads.pop(index, None)
        return ok

    def close(self) -> None:
        with self._lock:
            for log in self._logs.values():
                try:
                    log.close()
                except Exception:  # noqa: BLE001
                    pass
            self._logs.clear()
            self._recorders.clear()

    def __enter__(self) -> "AgentJournals":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Sink:
    """What an adapter writes to: a single log (every agent in the run
    shares one journal) or an :class:`AgentJournals` (one per agent). With
    a single log a handoff is visible as the handoff tool's own intent /
    result pair, annotated ``handoff_to``; with journals it also gets the
    Sent / Received leaves on both sides."""

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        if isinstance(target, AgentJournals):
            self.journals: Optional[AgentJournals] = target
            self._single: Optional[Recorder] = None
        else:
            self.journals = None
            self._single = Recorder(target, record_output=record_output, raise_on_error=raise_on_error)

    def recorder(self, agent: Optional[str] = None) -> Recorder:
        if self.journals is not None:
            return self.journals.recorder(agent or "agent")
        assert self._single is not None
        return self._single

    def handoff(self, from_agent: Optional[str], to_agent: str, state: bytes) -> Tuple[Optional[int], Optional[int]]:
        if self.journals is None or from_agent is None:
            return None, None
        return self.journals.handoff(from_agent, to_agent, state)

    @property
    def errors(self) -> List[str]:
        if self.journals is not None:
            return self.journals.errors
        assert self._single is not None
        return self._single.errors

    @property
    def payloads(self) -> Mapping[int, bytes]:
        """Kept payloads of the single log (for ``dispute_export``); with
        journals use ``journals.recorder(agent).payloads``."""
        if self._single is None:
            raise AttributeError("payloads are per agent with AgentJournals: journals.recorder(name).payloads")
        return self._single.payloads
