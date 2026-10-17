"""Claude Agent SDK: ``PreToolUse`` / ``PostToolUse`` / ``PostToolUseFailure``
hook callbacks that record every tool call, with the payloads the Claude
Code hook (``witness-log-hook``) writes.

::

    import witness_log
    from claude_agent_sdk import ClaudeAgentOptions, query
    from witness_log.integrations.claude_agent_sdk import WitnessLogClaudeHooks, witness_hooks

    log = witness_log.open("agent.jsonl")
    options = ClaudeAgentOptions(hooks=witness_hooks(log), allowed_tools=["Read", "Grep"])
    async for message in query(prompt="...", options=options):
        ...

    # or keep the recorder (.errors, .recorder.payloads) and merge into options you already have:
    audit = WitnessLogClaudeHooks(log)
    options = audit.options(ClaudeAgentOptions(model="...", hooks=my_hooks))   # a copy, hooks merged

The SDK hands a hook callback the same JSON object Claude Code pipes to a
command hook, so the payloads come from :func:`witness_log.hook.normalize`,
the function behind ``witness-log-hook``, and read the same in a dossier
from either:

* ``PreToolUse`` -> intent leaf: ``{"profile": "hook.claude-code v1",
  "event", "session_id", "tool_name", "tool_input", "tool_use_id",
  "cwd"}``, byte for byte what the hook writes for that event.
* ``PostToolUse`` -> result leaf: the same plus ``"tool_response"``, and
  ``"intent_index"``, the leaf index of the call's intent (the link every
  adapter's result carries; ``null`` when that intent was not recorded).
* ``PostToolUseFailure`` -> result leaf: the event as the profile records
  any other event (every field except ``transcript_path``, so ``"error"``
  and ``"is_interrupt"`` are in it; what ``witness-log-hook --kind result``
  writes), plus ``"intent_index"``.

Calls are paired by ``tool_use_id``, so parallel calls of one tool each
get their own intent and result. ``record_output=False`` leaves
``tool_response`` out of the result leaf (a failure's ``error`` is still
recorded). ``target`` is a log or an
:class:`~witness_log.integrations.AgentJournals`; with journals a call made
inside a subagent goes to the journal named by its ``agent_type`` and a
main-thread call to ``agent`` (default ``"main"``). The hook payload
itself does not name the subagent, as with ``witness-log-hook``.

A callback never raises into the SDK and never blocks the tool: a failed
append is kept in ``.errors`` and the callback answers ``{}`` (no
decision). With ``strict=True`` a ``PreToolUse`` whose intent leaf could
not be written answers ``permissionDecision: "deny"`` instead, so the tool
does not run unrecorded (``witness-log-hook --strict``). Raising is not
offered: Claude Code logs a failed hook callback and carries on, so it
would block nothing.

Only the hook configuration needs the SDK (``HookMatcher``,
``ClaudeAgentOptions``); it is imported when :meth:`WitnessLogClaudeHooks.hooks`
or :meth:`~WitnessLogClaudeHooks.options` is called, and this module
imports without it.
"""

from __future__ import annotations

import dataclasses
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Mapping, Optional, Tuple

from ..hook import normalize
from . import Recorder, Sink

__all__ = ["WitnessLogClaudeHooks", "witness_hooks"]

PRE, POST, FAILURE = "PreToolUse", "PostToolUse", "PostToolUseFailure"


def _sdk() -> Any:
    try:
        import claude_agent_sdk
    except ImportError as e:
        raise ImportError(
            "witness_log.integrations.claude_agent_sdk needs the Claude Agent SDK: "
            'pip install "witness-log[claude-agent-sdk]" (or pip install claude-agent-sdk)'
        ) from e
    return claude_agent_sdk


def _event(input_data: Any, tool_use_id: Optional[str]) -> Any:
    """A copy of the hook input, with the callback's ``tool_use_id`` filled
    in if the input lacks one (the CLI sends it in both places)."""
    if not isinstance(input_data, Mapping):
        return input_data
    ev = dict(input_data)
    if tool_use_id and not ev.get("tool_use_id"):
        ev["tool_use_id"] = tool_use_id
    return ev


class WitnessLogClaudeHooks:
    """Intent leaf in ``PreToolUse``, result leaf in ``PostToolUse`` /
    ``PostToolUseFailure``. :meth:`hooks` is the ``hooks=`` value for
    ``ClaudeAgentOptions``; :meth:`options` builds or copies the options
    with it merged in. The three callbacks are the SDK's ``HookCallback``
    (``async (input_data, tool_use_id, context) -> dict``)."""

    def __init__(
        self,
        target: Any,
        *,
        agent: str = "main",
        record_output: bool = True,
        strict: bool = False,
    ) -> None:
        self.sink = Sink(target, record_output=record_output, raise_on_error=False)
        self.agent = agent
        self.record_output = record_output
        self.strict = strict
        self._own_errors: List[str] = []
        self._pending: Dict[Any, Deque[Tuple[Optional[str], Optional[int]]]] = defaultdict(deque)
        self._lock = threading.Lock()

    @property
    def errors(self) -> List[str]:
        with self._lock:
            own = list(self._own_errors)
        return self.sink.errors + own

    @property
    def recorder(self) -> Recorder:
        """The single log's :class:`~witness_log.integrations.Recorder`
        (``.payloads`` for disclosure)."""
        return self.sink.recorder()

    # -- configuration (needs the SDK) ----------------------------------------

    def hooks(
        self,
        existing: Optional[Mapping[str, List[Any]]] = None,
        *,
        matcher: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, List[Any]]:
        """``{"PreToolUse": [...], "PostToolUse": [...], "PostToolUseFailure":
        [...]}`` for ``ClaudeAgentOptions(hooks=...)``. ``existing`` (your
        own hooks) is kept, with one ``HookMatcher`` per event appended;
        Claude Code runs the matchers of one event concurrently, so the
        order does not matter. ``matcher=None`` matches every tool."""
        HookMatcher = _sdk().HookMatcher
        out: Dict[str, List[Any]] = {str(k): list(v) for k, v in (existing or {}).items()}
        for event, fn in ((PRE, self.pre_tool_use), (POST, self.post_tool_use), (FAILURE, self.post_tool_use_failure)):
            out.setdefault(event, []).append(HookMatcher(matcher=matcher, hooks=[fn], timeout=timeout))
        return out

    def options(self, options: Any = None, **kwargs: Any) -> Any:
        """``ClaudeAgentOptions(**kwargs)`` with :meth:`hooks` merged in, or,
        given ``options``, a copy of it (``dataclasses.replace``, with
        ``kwargs`` applied) whose ``hooks`` keep the ones it had."""
        sdk = _sdk()
        if options is None:
            return sdk.ClaudeAgentOptions(**{**kwargs, "hooks": self.hooks(kwargs.get("hooks"))})
        existing = kwargs.pop("hooks", getattr(options, "hooks", None))
        return dataclasses.replace(options, hooks=self.hooks(existing), **kwargs)

    # -- the hook callbacks ---------------------------------------------------

    async def pre_tool_use(self, input_data: Any, tool_use_id: Optional[str], context: Any) -> Dict[str, Any]:
        """``PreToolUse``: the intent leaf. Answers ``{}`` (no decision), or a
        deny with ``strict=True`` when the leaf could not be written."""
        i: Optional[int] = None
        why: Optional[str] = None
        try:
            ev = _event(input_data, tool_use_id)
            _, payload = normalize(ev, "intent")
            who = self._journal(ev)
            i, why = self._append(who, "intent", payload)
            if i is not None or not self.strict:  # a denied call never gets a result
                with self._lock:
                    self._pending[self._key(ev)].append((who, i))
        except Exception as e:  # noqa: BLE001 -- never break the agent
            why = self._error(PRE, e)
        if i is None and self.strict:
            return {
                "hookSpecificOutput": {
                    "hookEventName": PRE,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"witness-log: the call could not be recorded, so it was not run (strict): {why}",
                }
            }
        return {}

    async def post_tool_use(self, input_data: Any, tool_use_id: Optional[str], context: Any) -> Dict[str, Any]:
        """``PostToolUse``: the result leaf. Answers ``{}`` (output unchanged)."""
        self._result(POST, input_data, tool_use_id)
        return {}

    async def post_tool_use_failure(self, input_data: Any, tool_use_id: Optional[str], context: Any) -> Dict[str, Any]:
        """``PostToolUseFailure``: the result leaf of a call that failed."""
        self._result(FAILURE, input_data, tool_use_id)
        return {}

    # -- internals ------------------------------------------------------------

    def _result(self, event: str, input_data: Any, tool_use_id: Optional[str]) -> None:
        try:
            ev = _event(input_data, tool_use_id)
            _, payload = normalize(ev, "result")
            key = self._key(ev)
            with self._lock:
                q = self._pending.get(key)
                entry = q.popleft() if q else None
                if q is not None and not q:
                    del self._pending[key]
            who, i = entry if entry is not None else (self._journal(ev), None)
            payload["intent_index"] = i
            if not (self.record_output and self.sink.recorder(who).record_output):  # AgentJournals(record_output=False) too
                payload.pop("tool_response", None)
            self._append(who, "result", payload)
        except Exception as e:  # noqa: BLE001
            self._error(event, e)

    def _journal(self, ev: Any) -> Optional[str]:
        if self.sink.journals is None:
            return None
        sub = ev.get("agent_type") if isinstance(ev, Mapping) else None
        return str(sub) if sub else self.agent

    @staticmethod
    def _key(ev: Any) -> Any:
        if not isinstance(ev, Mapping):
            return ("?",)
        tid = ev.get("tool_use_id")
        if tid:
            return str(tid)
        # No id at all (not seen from a real CLI): first in, first out per tool.
        return ("no-id", ev.get("session_id"), ev.get("agent_id"), ev.get("tool_name"))

    def _append(self, who: Optional[str], kind: str, payload: Dict[str, Any]) -> Tuple[Optional[int], Optional[str]]:
        """``(leaf index, None)``, or ``(None, reason)`` when the append failed
        (the reason is also in ``.errors``, put there by the Recorder)."""
        rec = self.sink.recorder(who)
        n = len(rec.errors)
        try:
            i = rec._append(kind, payload)
        except Exception:  # noqa: BLE001 -- AgentJournals(raise_on_error=True); already in rec.errors
            i = None
        if i is None:
            return None, rec.errors[-1] if len(rec.errors) > n else f"{kind}: append failed"
        return i, None

    def _error(self, event: str, e: BaseException) -> str:
        msg = f"{event}: {type(e).__name__}: {e}"
        with self._lock:
            self._own_errors.append(msg)
        return msg


def witness_hooks(
    target: Any,
    *,
    matcher: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Dict[str, List[Any]]:
    """The ``hooks=`` value for ``ClaudeAgentOptions``: every tool call as an
    intent leaf and a result leaf on ``target`` (a log or ``AgentJournals``).
    ``kwargs`` go to :class:`WitnessLogClaudeHooks`; use that class directly
    to keep ``.errors`` and the kept payloads."""
    return WitnessLogClaudeHooks(target, **kwargs).hooks(matcher=matcher, timeout=timeout)
