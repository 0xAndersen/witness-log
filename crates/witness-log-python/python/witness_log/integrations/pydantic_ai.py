"""pydantic-ai: a ``WrapperToolset`` that records every tool call it
delegates.

::

    from pydantic_ai import Agent
    from pydantic_ai.toolsets import FunctionToolset
    from witness_log.integrations.pydantic_ai import WitnessLogToolset

    tools = FunctionToolset([get_balance, send_invoice])
    agent = Agent("openai:gpt-4o", toolsets=[WitnessLogToolset(tools, witness_log.open("agent.jsonl"))])

``WitnessLogToolset(wrapped, target)`` keeps pydantic-ai's own argument
order (``wrapped`` first, as ``WrapperToolset`` does). ``target`` is a
log or an :class:`~witness_log.integrations.AgentJournals`, in which case
the journal is chosen by the agent's ``name``.

Calls are paired by ``RunContext.tool_call_id``; the arguments recorded
are the validated ones pydantic-ai hands to the tool. A tool that raises
``ModelRetry`` (asking the model to try again) is recorded as
``outcome: "error"`` with ``retry: true``; any other exception is
recorded as ``"error"`` and re-raised unchanged, so the agent's behaviour
does not change. pydantic-ai has no built-in handoff; an agent used as a
tool is recorded as the tool call it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from pydantic_ai.exceptions import ModelRetry
from pydantic_ai.toolsets import WrapperToolset

from . import Sink

__all__ = ["WitnessLogToolset"]


def _plain(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if hasattr(v, "model_dump"):
        try:
            return v.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            return repr(v)
    return v


@dataclass
class WitnessLogToolset(WrapperToolset[Any]):
    """Intent leaf before ``wrapped.call_tool``, result leaf after.

    ``target`` is required; ``sink`` is derived from it and shared by the
    copies pydantic-ai makes with ``dataclasses.replace`` (``for_run``,
    ``visit_and_replace``), so one record spans the whole run."""

    target: Any = None
    record_output: bool = True
    raise_on_error: bool = False
    sink: Optional[Sink] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.sink is None:
            if self.target is None:
                raise TypeError("WitnessLogToolset(wrapped, target): target (a log or AgentJournals) is required")
            self.sink = Sink(self.target, record_output=self.record_output, raise_on_error=self.raise_on_error)

    @property
    def id(self) -> Optional[str]:
        return self.wrapped.id

    @property
    def errors(self) -> list:
        assert self.sink is not None
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        assert self.sink is not None
        return self.sink.recorder()

    async def call_tool(self, name: str, tool_args: Dict[str, Any], ctx: Any, tool: Any) -> Any:
        assert self.sink is not None
        agent = getattr(getattr(ctx, "agent", None), "name", None)
        call_id = getattr(ctx, "tool_call_id", None)
        rec = self.sink.recorder(agent)
        i = rec.intent(name, _plain(dict(tool_args)), call_id=call_id, agent=agent, run_step=getattr(ctx, "run_step", None))
        try:
            out = await self.wrapped.call_tool(name, tool_args, ctx, tool)
        except ModelRetry as e:
            rec.result(name, i, f"ModelRetry: {e}", outcome="error", call_id=call_id, retry=True)
            raise
        except BaseException as e:  # noqa: BLE001 -- recorded, then re-raised unchanged
            rec.result(name, i, f"{type(e).__name__}: {e}", outcome="error", call_id=call_id)
            raise
        rec.result(name, i, _plain(out), call_id=call_id)
        return out
