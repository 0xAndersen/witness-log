"""LangChain / LangGraph: a callback handler that records every tool call.

::

    from witness_log.integrations.langchain import WitnessLogCallbackHandler
    handler = WitnessLogCallbackHandler(witness_log.open("agent.jsonl"))
    agent.invoke({"messages": [...]}, config={"callbacks": [handler]})

Calls are paired by LangChain's ``run_id``, so parallel tool calls are
recorded correctly.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from . import Recorder

__all__ = ["WitnessLogCallbackHandler"]


def _value(output: Any) -> Any:
    # A ToolMessage (LangChain >= 0.3) carries the tool's return in .content.
    return getattr(output, "content", output)


class WitnessLogCallbackHandler(BaseCallbackHandler):
    """Intent leaf in ``on_tool_start``, result leaf in ``on_tool_end`` /
    ``on_tool_error``. ``record_output=False`` keeps return values out of
    the result leaf (errors are still recorded)."""

    def __init__(self, log: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        super().__init__()
        self.recorder = Recorder(log, record_output=record_output, raise_on_error=raise_on_error)
        self.raise_error = raise_on_error
        self._pending: Dict[UUID, tuple] = {}

    @property
    def errors(self) -> list:
        return self.recorder.errors

    def on_tool_start(
        self,
        serialized: Optional[Dict[str, Any]],
        input_str: str,
        *,
        run_id: UUID,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        args = inputs if inputs is not None else input_str
        self._pending[run_id] = (name, self.recorder.intent(name, args, run_id=str(run_id)))

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        name, i = self._pending.pop(run_id, ("tool", None))
        self.recorder.result(name, i, _value(output))

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        name, i = self._pending.pop(run_id, ("tool", None))
        self.recorder.result(name, i, f"{type(error).__name__}: {error}", outcome="error")
