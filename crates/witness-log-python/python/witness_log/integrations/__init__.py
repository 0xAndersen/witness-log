"""Framework adapters: an intent leaf before every tool call and a result
leaf after it, wired to each framework's own hook. Each submodule imports
its framework lazily, so ``import witness_log`` never needs them.

* ``witness_log.integrations.langchain`` -- ``WitnessLogCallbackHandler``
  (LangChain / LangGraph callbacks; ``pip install "witness-log[langchain]"``)
* ``witness_log.integrations.openai_agents`` -- ``WitnessLogHooks``
  (OpenAI Agents SDK ``RunHooks``; ``pip install "witness-log[openai-agents]"``)
* ``witness_log.integrations.crewai`` -- ``witness_crewai`` (CrewAI global
  tool-call hooks; ``pip install "witness-log[crewai]"``)

Payload shapes match :func:`witness_log.step`: the intent commits to
``{"tool", "args", "t", ...}``, the result to ``{"tool", "intent_index",
"outcome", "value"}``. A failure to append is never raised into the
framework unless ``raise_on_error=True``; it is kept in ``.errors``.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

import witness_log

__all__ = ["Recorder"]


class Recorder:
    """The shared part of every adapter: append the two leaves."""

    def __init__(self, log: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        self.log = log
        self.record_output = record_output
        self.raise_on_error = raise_on_error
        self.errors: List[str] = []

    def _append(self, kind: str, payload: dict) -> Optional[int]:
        try:
            fn = self.log.append_intent if kind == "intent" else self.log.append_result
            return fn(witness_log.canonical_json(payload))
        except Exception as e:  # noqa: BLE001 -- never break the agent unless asked
            self.errors.append(f"{kind}: {type(e).__name__}: {e}")
            if self.raise_on_error:
                raise
            return None

    def intent(self, tool: str, args: Any, **extra: Any) -> Optional[int]:
        return self._append("intent", {"tool": tool, "args": args, "t": time.time(), **extra})

    def result(self, tool: str, intent_index: Optional[int], value: Any, outcome: str = "ok") -> Optional[int]:
        payload = {"tool": tool, "intent_index": intent_index, "outcome": outcome}
        if self.record_output or outcome == "error":
            payload["value"] = value
        return self._append("result", payload)
