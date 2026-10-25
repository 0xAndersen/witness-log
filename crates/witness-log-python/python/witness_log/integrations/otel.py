"""OpenTelemetry: one span processor turns an instrumented agent's traces
into a witness-log.

::

    import witness_log
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from witness_log.integrations.otel import WitnessLogSpanProcessor

    provider = TracerProvider()
    provider.add_span_processor(WitnessLogSpanProcessor(witness_log.open("agent.jsonl")))
    trace.set_tracer_provider(provider)

Any agent framework or instrumentation that emits the OpenTelemetry GenAI
semantic conventions (``gen_ai.*``: Google ADK, pydantic-ai / Logfire,
Strands, OpenLLMetry, the OpenTelemetry GenAI instrumentations) or
OpenInference (``openinference.span.kind``: Arize Phoenix and its
instrumentors for LangChain, LlamaIndex, OpenAI Agents, CrewAI, ...) is
then recorded, next to whatever exporter already sends those spans to your
observability backend. ``pip install "witness-log[otel]"``.

What is recorded:

* **Tool calls** (``gen_ai.operation.name = execute_tool``, or
  OpenInference ``TOOL``): an *intent* leaf when the span starts, before
  the tool runs, and a *result* leaf when it ends (``outcome`` ``ok`` or
  ``error`` from the span status). Payloads match the other adapters':
  ``{"tool", "args", "t_ms", ...}`` and ``{"tool", "intent_index",
  "outcome", "value"}``, plus ``source``, ``trace_id``, ``span_id``,
  ``parent_span_id`` and ``tool_call_id``. Arguments and results come
  from ``gen_ai.tool.call.arguments`` / ``gen_ai.tool.call.result`` or
  OpenInference ``input.value`` / ``output.value`` when the
  instrumentation records them. Arguments set only after the span started
  are added to the result leaf (``args_at_end``).
* **Model and agent calls** (``chat``, ``generate_content``,
  ``text_completion``, ``invoke_agent``, ``invoke_workflow``, or
  OpenInference ``LLM`` / ``AGENT``): one *memory* leaf
  when the span ends: operation, model, provider, agent, conversation id,
  token usage, finish reasons, outcome. Prompts and completions
  (``gen_ai.input.messages``, ``gen_ai.output.messages``) are left out
  unless ``record_content=True``.

Every payload is committed to the log as a salted hash; what the journal
keeps of the payload itself follows how the log was opened
(``store_payloads``), and ``.payloads`` keeps the exact bytes by leaf index
for later disclosure, as :class:`witness_log.integrations.Recorder` does.

The processor never raises into the tracing pipeline: a failed append is
kept in ``.errors`` (``raise_on_error=True`` raises instead). Callbacks may
arrive from several threads; appends are serialised by the log.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Mapping, Optional

from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
from opentelemetry.trace import StatusCode

import witness_log

from . import Recorder

__all__ = ["WitnessLogSpanProcessor"]

TOOL_OPERATIONS = frozenset({"execute_tool"})
CALL_OPERATIONS = frozenset({"chat", "generate_content", "text_completion", "invoke_agent", "invoke_workflow"})
# OpenInference span kinds (openinference.span.kind).
OI_TOOL = "TOOL"
OI_CALLS = frozenset({"LLM", "AGENT"})


def _hex(n: Optional[int], width: int) -> Optional[str]:
    return None if n is None else format(n, f"0{width}x")


def _json_or_text(v: Any) -> Any:
    """An attribute holding JSON (tool arguments, results) as the value it
    encodes; anything else as given."""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    if isinstance(v, (list, tuple)):
        return list(v)
    return v


def _first(attrs: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        v = attrs.get(k)
        if v is not None:
            return v
    return None


class WitnessLogSpanProcessor(SpanProcessor):
    """An OpenTelemetry ``SpanProcessor`` that writes witness-log leaves
    for GenAI tool, model and agent spans. See the module docstring."""

    def __init__(
        self,
        log: Any,
        *,
        record_inputs: bool = True,
        record_outputs: bool = True,
        record_content: bool = False,
        record_calls: bool = True,
        raise_on_error: bool = False,
        keep_payloads: bool = True,
    ) -> None:
        self.log = log
        self.record_inputs = record_inputs
        self.record_content = record_content
        self.record_calls = record_calls
        self.raise_on_error = raise_on_error
        self.recorder = Recorder(
            log, record_output=record_outputs, raise_on_error=raise_on_error, keep_payloads=keep_payloads
        )
        self._pending: Dict[int, Optional[int]] = {}
        self._lock = threading.Lock()

    @property
    def errors(self) -> List[str]:
        return self.recorder.errors

    @property
    def payloads(self) -> Dict[int, bytes]:
        return self.recorder.payloads

    # -- classification ---------------------------------------------------

    @staticmethod
    def _kind(attrs: Mapping[str, Any]) -> Optional[str]:
        op = attrs.get("gen_ai.operation.name")
        oi = attrs.get("openinference.span.kind")
        if op in TOOL_OPERATIONS or oi == OI_TOOL:
            return "tool"
        if op in CALL_OPERATIONS or oi in OI_CALLS:
            return "call"
        return None

    @staticmethod
    def _ids(span: Any) -> Dict[str, Optional[str]]:
        ctx = span.get_span_context()
        parent = getattr(span, "parent", None)
        return {
            "trace_id": _hex(getattr(ctx, "trace_id", None), 32),
            "span_id": _hex(getattr(ctx, "span_id", None), 16),
            "parent_span_id": _hex(getattr(parent, "span_id", None), 16) if parent is not None else None,
        }

    @staticmethod
    def _tool_name(span: Any, attrs: Mapping[str, Any]) -> str:
        name = _first(attrs, "gen_ai.tool.name", "tool.name")
        if name is None:
            # "execute_tool {gen_ai.tool.name}" is the conventional span name.
            name = span.name[len("execute_tool ") :] if span.name.startswith("execute_tool ") else span.name
        return str(name)

    def _args(self, attrs: Mapping[str, Any]) -> Any:
        if not self.record_inputs:
            return None
        v = _first(attrs, "gen_ai.tool.call.arguments", "tool.parameters", "input.value")
        return None if v is None else _json_or_text(v)

    # -- SpanProcessor ----------------------------------------------------

    def on_start(self, span: Span, parent_context: Any = None) -> None:
        try:
            attrs = span.attributes or {}
            if self._kind(attrs) != "tool":
                return
            ids = self._ids(span)
            idx = self.recorder.intent(
                self._tool_name(span, attrs),
                self._args(attrs),
                source="otel",
                tool_call_id=attrs.get("gen_ai.tool.call.id"),
                **ids,
            )
            with self._lock:
                self._pending[span.get_span_context().span_id] = idx
        except Exception as e:  # noqa: BLE001 -- never break tracing unless asked
            self._fail("on_start", e)

    def on_end(self, span: ReadableSpan) -> None:
        try:
            attrs = span.attributes or {}
            kind = self._kind(attrs)
            if kind == "tool":
                self._tool_end(span, attrs)
            elif kind == "call" and self.record_calls:
                self._call_end(span, attrs)
        except Exception as e:  # noqa: BLE001
            self._fail("on_end", e)

    def shutdown(self) -> None:
        sync = getattr(self.log, "sync", None)
        if callable(sync):
            try:
                sync()
            except Exception as e:  # noqa: BLE001
                self._fail("shutdown", e)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        self.shutdown()
        return True

    # -- leaves -----------------------------------------------------------

    def _tool_end(self, span: ReadableSpan, attrs: Mapping[str, Any]) -> None:
        with self._lock:
            known = span.context.span_id in self._pending
            intent_index = self._pending.pop(span.context.span_id, None)
        tool = self._tool_name(span, attrs)
        ids = self._ids(span)
        extra: Dict[str, Any] = {"source": "otel", "tool_call_id": attrs.get("gen_ai.tool.call.id"), **ids}
        if not known:
            # Started before this processor was added: write the intent now,
            # so the pair stays complete (marked as written at the end).
            intent_index = self.recorder.intent(tool, self._args(attrs), late=True, **extra)
        elif self.record_inputs:
            args = self._args(attrs)
            if args is not None:
                extra["args_at_end"] = args
        failed = span.status is not None and span.status.status_code == StatusCode.ERROR
        if failed:
            value: Any = span.status.description or _first(attrs, "error.type", "exception.message") or "error"
        else:
            out = _first(attrs, "gen_ai.tool.call.result", "output.value")
            value = None if out is None else _json_or_text(out)
        self.recorder.result(tool, intent_index, value, outcome="error" if failed else "ok", **extra)

    def _call_end(self, span: ReadableSpan, attrs: Mapping[str, Any]) -> None:
        failed = span.status is not None and span.status.status_code == StatusCode.ERROR
        payload: Dict[str, Any] = {
            "profile": "otel.gen_ai.call/1",
            "source": "otel",
            "span_name": span.name,
            "operation": _first(attrs, "gen_ai.operation.name", "openinference.span.kind"),
            "model": _first(attrs, "gen_ai.response.model", "gen_ai.request.model", "llm.model_name"),
            "provider": _first(attrs, "gen_ai.provider.name", "gen_ai.system", "llm.provider", "llm.system"),
            "agent": _first(attrs, "gen_ai.agent.name", "agent.name"),
            "agent_id": attrs.get("gen_ai.agent.id"),
            "conversation_id": _first(attrs, "gen_ai.conversation.id", "session.id"),
            "response_id": attrs.get("gen_ai.response.id"),
            "finish_reasons": _json_or_text(attrs.get("gen_ai.response.finish_reasons")),
            "usage": {
                "input_tokens": _first(attrs, "gen_ai.usage.input_tokens", "llm.token_count.prompt"),
                "output_tokens": _first(attrs, "gen_ai.usage.output_tokens", "llm.token_count.completion"),
            },
            "outcome": "error" if failed else "ok",
            "start_ns": span.start_time,
            "end_ns": span.end_time,
            "t_ms": time.time_ns() // 1_000_000,
            **self._ids(span),
        }
        if failed:
            payload["error"] = span.status.description or attrs.get("error.type") or "error"
        if self.record_content:
            payload["input_messages"] = _json_or_text(_first(attrs, "gen_ai.input.messages", "input.value"))
            payload["output_messages"] = _json_or_text(_first(attrs, "gen_ai.output.messages", "output.value"))
        payload = {k: v for k, v in payload.items() if v is not None}
        data = witness_log.canonical_json(payload)
        idx = self.log.append_memory(data)
        if self.recorder.keep_payloads:
            self.recorder.payloads[idx] = data

    def _fail(self, where: str, e: BaseException) -> None:
        self.recorder.errors.append(f"{where}: {type(e).__name__}: {e}")
        if self.raise_on_error:
            raise e

