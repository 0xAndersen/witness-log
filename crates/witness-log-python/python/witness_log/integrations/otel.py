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
  OpenInference ``TOOL``): an *intent* leaf and a *result* leaf
  (``outcome`` ``ok`` or ``error`` from the span status). Payloads match
  the other adapters': ``{"tool", "args", "t_ms", ...}`` and ``{"tool",
  "intent_index", "outcome", "value"}``, plus ``source``, ``call_id``,
  ``trace_id``, ``span_id`` and ``parent_span_id``. Arguments and results
  come from ``gen_ai.tool.call.arguments`` / ``gen_ai.tool.call.result`` or
  OpenInference ``input.value`` / ``output.value`` when the
  instrumentation records them (never ``tool.parameters``, which is the
  tool's schema). A JSON object or array is recorded as the value it
  encodes; anything else as the text given.

  **When the intent is written.** The processor sees a span's attributes
  when it starts and when it ends. The intent is written at the start,
  before the tool runs, only if the instrumentation marks the span as a
  tool span when it creates it (``gen_ai.operation.name`` or
  ``openinference.span.kind`` set at creation). Several instrumentations
  set them only at the end (the OpenInference LangChain and LlamaIndex
  instrumentors, for example); their intents are written when the span
  ends, with ``"late": true``. Where the order matters, use the framework's
  own adapter (``witness_log.integrations.<framework>``), which records
  the intent before the call. Arguments set only after the span started
  are added to the result leaf as ``args_at_end``.
* **Model and agent calls** (``chat``, ``generate_content``,
  ``text_completion``, ``invoke_agent``, ``invoke_workflow``, or
  OpenInference ``LLM`` / ``AGENT``): one *memory* leaf when the span
  ends: operation, model, provider, agent, conversation id, token usage,
  finish reasons, outcome. Prompts and completions
  (``gen_ai.input.messages``, ``gen_ai.output.messages``) are left out
  unless ``record_content=True``.

**Sampling.** OpenTelemetry runs span processors only for spans the
sampler records. A ratio sampler, or a parent-based sampler under an
incoming ``traceparent`` that is not sampled, therefore drops leaves
without an error. Give this processor a ``TracerProvider`` whose sampler
records every span (the default ``ParentBased(ALWAYS_ON)`` does, except
under an unsampled parent), or a provider of its own.

Every payload is committed to the log as a salted hash; what the journal
keeps of the payload itself follows how the log was opened
(``store_payloads``). ``keep_payloads=True`` also keeps the exact bytes in
``.payloads`` by leaf index for later disclosure; it is off by default
here because a tracing processor lives as long as the process.

The processor never raises into the tracing pipeline: a failed append is
kept in ``.errors`` (``raise_on_error=True`` raises instead, inside the
SDK's processor loop, so the processors after this one miss that span:
for tests only). Callbacks may arrive from several threads; appends are
serialised by the log.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
# Google ADK wraps parallel tool calls in one extra span named this, whose
# tool name it sets to "(merged tools)"; the calls inside have their own.
MERGED_SPAN_NAMES = frozenset({"execute_tool (merged)"})
MERGED_TOOL_NAMES = frozenset({"(merged tools)"})
# Tool spans started but not ended are held at most this many at once; a
# span that never ends must not grow the processor without bound.
MAX_PENDING = 10_000


def _hex(n: Optional[int], width: int) -> Optional[str]:
    return None if n is None else format(n, f"0{width}x")


def _no_constant(name: str) -> Any:
    raise ValueError(f"not JSON: {name}")


def _json_or_text(v: Any) -> Any:
    """A JSON object or array held as text (tool arguments, results) as the
    value it encodes; any other text as given. A bare number, ``true``,
    ``null`` or ``NaN`` is not reinterpreted: ``"12345678901234567890"`` or
    ``"null"`` is what the tool said, not a JSON value."""
    if isinstance(v, str):
        s = v.lstrip()
        if s[:1] in ("{", "["):
            try:
                return json.loads(v, parse_constant=_no_constant)
            except ValueError:
                return v
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


def _exception_message(span: Any) -> Optional[str]:
    """The message of the last ``exception`` event on the span, if any
    (``exception.message`` is an event attribute, not a span attribute)."""
    for ev in reversed(list(getattr(span, "events", None) or ())):
        if getattr(ev, "name", None) == "exception":
            msg = (getattr(ev, "attributes", None) or {}).get("exception.message")
            if msg is not None:
                return str(msg)
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
        keep_payloads: bool = False,
    ) -> None:
        self.log = log
        self.record_inputs = record_inputs
        self.record_content = record_content
        self.record_calls = record_calls
        self.raise_on_error = raise_on_error
        self.recorder = Recorder(
            log, record_output=record_outputs, raise_on_error=raise_on_error, keep_payloads=keep_payloads
        )
        # (trace_id, span_id) -> (intent index, the arguments recorded in it).
        self._pending: Dict[Tuple[int, int], Tuple[Optional[int], Any]] = {}
        self._lock = threading.Lock()

    @property
    def errors(self) -> List[str]:
        return self.recorder.errors

    @property
    def payloads(self) -> Dict[int, bytes]:
        return self.recorder.payloads

    # -- classification ---------------------------------------------------

    @staticmethod
    def _kind(span: Any, attrs: Mapping[str, Any]) -> Optional[str]:
        op = attrs.get("gen_ai.operation.name")
        oi = attrs.get("openinference.span.kind")
        if op in TOOL_OPERATIONS or oi == OI_TOOL:
            if span.name in MERGED_SPAN_NAMES or attrs.get("gen_ai.tool.name") in MERGED_TOOL_NAMES:
                return None
            return "tool"
        if op in CALL_OPERATIONS or oi in OI_CALLS:
            return "call"
        return None

    @staticmethod
    def _key(span: Any) -> Tuple[int, int]:
        ctx = span.get_span_context()
        return (ctx.trace_id, ctx.span_id)

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
        # Not `tool.parameters`: in OpenInference that is the tool's schema.
        v = _first(attrs, "gen_ai.tool.call.arguments", "input.value")
        return None if v is None else _json_or_text(v)

    def _nested_in(self, span: Any) -> Optional[str]:
        """The span id of the tool span this one runs inside (an MCP client
        span under a framework's tool span: one call, two spans), if any."""
        parent = getattr(span, "parent", None)
        if parent is None:
            return None
        with self._lock:
            enclosing = (parent.trace_id, parent.span_id) in self._pending
        return _hex(parent.span_id, 16) if enclosing else None

    # -- SpanProcessor ----------------------------------------------------

    def on_start(self, span: Span, parent_context: Any = None) -> None:
        try:
            attrs = span.attributes or {}
            if self._kind(span, attrs) != "tool":
                return
            extra: Dict[str, Any] = {"source": "otel", "call_id": attrs.get("gen_ai.tool.call.id"), **self._ids(span)}
            nested = self._nested_in(span)
            if nested is not None:
                extra["nested_in"] = nested
            args = self._args(attrs)
            idx = self.recorder.intent(self._tool_name(span, attrs), args, **extra)
            with self._lock:
                if len(self._pending) >= MAX_PENDING:
                    # The oldest span still open: it will get a late intent
                    # of its own if it ever ends.
                    self._pending.pop(next(iter(self._pending)))
                    self.recorder.errors.append(
                        f"on_start: more than {MAX_PENDING} tool spans open at once; forgot the oldest"
                    )
                self._pending[self._key(span)] = (idx, args)
        except Exception as e:  # noqa: BLE001 -- never break tracing unless asked
            self._fail("on_start", e)

    def on_end(self, span: ReadableSpan) -> None:
        try:
            attrs = span.attributes or {}
            kind = self._kind(span, attrs)
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
        key = self._key(span)
        with self._lock:
            pending = self._pending.pop(key, None)
        tool = self._tool_name(span, attrs)
        extra: Dict[str, Any] = {"source": "otel", "call_id": attrs.get("gen_ai.tool.call.id"), **self._ids(span)}
        nested = self._nested_in(span)
        if nested is not None:
            extra["nested_in"] = nested
        args = self._args(attrs)
        if pending is None:
            # Marked a tool span only at its end (or started before this
            # processor was added): the intent is written now, after the
            # tool ran, and says so.
            intent_index = self.recorder.intent(tool, args, late=True, **extra)
        else:
            intent_index, args_at_start = pending
            if args is not None and args != args_at_start:
                extra["args_at_end"] = args
        failed = span.status is not None and span.status.status_code == StatusCode.ERROR
        if failed:
            value: Any = span.status.description or _exception_message(span) or attrs.get("error.type") or "error"
        else:
            out = _first(attrs, "gen_ai.tool.call.result", "output.value")
            value = None if out is None else _json_or_text(out)
        self.recorder.result(tool, intent_index, value, outcome="error" if failed else "ok", **extra)

    def _call_end(self, span: ReadableSpan, attrs: Mapping[str, Any]) -> None:
        failed = span.status is not None and span.status.status_code == StatusCode.ERROR
        finish = attrs.get("gen_ai.response.finish_reasons")
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
            "finish_reasons": list(finish) if isinstance(finish, (list, tuple)) else finish,
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
