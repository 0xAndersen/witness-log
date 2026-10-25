"""OpenTelemetry span processor: GenAI semantic-convention and OpenInference
spans become witness-log leaves, with the real OpenTelemetry SDK."""

from __future__ import annotations

import json

import pytest

otel = pytest.importorskip("opentelemetry.sdk.trace")

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.trace import Status, StatusCode  # noqa: E402

import witness_log  # noqa: E402
from witness_log.integrations.otel import WitnessLogSpanProcessor  # noqa: E402


def _setup(tmp_path, **kw):
    log = witness_log.open(str(tmp_path / "agent.jsonl"))
    processor = WitnessLogSpanProcessor(log, **kw)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    return log, processor, provider.get_tracer("test")


def _leaves(processor):
    return {i: json.loads(b) for i, b in sorted(processor.payloads.items())}


def test_a_gen_ai_tool_span_is_an_intent_before_and_a_result_after(tmp_path):
    log, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span("invoke_agent triage", attributes={"gen_ai.operation.name": "invoke_agent"}):
        with tracer.start_as_current_span(
            "execute_tool get_weather",
            attributes={
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "get_weather",
                "gen_ai.tool.call.id": "call_1",
                "gen_ai.tool.call.arguments": '{"city": "Lisbon"}',
            },
        ) as span:
            # The intent is in the log before the tool body runs.
            assert log.tree_size() == 1
            span.set_attribute("gen_ai.tool.call.result", '{"temp_c": 21}')
    leaves = _leaves(p)
    intent, result, agent = leaves[0], leaves[1], leaves[2]
    assert intent["tool"] == "get_weather" and intent["args"] == {"city": "Lisbon"}
    assert intent["tool_call_id"] == "call_1" and intent["source"] == "otel" and len(intent["span_id"]) == 16
    assert result["intent_index"] == 0 and result["outcome"] == "ok" and result["value"] == {"temp_c": 21}
    assert result["span_id"] == intent["span_id"] and result["trace_id"] == intent["trace_id"]
    assert agent["operation"] == "invoke_agent" and agent["profile"] == "otel.gen_ai.call/1"
    assert intent["parent_span_id"] == agent["span_id"]
    assert p.errors == []
    # The log is an ordinary witness-log: its dossier verifies.
    report = json.loads(witness_log.verify_dossier_json(log.to_dossier_json(), 0.66))
    assert report["verdict"] == "unanchored", report["verdict"]  # no witnesses: valid, unanchored


def test_a_failed_tool_span_is_an_error_result(tmp_path):
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span(
        "execute_tool pay", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "pay"}
    ) as span:
        span.set_status(Status(StatusCode.ERROR, "card declined"))
    result = _leaves(p)[1]
    assert result["outcome"] == "error" and result["value"] == "card declined"


def test_arguments_set_after_start_go_in_the_result(tmp_path):
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span(
        "execute_tool search", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "search"}
    ) as span:
        span.set_attribute("gen_ai.tool.call.arguments", '{"q": "witness"}')
    intent, result = _leaves(p)[0], _leaves(p)[1]
    assert intent["args"] is None and result["args_at_end"] == {"q": "witness"}


def test_openinference_tool_and_llm_spans(tmp_path):
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span(
        "lookup", attributes={"openinference.span.kind": "TOOL", "tool.name": "lookup", "input.value": '{"id": 7}'}
    ) as span:
        span.set_attribute("output.value", "found")
    with tracer.start_as_current_span(
        "ChatOpenAI",
        attributes={
            "openinference.span.kind": "LLM",
            "llm.model_name": "gpt-x",
            "llm.provider": "openai",
            "llm.token_count.prompt": 12,
            "llm.token_count.completion": 3,
            "input.value": "secret prompt",
        },
    ):
        pass
    leaves = _leaves(p)
    assert leaves[0]["tool"] == "lookup" and leaves[0]["args"] == {"id": 7}
    assert leaves[1]["value"] == "found"
    llm = leaves[2]
    assert llm["model"] == "gpt-x" and llm["provider"] == "openai" and llm["usage"] == {"input_tokens": 12, "output_tokens": 3}
    # Content is left out unless asked for.
    assert "input_messages" not in llm and "secret prompt" not in json.dumps(llm)


def test_model_call_usage_and_content_opt_in(tmp_path):
    _, p, tracer = _setup(tmp_path, record_content=True)
    with tracer.start_as_current_span(
        "chat claude",
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "anthropic",
            "gen_ai.request.model": "claude-x",
            "gen_ai.usage.input_tokens": 100,
            "gen_ai.usage.output_tokens": 20,
            "gen_ai.response.finish_reasons": ["stop"],
            "gen_ai.input.messages": '[{"role": "user", "parts": [{"type": "text", "content": "hi"}]}]',
        },
    ):
        pass
    call = _leaves(p)[0]
    assert call["model"] == "claude-x" and call["provider"] == "anthropic" and call["finish_reasons"] == ["stop"]
    assert call["usage"] == {"input_tokens": 100, "output_tokens": 20}
    assert call["input_messages"][0]["role"] == "user"


def test_other_spans_are_ignored_and_options_are_honoured(tmp_path):
    log, p, tracer = _setup(tmp_path, record_calls=False, record_inputs=False, record_outputs=False)
    with tracer.start_as_current_span("GET /health", attributes={"http.request.method": "GET"}):
        pass
    with tracer.start_as_current_span("chat m", attributes={"gen_ai.operation.name": "chat"}):
        pass
    with tracer.start_as_current_span(
        "execute_tool t",
        attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.arguments": '{"a": 1}'},
    ) as span:
        span.set_attribute("gen_ai.tool.call.result", "secret result")
    leaves = _leaves(p)
    assert log.tree_size() == 2  # the tool pair only
    assert leaves[0]["tool"] == "t" and leaves[0]["args"] is None  # name from the span name
    assert "value" not in leaves[1] and "secret result" not in json.dumps(leaves)


def test_a_span_started_before_the_processor_still_gets_both_leaves(tmp_path):
    log = witness_log.open(str(tmp_path / "agent.jsonl"))
    provider = TracerProvider()
    tracer = provider.get_tracer("test")
    span = tracer.start_span("execute_tool late", attributes={"gen_ai.operation.name": "execute_tool"})
    p = WitnessLogSpanProcessor(log)
    p.on_end(span)  # as if the processor were added mid-span
    leaves = _leaves(p)
    assert leaves[0]["late"] is True and leaves[1]["intent_index"] == 0


def test_a_failing_log_never_breaks_tracing(tmp_path):
    class Broken:
        def append_intent(self, data):
            raise OSError("disk full")

        append_result = append_memory = append_intent

    p = WitnessLogSpanProcessor(Broken())
    provider = TracerProvider()
    provider.add_span_processor(p)
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("execute_tool x", attributes={"gen_ai.operation.name": "execute_tool"}):
        pass
    with tracer.start_as_current_span("chat m", attributes={"gen_ai.operation.name": "chat"}):
        pass
    assert len(p.errors) == 3 and all("disk full" in e for e in p.errors), p.errors
    with pytest.raises(OSError):
        WitnessLogSpanProcessor(Broken(), raise_on_error=True).on_end(tracer.start_span("chat", attributes={"gen_ai.operation.name": "chat"}))
