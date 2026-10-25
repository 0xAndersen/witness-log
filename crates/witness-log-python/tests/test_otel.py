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
    kw.setdefault("keep_payloads", True)
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
    assert intent["call_id"] == "call_1" and intent["source"] == "otel" and len(intent["span_id"]) == 16
    assert "late" not in intent and "args_at_end" not in result  # the arguments did not change
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
    p = WitnessLogSpanProcessor(log, keep_payloads=True)
    provider.add_span_processor(p)  # added mid-span
    span.end()
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


def test_a_span_marked_as_a_tool_only_at_its_end_gets_a_late_intent(tmp_path):
    """OpenInference's LangChain and LlamaIndex instrumentors set the span
    kind when the span ends: the intent cannot precede the tool, and says so."""
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span("lookup") as span:
        span.set_attribute("openinference.span.kind", "TOOL")
        span.set_attribute("input.value", '{"id": 7}')
    intent, result = _leaves(p)[0], _leaves(p)[1]
    assert intent["late"] is True and intent["args"] == {"id": 7} and result["intent_index"] == 0


def test_the_tool_schema_is_not_taken_for_the_arguments(tmp_path):
    """OpenInference `tool.parameters` is the tool's parameter schema
    (LlamaIndex sets it from fn_schema), not the call's arguments."""
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span(
        "lookup",
        attributes={
            "openinference.span.kind": "TOOL",
            "tool.name": "lookup",
            "tool.parameters": '{"type": "object", "properties": {"id": {"type": "integer"}}}',
            "input.value": '{"id": 7}',
        },
    ):
        pass
    assert _leaves(p)[0]["args"] == {"id": 7}


def test_only_json_objects_and_arrays_are_reinterpreted(tmp_path):
    _, p, tracer = _setup(tmp_path)
    for raw in ("12345678901234567890", "null", "true", "[NaN]", "plain text", '{"a": 1}'):
        with tracer.start_as_current_span(
            "execute_tool t", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.arguments": raw}
        ):
            pass
    args = [leaf["args"] for i, leaf in _leaves(p).items() if i % 2 == 0]
    assert args == ["12345678901234567890", "null", "true", "[NaN]", "plain text", {"a": 1}]


def test_arguments_seen_at_start_and_changed_at_end(tmp_path):
    _, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span(
        "execute_tool t",
        attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.arguments": '{"q": 1}'},
    ) as span:
        span.set_attribute("gen_ai.tool.call.arguments", '{"q": 2}')
    intent, result = _leaves(p)[0], _leaves(p)[1]
    assert intent["args"] == {"q": 1} and result["args_at_end"] == {"q": 2}


def test_adk_merged_parallel_span_is_not_a_tool_call(tmp_path):
    log, p, tracer = _setup(tmp_path)
    with tracer.start_as_current_span("execute_tool (merged)", attributes={"gen_ai.operation.name": "execute_tool"}) as m:
        m.set_attribute("gen_ai.tool.name", "(merged tools)")
        for name in ("a", "b"):
            with tracer.start_as_current_span(
                f"execute_tool {name}", attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": name}
            ):
                pass
    assert sorted(leaf["tool"] for leaf in _leaves(p).values()) == ["a", "a", "b", "b"]
    assert log.tree_size() == 4


def test_a_tool_span_inside_a_tool_span_says_so(tmp_path):
    """An MCP client span (execute_tool, per the MCP conventions) inside a
    framework's tool span: one call, two spans; the inner pair names the outer."""
    _, p, tracer = _setup(tmp_path)
    attrs = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "search"}
    with tracer.start_as_current_span("execute_tool search", attributes=attrs) as outer:
        with tracer.start_as_current_span("tools/call search", attributes=attrs):
            pass
    outer_id = format(outer.get_span_context().span_id, "016x")
    leaves = _leaves(p)
    inner = [leaf for leaf in leaves.values() if leaf.get("nested_in") == outer_id]
    assert len(inner) == 2 and all(leaf["span_id"] != outer_id for leaf in inner)
    assert sum("nested_in" not in leaf for leaf in leaves.values()) == 2


def test_spans_that_never_end_are_not_held_forever(tmp_path, monkeypatch):
    import witness_log.integrations.otel as otel_mod

    monkeypatch.setattr(otel_mod, "MAX_PENDING", 5)
    _, p, tracer = _setup(tmp_path)
    for i in range(12):
        tracer.start_span(f"execute_tool t{i}", attributes={"gen_ai.operation.name": "execute_tool"})
    assert len(p._pending) == 5
    assert any("forgot the oldest" in e for e in p.errors)


def test_the_failure_message_comes_from_the_exception_event(tmp_path):
    _, p, tracer = _setup(tmp_path)
    with pytest.raises(RuntimeError):
        with tracer.start_as_current_span(
            "execute_tool pay", attributes={"gen_ai.operation.name": "execute_tool"}, set_status_on_exception=False
        ) as span:
            try:
                raise RuntimeError("card declined")
            except RuntimeError as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                raise
    assert _leaves(p)[1]["value"] == "card declined"


def test_payloads_are_not_kept_unless_asked(tmp_path):
    log = witness_log.open(str(tmp_path / "agent.jsonl"))
    p = WitnessLogSpanProcessor(log)
    provider = TracerProvider()
    provider.add_span_processor(p)
    with provider.get_tracer("t").start_as_current_span("chat m", attributes={"gen_ai.operation.name": "chat"}):
        pass
    assert log.tree_size() == 1 and p.payloads == {}


def test_a_span_the_sampler_drops_writes_nothing(tmp_path):
    """Documented, not fixed: processors only see recorded spans."""
    from opentelemetry.sdk.trace.sampling import ALWAYS_OFF

    log = witness_log.open(str(tmp_path / "agent.jsonl"))
    provider = TracerProvider(sampler=ALWAYS_OFF)
    provider.add_span_processor(WitnessLogSpanProcessor(log))
    with provider.get_tracer("t").start_as_current_span("execute_tool t", attributes={"gen_ai.operation.name": "execute_tool"}):
        pass
    assert log.tree_size() == 0
