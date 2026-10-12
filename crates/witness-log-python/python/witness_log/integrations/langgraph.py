"""LangGraph: a callback handler keyed by ``run_id`` that records every
tool call and treats a ``Command(goto=...)`` as a handoff.

::

    from witness_log.integrations.langgraph import WitnessLogGraphHandler

    handler = WitnessLogGraphHandler(witness_log.open("graph.jsonl"))
    graph.invoke(state, config={"callbacks": [handler]})

    # or one journal per agent node, with handoff leaves on both sides:
    from witness_log.integrations import AgentJournals
    handler = WitnessLogGraphHandler(AgentJournals("audit/", seed_for=kms.seed_for))

LangGraph runs tools through LangChain's callback system, so this is the
LangChain handler with two additions. The node a tool runs in is read
from the callback metadata (``langgraph_node``) and recorded as the
agent; with :class:`~witness_log.integrations.AgentJournals` that node
name selects the journal. A tool or node that returns
``Command(goto="other_node")`` (the ``langgraph-supervisor`` /
``create_handoff_tool`` pattern) is recorded as a handoff from the
current node to ``goto``: the tool's own result leaf carries
``handoff_to``, and with journals a ``Sent`` attestation lands in the
source node's journal and ``Received`` in the target's.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from . import Sink, handoff_state

__all__ = ["WitnessLogGraphHandler"]


def _node(metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    if not metadata:
        return None
    n = metadata.get("langgraph_node")
    return str(n) if n else None


def _goto_targets(value: Any) -> List[str]:
    """The node names a ``Command`` sends control to, or ``[]``."""
    try:
        from langgraph.types import Command, Send
    except Exception:  # noqa: BLE001 -- an older langgraph without Send
        Command, Send = None, None  # type: ignore[assignment]
    if Command is None or not isinstance(value, Command):
        return []
    goto = value.goto
    items: Sequence[Any] = goto if isinstance(goto, (list, tuple)) else [goto]
    out: List[str] = []
    for g in items:
        if Send is not None and isinstance(g, Send):
            out.append(str(g.node))
        elif isinstance(g, str) and g:
            out.append(g)
    return out


def _tool_value(output: Any) -> Any:
    if _goto_targets(output):
        upd = getattr(output, "update", None)
        return {"command": {"goto": _goto_targets(output), "update": _plain(upd)}}
    return getattr(output, "content", output)


def _plain(v: Any) -> Any:
    """Messages and other LangChain objects, made JSON-friendly."""
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if hasattr(v, "content") and hasattr(v, "type"):
        return {"type": getattr(v, "type", None), "content": getattr(v, "content", None)}
    return v


class WitnessLogGraphHandler(BaseCallbackHandler):
    """Intent leaf in ``on_tool_start``, result leaf in ``on_tool_end`` /
    ``on_tool_error``; a ``Command(goto=...)`` result or node output is a
    handoff. ``target`` is a log or an ``AgentJournals``."""

    run_inline = True  # LangGraph may run handlers in a thread pool otherwise; keep leaf order

    def __init__(self, target: Any, *, record_output: bool = True, raise_on_error: bool = False) -> None:
        super().__init__()
        self.sink = Sink(target, record_output=record_output, raise_on_error=raise_on_error)
        self.raise_error = raise_on_error
        self._pending: Dict[UUID, Tuple[Optional[str], str, Optional[int]]] = {}
        self._nodes: Dict[UUID, str] = {}  # chain run_id -> node name, for node-level Commands
        self._lock = threading.Lock()
        self._seq = 0

    @property
    def errors(self) -> list:
        return self.sink.errors

    @property
    def recorder(self) -> Any:
        return self.sink.recorder()

    def _handoff(self, src: Optional[str], targets: List[str], **content: Any) -> Dict[str, Any]:
        """Sent/Received leaves (journals only); returns the result annotations."""
        out: Dict[str, Any] = {"handoff_to": targets if len(targets) > 1 else targets[0]}
        leaves = []
        for dst in targets:
            with self._lock:
                self._seq += 1
                n = self._seq
            sent, recv = self.sink.handoff(src, dst, handoff_state(src or "graph", dst, seq=n, **content))
            if sent is not None or recv is not None:
                leaves.append({"to": dst, "sent_leaf": sent, "received_leaf": recv})
        if leaves:
            out["handoff_leaves"] = leaves
        return out

    # -- tools -------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: Optional[Dict[str, Any]],
        input_str: str,
        *,
        run_id: UUID,
        inputs: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        node = _node(metadata)
        args = inputs if inputs is not None else input_str
        i = self.sink.recorder(node).intent(name, args, run_id=str(run_id), node=node)
        with self._lock:
            self._pending[run_id] = (node, name, i)

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            node, name, i = self._pending.pop(run_id, (None, "tool", None))
        extra: Dict[str, Any] = {"run_id": str(run_id)}
        targets = _goto_targets(output)
        if targets:
            extra.update(self._handoff(node, targets, tool=name, run_id=str(run_id)))
        self.sink.recorder(node).result(name, i, _tool_value(output), **extra)

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            node, name, i = self._pending.pop(run_id, (None, "tool", None))
        self.sink.recorder(node).result(name, i, f"{type(error).__name__}: {error}", outcome="error", run_id=str(run_id))

    # -- nodes: a node returning Command(goto=...) is a handoff too --------

    def on_chain_start(
        self,
        serialized: Optional[Dict[str, Any]],
        inputs: Any,
        *,
        run_id: UUID,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        node = _node(metadata)
        if node and kwargs.get("name") == node:
            with self._lock:
                self._nodes[run_id] = node

    def on_chain_end(self, outputs: Any, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            node = self._nodes.pop(run_id, None)
        if node is None:
            return
        targets = _goto_targets(outputs)
        if not targets:
            return
        rec = self.sink.recorder(node)
        i = rec.intent("handoff", {"from": node, "to": targets if len(targets) > 1 else targets[0]}, node=node)
        rec.result("handoff", i, {"command": {"goto": targets}}, **self._handoff(node, targets, node_output=True))

    def on_chain_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            self._nodes.pop(run_id, None)
