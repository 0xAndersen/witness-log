#!/usr/bin/env python3
"""A real Claude Agent SDK agent with every tool call on a witness-log journal.

    pip install witness-log claude-agent-sdk
    export ANTHROPIC_API_KEY=...
    python3 examples/claude-agent-sdk/run.py [--out DIR] [--model MODEL]

The agent answers one question with two in-process tools (an SDK MCP
server, so nothing outside this process is touched; built-in tools and
filesystem settings are switched off). The witness-log hooks record each
call as an intent leaf (PreToolUse) and a result leaf (PostToolUse /
PostToolUseFailure). Afterwards the script exports the dossier, verifies
it offline pinned to the agent's identity, and discloses the first leaf.

Exits 0 only if at least one tool call was recorded, every intent has its
result, nothing failed to append, the dossier verifies and the disclosure
checks out; 1 otherwise. Costs one short agent run on your API key.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile

try:
    import witness_log as wl
    from witness_log.integrations.claude_agent_sdk import WitnessLogClaudeHooks
except ImportError:  # pragma: no cover
    sys.exit("this example needs the Python package: pip install witness-log")

try:
    from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, create_sdk_mcp_server, query, tool
except ImportError:  # pragma: no cover
    sys.exit('this example needs the Claude Agent SDK: pip install "witness-log[claude-agent-sdk]"')

LEDGER = {"acct-001": 1250, "acct-002": 75, "acct-003": 4300}


@tool("list_accounts", "List the account ids in the ledger.", {})
async def list_accounts(args):
    return {"content": [{"type": "text", "text": json.dumps(sorted(LEDGER))}]}


@tool("get_balance", "Get one account's balance in USD.", {"account": str})
async def get_balance(args):
    account = args["account"]
    if account not in LEDGER:
        return {"content": [{"type": "text", "text": f"unknown account {account}"}], "is_error": True}
    return {"content": [{"type": "text", "text": json.dumps({"account": account, "balance_usd": LEDGER[account]})}]}


PROMPT = "What is the total balance across every account in the ledger? Use the ledger tools, then answer in one sentence."
TOOLS = ["mcp__ledger__list_accounts", "mcp__ledger__get_balance"]


def check(cond: bool, what: str, failures: list) -> None:
    print(f"   {'✓' if cond else '✗'} {what}")
    if not cond:
        failures.append(what)


async def run_agent(audit: WitnessLogClaudeHooks, out_dir: str, model: str | None) -> str:
    options = audit.options(
        mcp_servers={"ledger": create_sdk_mcp_server("ledger", tools=[list_accounts, get_balance])},
        tools=[],               # no built-in tools: only the ledger
        allowed_tools=TOOLS,    # run them without a permission prompt
        setting_sources=[],     # ignore ~/.claude and project settings (and any hooks there)
        cwd=out_dir,
        max_turns=8,
        model=model,
    )
    answer = ""
    async for message in query(prompt=PROMPT, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    answer = block.text
        elif isinstance(message, ResultMessage) and message.result:
            answer = message.result
    return answer


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="directory for the journal and dossier (default: a new temp directory, kept)")
    ap.add_argument("--model", help="model for the agent (default: the CLI's default)")
    a = ap.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("this example runs a real agent: set ANTHROPIC_API_KEY first (it makes one short run)")

    out_dir = os.path.abspath(a.out or tempfile.mkdtemp(prefix="witness-claude-agent-"))
    os.makedirs(out_dir, exist_ok=True)
    journal = os.path.join(out_dir, "agent.jsonl")
    log = wl.open(journal)
    audit = WitnessLogClaudeHooks(log)
    failures: list = []

    print(f"── 1. Run the agent (journal {journal})")
    answer = asyncio.run(run_agent(audit, out_dir, a.model))
    print(f"   agent: {answer.strip()}")

    print("── 2. What was recorded")
    log.sync()
    leaves = json.loads(log.leaves_json())
    payloads = {i: json.loads(b) for i, b in audit.recorder.payloads.items()}
    for leaf in leaves:
        p = payloads.get(leaf["index"], {})
        kind = {1: "intent", 2: "result"}.get(leaf["leaf_type"], str(leaf["leaf_type"]))
        detail = json.dumps(p.get("tool_input"), separators=(",", ":"))
        link = f"  -> intent {p['intent_index']}" if "intent_index" in p else ""
        print(f"   leaf {leaf['index']}  {kind:6}  {p.get('event', '?'):18} {p.get('tool_name', '?')} {detail}{link}")
    intents = {p["tool_use_id"]: i for i, p in payloads.items() if p.get("event") == "PreToolUse"}
    results = {p["tool_use_id"]: p for p in payloads.values() if p.get("event") in ("PostToolUse", "PostToolUseFailure")}
    check(len(intents) > 0, f"{len(intents)} tool call(s) recorded", failures)
    check(set(intents) == set(results) and all(results[t]["intent_index"] == i for t, i in intents.items()),
          "every intent has its result, linked by intent_index", failures)
    check(all(p.get("profile") == "hook.claude-code v1" for p in payloads.values()), 'payloads in the "hook.claude-code v1" profile', failures)
    check(audit.errors == [], f"no append failures {audit.errors or ''}", failures)

    print("── 3. Export the dossier and verify it offline")
    dossier = log.to_dossier_json()
    path = os.path.join(out_dir, "agent.dossier.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(dossier)
    identity = log.identity_pubkey_hex()
    report = json.loads(wl.verify_dossier_json(dossier, 0.66, identity))
    check(bool(report.get("internally_consistent")), f"{path} verifies: {report.get('verdict')} (no witnesses yet)", failures)
    print(f"   witness-log verify {path} --identity {identity}")

    if leaves:
        print("── 4. Disclose leaf 0 to an auditor: payload + salt recompute its hash")
        payload = audit.recorder.payloads.get(0)
        salt = log.salt_hex(0)
        ok = payload is not None and salt is not None and wl.verify_disclosure(json.loads(dossier)["leaves"][0], payload, salt)
        check(ok, "disclosure verifies against the dossier's leaf 0", failures)

    log.close()
    print()
    print("OK" if not failures else f"FAILED: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
