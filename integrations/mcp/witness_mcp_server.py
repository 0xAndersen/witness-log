#!/usr/bin/env python3
"""witness-log MCP server: an agent's own tamper-evident audit trail, as tools.

Any MCP-capable agent or runtime (Claude, coding agents, multi-agent
frameworks) can call these tools to provision a cryptographic audit
trail for itself on boot, append every step, prove any step was
recorded, erase a step for GDPR, and hand a verifiable dossier to anyone.

Everything cryptographic is the Rust core (`pip install witness-log`):
RFC 6962 Merkle tree, Ed25519 identity and session keys, salted
redaction, the c2sp.org/tlog-witness protocol, offline verification.
This file only maps it onto MCP tools and keeps one journal per session
on disk.

Run (stdio, what MCP clients expect):

    pip install "mcp>=2" witness-log
    python witness_mcp_server.py

    # or with uv, no install step:
    uv run --with "mcp>=2" --with witness-log witness_mcp_server.py

Inspect interactively with the MCP Inspector:

    uv run --with "mcp[cli]>=2" --with witness-log mcp dev witness_mcp_server.py

Configure in a client (Claude Desktop / Claude Code / any MCP host):

    {"mcpServers": {"witness-log": {
        "command": "uv",
        "args": ["run", "--with", "mcp>=2", "--with", "witness-log",
                 "/absolute/path/to/witness_mcp_server.py"],
        "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}

State: `$WITNESS_LOG_HOME` (default `~/.witness-log/mcp`), one directory
per session holding `journal.jsonl` (the log; identity seed in its
header, mode 0600) and `journal.jsonl.witnesses.json` (what each witness
last cosigned). An optional `$WITNESS_LOG_HOME/witnesses.json` is the
directory of witnesses `submit_to_witnesses` uses by default.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import witness_log as wl

try:  # official SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

# ----------------------------------------------------------------- config

HOME = Path(os.environ.get("WITNESS_LOG_HOME", Path.home() / ".witness-log" / "mcp"))
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_PAYLOAD_BYTES = 1_000_000  # one leaf's payload; hashes are 32 bytes regardless
DEFAULT_THRESHOLD = 0.66
WITNESS_TIMEOUT_S = 10

server = _Server(
    name="witness-log",
    instructions=(
        "Tamper-evident audit trail for this agent. Call initialize_witness_chain "
        "once per session (safe to repeat: it resumes), append_audit_step for every "
        "tool call or decision, and export_dossier when someone needs to verify "
        "what happened. Nothing here can be edited after the fact; redaction "
        "erases a payload but leaves proof that an entry existed."
    ),
)

# One journal per session, one asyncio lock per session so concurrent
# tool calls from a multi-agent host serialise cleanly. The Rust objects
# are internally locked too; this lock just keeps multi-call sequences
# (append intent, then result) atomic from the caller's view.
_sessions: dict[str, wl.JournaledLog] = {}
_locks: dict[str, asyncio.Lock] = {}
_registry_lock = asyncio.Lock()


def _session_dir(session_id: str) -> Path:
    if not SESSION_ID.match(session_id):
        raise ValueError(
            "session_id must be 1-128 characters of letters, digits, '.', '_' or '-' "
            "(it names a directory; no path separators)"
        )
    return HOME / session_id


def _journal_path(session_id: str) -> Path:
    return _session_dir(session_id) / "journal.jsonl"


async def _get(session_id: str) -> tuple[wl.JournaledLog, asyncio.Lock]:
    """The open log for a session, resuming it from disk if this process
    has not touched it yet. Raises if it was never initialised."""
    async with _registry_lock:
        log = _sessions.get(session_id)
        if log is None:
            p = _journal_path(session_id)
            if not p.exists():
                raise ValueError(
                    f"no witness chain for session {session_id!r}; "
                    "call initialize_witness_chain first"
                )
            log = await asyncio.to_thread(_open_existing, p)
            _sessions[session_id] = log
        lock = _locks.setdefault(session_id, asyncio.Lock())
    return log, lock


def _open_existing(p: Path) -> wl.JournaledLog:
    try:
        log, dropped = wl.JournaledLog.resume(str(p))
    except OSError as e:
        msg = str(e)
        if "already open" in msg:
            raise RuntimeError(
                f"{p} is locked by another process. Only one process may write a "
                "journal; if the previous one crashed, delete the .lock file next to it."
            ) from e
        raise RuntimeError(f"could not resume {p}: {msg}") from e
    if dropped:
        # A torn last line from a crash was healed. Nothing else to do; the
        # caller's next append lands after the last complete leaf.
        pass
    return log


def _payload_bytes(value: Any) -> bytes:
    data = wl.canonical_json(value)
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload is {len(data)} bytes; the limit is {MAX_PAYLOAD_BYTES}. "
            "Log a hash or a summary of large data, not the data itself."
        )
    return data


def _head(log: wl.JournaledLog) -> dict[str, Any]:
    return {
        "identity_pubkey": log.identity_pubkey_hex(),
        "origin": log.canonical_origin(),
        "tree_size": log.tree_size(),
        "root_hash": log.root_hex(),
    }


def _proof(log: wl.JournaledLog, index: int) -> dict[str, Any]:
    got = log.inclusion_proof(index)
    if got is None:
        raise ValueError(f"no leaf at index {index}")
    tree_size, root, path = got
    return {
        "leaf_index": index,
        "leaf_hash": log.leaf_hash_hex(index),
        "tree_size": tree_size,
        "root_hash": root,
        "path": path,
        "verify_with": "witness_log.verify_inclusion(leaf_hash, leaf_index, tree_size, path, root_hash)",
    }


# ------------------------------------------------------------------ tools


@server.tool()
async def initialize_witness_chain(
    session_id: str, metadata: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """Create the audit chain for a session, or resume it if it exists.

    Binds an append-only RFC 6962 Merkle log to an Ed25519 identity key
    (generated on first call and kept in the journal header, mode 0600)
    and a fresh per-process session key. Safe to call on every boot: an
    existing chain is resumed with the same identity and a new session
    number, and a half-written last line from a crash is healed.

    Args:
        session_id: Stable name for this agent/session; 1-128 characters
            of letters, digits, '.', '_' or '-'. Reuse it to resume.
        metadata: Optional JSON object recorded as the chain's first
            memory leaf on creation (agent name, model, deployment, ...).
            Ignored when resuming.

    Returns: identity public key, canonical witness origin
    (`witness-log/<identity>`), current tree size and root, whether the
    chain was resumed, and the journal path.
    """
    p = _journal_path(session_id)
    async with _registry_lock:
        existing = _sessions.get(session_id)
        if existing is not None:
            return {**_head(existing), "resumed": True, "journal": str(p)}
        resumed = p.exists()
        if resumed:
            log = await asyncio.to_thread(_open_existing, p)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(p.parent, 0o700)
            except OSError:
                pass
            log = wl.JournaledLog.create_ephemeral(str(p))
            if metadata is not None:
                log.append_memory(_payload_bytes({"kind": "session_metadata", **metadata}))
            await asyncio.to_thread(log.sync)
        _sessions[session_id] = log
        _locks.setdefault(session_id, asyncio.Lock())
    return {**_head(log), "resumed": resumed, "journal": str(p)}


@server.tool()
async def append_audit_step(
    session_id: str,
    intent: str,
    tool_name: str,
    payload: Optional[dict[str, Any]] = None,
    state_transition: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Record one step: what the agent intended and what came of it.

    Appends an *intent* leaf (`intent`, `tool_name`, `payload`) signed by
    the session key, and, if `state_transition` is given, a *result* leaf
    bound to it. Payloads are encoded as canonical JSON (sorted keys, no
    whitespace), hashed with a per-leaf salt, and only the hash enters
    the tree, so a leaf can later be erased with redact_audit_entry
    without breaking any proof. Nothing is ever overwritten.

    Args:
        session_id: The chain to append to (see initialize_witness_chain).
        intent: What the agent is about to do, in its own words.
        tool_name: The tool or action being invoked.
        payload: Arguments or inputs (JSON object, up to 1 MB encoded).
        state_transition: Outcome or new state after the step (JSON
            object). Omit to record the intent only and call again later.

    Returns: the indices of the leaves written, a signed checkpoint over
    the whole tree (the receipt: anyone holding it can detect a later
    rewrite), and an inclusion proof for the last leaf written.
    """
    log, lock = await _get(session_id)
    intent_payload = _payload_bytes({"intent": intent, "tool": tool_name, "payload": payload or {}})
    result_payload = (
        _payload_bytes({"tool": tool_name, "state_transition": state_transition})
        if state_transition is not None
        else None
    )
    async with lock:
        intent_index = log.append_intent(intent_payload)
        result_index = log.append_result(result_payload) if result_payload is not None else None
        await asyncio.to_thread(log.sync)
        last = result_index if result_index is not None else intent_index
        return {
            "intent_index": intent_index,
            "result_index": result_index,
            "checkpoint": json.loads(log.checkpoint()),
            "inclusion_proof": _proof(log, last),
            **_head(log),
        }


@server.tool()
async def get_inclusion_proof(session_id: str, entry_index: int) -> dict[str, Any]:
    """Inclusion proof that a given entry is in the current tree.

    Verifiable offline by anyone with the root hash, with
    `witness_log.verify_inclusion` or any RFC 6962 verifier.
    """
    log, lock = await _get(session_id)
    async with lock:
        return _proof(log, entry_index)


@server.tool()
async def verify_chain_integrity(
    session_id: str, trusted_directory: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """Re-verify the whole chain and report any tampering.

    Exports the dossier and runs the same verifier the `witness-log` CLI
    uses: checkpoint signature, identity binding, structural validity of
    every leaf, key bindings, and the Merkle root recomputed from the
    leaves. Any mismatch is a tamper alert. With a `trusted_directory`
    (a witness directory *you* trust, never the chain's own) the witness
    quorum is scored too and the verdict can reach "witnessed".

    Returns: verdict (witnessed / consistent_unwitnessed / unanchored /
    diverged), the full check report, and a list of tamper alerts (empty
    when the chain is intact).
    """
    log, lock = await _get(session_id)
    async with lock:
        dossier = log.to_dossier_json()
        ident = log.identity_pubkey_hex()
    report = json.loads(
        wl.verify_dossier_json(
            dossier,
            DEFAULT_THRESHOLD,
            ident,
            json.dumps(trusted_directory) if trusted_directory is not None else None,
        )
    )
    alerts = [
        f"{check} failed"
        for check in (
            "checkpoint_signature_valid",
            "identity_bound",
            "leaves_structurally_valid",
            "bindings_valid",
            "merkle_continuity_valid",
        )
        if report.get(check) is False
    ]
    return {"verdict": report.get("verdict"), "tamper_alerts": alerts, "report": report}


@server.tool()
async def redact_audit_entry(session_id: str, entry_index: int) -> dict[str, Any]:
    """Erase one entry's payload for GDPR while keeping every proof valid.

    Each payload is committed as `SHA256(pad(payload) || salt || index)`
    with a salt held only by this log. Forgetting the salt makes the
    payload unrecoverable from the tree, and a redaction marker leaf is
    appended so verifiers see that an entry was erased and when. No
    existing leaf hash changes, so the root, every inclusion proof and
    every witness cosignature stay valid.

    Returns: whether a payload was erased (False if the entry had no
    live payload or was already forgotten), the marker's index, and the
    root before and after (identical except for the appended marker).
    """
    log, lock = await _get(session_id)
    async with lock:
        before = log.tree_size()
        erased = log.forget(entry_index)
        await asyncio.to_thread(log.sync)
        after = log.tree_size()
        return {
            "erased": erased,
            "entry_index": entry_index,
            "redaction_marker_index": after - 1 if after > before else None,
            "tree_size": after,
            "root_hash": log.root_hex(),
            "proofs_unaffected": True,
        }


@server.tool()
async def export_dossier(session_id: str) -> dict[str, Any]:
    """The portable, offline-verifiable record of this chain.

    A dossier is one JSON document: every leaf, the signed checkpoint,
    the key bindings, and any witness receipts. Anyone can verify it
    with `witness-log verify dossier.json --identity <identity_pubkey>`
    (exit 0 = WITNESSED, 10 = consistent but unwitnessed, 20 =
    unanchored, 30 = diverged) or `witness_log.verify_dossier_json`.
    """
    log, lock = await _get(session_id)
    async with lock:
        dossier = log.to_dossier_json()
        ident = log.identity_pubkey_hex()
    return {
        "dossier": json.loads(dossier),
        "verify_command": f"witness-log verify dossier.json --identity {ident} --directory <directory you trust>",
    }


def _post(url: str, body: str) -> tuple[int, str]:
    req = urllib.request.Request(
        url.rstrip("/") + "/add-checkpoint",
        data=body.encode(),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=WITNESS_TIMEOUT_S) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


@server.tool()
async def submit_to_witnesses(
    session_id: str, directory: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """Get the current head cosigned by independent witnesses.

    Sends the signed checkpoint (with a consistency proof from what each
    witness last cosigned) to every witness in `directory` -- or in
    `$WITNESS_LOG_HOME/witnesses.json` -- over the c2sp.org/tlog-witness
    protocol, keeps only cosignatures that verify against the witness's
    published key, and returns a dossier carrying them plus the verdict a
    verifier holding that directory would reach. WITNESSED needs valid
    cosignatures from at least two distinct independent operators.
    """
    if directory is None:
        p = HOME / "witnesses.json"
        if not p.exists():
            raise ValueError(f"no directory given and {p} does not exist")
        directory = json.loads(p.read_text())
    witnesses = directory.get("witnesses") or []
    if not witnesses:
        raise ValueError("directory has no witnesses")
    log, lock = await _get(session_id)
    state_path = _journal_path(session_id).with_suffix(".jsonl.witnesses.json")
    try:
        sizes: dict[str, int] = json.loads(state_path.read_text()) if state_path.exists() else {}
    except (OSError, ValueError):
        sizes = {}
    async with lock:
        size = log.tree_size()
        outcomes: list[dict[str, Any]] = []
        responses: list[tuple[str, str]] = []

        async def one(w: dict[str, Any]) -> None:
            pk = str(w.get("pubkey", "")).lower()
            old = sizes.get(pk, 0)
            if old > size:
                old = 0
            status, text = 0, ""
            for _ in range(4):
                body = log.add_checkpoint_body(old)
                try:
                    status, text = await asyncio.to_thread(_post, str(w.get("url", "")), body)
                except (urllib.error.URLError, OSError, ValueError) as e:
                    outcomes.append({"witness": w.get("name"), "status": 0, "error": str(e)})
                    return
                if status == 409:
                    try:
                        old = int(text.strip())
                    except ValueError:
                        break
                    if old > size:
                        break
                    continue
                break
            outcomes.append({"witness": w.get("name"), "status": status, "body": text.strip()[:200]})
            if status == 200:
                responses.append((pk, text))
                sizes[pk] = size

        await asyncio.gather(*(one(w) for w in witnesses))
        dossier, accepted = log.dossier_from_responses(responses)
        ident = log.identity_pubkey_hex()
    try:
        state_path.write_text(json.dumps(sizes))
    except OSError:
        pass
    doc = json.loads(dossier)
    doc["witness_directory"] = directory
    report = json.loads(
        wl.verify_dossier_json(json.dumps(doc), DEFAULT_THRESHOLD, ident, json.dumps(directory))
    )
    return {
        "cosignatures_accepted": accepted,
        "witnesses_contacted": len(witnesses),
        "outcomes": outcomes,
        "verdict": report.get("verdict"),
        "dossier": doc,
    }


if __name__ == "__main__":
    server.run()
