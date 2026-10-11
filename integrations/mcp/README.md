# witness-log MCP server

Gives any MCP-capable agent its own tamper-evident audit trail as tools.
One file, no framework: `witness_mcp_server.py` on top of the
`witness-log` wheel (from the Releases page until PyPI publication lands).

| Tool | What it does |
|---|---|
| `initialize_witness_chain(session_id, metadata?)` | Create, or resume on boot, a Merkle log bound to an Ed25519 identity. Idempotent. |
| `append_audit_step(session_id, intent, tool_name, payload?, state_transition?)` | Record a step as an intent leaf (+ a result leaf). Returns a signed checkpoint and an inclusion proof. |
| `get_inclusion_proof(session_id, entry_index)` | Proof an entry is in the tree; verifiable offline by any RFC 6962 verifier. |
| `verify_chain_integrity(session_id, trusted_directory?, min_witnesses?)` | Re-run the full verifier; returns the verdict and any tamper alerts. `min_witnesses` gates on an absolute count (use for large directories). |
| `redact_audit_entry(session_id, entry_index)` | GDPR erasure of one payload; all proofs stay valid. |
| `export_dossier(session_id)` | The portable record anyone can verify with `witness-log verify`. |
| `record_handoff(session_id, direction, counterparty_identity_pubkey, state)` | One side of an agent-to-agent handoff (SPEC §3.1): `"sent"` or `"received"`, with the other agent's identity. `witness-log bind a.json b.json` proves both sides committed to the same bytes. |
| `record_authorization(session_id, kind, counterparty_identity_pubkey, scope)` | A delegation / scope change / revocation between two agents (SPEC §3.2), logging only. Put an AP2 mandate hash or a UCAN in `scope`; both sides commit to its hash and `bind` matches them. |
| `submit_to_witnesses(session_id, directory?, max_witnesses=8, min_witnesses=2)` | Get the head cosigned by up to `max_witnesses` diversity-selected witnesses over `c2sp.org/tlog-witness`; WITNESSED needs `min_witnesses` cosignatures from two independent operators. |

## Run

Python 3.10 or newer (the MCP SDK's requirement; the `witness-log`
package itself supports 3.9).

```sh
pip install "mcp>=2" witness-log
python integrations/mcp/witness_mcp_server.py           # stdio
# or, nothing to install:
uv run --with "mcp>=2" --with witness-log integrations/mcp/witness_mcp_server.py
# interactive inspector:
uv run --with "mcp[cli]>=2" --with witness-log mcp dev integrations/mcp/witness_mcp_server.py
```

Client configuration (Claude Desktop, Claude Code, any MCP host):

```json
{"mcpServers": {"witness-log": {
  "command": "uv",
  "args": ["run", "--with", "mcp>=2", "--with", "witness-log",
           "/absolute/path/to/witness_mcp_server.py"],
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}
```

State lives under `$WITNESS_LOG_HOME` (default `~/.witness-log/mcp`): one
directory per session with the journal (identity seed in its header,
mode 0600). Put a witness directory you trust at
`$WITNESS_LOG_HOME/witnesses.json` and `submit_to_witnesses` uses it by
default.

## Guarantees and limits

- Nothing is ever edited in place; the journal is append-only and every
  leaf is signed by the session key, bound to the identity key.
- Payloads are stored only as salted hashes in the tree (the journal
  keeps the hash, not your data; log what you need to prove, not
  secrets). A payload over 1 MB is refused: log a hash of it instead.
- One process per journal. A second process gets a clear error, never a
  corrupted log.
- `verify_chain_integrity` without a trusted directory proves internal
  consistency only (verdict `unanchored`). Independence comes from
  witnesses *you* choose.

Tested end to end over stdio with the official client:
`pytest -q integrations/mcp -p anyio`.
