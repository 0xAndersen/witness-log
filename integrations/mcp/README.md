# witness-log MCP server

Gives any MCP-capable agent its own tamper-evident audit trail as tools.
Since 0.3.6 it ships in the Python package (`witness_log.mcp_server`,
console script `witness-log-mcp`); `witness_mcp_server.py` here is a
launcher kept for existing configurations.

| Tool | What it does |
|---|---|
| `initialize_witness_chain(session_id, metadata?)` | Create, or resume on boot, a Merkle log bound to an Ed25519 identity. Idempotent. |
| `append_audit_step(session_id, intent, tool_name, payload?, state_transition?)` | Record a step as an intent leaf (+ a result leaf). Returns a signed checkpoint and an inclusion proof. |
| `record_result(session_id, intent_index, tool_name, outcome="ok", value?)` | The result leaf for an intent recorded earlier with `append_audit_step` (no `state_transition`): intent before acting, result after. |
| `get_inclusion_proof(session_id, entry_index)` | Proof an entry is in the tree; verifiable offline by any RFC 6962 verifier. |
| `verify_chain_integrity(session_id, trusted_directory?, min_witnesses?)` | Re-run the full verifier; returns the verdict and any tamper alerts. Includes the cosignatures from the last `submit_to_witnesses` while the chain has not grown; `witnessed_size` / `witnessed_verdict` report the latest witnessed head. Once the chain has grown, that head is checked as a known head, so a journal rewritten after witnessing reports `diverged`; a failed check reports `invalid` (0.5.0+). |
| `redact_audit_entry(session_id, entry_index)` | GDPR erasure of one payload; all proofs stay valid. |
| `export_dossier(session_id)` | The portable record anyone can verify with `witness-log verify`. Carries the last cosignatures when the head is unchanged; otherwise `witnessed_dossier` is the latest witnessed prefix. Also written to `<session>/dossier.json` (`path`, `sha256`, `bytes`). |
| `record_handoff(session_id, direction, counterparty_identity_pubkey, state)` | One side of an agent-to-agent handoff (SPEC §3.1): `"sent"` or `"received"`, with the other agent's identity key (64 hex). `witness-log bind a.json b.json` proves both sides committed to the same bytes. |
| `record_authorization(session_id, kind, counterparty_identity_pubkey, scope)` | A delegation / scope change / revocation between two agents (SPEC §3.2), logging only. Put an AP2 mandate hash or a UCAN in `scope`; both sides commit to its hash and `bind` matches them. |
| `submit_to_witnesses(session_id, directory?, max_witnesses=8, min_witnesses=2)` | Get the head cosigned by up to `max_witnesses` diversity-selected witnesses over `c2sp.org/tlog-witness`; WITNESSED needs `min_witnesses` cosignatures from two independent operators. http(s) witness URLs only; redirects are not followed; a directory passed in the call may not name link-local or metadata addresses, nor loopback or private ones unless `WITNESS_LOG_ALLOW_PRIVATE_WITNESSES=1`. |
| `audit_this_session(session_id)` | `{leaf_count, root, identity, witnessed, last_verdict, witnessed_size, journal}`: where the trail stands, no side effects. |

Eleven tools. `record_authorization.kind` is a JSON-schema enum of the six
SPEC §3.2 kinds; `scope` is a JSON object (committed as RFC 8785 canonical
JSON) or a string (its UTF-8 bytes). `export_dossier` also writes
`<session>/dossier.json` and returns its `path`, `sha256` and `bytes`.

Errors come back as tool errors with the reason (`session_id must be ...`,
`counterparty must be ... 64 hex characters`), so an agent can correct the
call.

## Run

Python 3.10 or newer (the MCP SDK's requirement; the `witness-log`
package itself supports 3.9).

```sh
pip install "witness-log[mcp]"
witness-log-mcp                                   # stdio; or: python -m witness_log.mcp_server
# nothing to install:
uvx --from "witness-log[mcp]" witness-log-mcp
# interactive inspector:
uv run --with "mcp[cli]>=2" --with "witness-log[mcp]" mcp dev "$(python -c 'import witness_log.mcp_server as m; print(m.__file__)')"
```

Client configuration (Claude Desktop, Claude Code, any MCP host):

```json
{"mcpServers": {"witness-log": {
  "command": "uvx",
  "args": ["--from", "witness-log[mcp]", "witness-log-mcp"],
  "env": {"WITNESS_LOG_HOME": "/var/lib/witness-log"}}}}
```

State lives under `$WITNESS_LOG_HOME` (default `~/.witness-log/mcp`): one
directory per session with the journal (identity seed in its header,
mode 0600, unless `WITNESS_LOG_IDENTITY_SEED_ENV` names an environment
variable holding a 32-byte hex seed, in which case every session is
sealed to that identity and the seed never touches a journal file),
`dossier.json` (the last export), `journal.jsonl.witnesses.json` (what each witness last
cosigned: the same file and format `witness-log witness submit` uses, so
the CLI can take over a session's witnessing) and
`journal.jsonl.witnessed.json` (the latest witnessed dossier). Put a
witness directory you trust at `$WITNESS_LOG_HOME/witnesses.json` and
`submit_to_witnesses` uses it by default.

From TypeScript, `@witness-log/client` (`clients/typescript`) starts this
server over stdio and wraps the tools as `step(name, fn)`, `forget(i)`,
`exportDossier()` and `verify()`.

## Guarantees and limits

- Nothing is ever edited in place; the journal is append-only. Leaves are
  not signed one by one: each names the session key that wrote it (bound
  to the identity key), and the identity-signed checkpoint over the
  whole tree is what makes the record tamper-evident.
- Payloads are stored only as salted hashes in the tree (the journal
  keeps the hash, not your data; log what you need to prove, not
  secrets). A payload over 1 MB is refused: log a hash of it instead.
- One process per journal. A second process gets a clear error, never a
  corrupted log. Within a process each journal is opened once and kept
  open: a tool call is an append and an fsync, not a resume.
- To audit an MCP server you already run instead of giving the model
  tools, `witness-log-mcp-proxy --name <server> --journal <file> -- <server
  command>` wraps it ([MCP proxy](../../docs/wiki/MCP-Proxy.md)).
- `submit_to_witnesses` refuses to submit a journal that does not extend
  the head witnesses already cosigned for this identity (a journal
  restored from an old backup), as the CLI does.
- `verify_chain_integrity` without a trusted directory proves internal
  consistency only (verdict `unanchored`). Independence comes from
  witnesses *you* choose, not the model: pin them with
  `WITNESS_LOG_TRUSTED_DIRECTORY=<file>` or `witness-log-mcp
  --trusted-directory <file>`, and a directory passed in a tool call is
  refused. Every verdict carries `directory_source` (`pinned`, `default`,
  `caller` or null); act only on `pinned` ([MCP
  integration](../../docs/wiki/MCP-Integration.md#pin-the-trust-anchor)).

Tested end to end over stdio with the official client:
`pytest -q integrations/mcp -p anyio`.
