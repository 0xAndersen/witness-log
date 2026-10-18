# MCP proxy: audit any MCP server you already run

`witness-log-mcp-proxy` sits between an MCP host and a stdio MCP server
and records every tool call in a witness-log journal. The server is
unchanged, the host's configuration changes by one line, and the model is
not asked to do anything. It ships in the `witness-log` Python package
(no extra: stdlib only).

```sh
pip install witness-log
witness-log-mcp-proxy --name git --journal ./git.wlog -- mcp-server-git
```

Put that where the host had `mcp-server-git`:

```json
{"mcpServers": {"git": {
  "command": "witness-log-mcp-proxy",
  "args": ["--name", "git", "--journal", "/var/lib/witness-log/git.wlog", "--", "mcp-server-git"]}}}
```

Anything the host sends arrives at the server unchanged and anything the
server answers arrives at the host unchanged, with three exceptions
described below (two injected tools, and errors the proxy itself issues
on timeout or crash).

## What is recorded

For each `tools/call` request the proxy appends an **intent** leaf before
forwarding it and a **result** leaf when the answer arrives. The leaves
carry hashes, not content: the host keeps its own transcript, and the
hashes bind that transcript to a signed, witnessable tree. Profile string:
`"mcp.tools/call v1"`.

```
intent payload = canonical_json({
    "profile":     "mcp.tools/call v1",
    "server":      <--name>,
    "tool":        <params.name>,
    "args_sha256": hex(SHA-256(canonical_json(params.arguments or {})))
})

result payload = canonical_json({
    "profile":       "mcp.tools/call v1",
    "server":        <--name>,
    "tool":          <params.name>,
    "intent_index":  <index of the intent leaf>,
    "result_sha256": hex(SHA-256(canonical_json(X))),
    "is_error":      <bool>
})
```

where `canonical_json` is RFC 8785 (JCS; `witness_log.canonical_json`),
and `X` is:

| case | `X` | `is_error` |
|---|---|---|
| success response | `response.result` (the whole `CallToolResult` object) | `result.isError == true` |
| JSON-RPC error response | `{"error": response.error}` | `true` |
| proxy timeout | `{"error": {"code": -32000, "message": "witness-log-mcp-proxy: timed out after <N>s"}}` | `true` |
| server exited mid-call | `{"error": {"code": -32000, "message": "witness-log-mcp-proxy: server exited with code <c> during <tool>"}}` | `true` |

Each payload is then committed as `SHA256(bucket_pad(payload) || salt ||
index)` with a fresh salt (SPEC §8), so `log.forget(i)` can erase one and
`log.disclose(i)` can reveal one. To check a recorded call against a
transcript: rebuild the payload above from the transcript's request and
response, then `witness_log.verify_disclosure(leaf, payload, salt)`.

Everything other than `tools/call` (`initialize`, `tools/list`,
`resources/*`, `prompts/*`, notifications, server-initiated requests) is
passed through without a leaf.

## Injected tools

The proxy appends two tools to every `tools/list` response and answers
them itself; the server never sees them.

| tool | returns |
|---|---|
| `audit__status` | `{server, journal, leaf_count, root, identity, calls, restarts, witnessed, last_verdict, directory_source}` |
| `audit__export` | writes `<journal>.dossier.json` and returns `{path, sha256, bytes, verdict, directory_source, split_view_unsafe, tamper_alerts}`; the verdict is `unanchored` unless `--directory` was given (a verifier needs a directory it trusts). The head witnesses last cosigned (`<journal>.witnesses.json`) is checked as a known head: a journal rewritten after witnessing is `diverged`, one truncated below it a tamper alert. `split_view_unsafe` is true for a `witnessed` verdict whose cosigners are not a strict majority of the directory |

A model can call them like any other tool; so can an operator with
`witness-log verify <journal>.dossier.json --identity <identity> --directory trusted.json`.

The trust anchor is the operator's. The only witness directory the proxy
uses is `--directory`, on its own command line in the host's
configuration; nothing the model sends can change it. The injected tools
take no arguments, and a call that passes any (a `directory` lifted from
a document or a tool result, say) is refused with an error rather than
answered as if it had been used. `directory_source` on `audit__export`
and on `audit__status.last_verdict` is `"pinned"` when the verdict was
scored against `--directory` and `null` when there was none, the same
field the [MCP server](MCP-Integration#pin-the-trust-anchor)'s verdicts
carry.

## Supervision and limits

- `--timeout N` (default 60 s): a call unanswered after `N` seconds gets a
  JSON-RPC error at the host and an `is_error` result leaf; a late answer
  from the server is dropped.
- If the server exits, every call it had been sent fails the same way, the
  server is restarted (`--max-restarts`, default 3; an attempt whose
  command cannot be started counts too) and the host's `initialize`
  request and `notifications/initialized` are replayed to it before any
  call. The new server's `initialize` response is not forwarded. A call
  that arrives during the restart is held and sent to the new server, and
  its real result is journaled. Past the limit every pending call fails,
  and the proxy exits with the server's code and the host sees the pipe
  close.
- `--directory trusted.json --submit-every N` submits the journal to those
  witnesses every `N` completed calls and once more when the host closes
  stdin; `audit__status.last_verdict` reports the outcome.
  `witness_log.open` rules apply: `WITNESS_LOG_IDENTITY_SEED_ENV` seals
  the journal, one process per journal.
- Newline-delimited JSON-RPC over stdio only. HTTP transports are not
  proxied; put the proxy in front of a stdio server, or use the
  [MCP server](MCP-Integration) tools instead.

## Compared with the MCP server

The [MCP server](MCP-Integration) gives the *model* audit tools: it
decides what to record and can record intent in its own words, handoffs
and authorizations. The proxy records what *happened* at the protocol
boundary, whether or not the model cooperates, and cannot see anything
the server does outside `tools/call`. They compose: a host can run the
proxy around each server and the witness-log server alongside.
