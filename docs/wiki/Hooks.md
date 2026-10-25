# Hooks: record a coding agent's tool calls from its hook system

Claude Code (and other coding agents) can run a command before and after
every tool call, with the event as JSON on stdin. `witness-log-hook` turns
that event into a leaf. Because a hook is a fresh process each time, and a
journal admits one writer, the hook does not open the journal itself: it
sends the event to `witness-log-hookd`, a small daemon that holds the
journal open behind a Unix socket. Both ship in the `witness-log` Python
package (stdlib only; Unix sockets, so not Windows).

<!-- doctest -->
```sh
pip install witness-log
witness-log-hook install claude-code --journal ~/.witness-log/claude-code.jsonl
```

prints (and does not write) the entries for `.claude/settings.json`, with
the journal path your shell expanded:

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "", "hooks": [{"type": "command", "command": "witness-log-hook --autostart --journal /home/you/.witness-log/claude-code.jsonl"}]}],
  "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "witness-log-hook --autostart --journal /home/you/.witness-log/claude-code.jsonl"}]}]}}
```

`--autostart` starts the daemon on the first call if none is listening.
From then on every tool call is an intent leaf (`PreToolUse`) and a result
leaf (`PostToolUse`), fsynced before the hook returns.

An agent built on the Claude Agent SDK gets the same payloads in process,
with no hook command and no daemon:
`ClaudeAgentOptions(hooks=witness_hooks(log))` from
`witness_log.integrations.claude_agent_sdk` (see
[Framework guides](Framework-Guides#claude-agent-sdk)).

## What is recorded

Claude Code's event (`session_id`, `transcript_path`, `cwd`,
`hook_event_name`, `tool_name`, `tool_input`, plus `tool_response` on
`PostToolUse` and `tool_use_id` where the version provides it) becomes:

```
PreToolUse  -> intent leaf:  canonical_json({"profile": "hook.claude-code v1", "event": "PreToolUse",
                                              "session_id", "tool_name", "tool_input", ["tool_use_id"], ["cwd"]})
PostToolUse -> result leaf:  the same plus "tool_response"
other event -> memory leaf:  the same plus every other field of the event
```

`transcript_path` is never recorded. The generic shape
`{"tool": ..., "args": ..., "result": ...}` becomes `{"profile":
"hook.generic v1", "tool", "args", ["result"]}` (intent without `result`,
result with it; `"kind"` in the event or `--kind` overrides). Events that
carry `tool_name`/`tool_input` (and `tool_response` or `output`) without a
`hook_event_name` are read the generic way. Anything else is recorded
whole as a memory leaf under `{"profile": "hook.generic v1", "event":
...}`, so an unexpected shape is still on the record.

Payloads are RFC 8785 canonical JSON, salted per leaf: `log.forget(i)`
erases one, `log.disclose(i)` reveals one to an auditor, and the daemon's
`export` writes a dossier anyone can verify with `witness-log verify`.

## Failure policy

The hook exits 0 whatever happens (daemon missing, socket refused,
malformed stdin), writing the reason to stderr, so a problem with the
audit trail never blocks the agent. With `--strict` it exits 2 instead;
Claude Code then blocks the tool call and shows the model the reason. Use
`--strict` where an unrecorded action is worse than a stopped one.

## The daemon

```sh
witness-log-hookd --journal ~/.witness-log/claude-code.jsonl                 # foreground
witness-log-hookd --journal agent.jsonl --socket /run/user/1000/wl.sock \
    --directory trusted.json --submit-every 50                              # witness every 50 appends
```

- Socket: `--socket`, default `$XDG_RUNTIME_DIR/witness-log-hookd.sock`
  or, without `XDG_RUNTIME_DIR`, `<tmpdir>/witness-log-<uid>/hookd.sock`;
  created `0600`. A stale socket file is replaced; a live one makes the
  second daemon refuse. The socket carries every tool call's input and
  output in plaintext, so the daemon creates the `witness-log-<uid>`
  directory `0700` and refuses to start if it exists owned by another
  user, as a symlink or file, or with group or other permissions (through
  0.6.0 the fallback was a socket name directly in the shared temp
  directory, which another local user could bind first). The hook sends
  nothing to a socket file another user owns, nor, on Linux, to a daemon
  running as another user (`SO_PEERCRED`); it reports "not recorded" and
  exits 0, or 2 with `--strict`. An explicit `--socket` should be in a
  directory only you can write to.
- Journal: `witness_log.open` rules. `WITNESS_LOG_IDENTITY_SEED_ENV` in
  the daemon's environment seals it (the hook passes nothing about keys).
- Protocol, one JSON object per line: `{"op": "append", "leaf":
  "intent"|"result"|"memory", "payload": <JSON>}` ->
  `{"ok", "index", "tree_size", "root"}`; `{"op": "status"}`;
  `{"op": "export"}` -> `{"path", "sha256", "bytes"}` (`<journal>.dossier.json`);
  `{"op": "submit"}` (needs `--directory`); `{"op": "sync"}`;
  `{"op": "shutdown"}`. `witness_log.hook.request(socket, req)` is a
  client for scripts.
- Witnessing: with `--directory`, every `--submit-every` appends and on
  shutdown. `--subject-org ORG` (default `$WITNESS_LOG_SUBJECT_ORG`) names
  the organisation that operates the journal, so its own witnesses never
  count as independent in the verdict (as `witness-log verify
  --subject-org`).

## Cursor and Codex

`witness-log-hook install cursor` and `install codex` print templates.
The command is the same; what differs is how each host names its events
and where its hook configuration lives, and that changes between
versions, so check the printed event names against your host's hooks
documentation before relying on them. Whatever JSON the host delivers is
recorded: with `tool_name`/`tool_input`-like fields under the generic
profile, otherwise whole as a memory leaf. Pass `--kind intent` or
`--kind result` per hook when the host does not distinguish before from
after.

For a host whose tools are MCP servers, the [MCP proxy](MCP-Proxy)
records every call at the protocol boundary and needs no hook support at
all.
