"""A minimal stdio MCP server for testing witness-log-mcp-proxy: JSON-RPC
over newline-delimited stdin/stdout. One tool, `echo`, which returns its
arguments; `{"crash": true}` makes the server exit mid-call, `{"sleep":
s}` delays the answer, `{"fail": true}` returns isError, `{"rpc_error":
true}` returns a JSON-RPC error. Each start writes its PID to the file
named by FAKE_MCP_PIDFILE (if set) so a test can see restarts."""

from __future__ import annotations

import json
import os
import sys
import time


def _send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    if os.environ.get("FAKE_MCP_PIDFILE"):
        with open(os.environ["FAKE_MCP_PIDFILE"], "a") as f:
            f.write(f"{os.getpid()}\n")
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "returns its arguments",
                                "inputSchema": {"type": "object"},
                            }
                        ]
                    },
                }
            )
        elif method == "tools/call":
            args = (msg.get("params") or {}).get("arguments") or {}
            if args.get("crash"):
                os._exit(3)
            if args.get("sleep"):
                time.sleep(float(args["sleep"]))
            if args.get("rpc_error"):
                _send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "bad params"}})
                continue
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(args)}],
                        "isError": bool(args.get("fail")),
                    },
                }
            )
        elif mid is not None:
            _send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"no method {method}"}})


if __name__ == "__main__":
    main()
