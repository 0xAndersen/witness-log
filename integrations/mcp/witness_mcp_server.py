#!/usr/bin/env python3
"""witness-log MCP server (stdio).

Since 0.3.6 the server ships inside the Python package, so nothing needs
to be copied from this repository:

    pip install "witness-log[mcp]"
    witness-log-mcp                       # or: python -m witness_log.mcp_server

This file is kept so existing client configurations that point at
``integrations/mcp/witness_mcp_server.py`` keep working. The tools, their
arguments and the on-disk state are documented in
``witness_log/mcp_server.py`` and in ``integrations/mcp/README.md``.
"""

from __future__ import annotations

import sys

try:
    from witness_log.mcp_server import *  # noqa: F401,F403 -- re-export for importers
    from witness_log.mcp_server import main, server  # noqa: F401
except ImportError as e:  # pragma: no cover - depends on the installed wheel
    sys.exit(
        f"{e}\n\nThis launcher needs witness-log >= 0.3.6 with the MCP SDK:\n"
        '    pip install "witness-log[mcp]>=0.3.6"\n'
        "then run `witness-log-mcp`."
    )

if __name__ == "__main__":
    main()
