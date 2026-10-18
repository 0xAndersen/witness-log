#!/usr/bin/env python3
"""Print a witness directory ({"witnesses": [...]}) from registry/witnesses/*.json.

The directory is the trust anchor of every WITNESSED verdict computed
against it, so the build refuses (exit 1, nothing on stdout, every problem
on stderr) unless every entry passes validate.py's offline checks: known
fields only, 64 lowercase hex pubkey, a real operator_org with no stray
whitespace, runtime human or agent, is_project_operated a boolean, an
https:// URL that is not a loopback address, a C2SP key name, and no
duplicate key or name.

validate.py's live check (GET <url>/ serves the entry's key and org) needs
the network, so the build skips it unless --live; with --live an
unreachable URL is a note, and --require-live makes it an error.

--exclude-project drops is_project_operated entries.
--registry-dir DIR reads DIR/*.json instead (for testing).
--allow-insecure accepts http:// and loopback URLs (tests, local fleets).
--timeout SECONDS bounds each live check (default 10).
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate  # noqa: E402


def main(argv=None, out=None) -> int:
    out = out if out is not None else sys.stdout
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--registry-dir", default=os.path.join(HERE, "witnesses"))
    ap.add_argument("--exclude-project", action="store_true")
    ap.add_argument("--allow-insecure", action="store_true")
    ap.add_argument("--live", action="store_true", help="also cross-check every entry against what its URL serves")
    ap.add_argument("--require-live", action="store_true", help="with --live, an unreachable URL is an error")
    ap.add_argument("--timeout", type=float, default=10)
    a = ap.parse_args(argv)
    if a.require_live and not a.live:
        ap.error("--require-live needs --live")
    files, problems, notes = validate.validate(
        a.registry_dir,
        offline=not a.live,
        require_live=a.require_live,
        allow_insecure=a.allow_insecure,
        timeout=a.timeout,
    )
    for n in notes:
        print("note:", n, file=sys.stderr)
    if problems:
        for p in problems:
            print("error:", p, file=sys.stderr)
        print(
            f"refusing to build a directory: {len(problems)} problem(s) in {len(files)} entries "
            "(the same checks as registry/validate.py)",
            file=sys.stderr,
        )
        return 1
    entries = []
    for p in files:
        with open(p, encoding="utf-8") as f:
            entries.append(json.load(f))
    if a.exclude_project:
        entries = [e for e in entries if not e.get("is_project_operated")]
    json.dump({"witnesses": entries}, out, indent=1)
    print(file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
