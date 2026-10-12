#!/usr/bin/env python3
"""Print a witness directory ({"witnesses": [...]}) from registry/witnesses/*.json.
--exclude-project drops is_project_operated entries.
--registry-dir DIR reads DIR/*.json instead (for testing)."""
import glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
reg = os.path.join(HERE, "witnesses")
if "--registry-dir" in sys.argv:
    reg = sys.argv[sys.argv.index("--registry-dir") + 1]
entries = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(reg, "*.json")))]
if "--exclude-project" in sys.argv:
    entries = [e for e in entries if not e.get("is_project_operated")]
json.dump({"witnesses": entries}, sys.stdout, indent=1)
print()
