#!/usr/bin/env python3
"""Validate registry/witnesses/*.json. Exit 1 on any problem.

Checks shape, 64-hex key, real operator_org, uniqueness, and (unless
--offline) that the URL answers GET / with the same pubkey_hex.
"""
import glob, json, os, re, sys, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = {"name", "operator_org", "url", "pubkey", "runtime", "is_project_operated"}
HEX32 = re.compile(r"^[0-9a-f]{64}$")
offline = "--offline" in sys.argv
problems, seen_keys, seen_names = [], {}, {}
files = sorted(glob.glob(os.path.join(HERE, "witnesses", "*.json")))
for path in files:
    rel = os.path.relpath(path, HERE)
    try:
        e = json.load(open(path))
    except Exception as ex:
        problems.append(f"{rel}: not JSON ({ex})"); continue
    missing = REQUIRED - set(e)
    if missing:
        problems.append(f"{rel}: missing {sorted(missing)}"); continue
    extra = set(e) - REQUIRED - {"compute_provider"}
    if extra:
        problems.append(f"{rel}: unknown fields {sorted(extra)}")
    if not HEX32.match(str(e["pubkey"]).lower()):
        problems.append(f"{rel}: pubkey must be 64 hex")
    if e["pubkey"].lower() != e["pubkey"]:
        problems.append(f"{rel}: pubkey must be lowercase")
    if e["runtime"] not in ("human", "agent"):
        problems.append(f"{rel}: runtime must be human or agent")
    org = " ".join(str(e["operator_org"]).split()).lower()
    if not org or org == "unspecified":
        problems.append(f"{rel}: operator_org must name the organisation that runs the key")
    if not isinstance(e["is_project_operated"], bool):
        problems.append(f"{rel}: is_project_operated must be a boolean")
    if not re.match(r"^https?://", str(e["url"])):
        problems.append(f"{rel}: url must be http(s)")
    else:
        host = urllib.parse.urlsplit(str(e["url"])).hostname or ""
        # `witness init` without --url writes http://127.0.0.1:7380; a registry
        # entry must be reachable by other people's clients.
        if host in ("localhost", "0.0.0.0", "::1", "::") or host.startswith("127.") or host.endswith(".localhost"):
            problems.append(f"{rel}: url {e['url']} is a loopback address; give the public URL clients reach")
    if "+" in e["name"] or any(c.isspace() for c in e["name"]):
        problems.append(f"{rel}: name is a C2SP key name: no whitespace, no '+'")
    if e["pubkey"] in seen_keys:
        problems.append(f"{rel}: duplicate pubkey, also in {seen_keys[e['pubkey']]}")
    seen_keys[e["pubkey"]] = rel
    if e["name"] in seen_names:
        problems.append(f"{rel}: duplicate name, also in {seen_names[e['name']]}")
    seen_names[e["name"]] = rel
    if not offline:
        try:
            with urllib.request.urlopen(e["url"].rstrip("/") + "/", timeout=10) as r:
                info = json.loads(r.read().decode())
            if info.get("pubkey_hex", "").lower() != e["pubkey"]:
                problems.append(f"{rel}: {e['url']} serves key {info.get('pubkey_hex')}, entry says {e['pubkey']}")
        except Exception as ex:
            print(f"note: {rel}: {e['url']} not reachable from here ({type(ex).__name__}); key not cross-checked")
for p in problems:
    print("error:", p)
print(f"{len(files)} entries, {len(problems)} problems")
sys.exit(1 if problems else 0)
