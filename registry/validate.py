#!/usr/bin/env python3
"""Validate registry/witnesses/*.json. Exit 1 on any problem.

Offline checks (always): shape, 64 lowercase hex pubkey, a real
operator_org, runtime, https URL that is not a loopback address, C2SP key
name, no duplicate key or name.

Live checks (unless --offline): GET <url>/ is what `witness-log witness
serve` answers with its public key and directory entry. The served
`pubkey_hex` must equal the entry's `pubkey`, and the served
`directory_entry.operator_org` must equal the entry's `operator_org`
byte for byte. Organisation names are case-sensitive: "Example Org" and
"example org" are two different labels to the verifier, so the registry
refuses an entry whose label differs from what the witness itself says.

A URL that cannot be reached is reported as a note, not an error, because
CI runs from places a witness may legitimately block; --require-live turns
it into an error (used when registering from a URL that was just fetched).

--allow-insecure accepts http:// and loopback URLs. It exists for the unit
tests, which run a local http.server; a public entry must be https.

Usage: validate.py [--offline] [--require-live] [--allow-insecure]
                   [--registry-dir DIR] [--timeout SECONDS]
"""
import glob
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = {"name", "operator_org", "url", "pubkey", "runtime", "is_project_operated"}
OPTIONAL = {"compute_provider"}
HEX32 = re.compile(r"^[0-9a-f]{64}$")
LOOPBACK = ("localhost", "0.0.0.0", "::1", "::")


def is_loopback(host: str) -> bool:
    return host in LOOPBACK or host.startswith("127.") or host.endswith(".localhost")


def check_entry(e, rel, allow_insecure=False):
    """Offline checks for one entry. Returns a list of problem strings."""
    problems = []
    if not isinstance(e, dict):
        return [f"{rel}: entry must be a JSON object"]
    missing = REQUIRED - set(e)
    if missing:
        return [f"{rel}: missing {sorted(missing)}"]
    extra = set(e) - REQUIRED - OPTIONAL
    if extra:
        problems.append(f"{rel}: unknown fields {sorted(extra)}")
    pubkey = str(e["pubkey"])
    if not HEX32.fullmatch(pubkey.lower()):
        problems.append(f"{rel}: pubkey must be 64 hex")
    elif pubkey.lower() != pubkey:
        problems.append(f"{rel}: pubkey must be lowercase")
    if e["runtime"] not in ("human", "agent"):
        problems.append(f"{rel}: runtime must be human or agent")
    org = str(e["operator_org"])
    if not org.strip() or org.strip().lower() == "unspecified":
        problems.append(f"{rel}: operator_org must name the organisation that runs the key")
    elif org != " ".join(org.split()):
        problems.append(
            f"{rel}: operator_org has leading, trailing or repeated whitespace ({org!r}); "
            "the label is compared byte for byte"
        )
    if not isinstance(e["is_project_operated"], bool):
        problems.append(f"{rel}: is_project_operated must be a boolean")
    url = str(e["url"])
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        problems.append(f"{rel}: url must be http(s)")
    else:
        host = parts.hostname or ""
        if parts.scheme == "http" and not allow_insecure:
            problems.append(
                f"{rel}: url {url} is plain http; a registry entry must be https "
                "(http is accepted only with --allow-insecure, for tests)"
            )
        # `witness init` without --url writes http://127.0.0.1:7380; a registry
        # entry must be reachable by other people's clients.
        if is_loopback(host) and not allow_insecure:
            problems.append(f"{rel}: url {url} is a loopback address; give the public URL clients reach")
    name = str(e["name"])
    if "+" in name or any(c.isspace() for c in name) or not name:
        problems.append(f"{rel}: name is a C2SP key name: non-empty, no whitespace, no '+'")
    return problems


def fetch_info(url, timeout):
    """GET <url>/ and parse the JSON the witness serves. Raises on failure."""
    with urllib.request.urlopen(url.rstrip("/") + "/", timeout=timeout) as r:
        return json.loads(r.read().decode())


def check_live(e, rel, timeout=10, require_live=False, fetch=fetch_info):
    """Cross-check the entry against what its URL serves.

    Returns (problems, notes). Key or organisation mismatch is a problem;
    an unreachable URL is a note unless require_live."""
    problems, notes = [], []
    try:
        info = fetch(str(e["url"]), timeout)
    except Exception as ex:  # URLError, timeout, JSON, HTTP status
        msg = f"{rel}: {e['url']} not reachable from here ({type(ex).__name__}); key and org not cross-checked"
        (problems if require_live else notes).append(msg)
        return problems, notes
    if not isinstance(info, dict):
        problems.append(f"{rel}: {e['url']} did not answer GET / with a JSON object")
        return problems, notes
    served_key = str(info.get("pubkey_hex", "")).lower()
    if served_key != e["pubkey"]:
        problems.append(f"{rel}: {e['url']} serves key {info.get('pubkey_hex')}, entry says {e['pubkey']}")
    de = info.get("directory_entry")
    if not isinstance(de, dict):
        problems.append(f"{rel}: {e['url']} does not advertise a directory_entry (witness-log 0.3.2+ does)")
        return problems, notes
    served_org = de.get("operator_org")
    if served_org != e["operator_org"]:
        problems.append(
            f"{rel}: {e['url']} says operator_org is {served_org!r}, entry says {e['operator_org']!r}; "
            "labels are case-sensitive and must match the witness exactly (re-run `witness init --org` "
            "or fix the entry)"
        )
    return problems, notes


def validate(registry_dir, offline=False, require_live=False, allow_insecure=False, timeout=10, fetch=fetch_info):
    """Validate every *.json in registry_dir. Returns (files, problems, notes)."""
    problems, notes, seen_keys, seen_names = [], [], {}, {}
    files = sorted(glob.glob(os.path.join(registry_dir, "*.json")))
    for path in files:
        rel = os.path.relpath(path, os.path.dirname(registry_dir.rstrip(os.sep)) or ".")
        try:
            with open(path, encoding="utf-8") as f:
                e = json.load(f)
        except Exception as ex:
            problems.append(f"{rel}: not JSON ({ex})")
            continue
        entry_problems = check_entry(e, rel, allow_insecure=allow_insecure)
        problems.extend(entry_problems)
        if not isinstance(e, dict) or REQUIRED - set(e):
            continue
        key = str(e["pubkey"])
        if key in seen_keys:
            problems.append(f"{rel}: duplicate pubkey, also in {seen_keys[key]}")
        seen_keys[key] = rel
        if e["name"] in seen_names:
            problems.append(f"{rel}: duplicate name, also in {seen_names[e['name']]}")
        seen_names[e["name"]] = rel
        if not offline and not entry_problems:
            p, n = check_live(e, rel, timeout=timeout, require_live=require_live, fetch=fetch)
            problems.extend(p)
            notes.extend(n)
    return files, problems, notes


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--help" in argv or "-h" in argv:
        print(__doc__.strip())
        return 0
    registry_dir = os.path.join(HERE, "witnesses")
    timeout = 10
    if "--registry-dir" in argv:
        registry_dir = argv[argv.index("--registry-dir") + 1]
    if "--timeout" in argv:
        timeout = float(argv[argv.index("--timeout") + 1])
    known = {"--offline", "--require-live", "--allow-insecure", "--registry-dir", "--timeout"}
    for i, a in enumerate(argv):
        if a.startswith("--") and a not in known:
            print(f"error: unknown flag {a}\n{__doc__.strip()}", file=sys.stderr)
            return 2
    files, problems, notes = validate(
        registry_dir,
        offline="--offline" in argv,
        require_live="--require-live" in argv,
        allow_insecure="--allow-insecure" in argv,
        timeout=timeout,
    )
    for n in notes:
        print("note:", n)
    for p in problems:
        print("error:", p)
    print(f"{len(files)} entries, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
