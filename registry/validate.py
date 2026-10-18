#!/usr/bin/env python3
"""Validate registry/witnesses/*.json. Exit 1 on any problem.

Offline checks (always): shape and types, 64 lowercase hex pubkey, a real
operator_org, runtime, https URL that is not a loopback or other
non-public address (an IP literal must be a public address in ordinary
dotted or IPv6 notation), C2SP key name, no invisible or control
characters in the name, operator_org or compute_provider, no duplicate
key or name.

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


# Characters that render as nothing (or as a space that is not U+0020): a
# label with one looks identical to a label without it, yet the verifier
# compares labels exactly, so one operator could register as two
# "independent" ones. Kept as an explicit list, not unicodedata, so this
# script and `witness-log directory build` refuse exactly the same text:
# C0 and C1 controls, format characters (Cf), invisible fillers and
# variation selectors, lone surrogates (JSON can escape them; Rust's JSON
# reader refuses them), private use and noncharacters.
INVISIBLE = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x034F, 0x034F),
    (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F),
    (0x0890, 0x0891), (0x08E2, 0x08E2), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
    (0x2800, 0x2800), (0x3164, 0x3164), (0xD800, 0xDFFF), (0xE000, 0xF8FF), (0xFDD0, 0xFDEF),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
    (0xF0000, 0x10FFFF),
)


def invisible_chars(text: str) -> list:
    """The code points in ``text`` from INVISIBLE (or U+xFFFE/U+xFFFF)."""
    bad = []
    for c in text:
        o = ord(c)
        if (o & 0xFFFE) == 0xFFFE or any(lo <= o <= hi for lo, hi in INVISIBLE):
            bad.append(f"U+{o:04X}")
    return bad


def numeric_ipv4(host: str):
    """``host`` read as inet_aton reads it (what socket.getaddrinfo, curl
    and browsers accept: ``2130706433``, ``0x7f.1``, ``127.1``), as a
    32-bit int, or None if it is not a numeric IPv4 address."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    vals = []
    for p in parts:
        # Exact ASCII digit classes: int() would also take "_", spaces and
        # non-ASCII digits, which the Rust twin of this check does not.
        if re.fullmatch(r"0[xX][0-9a-fA-F]*", p):
            v = int(p[2:], 16) if p[2:] else 0
        elif re.fullmatch(r"0[0-7]+", p):
            v = int(p, 8)
        elif re.fullmatch(r"[0-9]+", p) and not (len(p) > 1 and p[0] == "0"):
            v = int(p)
        else:
            return None
        vals.append(v)
    last_bits = 8 * (5 - len(vals))
    if any(v > 255 for v in vals[:-1]) or vals[-1] >= 1 << last_bits:
        return None
    n = 0
    for v in vals[:-1]:
        n = n << 8 | v
    return n << last_bits | vals[-1]


# Address blocks no public witness URL may name (RFC 6890 special-purpose
# registries; IPv6 forms that carry an IPv4 address are refused outright).
BLOCKED_V4 = ((0x00000000, 8), (0x0A000000, 8), (0x64400000, 10), (0x7F000000, 8),
              (0xA9FE0000, 16), (0xAC100000, 12), (0xC0000000, 24), (0xC0000200, 24),
              (0xC0586300, 24), (0xC0A80000, 16), (0xC6120000, 15), (0xC6336400, 24),
              (0xCB007100, 24), (0xE0000000, 4), (0xF0000000, 4))
BLOCKED_V6 = (("::", 96), ("::ffff:0:0", 96), ("64:ff9b::", 96), ("64:ff9b:1::", 48),
              ("100::", 64), ("2001::", 23), ("2001:db8::", 32), ("2002::", 16), ("3fff::", 20),
              ("fc00::", 7), ("fe80::", 10), ("fec0::", 10), ("ff00::", 8))


# A registry URL's authority: a DNS name (ASCII letters, digits, '.', '-';
# an internationalised name in its xn-- form) or a bracketed IPv6 address,
# and an optional port. No user info, no percent-encoding: clients decode
# those differently (urllib unquotes %31 to "1"; IDNA folds fullwidth
# digits to ASCII ones), so a host that looks public here could connect to
# a private address there.
AUTHORITY = re.compile(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::([0-9]{1,5}))?")


def url_scheme_and_host(url: str):
    """(scheme, lowercased host) of a registry URL, or (None, why not).
    The same reading as `url_scheme_and_host` in `witness-log directory
    build`, so both refuse the same URLs."""
    if not all(0x21 <= ord(c) <= 0x7E for c in url) or "\\" in url:
        return None, (f"url {url!r} must be printable ASCII without spaces, control characters "
                      "or backslashes")
    for scheme in ("https", "http"):
        if url.startswith(scheme + "://"):
            break
    else:
        return None, "url must be http(s)"
    authority = re.split(r"[/?#]", url[len(scheme) + 3:], maxsplit=1)[0]
    m = AUTHORITY.fullmatch(authority)
    if not m or (m.group(1) is not None and int(m.group(1)) > 65535):
        return None, (f"url {url}: the host must be a DNS name (letters, digits, '.', '-'; an "
                      "internationalised name in its xn-- form) or an IP address, with an optional "
                      "port; no user info or percent-encoding")
    host = authority[1:authority.index("]")] if authority.startswith("[") else authority.split(":", 1)[0]
    if not host:
        return None, f"url {url} has no host"
    return scheme, host.lower()


def ip_literal_problem(host: str):
    """None if ``host`` is a name or a public IP address written the
    ordinary way; otherwise why a registry URL may not use it."""
    import ipaddress

    host = host[:-1] if host.endswith(".") else host  # "1.2.3.4." resolves like 1.2.3.4
    if ":" in host:
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError:
            return f"host {host!r} is not a valid IPv6 address"
        for net, plen in BLOCKED_V6:
            if ip in ipaddress.IPv6Network(f"{net}/{plen}"):
                return f"host {host} is a non-public or IPv4-embedding IPv6 address"
        return None
    n = numeric_ipv4(host)
    if n is None:
        return None
    dotted = ".".join(str(n >> s & 255) for s in (24, 16, 8, 0))
    if host != dotted:
        return f"host {host!r} is the IPv4 address {dotted} in another notation; write it as {dotted} (or use a name)"
    for net, plen in BLOCKED_V4:
        if n >> (32 - plen) == net >> (32 - plen):
            return f"host {host} is not a public IPv4 address"
    return None


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
    for field in ("name", "operator_org", "url", "pubkey"):
        if not isinstance(e[field], str):
            problems.append(f"{rel}: {field} must be a string")
    if e.get("compute_provider") is not None and not isinstance(e["compute_provider"], str):
        problems.append(f"{rel}: compute_provider must be a string or null")
    if problems and any("must be a string" in p for p in problems):
        return problems
    for field in ("name", "operator_org", "compute_provider"):
        bad = invisible_chars(e.get(field) or "")
        if bad:
            problems.append(
                f"{rel}: {field} contains invisible or control characters ({', '.join(bad)}); "
                "labels are compared exactly, so they would make two labels that look the same differ"
            )
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
    scheme, host = url_scheme_and_host(url)
    if scheme is None:
        problems.append(f"{rel}: {host}")
    else:
        if scheme == "http" and not allow_insecure:
            problems.append(
                f"{rel}: url {url} is plain http; a registry entry must be https "
                "(http is accepted only with --allow-insecure, for tests)"
            )
        # `witness init` without --url writes http://127.0.0.1:7380; a registry
        # entry must be reachable by other people's clients.
        if is_loopback(host) and not allow_insecure:
            problems.append(f"{rel}: url {url} is a loopback address; give the public URL clients reach")
        elif not allow_insecure:
            why = ip_literal_problem(host)
            if why:
                problems.append(f"{rel}: url {url}: {why}")
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
        name = e["name"] if isinstance(e["name"], str) else repr(e["name"])
        if name in seen_names:
            problems.append(f"{rel}: duplicate name, also in {seen_names[name]}")
        seen_names[name] = rel
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
