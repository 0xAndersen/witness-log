#!/usr/bin/env bash
# Regenerates the golden dossiers under clients/go/testdata from the Rust
# reference implementation. The Go and wasm verifiers are tested against
# these files AND against the Rust CLI's own `verify --json` / `bind --json`
# output on them, so a change in the reference verifier shows up as a Go
# test failure here, not as silent drift.
#
#   clients/go/testdata/regen.sh
#
# Needs: cargo (the repository's Rust workspace), python3, two free TCP
# ports on 127.0.0.1. Everything the Rust side produces is random per run
# (fresh identities, fresh salts), so the files change on every
# regeneration; the Go tests check verdicts and report fields, not bytes.
#
# Layout written:
#   native/   dossier.json + trusted.json from witness-log-network's
#             generate_sample_dossier example (native §7 receipts, a
#             redaction leaf, one key binding; WITNESSED with trusted.json)
#   c2sp/     a.json, b.json: two agents' journals cosigned by two local
#             `witness-log witness serve` instances (C2SP cosignature
#             receipts); trusted.json is the two `witness init` entries;
#             bind.expected.json is `witness-log bind a.json b.json --json`;
#             disclosure.json is leaf 0 of A's payload and salt (SPEC §8)
#   expect/   `witness-log verify --json` for every dossier x context
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
cd "$repo"

cargo build -q -p witness-log-cli
cargo build -q -p witness-log-wasm --example golden_journals
cli="$repo/target/debug/witness-log"
work="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT

rm -rf "$here/native" "$here/c2sp" "$here/expect"
mkdir -p "$here/native" "$here/c2sp" "$here/expect"

# ---- native receipts: the README's sample dossier generator -------------
(cd "$work" && cargo run -q --manifest-path "$repo/Cargo.toml" -p witness-log-network --example generate_sample_dossier >/dev/null)
cp "$work/examples/sample-dossier.json" "$here/native/dossier.json"
cp "$work/examples/trusted-directory.json" "$here/native/trusted.json"

# ---- C2SP cosignatures: two journals, two local witnesses ----------------
"$repo/target/debug/examples/golden_journals" "$work/journals" > "$work/identities.txt"
a_id="$(sed -n 1p "$work/identities.txt")"
b_id="$(sed -n 2p "$work/identities.txt")"

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
p1="$(free_port)"; p2="$(free_port)"
"$cli" witness init "$work/w1" --name golden-one.example/witness --org "Golden Org One" --url "http://127.0.0.1:$p1" --compute "provider-one" 2>/dev/null > "$work/w1.json"
"$cli" witness init "$work/w2" --name golden-two.example/witness --org "Golden Org Two" --url "http://127.0.0.1:$p2" --compute "provider-two" 2>/dev/null > "$work/w2.json"
python3 -I - "$work/w1.json" "$work/w2.json" "$here/c2sp/trusted.json" <<'EOF'
import json, sys
entries = [json.load(open(p)) for p in sys.argv[1:3]]
json.dump({"witnesses": entries}, open(sys.argv[3], "w"), indent=2)
EOF

"$cli" witness serve "$work/w1" --listen "127.0.0.1:$p1" --open-enrollment >"$work/w1.log" 2>&1 &
"$cli" witness serve "$work/w2" --listen "127.0.0.1:$p2" --open-enrollment >"$work/w2.log" 2>&1 &
for p in "$p1" "$p2"; do
  for _ in $(seq 1 50); do
    if python3 -I -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:$p/health', timeout=1)" 2>/dev/null; then break; fi
    sleep 0.2
  done
done

"$cli" witness submit "$work/journals/agent-a.jsonl" --directory "$here/c2sp/trusted.json" --out "$here/c2sp/a.json" --state "$work/a.state.json" >/dev/null
"$cli" witness submit "$work/journals/agent-b.jsonl" --directory "$here/c2sp/trusted.json" --out "$here/c2sp/b.json" --state "$work/b.state.json" >/dev/null
kill $(jobs -p) 2>/dev/null || true

# Disclosure fixture: leaf 0 of A is the read_invoice intent (see the
# golden_journals example for the exact bytes); its salt is in the sidecar.
python3 -I - "$work/journals/agent-a.jsonl.salts" "$here/c2sp/disclosure.json" <<'EOF'
import json, sys
salts = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        rec = json.loads(line)
        salts[rec["i"]] = rec["s"]
payload = b'{"tool":"read_invoice","args":{"invoice":"INV-0042"}}'
json.dump({"leaf_index": 0, "payload_hex": payload.hex(), "salt_hex": salts[0],
           "forgotten_leaf_index": 2, "note": "leaf 2 was redacted: its salt is gone and no disclosure of it can verify"},
          open(sys.argv[2], "w"), indent=2)
EOF

"$here/regen-expect.sh"

ls "$here"/native "$here"/c2sp "$here"/expect
