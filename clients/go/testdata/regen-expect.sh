#!/usr/bin/env bash
# Rewrites clients/go/testdata/expect/ (and c2sp/bind.expected.*) from the
# CURRENT golden dossiers with the current Rust CLI, without regenerating
# the dossiers themselves. Run after a change to the reference verifier's
# report or exit codes; regen.sh calls it after writing new dossiers.
#
#   clients/go/testdata/regen-expect.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
cd "$repo"
cargo build -q -p witness-log-cli
cli="${RUST_CLI:-$repo/target/debug/witness-log}"
mkdir -p "$here/expect"
a_id="$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['identity_pubkey'])" "$here/c2sp/a.json")"
b_id="$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['identity_pubkey'])" "$here/c2sp/b.json")"

# ---- Rust expectations -------------------------------------------------
expect() { # name dossier [verify args...]
  local name="$1"; shift
  set +e
  "$cli" verify "$@" --json > "$here/expect/$name.json"
  echo "$?" > "$here/expect/$name.exit"
  set -e
}
expect native.unanchored "$here/native/dossier.json"
expect native.directory "$here/native/dossier.json" --directory "$here/native/trusted.json"
native_id="$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['identity_pubkey'])" "$here/native/dossier.json")"
expect native.pinned "$here/native/dossier.json" --directory "$here/native/trusted.json" --identity "$native_id"
expect native.wrong-identity "$here/native/dossier.json" --directory "$here/native/trusted.json" --identity "$b_id"
expect native.min-witnesses-4 "$here/native/dossier.json" --directory "$here/native/trusted.json" --min-witnesses 4
expect native.threshold-1 "$here/native/dossier.json" --directory "$here/native/trusted.json" --threshold 1.0
expect native.c2sp-directory "$here/native/dossier.json" --directory "$here/c2sp/trusted.json"
expect c2sp-a.unanchored "$here/c2sp/a.json"
expect c2sp-a.directory "$here/c2sp/a.json" --directory "$here/c2sp/trusted.json"
expect c2sp-a.pinned "$here/c2sp/a.json" --directory "$here/c2sp/trusted.json" --identity "$a_id"
expect c2sp-a.wrong-identity "$here/c2sp/a.json" --directory "$here/c2sp/trusted.json" --identity "$b_id"
expect c2sp-a.min-witnesses-3 "$here/c2sp/a.json" --directory "$here/c2sp/trusted.json" --min-witnesses 3
expect c2sp-b.directory "$here/c2sp/b.json" --directory "$here/c2sp/trusted.json"
expect c2sp-b.pinned "$here/c2sp/b.json" --directory "$here/c2sp/trusted.json" --identity "$b_id"
expect c2sp-b.native-directory "$here/c2sp/b.json" --directory "$here/native/trusted.json"

set +e
"$cli" bind "$here/c2sp/a.json" "$here/c2sp/b.json" --json > "$here/c2sp/bind.expected.json"
echo "$?" > "$here/c2sp/bind.expected.exit"
set -e

# The expectations embed absolute paths; make them relative so the files
# are stable across checkouts.
python3 -I - "$here" "$here"/expect/*.json "$here/c2sp/bind.expected.json" <<'EOF'
import json, sys
here = sys.argv[1]
for p in sys.argv[2:]:
    text = open(p).read().replace(here + "/", "")
    open(p, "w").write(text)
EOF

echo "regenerated goldens under $here"
