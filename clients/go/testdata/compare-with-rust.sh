#!/usr/bin/env bash
# Runs the Rust CLI and the Go CLI over every golden dossier under a matrix
# of contexts and fails if any verdict, exit code or report field differs.
# CI runs this (.github/workflows/go.yml); run it locally after changing
# either verifier:
#
#   cargo build -p witness-log-cli
#   (cd clients/go && go build -o ../../target/witness-log-verify ./cmd/witness-log-verify)
#   clients/go/testdata/compare-with-rust.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
rust="${RUST_CLI:-$repo/target/debug/witness-log}"
gocli="${GO_CLI:-$repo/target/witness-log-verify}"
cd "$here"
fail=0
compare() {
  local label="$1"; shift
  set +e
  "$rust" verify "$@" --json > "${TMPDIR:-/tmp}/wl-rust.json"; local rust_exit=$?
  "$gocli" "$@" --json > "${TMPDIR:-/tmp}/wl-go.json"; local go_exit=$?
  set -e
  python3 -I - "$label" "$rust_exit" "$go_exit" "${TMPDIR:-/tmp}/wl-rust.json" "${TMPDIR:-/tmp}/wl-go.json" <<'EOF'
import json, sys
label, rust_exit, go_exit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
r = json.load(open(sys.argv[4])); g = json.load(open(sys.argv[5]))
# Failure wording is per-implementation; whether a check failed is not.
rf = r["report"].pop("failures", None); gf = g["report"].pop("failures", None)
ok = (rust_exit == go_exit and r["verdict"] == g["verdict"] and r["report"] == g["report"]
      and bool(rf) == bool(gf)
      and all(r.get(k) == g.get(k) for k in ("strict", "allow_sub_majority", "exit_code", "subject_org")))
print(("ok   " if ok else "DIFF ") + f"{label}: rust {r['verdict']} ({rust_exit}), go {g['verdict']} ({go_exit})")
if not ok:
    for k in sorted(set(r["report"]) | set(g["report"])):
        if r["report"].get(k) != g["report"].get(k):
            print(f"       report.{k}: rust {r['report'].get(k)!r} go {g['report'].get(k)!r}")
sys.exit(0 if ok else 1)
EOF
}
wrong_identity="$(printf 'ab%.0s' $(seq 32))"
for d in native/dossier.json c2sp/a.json c2sp/b.json; do
  compare "$d, no directory" "$d" || fail=1
  for dir in native/trusted.json c2sp/trusted.json; do
    compare "$d + $dir" "$d" --directory "$dir" || fail=1
    compare "$d + $dir, --min-witnesses 2" "$d" --directory "$dir" --min-witnesses 2 || fail=1
    compare "$d + $dir, --threshold 1.0" "$d" --directory "$dir" --threshold 1.0 || fail=1
    compare "$d + $dir, wrong --identity" "$d" --directory "$dir" --identity "$wrong_identity" || fail=1
    compare "$d + $dir, --min-witnesses 1" "$d" --directory "$dir" --min-witnesses 1 || fail=1
    compare "$d + $dir, --min-witnesses 1 --allow-sub-majority" "$d" --directory "$dir" --min-witnesses 1 --allow-sub-majority || fail=1
    compare "$d + $dir, --min-witnesses 1 --no-strict" "$d" --directory "$dir" --min-witnesses 1 --no-strict || fail=1
  done
  compare "$d, wrong --known-head" "$d" --known-head "1:$wrong_identity" || fail=1
done
# RFC-0002 exit 11: native has 3 of 4 receipts; keep two (two operators),
# which is WITNESSED under --min-witnesses 2 but not a strict majority.
two_of_four="${TMPDIR:-/tmp}/wl-two-of-four.json"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d["witness_receipts"]=d["witness_receipts"][:2]; json.dump(d,open(sys.argv[2],"w"))' native/dossier.json "$two_of_four"
compare "2 of 4 receipts, --min-witnesses 2" "$two_of_four" --directory native/trusted.json --min-witnesses 2 || fail=1
compare "2 of 4 receipts, --min-witnesses 2 --allow-sub-majority" "$two_of_four" --directory native/trusted.json --min-witnesses 2 --allow-sub-majority || fail=1
compare "2 of 4 receipts, --min-witnesses 2 --no-strict" "$two_of_four" --directory native/trusted.json --min-witnesses 2 --no-strict || fail=1
compare "2 of 4 receipts, default threshold" "$two_of_four" --directory native/trusted.json || fail=1
# --subject-org: the log's own operator never counts as independent.
compare "native, --subject-org of a cosigner" native/dossier.json --directory native/trusted.json --subject-org "Example-University" || fail=1
compare "native, --subject-org not in the directory" native/dossier.json --directory native/trusted.json --subject-org "nobody" || fail=1
compare "2 of 4 receipts, --subject-org of a cosigner" "$two_of_four" --directory native/trusted.json --min-witnesses 2 --subject-org " example-infra-co " || fail=1
exit $fail
