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
if 2 in (rust_exit, go_exit):
    # A usage error (exit 2) prints no report: the exit codes alone must agree.
    ok = rust_exit == go_exit
    print(("ok   " if ok else "DIFF ") + f"{label}: rust exit {rust_exit}, go exit {go_exit}")
    sys.exit(0 if ok else 1)
r = json.load(open(sys.argv[4])); g = json.load(open(sys.argv[5]))
# Failure wording is per-implementation; whether a check failed is not.
rf = r["report"].pop("failures", None); gf = g["report"].pop("failures", None)
for x in (r, g):
    fa = x["report"].get("fleet_anchor")
    if fa:
        fa["failures"] = bool(fa["failures"])
ok = (rust_exit == go_exit and r["verdict"] == g["verdict"] and r["report"] == g["report"]
      and bool(rf) == bool(gf)
      and all(r.get(k) == g.get(k) for k in ("strict", "allow_sub_majority", "exit_code", "subject_org", "identity_pubkey")))
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
# Dossier fields no valid dossier has at that length are not echoed whole:
# a fleet origin over 255 bytes is reported as null, an identity_pubkey over
# 64 bytes as its first 64 characters and "…".
long_fields="${TMPDIR:-/tmp}/wl-long-fields.json"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d["identity_pubkey"]="é"*40; d["fleet_anchor"]={"origin":"o"*256,"entry_index":0,"entry_bytes_b64":"","inclusion_proof":[],"fleet_checkpoint_note":""}; json.dump(d,open(sys.argv[2],"w"))' native/dossier.json "$long_fields"
compare "a 256-byte fleet origin and an 80-byte identity_pubkey" "$long_fields" || fail=1
compare "a 256-byte fleet origin, --accept-fleet-anchor" "$long_fields" --subject-org org --accept-fleet-anchor || fail=1
# An evidence file is UTF-8 JSON (SPEC.md §9), which a corpus, itself JSON,
# cannot hold otherwise: both refuse an invalid byte in an ignored member,
# and both count the same item without it.
utf8_dir="${TMPDIR:-/tmp}/wl-evidence-utf8"
mkdir -p "$utf8_dir"
python3 -I -c 'import json,os,sys; v=json.load(open(sys.argv[1],encoding="utf-8")); d=[c["dossier_json"] for c in v["cases"] if c["name"]=="valid"][0]; t=[c["text"] for c in v["inputs"] if c["name"]=="an evidence item with an ignored member holding 1e400"][0].encode(); open(os.path.join(sys.argv[2],"dossier.json"),"w").write(d); open(os.path.join(sys.argv[2],"good.json"),"wb").write(t); open(os.path.join(sys.argv[2],"bad.json"),"wb").write(t.replace(b"1e400",bytes([34,255,34])))' "$repo/corpus/17_dossier_parsing.json" "$utf8_dir"
compare "evidence, an ignored member holding 1e400" "$utf8_dir/dossier.json" --evidence "$utf8_dir/good.json" || fail=1
compare "evidence, an invalid UTF-8 byte in an ignored member" "$utf8_dir/dossier.json" --evidence "$utf8_dir/bad.json" || fail=1
# RFC-0001 (experimental): corpus 14's fleet-anchored dossiers, with and
# without --accept-fleet-anchor.
fleet="${TMPDIR:-/tmp}/wl-fleet-corpus"
mkdir -p "$fleet"
python3 -I -c 'import json,sys,os; v=json.load(open(sys.argv[1])); json.dump(v["trusted_directory"],open(os.path.join(sys.argv[2],"trusted.json"),"w")); [json.dump(d,open(os.path.join(sys.argv[2],n+".dossier.json"),"w")) for n,d in v["dossiers"].items()]' "$repo/corpus/14_fleet_anchor.json" "$fleet"
for d in "$fleet"/*.dossier.json; do
  n="$(basename "$d" .dossier.json)"
  compare "fleet $n" "$d" --directory "$fleet/trusted.json" --min-witnesses 2 --subject-org corpus-fleet-org || fail=1
  compare "fleet $n, --accept-fleet-anchor" "$d" --directory "$fleet/trusted.json" --min-witnesses 2 --subject-org corpus-fleet-org --accept-fleet-anchor || fail=1
  compare "fleet $n, --accept-fleet-anchor, no directory" "$d" --subject-org corpus-fleet-org --accept-fleet-anchor || fail=1
done
# Argument parsing (security review of 0.5.0, F6): every flag is known or
# the run is a usage error; a value flag takes the next argument; a repeated
# single-value flag keeps its last value; --no-strict (removed in 0.6.0)
# is a usage error wherever it stands. (compare appends --json, so a value flag given last consumes it.)
native_id="$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['identity_pubkey'])" native/dossier.json)"
args() { compare "args: $*" "$@" || fail=1; }
args native/dossier.json --known-heads "1:$wrong_identity"
args native/dossier.json --evidance c2sp/a.json
args native/dossier.json --directory native/trusted.json --jsn
args native/dossier.json -x
args native/dossier.json native/dossier.json
args native/dossier.json --identity "$wrong_identity" --identity "$native_id"
args native/dossier.json --identity "$native_id" --identity "$wrong_identity"
args native/dossier.json --identity zz
args native/dossier.json --identity "${native_id:0:62}"
args "$two_of_four" --directory native/trusted.json --min-witnesses 2 --no-strict --strict
args "$two_of_four" --directory native/trusted.json --min-witnesses 2 --strict --no-strict
args "$two_of_four" --directory native/trusted.json --min-witnesses 5 --min-witnesses 2
args "$two_of_four" --directory native/trusted.json --min-witnesses +2
args native/dossier.json --directory native/trusted.json --min-witnesses 0
args native/dossier.json --directory native/trusted.json --min-witnesses -1
args native/dossier.json --directory native/trusted.json --min-witnesses 2.0
args "$two_of_four" --directory native/trusted.json --threshold 0
args "$two_of_four" --directory native/trusted.json --threshold +.5
args "$two_of_four" --directory native/trusted.json --threshold 5e-1
args native/dossier.json --directory native/trusted.json --threshold 0x1p-1
args native/dossier.json --directory native/trusted.json --threshold 1_0
args native/dossier.json --directory native/trusted.json --threshold nan
args native/dossier.json --directory native/trusted.json --threshold
args native/dossier.json --directory /nonexistent/trusted.json --directory native/trusted.json
args native/dossier.json --directory native/trusted.json --directory /nonexistent/trusted.json
args native/dossier.json --directory ""
args native/dossier.json --directory native/trusted.json --subject-org nobody --subject-org "Example-University"
args native/dossier.json --directory native/trusted.json --subject-org --json
args native/dossier.json --directory native/trusted.json --subject-org "  "
args native/dossier.json --directory native/trusted.json --explain
args native/dossier.json --known-head "1:$wrong_identity" --evidence
# Corpus 16 (strict Ed25519) and 17 (reading a dossier, outside review of
# 0.6.0): every case through both CLIs, the dossier as its exact text. A
# text the reference cannot read is a usage error (exit 2) from both. Corpus
# 17's `inputs` give a --directory, --revocations or --evidence file as its
# exact text, nested up to 1000 deep (read) and beyond (exit 2 from both).
vectors="${TMPDIR:-/tmp}/wl-corpus-16-17"
rm -rf "$vectors" && mkdir -p "$vectors"
python3 -I - "$repo/corpus" "$vectors" <<'EOF'
import json, os, sys
src, out = sys.argv[1], sys.argv[2]
rows = []
for name in ("16_ed25519_strict.json", "17_dossier_parsing.json"):
    v = json.load(open(os.path.join(src, name), encoding="utf-8"))
    tag = name[:2]
    for n, d in v.get("directories", {}).items():
        json.dump(d, open(os.path.join(out, f"{tag}-dir-{n}.json"), "w"))
    for k, e in v.get("evidence", {}).items():
        json.dump(e, open(os.path.join(out, f"{tag}-ev-{k}.json"), "w"))
    for i, c in enumerate(v["cases"]):
        path = os.path.join(out, f"{tag}-{i}.json")
        text = c["dossier_json"] if "dossier_json" in c else json.dumps(v["dossiers"][c["dossier"]])
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        args = [path]
        if c["directory"]:
            args += ["--directory", os.path.join(out, f"{tag}-dir-{c['directory']}.json")]
        if c["min_witnesses"] is not None:
            args += ["--min-witnesses", str(c["min_witnesses"])]
        if c["expected_identity"]:
            args += ["--identity", c["expected_identity"]]
        for h in c["known_heads"]:
            args += ["--known-head", h]
        for k in c["evidence"]:
            args += ["--evidence", os.path.join(out, f"{tag}-ev-{k}.json")]
        rows.append("\t".join([f"corpus {tag}: {c['name']}"] + args))
    dossiers = {c["name"]: c.get("dossier_json") for c in v["cases"]}
    flags = {"directory": "--directory", "revocations": "--revocations", "evidence": "--evidence"}
    for i, c in enumerate(v.get("inputs", [])):
        dossier = os.path.join(out, f"{tag}-input-{i}-dossier.json")
        text = os.path.join(out, f"{tag}-input-{i}.json")
        for path, content in ((dossier, dossiers[c["dossier"]]), (text, c["text"])):
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
        args = [dossier, flags[c["input"]], text]
        if c["min_witnesses"] is not None:
            args += ["--min-witnesses", str(c["min_witnesses"])]
        rows.append("\t".join([f"corpus {tag} input: {c['name']}"] + args))
open(os.path.join(out, "cases.tsv"), "w", encoding="utf-8").write("\n".join(rows) + "\n")
EOF
while IFS=$'\t' read -r -a fields; do
  compare "${fields[0]}" "${fields[@]:1}" || fail=1
done < "$vectors/cases.tsv"
exit $fail
