#!/usr/bin/env bash
# Interop: witness-log logs cosigned by transparency-dev/witness's
# omniwitness, configured the way public witness-network.org witnesses are,
# from a logs/v0 log list that `witness-log witness-network log-list`
# wrote. CI runs it against omniwitness built from a pinned commit
# (.github/workflows/interop.yml); WITNESS_IMPL=witness-log runs the same
# checks against witness-log's own witness, for a machine without Go.
#
#   WL=path/to/witness-log OMNIWITNESS=path/to/omniwitness \
#     GENERATE_KEYS=path/to/generate_keys tests/interop/omniwitness.sh
#
# What it checks, each against two witnesses run as two operators:
#  1. An agent's own log on the list is cosigned by both (WITNESSED, exit
#     0), again after it grows (consistency proofs), and the cosignatures
#     verify as C2SP cosignature/v1 lines (`c2sp verify`).
#  2. A rewritten history of that agent (same key, other leaves) is
#     refused: submit exits 20.
#  3. A fleet log (RFC-0001) on the list is cosigned; an agent NOT on the
#     list reaches WITNESSED through its fleet anchor only (verify exits 11,
#     split view possible, and 0 with --allow-sub-majority), and its own
#     direct submission gets the 404 that names enrollment.
#  4. `directory add` takes the full add-checkpoint URL an about page gives.
set -euo pipefail

WL=${WL:-witness-log}
IMPL=${WITNESS_IMPL:-omniwitness}
OMNI=${OMNIWITNESS:-omniwitness}
GENKEYS=${GENERATE_KEYS:-generate_keys}
ORG="Interop Fleet Org"

work=$(mktemp -d "${TMPDIR:-/tmp}/wl-interop.XXXXXX")
pids=()
cleanup() {
  local rc=$?
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for f in "$work"/*.pid; do
    if [ -f "$f" ]; then kill "$(cat "$f")" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo "--- failed (exit $rc); logs:" >&2
    for f in "$work"/*.log; do
      [ -f "$f" ] || continue
      echo "== $f" >&2
      tail -n 40 "$f" >&2
    done
  fi
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
json() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$@"; }
# Run a command, keep its exit status, never trip `set -e`.
run() { set +e; "$@"; rc=$?; set -e; }
expect() { [ "$rc" -eq "$1" ] || fail "$2: exit $rc, want $1"; }

cd "$work"
"$WL" --version

step "Logs: a fleet log, an agent on the list, an agent only in the fleet"
"$WL" fleet init fleet --origin interop.example/witness-log/fleet --org "$ORG" --json > fleet.json
"$WL" log init direct.wlog --identity-seed-file direct.seed > direct.init.json
"$WL" log init fleet-only.wlog > fleet-only.init.json
DIRECT_ID=$(json direct.init.json 'd["identity"]')
for i in 1 2 3; do "$WL" log append direct.wlog --intent "pay invoice $i" > /dev/null; done
"$WL" log append fleet-only.wlog --intent "refund order 7" > /dev/null

step "The log list witnesses poll (witness-network log-list)"
mkdir www
"$WL" witness-network log-list --fleet fleet --identity "$DIRECT_ID" --every 1 \
  --contact "interop test (at) example.org" > www/log-list.1
cat www/log-list.1
LIST_PORT=$(free_port)
python3 -m http.server "$LIST_PORT" --bind 127.0.0.1 --directory www > list.log 2>&1 &
pids+=($!)
LIST_URL="http://127.0.0.1:$LIST_PORT/log-list.1"

step "Two witnesses, two operators ($IMPL)"
start_witness() { # name port -> writes the witness's cosignature vkey to $name.vkey
  # Not called in $(...): a subshell's background process would escape
  # cleanup. The pid goes to $name.pid, which cleanup reads.
  local name=$1 port=$2
  if [ "$IMPL" = omniwitness ]; then
    "$GENKEYS" --origin "interop-$name.example/witness" --print > "$name.keys"
    # The key file holds the bare note key, no newline (as generate_keys
    # --out_priv writes it).
    printf '%s' "$(sed -n 1p "$name.keys")" > "$name.sec"
    "$OMNI" --private_key_path "$name.sec" --db_file "$name.db" \
      --listen "127.0.0.1:$port" --metrics_listen "" \
      --public_witness_config_url "$LIST_URL" \
      --public_witness_config_poll_interval 1s \
      --alsologtostderr --v=1 > "$name.log" 2>&1 &
    echo $! > "$name.pid"
    sed -n 2p "$name.keys" > "$name.vkey"
  else
    # witness-log's witness has no log-list poller: enroll the listed logs
    # the way an operator configuring from the list would.
    "$WL" witness init "w-$name" --name "interop-$name.example/witness" --json > "$name.init.json"
    while read -r kw vkey; do
      [ "$kw" = vkey ] || continue
      "$WL" witness add-log "w-$name" "${vkey%%+*}" "$vkey" > /dev/null
    done < www/log-list.1
    "$WL" witness serve "w-$name" --listen "127.0.0.1:$port" > "$name.log" 2>&1 &
    echo $! > "$name.pid"
    json "$name.init.json" 'd["vkey"]' > "$name.vkey"
  fi
}
PA=$(free_port); PB=$(free_port)
start_witness a "$PA"
start_witness b "$PB"
VKA=$(cat a.vkey)
VKB=$(cat b.vkey)
echo "witness A: $VKA"
echo "witness B: $VKB"

step "Directory from the witnesses' about-page facts (full add-checkpoint URL)"
"$WL" directory add trusted.json --vkey "$VKA" --org "Interop Operator A" \
  --url "http://127.0.0.1:$PA/add-checkpoint" 2> add.err
grep -q "appends /add-checkpoint" add.err || fail "directory add kept the endpoint path"
"$WL" directory add trusted.json --vkey "$VKB" --org "Interop Operator B" --url "http://127.0.0.1:$PB"
[ "$(json trusted.json 'd["witnesses"][0]["url"]')" = "http://127.0.0.1:$PA" ] || fail "url not normalised"

step "1. The listed agent log is cosigned by both witnesses"
ok=""
for _ in $(seq 1 60); do
  run "$WL" submit direct.wlog --directory trusted.json --out direct.json 2> submit.err
  if [ "$rc" -eq 0 ]; then ok=1; break; fi
  sleep 1 # the witnesses may not have read the list yet
done
[ -n "$ok" ] || { cat submit.err >&2; fail "no cosignatures for the listed log"; }
run "$WL" verify direct.json --directory trusted.json
expect 0 "verify (direct)"

for i in 4 5 6 7; do "$WL" log append direct.wlog --result "paid $i" > /dev/null; done
run "$WL" submit direct.wlog --directory trusted.json --out direct2.json
expect 0 "submit after growth (consistency proof from size 3 to 7)"
run "$WL" verify direct2.json --directory trusted.json --json
expect 0 "verify after growth"

"$WL" c2sp export direct2.json --directory trusted.json --sign-with direct.wlog \
  --identity-seed-file direct.seed --out direct2.note
LOG_VKEY=$(sed -n 's/^vkey \(witness-log\/.*\)$/\1/p' www/log-list.1)
run "$WL" c2sp verify direct2.note --vkey "$LOG_VKEY" --vkey "$VKA" --vkey "$VKB"
expect 0 "c2sp verify: the log's signature and both cosignature/v1 lines"

step "2. A rewritten history of the same key is refused"
"$WL" log init fork.wlog --identity-seed-file direct.seed > /dev/null
for i in 1 2 3 4 5 6 7 8; do "$WL" log append fork.wlog --intent "other history $i" > /dev/null; done
run "$WL" submit fork.wlog --directory trusted.json --out fork.json 2> fork.err
cat fork.err
expect 20 "submit of a rewritten history"

step "3. The fleet log: an unlisted agent anchored through it"
FP=$(free_port)
"$WL" fleet serve fleet --listen "127.0.0.1:$FP" --directory trusted.json \
  --witness-every 1 --min 2 > fleet.log 2>&1 &
pids+=($!)
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$FP/health" > /dev/null 2>&1 && break
  sleep 0.5
done
run "$WL" submit fleet-only.wlog --fleet "http://127.0.0.1:$FP" --fleet-wait 90 --out fleet-only.json
expect 0 "submit --fleet (a cosigned fleet checkpoint covers the entry)"
run "$WL" verify fleet-only.json --directory trusted.json \
  --accept-fleet-anchor --subject-org "$ORG" --json > fleet-verify.json
expect 11 "verify through the fleet anchor (split view possible)"
[ "$(json fleet-verify.json 'd["report"]["witnessed_via"]')" = fleet ] || fail "witnessed_via"
run "$WL" verify fleet-only.json --directory trusted.json \
  --accept-fleet-anchor --subject-org "$ORG" --allow-sub-majority
expect 0 "verify through the fleet anchor, sub-majority allowed"
run "$WL" verify fleet-only.json --directory trusted.json
expect 10 "verify without --accept-fleet-anchor ignores the anchor"

run "$WL" submit fleet-only.wlog --directory trusted.json --out unlisted.json 2> unlisted.err
cat unlisted.err
expect 20 "direct submit of a log no witness enrolled"
grep -q "has not enrolled the log" unlisted.err || fail "404 not explained"

step "interop with $IMPL: all checks passed"
