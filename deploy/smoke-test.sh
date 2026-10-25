#!/usr/bin/env bash
# Run the witness image the way a deploy configuration runs it, and check it.
#
#   deploy/smoke-test.sh render  IMAGE   # as render.yaml configures it
#   deploy/smoke-test.sh fly     IMAGE   # as deploy/fly/fly.toml configures it
#   deploy/smoke-test.sh default IMAGE   # plain `docker run` with a named volume
#
# IMAGE is deploy/witness/Dockerfile built with the configuration's build
# arguments (`deploy/check_configs.py --emit render` prints them) or, for
# `default`, with none. render and fly take their environment, port and mount
# from deploy/check_configs.py --emit, add what the platform adds (the
# operator's WITNESS_ORG, RENDER_EXTERNAL_URL or FLY_APP_NAME), and mount a
# directory owned by root with a lost+found in it, as both platforms mount a
# fresh disk. No command is passed: both platforms run the image's
# entrypoint. Checks:
#   - GET /health is ok; GET / serves a vkey and a directory_entry with the
#     platform's URL, the operator's org and the configured compute provider
#   - the witness runs as uid 10001 and owns its state, never root
#   - the directory entry passes registry/validate.py --offline
#   - a journal submitted from the host gets a cosignature
#   - same key and the log still remembered after stop/start, after a kill,
#     and in a new container on the same state (a redeploy)
#   - a second container on the same state is refused (exit 75)
#   - a first start without WITNESS_ORG is refused (exit 64)
#
# Needs docker, curl, jq, python3 with PyYAML, and root or sudo (the state
# directory is root-owned, as on the platforms). DOCKER overrides the docker
# command; HOST_PORT (default 17380) is the port published on 127.0.0.1.
set -euo pipefail

which=${1:?usage: deploy/smoke-test.sh render|fly|default IMAGE}
image=${2:?usage: deploy/smoke-test.sh render|fly|default IMAGE}
root=$(cd "$(dirname "$0")/.." && pwd)
read -r -a docker <<< "${DOCKER:-docker}"
hostport=${HOST_PORT:-17380}
name="wl-smoke-$which"
work=$(mktemp -d)
as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
fail() { echo "::error::$which: $*"; "${docker[@]}" logs "$name" 2>&1 | tail -40 || true; exit 1; }
cleanup() {
  "${docker[@]}" rm -f "$name" "$name-2" >/dev/null 2>&1 || true
  if [ "$which" = default ]; then "${docker[@]}" volume rm -f "$name-state" >/dev/null 2>&1 || true; fi
  as_root rm -rf "$work"
}
trap cleanup EXIT

env_args=()
case "$which" in
  render|fly)
    cfg=$(python3 "$root/deploy/check_configs.py" --emit "$which")
    port=$(jq -r .port <<< "$cfg")
    mount=$(jq -r .mount <<< "$cfg")
    compute=$(jq -r .env.WITNESS_COMPUTE <<< "$cfg")
    while IFS= read -r kv; do env_args+=(-e "$kv"); done < <(jq -r '.env | to_entries[] | "\(.key)=\(.value)"' <<< "$cfg")
    if [ "$which" = render ]; then
      org="Render Smoke Test"; want_url=https://wl-smoke.onrender.com
      env_args+=(-e "PORT=$port" -e "RENDER_EXTERNAL_URL=$want_url")
    else
      org="Fly Smoke Test"; want_url=https://wl-smoke.fly.dev
      env_args+=(-e "FLY_APP_NAME=wl-smoke")
    fi
    state="$work/state"
    as_root install -d -o 0 -g 0 -m 0755 "$state"
    as_root install -d -o 0 -g 0 -m 0700 "$state/lost+found"
    vol="$state:$mount"
    fresh_vol() { as_root install -d -o 0 -g 0 -m 0755 "$work/$1"; echo "$work/$1:$mount"; }
    ;;
  default)
    port=7380; mount=/state; compute="docker-smoke-test"
    org="Docker Smoke Test"; want_url=https://witness-smoke.example.org
    env_args+=(-e "WITNESS_URL=$want_url" -e "WITNESS_COMPUTE=$compute")
    "${docker[@]}" volume rm -f "$name-state" >/dev/null 2>&1 || true
    vol="$name-state:$mount"
    fresh_vol() { echo "$name-$1:$mount"; }
    ;;
  *) echo "usage: deploy/smoke-test.sh render|fly|default IMAGE" >&2; exit 2 ;;
esac
want_name="${want_url#https://}/w1"
run() { "${docker[@]}" run -d --name "$name" -p "127.0.0.1:$hostport:$port" -v "$vol" "${env_args[@]}" -e "WITNESS_ORG=$org" "$image" >/dev/null; }
info() { curl -fsS --max-time 5 "http://127.0.0.1:$hostport/"; }
wait_health() {
  for _ in $(seq 1 60); do
    [ "$(curl -fsS --max-time 2 "http://127.0.0.1:$hostport/health" 2>/dev/null)" = ok ] && return 0
    sleep 1
  done
  fail "no ok from GET /health within 60 s ($1)"
}
uid_of_pid1() { "${docker[@]}" exec "$name" sh -c 'grep "^Uid:" /proc/1/status' | awk '{print $2 $3 $4 $5}'; }

echo "== $which: first start"
run
wait_health "first start"
i=$(info)
key=$(jq -r .pubkey_hex <<< "$i")
if [ -z "$key" ] || [ "$key" = null ]; then fail "GET / has no pubkey_hex"; fi
jq -e '.vkey | type == "string" and length > 0' <<< "$i" >/dev/null || fail "GET / has no vkey"
jq -e --arg u "$want_url" --arg o "$org" --arg c "$compute" --arg n "$want_name" '.directory_entry
    | .url == $u and .operator_org == $o and .compute_provider == $c and .name == $n
      and .is_project_operated == false' <<< "$i" >/dev/null \
  || fail "directory_entry is not {url: $want_url, operator_org: $org, compute_provider: $compute, name: $want_name}: $(jq -c .directory_entry <<< "$i")"
echo "key $key, entry $(jq -c .directory_entry <<< "$i")"

[ "$(uid_of_pid1)" = 10001100011000110001 ] || fail "the witness is not running as uid 10001: $(uid_of_pid1)"
if [ "$which" != default ]; then
  [ "$(as_root stat -c '%u:%g %a' "$state")" = "10001:10001 700" ] || fail "state dir is $(as_root stat -c '%u:%g %a' "$state")"
  [ "$(as_root stat -c '%u' "$state/witness.key")" = 10001 ] || fail "witness.key is not owned by 10001"
  [ "$(as_root stat -c '%u' "$state/lost+found")" = 0 ] || fail "lost+found was changed"
fi
echo "runs as uid 10001 and owns its state"

mkdir -p "$work/registry"
jq .directory_entry <<< "$i" > "$work/registry/smoke-w1.json"
python3 "$root/registry/validate.py" --offline --registry-dir "$work/registry" || fail "registry/validate.py refused the entry from GET /"

"${docker[@]}" cp "$name:/usr/local/bin/witness-log" "$work/witness-log"
wl="$work/witness-log"
"$wl" log init "$work/agent.jsonl" >/dev/null
"$wl" log append "$work/agent.jsonl" --intent '{"tool":"smoke_test"}' >/dev/null
jq --arg u "http://127.0.0.1:$hostport" '{witnesses: [.directory_entry | .url = $u]}' <<< "$i" > "$work/dir.json"
"$wl" witness submit "$work/agent.jsonl" --directory "$work/dir.json" --out "$work/dossier.json" --min 1 \
  || fail "witness submit did not get a cosignature"
ident=$("$wl" log info "$work/agent.jsonl" | jq -r .identity)
rc=0; "$wl" verify "$work/dossier.json" --identity "$ident" --directory "$work/dir.json" --min-witnesses 1 --json > "$work/verify.json" || rc=$?
# One operator: CONSISTENT-UNWITNESSED (exit 10) is the right verdict; the cosignature must count.
if [ "$rc" != 10 ] || [ "$(jq .report.quorum.valid_receipts "$work/verify.json")" != 1 ]; then
  fail "verify: exit $rc, $(jq -c '{verdict, receipts: .report.quorum.valid_receipts}' "$work/verify.json")"
fi
info | jq -e '.logs == 1 and .cosigned_since_start >= 1' >/dev/null || fail "GET / does not count the cosigned log"
echo "cosigned a journal; verify counts the receipt"

same_state() {
  wait_health "$1"
  local j; j=$(info)
  [ "$(jq -r .pubkey_hex <<< "$j")" = "$key" ] || fail "$1: the key changed"
  [ "$(jq -r .logs <<< "$j")" = 1 ] || fail "$1: the witness forgot the log it cosigned"
  echo "$1: same key, log remembered"
}
"${docker[@]}" stop "$name" >/dev/null && "${docker[@]}" start "$name" >/dev/null
same_state "stop and start"
"${docker[@]}" kill "$name" >/dev/null && "${docker[@]}" start "$name" >/dev/null
same_state "kill and start"
"${docker[@]}" rm -f "$name" >/dev/null && run
same_state "new container on the same state"

rc=0; "${docker[@]}" run --rm --name "$name-2" -v "$vol" "${env_args[@]}" -e "WITNESS_ORG=$org" "$image" >/dev/null 2>&1 || rc=$?
[ "$rc" = 75 ] || fail "a second container on the same state exited $rc, expected 75 (refused)"
echo "a second container on the same state is refused"

rc=0; "${docker[@]}" run --rm --name "$name-2" -v "$(fresh_vol no-org)" "${env_args[@]}" "$image" >/dev/null 2>&1 || rc=$?
if [ "$which" = default ]; then "${docker[@]}" volume rm -f "$name-no-org" >/dev/null 2>&1 || true; fi
[ "$rc" = 64 ] || fail "a first start without WITNESS_ORG exited $rc, expected 64"
echo "a first start without WITNESS_ORG is refused"

echo "== $which: all checks passed"
