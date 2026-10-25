#!/bin/sh
# Entrypoint for the witness-log witness images: Dockerfile.release (the
# published image) and Dockerfile (from source; render.yaml and
# deploy/fly/fly.toml build that one).
#
# No arguments: initialise /state on first start (from env), print the
# directory entry, then serve. With arguments: run `witness-log <args>`
# (e.g. `docker run --rm IMAGE witness info https://witness.example`).
#
# Environment:
#   WITNESS_ORG       required on first start: the organisation that controls
#                     this machine and key (the independence label)
#   WITNESS_NAME      C2SP key name; default <host of WITNESS_URL>/w1, or
#                     <org-slug>.witness/<8 random hex> without a URL
#   WITNESS_URL       public base URL, e.g. https://witness.example.org. Unset
#                     on Render or Fly.io, the URL the platform gives the
#                     service is used: RENDER_EXTERNAL_URL, or
#                     https://$FLY_APP_NAME.fly.dev
#   WITNESS_COMPUTE   where it runs: hetzner, oracle-cloud, homelab, ...
#   WITNESS_BEHIND_PROXY=1  raise per-address limits (every client then
#                     shares the proxy's address); leave unset when clients
#                     reach port 7380 directly
#   WITNESS_LISTEN    default 0.0.0.0:7380
#
# Started as root (the Render and Fly.io configurations build the image that
# way, with WITNESS_IMAGE_USER=0:0, because those platforms mount the state
# disk owned by root; the published image and the default build start as
# uid 10001): give /state to uid 10001, then run this script again as that
# user. The witness never runs as root.
set -eu

STATE=/state
WITNESS_UID=10001
log() { echo "[witness-log] $*" >&2; }

if [ "$(id -u)" = 0 ]; then
  if [ -d "$STATE" ]; then
    # Everything in the state directory belongs to the witness user. Symlinks
    # are changed, not followed; the platform's lost+found is left alone.
    find "$STATE" -xdev \( ! -user "$WITNESS_UID" -o ! -group "$WITNESS_UID" \) \
      ! -path "$STATE/lost+found" ! -path "$STATE/lost+found/*" \
      -exec chown -h "$WITNESS_UID:$WITNESS_UID" {} +
    chmod 0700 "$STATE"
  fi
  export HOME="$STATE"
  exec setpriv --reuid="$WITNESS_UID" --regid="$WITNESS_UID" --clear-groups --no-new-privs -- "$0" "$@"
fi

if [ "$#" -gt 0 ]; then
  exec witness-log "$@"
fi

if [ ! -w "$STATE" ]; then
  log "error: $STATE is not writable by uid $(id -u). For a bind mount run: chown $(id -u):$(id -g) <host dir>"
  exit 73
fi

if [ ! -f "$STATE/witness.key" ]; then
  if [ -e "$STATE/witness.json" ] || [ -d "$STATE/logs" ]; then
    log "error: $STATE has witness.json or logs/ but no witness.key. Refusing to create a new key over"
    log "partial state; restore the whole state directory from one snapshot (OPERATORS.md section 3)."
    exit 78
  fi
  org=$(printf '%s' "${WITNESS_ORG:-}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
  lower=$(printf '%s' "$org" | tr '[:upper:]' '[:lower:]')
  if [ -z "$org" ] || [ "$lower" = "unspecified" ]; then
    log "error: set WITNESS_ORG to the organisation that runs this witness, e.g."
    log "  docker run ... -e WITNESS_ORG=\"Your Org\" ghcr.io/0xandersen/witness-log:latest"
    log "  (Render: the service's Environment page; Fly.io: fly secrets set WITNESS_ORG=\"Your Org\")"
    log "It is the independence label verifiers count; WITNESSED needs two distinct ones."
    exit 64
  fi
  url=${WITNESS_URL:-}
  if [ -z "$url" ] && [ -n "${RENDER_EXTERNAL_URL:-}" ]; then
    url=${RENDER_EXTERNAL_URL%/}
    log "WITNESS_URL is unset; using Render's public URL $url"
  elif [ -z "$url" ] && [ -n "${FLY_APP_NAME:-}" ]; then
    url="https://${FLY_APP_NAME}.fly.dev"
    log "WITNESS_URL is unset; using Fly.io's public URL $url"
  fi
  name=${WITNESS_NAME:-}
  if [ -z "$name" ]; then
    if [ -n "$url" ]; then
      host=$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##; s#:[0-9]+$##')
      name="$host/w1"
    else
      slug=$(printf '%s' "$lower" | tr -c 'a-z0-9\n' '-' | sed -E 's/-+/-/g; s/^-//; s/-$//')
      rnd=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
      name="${slug:-witness}.witness/$rnd"
    fi
  fi
  set -- witness init "$STATE" --name "$name" --org "$org"
  [ -n "$url" ] && set -- "$@" --url "$url"
  [ -n "${WITNESS_COMPUTE:-}" ] && set -- "$@" --compute "$WITNESS_COMPUTE"
  umask 077
  witness-log "$@" > "$STATE/entry.json.tmp"
  mv "$STATE/entry.json.tmp" "$STATE/entry.json"
  log "initialised a new witness in $STATE (key name $name, org \"$org\")"
  [ -z "$url" ] && log "note: WITNESS_URL is unset, so the entry's url is a placeholder; registration takes the URL you give it."
  set --
fi

# One container per volume. witness.lock names a PID, and in a container the
# witness is always PID 1, so after `docker kill`, an OOM kill or a power cut
# the next container would see "held by pid 1" (itself) and refuse forever.
# An flock on the volume, held for the life of the server (fd 9 survives
# exec), tells a stale lock from a live one: if we get the flock, no other
# container on this host is serving the volume, so a lock naming PID 1 is
# left over from a previous container and is removed.
exec 9>>"$STATE/container.lock"
if ! flock -n 9; then
  log "error: another container is already serving this volume ($STATE). Two witnesses on one"
  log "state directory could cosign two forks; stop the other container first."
  exit 75
fi
if [ -f "$STATE/witness.lock" ] && [ "$(tr -dc '0-9' < "$STATE/witness.lock")" = "1" ]; then
  log "removing a stale witness.lock left by a previous container (it named PID 1)"
  rm -f "$STATE/witness.lock"
fi

log "directory entry (publish it; register it with a PR to registry/witnesses/):"
cat "$STATE/entry.json" 2>/dev/null || log "(no entry.json in $STATE; GET / serves directory_entry)"
log "BACKUP RULE: $STATE is the whole witness (key + logs/). Snapshot it as one unit; never restore the key alone."

listen=${WITNESS_LISTEN:-0.0.0.0:7380}
if [ "${WITNESS_BEHIND_PROXY:-}" = "1" ]; then
  exec witness-log witness serve "$STATE" --listen "$listen" --open-enrollment --max-conns-per-ip 256 --enroll-rate 6000
fi
exec witness-log witness serve "$STATE" --listen "$listen" --open-enrollment
