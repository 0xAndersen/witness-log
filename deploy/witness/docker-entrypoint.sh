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
#   WITNESS_PUBKEY    the witness's public key (64 hex, `pubkey_hex` in GET /).
#                     Set it after the first start: from then on this
#                     entrypoint never creates a key, and refuses a state
#                     directory that holds a different key or none (a new,
#                     replaced or unmounted disk)
#
# A new key is only ever created on a mounted volume. If /state were just a
# directory in the container, the key would vanish with the container and
# the next start would quietly be a different witness under the same name.
#
# Started as root in an image built with WITNESS_IMAGE_USER=0:0 (render.yaml
# and deploy/fly/fly.toml build it that way, because those platforms mount
# the state disk owned by root): take the volume's lock, give /state to uid
# 10001, then run this script again as that user with no capabilities and
# no supplementary groups. The witness never runs as root there. Such an
# image, run as root with a bind mount, changes the owner of the mounted
# directory to 10001. The published image and the default build start as
# uid 10001 and skip this step; started as root (--user 0) they change no
# ownership and run as root, as before.
set -eu

STATE=/state
WITNESS_UID=10001
log() { echo "[witness-log] $*" >&2; }

# One container per volume: an flock on $STATE/container.lock, held on fd 9
# for the life of the server (fd 9 survives setpriv and exec).
lock_state() {
  if ! { true >&9; } 2>/dev/null; then
    exec 9>>"$STATE/container.lock"
  fi
  if ! flock -n 9; then
    log "error: another container is already serving this volume ($STATE). Two witnesses on one"
    log "state directory could cosign two forks; stop the other container first."
    exit 75
  fi
}

# Whether $STATE is a mount point (a volume, a bind mount, a platform disk).
is_mount() {
  [ -r /proc/self/mountinfo ] || return 1
  while read -r _ _ _ _ mp _; do
    if [ "$mp" = "$STATE" ]; then return 0; fi
  done < /proc/self/mountinfo
  return 1
}

# The public key of the witness in $STATE, as `witness init` recorded it.
state_pubkey() {
  k=$(sed -n 's/.*"pubkey_hex"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$STATE/witness.json" 2>/dev/null | head -n 1)
  if [ -z "$k" ]; then
    k=$(sed -n 's/.*"pubkey"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$STATE/entry.json" 2>/dev/null | head -n 1)
  fi
  printf '%s' "$k"
}

if [ "$(id -u)" = 0 ] && [ "${WITNESS_IMAGE_USER:-}" = "0:0" ]; then
  if [ -d "$STATE" ]; then
    # Lock first: a second container on this volume stops here, before it
    # changes anything.
    lock_state
    # Everything in the state directory belongs to the witness user. Symlinks
    # are changed, not followed; the platform's lost+found is left alone.
    find "$STATE" -xdev \( ! -user "$WITNESS_UID" -o ! -group "$WITNESS_UID" \) \
      ! -path "$STATE/lost+found" ! -path "$STATE/lost+found/*" \
      -exec chown -h "$WITNESS_UID:$WITNESS_UID" {} +
    chmod 0700 "$STATE"
  fi
  export HOME="$STATE"
  # Empty the bounding set too where the runtime allows it (that needs
  # CAP_SETPCAP); without it the change of uid still leaves no capabilities.
  bounding=
  if setpriv --bounding-set=-all -- true 2>/dev/null; then bounding=--bounding-set=-all; fi
  # shellcheck disable=SC2086  # $bounding is one flag or nothing
  exec setpriv --reuid="$WITNESS_UID" --regid="$WITNESS_UID" --clear-groups \
    --inh-caps=-all $bounding --no-new-privs -- "$0" "$@"
fi

if [ "$#" -gt 0 ]; then
  exec witness-log "$@"
fi

if [ ! -w "$STATE" ]; then
  log "error: $STATE is not writable by uid $(id -u). For a bind mount run: chown $(id -u):$(id -g) <host dir>"
  exit 73
fi

lock_state

want_key=$(printf '%s' "${WITNESS_PUBKEY:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
if [ -n "$want_key" ] && { [ "${#want_key}" -ne 64 ] || [ -n "$(printf '%s' "$want_key" | tr -d '0-9a-f')" ]; }; then
  log "error: WITNESS_PUBKEY must be the witness's 64-hex public key (pubkey_hex in GET /), got \"$want_key\""
  exit 64
fi

if [ -f "$STATE/witness.key" ]; then
  have_key=$(state_pubkey)
  if [ -n "$want_key" ] && [ "$have_key" != "$want_key" ]; then
    log "error: $STATE holds the witness with public key ${have_key:-(unreadable)}, but WITNESS_PUBKEY"
    log "says $want_key. This is not that witness's disk; refusing to serve it under the same name."
    log "Attach the disk that holds $want_key, or, if it is lost for good, retire that key"
    log "(OPERATORS.md section 3), unset WITNESS_PUBKEY and register this witness as a new one."
    exit 78
  fi
  if ! is_mount; then
    log "warning: $STATE is not a separate mount, so this witness's key and memory live in the"
    log "container and go with it. Move the whole directory onto a volume (OPERATORS.md section 3)."
  fi
  [ -z "$want_key" ] && log "note: set WITNESS_PUBKEY=$have_key so that a new or replaced disk is refused instead of becoming a new witness"
else
  if [ -n "$want_key" ]; then
    log "error: WITNESS_PUBKEY is $want_key, but $STATE holds no witness: this is a new, replaced"
    log "or unmounted disk, not the one that key lives on. Refusing to create a different key behind"
    log "the same name. Attach the original disk; if it is lost for good, retire the key"
    log "(OPERATORS.md section 3), unset WITNESS_PUBKEY and register the new witness."
    exit 78
  fi
  if ! is_mount; then
    log "error: $STATE is not a mounted volume, so a key created here would vanish with the container"
    log "and the next start would be a different witness under the same name. Mount persistent"
    log "storage at $STATE: docker run -v witness-log:/state ..., the disk in render.yaml, or the"
    log "[[mounts]] section of fly.toml (check that fly launch kept it)."
    exit 78
  fi
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
  log "next: set WITNESS_PUBKEY=$(state_pubkey) so that a new or replaced disk is refused instead of becoming a new witness"
  [ -z "$url" ] && log "note: WITNESS_URL is unset, so the entry's url is a placeholder; registration takes the URL you give it."
  set --
fi

# witness.lock names a PID, and in a container the witness is always PID 1,
# so after `docker kill`, an OOM kill or a power cut the next container would
# see "held by pid 1" (itself) and refuse forever. The flock taken above
# tells a stale lock from a live one: we hold it, so no other container on
# this host is serving the volume, and a lock naming PID 1 is left over from
# a previous container and is removed.
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
