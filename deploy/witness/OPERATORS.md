# Running a witness-log witness

A witness is a small, internet-facing service that countersigns other
people's logs. It holds one Ed25519 key and a memory of the last head it
cosigned for every log it has seen. Its one job is never to cosign two
different histories of the same log. Everything on this page follows from
that.

This directory has a Dockerfile, a docker-compose file with a
TLS-terminating proxy, and a hardened systemd unit. `THREAT_MODEL.md`
("Running a witness") says what the server defends against;
`GOVERNANCE.md` says why independent operators matter.

## 1. Initialise

```sh
witness-log witness init ./w1 \
    --name witness.example/w1 \
    --org "Example Org" \
    --url https://witness.example \
    --compute hetzner
```

- `--name` is the C2SP key name verifiers see in cosignatures. Use a
  hostname you control plus a suffix.
- `--org` **is the independence label.** Verifiers reach WITNESSED only when
  cosignatures come from two or more distinct `operator_org` values in
  their directory. Two witnesses with the same label are one operator; a
  label left as `unspecified` shares a bucket with every other unspecified
  witness forever. Put the real organisation here.
- `--url` is the public base URL clients will use. The registry requires
  `https://` and cross-checks the URL live: `GET /` must serve this key and
  this exact `--org` string (`registry/README.md`).
- `--org` is compared byte for byte by the registry against what the
  witness serves, so use one spelling, with one capitalisation, for every
  witness one organisation runs. The verifier itself folds case when
  scoring, so `Example Org` and `example org` are one operator to a
  verdict either way; the registry rule is there so the file, the witness
  and the operator agree on one string.
- `--compute` is where the machine runs (cloud provider, "homelab", a
  model/inference provider for agent witnesses). Verifiers score
  compute-provider diversity separately; undisclosed scores as its own weak
  bucket, never as neutral.

`init` prints the **directory entry** (JSON) and the **vkey**. Publish both
somewhere the log operators you serve cannot edit: your website, a
repository you control, a registry a verifier community curates. Nothing
counts until a verifier adds your entry to the directory they pass as
`--directory`.

The state directory is created `0700` with:

| path | what it is |
|---|---|
| `witness.key` | the 32-byte Ed25519 seed, hex, `0600`. **Private key.** |
| `witness.json` | key name, org, URL, compute provider, and the public key the directory was initialised with |
| `logs/<sha256(origin)>.json` | one record per log: origin, log vkey, last cosigned size and root, last cosigned note. Read when a request for that log arrives, never all at start |
| `evidence/<sha256(origin)>.json` | written only when a log provably equivocated: two log-signed roots for one size |
| `witness.lock` | held while `serve` runs; names the PID |

## 2. Serve

```sh
witness-log witness serve ./w1 --listen 127.0.0.1:7380 --open-enrollment
```

`--open-enrollment` accepts any log whose origin is the canonical
`witness-log/<identity key hex>`: the origin *is* the key, so no key
exchange is needed and nothing is trusted on first use. Without it, add
logs explicitly with `witness add-log <dir> <origin> <log-vkey>`.

Endpoints:

| | |
|---|---|
| `POST /add-checkpoint` | the `c2sp.org/tlog-witness` protocol. 200 cosignature; 409 + the size the witness expects (`text/x.tlog.size`); 422 the log equivocated (refused, recorded if provable); 400/403/404 bad or unknown input |
| `GET /` | JSON: software, vkey, `directory_entry`, log count, counters since start |
| `GET /health` | `ok` |

Logging is deliberately sparse: one line at start, one when a stale lock
is removed, one per proven equivocation. Counters are on `GET /`. There is
no access log; if you want one, your proxy has it.

### Start-up time and memory

`serve` does not read the records in `logs/` when it starts. It lists the
directory once, by file name (that is the log count `GET /` reports and
`--max-logs` is checked against), and reads a log's record when a request
for that log arrives, keeping the 4,096 most recently used records in
memory. Start-up time and memory therefore stay flat however many logs
the witness has cosigned. (0.5.0 and earlier parsed every record before
listening, which took minutes for ~25,000 logs on a cold disk.)

What that changes for an operator:

- A file in `logs/` whose name is not `<sha256(origin)>.json` still stops
  the start (move it out). A record that is **damaged** (truncated, edited,
  stored under another log's name) is found only when its log next
  submits: that log gets HTTP 500 (`witness state for this log is
  unreadable`) and the witness writes one error line per request naming
  the file. Every other log is served normally. The witness never treats
  such a log as new.
- **Do not delete a damaged record to make the error go away**: the
  witness would then enroll that log afresh at size 0 and could cosign a
  fork of it. Restore the file under the rule in section 3 (only from a
  snapshot newer than the log's last cosignature), or leave the log
  refused.
- `witness add-log` takes effect on a running witness without a restart
  (the record is read on the first request for that log); the `GET /`
  count includes it from the next start.

### Behind a reverse proxy (recommended)

The built-in server speaks plain HTTP; integrity rests on signatures, so
TLS is for privacy and for looking normal to corporate egress filters.
Terminate TLS in Caddy, nginx or your cloud load balancer and forward to
`127.0.0.1:7380`. Because every client then arrives from the proxy's
address, raise the per-address limits:

```
--max-conns-per-ip 256 --enroll-rate 6000
```

(defaults: 16 connections and 600 new enrollments per minute per address;
`--max-conns 256` total and `--max-logs 100000` are independent of the
proxy). Request limits are fixed: 8 KiB head, 64 KiB body, 10 s per
request, chunked bodies refused.

### systemd

`witness-log-witness.service` runs the binary as a dedicated user with the
state directory as the only writable path. `Restart=always` is safe: a
`SIGTERM`/`SIGINT` stop finishes any in-flight decision, releases the lock
and exits 0; after a crash or `kill -9` the lock names a dead PID and the
next start removes it itself, with one log line.

### Docker

One line, any amd64 or arm64 host with Docker:

```sh
docker run -d --name witness-log --restart unless-stopped -p 7380:7380 \
  -v witness-log:/state -e WITNESS_ORG="Your Org" ghcr.io/0xandersen/witness-log:latest
docker logs witness-log                 # prints the directory entry
curl -s http://127.0.0.1:7380/health    # ok
```

On first start with an empty `/state` the image runs `witness init` from
the environment, writes `/state/entry.json`, prints the entry, then
serves; every later start serves the existing key. Variables:
`WITNESS_ORG` (required on first start), `WITNESS_URL` (your public base
URL; the key name defaults to its host plus `/w1`), `WITNESS_NAME`,
`WITNESS_COMPUTE`, and `WITNESS_BEHIND_PROXY=1` when a TLS proxy sits in
front (raises the per-address limits). The volume `witness-log` is the
whole witness: back it up as one unit (section 3). Arguments replace the
default and go to the binary: `docker run --rm IMAGE witness info URL`.

The witness is always PID 1 inside a container, so its PID lock file
cannot tell a killed container's lock from a live one. The entrypoint
holds an `flock` on `/state/container.lock` for the life of the server: a
second container on the same volume is refused, and a lock left by a
killed container is cleared on the next start.

The image is built by `.github/workflows/docker.yml` from the release
binaries (`Dockerfile.release`, checksum-verified, linux/amd64 and
linux/arm64). `Dockerfile` builds from source instead (Debian slim,
non-root, read-only root filesystem under compose) and uses the same
entrypoint, so `docker build -t witness-log -f deploy/witness/Dockerfile .`
gives an image that behaves like the published one; `docker-compose.yml`
adds Caddy for TLS.

### Render and Fly.io (one click)

`render.yaml` at the repository root is a Render Blueprint and
`deploy/fly/fly.toml` a Fly.io configuration (steps in
`deploy/fly/README.md`; both are walked through in
`docs/wiki/Operator-Onboarding.md`, "Deploy in one click"). Each builds
`Dockerfile` from the repository, mounts a persistent disk at `/state`,
runs one instance, checks `GET /health`, and leaves `WITNESS_ORG` for the
operator to fill in. The platform terminates TLS, so both set
`WITNESS_BEHIND_PROXY=1`, and the entrypoint takes the witness's URL from
the platform (`RENDER_EXTERNAL_URL`, or `https://$FLY_APP_NAME.fly.dev`)
unless `WITNESS_URL` is set. Both platforms mount the disk owned by root,
so both build with `WITNESS_IMAGE_USER=0:0`: the entrypoint starts as
root, gives `/state` to uid 10001, and runs the witness as uid 10001.
Their daily disk snapshots fall under section 3: restoring one after
the witness has cosigned anything newer is a stale restore.
`.github/workflows/deploy-configs.yml` checks both files and runs the
image the way they configure it.

### cloud-init (paste into a new VM)

`cloud-init.yaml` does install, init, systemd, Caddy and firewall at first
boot; `AGENT_OPERATOR.md` describes it. What is tested, and how:

- `.github/workflows/cloud-init-test.yml` (manual) boots the file in a real
  Ubuntu 24.04 cloud image under QEMU/KVM on a GitHub runner and checks,
  from outside the VM, `/health` through Caddy, the binary version, the
  unit, `entry.json`, that 7380 is not exposed, a cosignature for a
  journal submitted from the runner, and the same key after a reboot.
- What no CI can test: the public certificate (the VM has no inbound
  internet). The test sets `HOST` to a `.invalid` name so Caddy's TLS
  step fails and the plain-http path, which must work without it, is what
  gets checked.
- Offline tolerance: if the public-IP lookup fails the script uses the
  default-route interface address (the lookup is skipped entirely when
  `HOST` is set); if Caddy cannot be fetched, or its archive does not match
  the checksum file its GitHub release publishes, the witness keeps serving
  on `127.0.0.1:7380` without TLS and the log says `WARNING: NO TLS` with
  the reason. Caddy's checksum file (`caddy_<ver>_checksums.txt`) carries
  SHA-512 digests, so that is the digest compared; the release is pinned by
  `CADDY_VERSION` in `/etc/witness-log/env`.
- Pinned inputs: the systemd unit is fetched from the repo at the release
  tag in `WL_REF` (default: the current release), never from a branch, and
  is checked to be a unit file before it is installed. `WL_VERSION` pins the
  witness-log release; `latest` resolves through the GitHub API at boot.
- Placeholder guard: the bootstrap exits 1 before touching anything if
  `ORG` is still `Your Organisation` (or empty, or `unspecified`). The
  label is the independence signal; a default would be worse than no
  witness. Edit `/etc/witness-log/env` and re-run
  `/usr/local/sbin/witness-log-bootstrap`.

## 3. Back up: the key and `logs/` are one object

**Never restore `witness.key` without the `logs/` directory that goes with
it.** A witness that remembers nothing will cosign whatever size-N root it
is shown next, and if that root differs from one the same key cosigned
earlier, the key has equivocated: two valid cosignatures by your key over
two histories of one log. Verifiers who notice will, correctly, remove your
entry from their directory. No software check can distinguish "restored
from a backup that lacked `logs/`" from "brand-new witness"; `witness.json`
only catches a key swapped for a different one.

So:

- Back up `witness.key`, `witness.json` and `logs/` **together, atomically**
  (filesystem snapshot, or stop the service, copy, start).
- Restore all three from the **same** snapshot, or none.
- A consistent snapshot can still be **stale**: if the witness cosigned
  anything after the snapshot was taken, the restored copy has forgotten
  those heads and could cosign a fork between the remembered size and the
  forgotten one. Restore only a snapshot taken after the last cosignature
  (for example after a clean stop); if the witness served after the newest
  snapshot you have, retire the key as below. Automatic VM or volume
  snapshots (daily, hourly) are a reason to retire, not to restore.
- If `logs/` is lost for good, retire the key: generate a new witness with
  `init` in a fresh directory, publish the new entry, and ask verifiers to
  drop the old one. Do not reuse the key.
- `evidence/` is publishable and worth keeping, but losing it harms no one.

A snapshot taken while the service runs is consistent: every record is
written to a temp file, fsynced and renamed into place before the matching
cosignature leaves the process, so the directory on disk never claims a
head the witness has not committed to.

## 4. Operate

- **Check it is alive**: `witness-log witness info https://witness.example`
  prints `GET /`.
- **Check an equivocation file**: `witness-log witness verify-evidence
  evidence/<file>.json` exits 0 if it proves two signed roots for one size
  (PROVEN) and 40 if it does not (NOT PROVEN; 30 before 0.5.0).
  Publish the file; it is self-contained and anyone can check it with the
  log's public key. A verifier holding it passes it to
  `witness-log verify <dossier> --evidence <file>`, which reports any
  valid dossier of that identity as DIVERGED (exit 30).
- **Two processes on one directory** is refused by the lock. If the lock
  names a live PID that is not a witness (PID reuse after a reboot), stop
  everything that could be serving that directory and delete `witness.lock`.
- **Key file permissions** are checked at start; a world-readable key logs a
  warning. Fix it (`chmod 600`).
- **Key rotation** means a new witness: `init` a new directory, publish
  the new entry, keep the old one serving until verifiers have switched,
  then stop it. Cosignatures are per key; there is no rollover protocol.
- **Updating** the binary is a stop/replace/start; the on-disk format is
  versioned and refused, never reinterpreted, if it ever changes.

## 5. More than one, and letting an agent do it

`fleet.py init/serve/status` runs N witnesses on one host (one key and
one memory each; one operator bucket in total). `witness-log-witness@.service`
is the per-instance systemd template. `AGENT_OPERATOR.md` is the same
procedure written for a coding agent to execute end to end, including
registration in `registry/`.

### A fleet on a cloud account, from Actions

`.github/workflows/deploy-fleet.yml` creates N small servers (Hetzner Cloud
or DigitalOcean) that boot `cloud-init.yaml` with your `ORG`, waits for each
to answer at `https://<ip>.sslip.io/`, registers the ones that came up and
commits the entries. The only input besides the form is a cloud API token
in the repository environment `fleet` (`HCLOUD_TOKEN` or
`DIGITALOCEAN_TOKEN`); it is read by the job and never printed. Expect
~15 minutes from dispatch to registered: apt, the release binary, and a
public certificate per machine. Rerun with a larger `count` to grow it;
servers carry the label/tag `witness-log` so the account's console lists
them. Delete a server from the console and its entry from
`registry/witnesses/` to retire it (`status.yml` marks a dead URL within
ten minutes either way).

A fleet is one operator. Five project-run witnesses in a directory give
capacity and availability; the verdict stays CONSISTENT-UNWITNESSED until
a second organisation's witness cosigns the same checkpoint.

## 6. What you are promising

By publishing a directory entry you are telling verifiers that this key
will never cosign two histories of one log, and that the `operator_org`
label is the organisation that actually controls the machine and the key.
The protocol enforces the first in software for every request it sees; the
backup rule above covers the case it cannot see. Only you can make the
second true.
