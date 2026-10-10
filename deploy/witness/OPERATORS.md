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
- `--url` is metadata for the directory entry; it is not checked.
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
| `logs/<sha256(origin)>.json` | one record per log: origin, log vkey, last cosigned size and root, last cosigned note |
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

`Dockerfile` builds a static-ish image (Debian slim, non-root, read-only
root filesystem under compose). The volume mounted at `/state` is the
whole witness. `docker-compose.yml` adds Caddy for TLS.

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
  evidence/<file>.json` exits 0 if it proves two signed roots for one size.
  Publish the file; it is self-contained and anyone can check it with the
  log's public key.
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

## 5. What you are promising

By publishing a directory entry you are telling verifiers that this key
will never cosign two histories of one log, and that the `operator_org`
label is the organisation that actually controls the machine and the key.
The protocol enforces the first in software for every request it sees; the
backup rule above covers the case it cannot see. Only you can make the
second true.
