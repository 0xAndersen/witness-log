# Running a witness

A witness is a small always-on service (1 MB binary, ~10 MB RAM, a few MB of
disk that must persist) that cosigns other people's logs over
`c2sp.org/tlog-witness`. Its one job is never to cosign two histories of
the same log. Every witness adds capacity; a witness run by a **new
organisation** adds independence, which is what the network needs most.

Full runbook: [`deploy/witness/OPERATORS.md`](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/OPERATORS.md).
Agent-executable version: [`deploy/witness/AGENT_OPERATOR.md`](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/AGENT_OPERATOR.md).

## One witness, five commands

```sh
witness-log witness init ./w1 --name witness.example/w1 --org "Example Org" \
    --url https://witness.example --compute hetzner      # prints the directory entry + vkey: publish both
witness-log witness serve ./w1 --listen 127.0.0.1:7380 --open-enrollment
# put Caddy/nginx in front for TLS; raise --max-conns-per-ip 256 --enroll-rate 6000 behind a proxy
witness-log witness info https://witness.example         # GET /: vkey, directory_entry, counters
witness-log witness verify-evidence ./w1/evidence/<f>.json   # check a recorded equivocation
```

`--org` is the independence label verifiers score by. Use the organisation
that controls the key. `--open-enrollment` accepts any log whose origin is
`witness-log/<its identity key>`; the origin *is* the key, so no key
exchange is needed.

## What it guarantees

- Persists the new head (fsync, atomic rename) **before** the cosignature leaves the process.
- Refuses forks with 422 and records provable equivocation (two log-signed roots for one size) under `evidence/`, one file per log.
- Lock file against two processes on one state directory; refuses to start on a missing `logs/` or a swapped key.
- Bounded: 8 KiB head, 64 KiB body, ≤63 proof lines, 1 KiB checkpoint, 10 s per request, 256 connections, 16 per address, 600 enrollments/address/minute, 100,000 logs, 64 MiB evidence. All flags.
- Clean SIGTERM; automatic stale-lock recovery after SIGKILL.

## Deployment kit (`deploy/witness/`)

| file | use |
|---|---|
| `Dockerfile` | non-root image; volume at `/state` is the whole witness |
| `docker-compose.yml` | witness + Caddy TLS |
| `witness-log-witness.service` | hardened systemd unit (one witness) |
| `witness-log-witness@.service` | template, one instance per name |
| `fleet.py init/serve/status/directory` | N witnesses on one host |

## Fleets

`fleet.py init /srv/fleet --count 25 --org "Example Org" --name-base witness.example/w --url-base https://witness.example`
then `fleet.py serve /srv/fleet --open-enrollment --behind-proxy`. 100
witnesses fit in ~500 MB on a two-core box. They are **one operator**;
the gain is availability and capacity, never independence.

## The backup rule

`witness.key`, `witness.json` and `logs/` are one object. Restore them
together or not at all. A key restored without its memory will cosign the
next size-N root it is shown, contradicting what it cosigned before, and
no software can tell that from a new witness. If `logs/` is lost, retire
the key and `init` a new witness.

## Free always-on hosting

Oracle Cloud Always Free (ARM/AMD VMs, persistent disk) is the best
zero-cost option; GCP e2-micro works; your own hardware behind Cloudflare
Tunnel works. Free tiers that sleep or wipe their disk (Render, Koyeb,
Railway free, HF Spaces, serverless) are unsuitable for the reason above.

## Register

Add the entry `init` printed as `registry/witnesses/<org>-<name>.json` in a
PR. CI validates it and cross-checks the key against your URL. See
[Getting witnessed](Getting-Witnessed).
