# A witness on Fly.io

This runs one witness for your organisation on your own Fly.io account. It
builds `deploy/witness/Dockerfile` from the checkout you deploy, keeps the
state on a Fly volume, and serves it at `https://<app>.fly.dev` with
Fly's TLS. You need [flyctl](https://fly.io/docs/flyctl/install/), a Fly.io
account with a payment method, and a clone of this repository.

```sh
git clone https://github.com/0xAndersen/witness-log && cd witness-log
cp deploy/fly/fly.toml fly.toml

fly launch --copy-config --no-deploy --name yourorg-witness --region fra
fly volumes create witness_state --size 1 --region fra
fly secrets set --stage WITNESS_ORG="Your Organisation"
fly deploy --ha=false
```

- `fly launch` creates the app and writes `app` and `primary_region` into
  `fly.toml`; nothing runs yet. Pick any region (`fly platform regions`)
  and use the same one for the volume. Afterwards `fly.toml` should still
  say `internal_port = 7380` and have the `[[mounts]]` section.
- `fly volumes create` makes the one volume the witness keeps its key and
  memory on. Fly warns that a single volume is not highly available:
  that is intended. One witness has exactly one volume.
- `WITNESS_ORG` is the organisation that controls this Fly.io account and
  so the key. It is the independence label verifiers count. Use the same
  spelling everywhere your organisation runs a witness.
- `fly deploy --ha=false` builds the image and starts one Machine. The
  first start creates the key, prints the directory entry (`fly logs`)
  and serves. The witness's URL and key name come from the app name:
  `https://yourorg-witness.fly.dev` and `yourorg-witness.fly.dev/w1`.

Check it:

```sh
curl -s https://yourorg-witness.fly.dev/health      # ok
curl -s https://yourorg-witness.fly.dev/ | jq '{vkey, directory_entry}'
```

## Register

The registry file is the `directory_entry` that `GET /` serves:

```sh
curl -fsS https://yourorg-witness.fly.dev/ | jq .directory_entry > registry/witnesses/yourorg-w1.json
python3 registry/validate.py        # checks the file and that your URL serves the same key and org
```

Open a pull request with that file, or open an issue with your URL and a
maintainer runs the `register-witness` workflow. Details:
[Operator onboarding](../../docs/wiki/Operator-Onboarding.md#register).

## Rules that keep it a witness

- **One Machine.** Never `fly scale count 2` or `fly machine clone`: each
  Machine gets its own volume, so a second one is a second witness with a
  different key behind the same URL. `fly.toml` keeps the one Machine
  running (`auto_stop_machines = "off"`); a stopped witness cosigns
  nothing.
- **The volume is the witness.** `witness.key`, `witness.json` and `logs/`
  are one unit (`deploy/witness/OPERATORS.md` section 3). Fly takes daily
  snapshots of the volume and keeps them 5 days by default. Restoring one
  after the witness has cosigned anything newer can make your key sign
  two histories of one log. If the volume is lost, retire the key: create
  a new app and volume, register the new entry, and ask for the old one
  to be removed.
- **Moving it.** Stop the Machine (`fly machine stop`), snapshot the
  volume (`fly volumes snapshots create <volume id>`), restore that
  snapshot as the new volume, and never start the old Machine again.
- **Your own domain.** `fly certs add witness.example.org`, and before the
  first deploy `fly secrets set --stage WITNESS_URL=https://witness.example.org`.
  The URL and key name are fixed at the first start.

## Updating

`fly deploy` builds whatever you have checked out, so you decide what
runs: `git pull` (or `git checkout` a release tag), then
`fly deploy --ha=false`. The volume and key stay; the Machine restarts
in place.

## Cost

When checked on 2026-10-25, [fly.io/pricing](https://fly.io/pricing/)
listed a `shared-cpu-1x` Machine with 256 MB at USD 2.19 a month, volumes
at USD 0.15 per GB-month (1 GB here), and the first 10 GB of snapshots
free: about USD 2.35 a month. There is no free tier for new
organisations. Check current pricing before you deploy.
