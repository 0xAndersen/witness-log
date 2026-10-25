# A witness on Fly.io

This runs one witness for your organisation on your own Fly.io account. It
builds `deploy/witness/Dockerfile` from the checkout you deploy, keeps the
state on a Fly volume, and serves it at `https://<app>.fly.dev` with
Fly's TLS. You need [flyctl](https://fly.io/docs/flyctl/install/), a Fly.io
account with a payment method, and a clone of this repository.

```sh
git clone https://github.com/0xAndersen/witness-log && cd witness-log
git checkout v0.7.0              # a release tag (v0.7.0 or newer), not main
cp deploy/fly/fly.toml fly.toml

fly launch --copy-config --no-deploy --name yourorg-witness --region fra
fly volumes create witness_state --size 1 --region fra
fly secrets set --stage WITNESS_ORG="Your Organisation"
fly deploy --ha=false
```

- `git checkout` a release tag so that you, not this repository's main
  branch, decide what code runs: `fly deploy` builds exactly your
  checkout.
- `fly launch` creates the app and writes `app` and `primary_region` into
  `fly.toml`; nothing runs yet. Pick any region (`fly platform regions`)
  and use the same one for the volume. Afterwards `fly.toml` should still
  say `internal_port = 7380`, `auto_start_machines = false`, and have the
  `[[mounts]]` section. Without the mount the witness refuses to create a
  key, so a dropped `[[mounts]]` shows up as a failed first start.
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

Check it, then pin the key:

```sh
curl -s https://yourorg-witness.fly.dev/health      # ok
fly volumes list                                     # exactly one witness_state, attached to one Machine
fly secrets set WITNESS_PUBKEY="$(curl -fsS https://yourorg-witness.fly.dev/ | jq -r .pubkey_hex)"
```

With `WITNESS_PUBKEY` set, the witness never creates a key again: started
on any other volume (a new one, a replaced one, none) it refuses to run
instead of quietly becoming a different witness under the same name.
Setting the secret restarts the Machine once.

If `fly volumes list` shows two `witness_state` volumes, or `fly machine
list` two Machines, something created a second witness. Keep the Machine
and volume whose key is the one `GET /` served when you registered (with
`WITNESS_PUBKEY` set, the other one refuses to start), then remove the
extra: `fly machine destroy <id>` and `fly volumes destroy <id>`.

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
  running (`auto_stop_machines = "off"`) and never starts a stopped one
  on a request (`auto_start_machines = false`).
- **The volume is the witness.** `witness.key`, `witness.json` and `logs/`
  are one unit (`deploy/witness/OPERATORS.md` section 3). Fly takes daily
  snapshots of the volume and keeps them 5 days by default. Restoring one
  after the witness has cosigned anything newer can make your key sign
  two histories of one log. If the volume is lost, retire the key: create
  a new app and volume, register the new entry, and ask for the old one
  to be removed.
- **Moving it** (another region or host). The old copy must never run
  again once the snapshot is taken:
  1. `fly machine stop <id>`; it stays stopped (`auto_start_machines = false`).
  2. `fly volumes snapshots create <volume id>` and wait until
     `fly volumes snapshots list <volume id>` shows it.
  3. `fly machine destroy <id>`, before anything else starts.
  4. `fly volumes create witness_state --snapshot-id <snapshot id> --size 1 --region <region>`
     (see https://docs.fly.io/volumes/snapshots), set `primary_region` in
     `fly.toml` to that region, and `fly deploy --ha=false`.
     `WITNESS_PUBKEY` stays as it is, so only that snapshot's key can start.
  5. When the new Machine serves the same key, `fly volumes destroy` the old volume.
- **Your own domain.** `fly certs add witness.example.org`, and before the
  first deploy `fly secrets set --stage WITNESS_URL=https://witness.example.org`.
  The URL and key name are fixed at the first start.

## Updating

`fly deploy` builds whatever you have checked out, so you decide what
runs: `git fetch --tags && git checkout <newer release tag>`, then
`fly deploy --ha=false`. The volume and key stay; the Machine restarts
in place.

## Cost

When checked on 2026-10-25, [fly.io/pricing](https://fly.io/pricing/)
listed a `shared-cpu-1x` Machine with 256 MB at USD 2.19 a month, volumes
at USD 0.15 per GB-month (1 GB here), and the first 10 GB of snapshots
free: about USD 2.35 a month. There is no free tier for new
organisations. Check current pricing before you deploy.
