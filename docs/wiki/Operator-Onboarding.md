# Operator onboarding

## Why run one

A witness-log verdict of WITNESSED needs cosignatures from at least two
witnesses run by different organisations, and today the public registry has
none, so every agent log in the world is capped at CONSISTENT-UNWITNESSED
until two independent operators exist. Running one witness makes your
organisation one of those two, and it is the same `c2sp.org/tlog-witness`
protocol the transparency-log ecosystem already uses.

## What it costs

- **Money:** nothing on the free hosting options below.
- **Machine:** a ~2 MB binary (the v0.3.5 x86_64 release binary is
  1,912,072 bytes); about 3–4 MB of resident memory idle (measured RSS of
  `witness-log 0.3.5 witness serve` on Linux) and roughly 5 MB per witness
  under load (100 witnesses in ~500 MB in the 1,000-agent swarm run,
  `examples/swarm/README.md`); a state directory that starts at a few KB and
  grows by one small JSON record per log it witnesses.
- **The one hard requirement:** that state directory must **persist**. A
  host that wipes its disk on redeploy, or sleeps and forgets, is unsuitable
  for the reason in the next section.
- **Time:** about two minutes to start, then nothing routine. Updating is
  stop, replace the binary (or pull the image), start.

## What you promise

Read [`OPERATORS.md` §6](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/OPERATORS.md#6-what-you-are-promising).
In short:

1. Your key never cosigns two histories of one log. The software enforces
   this for every request it sees, as long as it keeps its memory.
2. **The backup rule:** `witness.key`, `witness.json` and `logs/` are one
   object. Back them up together; restore them together or not at all. A
   key without its `logs/` will cosign whatever it is shown next and can
   contradict itself. If `logs/` is lost, retire the key and start a new
   witness. ([§3](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/OPERATORS.md#3-back-up-the-key-and-logs-are-one-object))
3. `--org` / `WITNESS_ORG` is the organisation that actually controls the
   machine and the key. Mislabelling is the one thing the protocol cannot
   detect, and it is what gets an entry removed.

Nothing else: no uptime SLA, no on-call. A witness that is down simply does
not cosign; the status page shows it honestly.

## Three two-minute paths

### 1. Paste cloud-init into a new VM

Open [`deploy/witness/cloud-init.yaml`](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/cloud-init.yaml),
change `ORG`, `NAME_BASE` and `COMPUTE`, paste the whole file into the
provider's *cloud-init* / *user data* box when you create an Ubuntu VM, and
open ports 80 and 443 in the provider's firewall. Three to five minutes
after boot:

```sh
curl -s http://<public-ip>/health        # ok
curl -s http://<public-ip>/ | jq .directory_entry
```

It installs the checksum-verified release binary, a dedicated user, one
witness under a hardened systemd unit, Caddy (http at once, TLS on
`<public-ip>.sslip.io` with no DNS needed) and the host firewall rules.
On an ARM VM with v0.3.5 it compiles the binary from crates.io first,
because that release has no aarch64 Linux binary; that adds several
minutes.

### 2. Docker, one line

```sh
docker run -d --name witness-log --restart unless-stopped -p 7380:7380 \
  -v witness-log:/state -e WITNESS_ORG="Your Org" ghcr.io/0xandersen/witness-log:latest
docker logs witness-log                  # the directory entry
curl -s http://127.0.0.1:7380/health     # ok
```

Optional: `-e WITNESS_URL=https://witness.example.org` (the key name then
becomes `witness.example.org/w1`), `-e WITNESS_COMPUTE=hetzner`, and
`-e WITNESS_BEHIND_PROXY=1` if a TLS proxy or tunnel sits in front.
linux/amd64 and linux/arm64. The named volume `witness-log` is the whole
witness: snapshot it as one unit. Details: [OPERATORS.md, Docker](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/OPERATORS.md#docker).

### 3. Binary and systemd

```sh
VER=v0.3.5
curl -fsSLO https://github.com/0xAndersen/witness-log/releases/download/$VER/witness-log-$VER-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/0xAndersen/witness-log/releases/download/$VER/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf witness-log-$VER-x86_64-unknown-linux-gnu.tar.gz && sudo install -m 0755 witness-log /usr/local/bin/
# ARM or anything else: cargo install --locked witness-log-cli
sudo useradd --system --home /var/lib/witness-log --shell /usr/sbin/nologin witness-log
sudo install -d -o witness-log -g witness-log -m 0700 /var/lib/witness-log
sudo -u witness-log witness-log witness init /var/lib/witness-log/w1 \
    --name witness.example.org/w1 --org "Your Org" --url https://witness.example.org --compute hetzner
sudo curl -fsSL -o /etc/systemd/system/witness-log-witness.service \
    https://raw.githubusercontent.com/0xAndersen/witness-log/main/deploy/witness/witness-log-witness.service
sudo systemctl daemon-reload && sudo systemctl enable --now witness-log-witness
curl -s http://127.0.0.1:7380/health     # ok
```

The unit listens on `127.0.0.1:7380`; put Caddy or nginx in front
([`AGENT_OPERATOR.md` §4](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/AGENT_OPERATOR.md)).

### Raspberry Pi, NAS, a machine under a desk

Run path 2 (64-bit OS; the image is arm64 and amd64) or path 3 with
`cargo install`, then publish it with a named [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
so you need no public IP or port forward:

```sh
docker run -d --name witness-log --restart unless-stopped -p 127.0.0.1:7380:7380 \
  -v witness-log:/state -e WITNESS_ORG="Your Org" -e WITNESS_URL=https://witness.example.org \
  -e WITNESS_BEHIND_PROXY=1 ghcr.io/0xandersen/witness-log:latest
cloudflared tunnel login
cloudflared tunnel create witness
cloudflared tunnel route dns witness witness.example.org
cloudflared tunnel run --url http://127.0.0.1:7380 witness
```

A named tunnel needs a Cloudflare account and a domain on it. Quick
tunnels (`trycloudflare.com`) get a new hostname every start and are meant
for testing, so they cannot be registered. `WITNESS_BEHIND_PROXY=1` matters
here: every request arrives from the tunnel's local address. Put the
volume on storage that survives an SD-card failure, or snapshot it.

## Where to host it

Checked October 2026. Prices and terms change; the sources are linked
below.

| provider | what you get | verdict |
|---|---|---|
| Oracle Cloud Always Free | 2 AMD micro VMs (1/8 OCPU, 1 GB) or Ampere A1 up to 2 OCPU / 12 GB; 200 GB block storage; 10 TB egress/month [1] | **Best free option.** Caveat: Oracle may reclaim Always Free instances that stay under 20% CPU (p95), network and (A1) memory over 7 days [1], which a witness does. Keep the state on a block volume you snapshot, and expect to recreate the VM. ARM needs the crates.io build or the Docker image for v0.3.5. |
| Google Cloud e2-micro | 1 e2-micro per month in us-west1, us-central1 or us-east1; 30 GB-months standard persistent disk; 1 GB egress/month from North America [2] | **Good.** Persistent disk, always on. Stay in those three regions and on a standard disk; check whether your bill shows an external IPv4 charge. |
| AWS | New accounts: USD 100 credit (up to 100 more for activities); the Free account plan ends after six months or when credits run out [3] | **Temporary.** Fine for a trial; budget for it or move before the plan ends. |
| Hetzner Cloud | CX23 (2 vCPU, 4 GB) EUR 5.49/month + EUR 0.50 IPv4 in DE/FI since the 15 June 2026 repricing; CAX11 (arm64) EUR 5.99 + 0.50 [4][5] | **Cheapest reliable paid option** we found; persistent disk, no idle reclamation. The cost-optimized line showed "currently unavailable" when checked [6]. |
| Fly.io | No free tier for new organisations; shared-cpu-1x 256 MB USD 2.19 per 30 days running; volumes USD 0.15/GB-month [7] | **Only with a volume and with auto-stop off** (`auto_stop_machines = "off"`, `min_machines_running = 1`). A stopped machine does not cosign. About USD 2.40/month. |
| Railway | Free plan: USD 1 credit/month, 0.5 GB volume per service; workloads stop when credit is exhausted; free-plan volume data deleted 30 days after expiry [8][9] | **Rejected.** Running out of credit stops the witness, and an expired volume takes the key and memory with it. |
| Render | Free web services spin down after 15 min without traffic, cannot attach persistent disks, filesystem is ephemeral [10] | **Rejected.** A restart wipes `logs/`. |
| Koyeb | Free instance scales to zero after 1 h without traffic; no volumes [11] | **Rejected.** Same reason. |
| Your own hardware | A Pi, a NAS, a spare box | **Good**, with a named tunnel or a port forward, and storage you back up. |

Also unsuitable: serverless and edge functions (no durable write before the
reply), CI runners (jobs end), anything without a persistent volume.

## Register

Once `GET /` answers from the internet:

- **Pull request:** add the `directory_entry` from `GET /` as
  `registry/witnesses/<org>-<name>.json` (exact steps:
  [`AGENT_OPERATOR.md` §6](https://github.com/0xAndersen/witness-log/blob/main/deploy/witness/AGENT_OPERATOR.md)).
  CI runs `registry/validate.py`, which checks the shape and that your URL
  serves the same key.
- **Or ask:** open an issue with your witness URL and the maintainers run
  the `register-witness` workflow, which fetches the entry from your URL,
  validates it and commits it.

## What you get

- **A registry entry** under your organisation's name in
  [`registry/witnesses/`](https://github.com/0xAndersen/witness-log/tree/main/registry/witnesses),
  which verifiers build their directory from.
- **A place in the Founding operators list** in
  [`GOVERNANCE.md`](https://github.com/0xAndersen/witness-log/blob/main/GOVERNANCE.md#founding-operators),
  in registration order.
- **A line on the status page**, probed every 10 minutes, with uptime over
  24 hours and 7 days and the counters your witness publishes:
  [STATUS.md](https://github.com/0xAndersen/witness-log/blob/status/STATUS.md)
  ([JSON](https://raw.githubusercontent.com/0xAndersen/witness-log/status/status.json)).
- Your own agents' logs can reach WITNESSED as soon as one other
  organisation runs a witness too.

## Sources

1. Oracle, Always Free Resources: <https://docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm>
2. Google Cloud, Free Program features (Compute Engine): <https://docs.cloud.google.com/free/docs/free-cloud-features>
3. AWS, Free Tier (account plans and credits): <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier.html>
4. Cloud pricing comparison, prices retrieved early August 2026: <https://kimmo.suominen.com/stuff/cpc-2026-08.txt>
5. Hetzner June 2026 cloud repricing: <https://privatedevops.com/news/hetzner-june-2026-cloud-price-increase-what-to-do>
6. Hetzner Cloud, cost-optimized plans: <https://www.hetzner.com/cloud/cost-optimized/>
7. Fly.io pricing: <https://docs.fly.io/about/pricing>
8. Railway plans: <https://docs.railway.com/reference/pricing/plans>
9. Railway free trial: <https://docs.railway.com/reference/pricing/free-trial>
10. Render free instances: <https://render.com/docs/free>
11. Koyeb instances: <https://www.koyeb.com/docs/reference/instances>
12. Cloudflare Tunnel: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>; Quick Tunnels: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/>
