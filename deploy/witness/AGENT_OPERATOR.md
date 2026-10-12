# Run a witness: the playbook for an agent

This page is written to be handed to a coding agent (Claude Code, Codex,
Cursor, an OpenClaw/AutoGPT-style loop, your own) with one line of
instruction: *"Follow deploy/witness/AGENT_OPERATOR.md and register the
witness."* Every step is a command; the agent needs a shell on a machine
that stays on, and nothing else. A human with a terminal can follow it too.

What you end up with: one always-on `c2sp.org/tlog-witness` witness, under
a key only this machine holds, listed in `registry/witnesses/` so verifiers
can add it to their directory. Every witness adds capacity; a witness run by
a **new organisation** adds independence, which is the thing the network
needs most (WITNESSED requires two distinct operators).

## Zero-touch path (no terminal): cloud-init

`cloud-init.yaml` in this directory does steps 1–5 and 7 by itself at the
VM's first boot: binary (checksum-verified), system user, one witness,
hardened systemd unit, Caddy with automatic TLS on `<public-ip>.sslip.io`
(no DNS needed), host firewall. Edit the three values at the top (`ORG`,
`NAME_BASE`, `COMPUTE`), paste the file into the provider's cloud-init /
user-data box when creating the VM, open ports 80 and 443 in the
provider's firewall, and 3–5 minutes later `http://<public-ip>/health`
answers `ok`. Then register it from the repo: Actions → *register-witness*
→ Run workflow → `url = https://<public-ip>.sslip.io` (an outside operator
opens the PR in step 6 instead). Manual steps follow for anyone who wants
to see what it does.

If the release has no Linux binary for the CPU (v0.3.5 ships
`x86_64-unknown-linux-gnu` only; Oracle's Always Free Ampere VMs are
`aarch64`), the script compiles the same version from crates.io instead,
which takes several minutes on first boot. The Docker image
(`OPERATORS.md`, "Docker") covers arm64 without compiling.

## 0. Where to run it (free, always-on)

The witness is a 1 MB static binary that needs ~10 MB of RAM, a few MB of
disk that must persist, and an inbound HTTPS port. Anything that sleeps
without disk or wipes its disk on redeploy is unsuitable: a witness that
forgets what it cosigned will contradict itself. Known-good free options:

| provider | tier | notes |
|---|---|---|
| Oracle Cloud | Always Free: 2 AMD VMs or 4 ARM OCPUs, 200 GB block storage | the best free always-on choice; `aarch64` binary from the release page |
| Google Cloud | e2-micro, 1 per account, always free (US regions) | 30 GB disk persists |
| AWS | t2/t3.micro, 12 months free | expires; set a reminder |
| your own hardware | a Raspberry Pi, a NAS, a desk machine | needs a port forward or a tunnel (Cloudflare Tunnel is free) |

Unsuitable: Render/Koyeb/Railway free tiers (ephemeral disk or sleep),
Hugging Face Spaces (persistent storage is paid), GitHub Actions (6-hour
jobs), serverless/edge functions (no durable fsync before reply).

## 1. Install

```sh
# pick the asset for your CPU from https://github.com/0xAndersen/witness-log/releases/latest
# (no aarch64 Linux asset in v0.3.5: on ARM use `cargo install` below or the Docker image)
ARCH=$(uname -m)            # x86_64 or aarch64
VER=v0.3.5
curl -fsSLO https://github.com/0xAndersen/witness-log/releases/download/$VER/witness-log-$VER-$ARCH-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/0xAndersen/witness-log/releases/download/$VER/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar xzf witness-log-$VER-$ARCH-unknown-linux-gnu.tar.gz      # flat: ./witness-log, LICENSE, README.md
sudo install -m 0755 ./witness-log /usr/local/bin/witness-log
witness-log --version
```

(Or `cargo install --git https://github.com/0xAndersen/witness-log --tag $VER witness-log-cli`.)

## 2. Initialise with your real organisation

```sh
sudo useradd --system --home /var/lib/witness-log --shell /usr/sbin/nologin witness-log
sudo install -d -o witness-log -g witness-log -m 0700 /var/lib/witness-log
HOST=witness.yourdomain.example        # the DNS name you will point at this machine
sudo -u witness-log witness-log witness init /var/lib/witness-log/w1 \
    --name $HOST/w1 \
    --org "Your Organisation" \
    --url https://$HOST \
    --compute oracle-cloud
```

Save what it prints: the JSON **directory entry** and the **vkey**. The
`--org` value is how verifiers tell operators apart. Use the name of the
organisation (or person) that controls this machine; never leave it out.

## 3. Run it under systemd

```sh
sudo curl -fsSL -o /etc/systemd/system/witness-log-witness.service \
  https://raw.githubusercontent.com/0xAndersen/witness-log/main/deploy/witness/witness-log-witness.service
sudo systemctl daemon-reload
sudo systemctl enable --now witness-log-witness
curl -s http://127.0.0.1:7380/health      # -> ok
```

The unit listens on `127.0.0.1:7380` and expects a TLS proxy in front.

## 4. Put TLS in front

```sh
sudo apt-get install -y caddy             # or any reverse proxy
echo "$HOST {
    reverse_proxy 127.0.0.1:7380
}" | sudo tee /etc/caddy/Caddyfile
sudo systemctl restart caddy
curl -s https://$HOST/ | head -c 300      # the witness's GET /, over TLS
```

Point the DNS A/AAAA record of `$HOST` at the machine first; Caddy obtains
the certificate itself. Open ports 80 and 443 in the provider firewall.

## 5. Back it up as one unit

`/var/lib/witness-log/w1` is the whole witness: `witness.key`,
`witness.json` and `logs/`. Snapshot the directory, never the key alone
(OPERATORS.md §3 explains why a key without its memory is dangerous).

## 6. Register

```sh
git clone https://github.com/0xAndersen/witness-log
cd witness-log
curl -s https://$HOST/ | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["directory_entry"], indent=2))' \
    > registry/witnesses/your-org-w1.json
python3 registry/validate.py
git checkout -b register-your-org-w1 && git add registry/witnesses/your-org-w1.json
git commit -m "registry: Your Organisation witness w1" && git push -u origin HEAD
gh pr create --fill          # or open the PR in the browser
```

CI validates the entry and cross-checks the key against your URL.

## 7. Prove it works from outside

```sh
witness-log witness info https://$HOST
python3 - <<'EOF'
import witness_log as wl, urllib.request, json
log = wl.open("probe.jsonl"); log.append_intent(b"hello witness")
body = log.add_checkpoint_body(0)
req = urllib.request.Request("https://HOST/add-checkpoint", data=body.encode(), method="POST")
print(urllib.request.urlopen(req).read().decode())   # a cosignature line
EOF
```

## Running more than one

`fleet.py init <root> --count N ...` and `fleet.py serve <root>` run N
witnesses on one host, or use the `witness-log-witness@.service` template.
They are all one operator; the gain is availability and capacity. The
network gains independence only when someone else does steps 0–6.
