# Pilot: three organisations, one witness each

The smallest deployment in which every participant's agent logs reach
WITNESSED without anyone outside the pilot: three organisations, one
witness each, one exchange of directory entries. Each organisation's own
witness never counts toward its own agents (it would be attesting to
itself), so each log is witnessed by the other two, which is exactly the
two independent operators WITNESSED requires.

Two organisations are not enough on their own: each log then has one
independent witness. A two-party pilot reaches WITNESSED if a third party
that both trust runs a witness: an auditor, a customer, a university lab,
or a transparency-log operator.

Run it on one machine first (two seconds, no network beyond localhost):

```sh
cargo install witness-log-cli        # or a release binary on PATH
python3 examples/pilot-triangle/run.py
```

It prints every command it runs; the steps below are the same commands on
three real machines.

## 1. Each organisation runs one witness

Any always-on machine with a persistent disk and an inbound HTTPS port: a
free Google Cloud e2-micro, a Hetzner CX23, a VM you already have. Pick
one path from [Operator onboarding](Operator-Onboarding):

- **one click** (no VM): the Render button or the Fly.io commands
  under [Deploy in one click](Operator-Onboarding#deploy-in-one-click);
  a paid instance with a persistent disk on your own account.
- **cloud-init** (no terminal): paste `deploy/witness/cloud-init.yaml`
  into the VM's user-data box with `ORG` set to your organisation's name;
  three to five minutes later `https://<ip>.sslip.io/health` answers.
- **a coding agent**: hand it `deploy/witness/AGENT_OPERATOR.md`.
- **by hand** (two minutes):

```sh
witness-log witness init ./witness --name witness.alpha.example/w1 \
  --org "Alpha Payments" --url https://witness.alpha.example --json
witness-log witness serve ./witness --listen 127.0.0.1:7380 --open-enrollment
# put TLS in front (Caddy, nginx, a load balancer)
```

`init --json` prints the witness's `vkey` and directory entry. `--org` is
the organisation that controls the machine and the key: one name per
organisation, spelled the same everywhere. Back up `witness.key`,
`witness.json` and `logs/` together ([why](Operator-Onboarding#what-you-promise)).

## 2. Exchange directory entries once

Each organisation sends the others three values: its witness's `vkey`,
its organisation name, its URL. Everyone builds the same file:

```sh
witness-log directory add pilot-directory.json --vkey 'witness.alpha.example/w1+…' \
  --org "Alpha Payments" --url https://witness.alpha.example
witness-log directory add pilot-directory.json --vkey 'witness.bravo.example/w1+…' \
  --org "Bravo Logistics" --url https://witness.bravo.example
witness-log directory add pilot-directory.json --vkey 'witness.charlie.example/w1+…' \
  --org "Charlie Audit" --url https://witness.charlie.example
```

This file is each verifier's own: nobody should take it from a dossier or
from the party being verified. Comparing its SHA-256 over a call is enough
to know all three hold the same one.

## 3. Agents submit to all three

```sh
witness-log witness submit agent.jsonl --directory pilot-directory.json --out dossier.json --min 3
```

or from Python, `log.submit("pilot-directory.json", min=3)`, or in the
background with `witness_log.Witnesser`. Each witness keeps the last head
it cosigned for each agent and refuses (HTTP 422, with a proof file) any
history that contradicts it.

## 4. Verify each other, naming the log's operator

```sh
witness-log verify dossier.json \
  --identity <the agent's key, obtained from its operator> \
  --directory pilot-directory.json \
  --subject-org "Alpha Payments"
```

`--subject-org` is the organisation that operates the log you are
checking. Its witness is then counted as a receipt but not as an
independent operator. Without it, a verifier cannot tell that Alpha's
witness belongs to the same organisation as Alpha's agent and would count
it as independent; always pass it. The same option exists in every
verifier: `subject_org` in Python's `verify_dossier_json`, `subjectOrg`
in the TypeScript and Node verifiers, `SubjectOrg` in Go, `subject_org`
in the wasm options.

Expected: exit 0, WITNESSED, `distinct_independent_operators: 2`.

## 5. Go public

After seven days of uptime, register each witness in the public
[registry](https://github.com/0xAndersen/witness-log/tree/main/registry):
open a pull request adding `registry/witnesses/<org>-<name>.json` (the
`entry` object `init --json` printed), or ask the maintainers to run the
*register-witness* workflow against your URL. The first two outside
organisations are listed as founding operators in
[GOVERNANCE.md](https://github.com/0xAndersen/witness-log/blob/main/GOVERNANCE.md#founding-operators),
and from then on anyone can reach WITNESSED against the public registry.

## What each party is promising

- the key never cosigns two histories of one log (the software enforces
  this while `logs/` survives; keep it with the key);
- `--org` is the true operator;
- nothing else: no uptime commitment, no on-call. A witness that is down
  does not cosign.

What a witness sees: for each checkpoint, the agent's origin
(`witness-log/<agent key>`), a tree size, a root hash and the hashes of a
consistency proof. Never a payload, a prompt, a tool argument or any
customer data.
