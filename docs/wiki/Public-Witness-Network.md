# Public witness network

WITNESSED needs cosignatures from at least two independent operators.
witness-log's own registry is small. The public witness network
([witness-network.org](https://witness-network.org)) already has
independent operators running C2SP witnesses, and they cosign any log on
the lists they configure. A witness-log log is an ordinary C2SP checkpoint
log, so it can join those lists like any other. This page shows how, and
what CI checks to back it.

Facts about the network below were read from
[transparency-dev/witness-network](https://github.com/transparency-dev/witness-network)
on 2026-10-25. It describes itself as a work in progress; check the site
before you rely on a detail.

## How the network works

- **Log lists.** The maintainers publish lists of logs in the `logs/v0`
  format: each log's vkey, its add-checkpoint rate (`qpd`, requests per
  day) and a contact. There is a `testing` list and two `staging` lists.
  There is no `production` list yet.
- **Witnesses poll the lists.** Each witness operator picks the lists
  their witness can handle and configures every new log on them
  automatically. transparency-dev's `omniwitness` does this with
  `--public_witness_config_url`. Operators poll at least weekly, and
  removing a log from a list never removes it from a witness.
- **Logs ask by email.** The request goes to
  `participate (at) lists.witness-network.org` and gives the origin line,
  the Ed25519 vkey, the add-checkpoint rate, the list, and a contact.

The site's witness tables list:

- **Testing list:** Elias Rudberg, Florian Larysch, IPng Networks,
  Markovian Protocol, rgdd and TrustFabric.
- **Staging lists:** GDB Security, Geomys, IPng Networks, Markovian
  Protocol, Mullvad VPN and TrustFabric.

None of them is run by this project.

## Which log to enroll

| | A fleet log (`--fleet`) | An agent's own log (`--identity`) |
|---|---|---|
| Requests | One per organisation, whatever the number of agents | One per agent |
| What a witness commits to | The fleet log's head | That agent's head |
| Verdict | WITNESSED via the fleet anchor. `verify` exits 11 (split view possible) unless `--allow-sub-majority` ([why](Fleet-Log#what-it-proves-less-well-than-direct-witnessing)) | WITNESSED with direct receipts. Exit 0 once a strict majority of your directory cosigned |
| Status | EXPERIMENTAL ([RFC-0001](https://github.com/0xAndersen/witness-log/blob/main/docs/rfcs/RFC-0001-fleet-checkpoint-log.md)) | Specification |

The fleet log is the unit a public witness can reasonably admit for an
organisation. An agent's own log is the stronger evidence, so it is worth
a request for a few high-value agents. A list may name both.

## Step by step

### 1. Describe the log

```sh
# A fleet log (one per organisation):
witness-log fleet init fleet --origin acme.example/witness-log/fleet --org "Acme Corp"
# ...or an agent's own log: its identity is in `witness-log log info agent.wlog`.

witness-log witness-network request --fleet fleet --every 300 \
  --contact "ops (at) acme.example" --list testing > request.txt
```

`request` prints the email: origin line, vkey, rate, list, contact, a line
on what the log is, and the `logs/v0` entry the maintainers would add.
Read it and send it yourself; nothing is sent from the CLI.

- **Rate.** `--every SECS` is how often the log asks each witness to
  cosign: for a fleet log, the `--witness-every` you will give `fleet
  serve`. It becomes `qpd = ceil(86400 / SECS)`. Use `--qpd N` to state the
  rate directly. A witness may rate-limit or drop a log that asks more
  often than it declared; witness-log reports such a refusal as
  `HTTP 429: rate limited`. A log with a small load is easier to approve,
  so the network's guidelines suggest asking rarely.
- **Name.** The origin is the vkey's key name, as the guidelines
  recommend. A fleet origin is a schema-less URL under a domain you
  control. An agent origin is `witness-log/` followed by its public key in
  hex, so it cannot collide with another log.

### 2. Try it against your own omniwitness first

`log-list` prints the same entries as a complete list, which is what an
omniwitness polls:

```sh
witness-log witness-network log-list --fleet fleet --every 300 \
  --contact "ops (at) acme.example" > www/log-list.1
python3 -m http.server 8000 --directory www &
go install github.com/transparency-dev/witness/cmd/omniwitness@<commit>
go install github.com/transparency-dev/witness/cmd/generate_keys@<commit>
generate_keys --origin witness.acme.example --out_priv w.sec --out_pub w.vkey
omniwitness --private_key_path w.sec --db_file w.db --listen 127.0.0.1:8080 \
  --metrics_listen "" --public_witness_config_url http://127.0.0.1:8000/log-list.1
```

[`tests/interop/omniwitness.sh`](https://github.com/0xAndersen/witness-log/blob/main/tests/interop/omniwitness.sh)
is this setup, end to end. CI runs it with two omniwitnesses built from a
pinned commit, on every change to the Rust crates and weekly
(`.github/workflows/interop.yml`). It checks that:

- an agent log on the list reaches WITNESSED, and again after it grows
  (consistency proofs);
- the cosignatures verify as C2SP `cosignature/v1` lines with `c2sp
  verify`;
- a rewritten history under the same key is refused (`submit` exits 20);
- a fleet log on the list anchors an agent that is not on it (`verify
  --accept-fleet-anchor` exits 11, and 0 with `--allow-sub-majority`);
- the unlisted agent's own submission gets the 404 that explains
  enrollment.

### 3. Once a list carries your log, build your directory

Each witness's about page (linked from the network's witness tables)
gives its vkey (key type 0x04, `cosignature/v1`) and its add-checkpoint
URL. Add each witness you choose to trust:

```sh
witness-log directory add trusted.json --vkey '<its vkey>' \
  --org "<its operator>" --url https://witness.example/add-checkpoint
```

`directory add` takes the full add-checkpoint URL and stores the base
URL; witness-log appends `/add-checkpoint` itself.

- **Your directory, your judgment.** The `--org` label is what WITNESSED
  counts: two operators, not two keys. Give two witnesses one label when
  you consider them one operator, for example two companies with one
  owner.
- **Don't register them for them.** Never list these witnesses in
  witness-log's `registry/`: an operator registers its own witness
  ([Running a witness](Running-a-Witness)).

### 4. Run it

```sh
witness-log fleet serve fleet --directory trusted.json --witness-every 300   # the rate you declared
witness-log submit agent.wlog --fleet http://127.0.0.1:7480 --fleet-wait 600 --out dossier.json
witness-log verify dossier.json --identity <agent hex> --directory trusted.json \
  --accept-fleet-anchor --subject-org "Acme Corp"
```

For an agent's own log, `submit agent.wlog --directory trusted.json` as
usual. Before the witnesses have read the list, each answers 404, and
`submit` says the witness has not enrolled the log.

## What this does not change

- A public witness cosigns heads. It never sees your log's entries,
  payloads or salts, as with any witness.
- Verifiers still decide whom to trust. A dossier cosigned by the
  network's witnesses is WITNESSED only for a verifier whose directory
  lists them under two or more independent operators.
- The testing list's witnesses are "just trying things out". Expect them
  to come and go, and keep more than the minimum in your directory.
