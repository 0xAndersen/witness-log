# Tutorial: audit a payments agent end to end

A complete, realistic walkthrough: an agent that moves money gets a
tamper-evident, erasable, independently witnessed audit trail, and a
compliance reviewer verifies it on a different machine with nothing but a
file. Along the way you will see every verdict, including the one an
attacker gets.

Time: about 20 minutes. Needs Python ≥3.9 with `witness-log`, the
`witness-log` CLI, and two terminals.

## The scenario

`payments_agent.py` receives instructions, looks up a customer, decides
whether to pay, and calls a payment API. Three parties care about its log:

- **Engineering** wants to know what the agent *decided* and what *happened*, separately, when a payment goes wrong.
- **Compliance** must prove to a regulator that the record has not been edited since the event, and must be able to erase a customer's personal data on request without destroying that proof.
- **The counterparty** (a bank, a partner) wants to verify the claim without trusting your infrastructure or your word.

## Step 1: instrument the agent

witness-log commits to events; it does not store their content. So the
agent keeps its own event store (here a plain JSONL file, in production
your database or trace backend) and the log holds the salted hash of each
entry. This split is the point: the proof is tiny and leaks nothing, and
the content stays under your own retention and access rules.

<!-- doctest: group=tutorial file=payments_agent.py -->
```python
# payments_agent.py
import witness_log, json, sys

log = witness_log.open("payments.jsonl")          # commitments: one journal per agent identity
EVENTS = "payments.events.jsonl"                  # content: YOUR store, keyed by leaf index
print("agent identity:", log.identity_pubkey_hex())

def record(kind: str, **fields) -> int:
    payload = witness_log.canonical_json(fields)  # deterministic bytes: same dict -> same hash
    idx = (log.append_intent if kind == "intent" else
           log.append_result if kind == "result" else log.append_memory)(payload)
    with open(EVENTS, "a") as f:                  # store content next to its index
        f.write(json.dumps({"index": idx, "kind": kind, **fields}) + "\n")
    log.sync()                                    # fsync: this is money
    return idx

def lookup_customer(customer_id: str) -> dict:
    record("intent", tool="lookup_customer", customer_id=customer_id)
    c = {"customer_id": customer_id, "email": f"{customer_id}@example.com", "kyc": "passed"}
    record("result", tool="lookup_customer", **c)
    return c

def authorize_payment(customer_id: str, amount_usd: int) -> bool:
    record("intent", tool="authorize_payment", customer_id=customer_id, amount_usd=amount_usd, policy="limit-10k")
    ok = amount_usd <= 10_000
    record("result", tool="authorize_payment", decision="approve" if ok else "decline")
    return ok

def send_payment(customer_id: str, amount_usd: int) -> dict:
    record("intent", tool="send_payment", customer_id=customer_id, amount_usd=amount_usd)
    r = {"status": "ok", "tx_id": "tx_7ac31", "amount_usd": amount_usd}
    record("result", tool="send_payment", **r)
    return r

def run(customer_id: str, amount: int):
    lookup_customer(customer_id)
    if authorize_payment(customer_id, amount):
        send_payment(customer_id, amount)
    else:
        record("memory", note="declined", reason="over single-payment limit")

if __name__ == "__main__":
    run("cust_42", int(sys.argv[1]) if len(sys.argv) > 1 else 250)
    print("tree size:", log.tree_size(), "root:", log.root_hex())
```

<!-- doctest: group=tutorial -->
```sh
python payments_agent.py 250        # approved path
python payments_agent.py 50000      # declined path, same journal, new session
```

(The `@witness_log.step` decorator does the intent/result pair for you in
one line; it is written out here so you can see each append.)

**What you have.** One journal, two sessions (the second run *resumed* the
first run's identity and wrote a new key binding), and for each tool call an
intent leaf before and a result leaf after. The declined run shows why two
leaves matter: the intent `authorize_payment(50000)` is on the record, the
result is `decline`, and no `send_payment` intent exists. "The agent never
tried to send that" is now a provable statement, not a log search that
found nothing.

`log.sync()` per event costs an `fsync`. For a payments agent that is the
right trade; for a chat agent sync at checkpoints instead.

## Step 2: look at what was recorded

<!-- doctest: group=tutorial -->
```python
import witness_log, json
log = witness_log.open("payments.jsonl")
events = {e["index"]: e for e in map(json.loads, open("payments.events.jsonl"))}
for leaf in json.loads(log.leaves_json()):
    e = events.get(leaf["index"], {})
    print(leaf["index"], hex(leaf["leaf_type"]), leaf["payload_hash"][:16], e.get("tool", e.get("note", "")))
log.close()                                           # one handle per journal: step 3 opens it again
```

Notice: the journal has only hashes and metadata; your event store has the
content; the two runs used two different `session_pubkey` values under one
identity. To prove a stored event matches its leaf, recompute
`SHA256(bucket_pad(canonical_json(event)) || salt || index)` with the salt
from `payments.jsonl.salts`; `verify_inclusion` then places that hash in
the witnessed root.

## Step 3: a customer asks to be forgotten

`cust_42`'s email address is in the `lookup_customer` result. Erase it from
both places:

<!-- doctest: group=tutorial -->
```python
import witness_log, json
log = witness_log.open("payments.jsonl")
events = [json.loads(l) for l in open("payments.events.jsonl")]
targets = [e["index"] for e in events if e.get("email", "").endswith("@example.com")]
root_before = log.root_hex()
for i in targets:
    assert log.can_forget(i)
    log.forget(i)                                      # salt erased; Redaction leaf appended
log.sync()
with open("payments.events.jsonl", "w") as f:          # and delete the content from YOUR store
    for e in events:
        if e["index"] not in targets:
            f.write(json.dumps(e) + "\n")
print("erased", targets, "| root changed:", root_before != log.root_hex())
log.close()
```

What happened, and what did not: the salts for those leaves were deleted
from `payments.jsonl.salts` and one Redaction leaf per erasure was appended.
Their `payload_hash` values are unchanged, so every proof and every witness
cosignature that covered them remains valid. The root changed because
leaves were *added*. Even if a copy of the deleted event surfaced later,
nobody could tie it to the hash without the salt. Compliance can show the
regulator the Redaction leaves: this entry was erased, on this date, and
nothing else was touched. ([Redaction explained](Redaction-Explained))

## Step 4: get the history witnessed

Start two witnesses, standing in for two organisations, in a second terminal:

<!-- doctest: group=tutorial timeout=30 -->
```sh
witness-log witness init ./wA --name local/a --org "Org A" --url http://127.0.0.1:7381
witness-log witness init ./wB --name local/b --org "Org B" --url http://127.0.0.1:7382
witness-log witness serve ./wA --listen 127.0.0.1:7381 --open-enrollment &
witness-log witness serve ./wB --listen 127.0.0.1:7382 --open-enrollment &
until witness-log witness info http://127.0.0.1:7381 >/dev/null 2>&1 &&
      witness-log witness info http://127.0.0.1:7382 >/dev/null 2>&1; do sleep 0.2; done   # until both answer
```

Build the directory **you** trust from their entries, then submit:

<!-- doctest: group=tutorial -->
```sh
python3 - <<'EOF'
import json, urllib.request
entries = [json.load(urllib.request.urlopen(u))["directory_entry"] for u in
           ("http://127.0.0.1:7381/", "http://127.0.0.1:7382/")]
json.dump({"witnesses": entries}, open("trusted.json", "w"), indent=1)
EOF
witness-log witness submit payments.jsonl --directory trusted.json --out dossier.json
```

`submit` signed a checkpoint over the current head, sent it to each
witness (first contact: `old 0`, empty proof), collected two cosignatures,
and wrote `dossier.json`. It also wrote `payments.jsonl.witnesses.json`
recording that each witness has cosigned this size. Run the agent again and
`submit` again: this time it sends `old <previous size>` with a consistency
proof, and the witnesses verify that nothing before was rewritten.

In production, the two organisations are real and not yours:
[Getting witnessed](Getting-Witnessed).

## Step 5: compliance verifies, on another machine

Copy `dossier.json` and `trusted.json` to a laptop with no network and the
`witness-log` binary. Compliance also has, from your configuration
management (not from the dossier), the agent's identity key: the
`agent identity:` that step 1 printed. On the laptop, put it in a variable
(`AGENT_ID=` followed by those 64 hex characters) and verify:

<!-- doctest: group=tutorial before="AGENT_ID=$(witness-log log info payments.jsonl | jq -r .identity)" -->
```sh
witness-log verify dossier.json --identity "$AGENT_ID" --directory trusted.json --min-witnesses 2
echo "exit $?"
```

```
✓ Checkpoint signature valid
✓ Identity bound to --identity f7809c16...0506b3be
✓ Leaf structure valid
✓ Key bindings valid (5 bindings, 0 revocations)
✓ Merkle continuity verified (13 leaves)
✓ 2/2 witness signatures valid (gate: at least 2 witnesses)
✓ Independent operators: 2 cosigned (org a, org b); 2 of 2 known operators represented (100%)
...
Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint
...
exit 0
```

Thirteen leaves: eleven from the two runs and the two Redaction leaves of
step 3.

Read `--explain` once to see what each line does and does not prove. The
precise claim is: this record, including the erasures, has not changed since
Org A and Org B saw it, and it belongs to the identity compliance expected.

Now see the other verdicts with the same file. With nothing from outside
the file:

<!-- doctest: group=tutorial exit=20 -->
```sh
witness-log verify dossier.json; echo $?          # 20 UNANCHORED: no directory, nothing external checked
```

Pinned to an identity that is not the agent's (64 zeros):

<!-- doctest: group=tutorial exit=40 -->
```sh
witness-log verify dossier.json --identity "$(printf '%064d' 0)" --directory trusted.json; echo $?   # 40 INVALID
```

## Step 6: the counterparty tries to catch you cheating

Suppose the counterparty suspects a leaf was edited after the fact. Flip
one character of a `payload_hash` in `dossier.json` and verify:

<!-- doctest: group=tutorial exit=40 -->
```sh
python3 -c "
import json; d=json.load(open('dossier.json')); h=d['leaves'][3]['payload_hash']
d['leaves'][3]['payload_hash']=('0' if h[0]!='0' else '1')+h[1:]; json.dump(d,open('edited.json','w'))"
witness-log verify edited.json --identity "$AGENT_ID" --directory trusted.json; echo $?
# ✗ Merkle continuity ... Verdict: INVALID, exit 40
```

Suppose instead *you* try to rewrite history: restore `payments.jsonl` from
a backup one leaf short of what was witnessed, append a different result in
its place, and `submit`. The local guard refuses (the cache says the
witnesses already cosigned a head this journal does not extend). Force it
by deleting `payments.jsonl.witnesses.json` and the witness answers `422`
and writes `wA/evidence/<hash>.json`: two checkpoints signed by *your* key
for one size with two roots. Anyone can check it:

<!-- doctest: group=tutorial before="sed '$d' payments.jsonl > backup.jsonl; cat backup.jsonl > payments.jsonl; witness-log log append payments.jsonl --result forged; rc=0; witness-log submit payments.jsonl --directory trusted.json --out forged.json 2> guard.txt || rc=$?; cat guard.txt; test $rc = 1; grep -q 'REFUSING TO SUBMIT' guard.txt; rm payments.jsonl.witnesses.json; rc=0; witness-log submit payments.jsonl --directory trusted.json --out forged.json || rc=$?; test $rc = 20" -->
```sh
witness-log witness verify-evidence wA/evidence/*.json   # exit 0: equivocation proven
```

That file is the counterparty's proof. There is no "it was a sync glitch"
story that survives it; this is why the guard exists and why backups must
include the sidecar and the cache.

## Step 7: hand a regulator only what they asked for

A regulator wants 09:00–09:05 on one day, not the whole log. In Rust or
via the Python `inclusion_proof(index)`, produce leaves in that range each
with an inclusion proof against the witnessed checkpoint; the regulator
verifies with the identity public key and the receipts, and learns nothing
outside the window. (`evidence_window` in the Rust API; a CLI subcommand is
on the [Roadmap](Roadmap).)

## What to keep from this tutorial

- Intent before result makes "never tried" provable.
- Erasure is a first-class operation that leaves proofs intact and a marker behind.
- The verifier's two inputs (expected identity, trusted directory) are where trust enters; the dossier only carries claims.
- Equivocation is not an argument, it is a file.

Variations: wrap the agent with the [MCP server](MCP-Integration) instead of
the decorator; plug into a framework via [Framework guides](Framework-Guides);
gate a deploy on exit code 0 in CI ([Quickstart: CLI](Quickstart-CLI)).
