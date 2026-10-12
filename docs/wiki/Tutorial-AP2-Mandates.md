# Tutorial: record what was done under an AP2 mandate

A mandate proves that a principal **authorised** a payment. It does not
prove what either agent later **did** under it, and neither side's own log
of that is worth much to the other if its operator can rewrite it. This
tutorial records one AP2-style mandate on both sides of a payment, records
what each agent did and the settlement, gets both logs witnessed, and
proves with two commands that the two parties committed to the same
mandate and that neither history has moved. It then does the auditor's
part in Python and writes a dispute bundle.

The recording uses the commerce profile helpers in
`witness_log.profiles.ap2` (`mandate_hash`, `record_grant`,
`record_receipt`, `bind_profile_ap2`, `dispute_export`); the
`witness_log.profiles.x402` and `witness_log.profiles.vi` modules map the
x402 and Verifiable Intent shapes onto the same four calls.

Time: 10 minutes. Needs `pip install witness-log` and
`cargo install witness-log-cli` (v0.3.6). Everything runs on localhost.
The output below is real, from a v0.3.6 checkout; hashes and keys differ on
your run.

## What the mandates actually contain

So that the claims below are precise, here is what the three common shapes
carry (sources at the bottom; checked 2026-10-12).

- **AP2** (Agent Payments Protocol, A2A extension v0.1): an
  **IntentMandate** (natural-language description, merchants, SKUs,
  refundability, expiry, whether the user must confirm the cart; the
  published example carries no signature); a **CartMandate** (the
  merchant's `payment_request`: line items, total, shipping, plus
  `merchant_signature` and timestamp); a **PaymentMandate**
  (`payment_mandate_contents`: mandate ID, the cart's `payment_details_id`,
  total, the payer's `payment_response`, merchant agent, timestamp; plus
  `user_authorization`, a JWS-style token in the example).
- **x402** (v2 specification): a `402 Payment Required` response lists
  `PaymentRequirements` (`scheme`, `network` in CAIP-2 form, `amount` in
  atomic units, `asset`, `payTo`, `maxTimeoutSeconds`, `extra`); the client
  answers with a `PaymentPayload` naming the requirement it `accepted` plus
  a scheme-specific signed `payload` (for `exact` on EVM, an EIP-712
  signature over an EIP-3009 authorization).
- **Mastercard Verifiable Intent** (announced 5 March 2026): a credential
  linking the consumer's identity, their instructions and the transaction
  outcome, with selective disclosure, designed to work with AP2. Its public
  description does not list fields; treat it like the others below: an
  opaque, signed object both sides can hash.

What all three have in common, for our purposes: a byte string both parties
hold and can hash. That hash is the `scope` of an `AuthorizationEvent`.

## What witness-log adds, and what it does not

Adds: an **unrewritable record of what was done under the mandate**, on
both sides. Each party's log commits to the mandate's hash, in a stated
role (`granted_by_me` / `granted_to_me`), naming the counterparty's
identity, followed by its own intent and result leaves and, on the side
that settles, an `ExternalAnchor` carrying the settlement record;
independent witnesses cosign each head, so neither operator can later
present a different history; `witness-log bind` proves the two sides
committed to the same mandate bytes between the same two identities.

Does not: **validate the mandate.** witness-log never checks
`user_authorization`, `merchant_signature`, an EIP-712 signature or a
Verifiable Intent credential, never evaluates scope or amounts, and never
blocks a payment. Verify the mandate with its own protocol's tooling. A
witnessed log of a payment made under a forged mandate is a faithful record
of a payment made under a forged mandate.

## Step 1: two witnesses run by two organisations

In production these are other organisations' witnesses (see
[Getting witnessed](Getting-Witnessed)). Here, two local processes with
different `operator_org` values:

```sh
witness-log witness init wa --name wa.example/w --org "Example Org A" --url http://127.0.0.1:7481 > /dev/null
witness-log witness init wb --name wb.example/w --org "Example Org B" --url http://127.0.0.1:7482 > /dev/null
witness-log witness serve wa --listen 127.0.0.1:7481 --open-enrollment > wa.log 2>&1 &
witness-log witness serve wb --listen 127.0.0.1:7482 --open-enrollment > wb.log 2>&1 &

python3 -c '
import json
w = [json.load(open(d + "/witness.json")) for d in ("wa", "wb")]
json.dump({"witnesses": [{"name": e["key_name"], "operator_org": e["operator_org"],
           "url": e["public_url"], "pubkey": e["pubkey_hex"]} for e in w]}, open("trusted.json", "w"), indent=2)'
```

`trusted.json` is the verifier's own directory. In real use the verifier
builds it, not the parties being verified.

## Step 2: both agents record the mandate, what they did, and the settlement

`ap2_mandate_demo.py`:

```python
# ap2_mandate_demo.py: two agents record the same AP2 mandate, what each did under it,
# and the settlement, with the commerce profile helpers.
import json
import witness_log as wl
from witness_log.profiles import ap2

# 1. The mandate both parties hold. Shape: an AP2 v0.1 PaymentMandate (A2A extension
#    example). Signature values are placeholders; witness-log never checks them.
payment_mandate = {
    "payment_mandate_contents": {
        "payment_mandate_id": "pm_example_0001",
        "payment_details_id": "order_example_0001",          # the CartMandate's payment_request.details.id
        "payment_details_total": {
            "label": "Total",
            "amount": {"currency": "USD", "value": 120.0},
            "pending": None,
            "refund_period": 30,
        },
        "payment_response": {"request_id": "order_example_0001", "method_name": "CARD",
                             "details": {"token": "tok_example"}},
        "merchant_agent": "merchant_agent_example",
        "timestamp": "2026-10-12T09:00:00Z",
    },
    "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJleGFtcGxlIn0.placeholder.placeholder",
}
mandate_sha256 = ap2.mandate_hash(payment_mandate)       # SHA-256 of the RFC 8785 (JCS) bytes

# 2. Two agents, two journals, two identities (exchanged out of band; they are public keys).
shopper = wl.open("shopper.jsonl")
merchant = wl.open("merchant.jsonl")
S, M = shopper.identity_pubkey_hex(), merchant.identity_pubkey_hex()

# 3. The shopper's agent: records the grant under the mandate, then what it did.
ap2.record_grant(shopper, payment_mandate, counterparty=M, scope="granted_by_me")
shopper.append_intent(wl.canonical_json({"tool": "submit_payment", "mandate_sha256": mandate_sha256,
                                         "amount": {"currency": "USD", "value": 120.0}}))
shopper.append_result(wl.canonical_json({"status": "authorized", "processor_ref": "auth_example_77"}))

# 4. The merchant's agent: records receiving the same grant, what it did, and the settlement
#    it got back from the processor, anchored to the mandate.
ap2.record_grant(merchant, payment_mandate, counterparty=S, scope="granted_to_me")
merchant.append_intent(wl.canonical_json({"tool": "capture_payment", "mandate_sha256": mandate_sha256,
                                          "amount": {"currency": "USD", "value": 120.0}}))
merchant.append_result(wl.canonical_json({"status": "captured", "processor_ref": "auth_example_77"}))
ap2.record_receipt(merchant,
                   {"status": "captured", "processor_ref": "auth_example_77",
                    "amount": {"currency": "USD", "value": 120.0}},
                   chain_id="offchain:card",                               # a card rail; a chain would be CAIP-2, e.g. eip155:8453
                   tx_ref="auth_example_77",
                   anchor_url="https://processor.example/receipts/auth_example_77",   # where the receipt can be re-fetched
                   mandate=payment_mandate)                                # ties the receipt to this mandate

for log in (shopper, merchant):
    log.sync()
json.dump({"shopper": S, "merchant": M, "mandate_sha256": mandate_sha256}, open("ids.json", "w"), indent=2)
json.dump(payment_mandate, open("payment_mandate.json", "w"), indent=2)   # what the auditor is handed
print(f"shopper  {S}\nmerchant {M}\nmandate sha256 {mandate_sha256}")

# 5. For the mismatch demo below: a copy of the merchant's identity claiming a $1,200 mandate.
#    (Never submitted to witnesses; it only exists to show what `bind` does with it.)
wider = json.loads(json.dumps(payment_mandate))
wider["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 1200.0
claim = wl.JournaledLog.create("merchant-claim.jsonl", merchant.identity_bytes())
ap2.record_grant(claim, wider, counterparty=S, scope="granted_to_me")
claim.sync()
open("merchant-claim.json", "w").write(claim.to_dossier_json())
for log in (shopper, merchant, claim):
    log.close()
```

```console
$ python3 ap2_mandate_demo.py
shopper  a9aa05d4c72d07b3f2a8b5774f11afb12f9714ee5d45b0fe5d4053264db7c732
merchant c30d7e033708259fa64922ad8cd86f0c378ca463a539c0d648a9dd91e35c324b
mandate sha256 29691ea6e27252e224a75fb8633015c5dcd25df43dc8b72230a31f74d067f926
```

Four things worth noticing:

- **Which bytes.** `authorization_scope_hash` is `SHA-256(scope)`,
  deliberately unsalted so two independently salted logs can be compared.
  Both sides must hash *identical* bytes. `mandate_hash` and
  `record_grant` hash the mandate's RFC 8785 (JCS) canonical form, so a
  counterparty written in another language reproduces the hash from the
  same JSON object regardless of key order, whitespace or how its JSON
  library prints `120.0`. Hand `record_grant` the raw `bytes` instead to
  hash exactly what crossed the wire.
- **Which mandate.** Use the object that authorised *this* payment: the
  PaymentMandate in AP2 (it names the cart by `payment_details_id`), the
  accepted `PaymentRequirements` plus `PaymentPayload` in x402
  (`witness_log.profiles.x402.mandate(requirements, payload)`), the
  credential in Verifiable Intent. Recording the IntentMandate as a
  separate, earlier `AuthorizationEvent` is reasonable too.
- **The hash is the content identifier, not a secret.** Because it is
  unsalted, anyone holding the mandate can confirm a leaf refers to it, and
  `forget()` does not remove it. If the mandate is low-entropy and
  sensitive, pass `salted=True, nonce=<random string both sides hold>` to
  `record_grant`; the leaf then commits to `{"mandate_sha256", "nonce"}`
  and only someone holding the nonce can tie it to the mandate.
- **The receipt is an anchor, not a result.** `record_receipt` writes an
  `ExternalAnchor` leaf (SPEC §3.3) whose proof JSON is the settlement
  record plus the rail (`chain_id` in CAIP-2 form, `offchain:card` here),
  the transaction reference and the mandate's hash; the leaf commits to
  `SHA-256` of that exact JSON text, so a swapped receipt is detected by
  every verifier. `anchor_url` is where an auditor can re-fetch the
  settlement; it has to be `http(s)` and is not fetched by witness-log.

## Step 3: get both heads witnessed

```console
$ witness-log witness submit shopper.jsonl  --directory trusted.json --out shopper.json
  ✓ wa.example/w                     cosigned size 3
  ✓ wb.example/w                     cosigned size 3
2/2 witnesses cosigned size 3 for witness-log/a9aa05d4c72d07b3f2a8b5774f11afb12f9714ee5d45b0fe5d4053264db7c732
wrote shopper.json. Verify with:
  witness-log verify shopper.json --identity a9aa05d4c72d07b3f2a8b5774f11afb12f9714ee5d45b0fe5d4053264db7c732 --directory <directory YOU trust>
$ witness-log witness submit merchant.jsonl --directory trusted.json --out merchant.json
  ✓ wa.example/w                     cosigned size 4
  ✓ wb.example/w                     cosigned size 4
2/2 witnesses cosigned size 4 for witness-log/c30d7e033708259fa64922ad8cd86f0c378ca463a539c0d648a9dd91e35c324b
wrote merchant.json. Verify with:
  witness-log verify merchant.json --identity c30d7e033708259fa64922ad8cd86f0c378ca463a539c0d648a9dd91e35c324b --directory <directory YOU trust>
```

The witnesses do not know the two logs are related and do not need to.
The merchant's head is one leaf longer: the settlement anchor.

## Step 4: bind the two sides

```console
$ witness-log bind shopper.json merchant.json; echo "exit $?"
witness-log bind
  A: a9aa05d4c72d07b3f2a8b5774f11afb12f9714ee5d45b0fe5d4053264db7c732
  B: c30d7e033708259fa64922ad8cd86f0c378ca463a539c0d648a9dd91e35c324b

✓ authorization bound: a9aa05d4...4db7c732#0 granted_by_me ↔ c30d7e03...e35c324b#0 granted_to_me  scope 29691ea6...d067f926

Result: BOUND — both parties committed, in their own logs, to the same content between the same two identities (1 binding(s)).

This checks the two logs against each other only. Run `witness-log verify` on each dossier first; a binding between two unverified logs proves nothing.
exit 0
```

`bind` exits 0 when bound, 30 on a mismatch, 10 when there is nothing to
bind. The scope shown is the mandate hash the script printed. Step 8 does
the same in Python with the AP2 checks on top.

## Step 5: verify each history, pinned to the identity you expect

```console
$ SHOPPER=$(python3 -c 'import json; print(json.load(open("ids.json"))["shopper"])')
$ MERCHANT=$(python3 -c 'import json; print(json.load(open("ids.json"))["merchant"])')
$ witness-log verify shopper.json --identity "$SHOPPER" --directory trusted.json; echo "exit $?"
WitnessLog dossier verification
  identity: a9aa05d4...4db7c732
  claimed tree size: 3

✓ Checkpoint signature valid
✓ Identity bound to --identity a9aa05d4...4db7c732
✓ Leaf structure valid
✓ Key bindings valid (2 bindings, 0 revocations)
✓ Merkle continuity verified (3 leaves)
✓ 2/2 witness signatures valid (gate: 66% of the directory)
✓ Independent operators: 2 cosigned (example org a, example org b); 2 of 2 known operators represented (100%)
✓ Compute-provider diversity: 1 of 1 known providers represented (100%)

Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint

Run with --explain for what each check does and doesn't prove, or see THREAT_MODEL.md
exit 0
```

The merchant's dossier gives the same result with `--identity "$MERCHANT"`
(exit 0, WITNESSED, 4 leaves), plus one line about the anchor:

```console
ℹ External anchors: 1 recorded (proof hashes bound to the leaves; the anchors themselves are NOT fetched or verified against their providers by this tool)
```

In a real audit the identities come from somewhere the parties do not
control (a contract, a registry, a prior exchange), not from `ids.json`.

## Step 6: check the leaf really is this mandate

Anyone holding the mandate can confirm both leaves commit to it, and that
the receipt names it:

```console
$ python3 - <<'EOF'
import json
from witness_log.profiles import ap2
want = ap2.mandate_hash(json.load(open("payment_mandate.json")))
for name in ("shopper", "merchant"):
    leaves = json.load(open(f"{name}.json"))["leaves"]
    grant = next(l for l in leaves if l["leaf_type"] == 6)
    print(name, grant["authorization_event_kind"], grant["authorization_scope_hash"] == want)
    for a in (l for l in leaves if l["leaf_type"] == 7):
        print(name, "anchor", a["anchor_url"], json.loads(a["anchor_proof_json"])["mandate_sha256"] == want)
EOF
shopper GrantedByMe True
merchant GrantedToMe True
merchant anchor https://processor.example/receipts/auth_example_77 True
```

## Step 7: what a disagreement looks like

The script also wrote `merchant-claim.json`: the merchant's identity
claiming it was granted a mandate for $1,200 instead of $120.

```console
$ witness-log bind shopper.json merchant-claim.json; echo "exit $?"
witness-log bind
  A: a9aa05d4c72d07b3f2a8b5774f11afb12f9714ee5d45b0fe5d4053264db7c732
  B: c30d7e033708259fa64922ad8cd86f0c378ca463a539c0d648a9dd91e35c324b

✗ authorization NOT bound (leaf 0): b leaf 0: scope hashes do not match — the two sides committed to different scope descriptions

Result: MISMATCH — the two logs disagree about what was handed over or to whom. Neither copy is 'the wrong one'; the disagreement is the finding.

This checks the two logs against each other only. Run `witness-log verify` on each dossier first; a binding between two unverified logs proves nothing.
exit 30
```

Had the merchant actually tried to get that history cosigned after its
honest size-4 head was witnessed, the witnesses would have refused it with
`422` and kept a proof: see [`examples/rewrite-attack/`](https://github.com/0xAndersen/witness-log/tree/main/examples/rewrite-attack).

## Step 8: the auditor's side in Python, and a dispute bundle

`bind_profile_ap2` is `witness-log bind` in Python plus three AP2 checks:
the bound scope is this mandate's hash; neither side committed to a scope
the other did not (a unilateral `scope_changed_*` or a second grant on one
side alone fails `scope_not_widened`); the settlement anchors carry their
proof, the proof hashes to what the leaf committed, and it names this
mandate (`require_anchors="either"` by default; `"both"` when both sides
must have anchored). `dispute_export` then writes a directory a third party
can be handed whole.

`ap2_bind_and_export.py`:

```python
# ap2_bind_and_export.py: the auditor's side, in Python: bind the two witnessed dossiers
# with the AP2 checks, then write the merchant's dispute bundle.
import json
import witness_log as wl
from witness_log.profiles import ap2

payment_mandate = json.load(open("payment_mandate.json"))      # the auditor holds the mandate too
report = ap2.bind_profile_ap2("shopper.json", "merchant.json", mandate=payment_mandate)
print("exit", report["exit"], "bound", len(report["bound"]), "failed", len(report["failed"]))
print(json.dumps(report["ap2"], indent=2))

# A dispute bundle for the merchant's side: its dossier, the disclosed leaves (payload + salt
# for the two it recorded itself; the grant and the receipt need no payload), and the binding.
merchant = wl.open("merchant.jsonl")
payloads = {
    1: wl.canonical_json({"tool": "capture_payment", "mandate_sha256": ap2.mandate_hash(payment_mandate),
                          "amount": {"currency": "USD", "value": 120.0}}),
    2: wl.canonical_json({"status": "captured", "processor_ref": "auth_example_77"}),
}
manifest = ap2.dispute_export(merchant, [0, 1, 2, 3], "dispute/", journal_path="merchant.jsonl",
                              payloads=payloads, bindings=[report], dossier_json=open("merchant.json").read())
merchant.close()
for name, digest in manifest.items():
    print(f"{digest}  {name}")
print([ (d["index"], d["complete"], d["verified"]) for d in json.load(open("dispute/disclosures.json"))])
```

```console
$ python3 ap2_bind_and_export.py
exit 0 bound 1 failed 0
{
  "mandate_sha256": "29691ea6e27252e224a75fb8633015c5dcd25df43dc8b72230a31f74d067f926",
  "expected_scope_hash": "29691ea6e27252e224a75fb8633015c5dcd25df43dc8b72230a31f74d067f926",
  "mandate_hash_equal": true,
  "scope_not_widened": true,
  "scopes": {
    "a": ["29691ea6e27252e224a75fb8633015c5dcd25df43dc8b72230a31f74d067f926"],
    "b": ["29691ea6e27252e224a75fb8633015c5dcd25df43dc8b72230a31f74d067f926"]
  },
  "settlement_anchors": {
    "a": {"count": 0, "proof_carried": 0, "proof_hash_ok": 0, "mandate_match": 0, "indices": []},
    "b": {"count": 1, "proof_carried": 1, "proof_hash_ok": 1, "mandate_match": 1, "indices": [3]},
    "ok": true,
    "required": "either"
  },
  "ok": true
}
d79a5c89a162836f53a0ce9b00c28c07ef3eb9e0017b0031bdc20dbcb02c39c2  bindings.json
869071fa70914ab93a8cb6f0d2b77a1d9a3e05382183e45e7ff2de70dd2d8ae1  disclosures.json
7140aa136b0b7da121d1ce1e40efe83789c165b4ba2d72975db6ed3099674938  dossier.json
[(0, False, None), (1, True, True), (2, True, True), (3, False, None)]
```

(The report is printed with `indent=2`; it is compacted here.) The bundle
is `dispute/dossier.json` (the witnessed dossier), `disclosures.json` (one
record per leaf: the leaf itself and, where the payload and salt were
available, both of them with `verified: true` meaning they recompute the
leaf's `payload_hash`), `bindings.json` (the report above) and
`MANIFEST.sha256`. Leaves 1 and 2 are the merchant's own intent and result,
disclosed in full; leaf 0 (the grant) and leaf 3 (the receipt) carry their
commitments in the leaf itself and need no payload. Running
`bind_profile_ap2("shopper.json", "merchant-claim.json", mandate=...)`
instead gives `exit 30`, `mandate_hash_equal: false`,
`scope_not_widened: false`, `ok: false`.

A disclosure is checked without witness-log:
`sha256(len(payload) as 8-byte BE || payload || zero padding to a 256-byte
bucket || salt || index as 8-byte BE)` must equal `leaf.payload_hash`
(SPEC §8; `witness_log.profiles._disclose.check_disclosure` does it).

Stop the witnesses when done (`kill %1 %2`, or by PID).

## What an auditor can now say, and what not

Can say: two named identities, in histories independent organisations
cosigned, committed to the same mandate bytes in matching roles, and each
recorded what it then did (`submit_payment` → `authorized`;
`capture_payment` → `captured`); the merchant's history also commits to a
settlement record naming that mandate, and the merchant disclosed the
content of the two leaves it chose to. Neither history can be rewritten
without the witnesses refusing it.

Cannot say: that the mandate was validly signed by the user or merchant
(check that with AP2 / x402 / the card network's tooling), that the amounts
or tools logged are true (a witness is a notary of history, not of facts),
or that the payment settled (the anchor commits to what the processor
*returned*, fetched by nobody here; re-fetch it from `anchor_url` and
compare). And the usual limit: the public registry of witness operators is
empty today, so "independent organisations" means the ones *you* put in
`trusted.json`.

## Sources (checked 2026-10-12)

- AP2 A2A extension v0.1 (IntentMandate, CartMandate, PaymentMandate examples): <https://ap2-protocol.org/a2a-extension>; repository <https://github.com/google-agentic-commerce/AP2> (Apache-2.0)
- x402 specification v2 (`PaymentRequired`, `PaymentRequirements`, `PaymentPayload`): <https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md>
- Mastercard Verifiable Intent announcement coverage (5 March 2026): <https://www.pymnts.com/mastercard/2026/mastercard-unveils-open-standard-to-verify-ai-agent-transactions/>; developer documentation: <https://developer.mastercard.com/mastercard-agent-pay/documentation/verifiable-intent/>
- witness-log `AuthorizationEvent`: `spec/SPEC.md` §3.2; corpus vector `08_authorization_event.json`

Next: [Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff) · [Comparison](Comparison) · [Threat model](Threat-Model)
