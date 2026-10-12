# Tutorial: record what was done under an AP2 mandate

A mandate proves that a principal **authorised** a payment. It does not
prove what either agent later **did** under it, and neither side's own log
of that is worth much to the other if its operator can rewrite it. This
tutorial records one AP2-style mandate on both sides of a payment, records
what each agent did, gets both logs witnessed, and proves with two commands
that the two parties committed to the same mandate and that neither
history has moved.

Time: 10 minutes. Needs `pip install witness-log` and
`cargo install witness-log-cli` (v0.3.5). Everything runs on localhost.
The output below is real, from v0.3.5; hashes and keys differ on your run.

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
identity, followed by its own intent and result leaves; independent
witnesses cosign each head, so neither operator can later present a
different history; `witness-log bind` proves the two sides committed to the
same mandate bytes between the same two identities.

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

## Step 2: both agents record the mandate and what they did

`ap2_mandate_demo.py`:

```python
# ap2_mandate_demo.py: two agents record the same AP2 mandate and what each did under it.
import hashlib, json
import witness_log as wl

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
mandate_bytes = wl.canonical_json(payment_mandate)       # both sides must hash the same bytes
mandate_sha256 = hashlib.sha256(mandate_bytes).hexdigest()

# 2. Two agents, two journals, two identities (exchanged out of band; they are public keys).
shopper = wl.open("shopper.jsonl")
merchant = wl.open("merchant.jsonl")
S, M = shopper.identity_pubkey_hex(), merchant.identity_pubkey_hex()

# 3. The shopper's agent: records the grant under the mandate, then what it did.
shopper.append_authorization_event("granted_by_me", mandate_bytes, M)
shopper.append_intent(wl.canonical_json({"tool": "submit_payment", "mandate_sha256": mandate_sha256,
                                         "amount": {"currency": "USD", "value": 120.0}}))
shopper.append_result(wl.canonical_json({"status": "authorized", "processor_ref": "auth_example_77"}))

# 4. The merchant's agent: records receiving the same grant, then what it did.
merchant.append_authorization_event("granted_to_me", mandate_bytes, S)
merchant.append_intent(wl.canonical_json({"tool": "capture_payment", "mandate_sha256": mandate_sha256,
                                          "amount": {"currency": "USD", "value": 120.0}}))
merchant.append_result(wl.canonical_json({"status": "captured", "processor_ref": "auth_example_77"}))

for log in (shopper, merchant):
    log.sync()
json.dump({"shopper": S, "merchant": M, "mandate_sha256": mandate_sha256}, open("ids.json", "w"), indent=2)
print(f"shopper  {S}\nmerchant {M}\nmandate sha256 {mandate_sha256}")

# 5. For the mismatch demo below: a copy of the merchant's identity claiming a $1,200 mandate.
#    (Never submitted to witnesses; it only exists to show what `bind` does with it.)
wider = json.loads(mandate_bytes)
wider["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 1200.0
claim = wl.JournaledLog.create("merchant-claim.jsonl", merchant.identity_bytes())
claim.append_authorization_event("granted_to_me", wl.canonical_json(wider), S)
claim.sync()
open("merchant-claim.json", "w").write(claim.to_dossier_json())
for log in (shopper, merchant, claim):
    log.close()
```

```console
$ python3 ap2_mandate_demo.py
shopper  a4ffdac404f689110ff825ca4cfd16793089f9c58e78129d776c80feddbf4b32
merchant 0d3df6d9b0ab84bcb5a9969b6c39efb5038da6d180507bca56cc822915bd621e
mandate sha256 08570b769be03e795ba15cff436a0055f681cb67ae0ac65e0c16bf5b6e8e5704
```

Three things worth noticing:

- **Which bytes.** `authorization_scope_hash` is `SHA-256(scope)`,
  deliberately unsalted so two independently salted logs can be compared.
  Both sides must hash *identical* bytes. `canonical_json` is RFC 8785
  (JCS) since 0.3.7, so any JCS library in any language produces the same
  bytes from the same JSON value; across implementations that do not
  canonicalize, hash the exact bytes received on the wire.
- **Which mandate.** Use the object that authorised *this* payment: the
  PaymentMandate in AP2 (it names the cart by `payment_details_id`), the
  accepted `PaymentRequirements` plus `PaymentPayload` in x402, the
  credential in Verifiable Intent. Recording the IntentMandate as a
  separate, earlier `AuthorizationEvent` is reasonable too.
- **The hash is the content identifier, not a secret.** Because it is
  unsalted, anyone holding the mandate can confirm a leaf refers to it, and
  `forget()` does not remove it. If the mandate is low-entropy and
  sensitive, record a reference (its ID plus a random nonce both sides
  hold) instead of the mandate itself.

## Step 3: get both heads witnessed

```console
$ witness-log witness submit shopper.jsonl  --directory trusted.json --out shopper.json
  ✓ wa.example/w                     cosigned size 3
  ✓ wb.example/w                     cosigned size 3
2/2 witnesses cosigned size 3 for witness-log/a4ffdac404f689110ff825ca4cfd16793089f9c58e78129d776c80feddbf4b32
wrote shopper.json. Verify with:
  witness-log verify shopper.json --identity a4ffdac404f689110ff825ca4cfd16793089f9c58e78129d776c80feddbf4b32 --directory <directory YOU trust>
$ witness-log witness submit merchant.jsonl --directory trusted.json --out merchant.json
  ✓ wa.example/w                     cosigned size 3
  ✓ wb.example/w                     cosigned size 3
2/2 witnesses cosigned size 3 for witness-log/0d3df6d9b0ab84bcb5a9969b6c39efb5038da6d180507bca56cc822915bd621e
wrote merchant.json. Verify with:
  witness-log verify merchant.json --identity 0d3df6d9b0ab84bcb5a9969b6c39efb5038da6d180507bca56cc822915bd621e --directory <directory YOU trust>
```

The witnesses do not know the two logs are related and do not need to.

## Step 4: bind the two sides

```console
$ witness-log bind shopper.json merchant.json; echo "exit $?"
witness-log bind
  A: a4ffdac404f689110ff825ca4cfd16793089f9c58e78129d776c80feddbf4b32
  B: 0d3df6d9b0ab84bcb5a9969b6c39efb5038da6d180507bca56cc822915bd621e

✓ authorization bound: a4ffdac4...ddbf4b32#0 Some(GrantedByMe) ↔ 0d3df6d9...15bd621e#0 Some(GrantedToMe)  scope 08570b76...6e8e5704

Result: BOUND — both parties committed, in their own logs, to the same content between the same two identities (1 binding(s)).

This checks the two logs against each other only. Run `witness-log verify` on each dossier first; a binding between two unverified logs proves nothing.
exit 0
```

`bind` exits 0 when bound, 30 on a mismatch, 10 when there is nothing to
bind. In Python, `witness_log.verify_authorization_binding(a_id, a_leaf_json,
b_id, b_leaf_json)` returns `None` when the pair binds and the reason
otherwise.

## Step 5: verify each history, pinned to the identity you expect

```console
$ SHOPPER=$(python3 -c 'import json; print(json.load(open("ids.json"))["shopper"])')
$ MERCHANT=$(python3 -c 'import json; print(json.load(open("ids.json"))["merchant"])')
$ witness-log verify shopper.json --identity "$SHOPPER" --directory trusted.json; echo "exit $?"
WitnessLog dossier verification
  identity: a4ffdac4...ddbf4b32
  claimed tree size: 3

✓ Checkpoint signature valid
✓ Identity bound to --identity a4ffdac4...ddbf4b32
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
(exit 0, WITNESSED). In a real audit the identities come from somewhere the
parties do not control (a contract, a registry, a prior exchange), not from
`ids.json`.

## Step 6: check the leaf really is this mandate

Anyone holding the mandate can confirm both leaves commit to it:

```console
$ python3 - <<'EOF'
import json
ids = json.load(open("ids.json"))
for name in ("shopper", "merchant"):
    leaf = next(l for l in json.load(open(f"{name}.json"))["leaves"] if l["leaf_type"] == 6)
    print(name, leaf["authorization_event_kind"], leaf["authorization_scope_hash"] == ids["mandate_sha256"])
EOF
shopper GrantedByMe True
merchant GrantedToMe True
```

## Step 7: what a disagreement looks like

The script also wrote `merchant-claim.json`: the merchant's identity
claiming it was granted a mandate for $1,200 instead of $120.

```console
$ witness-log bind shopper.json merchant-claim.json; echo "exit $?"
witness-log bind
  A: a4ffdac404f689110ff825ca4cfd16793089f9c58e78129d776c80feddbf4b32
  B: 0d3df6d9b0ab84bcb5a9969b6c39efb5038da6d180507bca56cc822915bd621e

✗ authorization NOT bound (leaf 0): b leaf 0: scope hashes do not match — the two sides committed to different scope descriptions

Result: MISMATCH — the two logs disagree about what was handed over or to whom. Neither copy is 'the wrong one'; the disagreement is the finding.

This checks the two logs against each other only. Run `witness-log verify` on each dossier first; a binding between two unverified logs proves nothing.
exit 30
```

Had the merchant actually tried to get that history cosigned after its
honest size-3 head was witnessed, the witnesses would have refused it with
`422` and kept a proof: see [`examples/rewrite-attack/`](https://github.com/0xAndersen/witness-log/tree/main/examples/rewrite-attack).

Stop the witnesses when done (`kill %1 %2`, or by PID).

## What an auditor can now say, and what not

Can say: two named identities, in histories independent organisations
cosigned, committed to the same mandate bytes in matching roles, and each
recorded what it then did (`submit_payment` → `authorized`;
`capture_payment` → `captured`). Neither history can be rewritten without
the witnesses refusing it.

Cannot say: that the mandate was validly signed by the user or merchant
(check that with AP2 / x402 / the card network's tooling), that the amounts
or tools logged are true (a witness is a notary of history, not of facts),
or that the payment settled (that is the processor's or the chain's record;
put its reference in the result leaf so the two point at each other). And
the usual limit: the public registry of witness operators is empty today,
so "independent organisations" means the ones *you* put in `trusted.json`.

## Sources (checked 2026-10-12)

- AP2 A2A extension v0.1 (IntentMandate, CartMandate, PaymentMandate examples): <https://ap2-protocol.org/a2a-extension>; repository <https://github.com/google-agentic-commerce/AP2> (Apache-2.0)
- x402 specification v2 (`PaymentRequired`, `PaymentRequirements`, `PaymentPayload`): <https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md>
- Mastercard Verifiable Intent announcement coverage (5 March 2026): <https://www.pymnts.com/mastercard/2026/mastercard-unveils-open-standard-to-verify-ai-agent-transactions/>; developer documentation: <https://developer.mastercard.com/mastercard-agent-pay/documentation/verifiable-intent/>
- witness-log `AuthorizationEvent`: `spec/SPEC.md` §3.2; corpus vector `08_authorization_event.json`

Next: [Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff) · [Comparison](Comparison) · [Threat model](Threat-Model)
