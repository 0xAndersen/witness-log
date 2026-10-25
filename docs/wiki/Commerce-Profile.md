# Commerce profiles: AP2, x402, Visa Intelligent Commerce

Agent payments run on mandates: a principal authorises an agent to spend
within a scope, the agent acts, a settlement happens. The mandate protocol
proves the *authorisation*; witness-log proves what each party's agent
*recorded* about it and that neither record moved afterwards. The profiles
in `witness_log.profiles` map three mandate formats onto the same three
leaves so that a dispute can be settled from files rather than from logs
one side controls.

| step | leaf | helper |
|---|---|---|
| the mandate is granted | `AuthorizationEvent` whose scope commits to `SHA256(JCS(mandate))` | `record_grant` |
| the payment settles | `ExternalAnchor` whose proof is the settlement record (CAIP-2 chain, CAIP-10 account, tx ref) | `record_receipt` |
| the two agents' logs are compared | `witness-log bind` plus the profile checks | `bind_profile_ap2` / `x402.bind` / `vi.bind` |
| a dispute is raised | a bundle: dossier, disclosures, bindings, manifest | `dispute_export` |

Everything below is runnable; the [AP2 tutorial](Tutorial-AP2-Mandates) walks
through it end to end with two agents and local witnesses.

One command runs it for an x402 payment, with three disputes that must fail: [`examples/agent-payments/`](https://github.com/0xAndersen/witness-log/tree/main/examples/agent-payments).

## Mandate hash

```python
from witness_log.profiles import ap2
h = ap2.mandate_hash(mandate)          # hex SHA-256 of the RFC 8785 canonical JSON
```

Both sides hash the mandate's RFC 8785 (JCS) form, so an agent written in
another language reproduces the hash from the same JSON object regardless
of key order or number formatting. Pass `bytes` to hash exactly what
crossed the wire instead.

## Recording the grant

```python
# principal's agent                               # merchant's or payee's agent
ap2.record_grant(log_a, mandate,                  ap2.record_grant(log_b, mandate,
    counterparty=B_IDENTITY,                          counterparty=A_IDENTITY,
    scope="granted_by_me")                            scope="granted_to_me")
```

The scope hash is unsalted so the two logs can be matched; it is therefore a
content identifier for the mandate. For a low-entropy mandate (a fixed
price list, say) pass `salted=True, nonce=<random string>` on both sides and
exchange the nonce with the mandate; the leaf then commits to
`{"mandate_sha256", "nonce"}`. Revocations and scope changes use the same
call with `revoked_by_me` / `revoked_to_me` / `scope_changed_by_me` /
`scope_changed_to_me` ([the six kinds](Keys-and-Identity#authorization-kinds)).

## Recording the settlement

```python
ap2.record_receipt(log_b, settlement,
    chain_id="eip155:8453",                       # CAIP-2
    account="eip155:8453:0xabc…",                 # CAIP-10, optional for card rails
    tx_ref="0x9f3…",
    anchor_url="https://basescan.org/tx/0x9f3…",  # where the record can be re-fetched
    mandate=mandate)                              # ties the receipt to the grant
```

The proof text is committed as `anchor_proof_hash`; the dossier carries the
proof so a verifier can recompute the hash and fetch the settlement from
`anchor_url` itself. Off-chain rails use a CAIP-2 style identifier the
profile defines (`vi.offchain_chain_id("visa")`).

## Binding the two logs

```python
report = ap2.bind_profile_ap2(dossier_a_json, dossier_b_json, mandate=mandate)
report["ap2"]["mandate_hash_equal"]    # both committed to this mandate
report["ap2"]["scope_not_widened"]     # neither side holds a grant/revocation/change the other lacks
report["ap2"]["settlement_anchors"]    # anchors per side, proofs present, proofs that hash correctly
```

`bind_profile_ap2` runs the same matching as `witness-log bind` (handoff and
authorization pairs committing to identical bytes between the same two
identities) and adds the three AP2 checks. Verify each dossier on its own
first; a binding between two unwitnessed dossiers proves only that the two
files agree with each other.

`x402.mandate(requirements, payload)` and `vi.mandate_hash(credential)` map
the x402 payment-requirements/payload pair and a Visa Intelligent Commerce
credential onto the same calls; `x402.bind` and `vi.bind` wrap
`bind_profile_ap2` with the profile's own mandate derivation.

## Dispute export

```python
ap2.dispute_export(log_b, [grant_index, receipt_index], "dispute-2026-10-12",
    payloads={grant_index: mandate_bytes}, bindings=[report], dossier_json=witnessed_dossier)
```

Writes `dossier.json`, `disclosures.json` (leaf, payload and salt per index
where available, so the counterparty can check each against `payload_hash`
with `verify_disclosure`), `bindings.json` and `MANIFEST.sha256`. The
bundle is self-contained: the receiving party verifies the dossier against
their own trusted directory, checks the disclosures, and re-runs the bind.

## What this proves and does not

Proven, given WITNESSED dossiers on both sides: that each party committed
to this mandate before the settlement, that the committed scopes match,
that a settlement record with this hash was anchored, and that neither
history was rewritten since. Not proven: that the mandate was valid under
the protocol's own rules, that the settlement actually occurred (fetch it
from `anchor_url`), or anything about payloads that were never disclosed.
witness-log is the transparency layer; AP2, x402 and the card schemes
remain the authorisation layer ([Architecture](Architecture)).
