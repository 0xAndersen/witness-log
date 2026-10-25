# Agent payments: x402 and AP2, both sides on the record

When two agents disagree about a payment, there is no shared record to
settle it from. An AP2 mandate proves what the user authorised. It does
not prove what either agent did under it. An x402 payment is final, so
there is no refund flow to fall back on.

This example has both agents record the payment in their own witnessed
logs. `witness-log bind` then shows that both committed to the same
mandate, payment and delivered bytes. Three disputes follow, and each one
must fail with a specific exit code.

## Run it

```sh
pip install witness-log            # the Python package
cargo install witness-log-cli      # the CLI (or put a release binary on PATH)
python3 examples/agent-payments/run.py
```

From a checkout, in a virtualenv: `make python`, then `make payments`.

It takes about a second and uses only 127.0.0.1. It exits 0 only if every
exit code in the summary table matches, and 1 otherwise. `--keep DIR`
keeps the journals, dossiers, witness state and evidence files.
`WITNESS_LOG_BIN=/path/to/witness-log` picks a specific CLI binary. CI runs
it on every push to main and every pull request
(`.github/workflows/ci.yml`, the Python bindings job).

The CLI must be 0.7.0 or later, the release in which `bind` matches
leaves one to one. `make payments` builds one from this checkout. With an
older CLI, `bind buyer.json seller-extra.json` exits 0, because `bind` did
not check a grant that only the second log holds. The run then fails on
that row and prints why.

## What it does

1. **Three witnesses.** Example Buyer Org, Example Seller Org and Example
   Third-Party Org each run one `witness-log witness serve` process.
   `trusted.json` lists all three.
2. **Two agents.** A buyer agent and a seller agent (the resource server),
   each with its own journal and identity key.
3. **AP2.** The buyer records an intent under the user's IntentMandate
   (budget 0.05 test USDC). The user approves the seller's cart. Both
   agents record the resulting PaymentMandate with `ap2.record_grant`:
   the buyer as `granted_by_me`, the seller as `granted_to_me`.
4. **x402.** The seller answers `402 Payment Required` (0.01 test USDC on
   Base Sepolia). The buyer records an intent, then the payment
   requirements plus its payment payload with `x402.record_grant`. The
   seller records the same payment, an intent to settle, the result, and
   the settlement response as an anchor with `x402.record_receipt`. The
   seller records the delivered bytes as a handoff sent, and the buyer
   records them as received, then its result.
5. **Witnessed.** Each log goes to all three witnesses (`witness submit
   --min 3`). `witness-log verify` with `--identity` and `--subject-org`
   gives WITNESSED for each. `--subject-org` stops the organisation that
   runs a log from counting as independent of it, so each log rests on
   the other two organisations. Here the organisations are only labels on
   processes the script runs, so this shows how the count works, not
   independence.
6. **Bound.** `witness-log bind buyer.json seller.json` finds three
   bindings: the PaymentMandate, the x402 payment and the delivered bytes,
   with nothing left over. `x402.bind` in Python adds the profile checks:
   the same payment hash on both sides, each grant on one side matched by
   exactly one on the other, and a receipt that hashes correctly and names
   this payment.

Then the three disputes:

| | what happens | command | exit |
|---|---|---|---|
| (a) | The seller writes a second log with its key: 10 test USDC for a 30-day report on all cities. The AP2 mandate still binds; the x402 payment and the delivered bytes do not, and `bind` lists both sides' unmatched leaves. The x402 profile check fails. Nobody cosigned the claim. | `bind buyer.json seller-claim.json`<br>`x402.bind(...)` in Python<br>`verify seller-claim.json ...` | 30<br>`ok: false`<br>10 |
| (a) | Or the seller keeps its real log and appends a second x402 grant, for 10 test USDC, that the buyer never made. That only extends the log, so the witnesses cosign it. `bind` reports the grant only the seller holds, in either argument order. | `verify seller-extra.json ...`<br>`bind buyer.json seller-extra.json`<br>`bind seller-extra.json buyer.json` | 0<br>30<br>30 |
| (b) | The buyer copies its journal, cuts it back to before the delivery and writes "paid, nothing delivered". Same key, same size. All three witnesses refuse it, and each keeps a file proving the buyer's key signed two histories of size 6. A verifier holding the earlier head gets DIVERGED. The rewrite no longer matches the seller's delivery. With the proof file, even the buyer's original dossier is DIVERGED. | `witness submit buyer-rewritten.jsonl ...`<br>`verify ... --known-head 6:<root>`<br>`bind buyer-rewritten.json seller.json`<br>`witness verify-evidence <file>`<br>`verify buyer.json ... --evidence <file>` | 20<br>30<br>30<br>0<br>30 |
| (c) | Someone edits the seller's witnessed dossier: the x402 grant leaf now commits to the 10 test USDC payment. The receipts are unchanged. The leaves no longer rebuild the signed root. | `verify seller-tampered.json ...` | 40 |

## Exit codes in this example

| code | meaning |
|---|---|
| 0 | `verify`: WITNESSED. `bind`: bound. `witness verify-evidence`: the file proves the key signed two histories. |
| 10 | `verify`: CONSISTENT-UNWITNESSED. The file is valid, but not enough of your witnesses cosigned it. |
| 20 | `witness submit`: a witness refused the history (422), or fewer than `--min` cosigned. |
| 30 | `verify`: DIVERGED. The file contradicts a head or a proof you hold. `bind`: the two logs disagree. |
| 40 | `verify`: INVALID. A check failed; here, the leaves do not rebuild the signed root. |

The full table, including 11 and 2, is in the
[CLI reference](../../docs/wiki/CLI-Reference.md#exit-codes).

## Test data

All payment data is fictional:

- Addresses are placeholders: `0x00…01` is the buyer's wallet, `0x00…02`
  the seller's, `0x00…03` stands in for the test USDC contract.
- Amounts are test USDC in atomic units (6 decimals) on Base Sepolia,
  a test network (`eip155:84532`).
- The merchant signature, the user authorisation, the payment signature
  and the transaction hash are synthetic bytes. No key signed them.
- The facilitator is a local function. It checks nothing and sends
  nothing; it returns a settlement response so the seller has a receipt
  to record.
- URLs use `.example`, a reserved domain.
- The agents' identity keys come from fixed public seeds, so they are the
  same on every run. Never derive a real key that way.

The x402 and AP2 objects follow the shapes summarised in the
[AP2 tutorial](../../docs/wiki/Tutorial-AP2-Mandates.md), trimmed to what
the example uses.

## What this does not prove

- **Settlement.** Nothing checks that the transaction exists or that money
  moved. The anchor commits to what the facilitator returned. In real use,
  fetch the transaction from the chain and compare.
- **Valid mandates or signatures.** witness-log never checks the user
  authorisation, the merchant signature or the payment signature. Use
  AP2's and x402's own tooling for that.
- **Independence.** The three witnesses are processes this script starts
  on your machine. The organisation names are labels. This shows the
  mechanics, not independence. In real use each witness runs at a
  separate organisation, on its own machine, and the verifier builds its
  own directory.
- **Who is right in (a).** `bind` shows that the two logs disagree, not
  which one is true. In the first variant the claim was never witnessed.
  In the second, both logs are witnessed and still disagree; the signed
  x402 payload, checked with x402's own tooling, decides it.
- **True content.** A witness notarises history, not facts. A log that
  recorded something false at the time keeps it.
- **Rewrites before the first cosignature.** Witnesses only remember heads
  they cosigned. Submit soon after each payment.

Related: [Commerce profiles](../../docs/wiki/Commerce-Profile.md) ·
[AP2 tutorial](../../docs/wiki/Tutorial-AP2-Mandates.md) ·
[The rewrite attack](../rewrite-attack/) ·
[Three-organisation pilot](../pilot-triangle/run.py)
