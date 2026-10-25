#!/usr/bin/env python3
"""Agent payments on the record: an x402 payment under an AP2-style
mandate, logged by both agents, witnessed, bound, then disputed.

A buyer agent pays a seller agent for one resource over x402, under a
mandate its user approved. Each agent records the mandate, the payment and
what it did in its own log. Three local witnesses, run by three fictional
organisations, cosign both logs, and `witness-log bind` shows that both
sides committed to the same mandate, payment and delivered bytes. Then
three disputes, each of which must fail in a specific way:

  (a) the seller presents a log claiming a larger amount for a different
      resource, or appends a grant the buyer never made to its real log:
      `bind` reports a mismatch (exit 30), in either argument order;
  (b) the buyer rewrites its own log to say nothing was delivered: the
      witnesses refuse it (submit exit 20), and a verifier holding the
      earlier head gets DIVERGED (exit 30);
  (c) someone edits one leaf of the seller's witnessed dossier: INVALID
      (exit 40).

    pip install witness-log              # Python package (import witness_log)
    cargo install witness-log-cli        # or put a release binary on PATH
    python3 examples/agent-payments/run.py

The CLI must be newer than 0.6.1, or built from this checkout (`make
payments` does that): 0.6.1's `bind` misses a grant only its second
argument holds, and the run fails on that row.

All payment data is fictional test data: placeholder addresses, amounts in
test USDC on Base Sepolia (a test network), synthetic signature bytes. No
network beyond 127.0.0.1: nothing is sent to a chain, a facilitator or any
other service. Exits 0 only if every exit code matched; 1 otherwise.

Options: --keep DIR keeps all artefacts in DIR (default: a temp dir, deleted).
Env: WITNESS_LOG_BIN=/path/to/witness-log to pick a specific CLI binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

try:
    import witness_log as wl
    from witness_log.profiles import ap2, x402
except ImportError:  # pragma: no cover
    sys.exit("this example needs the Python package: pip install witness-log (or `make python` in a virtualenv)")

CLI = os.environ.get("WITNESS_LOG_BIN") or shutil.which("witness-log")
if CLI and os.sep in CLI:
    CLI = os.path.abspath(CLI)  # commands run from the work directory
if not CLI:
    sys.exit("this example needs the CLI on PATH: cargo install witness-log-cli (or set WITNESS_LOG_BIN)")

# Three fictional organisations, each running one witness on localhost. The
# buyer's and the seller's organisations each run one; a third party runs
# the third. A verifier passes --subject-org naming the organisation that
# operates the log it checks, so that organisation's own witness is not
# counted as independent of its own agent: each log is WITNESSED by the
# other two. All three are processes this script starts; they demonstrate
# the mechanics, not independence.
ORGS = [
    ("buyer-org", "Example Buyer Org"),
    ("seller-org", "Example Seller Org"),
    ("third-org", "Example Third-Party Org"),
]
BUYER_ORG, SELLER_ORG = ORGS[0][1], ORGS[1][1]

# Fixed test seeds, so the agents' identity keys are the same on every run.
# Never derive a real key from a public string like this.
BUYER_SEED = hashlib.sha256(b"witness-log agent-payments example: buyer agent, test key").digest()
SELLER_SEED = hashlib.sha256(b"witness-log agent-payments example: seller agent, test key").digest()

# ---------------------------------------------------------------- test data
#
# Everything below is fictional. The addresses are placeholders, not real
# accounts or contracts. Amounts are test USDC in atomic units (6 decimals:
# "10000" is 0.01) on Base Sepolia, a test network (CAIP-2 eip155:84532).
# Signatures and the transaction hash are SYNTHETIC: fixed bytes of the
# right length, not produced by any key and not on any chain. witness-log
# never checks them; the protocols' own tooling does that.
NETWORK = "eip155:84532"  # Base Sepolia (test network)
BUYER_WALLET = "0x0000000000000000000000000000000000000001"
SELLER_WALLET = "0x0000000000000000000000000000000000000002"
TEST_USDC = "0x0000000000000000000000000000000000000003"  # placeholder, not the real test-USDC contract
SYNTHETIC_SIGNATURE = "0x" + "00" * 65  # SYNTHETIC: stands in for an EIP-712 signature
SYNTHETIC_TX = "0x" + "00" * 31 + "01"  # SYNTHETIC: no such transaction exists
EXPLORER = "https://explorer.example/base-sepolia/tx/"  # .example: a reserved, fictional domain

RESOURCE = {
    "url": "https://seller.example/reports/oslo-7-day",
    "description": "7-day weather report for Oslo (fictional test data)",
    "mimeType": "application/json",
}
DELIVERED = wl.canonical_json({"report": "Oslo, 7 days", "days": ["rain", "rain", "sun", "cloud", "rain", "sun", "sun"],
                               "note": "fictional test data"})

# AP2 shapes, after the A2A extension v0.1 examples summarised in
# docs/wiki/Tutorial-AP2-Mandates.md, trimmed to what this example uses.
INTENT_MANDATE = {  # what the user tells the buyer agent it may do
    "user_cart_confirmation_required": True,
    "natural_language_description": "Buy a 7-day weather report for Oslo from Example Seller. Spend at most 0.05 test USDC.",
    "merchants": ["Example Seller (fictional)"],
    "requires_refundability": False,
    "intent_expiry": "2026-10-25T13:00:00Z",
}
CART_MANDATE = {  # the seller's offer
    "contents": {
        "id": "cart_example_0001",
        "user_cart_confirmation_required": True,
        "payment_request": {
            "method_data": [{"supported_methods": "x402", "data": {"network": NETWORK, "asset": TEST_USDC, "payTo": SELLER_WALLET}}],
            "details": {
                "id": "order_example_0001",
                "display_items": [{"label": RESOURCE["description"], "amount": {"currency": "USDC", "value": 0.01}}],
                "total": {"label": "Total", "amount": {"currency": "USDC", "value": 0.01}},
            },
        },
        "cart_expiry": "2026-10-25T12:15:00Z",
        "merchant_name": "Example Seller (fictional)",
    },
    "merchant_signature": "SYNTHETIC-merchant-signature",  # SYNTHETIC: not a signature
    "timestamp": "2026-10-25T12:00:00Z",
}
PAYMENT_MANDATE = {  # the user's sign-off on that cart; both agents hold it
    "payment_mandate_contents": {
        "payment_mandate_id": "pm_example_0001",
        "payment_details_id": "order_example_0001",  # the cart's payment_request.details.id
        "payment_details_total": {"label": "Total", "amount": {"currency": "USDC", "value": 0.01}, "refund_period": 0},
        "payment_response": {"request_id": "order_example_0001", "method_name": "x402",
                             "details": {"network": NETWORK, "payer": BUYER_WALLET}},
        "merchant_agent": "Example Seller (fictional)",
        "timestamp": "2026-10-25T12:01:00Z",
    },
    "user_authorization": "SYNTHETIC.user-authorization.not-a-token",  # SYNTHETIC: not a JWS
}
BUDGET_ATOMIC = 50000  # 0.05 test USDC, from the IntentMandate


def payment_required(resource: dict, amount: str) -> dict:
    """The seller's `402 Payment Required` body (x402 v2 shape)."""
    return {
        "x402Version": 2,
        "error": "payment required",
        "resource": resource,
        "accepts": [{
            "scheme": "exact",
            "network": NETWORK,
            "amount": amount,  # atomic units
            "asset": TEST_USDC,
            "payTo": SELLER_WALLET,
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }],
    }


def payment_payload(required: dict) -> dict:
    """The buyer's answer (x402 v2 PaymentPayload, `exact` scheme on EVM).
    The signature is SYNTHETIC: 65 zero bytes where an EIP-712 signature
    over the EIP-3009 authorization would be. Nothing here signs for a chain."""
    req = required["accepts"][0]
    return {
        "x402Version": 2,
        "resource": required["resource"],
        "accepted": req,
        "payload": {
            "signature": SYNTHETIC_SIGNATURE,
            "authorization": {"from": BUYER_WALLET, "to": req["payTo"], "value": req["amount"],
                              "validAfter": "1792929600", "validBefore": "1792929660", "nonce": "0x" + "00" * 31 + "01"},
        },
    }


def local_facilitator_settle(payload: dict) -> dict:
    """Stands in for an x402 facilitator's settle call. It verifies nothing
    and contacts nothing: it returns a settlement response (the
    PAYMENT-RESPONSE body) with a synthetic transaction hash, so the seller
    has a receipt to record."""
    return {"success": True, "transaction": SYNTHETIC_TX, "network": payload["accepted"]["network"],
            "payer": payload["payload"]["authorization"]["from"]}


# ------------------------------------------------------------------ output

class Abort(Exception):
    """A step the rest of the run depends on failed."""


failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []  # (scenario, command, expected, actual)
aliases: dict[str, str] = {}  # long values shown by name in printed commands


def say(text: str = "") -> None:
    print(text, flush=True)


def step(title: str) -> None:
    say()
    say(f"── {title}")


def check(cond: bool, what: str) -> None:
    say(f"   {'✓' if cond else '✗'} {what}")
    if not cond:
        failures.append(what)


def expect(scenario: str, shown: str, want: int, got: int, what: str) -> None:
    """One row of the summary table; a mismatch fails the run."""
    rows.append((scenario, shown, str(want), str(got)))
    check(got == want, f"{what}: exit {got} (expected {want})")


def alias(text: str) -> str:
    for value, name in aliases.items():
        text = text.replace(value, name)
    return text


def cli(work: str, *args: str, show: bool = True) -> tuple[int, str, str]:
    if show:
        say("   $ witness-log " + alias(" ".join(a if " " not in a else repr(a) for a in args)))
    r = subprocess.run([CLI, *args], cwd=work, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr


def clip(text: str, width: int = 140) -> str:
    text = alias(text.rstrip())
    return text if len(text) <= width else text[: width - 1] + "…"


def quote(out: str, keep: tuple[str, ...] = (), limit: int = 8) -> None:
    """Print the CLI output lines that carry the point (all if keep is empty)."""
    lines = [line for line in out.splitlines() if line.strip()]
    if keep:
        lines = [line for line in lines if any(k in line for k in keep)]
    for line in lines[:limit]:
        say(f"     │ {clip(line)}")


def leaf(who: str, index: int, kind: str, text: str) -> None:
    say(f"   {who:<6} leaf {index}  {kind:<13} {text}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_healthy(url: str) -> bool:
    for _ in range(200):
        try:
            urllib.request.urlopen(url + "/health", timeout=1).read()
            return True
        except Exception:
            time.sleep(0.05)
    return False


def verify(work: str, dossier: str, identity: str, *extra: str) -> tuple[int, dict]:
    code, out, err = cli(work, "verify", dossier, "--identity", identity, "--directory", "trusted.json", "--json", *extra)
    try:
        return code, json.loads(out)
    except ValueError:
        return code, {"error": err.strip()}


def describe(rep: dict) -> str:
    """One line from `verify --json`: the verdict and why."""
    if "error" in rep:
        return f"no JSON from verify: {rep['error']}"
    r = rep.get("report") or {}
    q = r.get("quorum") or {}
    why = r.get("failures") or r.get("contradictions") or []
    if why:
        return f"{rep.get('verdict')}: {why[0]}"
    if rep.get("verdict") == "WITNESSED":
        ops = ", ".join(q.get("independent_operators_represented") or [])
        return (f"WITNESSED: {q.get('valid_receipts')}/{q.get('total_directory_witnesses')} witnesses cosigned; "
                f"independent of the log's operator: {ops}")
    if not q:
        return f"{rep.get('verdict')}: the file carries no witness receipts"
    return str(rep.get("verdict"))


def rewrite_from(src: str, dst: str, keep: int):
    """What an operator holding the key and the journal can do: copy the
    journal and cut it back to `keep` leaves (exactly what restoring an old
    backup does). Leaves 0..keep-1 stay byte-identical, salts included; the
    reopened log has the same identity key. A fresh copy has no
    `.witnesses.json` sidecar, so `submit`'s local guard has nothing to
    compare against and the request reaches the witnesses."""
    with open(src) as f, open(dst, "w") as g:
        for line in f:
            rec = json.loads(line)
            if "leaf_type" in rec and rec["index"] >= keep:
                continue
            g.write(line)
    with open(src + ".salts") as f, open(dst + ".salts", "w") as g:
        for line in f:
            if json.loads(line)["i"] < keep:
                g.write(line)
    os.chmod(dst, 0o600)
    os.chmod(dst + ".salts", 0o600)
    return wl.open(dst, BUYER_SEED)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keep", metavar="DIR", help="keep artefacts in DIR instead of a temp dir")
    args = ap.parse_args()
    if args.keep:
        work = os.path.abspath(args.keep)
        if os.path.exists(work):
            sys.exit(f"{work} exists; pick a new directory")
        os.makedirs(work)
    else:
        work = tempfile.mkdtemp(prefix="wl-payments-")
    t0 = time.monotonic()
    procs: list[subprocess.Popen] = []
    _, version, _ = cli(work, "--version", show=False)
    say(f"witness-log agent-payments example  ({version.strip()}, Python witness_log {wl.__version__})")
    say("x402 + AP2-style mandate, both sides logged and witnessed. All payment data is fictional test data.")

    try:
        # ── witnesses ────────────────────────────────────────────────────
        step("1. Three organisations each start one witness (local processes, loopback only)")
        for slug, org in ORGS:
            port = free_port()
            url = f"http://127.0.0.1:{port}"
            code, out, err = cli(work, "witness", "init", f"{slug}/witness", "--name", f"witness.{slug}.example/w1",
                                 "--org", org, "--url", url, "--json", show=False)
            if code != 0:
                check(False, f"{org}: witness init ({err.strip()[-160:]})")
                raise Abort("could not set up the witnesses")
            info = json.loads(out)
            procs.append(subprocess.Popen(
                [CLI, "witness", "serve", f"{slug}/witness", "--listen", f"127.0.0.1:{port}", "--open-enrollment"],
                cwd=work, stdout=open(os.path.join(work, f"{slug}-witness.log"), "w"), stderr=subprocess.STDOUT))
            healthy = wait_healthy(url)
            check(healthy, f"{org}: witness answering at {url}")
            if not healthy:
                raise Abort("a witness did not start; see its log in the work directory (--keep DIR)")
            code, _, err = cli(work, "directory", "add", "trusted.json", "--vkey", info["vkey"], "--org", org,
                               "--url", url, show=False)
            check(code == 0, f"{org}: added to trusted.json" + (f" ({err.strip()})" if code else ""))
        say("   trusted.json is the verifier's own list of witnesses; in real use the verifier builds it.")

        # ── agents ───────────────────────────────────────────────────────
        step("2. Two agents, two journals, two identities")
        buyer = wl.open(os.path.join(work, "buyer.jsonl"), BUYER_SEED)
        seller = wl.open(os.path.join(work, "seller.jsonl"), SELLER_SEED)
        B, S = buyer.identity_pubkey_hex(), seller.identity_pubkey_hex()
        aliases.update({B: "$BUYER", S: "$SELLER"})
        say(f"   BUYER={B}   buyer agent, run by {BUYER_ORG}")
        say(f"   SELLER={S}   seller agent (resource server), run by {SELLER_ORG}")
        say("   Each side knows the other's identity key (a public key, exchanged out of band).")

        # ── AP2 ──────────────────────────────────────────────────────────
        step("3. AP2: the user's intent, the seller's cart, the user's sign-off on it")
        h_intent = ap2.mandate_hash(INTENT_MANDATE)
        i = buyer.append_intent(wl.canonical_json({"tool": "shop", "intent_mandate_sha256": h_intent,
                                                   "budget": {"asset": "test USDC", "atomic": BUDGET_ATOMIC}}))
        leaf("buyer", i, "intent", f"shop under the user's IntentMandate (budget 0.05 test USDC, sha256 {h_intent[:12]}…)")
        say(f"   seller offers cart {CART_MANDATE['contents']['id']}: 1 × {RESOURCE['description']}, 0.01 test USDC")
        say("   the user approves it: the PaymentMandate (user_authorization is synthetic here) goes to both agents")
        h_pm = ap2.mandate_hash(PAYMENT_MANDATE)
        i = ap2.record_grant(buyer, PAYMENT_MANDATE, counterparty=S, scope="granted_by_me")
        leaf("buyer", i, "authorization", f"granted_by_me → SELLER, PaymentMandate sha256 {h_pm[:12]}…")
        i = ap2.record_grant(seller, PAYMENT_MANDATE, counterparty=B, scope="granted_to_me")
        leaf("seller", i, "authorization", f"granted_to_me ← BUYER, PaymentMandate sha256 {h_pm[:12]}…")

        # ── x402 ─────────────────────────────────────────────────────────
        step("4. x402: 402 Payment Required → payment payload → settlement → the resource")
        required = payment_required(RESOURCE, "10000")
        req = required["accepts"][0]
        say(f"   GET {RESOURCE['url']} → 402: {req['scheme']} {req['amount']} atomic test USDC on {req['network']} to {req['payTo']}")
        check(int(req["amount"]) <= BUDGET_ATOMIC, "buyer: the amount is within the IntentMandate's budget")
        payload = payment_payload(required)
        mandate = x402.mandate(req, payload)
        h_x402 = x402.mandate_hash(mandate)
        i = buyer.append_intent(wl.canonical_json({"tool": "x402_pay", "resource": RESOURCE["url"], "amount": req["amount"],
                                                   "network": NETWORK, "payment_mandate_sha256": h_pm}))
        leaf("buyer", i, "intent", f"pay {req['amount']} atomic test USDC for {RESOURCE['url']}")
        i = x402.record_grant(buyer, mandate, counterparty=S)
        leaf("buyer", i, "authorization", f"granted_by_me → SELLER, x402 requirements+payload sha256 {h_x402[:12]}…")
        say("   buyer retries the GET with the payment payload; the seller receives it")
        i = x402.record_grant(seller, mandate, counterparty=B, scope="granted_to_me")
        leaf("seller", i, "authorization", f"granted_to_me ← BUYER, x402 requirements+payload sha256 {h_x402[:12]}…")
        i = seller.append_intent(wl.canonical_json({"tool": "x402_settle", "x402_mandate_sha256": h_x402,
                                                    "amount": req["amount"], "network": NETWORK}))
        leaf("seller", i, "intent", "settle the payment (a local stand-in facilitator; nothing leaves this machine)")
        settlement = local_facilitator_settle(payload)
        i = seller.append_result(wl.canonical_json({"tool": "x402_settle", "settlement": settlement}))
        leaf("seller", i, "result", f"settled: success, transaction {SYNTHETIC_TX[:10]}… (synthetic)")
        i = x402.record_receipt(seller, settlement, anchor_url=EXPLORER + SYNTHETIC_TX, mandate=mandate)
        leaf("seller", i, "anchor", f"settlement response, chain {NETWORK}, names the x402 mandate")
        i = seller.append_handoff_sent(DELIVERED, B)
        h_delivered = hashlib.sha256(DELIVERED).hexdigest()
        leaf("seller", i, "handoff sent", f"200 OK: the report, {len(DELIVERED)} bytes, sha256 {h_delivered[:12]}…")
        i = buyer.append_handoff_received(DELIVERED, S)
        leaf("buyer", i, "handoff recv", f"the same {len(DELIVERED)} bytes")
        i = buyer.append_result(wl.canonical_json({"tool": "x402_pay", "http_status": 200, "transaction": SYNTHETIC_TX,
                                                   "resource_sha256": h_delivered}))
        leaf("buyer", i, "result", "200 OK, report received")
        for log in (buyer, seller):
            log.sync()
        buyer_root, buyer_size = buyer.root_hex(), buyer.tree_size()
        seller_size = seller.tree_size()
        buyer.close()
        seller.close()

        # ── witnessed ────────────────────────────────────────────────────
        step("5. Both logs witnessed, then each verified pinned to its identity and its operator")
        for name, size in (("buyer", buyer_size), ("seller", seller_size)):
            code, _, err = cli(work, "witness", "submit", f"{name}.jsonl", "--directory", "trusted.json",
                               "--out", f"{name}.json", "--min", "3")
            quote(err, keep=("cosigned size",), limit=4)
            check(code == 0, f"{name}: 3/3 witnesses cosigned size {size}" + (f" ({err.strip()[-160:]})" if code else ""))
        say("   --subject-org names who operates the log, so that organisation's own witness is not counted as")
        say("   independent of its own agent: each log is WITNESSED by the two organisations that do not run it.")
        for name, ident, org in (("buyer", B, BUYER_ORG), ("seller", S, SELLER_ORG)):
            var = "$" + name.upper()
            code, rep = verify(work, f"{name}.json", ident, "--subject-org", org)
            say(f"     │ {clip(describe(rep))}")
            expect("happy path", f"verify {name}.json --identity {var} --subject-org ...", 0, code,
                   f"{name}.json WITNESSED by the two organisations that do not run it")

        # ── bound ────────────────────────────────────────────────────────
        step("6. Bind the two logs: same mandate, same payment, same delivered bytes")
        code, out, _ = cli(work, "bind", "buyer.json", "seller.json")
        quote(out, keep=("bound", "Result"))
        expect("happy path", "bind buyer.json seller.json", 0, code, "bind: BOUND")
        rep = x402.bind(os.path.join(work, "buyer.json"), os.path.join(work, "seller.json"), mandate=mandate)
        p = rep["ap2"]
        say(f"   x402.bind (Python): mandate_hash_equal={p['mandate_hash_equal']}  scope_not_widened={p['scope_not_widened']}"
            f"  settlement anchors on the seller's side: {p['settlement_anchors']['b']['proof_hash_ok']} hash-checked")
        rows.append(("happy path", "x402.bind(buyer, seller, mandate=...) [Python]", "ok", "ok" if p["ok"] else "not ok"))
        check(p["ok"], "x402 profile checks: both sides committed to this payment and the receipt names it")

        # ── dispute (a) ──────────────────────────────────────────────────
        step("7. Dispute (a): the seller shows a log claiming 10 test USDC for a bigger report")
        say("   The seller's operator holds its key and writes a second journal: same AP2 mandate, but the x402")
        say("   payment and the delivered resource say 10 test USDC for a 30-day all-cities report.")
        big = {"url": "https://seller.example/reports/all-cities-30-day",
               "description": "30-day report, all cities (fictional test data)", "mimeType": "application/json"}
        big_required = payment_required(big, "10000000")
        big_payload = payment_payload(big_required)
        big_mandate = x402.mandate(big_required["accepts"][0], big_payload)
        big_delivered = wl.canonical_json({"report": "all cities, 30 days", "note": "fictional test data"})
        claim = wl.open(os.path.join(work, "seller-claim.jsonl"), SELLER_SEED)
        ap2.record_grant(claim, PAYMENT_MANDATE, counterparty=B, scope="granted_to_me")
        x402.record_grant(claim, big_mandate, counterparty=B, scope="granted_to_me")
        claim.append_intent(wl.canonical_json({"tool": "x402_settle", "x402_mandate_sha256": x402.mandate_hash(big_mandate),
                                               "amount": "10000000", "network": NETWORK}))
        claim.append_result(wl.canonical_json({"tool": "x402_settle", "settlement": settlement}))
        x402.record_receipt(claim, settlement, anchor_url=EXPLORER + SYNTHETIC_TX, mandate=big_mandate)
        claim.append_handoff_sent(big_delivered, B)
        claim.sync()
        with open(os.path.join(work, "seller-claim.json"), "w") as f:
            f.write(claim.to_dossier_json())
        claim.close()
        code, out, _ = cli(work, "bind", "buyer.json", "seller-claim.json")
        quote(out, keep=("bound", "Result"))
        expect("(a) seller claims more", "bind buyer.json seller-claim.json", 30, code,
               "bind: MISMATCH on the x402 payment and the delivered bytes")
        rep = x402.bind(os.path.join(work, "buyer.json"), os.path.join(work, "seller-claim.json"), mandate=mandate)
        say(f"   x402.bind (Python): mandate_hash_equal={rep['ap2']['mandate_hash_equal']}  "
            f"scope_not_widened={rep['ap2']['scope_not_widened']}  ok={rep['ap2']['ok']}")
        code, rep = verify(work, "seller-claim.json", S, "--subject-org", SELLER_ORG)
        say(f"     │ {clip(describe(rep))}")
        expect("(a) seller claims more", "verify seller-claim.json --identity $SELLER ...", 10, code,
               "the claim was never witnessed: CONSISTENT-UNWITNESSED, not WITNESSED")

        say("   Or the seller keeps its real log and appends one more grant naming the buyer: the 10 test USDC")
        say("   payment. That only extends the log, so the witnesses cosign it. bind is what catches it.")
        seller = wl.open(os.path.join(work, "seller.jsonl"), SELLER_SEED)
        i = x402.record_grant(seller, big_mandate, counterparty=B, scope="granted_to_me")
        leaf("seller", i, "authorization", "granted_to_me ← BUYER, x402 payment for 10 test USDC (only the seller says so)")
        seller.sync()
        seller.close()
        code, _, err = cli(work, "witness", "submit", "seller.jsonl", "--directory", "trusted.json",
                           "--out", "seller-extra.json", "--min", "3")
        quote(err, keep=("cosigned size",), limit=3)
        check(code == 0, f"the witnesses cosigned the extended seller log (exit {code})")
        code, rep = verify(work, "seller-extra.json", S, "--subject-org", SELLER_ORG)
        say(f"     │ {clip(describe(rep))}")
        expect("(a) seller claims more", "verify seller-extra.json --identity $SELLER ...", 0, code,
               "the extended seller log is WITNESSED: witnesses check history, not content")
        for x, y in (("buyer.json", "seller-extra.json"), ("seller-extra.json", "buyer.json")):
            code, out, _ = cli(work, "bind", x, y)
            quote(out, keep=("NOT bound", "Result"), limit=2)
            expect("(a) seller claims more", f"bind {x} {y}", 30, code,
                   "a grant only the seller recorded is a MISMATCH, whichever log comes first")

        # ── dispute (b) ──────────────────────────────────────────────────
        step("8. Dispute (b): the buyer rewrites its log to say nothing was delivered")
        say("   x402 has no refunds, so the buyer's operator copies the journal, cuts it back to before the")
        say(f"   delivery (what restoring an old backup does) and writes a different ending. Same key, same size {buyer_size}.")
        rw = rewrite_from(os.path.join(work, "buyer.jsonl"), os.path.join(work, "buyer-rewritten.jsonl"), keep=4)
        i = rw.append_result(wl.canonical_json({"tool": "x402_pay", "http_status": 502, "transaction": SYNTHETIC_TX,
                                                "error": "paid, but no resource was delivered"}))
        leaf("buyer'", i, "result", "502: paid, but nothing delivered")
        i = rw.append_intent(wl.canonical_json({"tool": "open_dispute", "transaction": SYNTHETIC_TX, "claim": "not delivered"}))
        leaf("buyer'", i, "intent", "open a dispute: not delivered")
        rw.sync()
        check(rw.identity_pubkey_hex() == B and rw.tree_size() == buyer_size and rw.root_hex() != buyer_root,
              f"same identity, same size {rw.tree_size()}, different root")
        rw.close()
        code, _, err = cli(work, "witness", "submit", "buyer-rewritten.jsonl", "--directory", "trusted.json",
                           "--out", "buyer-rewritten.json", "--min", "3")
        quote(err, keep=("REFUSED (422)",), limit=3)
        expect("(b) buyer rewrites", "witness submit buyer-rewritten.jsonl ...", 20, code,
               "every witness refused the rewritten history (422)")
        aliases[buyer_root] = "<buyer root>"
        code, rep = verify(work, "buyer-rewritten.json", B, "--subject-org", BUYER_ORG,
                           "--known-head", f"{buyer_size}:{buyer_root}")
        say(f"     │ {clip(describe(rep))}")
        expect("(b) buyer rewrites", f"verify buyer-rewritten.json ... --known-head {buyer_size}:<buyer root>", 30, code,
               "a verifier holding the witnessed head: DIVERGED")
        code, out, _ = cli(work, "bind", "buyer-rewritten.json", "seller.json")
        quote(out, keep=("bound", "Result"), limit=5)
        expect("(b) buyer rewrites", "bind buyer-rewritten.json seller.json", 30, code,
               "the rewrite also contradicts the seller's witnessed delivery")
        # Same size, different root: each witness now holds two checkpoints
        # signed by the buyer's key for one size, and wrote them to evidence/.
        kept = {}
        for slug, _ in ORGS:
            ev_dir = os.path.join(work, slug, "witness", "evidence")
            kept[slug] = sorted(os.listdir(ev_dir)) if os.path.isdir(ev_dir) else []
        check(all(len(v) == 1 for v in kept.values()),
              "each witness kept a proof file: " + ", ".join(f"{k}/witness/evidence/ ({len(v)})" for k, v in kept.items()))
        if kept["third-org"]:
            ev = os.path.join("third-org", "witness", "evidence", kept["third-org"][0])
            aliases[ev] = "<evidence file>"
            code, out, _ = cli(work, "witness", "verify-evidence", ev)
            quote(out, keep=("PROVEN",), limit=1)
            expect("(b) buyer rewrites", "witness verify-evidence <evidence file>", 0, code,
                   "the buyer's key provably signed two histories of one size")
            code, rep = verify(work, "buyer.json", B, "--subject-org", BUYER_ORG, "--evidence", ev)
            say(f"     │ {clip(describe(rep))}")
            expect("(b) buyer rewrites", "verify buyer.json ... --evidence <evidence file>", 30, code,
                   "with that proof, even the buyer's original dossier is DIVERGED")

        # ── dispute (c) ──────────────────────────────────────────────────
        step("9. Dispute (c): one leaf of the seller's witnessed dossier is edited")
        say("   The x402 grant leaf's scope hash is replaced with the 10 test USDC mandate's hash; the witness")
        say("   receipts are kept as they were.")
        with open(os.path.join(work, "seller.json")) as f:
            d = json.load(f)
        grant = next(lf for lf in d["leaves"] if lf.get("authorization_scope_hash") == h_x402)
        grant["authorization_scope_hash"] = x402.mandate_hash(big_mandate)
        with open(os.path.join(work, "seller-tampered.json"), "w") as f:
            json.dump(d, f)
        code, rep = verify(work, "seller-tampered.json", S, "--subject-org", SELLER_ORG)
        say(f"     │ {clip(describe(rep))}")
        expect("(c) edited leaf", "verify seller-tampered.json --identity $SELLER ...", 40, code,
               "the edited leaf no longer rebuilds the signed root: INVALID")
    except Abort as e:
        say(f"   stopped: {e}")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    say()
    say("Summary: expected vs actual")
    w = max([len(r[1]) for r in rows] + [7])
    say(f"   {'scenario':<23} {'command':<{w}}  expected  actual")
    for scenario, shown, want, got in rows:
        mark = "✓" if want == got else "✗"
        say(f"   {scenario:<23} {shown:<{w}}  {want:>8}  {got:>6}  {mark}")
    say()
    elapsed = time.monotonic() - t0
    if failures:
        say(f"FAILED ({len(failures)}): " + "; ".join(failures))
    else:
        say("Result: both agents committed to the same mandate, payment and delivered bytes in witnessed logs;")
        say("a different claim, a rewritten history and an edited dossier each failed with the expected exit code.")
    say(f"({elapsed:.1f} s; artefacts in {work})" if args.keep else f"({elapsed:.1f} s)")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
