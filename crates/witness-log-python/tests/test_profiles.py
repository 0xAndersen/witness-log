"""Commerce profiles: AP2 / x402 / Verifiable Intent helpers over two
journals, bound in Python, including the tampered-mandate negative case
and the dispute bundle."""

from __future__ import annotations

import hashlib
import json
import os

import pytest

import witness_log as wl
from witness_log.profiles import ap2, vi, x402, _jcs

MANDATE = {
    "payment_mandate_contents": {
        "payment_mandate_id": "pm_example_0001",
        "payment_details_id": "order_example_0001",
        "payment_details_total": {"label": "Total", "amount": {"currency": "USD", "value": 120.0}, "pending": None, "refund_period": 30},
        "payment_response": {"request_id": "order_example_0001", "method_name": "CARD", "details": {"token": "tok_example"}},
        "merchant_agent": "merchant_agent_example",
        "timestamp": "2026-10-12T09:00:00Z",
    },
    "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJleGFtcGxlIn0.placeholder.placeholder",
}
SETTLEMENT = {"status": "captured", "processor_ref": "auth_example_77", "amount": {"currency": "USD", "value": 120.0}}
URL = "https://processor.example/receipts/auth_example_77"


def _pair(tmp_path, names=("shopper", "merchant")):
    a = wl.open(str(tmp_path / f"{names[0]}.jsonl"))
    b = wl.open(str(tmp_path / f"{names[1]}.jsonl"))
    return a, b, a.identity_pubkey_hex(), b.identity_pubkey_hex()


def _verified(log):
    d = log.to_dossier_json()
    rep = json.loads(wl.verify_dossier_json(d, 0.66, log.identity_pubkey_hex()))
    assert rep["internally_consistent"], rep
    return d


# ---------------------------------------------------------------- mandate hash


def test_mandate_hash_is_sha256_of_jcs_and_order_independent():
    h = ap2.mandate_hash(MANDATE)
    assert h == hashlib.sha256(_jcs.canonicalize(MANDATE)).hexdigest()
    reordered = json.loads(json.dumps(MANDATE, sort_keys=True))
    reordered["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 120  # int vs 120.0
    assert ap2.mandate_hash(reordered) == h
    # JSON text and raw bytes are accepted too.
    assert ap2.mandate_hash(json.dumps(MANDATE)) == h
    assert ap2.mandate_hash(_jcs.canonicalize(MANDATE)) == h
    # A different mandate hashes differently (the thing bind catches).
    wider = json.loads(json.dumps(MANDATE))
    wider["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 1200.0
    assert ap2.mandate_hash(wider) != h


def test_mandate_hash_rejects_non_objects():
    with pytest.raises(TypeError):
        ap2.mandate_hash(["not", "an", "object"])  # type: ignore[arg-type]


# --------------------------------------------------------------------- grants


def test_record_grant_pair_binds(tmp_path):
    a, b, A, B = _pair(tmp_path)
    ia = ap2.record_grant(a, MANDATE, counterparty=B, scope="granted_by_me")
    ib = ap2.record_grant(b, MANDATE, counterparty=A, scope="granted_to_me")
    assert (ia, ib) == (0, 0)
    la = json.loads(a.leaves_json())[0]
    lb = json.loads(b.leaves_json())[0]
    assert la["authorization_scope_hash"] == lb["authorization_scope_hash"] == ap2.mandate_hash(MANDATE)
    assert wl.verify_authorization_binding(A, json.dumps(la), B, json.dumps(lb)) is True


def test_record_grant_validates_scope_and_counterparty(tmp_path):
    a, b, A, B = _pair(tmp_path)
    with pytest.raises(ValueError):
        ap2.record_grant(a, MANDATE, counterparty=B, scope="granted")
    with pytest.raises(Exception):  # the core refuses a non-key counterparty
        ap2.record_grant(a, MANDATE, counterparty="zz")
    # Uppercase hex is accepted and stored lowercase.
    ap2.record_grant(a, MANDATE, counterparty=B.upper())
    assert json.loads(a.leaves_json())[0]["counterparty_pubkey"] == B


def test_salted_grant_hides_the_mandate_hash_but_still_binds(tmp_path):
    a, b, A, B = _pair(tmp_path)
    with pytest.raises(ValueError):
        ap2.record_grant(a, MANDATE, counterparty=B, salted=True)  # needs a nonce
    ap2.record_grant(a, MANDATE, counterparty=B, salted=True, nonce="n-7f3a")
    ap2.record_grant(b, MANDATE, counterparty=A, scope="granted_to_me", salted=True, nonce="n-7f3a")
    la = json.loads(a.leaves_json())[0]
    assert la["authorization_scope_hash"] != ap2.mandate_hash(MANDATE)
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), mandate=MANDATE, nonce="n-7f3a", require_anchors="none")
    assert rep["exit"] == 0 and rep["ap2"]["mandate_hash_equal"] and rep["ap2"]["ok"]
    # Without the nonce the auditor cannot tie the leaf to the mandate.
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), mandate=MANDATE, require_anchors="none")
    assert rep["exit"] == 0 and not rep["ap2"]["mandate_hash_equal"] and not rep["ap2"]["ok"]


# ------------------------------------------------------------------- receipts


def test_record_receipt_proof_hashes_to_anchor_proof_hash(tmp_path):
    a, b, A, B = _pair(tmp_path)
    i = ap2.record_receipt(
        b, SETTLEMENT, chain_id="eip155:8453", account="eip155:8453:0x1111111111111111111111111111111111111111",
        tx_ref="0xabc", anchor_url=URL, mandate=MANDATE,
    )
    leaf = json.loads(b.leaves_json())[i]
    assert leaf["leaf_type"] == 7 and leaf["anchor_url"] == URL
    assert hashlib.sha256(leaf["anchor_proof_json"].encode()).hexdigest() == leaf["anchor_proof_hash"]
    proof = json.loads(leaf["anchor_proof_json"])
    assert proof["chain_id"] == "eip155:8453" and proof["tx_ref"] == "0xabc" and proof["profile"] == "ap2"
    assert proof["mandate_sha256"] == ap2.mandate_hash(MANDATE)
    assert proof["settlement"] == SETTLEMENT
    _verified(b)


@pytest.mark.parametrize(
    "kw",
    [
        {"chain_id": "8453"},  # not CAIP-2
        {"chain_id": "eip155:8453", "account": "0xabc"},  # not CAIP-10
        {"chain_id": "eip155:8453", "account": "eip155:1:0xabc"},  # wrong chain
        {"chain_id": "eip155:8453", "tx_ref": ""},
        {"chain_id": "eip155:8453", "anchor_url": "ftp://x"},  # the core's URL rule
    ],
)
def test_record_receipt_rejects_bad_identifiers(tmp_path, kw):
    a, _, _, _ = _pair(tmp_path)
    args = {"chain_id": "eip155:8453", "account": None, "tx_ref": "0x1", "anchor_url": URL}
    args.update(kw)
    with pytest.raises(Exception):
        ap2.record_receipt(a, SETTLEMENT, **args)
    assert a.tree_size() == 0  # refused before any leaf exists


# ----------------------------------------------------------------------- bind


def _full_flow(tmp_path):
    a, b, A, B = _pair(tmp_path)
    ap2.record_grant(a, MANDATE, counterparty=B, scope="granted_by_me")
    a.append_intent(wl.canonical_json({"tool": "submit_payment", "mandate_sha256": ap2.mandate_hash(MANDATE)}))
    a.append_result(wl.canonical_json({"status": "authorized", "processor_ref": "auth_example_77"}))
    ap2.record_grant(b, MANDATE, counterparty=A, scope="granted_to_me")
    b.append_intent(wl.canonical_json({"tool": "capture_payment", "mandate_sha256": ap2.mandate_hash(MANDATE)}))
    b.append_result(wl.canonical_json({"status": "captured", "processor_ref": "auth_example_77"}))
    ap2.record_receipt(b, SETTLEMENT, chain_id="offchain:card", tx_ref="auth_example_77", anchor_url=URL, mandate=MANDATE)
    return a, b, A, B


def test_bind_profile_ap2_bound(tmp_path):
    a, b, A, B = _full_flow(tmp_path)
    rep = ap2.bind_profile_ap2(_verified(a), _verified(b), mandate=MANDATE)
    assert rep["exit"] == 0 and rep["failed"] == []
    assert rep["bound"] == [
        {"kind": "authorization", "a": A, "a_leaf": 0, "a_event": "granted_by_me", "b": B, "b_leaf": 0,
         "b_event": "granted_to_me", "scope_hash": ap2.mandate_hash(MANDATE)}
    ]
    p = rep["ap2"]
    assert p["mandate_hash_equal"] and p["scope_not_widened"] and p["ok"]
    assert p["settlement_anchors"]["b"] == {"count": 1, "proof_carried": 1, "proof_hash_ok": 1, "mandate_match": 1, "indices": [3]}
    assert p["settlement_anchors"]["a"]["count"] == 0 and p["settlement_anchors"]["ok"]
    # Stricter: both sides must have anchored.
    rep2 = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), mandate=MANDATE, require_anchors="both")
    assert not rep2["ap2"]["ok"] and not rep2["ap2"]["settlement_anchors"]["ok"]
    # Dossiers can also be given as file paths.
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    pa.write_text(a.to_dossier_json())
    pb.write_text(b.to_dossier_json())
    assert ap2.bind_profile_ap2(str(pa), str(pb), mandate=MANDATE)["ap2"]["ok"]


def test_bind_profile_ap2_tampered_mandate_is_a_mismatch(tmp_path):
    # The merchant's identity claims a $1,200 mandate in a second journal.
    a, b, A, B = _full_flow(tmp_path)
    wider = json.loads(json.dumps(MANDATE))
    wider["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 1200.0
    claim = wl.JournaledLog.create(str(tmp_path / "merchant-claim.jsonl"), b.identity_bytes())
    ap2.record_grant(claim, wider, counterparty=A, scope="granted_to_me")
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), claim.to_dossier_json(), mandate=MANDATE)
    assert rep["exit"] == 30 and rep["bound"] == []
    assert len(rep["failed"]) == 1 and "scope hashes do not match" in rep["failed"][0]["reason"]
    p = rep["ap2"]
    assert not p["ok"] and not p["mandate_hash_equal"] and not p["scope_not_widened"]
    assert p["scopes"]["a"] == [ap2.mandate_hash(MANDATE)] and p["scopes"]["b"] == [ap2.mandate_hash(wider)]


def test_bind_profile_ap2_unilateral_widening(tmp_path):
    # Both sides agree on the first mandate; one side alone records a
    # scope change. bind still finds the first pair, but the profile check
    # reports the widening.
    a, b, A, B = _full_flow(tmp_path)
    wider = json.loads(json.dumps(MANDATE))
    wider["payment_mandate_contents"]["payment_details_total"]["amount"]["value"] = 1200.0
    ap2.record_grant(b, wider, counterparty=A, scope="scope_changed_to_me")
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), mandate=MANDATE)
    assert rep["ap2"]["mandate_hash_equal"] and not rep["ap2"]["scope_not_widened"] and not rep["ap2"]["ok"]
    # From the honest side's point of view every one of its leaves binds, so
    # the plain bind exit is 0; the ap2 block is what carries the finding.
    assert rep["exit"] == 0


def test_bind_profile_ap2_swapped_anchor_proof_is_detected(tmp_path):
    a, b, A, B = _full_flow(tmp_path)
    doc = json.loads(b.to_dossier_json())
    anchor = next(l for l in doc["leaves"] if l["leaf_type"] == 7)
    anchor["anchor_proof_json"] = json.dumps({"profile": "ap2", "tx_ref": "0xother", "mandate_sha256": ap2.mandate_hash(MANDATE)})
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), json.dumps(doc), mandate=MANDATE)
    assert rep["ap2"]["settlement_anchors"]["b"]["proof_hash_ok"] == 0 and not rep["ap2"]["ok"]


def test_bind_profile_ap2_nothing_to_bind_and_same_identity(tmp_path):
    a, b, A, B = _pair(tmp_path)
    a.append_intent(b"{}")
    b.append_intent(b"{}")
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), require_anchors="none")
    assert rep["exit"] == 10 and not rep["ap2"]["ok"]
    with pytest.raises(ValueError):
        ap2.bind_profile_ap2(a.to_dossier_json(), a.to_dossier_json())


def test_bind_handoffs_too(tmp_path):
    a, b, A, B = _pair(tmp_path)
    state = _jcs.canonicalize({"order": "order_example_0001"})
    a.append_handoff_sent(state, B)
    b.append_handoff_received(state, A)
    rep = ap2.bind_dossiers(a.to_dossier_json(), b.to_dossier_json())
    assert rep["exit"] == 0 and rep["bound"][0]["kind"] == "handoff"
    b2 = wl.JournaledLog.create(str(tmp_path / "b2.jsonl"), b.identity_bytes())
    b2.append_handoff_received(b"other state", A)
    rep = ap2.bind_dossiers(a.to_dossier_json(), b2.to_dossier_json())
    assert rep["exit"] == 30 and "state hashes do not match" in rep["failed"][0]["reason"]


# -------------------------------------------------------------- dispute export


def test_dispute_export_bundle(tmp_path):
    a, b, A, B = _full_flow(tmp_path)
    payloads = {
        1: wl.canonical_json({"tool": "capture_payment", "mandate_sha256": ap2.mandate_hash(MANDATE)}),
        2: wl.canonical_json({"status": "captured", "processor_ref": "auth_example_77"}),
    }
    b.sync()
    rep = ap2.bind_profile_ap2(a.to_dossier_json(), b.to_dossier_json(), mandate=MANDATE)
    out = tmp_path / "dispute"
    manifest = ap2.dispute_export(b, [0, 1, 2, 3], str(out), journal_path=str(tmp_path / "merchant.jsonl"), payloads=payloads, bindings=[rep])
    assert sorted(os.listdir(out)) == ["MANIFEST.sha256", "bindings.json", "disclosures.json", "dossier.json"]
    assert set(manifest) == {"bindings.json", "disclosures.json", "dossier.json"}
    for name, digest in manifest.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    lines = (out / "MANIFEST.sha256").read_text().splitlines()
    assert lines == [f"{manifest[n]}  {n}" for n in sorted(manifest)]

    discl = json.loads((out / "disclosures.json").read_text())
    by_index = {d["index"]: d for d in discl}
    # Leaves 1 and 2 had payloads and salts: complete and verified.
    assert by_index[1]["complete"] and by_index[1]["verified"] is True
    assert by_index[2]["complete"] and by_index[2]["verified"] is True
    assert json.loads(by_index[1]["payload"])["tool"] == "capture_payment"
    # Leaf 0 (the grant) and 3 (the anchor): no payload was passed, so bare leaf + salt.
    assert not by_index[0]["complete"] and "salt" in by_index[0] and "payload" not in by_index[0]
    assert by_index[3]["leaf"]["leaf_type"] == 7
    # The dossier in the bundle verifies on its own.
    assert json.loads(wl.verify_dossier_json((out / "dossier.json").read_text(), 0.66, B))["internally_consistent"]
    assert json.loads((out / "bindings.json").read_text())[0]["ap2"]["ok"]

    with pytest.raises(IndexError):
        ap2.dispute_export(b, [99], str(tmp_path / "x"))


# ----------------------------------------------------------- x402 and VI shapes


X402_REQ = {"scheme": "exact", "network": "eip155:8453", "amount": "1000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0x2222222222222222222222222222222222222222", "maxTimeoutSeconds": 60, "extra": {"name": "USDC", "version": "2"}}
X402_PAYLOAD = {"x402Version": 2, "accepted": X402_REQ, "payload": {"signature": "0xsig", "authorization": {"from": "0x3333333333333333333333333333333333333333"}}}
X402_SETTLE = {"success": True, "transaction": "0x" + "ab" * 32, "network": "eip155:8453", "payer": "0x3333333333333333333333333333333333333333"}


def test_x402_profile_maps_onto_the_same_leaves(tmp_path):
    client, server, C, S = _pair(tmp_path, ("client", "server"))
    m = x402.mandate(X402_REQ, X402_PAYLOAD)
    x402.record_grant(client, m, counterparty=S)
    x402.record_grant(server, m, counterparty=C, scope="granted_to_me")
    i = x402.record_receipt(server, X402_SETTLE, anchor_url="https://explorer.example/tx/" + X402_SETTLE["transaction"], mandate=m)
    proof = json.loads(json.loads(server.leaves_json())[i]["anchor_proof_json"])
    assert proof["profile"] == "x402" and proof["chain_id"] == "eip155:8453"
    assert proof["account"] == "eip155:8453:" + X402_SETTLE["payer"] and proof["tx_ref"] == X402_SETTLE["transaction"]
    rep = x402.bind(_verified(client), _verified(server), mandate=m)
    assert rep["ap2"]["ok"] and rep["bound"][0]["scope_hash"] == x402.mandate_hash(m)
    with pytest.raises(ValueError):
        x402.record_receipt(server, {"success": True}, anchor_url=URL)  # no network / transaction


def test_vi_profile_offchain_rail(tmp_path):
    consumer, merchant, C, M = _pair(tmp_path, ("consumer", "merchant"))
    credential = {"type": "VerifiableIntent", "id": "vi_example_1", "instructions": "buy one, up to 120 USD", "proof": "opaque"}
    vi.record_grant(consumer, credential, counterparty=M)
    vi.record_grant(merchant, credential, counterparty=C, scope="granted_to_me")
    i = vi.record_receipt(merchant, {"status": "approved"}, network="card", tx_ref="auth_example_77", anchor_url=URL, credential=credential)
    proof = json.loads(json.loads(merchant.leaves_json())[i]["anchor_proof_json"])
    assert proof["profile"] == "vi" and proof["chain_id"] == "offchain:card"
    assert vi.bind(_verified(consumer), _verified(merchant), credential=credential)["ap2"]["ok"]
    with pytest.raises(ValueError):
        vi.record_receipt(merchant, {}, tx_ref="x", anchor_url=URL)  # neither chain_id nor network
    with pytest.raises(ValueError):
        vi.record_receipt(merchant, {}, tx_ref="x", anchor_url=URL, network="card", chain_id="eip155:1")
    with pytest.raises(ValueError):
        vi.offchain_chain_id("Card Network!")
