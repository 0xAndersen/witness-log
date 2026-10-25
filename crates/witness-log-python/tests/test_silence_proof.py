"""Write receipts and silence proofs from Python (SPEC §9.4): a log signs a
receipt when it accepts an event (``write_receipt_json``), and the party
holding it checks the log's witnessed dossiers for that event
(``witness_log.prove_silence``), the same check as ``witness-log
prove-silence``. Witnesses run in process (``WitnessService``), two
organisations, so a checkpoint is witnessed by two independent operators.
"""

import json
import os

import pytest
import witness_log


def _network():
    seeds = [os.urandom(32) for _ in range(2)]
    names = [f"w{i}.test/x" for i in range(2)]
    pubkeys = [witness_log.WitnessService.new(n, s, None, True).pubkey_hex() for n, s in zip(names, seeds)]
    directory = {
        "witnesses": [
            json.loads(witness_log.witness_entry_independent(n, f"Org {i}", f"https://w{i}.test", pk))
            for i, (n, pk) in enumerate(zip(names, pubkeys))
        ]
    }

    def witnesses():
        # Same keys, fresh state: what a log showing a second history to a
        # second set of witness instances would get.
        return [witness_log.WitnessService.new(n, s, None, True) for n, s in zip(names, seeds)]

    return directory, witnesses


def _witness(log, ws, old_size):
    responses = []
    for w in ws:
        status, _, body = w.handle_add_checkpoint_http(log.add_checkpoint_body(old_size))
        assert status == 200, body
        responses.append((w.pubkey_hex(), body))
    dossier, n = log.dossier_from_responses(responses)
    assert n == len(ws)
    return dossier


@pytest.fixture()
def accepted(tmp_path):
    """A journal that accepted "the event" at index 3 and signed a receipt for it."""
    seed = os.urandom(32)
    log = witness_log.JournaledLog.create(str(tmp_path / "agent.jsonl"), seed)
    for i in range(3):
        log.append_intent(b"e%d" % i)
    index = log.append_intent(b"the event")
    receipt = log.write_receipt_json(index)
    log.append_intent(b"e4")
    yield seed, log, index, receipt
    log.close()


def test_write_receipt_json_is_the_logs_signed_statement_for_one_leaf(accepted):
    _, log, index, receipt = accepted
    r = json.loads(receipt)
    assert index == 3
    assert r["tree_size"] == 3
    assert r["signer_pubkey"] == log.identity_pubkey_hex()
    assert r["payload_hash"] == json.loads(log.leaf_json(3))["payload_hash"]
    assert set(r) == {"payload_hash", "tree_size", "issued_at_ms", "sig_alg", "signer_pubkey", "signature"}
    assert log.write_receipt_json(5) is None

    mem = witness_log.WitnessLog.generate()
    i = mem.append_intent(b"x")
    assert json.loads(mem.write_receipt_json(i))["signer_pubkey"] == mem.identity_pubkey_hex()
    assert mem.write_receipt_json(i + 1) is None


def test_an_honest_log_is_present_and_bound_to_the_witnessed_root(accepted):
    _, log, _, receipt = accepted
    directory, witnesses = _network()
    ws = witnesses()
    d5 = _witness(log, ws, 0)
    for i in range(5, 9):
        log.append_intent(b"e%d" % i)
    d9 = _witness(log, ws, 5)
    rep = witness_log.prove_silence(receipt, [d5, d9], directory, expected_identity=log.identity_pubkey_hex())
    assert rep["result"] == "present", rep
    assert rep["leaf_index"] == 3 == rep["promised_index"]
    assert rep["bound_tree_size"] == 9
    assert rep["bound_root_hash"] == log.root_hex()
    assert rep["reason"] is None
    assert rep["identity_pinned"] is True
    assert rep["leaves_from"] == 1
    assert [d["status"] for d in rep["dossiers"]] == ["counted", "counted"]

    # An unwitnessed copy holding the event is used for nothing.
    rep = witness_log.prove_silence(receipt, [log.to_dossier_json()], directory)
    assert rep["result"] == "inconclusive" and rep["leaf_index"] is None, rep
    assert rep["dossiers"][0]["status"] == "not_witnessed"

    # An accuser dropping the event from the leaves of the size-9 dossier:
    # the edited copy is set aside, and the size-5 one shows the event.
    doctored = json.loads(d9)
    del doctored["leaves"][3]
    rep = witness_log.prove_silence(receipt, [d5, doctored], directory)
    assert rep["result"] == "present" and rep["bound_tree_size"] == 5, rep
    assert rep["dossiers"][1]["status"] == "leaves_do_not_reproduce"
    assert witness_log.prove_silence(receipt, [doctored], directory)["result"] == "inconclusive"


def test_a_log_that_omits_an_event_it_signed_for_is_censored(accepted, tmp_path):
    seed, log, _, receipt = accepted
    directory, witnesses = _network()
    # The same identity publishes a history without the event, witnessed twice.
    fork = witness_log.JournaledLog.create(str(tmp_path / "fork.jsonl"), seed)
    ws = witnesses()
    for i in range(5):
        fork.append_intent(b"other %d" % i)
    c5 = _witness(fork, ws, 0)
    for i in range(5, 9):
        fork.append_intent(b"other %d" % i)
    c9 = _witness(fork, ws, 5)

    rep = witness_log.prove_silence(receipt, [c5, c9], directory, expected_identity=log.identity_pubkey_hex())
    assert rep["result"] == "censored", rep
    assert rep["witnessed_checkpoints_after"] == 2
    assert rep["receipt_tree_size"] == 3
    assert rep["bound_tree_size"] == 9
    assert rep["bound_root_hash"] == fork.root_hex()
    assert rep["leaf_index"] is None
    # Parsed objects work the same as JSON text.
    rep2 = witness_log.prove_silence(json.loads(receipt), [json.loads(c5), json.loads(c9)], directory["witnesses"])
    assert rep2["result"] == "censored"

    # One witnessed checkpoint: below the default minimum of two.
    rep = witness_log.prove_silence(receipt, [c9], directory)
    assert rep["result"] == "inconclusive" and rep["witnessed_checkpoints_seen"] == 1, rep
    assert witness_log.prove_silence(receipt, [c9], directory, min_checkpoints=1)["result"] == "censored"
    # One of the two operators runs the log: nothing counts.
    rep = witness_log.prove_silence(receipt, [c5, c9], directory, subject_org="org 1")
    assert rep["result"] == "inconclusive" and rep["witnessed_checkpoints_seen"] == 0, rep

    # The log's key revoked (stolen, say): a receipt proves nothing, whether
    # the revocation is passed in or carried by a dossier.
    revocation = log.revoke_json("key stolen")
    rep = witness_log.prove_silence(receipt, [c5, c9], directory, revocations_json=revocation)
    assert rep["result"] == "inconclusive" and "revoked" in rep["reason"], rep
    rep = witness_log.prove_silence(receipt, [c5, c9], directory, revocations_json=[json.loads(revocation)])
    assert rep["result"] == "inconclusive", rep
    carried = json.loads(c9)
    carried["revocations"] = [json.loads(revocation)]
    assert witness_log.prove_silence(receipt, [c5, carried], directory)["result"] == "inconclusive"
    fork.close()


def test_bad_inputs_raise(accepted):
    _, log, _, receipt = accepted
    directory, _ = _network()
    dossier = log.to_dossier_json()
    with pytest.raises(ValueError, match="not from the log you named"):
        witness_log.prove_silence(receipt, [dossier], directory, expected_identity="ab" * 32)
    with pytest.raises(ValueError):
        witness_log.prove_silence(receipt, [dossier], directory, expected_identity="zz")
    altered = json.loads(receipt)
    altered["payload_hash"] = "ab" * 32
    with pytest.raises(witness_log.SignatureError):
        witness_log.prove_silence(altered, [dossier], directory)
    with pytest.raises(witness_log.MalformedError):
        witness_log.prove_silence("not json", [dossier], directory)
    as_array = json.dumps(list(json.loads(receipt).values()))
    with pytest.raises(witness_log.MalformedError):
        witness_log.prove_silence(as_array, [dossier], directory)
    with pytest.raises(witness_log.MalformedError, match="dossier 1"):
        witness_log.prove_silence(receipt, [dossier, "{}"], directory)
    with pytest.raises(witness_log.MalformedError):
        witness_log.prove_silence(receipt, [dossier], {"witnesses": 3})
    with pytest.raises(ValueError, match="at least one dossier"):
        witness_log.prove_silence(receipt, [], directory)
    with pytest.raises(TypeError):
        witness_log.prove_silence(receipt, dossier, directory)
    for bad in (0, -1, -(2**70), 1.5, True):
        with pytest.raises(ValueError):
            witness_log.prove_silence(receipt, [dossier], directory, min_checkpoints=bad)
    # The extension itself refuses a negative minimum with ValueError too.
    with pytest.raises(ValueError):
        witness_log._core.prove_silence_json(receipt, [dossier], json.dumps(directory), -1)
    with pytest.raises(ValueError):
        witness_log.prove_silence(receipt, [dossier], directory, subject_org=" ")
    with pytest.raises(witness_log.MalformedError):
        witness_log.prove_silence(receipt, [dossier], directory, revocations_json="[1]")
