"""AP2 (Agent Payments Protocol) profile: record a mandate, record its
settlement, bind the two sides, export a dispute bundle.

::

    from witness_log.profiles import ap2

    h = ap2.mandate_hash(payment_mandate)                 # SHA-256(JCS(mandate))
    ap2.record_grant(shopper, payment_mandate, counterparty=M, scope="granted_by_me")
    ap2.record_grant(merchant, payment_mandate, counterparty=S, scope="granted_to_me")
    ...                                                   # intent / result leaves as usual
    ap2.record_receipt(merchant, settlement, chain_id="eip155:8453",
                       account="eip155:8453:0xabc...", tx_ref="0x...",
                       anchor_url="https://processor.example/receipts/...", mandate=payment_mandate)
    report = ap2.bind_profile_ap2(shopper_dossier, merchant_dossier, mandate=payment_mandate)
    assert report["ap2"]["ok"]

The mandate is any JSON object both parties hold (a PaymentMandate, a
CartMandate, an IntentMandate). The two sides hash the *same JSON*, not
the same Python object: RFC 8785 fixes key order, number format and
escaping, so a counterparty in another language gets the same bytes.

Logging only, as everywhere in witness-log: nothing here checks
``user_authorization`` or ``merchant_signature``, evaluates amounts, or
blocks a payment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .. import _core
from . import _disclose, _jcs

__all__ = [
    "mandate_hash",
    "mandate_bytes",
    "grant_scope_bytes",
    "record_grant",
    "receipt_proof",
    "record_receipt",
    "bind_dossiers",
    "bind_profile_ap2",
    "dispute_export",
    "GRANT_KINDS",
]

GRANT_KINDS = (
    "granted_by_me",
    "granted_to_me",
    "revoked_by_me",
    "revoked_to_me",
    "scope_changed_by_me",
    "scope_changed_to_me",
)

# CAIP-2 chain id and CAIP-10 account id (namespace:reference[:address]).
_CAIP2 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
_CAIP10 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$")

LEAF_HANDOFF = 5
LEAF_AUTHORIZATION = 6
LEAF_ANCHOR = 7

# The CLI's exit codes for `bind`, reproduced so a Python caller can map
# the report onto the same three outcomes.
EXIT_BOUND = 0
EXIT_NO_CROSS_LOG_LEAVES = 10
EXIT_MISMATCH = 30


# ------------------------------------------------------------------ mandate


def mandate_bytes(mandate: Union[Mapping[str, Any], bytes, str]) -> bytes:
    """The bytes that are hashed: RFC 8785 canonical JSON of a mapping; a
    ``bytes`` value is taken as-is (hash exactly what crossed the wire);
    a ``str`` is parsed as JSON and canonicalised."""
    if isinstance(mandate, bytes):
        return mandate
    if isinstance(mandate, str):
        mandate = json.loads(mandate)
    if not isinstance(mandate, Mapping):
        raise TypeError("mandate must be a JSON object (mapping), JSON text, or raw bytes")
    return _jcs.canonicalize(mandate)


def mandate_hash(mandate: Union[Mapping[str, Any], bytes, str]) -> str:
    """``SHA-256(JCS(mandate))`` as lowercase hex. This is what both
    sides' ``AuthorizationEvent`` leaves carry as ``authorization_scope_hash``."""
    return hashlib.sha256(mandate_bytes(mandate)).hexdigest()


# -------------------------------------------------------------------- grant


def grant_scope_bytes(
    mandate: Union[Mapping[str, Any], bytes, str], *, salted: bool = False, nonce: Optional[str] = None
) -> bytes:
    """The scope bytes an ``AuthorizationEvent`` commits to for ``mandate``:
    its JCS bytes, or with ``salted=True`` the reference
    ``JCS({"mandate_sha256": <hash>, "nonce": <nonce>})``."""
    if not salted:
        return mandate_bytes(mandate)
    if not nonce:
        raise ValueError("salted=True needs nonce (a random string both sides hold, exchanged with the mandate)")
    return _jcs.canonicalize({"mandate_sha256": mandate_hash(mandate), "nonce": str(nonce)})


def record_grant(
    log: Any,
    mandate: Union[Mapping[str, Any], bytes, str],
    *,
    counterparty: str,
    scope: str = "granted_by_me",
    salted: bool = False,
    nonce: Optional[str] = None,
) -> int:
    """Append an ``AuthorizationEvent`` committing to ``mandate`` between
    this log's identity and ``counterparty`` (its identity pubkey, hex).

    ``scope`` is this side's role: ``granted_by_me`` for the principal's
    agent, ``granted_to_me`` for the one receiving the mandate (and the
    revoked / scope_changed pairs). The two roles must mirror each other
    for ``bind`` to match them. Returns the leaf index.

    The scope hash is unsalted so the two logs can be compared, which
    makes it a content identifier: anyone holding a candidate mandate can
    confirm a leaf refers to it. For a low-entropy mandate pass
    ``salted=True, nonce=<random string>``; the leaf then commits to
    ``{"mandate_sha256", "nonce"}`` instead, and both sides must use the
    same nonce (exchange it with the mandate). ``bind_profile_ap2`` with
    ``mandate=`` then needs ``nonce=`` too."""
    if scope not in GRANT_KINDS:
        raise ValueError(f"scope must be one of {GRANT_KINDS}, got {scope!r}")
    return log.append_authorization_event(scope, grant_scope_bytes(mandate, salted=salted, nonce=nonce), counterparty.lower())


# ------------------------------------------------------------------ receipt


def _check_caip(chain_id: str, account: Optional[str]) -> None:
    if not _CAIP2.fullmatch(chain_id):
        raise ValueError(f"chain_id must be a CAIP-2 id like 'eip155:8453', got {chain_id!r}")
    if account is not None:
        if not _CAIP10.fullmatch(account):
            raise ValueError(f"account must be a CAIP-10 id like 'eip155:8453:0xabc', got {account!r}")
        if not account.startswith(chain_id + ":"):
            raise ValueError(f"account {account!r} is not on chain {chain_id!r}")


def receipt_proof(
    settlement: Mapping[str, Any],
    *,
    chain_id: str,
    account: Optional[str],
    tx_ref: str,
    mandate: Union[Mapping[str, Any], bytes, str, None] = None,
    profile: str = "ap2",
) -> str:
    """The anchor proof JSON for a settlement, as text. ``SHA-256`` of
    exactly this text is what the ``ExternalAnchor`` leaf commits to
    (``anchor_proof_hash``); the verifier recomputes it from the carried
    JSON, so the text is canonical (JCS) and must not be reformatted."""
    _check_caip(chain_id, account)
    if not tx_ref:
        raise ValueError("tx_ref is required (the processor's or chain's reference for the settlement)")
    body: Dict[str, Any] = {
        "profile": profile,
        "chain_id": chain_id,
        "tx_ref": str(tx_ref),
        "settlement": dict(settlement),
    }
    if account is not None:
        body["account"] = account
    if mandate is not None:
        body["mandate_sha256"] = mandate_hash(mandate)
    return _jcs.dumps(body)


def record_receipt(
    log: Any,
    settlement: Mapping[str, Any],
    *,
    chain_id: str,
    account: Optional[str] = None,
    tx_ref: str,
    anchor_url: str,
    mandate: Union[Mapping[str, Any], bytes, str, None] = None,
    profile: str = "ap2",
) -> int:
    """Append an ``ExternalAnchor`` leaf whose proof is the settlement
    record. ``chain_id`` is CAIP-2 (``eip155:8453``), ``account`` CAIP-10
    (``eip155:8453:0x...``; optional for card rails), ``tx_ref`` the
    transaction hash or processor reference, ``anchor_url`` where the
    settlement can be re-fetched (an explorer or processor URL; http(s)
    is required by the leaf rules). Passing ``mandate`` embeds its hash
    so the receipt is tied to the grant it settles. Returns the leaf
    index. The proof text hashes to the leaf's ``anchor_proof_hash``."""
    proof = receipt_proof(settlement, chain_id=chain_id, account=account, tx_ref=tx_ref, mandate=mandate, profile=profile)
    return log.append_external_anchor(anchor_url, proof)


# --------------------------------------------------------------------- bind


def _load(d: Union[str, Mapping[str, Any], bytes]) -> Dict[str, Any]:
    if isinstance(d, (str, bytes)):
        try:
            return json.loads(d)
        except ValueError:
            if isinstance(d, str) and os.path.exists(d):
                with open(d, encoding="utf-8") as f:
                    return json.load(f)
            raise
    return dict(d)


def _names_other(leaves: Sequence[Mapping[str, Any]], other: str, tag: int) -> List[Mapping[str, Any]]:
    return [l for l in leaves if l.get("leaf_type") == tag and l.get("counterparty_pubkey") == other]


_MIRRORED_KIND = {
    "GrantedByMe": "GrantedToMe",
    "GrantedToMe": "GrantedByMe",
    "RevokedByMe": "RevokedToMe",
    "RevokedToMe": "RevokedByMe",
    "ScopeChangedByMe": "ScopeChangedToMe",
    "ScopeChangedToMe": "ScopeChangedByMe",
}


def _event_name(kind: Optional[str]) -> str:
    table = {
        "GrantedByMe": "granted_by_me",
        "GrantedToMe": "granted_to_me",
        "RevokedByMe": "revoked_by_me",
        "RevokedToMe": "revoked_to_me",
        "ScopeChangedByMe": "scope_changed_by_me",
        "ScopeChangedToMe": "scope_changed_to_me",
    }
    return table.get(kind or "", "unknown")


class _Matching:
    """One-to-one matching of two leaf lists (each in index order), as the
    CLI does it: each left leaf binds the first right leaf ``check``
    accepts (returns ``None``) that no earlier left leaf took. A leaf binds
    at most once, so an event one side recorded twice and the other once
    leaves one over, and what is bound or left over does not depend on
    which side is left."""

    def __init__(self, left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]], check: Any):
        self.left, self.right, self.check = left, right, check
        self.left_partner: List[Optional[int]] = [None] * len(left)
        self.right_partner: List[Optional[int]] = [None] * len(right)
        self.pairs: List[Tuple[int, int]] = []
        for i, l in enumerate(left):
            for j, r in enumerate(right):
                if self.right_partner[j] is None and check(l, r) is None:
                    self.left_partner[i], self.right_partner[j] = j, i
                    self.pairs.append((i, j))
                    break

    def left_over(self, side: str) -> List[int]:
        partners = self.left_partner if side == "left" else self.right_partner
        return [k for k, p in enumerate(partners) if p is None]

    def why(self, side: str, k: int, names: Tuple[str, str], none: str) -> str:
        """Why leaf ``k`` of ``side`` bound to nothing, one clause per leaf
        on the other side (the CLI's wording)."""
        if side == "left":
            others, other_partner, other_name, own_name, own = self.right, self.right_partner, names[1], names[0], self.left
        else:
            others, other_partner, other_name, own_name, own = self.left, self.left_partner, names[0], names[1], self.right
        if not others:
            return none
        out = []
        for o, other in enumerate(others):
            err = self.check(self.left[k], other) if side == "left" else self.check(other, self.right[k])
            if err is not None:
                out.append(f"{other_name} leaf {other['index']}: {err}")
            elif other_partner[o] is not None:
                out.append(f"{other_name} leaf {other['index']}: already bound to {own_name} leaf {own[other_partner[o]]['index']}")
            else:
                out.append(f"{other_name} leaf {other['index']}: unbound")
        return "; ".join(out)


def bind_dossiers(dossier_a: Any, dossier_b: Any) -> Dict[str, Any]:
    """``witness-log bind`` in Python: the HandoffAttestations and
    AuthorizationEvents in A naming B are matched one to one against B's
    leaves naming A with the core's ``verify_handoff_binding`` /
    ``verify_authorization_binding``. Every such leaf on either side that
    binds to nothing is a failure: a Sent leaf (``"sender_leaf"``), a
    Received leaf (``"receiver_leaf"``), an AuthorizationEvent of A
    (``"a_leaf"``) or of B (``"b_leaf"``), including a repeated event the
    other side recorded fewer times. Bound pairs and failures are the same
    in either argument order. Returns ``{"a", "b", "bound", "failed",
    "exit"}`` with the CLI's exit codes (0 bound, 30 mismatch, 10 nothing
    to bind). Raises ``ValueError`` when both dossiers claim one identity
    (that is ``diff``'s job)."""
    a, b = _load(dossier_a), _load(dossier_b)
    ia, ib = str(a["identity_pubkey"]), str(b["identity_pubkey"])
    if ia == ib:
        raise ValueError(f"both dossiers claim the same identity {ia}; bind is for two different agents")
    bound: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []

    for sender, sid, receiver, rid in ((a, ia, b, ib), (b, ib, a, ia)):
        sent = [l for l in _names_other(sender["leaves"], rid, LEAF_HANDOFF) if l.get("handoff_direction") == "Sent"]
        recv = [l for l in _names_other(receiver["leaves"], sid, LEAF_HANDOFF) if l.get("handoff_direction") == "Received"]

        def check_handoff(s: Mapping[str, Any], r: Mapping[str, Any], sid: str = sid, rid: str = rid) -> Optional[str]:
            return _core.handoff_binding_error(sid, json.dumps(s), rid, json.dumps(r))

        m = _Matching(sent, recv, check_handoff)
        for i, j in m.pairs:
            bound.append({"kind": "handoff", "sender": sid, "sender_leaf": sent[i]["index"], "receiver": rid,
                          "receiver_leaf": recv[j]["index"], "state_hash": sent[i].get("handoff_state_hash")})
        for i in m.left_over("left"):
            failed.append({"kind": "handoff", "sender": sid, "sender_leaf": sent[i]["index"], "receiver": rid,
                           "reason": m.why("left", i, ("sender", "receiver"),
                                           "receiver logged no HandoffAttestation naming this sender")})
        for j in m.left_over("right"):
            failed.append({"kind": "handoff", "sender": sid, "receiver": rid, "receiver_leaf": recv[j]["index"],
                           "reason": m.why("right", j, ("sender", "receiver"),
                                           "sender logged no HandoffAttestation (Sent) naming this receiver")})

    auth_a = _names_other(a["leaves"], ib, LEAF_AUTHORIZATION)
    auth_b = _names_other(b["leaves"], ia, LEAF_AUTHORIZATION)

    def check_auth(la: Mapping[str, Any], lb: Mapping[str, Any]) -> Optional[str]:
        return _core.authorization_binding_error(ia, json.dumps(la), ib, json.dumps(lb))

    m = _Matching(auth_a, auth_b, check_auth)
    for i, j in m.pairs:
        la, lb = auth_a[i], auth_b[j]
        bound.append({"kind": "authorization", "a": ia, "a_leaf": la["index"], "a_event": _event_name(la.get("authorization_event_kind")),
                      "b": ib, "b_leaf": lb["index"], "b_event": _event_name(lb.get("authorization_event_kind")),
                      "scope_hash": la.get("authorization_scope_hash")})
    no_auth = "the other log has no AuthorizationEvent naming this agent"
    for i in m.left_over("left"):
        failed.append({"kind": "authorization", "a": ia, "a_leaf": auth_a[i]["index"], "b": ib,
                       "reason": m.why("left", i, ("a", "b"), no_auth)})
    for j in m.left_over("right"):
        failed.append({"kind": "authorization", "a": ia, "b": ib, "b_leaf": auth_b[j]["index"],
                       "reason": m.why("right", j, ("a", "b"), no_auth)})

    code = EXIT_MISMATCH if failed else (EXIT_NO_CROSS_LOG_LEAVES if not bound else EXIT_BOUND)
    return {"a": {"identity": ia}, "b": {"identity": ib}, "bound": bound, "failed": failed, "exit": code}


def _anchor_checks(leaves: Sequence[Mapping[str, Any]], want_mandate_hash: Optional[str]) -> Dict[str, Any]:
    anchors = [l for l in leaves if l.get("leaf_type") == LEAF_ANCHOR]
    out: Dict[str, Any] = {"count": len(anchors), "proof_carried": 0, "proof_hash_ok": 0, "mandate_match": 0, "indices": [l["index"] for l in anchors]}
    for l in anchors:
        pj = l.get("anchor_proof_json")
        if not isinstance(pj, str):
            continue
        out["proof_carried"] += 1
        if hashlib.sha256(pj.encode("utf-8")).hexdigest() == str(l.get("anchor_proof_hash", "")).lower():
            out["proof_hash_ok"] += 1
        if want_mandate_hash is not None:
            try:
                if json.loads(pj).get("mandate_sha256") == want_mandate_hash:
                    out["mandate_match"] += 1
            except (ValueError, AttributeError):
                pass
    return out


def bind_profile_ap2(
    dossier_a: Any,
    dossier_b: Any,
    *,
    mandate: Union[Mapping[str, Any], bytes, str, None] = None,
    nonce: Optional[str] = None,
    require_anchors: str = "either",
) -> Dict[str, Any]:
    """``bind_dossiers`` plus the AP2 checks, under ``report["ap2"]``:

    * ``mandate_hash_equal``: at least one authorization pair bound, and
      (when ``mandate`` is given) its scope hash is that mandate's hash
      (with ``nonce`` when the grants were recorded ``salted=True``).
    * ``scope_not_widened``: every grant, revocation or scope change A
      recorded towards B has exactly one counterpart in B's log (the
      mirrored kind, the same scope hash) and the other way round,
      counted per (kind, scope): equal multisets, not just equal sets. A
      side that holds an event the other never recorded, or holds it more
      times (a re-grant after a revocation, say), fails this; that is how
      a unilateral widening shows up.
    * ``settlement_anchors``: ExternalAnchor leaves on each side, how
      many carry their proof, how many proofs hash to the committed
      ``anchor_proof_hash``, and how many name this mandate.
      ``require_anchors`` is ``"either"`` (default: at least one side
      anchored its settlement), ``"both"``, or ``"none"``.
    * ``ok``: all of the above, and ``exit == 0``.

    Verify each dossier with ``verify_dossier_json`` first; binding two
    unverified logs proves nothing."""
    if require_anchors not in ("either", "both", "none"):
        raise ValueError("require_anchors must be 'either', 'both' or 'none'")
    a, b = _load(dossier_a), _load(dossier_b)
    rep = bind_dossiers(a, b)
    ia, ib = rep["a"]["identity"], rep["b"]["identity"]
    want = mandate_hash(mandate) if mandate is not None else None
    # The scope hash on the leaves: the mandate's hash, or the hash of the
    # salted reference when the grants were recorded with a nonce.
    want_scope = None
    if mandate is not None:
        want_scope = hashlib.sha256(grant_scope_bytes(mandate, salted=nonce is not None, nonce=nonce)).hexdigest()

    auth_pairs = [p for p in rep["bound"] if p["kind"] == "authorization"]
    if want_scope is None:
        mandate_equal = bool(auth_pairs)
    else:
        mandate_equal = any(p["scope_hash"] == want_scope for p in auth_pairs)

    auth_a = _names_other(a["leaves"], ib, LEAF_AUTHORIZATION)
    auth_b = _names_other(b["leaves"], ia, LEAF_AUTHORIZATION)
    scopes_a = {l.get("authorization_scope_hash") for l in auth_a}
    scopes_b = {l.get("authorization_scope_hash") for l in auth_b}
    # Count (kind, scope) per side, B's kinds mirrored into A's role.
    events_a = Counter((l.get("authorization_event_kind"), l.get("authorization_scope_hash")) for l in auth_a)
    events_b = Counter((_MIRRORED_KIND.get(str(l.get("authorization_event_kind"))), l.get("authorization_scope_hash")) for l in auth_b)
    not_widened = bool(events_a) and events_a == events_b

    anc_a = _anchor_checks(a["leaves"], want)
    anc_b = _anchor_checks(b["leaves"], want)

    def good(c: Dict[str, Any]) -> bool:
        return c["count"] > 0 and c["proof_hash_ok"] == c["proof_carried"] == c["count"] and (want is None or c["mandate_match"] == c["count"])

    if require_anchors == "none":
        anchors_ok = anc_a["proof_hash_ok"] == anc_a["proof_carried"] and anc_b["proof_hash_ok"] == anc_b["proof_carried"]
    elif require_anchors == "both":
        anchors_ok = good(anc_a) and good(anc_b)
    else:
        anchors_ok = (good(anc_a) or good(anc_b)) and anc_a["proof_hash_ok"] == anc_a["proof_carried"] and anc_b["proof_hash_ok"] == anc_b["proof_carried"]

    rep["ap2"] = {
        "mandate_sha256": want,
        "expected_scope_hash": want_scope,
        "mandate_hash_equal": mandate_equal,
        "scope_not_widened": not_widened,
        "scopes": {"a": sorted(s for s in scopes_a if s), "b": sorted(s for s in scopes_b if s)},
        "settlement_anchors": {"a": anc_a, "b": anc_b, "ok": anchors_ok, "required": require_anchors},
        "ok": rep["exit"] == EXIT_BOUND and mandate_equal and not_widened and anchors_ok,
    }
    return rep


# ------------------------------------------------------------ dispute bundle


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def dispute_export(
    log: Any,
    indices: Iterable[int],
    out_path: str,
    *,
    journal_path: Optional[str] = None,
    payloads: Optional[Mapping[int, bytes]] = None,
    bindings: Optional[Sequence[Mapping[str, Any]]] = None,
    dossier_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Write a dispute bundle directory at ``out_path``::

        dossier.json        the log's current dossier (or ``dossier_json``, e.g. a witnessed one)
        disclosures.json    one record per index: leaf, and payload + salt where available
        bindings.json       the ``bind_profile_ap2`` / ``bind_dossiers`` reports passed in
        MANIFEST.sha256     "<sha256>  <file>" per file, so the bundle can be handed over whole

    Payloads are not stored in a journal (only their salted hashes are), so
    they come from the caller: ``payloads`` maps leaf index to the exact
    bytes appended (the adapters keep these; see ``Recorder.payloads``).
    Salts are read from ``<journal_path>.salts``; a forgotten leaf has none
    and is disclosed as the bare leaf. Returns the manifest as a dict."""
    doc_text = dossier_json if dossier_json is not None else log.to_dossier_json()
    doc = json.loads(doc_text)
    leaves = {int(l["index"]): l for l in doc["leaves"]}
    salts = _disclose.read_salts(journal_path) if journal_path else {}
    payloads = payloads or {}
    discl = []
    for i in sorted(set(int(i) for i in indices)):
        if i not in leaves:
            raise IndexError(f"leaf {i} is not in the dossier (tree size {len(leaves)})")
        discl.append(_disclose.disclosure(leaves[i], payloads.get(i), salts.get(i)))

    os.makedirs(out_path, exist_ok=True)
    files = {
        "dossier.json": doc_text,
        "disclosures.json": json.dumps(discl, indent=2, sort_keys=True),
        "bindings.json": json.dumps(list(bindings or []), indent=2, sort_keys=True),
    }
    for name, text in files.items():
        with open(os.path.join(out_path, name), "w", encoding="utf-8") as f:
            f.write(text)
    manifest = {name: _sha256_file(os.path.join(out_path, name)) for name in sorted(files)}
    with open(os.path.join(out_path, "MANIFEST.sha256"), "w", encoding="utf-8") as f:
        for name, digest in manifest.items():
            f.write(f"{digest}  {name}\n")
    return manifest
