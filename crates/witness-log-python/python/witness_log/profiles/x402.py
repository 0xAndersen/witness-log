"""x402 profile: the accepted ``PaymentRequirements`` plus the client's
``PaymentPayload`` are the mandate; the facilitator's settlement response
is the receipt.

::

    from witness_log.profiles import x402

    mandate = x402.mandate(requirements, payload)        # what both sides hold
    x402.record_grant(client_log, mandate, counterparty=SERVER)            # granted_by_me
    x402.record_grant(server_log, mandate, counterparty=CLIENT, scope="granted_to_me")
    x402.record_receipt(server_log, settlement_response, anchor_url="https://...")

x402 v2 already names the chain in CAIP-2 form (``network``) and the
settlement response carries ``transaction`` and ``payer``; this module
reads those and calls the AP2 profile's functions with them, so the
leaves bind with ``bind_profile_ap2`` unchanged. Nothing here checks the
EIP-712 signature in the payload; the facilitator does that.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union

from . import ap2

__all__ = ["mandate", "mandate_hash", "record_grant", "record_receipt", "bind"]


def mandate(requirements: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
    """The object both sides hash: the requirement the client ``accepted``
    and the payload it answered with. Both are JSON on the wire already."""
    return {"x402": 2, "requirements": dict(requirements), "payload": dict(payload)}


def mandate_hash(m: Union[Mapping[str, Any], bytes, str]) -> str:
    return ap2.mandate_hash(m)


def record_grant(log: Any, m: Union[Mapping[str, Any], bytes, str], *, counterparty: str, scope: str = "granted_by_me", **kw: Any) -> int:
    return ap2.record_grant(log, m, counterparty=counterparty, scope=scope, **kw)


def _network(settlement: Mapping[str, Any], requirements: Optional[Mapping[str, Any]]) -> str:
    net = settlement.get("network") or (requirements or {}).get("network")
    if not net:
        raise ValueError("no 'network' in the settlement response or requirements; pass chain_id=")
    return str(net)


def record_receipt(
    log: Any,
    settlement: Mapping[str, Any],
    *,
    anchor_url: str,
    requirements: Optional[Mapping[str, Any]] = None,
    chain_id: Optional[str] = None,
    account: Optional[str] = None,
    tx_ref: Optional[str] = None,
    mandate: Union[Mapping[str, Any], bytes, str, None] = None,
) -> int:
    """Anchor an x402 settlement response (``{"success", "transaction",
    "network", "payer", ...}``, the ``PAYMENT-RESPONSE`` header body).
    ``chain_id`` defaults to its ``network`` (CAIP-2), ``tx_ref`` to
    ``transaction``, ``account`` to ``<network>:<payer>`` (CAIP-10).
    ``anchor_url`` is where the transaction can be re-fetched."""
    chain = chain_id or _network(settlement, requirements)
    tx = tx_ref or settlement.get("transaction")
    if not tx:
        raise ValueError("no 'transaction' in the settlement response; pass tx_ref=")
    if account is None and settlement.get("payer"):
        account = f"{chain}:{settlement['payer']}"
    return ap2.record_receipt(
        log, settlement, chain_id=chain, account=account, tx_ref=str(tx), anchor_url=anchor_url, mandate=mandate, profile="x402"
    )


def bind(dossier_a: Any, dossier_b: Any, *, mandate: Union[Mapping[str, Any], bytes, str, None] = None, **kw: Any) -> Dict[str, Any]:
    """``ap2.bind_profile_ap2`` for an x402 pair."""
    return ap2.bind_profile_ap2(dossier_a, dossier_b, mandate=mandate, **kw)
