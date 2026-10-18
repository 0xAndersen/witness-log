"""Verifiable Intent profile: the credential is an opaque signed object
both sides hold; the transaction outcome is the receipt.

::

    from witness_log.profiles import vi

    vi.record_grant(consumer_log, credential, counterparty=MERCHANT)                # granted_by_me
    vi.record_grant(merchant_log, credential, counterparty=CONSUMER, scope="granted_to_me")
    vi.record_receipt(merchant_log, outcome, network="card", tx_ref="auth_...",
                      anchor_url="https://processor.example/receipts/auth_...")

The credential's public description lists no field schema, and with
selective disclosure the two parties may not even hold identical copies.
Hash what you both hold: the credential as presented (a JSON object or
the raw bytes of a compact serialisation). When the copies differ, agree
on a reference instead (``{"credential_id", "nonce"}``) and pass it as
the mandate with ``salted=True`` on both sides. Nothing here verifies
the credential; the issuer's tooling does.

Card rails have no CAIP-2 chain id. ``record_receipt`` accepts a
``network`` label (``"card"``, ``"ach"``, ...) and records it as the
CAIP-2-shaped ``offchain:<network>`` so the receipt has the same shape as
the chain-settled ones and ``bind_profile_ap2`` treats it alike.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional, Union

from . import ap2

__all__ = ["mandate_hash", "record_grant", "record_receipt", "bind", "offchain_chain_id"]

_NET = re.compile(r"^[a-z0-9][-a-z0-9]{0,31}$")


def offchain_chain_id(network: str) -> str:
    """``offchain:<network>``: a CAIP-2-shaped id for a non-chain rail."""
    n = str(network).lower()
    if not _NET.fullmatch(n):
        raise ValueError(f"network must be a short lowercase label like 'card' or 'ach', got {network!r}")
    return f"offchain:{n}"


def mandate_hash(credential: Union[Mapping[str, Any], bytes, str]) -> str:
    return ap2.mandate_hash(credential)


def record_grant(log: Any, credential: Union[Mapping[str, Any], bytes, str], *, counterparty: str, scope: str = "granted_by_me", **kw: Any) -> int:
    return ap2.record_grant(log, credential, counterparty=counterparty, scope=scope, **kw)


def record_receipt(
    log: Any,
    outcome: Mapping[str, Any],
    *,
    tx_ref: str,
    anchor_url: str,
    network: Optional[str] = None,
    chain_id: Optional[str] = None,
    account: Optional[str] = None,
    credential: Union[Mapping[str, Any], bytes, str, None] = None,
) -> int:
    """Anchor the transaction outcome. Give either ``chain_id`` (CAIP-2,
    for a chain-settled transaction) or ``network`` (a rail label, made
    into ``offchain:<network>``). ``credential`` embeds the credential's
    hash so the receipt names the intent it settled."""
    if (chain_id is None) == (network is None):
        raise ValueError("pass exactly one of chain_id= (CAIP-2) or network= (a rail label)")
    chain = chain_id if chain_id is not None else offchain_chain_id(str(network))
    return ap2.record_receipt(
        log, outcome, chain_id=chain, account=account, tx_ref=tx_ref, anchor_url=anchor_url, mandate=credential, profile="vi"
    )


def bind(dossier_a: Any, dossier_b: Any, *, credential: Union[Mapping[str, Any], bytes, str, None] = None, **kw: Any) -> Dict[str, Any]:
    """``ap2.bind_profile_ap2`` for a Verifiable Intent pair."""
    return ap2.bind_profile_ap2(dossier_a, dossier_b, mandate=credential, **kw)
