"""Commerce profiles: record a payment mandate and its settlement in a
witness-log journal in a shape the other side can bind to.

* :mod:`witness_log.profiles.ap2` -- Agent Payments Protocol mandates
  (IntentMandate / CartMandate / PaymentMandate)
* :mod:`witness_log.profiles.x402` -- x402 ``PaymentRequirements`` +
  ``PaymentPayload``, settlement response as the receipt
* :mod:`witness_log.profiles.vi` -- Verifiable Intent credentials, treated
  as an opaque signed object both sides hold

All three map onto the same four calls, defined in :mod:`.ap2` and
re-exported here: :func:`mandate_hash`, :func:`record_grant`,
:func:`record_receipt`, :func:`bind_profile_ap2`, plus
:func:`dispute_export`. The mandate hash is ``SHA-256(JCS(mandate))``
with JCS per RFC 8785 (:mod:`._jcs`), so a counterparty written in another
language reproduces it from the same JSON.

What this does not do: validate the mandate. ``user_authorization``,
``merchant_signature``, an EIP-712 signature or a credential's proof are
never checked here; use the protocol's own tooling for that. These helpers
make the record of what was done under the mandate unrewritable and
comparable across the two parties' logs.
"""

from __future__ import annotations

from ._jcs import canonicalize as jcs_canonicalize
from .ap2 import (
    bind_profile_ap2,
    dispute_export,
    mandate_hash,
    record_grant,
    record_receipt,
)

__all__ = [
    "jcs_canonicalize",
    "mandate_hash",
    "record_grant",
    "record_receipt",
    "bind_profile_ap2",
    "dispute_export",
]
