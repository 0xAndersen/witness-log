# RFC-0005: Index-based revocation cut-off

Status: Draft
Target: 0.5.0 (new signed field with a presence byte; corpus vector; verifier rule)
Related: SPEC §5 (RevocationStatement), §9.1 (bindings and revocations), THREAT_MODEL "Key compromise, identity key"; review round 2, finding W2

## Problem

A `RevocationStatement` says "this identity key is revoked as of
`as_of_ms`". The verifier rejects leaves whose `timestamp_ms` is at or
after that instant and (since 0.4.2) checkpoints whose `timestamp_ms` is.
Both timestamps are written by whoever holds the key, and the party the
revocation defends against is exactly the party who now holds it. A
holder who backdates leaves and the checkpoint produces a dossier that
passes the cut-off; a verifier who does not have the revocation out of
band cannot tell a stripped revocation from one never issued.

0.4.2 closes the second gap (`VerifyContext::revocations`,
`verify --revocations`). This RFC closes the first.

## Proposal

1. `RevocationStatement` gains an optional `as_of_index: u64`: the tree
   size at which the revocation takes effect. The signed message becomes
   `"witness-log-revoke-v2" || identity_pubkey || as_of_ms || presence || [as_of_index] || reason`;
   v1 statements stay valid and keep the timestamp rule.
2. When `as_of_index` is present, a verifier rejects every leaf with
   `index >= as_of_index` and every checkpoint with `tree_size > as_of_index`,
   regardless of timestamps.
3. The operator who revokes is expected to hold a witnessed checkpoint of
   size `as_of_index` (the last good head). Witnesses already refuse to
   cosign a different root at that size, so a holder of the compromised
   key cannot rewrite history below the cut-off, and nothing above it
   verifies. The revocation and that checkpoint together are the
   operator's proof of where the honest record ends.
4. A witness that receives a revocation for a log it holds (new
   `POST /revoke` carrying the statement) records it and refuses to
   cosign any later size, so the cut-off is enforced before verification
   as well as at it.

## Compatibility

Additive: a presence byte on the new field keeps v1 statements
verifiable; a verifier that does not know v2 fails closed on the unknown
message prefix. Corpus vector 12 will carry a v2 statement with and
without the index.

## Open questions

- Whether `as_of_index` should be mandatory in v2 (simpler rule, but an
  operator who lost the last good size could not revoke at all).
- Whether the registry should carry revocations for registered logs so
  verifiers get them without an out-of-band channel.
