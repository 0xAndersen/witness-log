# Specification and interoperability

`spec/SPEC.md` is normative. `corpus/*.json` (11 vectors) is the
interoperability gate: an implementation that reproduces every value byte
for byte is wire-compatible; `witness-log conform <dir>` diffs yours
against it. `spec/dossier.schema.json` is the JSON Schema for the dossier.

## Primitives

- SHA-256 everywhere; RFC 6962 Merkle tree (leaf prefix 0x00, node prefix 0x01); inclusion and consistency proofs per RFC 6962/9162.
- Ed25519 with strict verification (`verify_strict`); identity and session keys.
- Length-prefixed binary leaf encoding (§3): fixed field order, `lp(x) = u32 BE length || bytes`. No JSON canonicalisation is involved in anything signed or hashed, which is why there is nothing to disagree about across languages.
- Signed messages: `"witness-log-sth-v2" || …` (checkpoint), `"witness-log-key-bind-v1" || …` (binding), `"witness-log-revoke-v1" || …`, `"witness-log-witness-receipt-v2" || …` (native receipt), `"witness-log-write-receipt-v1" || …` (write receipt for silence proofs).

## C2SP (the Certificate Transparency ecosystem)

witness-log checkpoints are expressible as `c2sp.org/tlog-checkpoint`
bodies in `c2sp.org/signed-note` envelopes; witnesses cosign with
`c2sp.org/tlog-cosignature` v1 over `c2sp.org/tlog-witness`. The
canonical origin is `witness-log/<identity key hex>`, so a witness can
verify a log's signature from the origin alone (open enrollment). Receipts
with `c2sp_origin` verify offline against
`"cosignature/v1\ntime <s>\n<body>"`. Vector 10 pins the bytes.

Consequence: an existing CT-style witness implementation can cosign
witness-log heads with no witness-log-specific code, and `witness-log c2sp
show --sign-with <journal> --raw` produces a note any C2SP verifier accepts.

## Implementing in another language

1. Reproduce `01_leaf_encoding.json` (encoding), `02_merkle_roots.json`, `03_inclusion_proofs.json`, `06_consistency_proof.json` (tree), `11_payload_hash.json` (§8 hash).
2. Reproduce `04_signed_tree_head.json`, `05_redaction_continuity.json`, `07`–`09` (leaf types), `10_c2sp_checkpoint.json`.
3. Emit a dossier that `witness-log verify` accepts; validate against the JSON Schema.
4. Run `witness-log conform <your-corpus-dir>`; zero diffs is the bar.

`CONTRIBUTING.md` describes the conformance-gate workflow for any change
to the wire format: spec, corpus and implementation move together.

## Standards lineage

RFC 6962 / RFC 9162 (Certificate Transparency), C2SP transparency-log
specifications, and the 1F916 Agent Record draft (four-valued anchor rule,
key custody). Where this spec deliberately departs (e.g. no JSON
canonicalisation, salted payload hashes), SPEC.md says so and why.
