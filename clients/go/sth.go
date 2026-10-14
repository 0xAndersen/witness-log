package witnesslog

import (
	"encoding/hex"
	"errors"
	"strings"
)

// SigAlgEd25519 is the only sig_alg a checkpoint may carry today.
const SigAlgEd25519 = "ed25519"

// Verification errors shared by checkpoints, receipts, bindings and
// revocations.
var (
	ErrInvalidSignature     = errors.New("signature invalid")
	ErrMalformed            = errors.New("malformed key or signature bytes")
	ErrUnsupportedAlgorithm = errors.New("unsupported signature algorithm")
	ErrMismatch             = errors.New("receipt does not match the checkpoint it claims to witness")
	ErrSubsecondCosignature = errors.New("c2sp cosignature witnessed_at_ms is not a whole number of seconds")
	ErrNonCanonicalOrigin   = errors.New("c2sp_origin is not the canonical origin of the checkpoint signer")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexN(s string, n int) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

// normalizeHex lowercases a hex string for case-insensitive key comparison.
func normalizeHex(s string) string { return strings.ToLower(s) }

// STHMessage is the signed message of SPEC.md §6:
// "witness-log-sth-v2" || lp(sig_alg) || lp(signer_pubkey) || tree_size || root_hash || timestamp_ms.
func STHMessage(sigAlg, signerPubkeyHex string, treeSize uint64, root Hash, timestampMs uint64) []byte {
	msg := []byte("witness-log-sth-v2")
	msg = putLP(msg, sigAlg)
	msg = putLP(msg, signerPubkeyHex)
	msg = putU64(msg, treeSize)
	msg = append(msg, root[:]...)
	msg = putU64(msg, timestampMs)
	return msg
}

// Verify checks the checkpoint's signature under its own signer_pubkey.
func (s *SignedTreeHead) Verify() error {
	if s.SigAlg != SigAlgEd25519 {
		return ErrUnsupportedAlgorithm
	}
	rootB, ok := hexN(s.RootHash, 32)
	if !ok {
		return ErrMalformed
	}
	pk, ok := hexN(s.SignerPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sig, ok := hexN(s.Signature, 64)
	if !ok {
		return ErrMalformed
	}
	var root Hash
	copy(root[:], rootB)
	if !VerifyStrict(pk, STHMessage(s.SigAlg, s.SignerPubkey, s.TreeSize, root, s.TimestampMs), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// KeyBindingMessage is SPEC.md §5's binding message.
func KeyBindingMessage(identityPk, sessionPk []byte, sessionNumber, timestampMs uint64, notAfterMs *uint64) []byte {
	msg := []byte("witness-log-key-bind-v1")
	msg = append(msg, identityPk...)
	msg = append(msg, sessionPk...)
	msg = putU64(msg, sessionNumber)
	msg = putU64(msg, timestampMs)
	if notAfterMs != nil {
		msg = append(msg, 1)
		msg = putU64(msg, *notAfterMs)
	} else {
		msg = append(msg, 0)
	}
	return msg
}

// Verify checks the binding's signature under identity_pubkey. It does not
// check expiry; VerifyDossier applies not_after_ms per leaf.
func (b *KeyBinding) Verify() error {
	idPk, ok := hexN(b.IdentityPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sessPk, ok := hexN(b.SessionPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sig, ok := hexN(b.Signature, 64)
	if !ok {
		return ErrInvalidSignature
	}
	if !VerifyStrict(idPk, KeyBindingMessage(idPk, sessPk, b.SessionNumber, b.TimestampMs, b.NotAfterMs), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// RevocationMessage is SPEC.md §5's revocation message: v1 without an
// index, v2 (RFC-0005) with one, under distinct prefixes so neither
// signature verifies as the other.
func RevocationMessage(identityPk []byte, asOfMs uint64, asOfIndex *uint64, reason string) []byte {
	var msg []byte
	if asOfIndex == nil {
		msg = []byte("witness-log-revoke-v1")
		msg = append(msg, identityPk...)
		msg = putU64(msg, asOfMs)
	} else {
		msg = []byte("witness-log-revoke-v2")
		msg = append(msg, identityPk...)
		msg = putU64(msg, asOfMs)
		msg = append(msg, 0x01)
		msg = putU64(msg, *asOfIndex)
	}
	msg = append(msg, reason...)
	return msg
}

// Verify checks the revocation's signature under identity_pubkey.
func (r *Revocation) Verify() error {
	idPk, ok := hexN(r.IdentityPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sig, ok := hexN(r.Signature, 64)
	if !ok {
		return ErrInvalidSignature
	}
	if !VerifyStrict(idPk, RevocationMessage(idPk, r.AsOfMs, r.AsOfIndex, r.Reason), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// ReceiptMessage is SPEC.md §7's native receipt message.
func ReceiptMessage(witnessPubkeyHex, logSignerPubkeyHex string, treeSize uint64, rootHashHex string, witnessedAtMs uint64) []byte {
	msg := []byte("witness-log-witness-receipt-v2")
	msg = putLP(msg, witnessPubkeyHex)
	msg = putLP(msg, logSignerPubkeyHex)
	msg = putU64(msg, treeSize)
	msg = putLP(msg, rootHashHex)
	msg = putU64(msg, witnessedAtMs)
	return msg
}

// Verify checks a receipt against the checkpoint it claims to witness:
// size and root must match, and the signature must verify under
// witness_pubkey, either as a native receipt (§7) or, when c2sp_origin is
// set, as a c2sp.org/tlog-cosignature over the reconstructed checkpoint
// body (§9.3).
func (r *WitnessReceipt) Verify(against *SignedTreeHead) error {
	if r.TreeSize != against.TreeSize || r.RootHash != against.RootHash {
		return ErrMismatch
	}
	if r.C2SPOrigin != "" {
		return r.verifyC2SP(against)
	}
	pk, ok := hexN(r.WitnessPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sig, ok := hexN(r.Signature, 64)
	if !ok {
		return ErrMalformed
	}
	msg := ReceiptMessage(r.WitnessPubkey, against.SignerPubkey, r.TreeSize, r.RootHash, r.WitnessedAtMs)
	if !VerifyStrict(pk, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func (r *WitnessReceipt) verifyC2SP(against *SignedTreeHead) error {
	signer, ok := hexN(against.SignerPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	if r.C2SPOrigin != CanonicalOrigin(signer) {
		return ErrNonCanonicalOrigin
	}
	if r.WitnessedAtMs%1000 != 0 {
		return ErrSubsecondCosignature
	}
	rootB, ok := hexN(r.RootHash, 32)
	if !ok {
		return ErrMalformed
	}
	var root Hash
	copy(root[:], rootB)
	cp := Checkpoint{Origin: r.C2SPOrigin, TreeSize: r.TreeSize, RootHash: root}
	body, err := cp.NoteText()
	if err != nil {
		return ErrMalformed
	}
	msg := CosignatureMessage(r.WitnessedAtMs/1000, body)
	pk, ok := hexN(r.WitnessPubkey, 32)
	if !ok {
		return ErrMalformed
	}
	sig, ok := hexN(r.Signature, 64)
	if !ok {
		return ErrMalformed
	}
	if !VerifyStrict(pk, []byte(msg), sig) {
		return ErrInvalidSignature
	}
	return nil
}
