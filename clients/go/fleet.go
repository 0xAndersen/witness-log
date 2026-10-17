package witnesslog

// RFC-0001, EXPERIMENTAL: fleet checkpoint log anchors, in lockstep with
// the reference verifier (crates/witness-log-network/src/fleet.rs) and
// pinned by /corpus/14_fleet_anchor.json. A dossier's fleet_anchor is read
// only when Options.AcceptFleetAnchor is set; without it the verdict and
// every report field are what they are without the field, apart from
// Report.FleetAnchor saying it was ignored.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds on a fleet anchor, the same as the reference verifier's.
const (
	MaxFleetEntryBytes        = 4096
	MaxFleetNoteTextBytes     = 1024
	MaxFleetNoteBytes         = 64 * 1024
	MaxFleetNoteSignatures    = 64
	MaxInclusionProofHashes   = 64
	fleetAnchorStatusIgnored  = "ignored"
	fleetAnchorStatusVerified = "verified"
	fleetAnchorStatusFailed   = "failed"
)

// FleetAnchor is the dossier field of RFC-0001: where the dossier's
// checkpoint sits in an organisation's fleet checkpoint log, and that
// log's cosigned checkpoint.
type FleetAnchor struct {
	Origin              string   `json:"origin"`
	EntryIndex          uint64   `json:"entry_index"`
	EntryBytesB64       string   `json:"entry_bytes_b64"`
	InclusionProof      []string `json:"inclusion_proof"`
	FleetCheckpointNote string   `json:"fleet_checkpoint_note"`
}

// FleetAnchorReport says what the verifier did with a dossier's fleet
// anchor. Status is "ignored" (no opt-in), "verified" or "failed".
type FleetAnchorReport struct {
	Status        string   `json:"status"`
	Origin        *string  `json:"origin"`
	EntryIndex    *uint64  `json:"entry_index"`
	FleetTreeSize *uint64  `json:"fleet_tree_size"`
	Failures      []string `json:"failures"`
}

// WitnessedVia is "direct", "fleet" or "both" for a Witnessed verdict, and
// the empty value (JSON null) for any other verdict.
type WitnessedVia string

// MarshalJSON writes the empty value as null.
func (w WitnessedVia) MarshalJSON() ([]byte, error) {
	if w == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(w))
}

// PathCount is the distinct trusted witness keys on one path and the
// distinct independent operators among them.
type PathCount struct {
	Witnesses            int `json:"witnesses"`
	IndependentOperators int `json:"independent_operators"`
}

// WitnessPaths are the per-path counts reported when the caller opted in.
type WitnessPaths struct {
	Direct PathCount `json:"direct"`
	Fleet  PathCount `json:"fleet"`
	OnBoth int       `json:"on_both"`
}

// attestation is one witness key's verified statement on one path.
type attestation struct {
	key   string
	atMs  uint64
	fleet bool
}

// parseFleetAnchor reads the raw field the way the reference verifier's
// serde does: an object with all five fields of the right types (extra
// fields ignored). Anything else is a malformed anchor, never a parse
// error of the dossier.
func parseFleetAnchor(raw json.RawMessage) (*FleetAnchor, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("fleet_anchor: expected an object")
	}
	for _, k := range []string{"origin", "entry_index", "entry_bytes_b64", "inclusion_proof", "fleet_checkpoint_note"} {
		v, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("fleet_anchor: missing field %q", k)
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, fmt.Errorf("fleet_anchor: field %q is null", k)
		}
	}
	var proof []json.RawMessage
	if err := json.Unmarshal(m["inclusion_proof"], &proof); err != nil {
		return nil, fmt.Errorf("fleet_anchor: inclusion_proof: %w", err)
	}
	for _, p := range proof {
		if t := bytes.TrimSpace(p); len(t) == 0 || t[0] != '"' {
			return nil, fmt.Errorf("fleet_anchor: inclusion_proof holds a non-string")
		}
	}
	var a FleetAnchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("fleet_anchor: %w", err)
	}
	return &a, nil
}

// ValidFleetOrigin is a C2SP origin (non-empty, at most 255 bytes, no
// space, '+' or control character) that is not a witness-log agent origin.
func ValidFleetOrigin(origin string) bool {
	if origin == "" || len(origin) > 255 || strings.HasPrefix(origin, CanonicalOriginPrefix) {
		return false
	}
	for _, r := range origin {
		if r == ' ' || r == '+' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// decodeCanonicalBase64 accepts standard base64 with padding in its one
// canonical spelling only.
func decodeCanonicalBase64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// agentCheckpointFromEntry is RFC-0001 step 2's shape check: the entry is
// a checkpoint note for identity, with no extension lines, signed by it.
func agentCheckpointFromEntry(entry []byte, identity []byte) (*Checkpoint, error) {
	if len(entry) > MaxFleetEntryBytes {
		return nil, fmt.Errorf("entry is larger than %d bytes", MaxFleetEntryBytes)
	}
	if !utf8.Valid(entry) {
		return nil, fmt.Errorf("entry is not UTF-8")
	}
	note, err := ParseC2SPNote(string(entry))
	if err != nil {
		return nil, fmt.Errorf("entry is not a signed note: %w", err)
	}
	if len(note.Text) > MaxFleetNoteTextBytes {
		return nil, fmt.Errorf("entry checkpoint body is larger than %d bytes", MaxFleetNoteTextBytes)
	}
	cp, err := CheckpointFromNote(note)
	if err != nil {
		return nil, fmt.Errorf("entry is not a checkpoint note: %w", err)
	}
	if len(cp.Extensions) > 0 {
		return nil, fmt.Errorf("entry checkpoint has extension lines")
	}
	origin := CanonicalOrigin(identity)
	if cp.Origin != origin {
		return nil, fmt.Errorf("entry is a checkpoint of %s, not of this identity (%s)", cp.Origin, origin)
	}
	if _, err := note.Verify([]VerifierKey{NewEd25519VerifierKey(origin, identity)}); err != nil {
		return nil, fmt.Errorf("entry is not signed by this identity: %w", err)
	}
	return cp, nil
}

// FleetCosigner is a trusted witness whose cosignature on a fleet
// checkpoint verified.
type FleetCosigner struct {
	WitnessPubkey string // lowercase hex
	WitnessedAtMs uint64
}

// VerifiedFleetAnchor is what a fleet anchor that passed every check
// contributes.
type VerifiedFleetAnchor struct {
	FleetTreeSize uint64
	Cosigners     []FleetCosigner
}

// VerifyFleetAnchor is RFC-0001 steps 2-4 against the dossier's own
// checkpoint: the entry is this checkpoint signed by its identity, it is
// included in the fleet checkpoint, and the cosignature lines that verify
// under keys in directory (nil: none) are the cosigners. The fleet log's
// own signature is not a trust input and is not checked. A non-empty
// failures list means the anchor does not count.
func VerifyFleetAnchor(a *FleetAnchor, sth *SignedTreeHead, directory *Directory) (*VerifiedFleetAnchor, []string) {
	atts, size, fails := verifyFleetAnchor(a, sth, directory)
	if len(fails) > 0 {
		return nil, fails
	}
	v := &VerifiedFleetAnchor{FleetTreeSize: size}
	for _, at := range atts {
		v.Cosigners = append(v.Cosigners, FleetCosigner{WitnessPubkey: at.key, WitnessedAtMs: at.atMs})
	}
	return v, nil
}

func verifyFleetAnchor(a *FleetAnchor, sth *SignedTreeHead, directory *Directory) ([]attestation, uint64, []string) {
	fail := func(format string, args ...any) ([]attestation, uint64, []string) {
		return nil, 0, []string{fmt.Sprintf(format, args...)}
	}
	if !ValidFleetOrigin(a.Origin) {
		return fail("fleet origin %q is not a fleet log origin (a C2SP origin that is not witness-log/...)", a.Origin)
	}
	identity, ok := hexN(sth.SignerPubkey, 32)
	if !ok {
		return fail("the checkpoint's signer_pubkey is not an Ed25519 key")
	}
	entry, ok := decodeCanonicalBase64(a.EntryBytesB64)
	if !ok {
		return fail("entry_bytes_b64 is not canonical standard base64")
	}
	cp, err := agentCheckpointFromEntry(entry, identity)
	if err != nil {
		return fail("%v", err)
	}
	root, ok := hexN(sth.RootHash, 32)
	if !ok || cp.TreeSize != sth.TreeSize || !bytes.Equal(cp.RootHash[:], root) {
		return fail("the entry commits to size %d, not this checkpoint (size %d)", cp.TreeSize, sth.TreeSize)
	}

	if len(a.FleetCheckpointNote) > MaxFleetNoteBytes {
		return fail("fleet_checkpoint_note is larger than %d bytes", MaxFleetNoteBytes)
	}
	note, err := ParseC2SPNote(a.FleetCheckpointNote)
	if err != nil {
		return fail("fleet_checkpoint_note is not a signed note: %v", err)
	}
	if len(note.Text) > MaxFleetNoteTextBytes || len(note.Signatures) > MaxFleetNoteSignatures {
		return fail("fleet_checkpoint_note is larger than a witness accepts")
	}
	fleet, err := CheckpointFromNote(note)
	if err != nil {
		return fail("fleet_checkpoint_note is not a checkpoint: %v", err)
	}
	if fleet.Origin != a.Origin {
		return fail("the fleet checkpoint is for origin %q, not %q", fleet.Origin, a.Origin)
	}
	if len(a.InclusionProof) > MaxInclusionProofHashes {
		return fail("inclusion_proof is longer than any tree needs")
	}
	proof := make([]Hash, 0, len(a.InclusionProof))
	for _, h := range a.InclusionProof {
		b, ok := hexN(h, 32)
		if !ok {
			return fail("inclusion_proof holds a value that is not 32 bytes of hex")
		}
		var x Hash
		copy(x[:], b)
		proof = append(proof, x)
	}
	if a.EntryIndex >= fleet.TreeSize {
		return fail("entry_index %d is not inside the fleet checkpoint (size %d)", a.EntryIndex, fleet.TreeSize)
	}
	if !VerifyInclusion(LeafHash(entry), a.EntryIndex, fleet.TreeSize, proof, fleet.RootHash) {
		return fail("the inclusion proof for entry %d does not verify under the fleet checkpoint's root", a.EntryIndex)
	}

	var cosigners []attestation
	if directory != nil {
		for _, sig := range note.Signatures {
			for i := range directory.Witnesses {
				w := &directory.Witnesses[i]
				pk, ok := hexN(w.Pubkey, 32)
				if !ok || KeyID(sig.KeyName, SigTypeCosignatureV1, pk) != sig.KeyID {
					continue
				}
				cos, err := CosignatureFromNoteSignature(sig)
				if err != nil {
					continue
				}
				if cos.Verify(NewCosignatureVerifierKey(sig.KeyName, pk), note.Text) == nil {
					ms := uint64(math.MaxUint64)
					if cos.Timestamp <= math.MaxUint64/1000 {
						ms = cos.Timestamp * 1000
					}
					cosigners = append(cosigners, attestation{key: normalizeHex(w.Pubkey), atMs: ms, fleet: true})
				}
			}
		}
	}
	return cosigners, fleet.TreeSize, nil
}

// evaluateFleetAnchor is the reference's Dossier::evaluate_fleet_anchor:
// the report on d.FleetAnchor and, when it fully verifies, its cosigners.
func (d *Dossier) evaluateFleetAnchor(directory *Directory, opts Options) (*FleetAnchorReport, []attestation, bool) {
	if len(d.FleetAnchor) == 0 {
		return nil, nil, false
	}
	parsed, perr := parseFleetAnchor(d.FleetAnchor)
	report := &FleetAnchorReport{Status: fleetAnchorStatusIgnored, Failures: []string{}}
	if parsed != nil {
		origin, index := parsed.Origin, parsed.EntryIndex
		report.Origin, report.EntryIndex = &origin, &index
	}
	if !opts.AcceptFleetAnchor {
		return report, nil, false
	}
	report.Status = fleetAnchorStatusFailed
	if perr != nil {
		report.Failures = append(report.Failures, "fleet_anchor is not well-formed: "+perr.Error())
		return report, nil, false
	}
	if normalizeLabel(opts.SubjectOrg) == "" {
		report.Failures = append(report.Failures, "no subject_org: a fleet log is run by its agents' own organisation, and without knowing which one its own witnesses could count as independent")
		return report, nil, false
	}
	atts, size, fails := verifyFleetAnchor(parsed, &d.Checkpoint, directory)
	if len(fails) > 0 {
		report.Failures = fails
		return report, nil, false
	}
	report.Status = fleetAnchorStatusVerified
	report.FleetTreeSize = &size
	return report, atts, true
}
