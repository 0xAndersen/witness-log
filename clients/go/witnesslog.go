// Package witnesslog verifies witness-log dossiers from the specification
// alone (spec/SPEC.md), with no dependency on the Rust reference
// implementation and no dependencies outside the Go standard library.
//
// The entry point is VerifyDossier. It reproduces the reference verifier's
// four-valued verdict and its report field for field, so a Go gate and a
// `witness-log verify` gate reach the same decision on the same input:
//
//	verdict, report, err := witnesslog.VerifyDossier(dossierJSON, trustedDirectory, witnesslog.Options{
//	    ExpectedIdentityPubkey: pinnedHex,
//	})
//	if err != nil { /* unparseable input: a problem with the call, not a verdict */ }
//	if verdict != witnesslog.Witnessed { /* do not proceed */ }
//
// The package also exposes the building blocks: RFC 6962 inclusion and
// consistency proofs, strict Ed25519 verification, the seven leaf
// encodings, C2SP signed-note parsing and cosignature verification,
// cross-log binding (SPEC.md §3.1–§3.2) and selective disclosure (§8).
// Every one of them is checked against /corpus in this module's tests.
package witnesslog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Verdict is the five-valued result of SPEC.md §9.2 (RFC-0002 split
// DIVERGED into DIVERGED and INVALID in 0.5.0).
type Verdict int

// Verdicts, strongest first. Diverged takes precedence over the others.
const (
	// Witnessed: every check passes, a trusted directory was supplied,
	// and valid receipts from at least two distinct independent operators
	// in that directory meet the count gate.
	Witnessed Verdict = iota
	// ConsistentUnwitnessed: every check passes and a trusted directory
	// was supplied, but witness coverage is absent, below the gate, or
	// from fewer than two independent operators.
	ConsistentUnwitnessed
	// Unanchored: every check passes but no trusted directory was
	// supplied. This is the ceiling for a fabricated dossier.
	Unanchored
	// Diverged: the dossier is valid but contradicts evidence the verifier
	// supplied about the same identity (a known head, an equivocation
	// proof). Since 0.5.0; one file on its own is never Diverged.
	Diverged
	// Invalid: a cryptographic, identity, structural, key-binding or
	// revocation check failed. Reported as Diverged before 0.5.0.
	Invalid
)

// MinIndependentOperatorsForWitnessed is the floor at which equivocation
// becomes detectable at all.
const MinIndependentOperatorsForWitnessed = 2

// DefaultThreshold is `witness-log verify`'s default quorum fraction.
const DefaultThreshold = 0.66

// Exit codes, identical to the Rust CLI's: the verdict is the exit status.
const (
	ExitWitnessed             = 0
	ExitConsistentUnwitnessed = 10
	ExitUnanchored            = 20
	ExitDiverged              = 30
	ExitInvalid               = 40
	// ExitSplitViewUnsafe is strict mode's (the default) exit for a
	// Witnessed verdict whose cosigners are not a strict majority of the
	// directory.
	ExitSplitViewUnsafe = 11
	// ExitUsage is for unreadable or unparseable input, distinct from any
	// verdict about a dossier.
	ExitUsage = 2
)

var verdictUpper = [...]string{"WITNESSED", "CONSISTENT-UNWITNESSED", "UNANCHORED", "DIVERGED", "INVALID"}
var verdictSnake = [...]string{"witnessed", "consistent_unwitnessed", "unanchored", "diverged", "invalid"}

// String is the CLI's display form (WITNESSED, CONSISTENT-UNWITNESSED, ...).
func (v Verdict) String() string {
	if int(v) < 0 || int(v) >= len(verdictUpper) {
		return "UNKNOWN"
	}
	return verdictUpper[v]
}

// ExitCode maps the verdict to the CLI's exit status.
func (v Verdict) ExitCode() int {
	switch v {
	case Witnessed:
		return ExitWitnessed
	case ConsistentUnwitnessed:
		return ExitConsistentUnwitnessed
	case Unanchored:
		return ExitUnanchored
	case Diverged:
		return ExitDiverged
	}
	return ExitInvalid
}

// ExitCode is the exit status `witness-log verify` returns for this report
// under strict mode (the default): the verdict's code, or 11 for a
// Witnessed verdict that is split-view unsafe unless allowSubMajority.
func (r *Report) ExitCode(allowSubMajority bool) int {
	if r.SplitViewUnsafe && !allowSubMajority {
		return ExitSplitViewUnsafe
	}
	return r.Verdict.ExitCode()
}

// MarshalJSON writes the reference report's snake_case form.
func (v Verdict) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(verdictSnake) {
		return nil, fmt.Errorf("verdict: unknown value %d", int(v))
	}
	return json.Marshal(verdictSnake[v])
}

// UnmarshalJSON accepts the snake_case form.
func (v *Verdict) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for i, name := range verdictSnake {
		if name == s {
			*v = Verdict(i)
			return nil
		}
	}
	return fmt.Errorf("verdict: unknown variant %q", s)
}

// Options are the inputs a verifier controls, as distinct from anything
// read from the dossier under test (SPEC.md §9.1).
type Options struct {
	// ExpectedIdentityPubkey, when non-empty, must equal the checkpoint's
	// signer (case-insensitively) or the verdict is Diverged. Obtain it
	// out-of-band; never read it from the dossier.
	ExpectedIdentityPubkey string
	// Threshold is the quorum gate as a fraction of the trusted
	// directory. Zero means DefaultThreshold unless ThresholdSet is true.
	Threshold float64
	// ThresholdSet makes Threshold apply as given, zero included, as the
	// reference applies `witness-log verify --threshold 0` (every receipt
	// count meets a zero fraction).
	ThresholdSet bool
	// MinReceipts, when set, replaces the fraction gate with an absolute
	// count of valid receipts from distinct witnesses in the directory.
	MinReceipts *int
	// Revocations the verifier knows about out of band. They apply whether
	// or not the dossier carries them; statements for other identities are
	// ignored (SPEC §5).
	Revocations []Revocation
	// KnownHeads the verifier already trusts for this identity; a dossier
	// whose leaves do not reproduce one is Diverged (RFC-0002).
	KnownHeads []KnownHead
	// Evidence holds witness equivocation proofs; one that verifies for
	// this identity makes the verdict Diverged.
	Evidence []EquivocationProof
	// SubjectOrg is the organisation that operates this log, as the
	// verifier knows it. Witnesses with that operator_org never count as
	// independent operators for this dossier.
	SubjectOrg string
	// AcceptFleetAnchor (RFC-0001, EXPERIMENTAL) counts the cosigners of a
	// fleet checkpoint that includes this dossier's checkpoint, when the
	// dossier's fleet_anchor fully verifies. It needs SubjectOrg (the
	// organisation that runs the fleet log). False ignores the field.
	AcceptFleetAnchor bool
}

// KnownHead is a (tree size, root) the verifier already trusts.
type KnownHead struct {
	TreeSize uint64
	RootHash Hash
}

// ParseKnownHead reads "<size>:<root hex>".
func ParseKnownHead(s string) (KnownHead, error) {
	size, root, ok := strings.Cut(s, ":")
	if !ok {
		return KnownHead{}, fmt.Errorf("expected <size>:<root hex>, got %q", s)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(size), 10, 64)
	if err != nil || strings.TrimSpace(size) != strconv.FormatUint(n, 10) {
		return KnownHead{}, fmt.Errorf("size %q is not a canonical decimal integer", size)
	}
	b, err := hex.DecodeString(strings.TrimSpace(root))
	if err != nil || len(b) != 32 {
		return KnownHead{}, fmt.Errorf("root %q is not 32 bytes of hex", root)
	}
	var h Hash
	copy(h[:], b)
	return KnownHead{TreeSize: n, RootHash: h}, nil
}

// EquivocationProof is a witness's evidence that one log signed two roots
// for one tree size (the JSON `witness serve` writes under "proof").
type EquivocationProof struct {
	Origin          string `json:"origin"`
	LogVkey         string `json:"log_vkey"`
	EarlierNote     string `json:"earlier_note"`
	ConflictingNote string `json:"conflicting_note"`
}

// ParseEvidence reads one evidence item as every verifier reads it: a JSON
// object that is the proof itself or, as `witness-log witness serve`
// writes it, carries the proof under "proof" ({"observed_unix", "kind":
// "equivocation", "proof": {...}}). The proof must be an object whose
// origin, log_vkey, earlier_note and conflicting_note are JSON strings;
// other keys are ignored. Anything else is an error (the caller's
// mistake, exit 2), never a proof that silently fails to verify. The
// reference (EquivocationProof::from_evidence) and TypeScript verifiers
// apply the same rule.
func ParseEvidence(raw []byte) (EquivocationProof, error) {
	var p EquivocationProof
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil || item == nil {
		return p, errors.New(`an evidence item must be a JSON object: a proof, or {"proof": {...}} as witness serve writes it`)
	}
	if inner, ok := item["proof"]; ok {
		item = nil
		if err := json.Unmarshal(inner, &item); err != nil || item == nil {
			return p, errors.New(`the evidence item's "proof" must be a JSON object`)
		}
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"origin", &p.Origin}, {"log_vkey", &p.LogVkey}, {"earlier_note", &p.EarlierNote}, {"conflicting_note", &p.ConflictingNote}} {
		v, ok := item[f.key]
		if !ok {
			return p, fmt.Errorf("equivocation proof is missing field %s", f.key)
		}
		// A JSON null would unmarshal into a string without error.
		if t := bytes.TrimLeft(v, " \t\r\n"); len(t) == 0 || t[0] != '"' || json.Unmarshal(v, f.dst) != nil {
			return p, fmt.Errorf("equivocation proof field %s must be a string", f.key)
		}
	}
	return p, nil
}

// Verify checks the proof with the key the canonical origin names: the
// proof's own log_vkey must be exactly that key (name, key ID, type and
// key), and both notes must verify under it, name the origin, and have one
// size and two roots. The key ID is computed from the origin, never read
// from the file.
func (p *EquivocationProof) Verify() bool {
	pub, ok := IdentityFromCanonicalOrigin(p.Origin)
	if !ok {
		return false
	}
	key := NewEd25519VerifierKey(p.Origin, pub)
	claimed, err := ParseVerifierKey(p.LogVkey)
	if err != nil || claimed.Name != key.Name || claimed.ID != key.ID || claimed.SigType != key.SigType || !bytes.Equal(claimed.PublicKey, key.PublicKey) {
		return false
	}
	read := func(text string) *Checkpoint {
		n, err := ParseC2SPNote(text)
		if err != nil {
			return nil
		}
		if _, err := n.Verify([]VerifierKey{key}); err != nil {
			return nil
		}
		c, err := CheckpointFromNote(n)
		if err != nil {
			return nil
		}
		return c
	}
	a, b := read(p.EarlierNote), read(p.ConflictingNote)
	return a != nil && b != nil && a.Origin == p.Origin && b.Origin == p.Origin &&
		a.TreeSize == b.TreeSize && a.RootHash != b.RootHash
}

// Quorum mirrors the reference QuorumResult field for field.
type Quorum struct {
	TreeSize                            uint64   `json:"tree_size"`
	ValidReceipts                       int      `json:"valid_receipts"`
	TotalDirectoryWitnesses             int      `json:"total_directory_witnesses"`
	DistinctOperatorsRepresented        int      `json:"distinct_operators_represented"`
	DistinctOperatorsInDirectory        int      `json:"distinct_operators_in_directory"`
	QuorumFraction                      float64  `json:"quorum_fraction"`
	DiversityFraction                   float64  `json:"diversity_fraction"`
	DistinctComputeProvidersRepresented int      `json:"distinct_compute_providers_represented"`
	DistinctComputeProvidersInDirectory int      `json:"distinct_compute_providers_in_directory"`
	ComputeDiversityFraction            float64  `json:"compute_diversity_fraction"`
	ProjectOperatedReceipts             int      `json:"project_operated_receipts"`
	DistinctIndependentOperators        int      `json:"distinct_independent_operators"`
	IndependentOperatorsRepresented     []string `json:"independent_operators_represented"`
	MeetsCountThreshold                 bool     `json:"meets_count_threshold"`
	CountGate                           string   `json:"count_gate"`
	SplitViewResistant                  bool     `json:"split_view_resistant"`
	NewestTrustedWitnessMs              *uint64  `json:"newest_trusted_witness_ms"`
}

// Report mirrors the reference DossierReport field for field. Callers
// gate on Verdict, not on the individual booleans.
type Report struct {
	CheckpointSignatureValid bool    `json:"checkpoint_signature_valid"`
	IdentityBound            bool    `json:"identity_bound"`
	LeavesStructurallyValid  bool    `json:"leaves_structurally_valid"`
	BindingsValid            bool    `json:"bindings_valid"`
	BindingsAsserted         bool    `json:"bindings_asserted"`
	LeafCount                uint64  `json:"leaf_count"`
	ClaimedTreeSize          uint64  `json:"claimed_tree_size"`
	MerkleContinuityValid    bool    `json:"merkle_continuity_valid"`
	ExternallyAnchored       bool    `json:"externally_anchored"`
	IdentityPinned           bool    `json:"identity_pinned"`
	InternallyConsistent     bool    `json:"internally_consistent"`
	Quorum                   *Quorum `json:"quorum"`
	// SplitViewUnsafe: Witnessed, but the cosigners are not a strict
	// majority of the directory (RFC-0002).
	SplitViewUnsafe bool `json:"split_view_unsafe"`
	// Failures lists, in check order, what failed and why. Empty unless
	// Verdict is Invalid. The wording is this implementation's; the
	// reference report carries its own under the same key.
	Failures []string `json:"failures"`
	// Contradictions lists the known heads and evidence the dossier
	// contradicts; empty unless Verdict is Diverged.
	Contradictions []string `json:"contradictions"`
	// KnownHeadsUnchecked lists known heads larger than the dossier.
	KnownHeadsUnchecked []string `json:"known_heads_unchecked"`
	Verdict             Verdict  `json:"verdict"`
	// FleetAnchor is set only when the dossier carries a fleet_anchor
	// (RFC-0001, EXPERIMENTAL).
	FleetAnchor *FleetAnchorReport `json:"fleet_anchor,omitempty"`
	// WitnessedVia and WitnessPaths are set only with
	// Options.AcceptFleetAnchor; WitnessedVia is then "direct", "fleet" or
	// "both" for a Witnessed verdict and null otherwise.
	WitnessedVia *WitnessedVia `json:"witnessed_via,omitempty"`
	WitnessPaths *WitnessPaths `json:"witness_paths,omitempty"`
}

// VerifyDossier parses dossierJSON and verifies it offline. directory is
// the witness directory the CALLER trusts (nil means none was supplied and
// the verdict is capped at Unanchored). The returned error is non-nil only
// when the input cannot be parsed; every other outcome is a verdict.
func VerifyDossier(dossierJSON []byte, directory *Directory, opts Options) (Verdict, *Report, error) {
	d, err := ParseDossier(dossierJSON)
	if err != nil {
		return Invalid, nil, err
	}
	report := d.Verify(directory, opts)
	return report.Verdict, report, nil
}

// Verify is VerifyDossier on an already-parsed Dossier.
func (d *Dossier) Verify(directory *Directory, opts Options) *Report {
	threshold := opts.Threshold
	if threshold == 0 && !opts.ThresholdSet {
		threshold = DefaultThreshold
	}
	r := &Report{Failures: []string{}, Contradictions: []string{}, KnownHeadsUnchecked: []string{}}

	if err := d.Checkpoint.Verify(); err == nil {
		r.CheckpointSignatureValid = true
	} else {
		r.Failures = append(r.Failures, "checkpoint signature: "+err.Error())
	}

	selfConsistent := normalizeHex(d.IdentityPubkey) == normalizeHex(d.Checkpoint.SignerPubkey)
	r.IdentityBound = selfConsistent
	if !selfConsistent {
		r.Failures = append(r.Failures, "identity: dossier identity_pubkey does not match checkpoint signer_pubkey")
	}
	if opts.ExpectedIdentityPubkey != "" {
		r.IdentityPinned = true
		if normalizeHex(opts.ExpectedIdentityPubkey) != normalizeHex(d.Checkpoint.SignerPubkey) {
			r.IdentityBound = false
			r.Failures = append(r.Failures, "identity: checkpoint signer_pubkey is not the expected identity")
		}
	}

	if err := ValidateSequence(d.Leaves); err == nil {
		r.LeavesStructurallyValid = true
	} else {
		r.Failures = append(r.Failures, "leaf structure: "+err.Error())
	}

	revocations := append([]Revocation(nil), d.Revocations...)
	for _, t := range opts.Revocations {
		if normalizeHex(t.IdentityPubkey) != normalizeHex(d.IdentityPubkey) {
			continue
		}
		dup := false
		for _, have := range d.Revocations {
			if have.Signature == t.Signature {
				dup = true
			}
		}
		if !dup {
			revocations = append(revocations, t)
		}
	}
	if err := bindingsAndRevocationsValid(d.Leaves, d.IdentityPubkey, d.KeyBindings, revocations, d.Checkpoint.TimestampMs, d.Checkpoint.TreeSize); err == nil {
		r.BindingsValid = true
	} else {
		r.Failures = append(r.Failures, "key bindings: "+err.Error())
	}
	r.BindingsAsserted = len(d.KeyBindings) > 0 || len(revocations) > 0

	hashes := make([]Hash, len(d.Leaves))
	for i := range d.Leaves {
		hashes[i] = d.Leaves[i].LeafHash()
	}
	root := MerkleRoot(hashes)
	r.LeafCount = uint64(len(d.Leaves))
	r.ClaimedTreeSize = d.Checkpoint.TreeSize
	sizeMatches := r.LeafCount == d.Checkpoint.TreeSize
	rootMatches := hex.EncodeToString(root[:]) == d.Checkpoint.RootHash
	r.MerkleContinuityValid = sizeMatches && rootMatches
	if !sizeMatches {
		r.Failures = append(r.Failures, fmt.Sprintf("merkle continuity: %d leaves but checkpoint claims tree_size %d", r.LeafCount, d.Checkpoint.TreeSize))
	} else if !rootMatches {
		r.Failures = append(r.Failures, "merkle continuity: rebuilt root does not match checkpoint root_hash")
	}

	r.ExternallyAnchored = directory != nil
	// RFC-0001 (experimental): read only with the opt-in.
	fleetReport, fleetCosigners, fleetVerified := d.evaluateFleetAnchor(directory, opts)
	r.FleetAnchor = fleetReport
	var paths WitnessPaths
	if directory != nil && (len(d.WitnessReceipts) > 0 || fleetVerified) {
		atts := directAttestations(&d.Checkpoint, d.WitnessReceipts)
		atts = append(atts, fleetCosigners...)
		q, p := scoreAttestations(&d.Checkpoint, atts, directory, threshold, opts.SubjectOrg)
		paths = p
		if opts.MinReceipts != nil {
			q.MeetsCountThreshold = q.ValidReceipts >= *opts.MinReceipts
			q.CountGate = "count >= " + strconv.Itoa(*opts.MinReceipts)
		}
		r.Quorum = q
	}

	r.InternallyConsistent = r.CheckpointSignatureValid && r.IdentityBound && r.LeavesStructurallyValid && r.BindingsValid && r.MerkleContinuityValid
	if r.InternallyConsistent {
		for _, kh := range opts.KnownHeads {
			if kh.TreeSize > uint64(len(hashes)) {
				r.KnownHeadsUnchecked = append(r.KnownHeadsUnchecked, fmt.Sprintf("%d:%s", kh.TreeSize, hex.EncodeToString(kh.RootHash[:])))
				continue
			}
			prefix := MerkleRoot(hashes[:kh.TreeSize])
			if prefix != kh.RootHash {
				r.Contradictions = append(r.Contradictions, fmt.Sprintf("known head %d:%s is not what this dossier's first %d leaves produce (%s)", kh.TreeSize, hex.EncodeToString(kh.RootHash[:]), kh.TreeSize, hex.EncodeToString(prefix[:])))
			}
		}
		if pub, ok := hexN(d.IdentityPubkey, 32); ok {
			origin := CanonicalOrigin(pub)
			for i := range opts.Evidence {
				if opts.Evidence[i].Origin == origin && opts.Evidence[i].Verify() {
					r.Contradictions = append(r.Contradictions, "witness evidence: this identity signed two different roots for one tree size ("+origin+")")
				}
			}
		}
	}
	switch {
	case !r.InternallyConsistent:
		r.Verdict = Invalid
	case len(r.Contradictions) > 0:
		r.Verdict = Diverged
	case !r.ExternallyAnchored:
		r.Verdict = Unanchored
	case r.Quorum == nil || !r.Quorum.MeetsCountThreshold:
		r.Verdict = ConsistentUnwitnessed
	case r.Quorum.DistinctIndependentOperators >= MinIndependentOperatorsForWitnessed:
		r.Verdict = Witnessed
	default:
		r.Verdict = ConsistentUnwitnessed
	}
	r.SplitViewUnsafe = r.Verdict == Witnessed && (r.Quorum == nil || !r.Quorum.SplitViewResistant)
	if opts.AcceptFleetAnchor {
		via := WitnessedVia("")
		if r.Verdict == Witnessed {
			switch {
			case paths.Fleet.Witnesses-paths.OnBoth == 0:
				via = "direct"
			case paths.Direct.Witnesses == 0:
				via = "fleet"
			default:
				via = "both"
			}
		}
		r.WitnessedVia = &via
		r.WitnessPaths = &paths
	}
	return r
}

// bindingsAndRevocationsValid is SPEC.md §9.1's self-consistency rule for
// key bindings: with none supplied the property is "not asserted" (valid);
// otherwise every binding and revocation must name this identity and
// verify, every leaf's session key must have a binding, no leaf may fall
// after its binding's not_after_ms, and no leaf may be at or after the
// earliest revocation.
func bindingsAndRevocationsValid(leaves []Leaf, identity string, bindings []KeyBinding, revocations []Revocation, checkpointTimestampMs, checkpointTreeSize uint64) error {
	if len(bindings) == 0 && len(revocations) == 0 {
		return nil
	}
	bySession := make(map[string]*KeyBinding, len(bindings))
	for i := range bindings {
		b := &bindings[i]
		if normalizeHex(b.IdentityPubkey) != normalizeHex(identity) {
			return fmt.Errorf("binding for session %s names a different identity", short(b.SessionPubkey))
		}
		if err := b.Verify(); err != nil {
			return fmt.Errorf("binding for session %s: %w", short(b.SessionPubkey), err)
		}
		bySession[normalizeHex(b.SessionPubkey)] = b
	}
	for i := range revocations {
		rv := &revocations[i]
		if normalizeHex(rv.IdentityPubkey) != normalizeHex(identity) {
			return fmt.Errorf("revocation names a different identity")
		}
		if err := rv.Verify(); err != nil {
			return fmt.Errorf("revocation: %w", err)
		}
	}
	for i := range leaves {
		l := &leaves[i]
		b, ok := bySession[normalizeHex(l.SessionPubkey)]
		if !ok {
			return fmt.Errorf("leaf %d: session key %s has no binding in this dossier", l.Index, short(l.SessionPubkey))
		}
		if b.NotAfterMs != nil && l.TimestampMs > *b.NotAfterMs {
			return fmt.Errorf("leaf %d: timestamp is after its session binding's not_after_ms", l.Index)
		}
	}
	return revocationCutOff(revocations, leaves, checkpointTimestampMs, checkpointTreeSize)
}

// revocationCutOff applies SPEC §5 to already-verified revocations: no leaf
// and no checkpoint at or after the earliest as_of_ms, and (RFC-0005) no
// leaf at or past the smallest as_of_index and no head larger than it.
func revocationCutOff(revocations []Revocation, leaves []Leaf, checkpointTimestampMs, checkpointTreeSize uint64) error {
	var revokedAsOf, revokedAtIndex *uint64
	for i := range revocations {
		rv := &revocations[i]
		if revokedAsOf == nil || rv.AsOfMs < *revokedAsOf {
			v := rv.AsOfMs
			revokedAsOf = &v
		}
		if rv.AsOfIndex != nil && (revokedAtIndex == nil || *rv.AsOfIndex < *revokedAtIndex) {
			v := *rv.AsOfIndex
			revokedAtIndex = &v
		}
	}
	if revokedAsOf != nil {
		if checkpointTimestampMs >= *revokedAsOf {
			return fmt.Errorf("checkpoint is signed at or after the identity's revocation")
		}
		for i := range leaves {
			if leaves[i].TimestampMs >= *revokedAsOf {
				return fmt.Errorf("leaf %d: timestamp is at or after the identity's revocation", leaves[i].Index)
			}
		}
	}
	if revokedAtIndex != nil {
		if checkpointTreeSize > *revokedAtIndex {
			return fmt.Errorf("checkpoint tree_size %d is past the revocation index %d", checkpointTreeSize, *revokedAtIndex)
		}
		for i := range leaves {
			if leaves[i].Index >= *revokedAtIndex {
				return fmt.Errorf("leaf %d is at or past the revocation index %d", leaves[i].Index, *revokedAtIndex)
			}
		}
	}
	return nil
}

func short(hexKey string) string {
	if len(hexKey) > 16 {
		return hexKey[:16] + "…"
	}
	return hexKey
}

// projectOperatedBucket is the reference's PROJECT_OPERATED_BUCKET, NULs
// included, so no operator_org label collides with it here and not there.
const projectOperatedBucket = "\x00witness-log-project-operated\x00"

func operatorKey(w *WitnessEntry) string {
	if w.IsProjectOperated {
		return projectOperatedBucket
	}
	return normalizeLabel(w.OperatorOrg)
}

func computeProviderKey(w *WitnessEntry) string {
	if w.IsProjectOperated {
		return projectOperatedBucket
	}
	if w.ComputeProvider == nil {
		return "undisclosed"
	}
	return normalizeLabel(*w.ComputeProvider)
}

// DistinctOperatorCount buckets every project-operated witness together.
func (d *Directory) DistinctOperatorCount() int {
	set := map[string]struct{}{}
	for i := range d.Witnesses {
		set[operatorKey(&d.Witnesses[i])] = struct{}{}
	}
	return len(set)
}

// DistinctComputeProviderCount scores non-disclosure as its own bucket.
func (d *Directory) DistinctComputeProviderCount() int {
	set := map[string]struct{}{}
	for i := range d.Witnesses {
		set[computeProviderKey(&d.Witnesses[i])] = struct{}{}
	}
	return len(set)
}

// formatFloat renders a float the way Rust's Display for f64 does for the
// values a threshold takes (0.66 -> "0.66", 1 -> "1").
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// EvaluateQuorum scores receipts against a trusted directory exactly as the
// reference evaluate_quorum does: only receipts that verify against the
// checkpoint and whose witness key is in the directory count, each witness
// key counts once, project-operated witnesses collapse to one bucket, and
// the subject's own operator (if its signing key is in the directory)
// never counts as independent.
func EvaluateQuorum(sth *SignedTreeHead, receipts []WitnessReceipt, directory *Directory, threshold float64) *Quorum {
	return EvaluateQuorumForSubject(sth, receipts, directory, threshold, "")
}

// EvaluateQuorumForSubject is EvaluateQuorum when the verifier knows which
// organisation operates the log: witnesses with that operator_org count
// toward the receipt total but never as independent operators.
func EvaluateQuorumForSubject(sth *SignedTreeHead, receipts []WitnessReceipt, directory *Directory, threshold float64, subjectOrg string) *Quorum {
	q, _ := scoreAttestations(sth, directAttestations(sth, receipts), directory, threshold, subjectOrg)
	return q
}

// directAttestations are the receipts that verify against sth, in order.
func directAttestations(sth *SignedTreeHead, receipts []WitnessReceipt) []attestation {
	var out []attestation
	for i := range receipts {
		r := &receipts[i]
		if r.Verify(sth) != nil {
			continue
		}
		out = append(out, attestation{key: normalizeHex(r.WitnessPubkey), atMs: r.WitnessedAtMs})
	}
	return out
}

// scoreAttestations is the quorum over verified attestations plus the
// per-path counts, as the reference's score_attestations: each witness key
// counts once (direct attestations come first and set its time), and only
// keys with a direct receipt count toward SplitViewResistant.
func scoreAttestations(sth *SignedTreeHead, atts []attestation, directory *Directory, threshold float64, subjectOrg string) (*Quorum, WitnessPaths) {
	declaredSubject := normalizeLabel(subjectOrg)
	var subjectOperator *string
	for i := range directory.Witnesses {
		if normalizeHex(directory.Witnesses[i].Pubkey) == normalizeHex(sth.SignerPubkey) {
			op := operatorKey(&directory.Witnesses[i])
			subjectOperator = &op
			break
		}
	}
	operators := map[string]struct{}{}
	providers := map[string]struct{}{}
	counted := map[string]struct{}{}
	independent := map[string]struct{}{}
	projectOperated := 0
	var newest *uint64
	directKeys, fleetKeys := map[string]struct{}{}, map[string]struct{}{}
	directIndep, fleetIndep := map[string]struct{}{}, map[string]struct{}{}

	for _, at := range atts {
		key := at.key
		var entry *WitnessEntry
		for j := range directory.Witnesses {
			if normalizeHex(directory.Witnesses[j].Pubkey) == key {
				entry = &directory.Witnesses[j]
				break
			}
		}
		if entry == nil {
			continue
		}
		indepOp, isIndep := "", false
		if !entry.IsProjectOperated {
			op := normalizeLabel(entry.OperatorOrg)
			if (subjectOperator == nil || *subjectOperator != op) && (declaredSubject == "" || declaredSubject != op) {
				indepOp, isIndep = op, true
			}
		}
		pathKeys, pathIndep := directKeys, directIndep
		if at.fleet {
			pathKeys, pathIndep = fleetKeys, fleetIndep
		}
		pathKeys[key] = struct{}{}
		if isIndep {
			pathIndep[indepOp] = struct{}{}
		}
		if _, dup := counted[key]; dup {
			continue
		}
		counted[key] = struct{}{}
		operators[operatorKey(entry)] = struct{}{}
		if isIndep {
			independent[indepOp] = struct{}{}
		}
		providers[computeProviderKey(entry)] = struct{}{}
		if entry.IsProjectOperated {
			projectOperated++
		}
		if newest == nil || at.atMs > *newest {
			v := at.atMs
			newest = &v
		}
	}
	onBoth := 0
	for k := range directKeys {
		if _, ok := fleetKeys[k]; ok {
			onBoth++
		}
	}
	paths := WitnessPaths{
		Direct: PathCount{Witnesses: len(directKeys), IndependentOperators: len(directIndep)},
		Fleet:  PathCount{Witnesses: len(fleetKeys), IndependentOperators: len(fleetIndep)},
		OnBoth: onBoth,
	}

	valid := len(counted)
	total := len(directory.Witnesses)
	if total < 1 {
		total = 1
	}
	opsInDir := directory.DistinctOperatorCount()
	if opsInDir < 1 {
		opsInDir = 1
	}
	provInDir := directory.DistinctComputeProviderCount()
	if provInDir < 1 {
		provInDir = 1
	}
	indepList := make([]string, 0, len(independent))
	for op := range independent {
		indepList = append(indepList, op)
	}
	sort.Strings(indepList)
	fraction := float64(valid) / float64(total)
	return &Quorum{
		TreeSize:                            sth.TreeSize,
		ValidReceipts:                       valid,
		TotalDirectoryWitnesses:             len(directory.Witnesses),
		DistinctOperatorsRepresented:        len(operators),
		DistinctOperatorsInDirectory:        opsInDir,
		QuorumFraction:                      fraction,
		DiversityFraction:                   float64(len(operators)) / float64(opsInDir),
		DistinctComputeProvidersRepresented: len(providers),
		DistinctComputeProvidersInDirectory: provInDir,
		ComputeDiversityFraction:            float64(len(providers)) / float64(provInDir),
		ProjectOperatedReceipts:             projectOperated,
		DistinctIndependentOperators:        len(independent),
		IndependentOperatorsRepresented:     indepList,
		MeetsCountThreshold:                 fraction >= threshold,
		CountGate:                           "fraction >= " + formatFloat(threshold),
		SplitViewResistant:                  2*len(directKeys) > len(directory.Witnesses),
		NewestTrustedWitnessMs:              newest,
	}, paths
}
