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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Verdict is the four-valued result of SPEC.md §9.2.
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
	// Diverged: a cryptographic, identity, structural or key-binding check
	// failed.
	Diverged
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
	// ExitUsage is for unreadable or unparseable input, distinct from any
	// verdict about a dossier.
	ExitUsage = 2
)

var verdictUpper = [...]string{"WITNESSED", "CONSISTENT-UNWITNESSED", "UNANCHORED", "DIVERGED"}
var verdictSnake = [...]string{"witnessed", "consistent_unwitnessed", "unanchored", "diverged"}

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
	}
	return ExitDiverged
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
	// directory. Zero means DefaultThreshold.
	Threshold float64
	// MinReceipts, when set, replaces the fraction gate with an absolute
	// count of valid receipts from distinct witnesses in the directory.
	MinReceipts *int
	// Revocations the verifier knows about out of band. They apply whether
	// or not the dossier carries them; statements for other identities are
	// ignored (SPEC §5).
	Revocations []Revocation
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
	Verdict                  Verdict `json:"verdict"`

	// Failures lists, in check order, what failed and why. Empty unless
	// Verdict is Diverged. Not part of the reference report's JSON; it is
	// serialised under "failures" so a Go caller can show the reason.
	Failures []string `json:"failures,omitempty"`
}

// VerifyDossier parses dossierJSON and verifies it offline. directory is
// the witness directory the CALLER trusts (nil means none was supplied and
// the verdict is capped at Unanchored). The returned error is non-nil only
// when the input cannot be parsed; every other outcome is a verdict.
func VerifyDossier(dossierJSON []byte, directory *Directory, opts Options) (Verdict, *Report, error) {
	d, err := ParseDossier(dossierJSON)
	if err != nil {
		return Diverged, nil, err
	}
	report := d.Verify(directory, opts)
	return report.Verdict, report, nil
}

// Verify is VerifyDossier on an already-parsed Dossier.
func (d *Dossier) Verify(directory *Directory, opts Options) *Report {
	threshold := opts.Threshold
	if threshold == 0 {
		threshold = DefaultThreshold
	}
	r := &Report{}

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
	if directory != nil && len(d.WitnessReceipts) > 0 {
		q := EvaluateQuorum(&d.Checkpoint, d.WitnessReceipts, directory, threshold)
		if opts.MinReceipts != nil {
			q.MeetsCountThreshold = q.ValidReceipts >= *opts.MinReceipts
			q.CountGate = "count >= " + strconv.Itoa(*opts.MinReceipts)
		}
		r.Quorum = q
	}

	r.InternallyConsistent = r.CheckpointSignatureValid && r.IdentityBound && r.LeavesStructurallyValid && r.BindingsValid && r.MerkleContinuityValid
	switch {
	case !r.InternallyConsistent:
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

const projectOperatedBucket = "__witness-log-project-operated__"

// normalizeLabel trims, lowercases and collapses whitespace runs, so an
// operator cannot inflate diversity with case or spacing variants.
func normalizeLabel(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

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

	for i := range receipts {
		r := &receipts[i]
		if r.Verify(sth) != nil {
			continue
		}
		key := normalizeHex(r.WitnessPubkey)
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
		if _, dup := counted[key]; dup {
			continue
		}
		counted[key] = struct{}{}
		operators[operatorKey(entry)] = struct{}{}
		if !entry.IsProjectOperated {
			op := normalizeLabel(entry.OperatorOrg)
			if subjectOperator == nil || *subjectOperator != op {
				independent[op] = struct{}{}
			}
		}
		providers[computeProviderKey(entry)] = struct{}{}
		if entry.IsProjectOperated {
			projectOperated++
		}
		if newest == nil || r.WitnessedAtMs > *newest {
			v := r.WitnessedAtMs
			newest = &v
		}
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
		SplitViewResistant:                  2*valid > len(directory.Witnesses),
		NewestTrustedWitnessMs:              newest,
	}
}
