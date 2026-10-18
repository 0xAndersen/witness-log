// Command witness-log-verify verifies a witness-log dossier offline with
// the pure-Go verifier. Its exit status is the verdict, with the same
// codes as `witness-log verify`: 0 WITNESSED, 11 WITNESSED by fewer than a
// strict majority of the directory (strict is the default since 0.5.0),
// 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30 DIVERGED, 40 INVALID,
// 2 usage or unreadable input.
//
//	witness-log-verify <dossier.json> [--identity <hex>] [--directory <dir.json>]
//	                   [--threshold 0.0-1.0 | --min-witnesses N]
//	                   [--allow-sub-majority] [--revocations <file>]
//	                   [--known-head <size>:<root>] [--evidence <file>]
//	                   [--subject-org ORG] [--accept-fleet-anchor] [--json]
//	witness-log-verify bind <a.json> <b.json> [--json]
//	witness-log-verify disclose <dossier.json> <leaf-index> <payload-file> <salt-hex>
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	witnesslog "github.com/0xAndersen/witness-log/clients/go"
)

const usage = `witness-log-verify — offline dossier verification in Go

USAGE:
  witness-log-verify <dossier.json> [--identity <hex>] [--directory <dir.json>]
                     [--threshold 0.0-1.0 | --min-witnesses N]
                     [--allow-sub-majority] [--revocations <file>]
                     [--known-head <size>:<root>] [--evidence <file>]
                     [--subject-org ORG] [--accept-fleet-anchor] [--json]
      --identity   the identity pubkey you expect, obtained out-of-band
      --directory  a witness directory YOU trust, obtained out-of-band
      --revocations  revocation statements you know of (JSON array or one object);
                   applied even when the dossier omits them
      --threshold  quorum gate as a fraction of the directory (default 0.66)
      --min-witnesses N  quorum gate as an absolute receipt count
      --allow-sub-majority  accept WITNESSED from fewer than a strict majority
                   of the directory as exit 0 instead of 11
      --known-head <size>:<root hex>  a head you already trust for this
                   identity (repeatable); not reproduced -> DIVERGED
      --evidence <file>  a witness equivocation proof (repeatable); if it
                   verifies for this identity -> DIVERGED
      --subject-org ORG  the organisation that operates this log; its own
                   witnesses never count as independent operators
      --accept-fleet-anchor  EXPERIMENTAL (RFC-0001): also count witnesses that
                   cosigned the fleet log holding this checkpoint (needs --subject-org)
      --json       machine-readable report (same fields as witness-log verify --json)
      --explain    accepted, as witness-log verify accepts it; prints nothing extra here

    Flags are parsed as witness-log verify parses them: an unknown flag is
    a usage error (exit 2) and a repeated flag keeps its last value.
    --no-strict, kept for one release after 0.5.0, is gone: a usage error.

  witness-log-verify bind <a.json> <b.json> [--json]
      Two different agents' dossiers: match their HandoffAttestation and
      AuthorizationEvent leaves (SPEC §3.1–§3.2). Exit 0 bound, 30 mismatch,
      10 nothing to bind.

  witness-log-verify disclose <dossier.json> <leaf-index> <payload-file> <salt-hex>
      Check that a disclosed payload and salt reproduce a leaf's payload_hash
      (SPEC §8). Exit 0 match, 30 mismatch.

EXIT CODES — the verdict IS the exit status:
   0  WITNESSED                30  DIVERGED (a contradiction with a head you
  11  WITNESSED by fewer than a      know, or verified equivocation evidence)
      strict majority of your  40  INVALID (a check failed: signature,
      directory (split-view risk)    identity, leaves, continuity, revocation)
  10  CONSISTENT-UNWITNESSED    2  usage / unreadable input
  20  UNANCHORED
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// positional returns the arguments that are not --flags, or an error
// naming the first --flag not in allowed (switches only), as the reference
// CLI's `bind` does. Unknown flags used to be skipped together with the
// argument after them (security review of 0.5.0, F6).
func positional(args []string, allowed ...string) ([]string, error) {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			out = append(out, a)
			continue
		}
		known := false
		for _, f := range allowed {
			known = known || a == f
		}
		if !known {
			return nil, fmt.Errorf("unrecognized flag: %s", a)
		}
	}
	return out, nil
}

// readEvidence reads a witness evidence file as `witness-log witness serve`
// writes it ({"kind": "equivocation", "proof": {...}}) or a bare proof,
// by the rule every verifier applies (witnesslog.ParseEvidence).
func readEvidence(path string) (witnesslog.EquivocationProof, error) {
	raw, err := readInput(path)
	if err != nil {
		return witnesslog.EquivocationProof{}, err
	}
	p, err := witnesslog.ParseEvidence(raw)
	if err != nil {
		return p, fmt.Errorf("not an equivocation proof: %v", err)
	}
	return p, nil
}

// verifyArgs is what `verify` was asked to do, parsed exactly as the
// reference CLI's parse_options parses it (crates/witness-log-cli): every
// flag is known or the run is a usage error (exit 2); a value flag takes
// the next argument whatever it looks like; a repeated single-value flag
// keeps its last value. --no-strict is a usage error since 0.6.0.
// Before this, unknown flags were skipped with the argument after them
// and the first of a repeated flag won, so a typo such as --evidance or
// --known-heads ran without the evidence the caller supplied (security
// review of 0.5.0, F6).
type verifyArgs struct {
	path            string
	threshold       float64
	thresholdSet    bool
	minWitnesses    *int
	json            bool
	identity        string
	directoryPath   *string
	revocationsPath *string
	strict          bool
	allowSub        bool
	knownHeads      []witnesslog.KnownHead
	evidencePaths   []string
	subjectOrg      string
	acceptFleet     bool
}

// noStrictRemoved is the reference CLI's message: RFC-0002 kept
// --no-strict for one release (0.5.x).
const noStrictRemoved = "--no-strict was removed in 0.6.0 (RFC-0002 kept it for one release). " +
	"A WITNESSED verdict from fewer than a strict majority of the directory exits 11; " +
	"--allow-sub-majority accepts it as exit 0"

// rustFloat is the grammar of Rust's f64::from_str for finite decimal
// values (the only ones --threshold accepts): no hex floats, underscores
// or spaces, which strconv.ParseFloat would otherwise take.
var rustFloat = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)

// rustUsize is the grammar of Rust's usize::from_str: digits, optionally
// after one '+'.
var rustUsize = regexp.MustCompile(`^\+?[0-9]+$`)

func isHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func parseVerifyArgs(args []string) (*verifyArgs, error) {
	a := &verifyArgs{threshold: witnesslog.DefaultThreshold, strict: true}
	havePath := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func(missing string) (string, error) {
			if i+1 >= len(args) {
				return "", errors.New(missing)
			}
			i++
			return args[i], nil
		}
		switch arg {
		case "--threshold":
			v, err := value("--threshold requires a value between 0.0 and 1.0")
			if err != nil {
				return nil, err
			}
			f, perr := strconv.ParseFloat(v, 64)
			if !rustFloat.MatchString(v) || perr != nil {
				return nil, fmt.Errorf("--threshold value '%s' is not a valid number", v)
			}
			if !(f >= 0 && f <= 1) {
				return nil, fmt.Errorf("--threshold must be between 0.0 and 1.0, got %s", v)
			}
			a.threshold, a.thresholdSet = f, true
		case "--revocations":
			v, err := value("--revocations requires a path")
			if err != nil {
				return nil, err
			}
			a.revocationsPath = &v
		case "--min-witnesses":
			v, err := value("--min-witnesses requires a positive integer")
			if err != nil {
				return nil, err
			}
			n, perr := strconv.ParseUint(strings.TrimPrefix(v, "+"), 10, 64)
			if !rustUsize.MatchString(v) || perr != nil || n > math.MaxInt {
				return nil, fmt.Errorf("--min-witnesses value '%s' is not a positive integer", v)
			}
			if n == 0 {
				return nil, errors.New("--min-witnesses must be at least 1")
			}
			m := int(n)
			a.minWitnesses = &m
		case "--json":
			a.json = true
		case "--explain":
			// Accepted as the reference accepts it; this verifier prints no
			// per-check explanations (`witness-log explain` does).
		case "--strict":
			a.strict = true
		case "--no-strict":
			return nil, errors.New(noStrictRemoved)
		case "--allow-sub-majority":
			a.allowSub = true
		case "--accept-fleet-anchor":
			a.acceptFleet = true
		case "--known-head":
			v, err := value("--known-head requires <size>:<root hex>")
			if err != nil {
				return nil, err
			}
			kh, perr := witnesslog.ParseKnownHead(v)
			if perr != nil {
				return nil, fmt.Errorf("--known-head: %v", perr)
			}
			a.knownHeads = append(a.knownHeads, kh)
		case "--evidence":
			v, err := value("--evidence requires a path to a witness evidence file")
			if err != nil {
				return nil, err
			}
			a.evidencePaths = append(a.evidencePaths, v)
		case "--identity":
			v, err := value("--identity requires a hex-encoded public key")
			if err != nil {
				return nil, err
			}
			if !isHex32(v) {
				return nil, fmt.Errorf("--identity must be a 32-byte Ed25519 public key as 64 hex characters, got '%s'", v)
			}
			a.identity = v
		case "--directory":
			v, err := value("--directory requires a path to a trusted witness directory JSON file")
			if err != nil {
				return nil, err
			}
			a.directoryPath = &v
		case "--subject-org":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") || strings.TrimSpace(args[i+1]) == "" {
				return nil, errors.New("--subject-org requires the organisation that operates this log")
			}
			i++
			a.subjectOrg = args[i]
		default:
			if strings.HasPrefix(arg, "--") {
				return nil, fmt.Errorf("unrecognized flag: %s", arg)
			}
			if havePath {
				return nil, fmt.Errorf("unexpected extra argument: '%s' (path already set)", arg)
			}
			a.path, havePath = arg, true
		}
	}
	if !havePath {
		return nil, errors.New(strings.TrimSpace(usage))
	}
	if a.acceptFleet && a.subjectOrg == "" {
		return nil, errors.New("--accept-fleet-anchor requires --subject-org ORG: the organisation that runs the fleet log (and its agents), whose own witnesses never count as independent")
	}
	return a, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return witnesslog.ExitUsage
		}
		return 0
	}
	switch args[0] {
	case "bind":
		return runBind(args[1:], stdout, stderr)
	case "disclose":
		return runDisclose(args[1:], stdout, stderr)
	}
	return runVerify(args, stdout, stderr)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	// As the reference: --help or -h anywhere prints the usage.
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Fprint(stdout, usage)
			return 0
		}
	}
	a, err := parseVerifyArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return witnesslog.ExitUsage
	}
	path := a.path
	opts := witnesslog.Options{
		ExpectedIdentityPubkey: a.identity,
		Threshold:              a.threshold,
		ThresholdSet:           true,
		MinReceipts:            a.minWitnesses,
		KnownHeads:             a.knownHeads,
		SubjectOrg:             a.subjectOrg,
		AcceptFleetAnchor:      a.acceptFleet,
	}
	var directory *witnesslog.Directory
	if p := a.directoryPath; p != nil {
		raw, err := readInput(*p)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *p, err)
			return witnesslog.ExitUsage
		}
		directory, err = witnesslog.ParseDirectory(raw)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *p, err)
			return witnesslog.ExitUsage
		}
	}
	if p := a.revocationsPath; p != nil {
		raw, err := readInput(*p)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *p, err)
			return witnesslog.ExitUsage
		}
		revs, err := witnesslog.ParseRevocations(raw)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *p, err)
			return witnesslog.ExitUsage
		}
		opts.Revocations = revs
	}
	for _, ep := range a.evidencePaths {
		p, err := readEvidence(ep)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", ep, err)
			return witnesslog.ExitUsage
		}
		opts.Evidence = append(opts.Evidence, p)
	}
	strict := a.strict
	allowSubFlag := a.allowSub
	allowSub := allowSubFlag || !strict
	raw, err := readInput(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", path, err)
		return witnesslog.ExitUsage
	}
	verdict, report, err := witnesslog.VerifyDossier(raw, directory, opts)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", path, err)
		return witnesslog.ExitUsage
	}
	if a.json {
		threshold := a.threshold
		var claimed struct {
			IdentityPubkey string `json:"identity_pubkey"`
		}
		_ = json.Unmarshal(raw, &claimed)
		out := map[string]any{
			"path":               path,
			"identity_pubkey":    claimed.IdentityPubkey,
			"threshold_used":     threshold,
			"min_witnesses_used": opts.MinReceipts,
			"identity_pinned":    opts.ExpectedIdentityPubkey != "",
			"subject_org":        subjectOrgJSON(opts.SubjectOrg),
			"directory_pinned":   directory != nil,
			"strict":             strict,
			"allow_sub_majority": allowSubFlag,
			"exit_code":          report.ExitCode(allowSub),
			"verdict":            verdict.String(),
			"report":             report,
		}
		if opts.AcceptFleetAnchor {
			out["accept_fleet_anchor"] = true
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return report.ExitCode(allowSub)
	}
	renderText(stdout, path, report, directory != nil, opts.ExpectedIdentityPubkey != "")
	if f := report.FleetAnchor; f != nil {
		switch f.Status {
		case "ignored":
			fmt.Fprintln(stdout, "Fleet anchor (EXPERIMENTAL, RFC-0001): present, not used (pass --accept-fleet-anchor --subject-org ORG).")
		case "verified":
			fmt.Fprintf(stdout, "Fleet anchor (EXPERIMENTAL): verified; %d witness(es) from your directory cosigned the fleet checkpoint; witnessed via %s.\n", report.WitnessPaths.Fleet.Witnesses, viaText(report.WitnessedVia))
		default:
			fmt.Fprintf(stdout, "Fleet anchor (EXPERIMENTAL): not used: %s\n", strings.Join(f.Failures, "; "))
		}
	}
	code := report.ExitCode(allowSub)
	if report.SplitViewUnsafe {
		if code == witnesslog.ExitSplitViewUnsafe {
			fmt.Fprintln(stdout, "Exit 11: WITNESSED, but not by a strict majority of your directory (strict is the default since 0.5.0). --allow-sub-majority accepts this as exit 0.")
		} else {
			fmt.Fprintln(stdout, "Accepted as exit 0 under --allow-sub-majority; a conflicting history could still have been cosigned by the rest of the directory.")
		}
	}
	return code
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func renderText(w io.Writer, path string, r *witnesslog.Report, directoryPinned, identityPinned bool) {
	fmt.Fprintf(w, "witness-log-verify %s\n\n", path)
	fmt.Fprintf(w, "%s checkpoint signature valid\n", mark(r.CheckpointSignatureValid))
	fmt.Fprintf(w, "%s identity bound", mark(r.IdentityBound))
	if !identityPinned {
		fmt.Fprint(w, " (self-consistency only: no --identity supplied)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s leaves structurally valid (%d leaves)\n", mark(r.LeavesStructurallyValid), r.LeafCount)
	if r.BindingsAsserted {
		fmt.Fprintf(w, "%s session key bindings valid\n", mark(r.BindingsValid))
	} else {
		fmt.Fprintf(w, "- session key bindings: not asserted by this dossier\n")
	}
	fmt.Fprintf(w, "%s Merkle continuity (rebuilt root matches checkpoint, size %d)\n", mark(r.MerkleContinuityValid), r.ClaimedTreeSize)
	if !directoryPinned {
		fmt.Fprintf(w, "- witness quorum: not scored (no --directory supplied)\n")
	} else if r.Quorum == nil {
		fmt.Fprintf(w, "%s witness quorum: dossier carries no receipts\n", mark(false))
	} else {
		q := r.Quorum
		fmt.Fprintf(w, "%s witness quorum: %d valid receipt(s) from %d directory witness(es), gate %s\n",
			mark(q.MeetsCountThreshold), q.ValidReceipts, q.TotalDirectoryWitnesses, q.CountGate)
		fmt.Fprintf(w, "%s independent operators: %d (need %d): %s\n",
			mark(q.DistinctIndependentOperators >= witnesslog.MinIndependentOperatorsForWitnessed),
			q.DistinctIndependentOperators, witnesslog.MinIndependentOperatorsForWitnessed,
			strings.Join(q.IndependentOperatorsRepresented, ", "))
		fmt.Fprintf(w, "  operator diversity %d/%d, compute-provider diversity %d/%d, project-operated receipts %d, split-view resistant: %t\n",
			q.DistinctOperatorsRepresented, q.DistinctOperatorsInDirectory,
			q.DistinctComputeProvidersRepresented, q.DistinctComputeProvidersInDirectory,
			q.ProjectOperatedReceipts, q.SplitViewResistant)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(w, "  failed: %s\n", f)
	}
	for _, c := range r.Contradictions {
		fmt.Fprintf(w, "  contradiction: %s\n", c)
	}
	for _, u := range r.KnownHeadsUnchecked {
		fmt.Fprintf(w, "  not checked: %s\n", u)
	}
	fmt.Fprintf(w, "\nVerdict: %s\n", r.Verdict)
}

func loadDossier(path string, stderr io.Writer) (*witnesslog.Dossier, bool) {
	raw, err := readInput(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", path, err)
		return nil, false
	}
	d, err := witnesslog.ParseDossier(raw)
	if err != nil {
		fmt.Fprintf(stderr, "%s: not a dossier: %v\n", path, err)
		return nil, false
	}
	return d, true
}

func runBind(args []string, stdout, stderr io.Writer) int {
	pos, err := positional(args, "--json")
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	if err != nil || len(pos) != 2 {
		fmt.Fprintln(stderr, "usage: witness-log-verify bind <a.json> <b.json> [--json]")
		return witnesslog.ExitUsage
	}
	a, ok := loadDossier(pos[0], stderr)
	if !ok {
		return witnesslog.ExitUsage
	}
	b, ok := loadDossier(pos[1], stderr)
	if !ok {
		return witnesslog.ExitUsage
	}
	result, err := witnesslog.Bind(a, b)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return witnesslog.ExitUsage
	}
	if hasFlag(args, "--json") {
		out := map[string]any{
			"a":      map[string]string{"path": pos[0], "identity": a.IdentityPubkey},
			"b":      map[string]string{"path": pos[1], "identity": b.IdentityPubkey},
			"bound":  result.Bound,
			"failed": result.Failed,
			"exit":   result.ExitCode(),
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return result.ExitCode()
	}
	fmt.Fprintf(stdout, "witness-log-verify bind\n  A: %s\n  B: %s\n\n", a.IdentityPubkey, b.IdentityPubkey)
	for _, p := range result.Bound {
		fmt.Fprintf(stdout, "✓ %s bound: A#%d ↔ B#%d  %s\n", p.Kind, p.ALeaf, p.BLeaf, p.Hash)
	}
	for _, f := range result.Failed {
		fmt.Fprintf(stdout, "✗ %s NOT bound (leaf %d of %s): %s\n", f.Kind, f.Leaf, f.Side, f.Reason)
	}
	switch result.ExitCode() {
	case 0:
		fmt.Fprintf(stdout, "\nResult: BOUND (%d binding(s))\n", len(result.Bound))
	case witnesslog.ExitDiverged:
		fmt.Fprintln(stdout, "\nResult: MISMATCH — the two logs disagree about what was handed over or to whom.")
	default:
		fmt.Fprintln(stdout, "\nResult: NO CROSS-LOG LEAVES — neither dossier names the other identity.")
	}
	return result.ExitCode()
}

func runDisclose(args []string, stdout, stderr io.Writer) int {
	pos, err := positional(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	if err != nil || len(pos) != 4 {
		fmt.Fprintln(stderr, "usage: witness-log-verify disclose <dossier.json> <leaf-index> <payload-file> <salt-hex>")
		return witnesslog.ExitUsage
	}
	d, ok := loadDossier(pos[0], stderr)
	if !ok {
		return witnesslog.ExitUsage
	}
	idx, err := strconv.ParseUint(pos[1], 10, 64)
	if err != nil || idx >= uint64(len(d.Leaves)) {
		fmt.Fprintf(stderr, "leaf index must be between 0 and %d\n", len(d.Leaves)-1)
		return witnesslog.ExitUsage
	}
	payload, err := readInput(pos[2])
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", pos[2], err)
		return witnesslog.ExitUsage
	}
	salt, err := hex.DecodeString(pos[3])
	if err != nil || len(salt) != 32 {
		fmt.Fprintln(stderr, "salt must be 64 hex characters")
		return witnesslog.ExitUsage
	}
	if err := witnesslog.VerifyDisclosure(&d.Leaves[idx], payload, salt); err != nil {
		fmt.Fprintf(stdout, "✗ %v\n", err)
		return witnesslog.ExitDiverged
	}
	fmt.Fprintf(stdout, "✓ leaf %d (%s) commits to this payload\n", idx, witnesslog.LeafTypeName(d.Leaves[idx].LeafType))
	return 0
}

// viaText renders Report.WitnessedVia for text output.
func viaText(v *witnesslog.WitnessedVia) string {
	if v == nil || *v == "" {
		return "neither path (not WITNESSED)"
	}
	return string(*v)
}

// subjectOrgJSON is null when no --subject-org was given, like the Rust CLI.
func subjectOrgJSON(org string) any {
	if org == "" {
		return nil
	}
	return org
}
