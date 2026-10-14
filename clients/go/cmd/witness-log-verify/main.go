// Command witness-log-verify verifies a witness-log dossier offline with
// the pure-Go verifier. Its exit status is the verdict, with the same
// codes as `witness-log verify`: 0 WITNESSED, 11 WITNESSED by fewer than a
// strict majority of the directory (strict is the default since 0.5.0),
// 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30 DIVERGED, 40 INVALID,
// 2 usage or unreadable input.
//
//	witness-log-verify <dossier.json> [--identity <hex>] [--directory <dir.json>]
//	                   [--threshold 0.0-1.0 | --min-witnesses N]
//	                   [--allow-sub-majority | --no-strict] [--revocations <file>]
//	                   [--known-head <size>:<root>] [--evidence <file>] [--json]
//	witness-log-verify bind <a.json> <b.json> [--json]
//	witness-log-verify disclose <dossier.json> <leaf-index> <payload-file> <salt-hex>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	witnesslog "github.com/0xAndersen/witness-log/clients/go"
)

const usage = `witness-log-verify — offline dossier verification in Go

USAGE:
  witness-log-verify <dossier.json> [--identity <hex>] [--directory <dir.json>]
                     [--threshold 0.0-1.0 | --min-witnesses N]
                     [--allow-sub-majority | --no-strict] [--revocations <file>]
                     [--known-head <size>:<root>] [--evidence <file>] [--json]
      --identity   the identity pubkey you expect, obtained out-of-band
      --directory  a witness directory YOU trust, obtained out-of-band
      --revocations  revocation statements you know of (JSON array or one object);
                   applied even when the dossier omits them
      --threshold  quorum gate as a fraction of the directory (default 0.66)
      --min-witnesses N  quorum gate as an absolute receipt count
      --allow-sub-majority  accept WITNESSED from fewer than a strict majority
                   of the directory as exit 0 instead of 11
      --no-strict  the 0.4 exit codes, without 11 (kept for one release)
      --known-head <size>:<root hex>  a head you already trust for this
                   identity (repeatable); not reproduced -> DIVERGED
      --evidence <file>  a witness equivocation proof (repeatable); if it
                   verifies for this identity -> DIVERGED
      --json       machine-readable report (same fields as witness-log verify --json)

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

func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			return args[i+1], true
		}
	}
	return "", false
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// switches take no value; every other --flag consumes the next argument.
var switches = map[string]bool{
	"--json": true, "--strict": true, "--no-strict": true, "--allow-sub-majority": true,
}

func positional(args []string) []string {
	var out []string
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(a, "--") {
			if !switches[a] {
				skip = true
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// flagValues returns every value of a repeatable flag, and false if the
// flag appears without one.
func flagValues(args []string, flag string) ([]string, bool) {
	var out []string
	for i, a := range args {
		if a != flag {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, false
		}
		out = append(out, args[i+1])
	}
	return out, true
}

// readEvidence reads a witness evidence file as `witness-log witness serve`
// writes it ({"kind": "equivocation", "proof": {...}}) or a bare proof.
func readEvidence(path string) (witnesslog.EquivocationProof, error) {
	var p witnesslog.EquivocationProof
	raw, err := readInput(path)
	if err != nil {
		return p, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return p, err
	}
	if inner, ok := doc["proof"]; ok {
		raw = inner
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("not an equivocation proof: %v", err)
	}
	if p.Origin == "" || p.EarlierNote == "" || p.ConflictingNote == "" {
		return p, fmt.Errorf("not an equivocation proof: missing origin or notes")
	}
	return p, nil
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
	pos := positional(args)
	if len(pos) != 1 {
		fmt.Fprint(stderr, usage)
		return witnesslog.ExitUsage
	}
	path := pos[0]
	opts := witnesslog.Options{}
	if v, ok := flagValue(args, "--identity"); ok {
		opts.ExpectedIdentityPubkey = v
	} else if hasFlag(args, "--identity") {
		fmt.Fprintln(stderr, "--identity needs a hex public key")
		return witnesslog.ExitUsage
	}
	if v, ok := flagValue(args, "--threshold"); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1 {
			fmt.Fprintln(stderr, "--threshold: expected a fraction between 0 and 1")
			return witnesslog.ExitUsage
		}
		opts.Threshold = f
	}
	if v, ok := flagValue(args, "--min-witnesses"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			fmt.Fprintln(stderr, "--min-witnesses: expected a non-negative integer")
			return witnesslog.ExitUsage
		}
		opts.MinReceipts = &n
	}
	var directory *witnesslog.Directory
	if dirPath, ok := flagValue(args, "--directory"); ok {
		raw, err := readInput(dirPath)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", dirPath, err)
			return witnesslog.ExitUsage
		}
		directory, err = witnesslog.ParseDirectory(raw)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", dirPath, err)
			return witnesslog.ExitUsage
		}
	} else if hasFlag(args, "--directory") {
		fmt.Fprintln(stderr, "--directory needs a path")
		return witnesslog.ExitUsage
	}
	if revPath, ok := flagValue(args, "--revocations"); ok {
		raw, err := readInput(revPath)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", revPath, err)
			return witnesslog.ExitUsage
		}
		revs, err := witnesslog.ParseRevocations(raw)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", revPath, err)
			return witnesslog.ExitUsage
		}
		opts.Revocations = revs
	} else if hasFlag(args, "--revocations") {
		fmt.Fprintln(stderr, "--revocations needs a path")
		return witnesslog.ExitUsage
	}
	heads, ok := flagValues(args, "--known-head")
	if !ok {
		fmt.Fprintln(stderr, "--known-head requires <size>:<root hex>")
		return witnesslog.ExitUsage
	}
	for _, h := range heads {
		kh, err := witnesslog.ParseKnownHead(h)
		if err != nil {
			fmt.Fprintf(stderr, "--known-head: %v\n", err)
			return witnesslog.ExitUsage
		}
		opts.KnownHeads = append(opts.KnownHeads, kh)
	}
	evidencePaths, ok := flagValues(args, "--evidence")
	if !ok {
		fmt.Fprintln(stderr, "--evidence requires a path to a witness evidence file")
		return witnesslog.ExitUsage
	}
	for _, ep := range evidencePaths {
		p, err := readEvidence(ep)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", ep, err)
			return witnesslog.ExitUsage
		}
		opts.Evidence = append(opts.Evidence, p)
	}
	strict := !hasFlag(args, "--no-strict")
	allowSubFlag := hasFlag(args, "--allow-sub-majority")
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
	if hasFlag(args, "--json") {
		threshold := opts.Threshold
		if threshold == 0 {
			threshold = witnesslog.DefaultThreshold
		}
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
			"directory_pinned":   directory != nil,
			"strict":             strict,
			"allow_sub_majority": allowSubFlag,
			"exit_code":          report.ExitCode(allowSub),
			"verdict":            verdict.String(),
			"report":             report,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return report.ExitCode(allowSub)
	}
	renderText(stdout, path, report, directory != nil, opts.ExpectedIdentityPubkey != "")
	code := report.ExitCode(allowSub)
	if report.SplitViewUnsafe {
		if code == witnesslog.ExitSplitViewUnsafe {
			fmt.Fprintln(stdout, "Exit 11: WITNESSED, but not by a strict majority of your directory (strict is the default since 0.5.0). --allow-sub-majority accepts this as exit 0.")
		} else {
			flag := "--no-strict"
			if strict {
				flag = "--allow-sub-majority"
			}
			fmt.Fprintf(stdout, "Accepted as exit 0 under %s; a conflicting history could still have been cosigned by the rest of the directory.\n", flag)
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
	pos := positional(args)
	if len(pos) != 2 {
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
	pos := positional(args)
	if len(pos) != 4 {
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
