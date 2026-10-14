package witnesslog

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The goldens under testdata/ were produced by the Rust reference
// implementation (testdata/regen.sh). Each expectation file is the Rust
// CLI's `verify --json` output for one (dossier, context) pair; the Go
// verifier must produce the same report and the same exit code.

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatalf("%s: %v (run testdata/regen.sh)", rel, err)
	}
	return raw
}

func loadDirectory(t *testing.T, rel string) *Directory {
	t.Helper()
	d, err := ParseDirectory(readTestdata(t, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return d
}

func loadDossier(t *testing.T, rel string) *Dossier {
	t.Helper()
	d, err := ParseDossier(readTestdata(t, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return d
}

func identityOf(t *testing.T, rel string) string {
	return loadDossier(t, rel).IdentityPubkey
}

type rustExpectation struct {
	Verdict          string          `json:"verdict"`
	IdentityPinned   bool            `json:"identity_pinned"`
	DirectoryPinned  bool            `json:"directory_pinned"`
	ThresholdUsed    float64         `json:"threshold_used"`
	MinWitnessesUsed *int            `json:"min_witnesses_used"`
	Report           json.RawMessage `json:"report"`
}

func TestGoldenVerifyMatchesRust(t *testing.T) {
	aID := identityOf(t, "c2sp/a.json")
	bID := identityOf(t, "c2sp/b.json")
	nativeID := identityOf(t, "native/dossier.json")
	four, three := 4, 3
	cases := []struct {
		name      string
		dossier   string
		directory string
		identity  string
		threshold float64
		min       *int
	}{
		{"native.unanchored", "native/dossier.json", "", "", 0, nil},
		{"native.directory", "native/dossier.json", "native/trusted.json", "", 0, nil},
		{"native.pinned", "native/dossier.json", "native/trusted.json", nativeID, 0, nil},
		{"native.wrong-identity", "native/dossier.json", "native/trusted.json", bID, 0, nil},
		{"native.min-witnesses-4", "native/dossier.json", "native/trusted.json", "", 0, &four},
		{"native.threshold-1", "native/dossier.json", "native/trusted.json", "", 1.0, nil},
		{"native.c2sp-directory", "native/dossier.json", "c2sp/trusted.json", "", 0, nil},
		{"c2sp-a.unanchored", "c2sp/a.json", "", "", 0, nil},
		{"c2sp-a.directory", "c2sp/a.json", "c2sp/trusted.json", "", 0, nil},
		{"c2sp-a.pinned", "c2sp/a.json", "c2sp/trusted.json", aID, 0, nil},
		{"c2sp-a.wrong-identity", "c2sp/a.json", "c2sp/trusted.json", bID, 0, nil},
		{"c2sp-a.min-witnesses-3", "c2sp/a.json", "c2sp/trusted.json", "", 0, &three},
		{"c2sp-b.directory", "c2sp/b.json", "c2sp/trusted.json", "", 0, nil},
		{"c2sp-b.pinned", "c2sp/b.json", "c2sp/trusted.json", bID, 0, nil},
		{"c2sp-b.native-directory", "c2sp/b.json", "native/trusted.json", "", 0, nil},
	}
	seen := map[string]bool{}
	verdicts := map[string]int{}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			seen[c.name] = true
			var want rustExpectation
			if err := json.Unmarshal(readTestdata(t, "expect/"+c.name+".json"), &want); err != nil {
				t.Fatal(err)
			}
			wantExit, err := strconv.Atoi(strings.TrimSpace(string(readTestdata(t, "expect/"+c.name+".exit"))))
			if err != nil {
				t.Fatal(err)
			}
			var dir *Directory
			if c.directory != "" {
				dir = loadDirectory(t, c.directory)
			}
			verdict, report, err := VerifyDossier(readTestdata(t, c.dossier), dir, Options{
				ExpectedIdentityPubkey: c.identity, Threshold: c.threshold, MinReceipts: c.min,
			})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if verdict.String() != want.Verdict {
				t.Errorf("verdict: Go %s, Rust %s", verdict, want.Verdict)
			}
			if verdict.ExitCode() != wantExit {
				t.Errorf("exit code: Go %d, Rust %d", verdict.ExitCode(), wantExit)
			}
			if report.IdentityPinned != want.IdentityPinned || report.ExternallyAnchored != want.DirectoryPinned {
				t.Errorf("pinning flags differ: Go (%t,%t) Rust (%t,%t)", report.IdentityPinned, report.ExternallyAnchored, want.IdentityPinned, want.DirectoryPinned)
			}
			// Field-for-field comparison of the report, through JSON so
			// that number formatting and null handling are compared too.
			// Failure wording is per-implementation; whether a check
			// failed is not.
			goFailed := len(report.Failures) > 0
			report.Failures = nil
			gotJSON, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var got, exp map[string]any
			if err := json.Unmarshal(gotJSON, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(want.Report, &exp); err != nil {
				t.Fatal(err)
			}
			rustFailures, _ := exp["failures"].([]any)
			if goFailed != (len(rustFailures) > 0) {
				t.Errorf("failures: Go failed=%t, Rust %v", goFailed, rustFailures)
			}
			delete(exp, "failures")
			delete(got, "failures")
			if !reflect.DeepEqual(got, exp) {
				for k := range exp {
					if !reflect.DeepEqual(got[k], exp[k]) {
						t.Errorf("report.%s: Go %v, Rust %v", k, got[k], exp[k])
					}
				}
				for k := range got {
					if _, ok := exp[k]; !ok {
						t.Errorf("report.%s: present in Go, absent in Rust", k)
					}
				}
			}
			verdicts[want.Verdict]++
		})
	}
	// Every expectation file the script wrote has a case here, and the
	// goldens exercise all four verdicts.
	entries, _ := filepath.Glob("testdata/expect/*.json")
	for _, e := range entries {
		name := strings.TrimSuffix(filepath.Base(e), ".json")
		if !seen[name] {
			t.Errorf("expectation %s has no test case", name)
		}
	}
	for _, v := range []string{"WITNESSED", "CONSISTENT-UNWITNESSED", "UNANCHORED", "INVALID"} {
		if verdicts[v] == 0 {
			t.Errorf("no golden reaches %s", v)
		}
	}
}

func TestGoldenBindMatchesRust(t *testing.T) {
	a := loadDossier(t, "c2sp/a.json")
	b := loadDossier(t, "c2sp/b.json")
	res, err := Bind(a, b)
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		Bound  []map[string]any `json:"bound"`
		Failed []map[string]any `json:"failed"`
		Exit   int              `json:"exit"`
	}
	if err := json.Unmarshal(readTestdata(t, "c2sp/bind.expected.json"), &want); err != nil {
		t.Fatal(err)
	}
	if res.ExitCode() != want.Exit {
		t.Errorf("exit: Go %d, Rust %d", res.ExitCode(), want.Exit)
	}
	if len(res.Failed) != len(want.Failed) {
		t.Errorf("failed: Go %d, Rust %d", len(res.Failed), len(want.Failed))
	}
	if len(res.Bound) != len(want.Bound) {
		t.Fatalf("bound: Go %d, Rust %d", len(res.Bound), len(want.Bound))
	}
	// Compare as sets of (kind, a leaf, b leaf, hash), with Rust's
	// handoff rows translated from sender/receiver to a/b.
	key := func(kind string, aLeaf, bLeaf float64, hash string) string {
		return kind + ":" + strconv.Itoa(int(aLeaf)) + ":" + strconv.Itoa(int(bLeaf)) + ":" + hash
	}
	wantSet := map[string]bool{}
	for _, r := range want.Bound {
		switch r["kind"] {
		case "handoff":
			if r["sender"] == a.IdentityPubkey {
				wantSet[key("handoff", r["sender_leaf"].(float64), r["receiver_leaf"].(float64), r["state_hash"].(string))] = true
			} else {
				wantSet[key("handoff", r["receiver_leaf"].(float64), r["sender_leaf"].(float64), r["state_hash"].(string))] = true
			}
		default:
			wantSet[key("authorization", r["a_leaf"].(float64), r["b_leaf"].(float64), r["scope_hash"].(string))] = true
		}
	}
	for _, p := range res.Bound {
		k := key(p.Kind, float64(p.ALeaf), float64(p.BLeaf), p.Hash)
		if !wantSet[k] {
			t.Errorf("Go bound %s, Rust did not", k)
		}
		delete(wantSet, k)
	}
	for k := range wantSet {
		t.Errorf("Rust bound %s, Go did not", k)
	}
	// Both directions of the call agree on the exit code.
	rev, err := Bind(b, a)
	if err != nil || rev.ExitCode() != res.ExitCode() || len(rev.Bound) != len(res.Bound) {
		t.Errorf("bind is not symmetric: %v %v", rev, err)
	}
	// Same identity on both sides is a usage error, as in the CLI.
	if _, err := Bind(a, a); err == nil {
		t.Errorf("binding a dossier to itself must be refused")
	}
	// A log that never named the other: nothing to bind (exit 10).
	native := loadDossier(t, "native/dossier.json")
	none, err := Bind(a, native)
	if err != nil || none.ExitCode() != ExitConsistentUnwitnessed {
		t.Errorf("unrelated dossiers must report nothing to bind: %v %v", none, err)
	}
	// B claiming a wider scope than A granted: mismatch (exit 30).
	wider := *b
	wider.Leaves = append([]Leaf(nil), b.Leaves...)
	widerHash := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	for i := range wider.Leaves {
		if wider.Leaves[i].LeafType == LeafAuthorizationEvent {
			l := wider.Leaves[i]
			l.AuthorizationScopeHash = &widerHash
			wider.Leaves[i] = l
		}
	}
	mismatch, err := Bind(a, &wider)
	if err != nil || mismatch.ExitCode() != ExitDiverged || len(mismatch.Failed) == 0 {
		t.Errorf("a widened scope must fail to bind: %+v %v", mismatch, err)
	}
}

func TestGoldenDisclosure(t *testing.T) {
	var fx struct {
		LeafIndex          uint64 `json:"leaf_index"`
		PayloadHex         string `json:"payload_hex"`
		SaltHex            string `json:"salt_hex"`
		ForgottenLeafIndex uint64 `json:"forgotten_leaf_index"`
	}
	if err := json.Unmarshal(readTestdata(t, "c2sp/disclosure.json"), &fx); err != nil {
		t.Fatal(err)
	}
	a := loadDossier(t, "c2sp/a.json")
	payload, _ := hex.DecodeString(fx.PayloadHex)
	salt, _ := hex.DecodeString(fx.SaltHex)
	if err := VerifyDisclosure(&a.Leaves[fx.LeafIndex], payload, salt); err != nil {
		t.Errorf("golden disclosure must verify: %v", err)
	}
	if VerifyDisclosure(&a.Leaves[fx.LeafIndex], []byte(`{"tool":"read_invoice","args":{"invoice":"INV-0043"}}`), salt) == nil {
		t.Errorf("a different payload must not verify")
	}
	salt[0] ^= 1
	if VerifyDisclosure(&a.Leaves[fx.LeafIndex], payload, salt) == nil {
		t.Errorf("a different salt must not verify")
	}
	// The redacted leaf still has a payload_hash; the dossier carries a
	// 0x03 tombstone naming it, and without the salt nothing verifies.
	forgotten := a.Leaves[fx.ForgottenLeafIndex]
	foundTombstone := false
	for _, l := range a.Leaves {
		if l.LeafType == LeafRedaction && l.RedactedIndex != nil && *l.RedactedIndex == fx.ForgottenLeafIndex {
			foundTombstone = true
		}
	}
	if !foundTombstone {
		t.Errorf("expected a redaction tombstone for leaf %d", fx.ForgottenLeafIndex)
	}
	if VerifyDisclosure(&forgotten, []byte("contact: ops@example.invalid"), make([]byte, 32)) == nil {
		t.Errorf("a guessed salt must not verify")
	}
}

// Every mutation of a WITNESSED golden lands on the verdict the
// specification assigns it. These are Go-side expectations derived from
// SPEC.md §9.2; the Rust-vs-Go comparison above covers the honest cases.
func TestGoldenTampering(t *testing.T) {
	type mutation struct {
		name string
		want Verdict
		dir  string
		mut  func(d *Dossier)
	}
	hash := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	cases := []mutation{
		{"leaf timestamp edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Leaves[1].TimestampMs++ }},
		{"leaf payload hash edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Leaves[0].PayloadHash = hash }},
		{"leaf removed", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Leaves = d.Leaves[:len(d.Leaves)-1] }},
		{"leaf appended", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			extra := d.Leaves[0]
			extra.Index = uint64(len(d.Leaves))
			d.Leaves = append(d.Leaves, extra)
		}},
		{"leaves reordered", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			d.Leaves[0], d.Leaves[1] = d.Leaves[1], d.Leaves[0]
		}},
		{"leaves reordered with indices rewritten", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			d.Leaves[0], d.Leaves[1] = d.Leaves[1], d.Leaves[0]
			d.Leaves[0].Index, d.Leaves[1].Index = 0, 1
		}},
		{"checkpoint root edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Checkpoint.RootHash = hash }},
		{"checkpoint size edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Checkpoint.TreeSize++ }},
		{"checkpoint timestamp edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Checkpoint.TimestampMs++ }},
		{"checkpoint re-attributed", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			d.Checkpoint.SignerPubkey = hash
			d.IdentityPubkey = hash
		}},
		{"identity claim edited", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.IdentityPubkey = hash }},
		{"unknown leaf type", Invalid, "c2sp/trusted.json", func(d *Dossier) { d.Leaves[0].LeafType = 0x09 }},
		{"anchor proof swapped", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			for i := range d.Leaves {
				if d.Leaves[i].LeafType == LeafExternalAnchor {
					s := `{"swapped":true}`
					d.Leaves[i].AnchorProofJSON = &s
				}
			}
		}},
		{"binding dropped for a used session", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			d.KeyBindings = d.KeyBindings[:0]
			d.Revocations = []Revocation{{IdentityPubkey: d.IdentityPubkey, AsOfMs: 1, Reason: "x", Signature: strings.Repeat("00", 64)}}
		}},
		{"binding signature edited", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			d.KeyBindings[0].Signature = "00" + d.KeyBindings[0].Signature[2:]
		}},
		{"binding expiry before the leaves", Invalid, "c2sp/trusted.json", func(d *Dossier) {
			one := uint64(1)
			d.KeyBindings[0].NotAfterMs = &one
		}},
		{"bindings removed entirely (not asserted)", Witnessed, "c2sp/trusted.json", func(d *Dossier) {
			d.KeyBindings = nil
		}},
		{"custody edited (unsigned, display only)", Witnessed, "c2sp/trusted.json", func(d *Dossier) {
			d.KeyBindings[0].Custody = Custody{Kind: "hsm"}
		}},
		{"receipt timestamp edited", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) {
			for i := range d.WitnessReceipts {
				d.WitnessReceipts[i].WitnessedAtMs += 1000
			}
		}},
		{"receipt sub-second time", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) {
			for i := range d.WitnessReceipts {
				d.WitnessReceipts[i].WitnessedAtMs++
			}
		}},
		{"receipt origin not canonical", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) {
			for i := range d.WitnessReceipts {
				d.WitnessReceipts[i].C2SPOrigin = "example.com/log"
			}
		}},
		{"receipts removed", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) { d.WitnessReceipts = nil }},
		{"one receipt duplicated, other removed", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) {
			d.WitnessReceipts = []WitnessReceipt{d.WitnessReceipts[0], d.WitnessReceipts[0]}
		}},
		{"receipt from a witness outside the directory", ConsistentUnwitnessed, "c2sp/trusted.json", func(d *Dossier) {
			d.WitnessReceipts[0].WitnessPubkey = hash
		}},
		{"dossier ships its own directory, verifier trusts none", Unanchored, "", func(d *Dossier) {}},
		{"dossier directory edited, verifier has its own", Witnessed, "c2sp/trusted.json", func(d *Dossier) {
			d.WitnessDirectory.Witnesses = nil
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			d := loadDossier(t, "c2sp/a.json")
			c.mut(d)
			var dir *Directory
			if c.dir != "" {
				dir = loadDirectory(t, c.dir)
			}
			r := d.Verify(dir, Options{})
			if r.Verdict != c.want {
				t.Errorf("verdict %s, want %s (failures: %v)", r.Verdict, c.want, r.Failures)
			}
			if (r.Verdict == Invalid) != (len(r.Failures) > 0) {
				t.Errorf("failures must be listed exactly when INVALID: %v", r.Failures)
			}
			if r.InternallyConsistent == (r.Verdict == Invalid) {
				t.Errorf("internally_consistent must be false exactly when INVALID")
			}
		})
	}
}

// A directory whose two witnesses share one operator, or that marks them
// project-operated, cannot reach WITNESSED however many receipts verify.
func TestGoldenOperatorDiversity(t *testing.T) {
	d := loadDossier(t, "c2sp/a.json")
	sameOrg := loadDirectory(t, "c2sp/trusted.json")
	for i := range sameOrg.Witnesses {
		sameOrg.Witnesses[i].OperatorOrg = "  Golden ORG   one "
	}
	r := d.Verify(sameOrg, Options{})
	if r.Verdict != ConsistentUnwitnessed || r.Quorum == nil || r.Quorum.DistinctIndependentOperators != 1 || !r.Quorum.MeetsCountThreshold {
		t.Errorf("one operator under two spellings must count once: %s %+v", r.Verdict, r.Quorum)
	}
	project := loadDirectory(t, "c2sp/trusted.json")
	for i := range project.Witnesses {
		project.Witnesses[i].IsProjectOperated = true
	}
	r = d.Verify(project, Options{})
	if r.Verdict != ConsistentUnwitnessed || r.Quorum.DistinctIndependentOperators != 0 || r.Quorum.ProjectOperatedReceipts != 2 {
		t.Errorf("project-operated witnesses must not count as independent: %s %+v", r.Verdict, r.Quorum)
	}
	// The subject's own operator never counts as independent.
	self := loadDirectory(t, "c2sp/trusted.json")
	self.Witnesses = append(self.Witnesses, WitnessEntry{
		Name: "the-agent-itself", OperatorOrg: self.Witnesses[0].OperatorOrg, URL: "http://127.0.0.1:1",
		Pubkey: d.Checkpoint.SignerPubkey, Runtime: "agent",
	})
	r = d.Verify(self, Options{})
	if r.Quorum == nil || r.Quorum.DistinctIndependentOperators != 1 {
		t.Errorf("the subject's operator must be excluded: %+v", r.Quorum)
	}
	// A larger directory makes the fraction gate fail but --min-witnesses pass.
	big := loadDirectory(t, "c2sp/trusted.json")
	for i := 0; i < 10; i++ {
		big.Witnesses = append(big.Witnesses, WitnessEntry{
			Name: "w" + strconv.Itoa(i), OperatorOrg: "org-" + strconv.Itoa(i), URL: "http://127.0.0.1:1",
			Pubkey: strings.Repeat(strconv.Itoa(i), 64)[:64], Runtime: "agent",
		})
	}
	r = d.Verify(big, Options{})
	if r.Verdict != ConsistentUnwitnessed || r.Quorum.SplitViewResistant {
		t.Errorf("2 of 12 must fail the 0.66 fraction gate: %s %+v", r.Verdict, r.Quorum)
	}
	two := 2
	r = d.Verify(big, Options{MinReceipts: &two})
	if r.Verdict != Witnessed || r.Quorum.CountGate != "count >= 2" || r.Quorum.SplitViewResistant {
		t.Errorf("--min-witnesses 2 must reach WITNESSED without split-view resistance: %s %+v", r.Verdict, r.Quorum)
	}
}

// Parsing rules: what the reference treats as unparseable (exit 2) must be
// an error here too, not a verdict.
func TestParseRules(t *testing.T) {
	raw := readTestdata(t, "c2sp/a.json")
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	drop := func(key string) []byte {
		c := map[string]json.RawMessage{}
		for k, v := range m {
			if k != key {
				c[k] = v
			}
		}
		b, _ := json.Marshal(c)
		return b
	}
	for _, key := range []string{"identity_pubkey", "leaves", "checkpoint"} {
		if _, _, err := VerifyDossier(drop(key), nil, Options{}); err == nil {
			t.Errorf("a dossier without %s must be unparseable", key)
		}
	}
	for _, key := range []string{"witness_receipts", "witness_directory", "key_bindings", "revocations"} {
		if _, _, err := VerifyDossier(drop(key), nil, Options{}); err != nil {
			t.Errorf("a dossier without %s must parse (defaults to empty): %v", key, err)
		}
	}
	bad := [][]byte{
		[]byte(`not json`),
		[]byte(`[]`),
		[]byte(strings.Replace(string(raw), `"leaf_type": 1`, `"leaf_type": 300`, 1)),
		[]byte(strings.Replace(string(raw), `"leaf_type": 1`, `"leaf_type": -1`, 1)),
		[]byte(strings.Replace(string(raw), `"handoff_direction": "Sent"`, `"handoff_direction": "sent"`, 1)),
		[]byte(strings.Replace(string(raw), `"authorization_event_kind": "GrantedByMe"`, `"authorization_event_kind": 0`, 1)),
		[]byte(strings.Replace(string(raw), `"custody": "undisclosed"`, `"custody": "stolen"`, 1)),
	}
	for i, b := range bad {
		if _, _, err := VerifyDossier(b, nil, Options{}); err == nil {
			t.Errorf("bad input %d must be unparseable", i)
		}
	}
	// Unknown fields are ignored, as serde does by default.
	extra := []byte(strings.Replace(string(raw), `"identity_pubkey"`, `"extra": 1, "identity_pubkey"`, 1))
	if _, _, err := VerifyDossier(extra, nil, Options{}); err != nil {
		t.Errorf("unknown fields must be ignored: %v", err)
	}
	// Directory accepts both shapes and rejects a bad runtime.
	entries := readTestdata(t, "c2sp/trusted.json")
	var dirObj struct {
		Witnesses []json.RawMessage `json:"witnesses"`
	}
	_ = json.Unmarshal(entries, &dirObj)
	bare, _ := json.Marshal(dirObj.Witnesses)
	if d, err := ParseDirectory(bare); err != nil || len(d.Witnesses) != 2 {
		t.Errorf("bare array directory must parse: %v", err)
	}
	if !strings.Contains(string(entries), `"runtime": "human"`) {
		t.Fatalf("fixture lost its runtime field")
	}
	if _, err := ParseDirectory([]byte(strings.Replace(string(entries), `"runtime": "human"`, `"runtime": "robot"`, 1))); err == nil {
		t.Errorf("bad runtime must be rejected")
	}
	if _, err := ParseDirectory([]byte(`{"witnesses": [{"name": "x"}]}`)); err == nil {
		t.Errorf("entry without operator_org/url/pubkey must be rejected")
	}
}

func TestDossierJSONRoundTrip(t *testing.T) {
	for _, rel := range []string{"native/dossier.json", "c2sp/a.json", "c2sp/b.json"} {
		d := loadDossier(t, rel)
		out, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseDossier(out)
		if err != nil {
			t.Fatalf("%s: reparse: %v", rel, err)
		}
		dir := loadDirectory(t, "c2sp/trusted.json")
		r1 := d.Verify(dir, Options{})
		r2 := again.Verify(dir, Options{})
		r1.Failures, r2.Failures = nil, nil
		if !reflect.DeepEqual(r1, r2) {
			t.Errorf("%s: report changed after a JSON round trip", rel)
		}
	}
}

// Ed25519 strictness: small-order points are refused even though
// crypto/ed25519 alone would accept some of them.
func TestStrictEd25519RejectsSmallOrder(t *testing.T) {
	small := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		// non-canonical encodings (y + p) of the same points
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for _, s := range small {
		if !isSmallOrderEncoding(mustHex(s)) {
			t.Errorf("%s must be recognised as small order", s)
		}
	}
	d := loadDossier(t, "c2sp/a.json")
	if isSmallOrderEncoding(mustHex(d.Checkpoint.SignerPubkey)) || isSmallOrderEncoding(mustHex(d.Checkpoint.Signature)[:32]) {
		t.Errorf("honest keys and signatures are never small order")
	}
	// A signature whose R is the identity never verifies here, whatever
	// the scalar part says.
	sig := mustHex(d.Checkpoint.Signature)
	copy(sig[:32], mustHex(small[0]))
	msg := []byte("anything")
	if VerifyStrict(mustHex(d.Checkpoint.SignerPubkey), msg, sig) {
		t.Errorf("small-order R accepted")
	}
	if VerifyStrict(mustHex(small[4]), msg, mustHex(d.Checkpoint.Signature)) {
		t.Errorf("small-order public key accepted")
	}
}
