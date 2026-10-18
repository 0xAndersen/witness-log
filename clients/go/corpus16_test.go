package witnesslog

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// corpusVerdictCase is a case in corpus vectors 15, 16 and 17: a dossier
// (named, or inline JSON text in 17), the caller's inputs, and the
// verdict, exit code and report fields the reference gives.
type corpusVerdictCase struct {
	Name             string   `json:"name"`
	Dossier          string   `json:"dossier"`
	DossierJSON      *string  `json:"dossier_json"`
	Directory        *string  `json:"directory"`
	ExpectedIdentity *string  `json:"expected_identity"`
	Threshold        float64  `json:"threshold"`
	MinWitnesses     *int     `json:"min_witnesses"`
	KnownHeads       []string `json:"known_heads"`
	Evidence         []string `json:"evidence"`
	AllowSubMajority bool     `json:"allow_sub_majority"`
	SubjectOrg       *string  `json:"subject_org"`
	Expect           struct {
		NotADossier          bool    `json:"not_a_dossier"`
		Verdict              *string `json:"verdict"`
		ExitCode             int     `json:"exit_code"`
		SplitViewUnsafe      *bool   `json:"split_view_unsafe"`
		InternallyConsistent *bool   `json:"internally_consistent"`
		HasFailures          *bool   `json:"has_failures"`
		Contradictions       *int    `json:"contradictions"`
		KnownHeadsUnchecked  *int    `json:"known_heads_unchecked"`
		ValidReceipts        *int    `json:"valid_receipts"`
		IndependentOperators *int    `json:"independent_operators"`
	} `json:"expect"`
}

// checkVerdictCase verifies raw (the dossier's JSON) as the case says and
// compares the report with the expectation.
func checkVerdictCase(t *testing.T, c corpusVerdictCase, raw []byte, directories, evidence map[string]json.RawMessage) {
	t.Helper()
	e := c.Expect
	opts := Options{Threshold: c.Threshold, ThresholdSet: true, MinReceipts: c.MinWitnesses}
	if c.SubjectOrg != nil {
		opts.SubjectOrg = *c.SubjectOrg
	}
	if c.ExpectedIdentity != nil {
		opts.ExpectedIdentityPubkey = *c.ExpectedIdentity
	}
	for _, h := range c.KnownHeads {
		kh, err := ParseKnownHead(h)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		opts.KnownHeads = append(opts.KnownHeads, kh)
	}
	for _, k := range c.Evidence {
		p, err := ParseEvidence(evidence[k])
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		opts.Evidence = append(opts.Evidence, p)
	}
	var trusted *Directory
	if c.Directory != nil {
		d, err := ParseDirectory(directories[*c.Directory])
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		trusted = d
	}
	verdict, r, err := VerifyDossier(raw, trusted, opts)
	if e.NotADossier {
		// The reference cannot deserialise it: VerifyDossier reports
		// Invalid with the parse error and no report (the CLI exits 2).
		if err == nil || verdict != Invalid || r != nil {
			t.Errorf("%s: not a dossier, got %v %v %v", c.Name, verdict, r, err)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: %v", c.Name, err)
		return
	}
	got, _ := json.Marshal(r.Verdict)
	if e.Verdict == nil || string(got) != `"`+*e.Verdict+`"` {
		t.Errorf("%s: verdict %s want %v (failures %v)", c.Name, got, e.Verdict, r.Failures)
	}
	if code := r.ExitCode(c.AllowSubMajority); code != e.ExitCode {
		t.Errorf("%s: exit %d want %d", c.Name, code, e.ExitCode)
	}
	if r.SplitViewUnsafe != *e.SplitViewUnsafe || r.InternallyConsistent != *e.InternallyConsistent ||
		(len(r.Failures) > 0) != *e.HasFailures || len(r.Contradictions) != *e.Contradictions ||
		len(r.KnownHeadsUnchecked) != *e.KnownHeadsUnchecked {
		t.Errorf("%s: report %+v", c.Name, r)
	}
	if (r.Quorum == nil) != (e.ValidReceipts == nil) || (r.Quorum != nil && r.Quorum.ValidReceipts != *e.ValidReceipts) {
		t.Errorf("%s: quorum %+v, want valid_receipts %v", c.Name, r.Quorum, e.ValidReceipts)
	}
	if (r.Quorum == nil) != (e.IndependentOperators == nil) || (r.Quorum != nil && r.Quorum.DistinctIndependentOperators != *e.IndependentOperators) {
		t.Errorf("%s: independent operators %+v, want %v", c.Name, r.Quorum, e.IndependentOperators)
	}
}

// TestCorpus16Ed25519Strict runs corpus vector 16 (outside review of
// 0.6.0, H3/M3): every signature through VerifyStrict, the check every
// Go verification path uses, and every dossier case through VerifyDossier.
// The expectations are ed25519-dalek's verify_strict.
func TestCorpus16Ed25519Strict(t *testing.T) {
	var v struct {
		Signatures []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Valid     bool   `json:"valid"`
		} `json:"signatures"`
		Directories map[string]json.RawMessage `json:"directories"`
		Dossiers    map[string]json.RawMessage `json:"dossiers"`
		Evidence    map[string]json.RawMessage `json:"evidence"`
		Cases       []corpusVerdictCase        `json:"cases"`
	}
	readCorpus(t, "16_ed25519_strict.json", &v)
	if len(v.Signatures) < 45 {
		t.Fatalf("only %d signatures", len(v.Signatures))
	}
	smallA := 0
	for _, s := range v.Signatures {
		pub, err1 := hex.DecodeString(s.PublicKey)
		msg, err2 := hex.DecodeString(s.Message)
		sig, err3 := hex.DecodeString(s.Signature)
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("%s: bad hex", s.Name)
		}
		if got := VerifyStrict(pub, msg, sig); got != s.Valid {
			t.Errorf("%s: VerifyStrict %v, want %v", s.Name, got, s.Valid)
		}
		if strings.HasPrefix(s.Name, "small-order A") {
			smallA++
			if !isSmallOrderEncoding(pub) {
				t.Errorf("%s: isSmallOrderEncoding false", s.Name)
			}
		}
	}
	if smallA < 14 {
		t.Errorf("only %d small-order public keys", smallA)
	}
	exits := map[int]bool{}
	for _, c := range v.Cases {
		exits[c.Expect.ExitCode] = true
		checkVerdictCase(t, c, v.Dossiers[c.Dossier], v.Directories, v.Evidence)
	}
	for _, code := range []int{10, 20, 40} {
		if !exits[code] {
			t.Errorf("no case exercises exit %d", code)
		}
	}
}
