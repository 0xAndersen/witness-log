package witnesslog

import (
	"encoding/json"
	"testing"
)

// TestCorpus15EvidenceAndArgs runs corpus vector 15 (security review of
// 0.5.0: F1, F5, F10, F12) through the Go verifier: evidence items read by
// ParseEvidence, known heads by ParseKnownHead, labels by normalizeLabel.
// A case whose inputs must be refused has exit_code 2.
func TestCorpus15EvidenceAndArgs(t *testing.T) {
	var v struct {
		Directories map[string]json.RawMessage `json:"directories"`
		Dossiers    map[string]json.RawMessage `json:"dossiers"`
		Evidence    map[string]json.RawMessage `json:"evidence"`
		Cases       []struct {
			Name             string   `json:"name"`
			Dossier          string   `json:"dossier"`
			Directory        *string  `json:"directory"`
			ExpectedIdentity *string  `json:"expected_identity"`
			Threshold        float64  `json:"threshold"`
			MinWitnesses     *int     `json:"min_witnesses"`
			KnownHeads       []string `json:"known_heads"`
			Evidence         []string `json:"evidence"`
			AllowSubMajority bool     `json:"allow_sub_majority"`
			SubjectOrg       *string  `json:"subject_org"`
			Expect           struct {
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
		} `json:"cases"`
	}
	readCorpus(t, "15_evidence_and_args.json", &v)
	if len(v.Cases) < 40 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	exits := map[int]bool{}
	for _, c := range v.Cases {
		e := c.Expect
		exits[e.ExitCode] = true
		opts := Options{Threshold: c.Threshold, ThresholdSet: true, MinReceipts: c.MinWitnesses}
		if c.SubjectOrg != nil {
			opts.SubjectOrg = *c.SubjectOrg
		}
		if c.ExpectedIdentity != nil {
			opts.ExpectedIdentityPubkey = *c.ExpectedIdentity
		}
		var refused error
		for _, h := range c.KnownHeads {
			kh, err := ParseKnownHead(h)
			if err != nil {
				refused = err
				break
			}
			opts.KnownHeads = append(opts.KnownHeads, kh)
		}
		for _, k := range c.Evidence {
			if refused != nil {
				break
			}
			raw, ok := v.Evidence[k]
			if !ok {
				t.Fatalf("%s: no evidence item %q", c.Name, k)
			}
			p, err := ParseEvidence(raw)
			if err != nil {
				refused = err
				break
			}
			opts.Evidence = append(opts.Evidence, p)
		}
		if refused != nil || e.ExitCode == 2 {
			if refused == nil || e.ExitCode != 2 {
				t.Errorf("%s: refused=%v, want exit %d", c.Name, refused, e.ExitCode)
			}
			continue
		}
		var trusted *Directory
		if c.Directory != nil {
			d, err := ParseDirectory(v.Directories[*c.Directory])
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			trusted = d
		}
		d, err := ParseDossier(v.Dossiers[c.Dossier])
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		r := d.Verify(trusted, opts)
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
		if (r.Quorum == nil) != (e.IndependentOperators == nil) || (r.Quorum != nil && r.Quorum.DistinctIndependentOperators != *e.IndependentOperators) {
			t.Errorf("%s: independent operators %+v, want %v", c.Name, r.Quorum, e.IndependentOperators)
		}
		if (r.Quorum == nil) != (e.ValidReceipts == nil) || (r.Quorum != nil && r.Quorum.ValidReceipts != *e.ValidReceipts) {
			t.Errorf("%s: quorum %+v, want valid_receipts %v", c.Name, r.Quorum, e.ValidReceipts)
		}
	}
	for _, code := range []int{2, 10, 11, 20, 30, 40} {
		if !exits[code] {
			t.Errorf("no case exercises exit %d", code)
		}
	}
}

// TestNormalizeLabelMatchesTheReference pins the label rule (spec/SPEC.md
// §7): Unicode White_Space runs collapse, then full default lowercasing,
// SpecialCasing included. Go's strings.ToLower has neither U+0130 -> i +
// U+0307 nor Final_Sigma (security review of 0.5.0, F12). Expected values
// are Rust's str::to_lowercase.
func TestNormalizeLabelMatchesTheReference(t *testing.T) {
	const (
		sigma      = "\U000003A3" // capital
		final      = "\U000003C2"
		medial     = "\U000003C3"
		acute      = "\U00000301" // Mn: case-ignorable
		dotAbove   = "\U00000307"
		omicron    = "\U0000039F"
		delta      = "\U00000394"
		lowOmicron = "\U000003BF"
		lowDelta   = "\U000003B4"
	)
	odos := omicron + delta + omicron + sigma
	for in, want := range map[string]string{
		"  Example   Infra\tCo ":             "example infra co",
		odos:                                 lowOmicron + lowDelta + lowOmicron + final,
		odos + " " + odos:                    lowOmicron + lowDelta + lowOmicron + final + " " + lowOmicron + lowDelta + lowOmicron + final,
		sigma + omicron:                      medial + lowOmicron,
		sigma:                                medial,
		"A" + sigma:                          "a" + final,
		"A" + sigma + "B":                    "a" + medial + "b",
		"A'" + sigma:                         "a'" + final,
		"A" + sigma + "'":                    "a" + final + "'",
		"A" + sigma + "'B":                   "a" + medial + "'b",
		"1" + sigma:                          "1" + medial,
		"A." + sigma + ".":                   "a." + final + ".",
		"A" + acute + sigma:                  "a" + acute + final,
		"A" + sigma + acute + "b":            "a" + medial + acute + "b",
		"\U00000130NC":                       "i" + dotAbove + "nc",
		"Acme\U00000085Labs":                 "acme labs",
		"\U0000FEFFacme":                     "\U0000FEFFacme",
		"acme\U00003000labs\U00002028":       "acme labs",
		"\U000000A0Org\U00002003X\U000000A0": "org x",
	} {
		if got := normalizeLabel(in); got != want {
			t.Errorf("normalizeLabel(%+q) = %+q, want %+q", in, got, want)
		}
	}
}
