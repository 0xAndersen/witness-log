package witnesslog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCorpus17DossierParsing runs corpus vector 17 (outside review of
// 0.6.0, H2 and P3): each case's dossier_json, byte for byte, through
// VerifyDossier. A text the reference cannot deserialise must come back as
// Invalid with an error and no report; every other case must give the
// reference's verdict, exit code and report fields. Before the fix
// encoding/json read null, repeated keys, keys differing only in case,
// unpaired surrogates and serde's {"Variant": null} differently.
func TestCorpus17DossierParsing(t *testing.T) {
	var v struct {
		Directories map[string]json.RawMessage `json:"directories"`
		Cases       []corpusVerdictCase        `json:"cases"`
	}
	readCorpus(t, "17_dossier_parsing.json", &v)
	if len(v.Cases) < 100 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	refused := 0
	exits := map[int]bool{}
	for _, c := range v.Cases {
		if c.DossierJSON == nil {
			t.Fatalf("%s: no dossier_json", c.Name)
		}
		if c.Expect.NotADossier {
			refused++
		} else {
			exits[c.Expect.ExitCode] = true
		}
		checkVerdictCase(t, c, []byte(*c.DossierJSON), v.Directories, nil)
	}
	if refused < 50 {
		t.Errorf("only %d texts the reference refuses", refused)
	}
	for _, code := range []int{0, 10, 20, 40} {
		if !exits[code] {
			t.Errorf("no case exercises exit %d", code)
		}
	}
}

// corpusInputCase is one of corpus 17's `inputs`: a directory, revocations
// or evidence text, given with the dossier of the case named by Dossier.
type corpusInputCase struct {
	Name         string `json:"name"`
	Input        string `json:"input"`
	Text         string `json:"text"`
	Dossier      string `json:"dossier"`
	MinWitnesses *int   `json:"min_witnesses"`
	Expect       struct {
		Refused        bool    `json:"refused"`
		Verdict        *string `json:"verdict"`
		ExitCode       int     `json:"exit_code"`
		HasFailures    *bool   `json:"has_failures"`
		Contradictions *int    `json:"contradictions"`
		ValidReceipts  *int    `json:"valid_receipts"`
	} `json:"expect"`
}

// TestCorpus17Inputs runs corpus 17's `inputs`: the nesting limit covers
// every JSON input, not only the dossier. Before, ParseDirectory,
// ParseRevocations and ParseEvidence refused an input only at
// encoding/json's 10,000 levels (the reference read a directory or
// revocations of any depth, and an evidence item to 128 levels).
func TestCorpus17Inputs(t *testing.T) {
	var v struct {
		Cases  []corpusVerdictCase `json:"cases"`
		Inputs []corpusInputCase   `json:"inputs"`
	}
	readCorpus(t, "17_dossier_parsing.json", &v)
	dossiers := map[string][]byte{}
	for _, c := range v.Cases {
		dossiers[c.Name] = []byte(*c.DossierJSON)
	}
	kinds := map[string]int{}
	for _, c := range v.Inputs {
		kinds[c.Input]++
		start := time.Now()
		opts := Options{Threshold: DefaultThreshold, ThresholdSet: true, MinReceipts: c.MinWitnesses}
		var directory *Directory
		var err error
		switch c.Input {
		case "directory":
			directory, err = ParseDirectory([]byte(c.Text))
		case "revocations":
			opts.Revocations, err = ParseRevocations([]byte(c.Text))
		case "evidence":
			var p EquivocationProof
			if p, err = ParseEvidence([]byte(c.Text)); err == nil {
				opts.Evidence = []EquivocationProof{p}
			}
		default:
			t.Fatalf("%s: unknown input %q", c.Name, c.Input)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: reading took %v", c.Name, time.Since(start))
		}
		e := c.Expect
		if e.Refused {
			// The cases about nesting are refused for their depth.
			if err == nil || (strings.Contains(c.Name, "nested") && !strings.Contains(err.Error(), "nested deeper than 1000")) {
				t.Errorf("%s: refused by the reference, got %v", c.Name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		raw, ok := dossiers[c.Dossier]
		if !ok {
			t.Fatalf("%s: no case %q", c.Name, c.Dossier)
		}
		verdict, r, err := VerifyDossier(raw, directory, opts)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		got, _ := json.Marshal(r.Verdict)
		if e.Verdict == nil || string(got) != `"`+*e.Verdict+`"` || r.ExitCode(false) != e.ExitCode {
			t.Errorf("%s: %v (exit %d), want %v (exit %d); failures %v", c.Name, verdict, r.ExitCode(false), e.Verdict, e.ExitCode, r.Failures)
		}
		if (len(r.Failures) > 0) != *e.HasFailures || len(r.Contradictions) != *e.Contradictions {
			t.Errorf("%s: report %+v", c.Name, r)
		}
		if (r.Quorum == nil) != (e.ValidReceipts == nil) || (r.Quorum != nil && r.Quorum.ValidReceipts != *e.ValidReceipts) {
			t.Errorf("%s: quorum %+v, want valid_receipts %v", c.Name, r.Quorum, e.ValidReceipts)
		}
	}
	for _, k := range []string{"directory", "revocations", "evidence"} {
		if kinds[k] < 6 {
			t.Errorf("only %d %s inputs", kinds[k], k)
		}
	}
}

// TestEvidenceIsValidUTF8: an evidence item is UTF-8 JSON, as every other
// input (a corpus, itself JSON, cannot carry invalid UTF-8). Before,
// ParseEvidence alone of the Parse functions read invalid bytes in an
// ignored member as U+FFFD, and the reference refused the file.
func TestEvidenceIsValidUTF8(t *testing.T) {
	var v struct {
		Inputs []corpusInputCase `json:"inputs"`
	}
	readCorpus(t, "17_dossier_parsing.json", &v)
	var item string
	for _, c := range v.Inputs {
		if c.Name == "an evidence item with an ignored member holding 1e400" {
			item = c.Text
		}
	}
	if _, err := ParseEvidence([]byte(item)); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(item, "1e400", "\"\xff\"", 1)
	if _, err := ParseEvidence([]byte(bad)); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("invalid UTF-8 in an ignored member: %v", err)
	}
}

// TestCheckJSONDepth: the one check, counted the same way for every input.
func TestCheckJSONDepth(t *testing.T) {
	nested := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	if MaxDossierDepth != 1000 {
		t.Fatal(MaxDossierDepth)
	}
	for _, ok := range []string{"1", nested(1000), `["\"` + strings.Repeat("{", 2000) + `"]`, "[]]]]"} {
		if err := CheckJSONDepth([]byte(ok)); err != nil {
			t.Errorf("%.20s: %v", ok, err)
		}
	}
	err := CheckJSONDepth([]byte(nested(1001)))
	if err == nil || err.Error() != "nested deeper than 1000 arrays and objects (at byte 1000)" {
		t.Errorf("1001 deep: %v", err)
	}
}

// minimalDossier is corpus 17's smallest valid dossier text (UNANCHORED).
func minimalDossier(t *testing.T) string {
	t.Helper()
	var v struct {
		Cases []corpusVerdictCase `json:"cases"`
	}
	readCorpus(t, "17_dossier_parsing.json", &v)
	for _, c := range v.Cases {
		if c.Name == "whitespace around the object" {
			return strings.TrimSpace(*c.DossierJSON)
		}
	}
	t.Fatal("no minimal dossier in corpus 17")
	return ""
}

// withField adds a member before the closing brace of the top-level object.
func withField(text, field string) string {
	return text[:len(text)-1] + "," + field + "}"
}

// TestDossierDepthLimit: a dossier text nests at most 1000 arrays and
// objects deep (SPEC.md §9), wherever the nesting is. Before, Go's limit was
// encoding/json's 10,000, and the reference read an ignored key of any depth
// (outside audit of 0.6.1).
func TestDossierDepthLimit(t *testing.T) {
	base := minimalDossier(t)
	nested := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	objects := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	for _, ok := range []string{nested(999), objects(999), `"\"` + strings.Repeat("[", 5000) + `"`} {
		if v, _, err := VerifyDossier([]byte(withField(base, `"zz":`+ok)), nil, Options{}); err != nil || v != Unanchored {
			t.Errorf("depth 1000: %v %v", v, err)
		}
	}
	for _, n := range []int{1000, 9998, 9999, 100_000} {
		for _, deep := range []string{nested(n), objects(n)} {
			start := time.Now()
			v, r, err := VerifyDossier([]byte(withField(base, `"zz":`+deep)), nil, Options{})
			if err == nil || v != Invalid || r != nil {
				t.Fatalf("an ignored key %d deep: %v %v", n, v, err)
			}
			if !strings.Contains(err.Error(), "nested deeper than 1000") {
				t.Errorf("an ignored key %d deep: %v", n, err)
			}
			if time.Since(start) > 2*time.Second {
				t.Errorf("an ignored key %d deep took %v", n, time.Since(start))
			}
		}
	}
}

// TestRefusalsQuoteABoundedPart: a refusal or a failure quotes a bounded
// part of a hostile input, never all of it (outside audit of 0.6.1: a
// 10-million-digit literal came back whole).
func TestRefusalsQuoteABoundedPart(t *testing.T) {
	base := minimalDossier(t)
	huge := strings.Repeat("S", 10_000_000)
	digits := "1" + strings.Repeat("0", 10_000_000)
	for name, text := range map[string]string{
		"a 10-million-digit tree_size": strings.Replace(base, `"tree_size":0`, `"tree_size":`+digits, 1),
		"a 10-million-character variant": strings.Replace(base, `"witness_directory":{"witnesses":[]}`,
			`"witness_directory":{"witnesses":[{"name":"n","operator_org":"o","url":"u","pubkey":"p","runtime":"`+huge+`"}]}`, 1),
	} {
		start := time.Now()
		_, _, err := VerifyDossier([]byte(text), nil, Options{})
		if err == nil {
			t.Fatalf("%s: read", name)
		}
		if len(err.Error()) > 400 {
			t.Errorf("%s: a %d-byte error", name, len(err.Error()))
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s took %v", name, time.Since(start))
		}
	}
	// A dossier, INVALID: the leaf check names the field without all of it.
	key := strings.Repeat("aa", 32)
	text := `{"identity_pubkey":"` + key + `","leaves":[{"index":0,"leaf_type":1,"timestamp_ms":1,"session_pubkey":"` + key +
		`","payload_hash":"` + huge + `"}],"checkpoint":{"sig_alg":"ed25519","tree_size":1,"root_hash":"","timestamp_ms":0,"signer_pubkey":"` + key + `","signature":""}}`
	v, r, err := VerifyDossier([]byte(text), nil, Options{})
	if err != nil || v != Invalid {
		t.Fatalf("%v %v", v, err)
	}
	found := false
	for _, f := range r.Failures {
		if len(f) > 400 {
			t.Errorf("a %d-byte failure", len(f))
		}
		found = found || strings.Contains(f, "payload_hash")
	}
	if !found {
		t.Errorf("no payload_hash failure in %q", r.Failures)
	}
}

func TestEchoAndBoundMessage(t *testing.T) {
	if got := echo("abc"); got != `"abc"` {
		t.Errorf("echo: %s", got)
	}
	long := strings.Repeat("é", 100)
	if got, want := echo(long), `"`+strings.Repeat("é", 64)+`"… (200 bytes)`; got != want {
		t.Errorf("echo: %s", got)
	}
	if got := boundMessage("short"); got != "short" {
		t.Errorf("boundMessage: %s", got)
	}
	msg := `json: cannot unmarshal number ` + strings.Repeat("1", 1_000_000) + ` into Go struct field .tree_size of type uint64`
	got := boundMessage(msg)
	if !strings.HasPrefix(got, "json: cannot unmarshal number 111") || !strings.HasSuffix(got, "1 into Go struct field .tree_size of type uint64") ||
		!strings.Contains(got, "bytes elided") || len(got) > 400 {
		t.Errorf("boundMessage: %s", got)
	}
}

// TestDecodesAsPoint pins the point decoding the key binding check uses
// against a few known encodings.
func TestDecodesAsPoint(t *testing.T) {
	for _, c := range []struct {
		hex string
		ok  bool
	}{
		{"0100000000000000000000000000000000000000000000000000000000000000", true},  // identity
		{"0100000000000000000000000000000000000000000000000000000000000080", true},  // identity, sign bit
		{"0000000000000000000000000000000000000000000000000000000000000000", true},  // order 4
		{"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},  // y = p
		{"0200000000000000000000000000000000000000000000000000000000000000", false}, // y = 2: not on the curve
	} {
		if got := decodesAsPoint(mustHex(c.hex)); got != c.ok {
			t.Errorf("%s: %v, want %v", c.hex, got, c.ok)
		}
	}
}
