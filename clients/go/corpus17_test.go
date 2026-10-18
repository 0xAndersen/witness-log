package witnesslog

import (
	"encoding/json"
	"testing"
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
