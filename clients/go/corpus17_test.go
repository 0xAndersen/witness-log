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
