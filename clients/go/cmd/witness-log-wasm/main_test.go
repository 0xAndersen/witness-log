//go:build js && wasm

// Run with GOOS=js GOARCH=wasm go test ./cmd/witness-log-wasm, with Go's
// lib/wasm/go_js_wasm_exec on PATH (it runs the test binary under Node).
package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// corpus17 returns the "valid" dossier text and the text of the input case
// named name.
func corpus17(t *testing.T, name string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("../../../../corpus/17_dossier_parsing.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name        string `json:"name"`
			DossierJSON string `json:"dossier_json"`
		} `json:"cases"`
		Inputs []struct {
			Name string `json:"name"`
			Text string `json:"text"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var dossier, text string
	for _, c := range v.Cases {
		if c.Name == "valid" {
			dossier = c.DossierJSON
		}
	}
	for _, c := range v.Inputs {
		if c.Name == name {
			text = c.Text
		}
	}
	if dossier == "" || text == "" {
		t.Fatalf("no case %q", name)
	}
	return dossier, text
}

// TestOptionsAreReadAsTheRustBuildReadsThem: exact keys, once each, null
// only for optional fields, and a bounded options text. With plain
// encoding/json, {"Evidence": [...]} and {"EXPECTED_IDENTITY_PUBKEY": ...}
// took effect here and not in the Rust build.
func TestOptionsAreReadAsTheRustBuildReadsThem(t *testing.T) {
	dossier, item := corpus17(t, "an evidence item as witness serve writes it, an unknown member nested to depth 1000, the limit")
	key := strings.Repeat("ab", 32)
	nested := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	for _, c := range []struct {
		options string
		verdict string // "" for an error
		pinned  bool
	}{
		{`{}`, "UNANCHORED", false},
		{`{"evidence":[` + item + `]}`, "DIVERGED", false},
		{`{"Evidence":[` + item + `]}`, "UNANCHORED", false},
		{`{"EXPECTED_IDENTITY_PUBKEY":"` + key + `"}`, "UNANCHORED", false},
		{`{"expected_identity_pubkey":"` + key + `"}`, "INVALID", true},
		{`{"expected_identity_pubkey":null,"revocations":null,"subject_org":null}`, "UNANCHORED", false},
		{`{"evidence":[],"evidence":[]}`, "", false},
		{`{"evidence":null}`, "", false},
		{`{"allow_sub_majority":null}`, "", false},
		{`{"min_receipts":-1}`, "", false},
		{`[]`, "", false},
		{`{"zz":` + nested(1001) + `}`, "UNANCHORED", false},
		{`{"zz":` + nested(1002) + `}`, "", false},
	} {
		var out struct {
			Verdict        string `json:"verdict"`
			IdentityPinned bool   `json:"identity_pinned"`
			Error          string `json:"error"`
		}
		if err := json.Unmarshal([]byte(verifyDossier(dossier, nil, c.options)), &out); err != nil {
			t.Fatal(err)
		}
		if c.verdict == "" {
			if out.Error == "" {
				t.Errorf("%.40s: read, %s", c.options, out.Verdict)
			}
			continue
		}
		if out.Error != "" || out.Verdict != c.verdict || out.IdentityPinned != c.pinned {
			t.Errorf("%.40s: %+v, want %s", c.options, out, c.verdict)
		}
	}
}
