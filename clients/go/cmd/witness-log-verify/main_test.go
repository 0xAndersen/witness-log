package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../testdata"

func TestExitCodesAreTheVerdict(t *testing.T) {
	a := filepath.Join(testdata, "c2sp/a.json")
	b := filepath.Join(testdata, "c2sp/b.json")
	dir := filepath.Join(testdata, "c2sp/trusted.json")
	cases := []struct {
		args []string
		exit int
		out  string
	}{
		{[]string{a}, 20, "Verdict: UNANCHORED"},
		{[]string{a, "--directory", dir}, 0, "Verdict: WITNESSED"},
		{[]string{a, "--directory", dir, "--identity", strings.Repeat("ab", 32)}, 30, "Verdict: DIVERGED"},
		{[]string{a, "--directory", dir, "--min-witnesses", "3"}, 10, "Verdict: CONSISTENT-UNWITNESSED"},
		{[]string{a, "--directory", dir, "--json"}, 0, `"verdict": "WITNESSED"`},
		{[]string{"bind", a, b}, 0, "Result: BOUND"},
		{[]string{"bind", a, b, "--json"}, 0, `"exit": 0`},
		{[]string{"bind", a, a}, 2, ""},
		{[]string{"does-not-exist.json"}, 2, ""},
		{[]string{a, "--directory", "does-not-exist.json"}, 2, ""},
		{[]string{a, "--threshold", "7"}, 2, ""},
		{[]string{}, 2, ""},
		{[]string{"--help"}, 0, "EXIT CODES"},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		got := run(c.args, &stdout, &stderr)
		if got != c.exit {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", c.args, got, c.exit, stderr.String())
		}
		if c.out != "" && !strings.Contains(stdout.String(), c.out) {
			t.Errorf("%v: stdout lacks %q:\n%s", c.args, c.out, stdout.String())
		}
	}
}

func TestJSONReportMatchesLibraryShape(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{filepath.Join(testdata, "native/dossier.json"), "--directory", filepath.Join(testdata, "native/trusted.json"), "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"path", "identity_pubkey", "threshold_used", "min_witnesses_used", "identity_pinned", "directory_pinned", "verdict", "report"} {
		if _, ok := out[k]; !ok {
			t.Errorf("missing top-level key %s", k)
		}
	}
	// The same keys the Rust CLI prints, so a consumer can swap binaries.
	rust, err := os.ReadFile(filepath.Join(testdata, "expect/native.directory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal(rust, &want)
	for k := range want {
		if k == "path" {
			continue
		}
		if _, ok := out[k]; !ok {
			t.Errorf("Rust CLI prints %s, Go CLI does not", k)
		}
	}
}

func TestDisclose(t *testing.T) {
	var fx struct {
		PayloadHex string `json:"payload_hex"`
		SaltHex    string `json:"salt_hex"`
	}
	raw, err := os.ReadFile(filepath.Join(testdata, "c2sp/disclosure.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &fx)
	payloadFile := filepath.Join(t.TempDir(), "payload.bin")
	payload, err := hex.DecodeString(fx.PayloadHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"disclose", filepath.Join(testdata, "c2sp/a.json"), "0", payloadFile, fx.SaltHex}, &stdout, &stderr); code != 0 {
		t.Errorf("disclosure must verify: exit %d %s %s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"disclose", filepath.Join(testdata, "c2sp/a.json"), "1", payloadFile, fx.SaltHex}, &stdout, &stderr); code != 30 {
		t.Errorf("wrong leaf must exit 30, got %d", code)
	}
	if code := run([]string{"disclose", filepath.Join(testdata, "c2sp/a.json"), "0", payloadFile, "zz"}, &stdout, &stderr); code != 2 {
		t.Errorf("bad salt must exit 2, got %d", code)
	}
}
