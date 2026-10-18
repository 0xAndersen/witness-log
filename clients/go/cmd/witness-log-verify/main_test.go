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
		{[]string{a, "--directory", dir, "--identity", strings.Repeat("ab", 32)}, 40, "Verdict: INVALID"},
		{[]string{a, "--known-head", "1:" + strings.Repeat("ab", 32)}, 30, "Verdict: DIVERGED"},
		{[]string{a, "--known-head", "1"}, 2, ""},
		{[]string{a, "--known-head"}, 2, ""},
		{[]string{a, "--evidence", "does-not-exist.json"}, 2, ""},
		{[]string{a, "--directory", dir, "--no-strict"}, 2, ""},
		{[]string{a, "--directory", dir, "--strict"}, 0, "Verdict: WITNESSED"},
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
	for _, k := range []string{"path", "identity_pubkey", "threshold_used", "min_witnesses_used", "identity_pinned", "directory_pinned", "strict", "allow_sub_majority", "exit_code", "verdict", "report"} {
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

// RFC-0002: WITNESSED by fewer than a strict majority of the directory
// exits 11 by default; --allow-sub-majority accepts it (--no-strict, kept
// for 0.5.x, is a usage error since 0.6.0).
func TestSplitViewUnsafeExitsEleven(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "native/dossier.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	receipts := d["witness_receipts"].([]any)
	if len(receipts) != 3 {
		t.Fatalf("fixture has %d receipts, want 3 of 4", len(receipts))
	}
	// Keep two receipts from two different operators: 2 of 4 is not a
	// strict majority.
	d["witness_receipts"] = receipts[:2]
	out, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "two-of-four.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(testdata, "native/trusted.json")
	cases := []struct {
		extra []string
		exit  int
		out   string
	}{
		{nil, 11, "Exit 11"},
		{[]string{"--allow-sub-majority"}, 0, "Accepted as exit 0 under --allow-sub-majority"},
	}
	for _, c := range cases {
		args := append([]string{path, "--directory", dir, "--min-witnesses", "2"}, c.extra...)
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != c.exit {
			t.Errorf("%v: exit %d, want %d\n%s%s", c.extra, got, c.exit, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "Verdict: WITNESSED") || !strings.Contains(stdout.String(), c.out) {
			t.Errorf("%v: stdout lacks WITNESSED or %q:\n%s", c.extra, c.out, stdout.String())
		}
		stdout.Reset()
		run(append(args, "--json"), &stdout, &stderr)
		var j map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &j); err != nil {
			t.Fatal(err)
		}
		if int(j["exit_code"].(float64)) != c.exit || j["report"].(map[string]any)["split_view_unsafe"] != true {
			t.Errorf("%v: json exit_code %v split_view_unsafe %v", c.extra, j["exit_code"], j["report"].(map[string]any)["split_view_unsafe"])
		}
	}
}

// TestFlagsParseAsTheReferenceParsesThem: security review of 0.5.0, F6.
// Unknown flags were skipped together with the argument after them, the
// first of a repeated flag won, and --no-strict won wherever it stood, so
// a typo such as --evidance ran without the evidence it named.
// compare-with-rust.sh checks the same cases against the Rust CLI.
func TestFlagsParseAsTheReferenceParsesThem(t *testing.T) {
	a := filepath.Join(testdata, "c2sp/a.json")
	dir := filepath.Join(testdata, "c2sp/trusted.json")
	raw, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		IdentityPubkey string `json:"identity_pubkey"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("ab", 32)
	cases := []struct {
		args []string
		exit int
	}{
		{[]string{a, "--known-heads", "1:" + other}, 2},
		{[]string{a, "--evidance", a}, 2},
		{[]string{a, "--directory", dir, "--jsn"}, 2},
		{[]string{a, a}, 2},
		{[]string{"", a}, 2},
		{[]string{a, "--identity", other, "--identity", d.IdentityPubkey}, 20},
		{[]string{a, "--identity", d.IdentityPubkey, "--identity", other}, 40},
		{[]string{a, "--identity", "zz"}, 2},
		{[]string{a, "--directory", dir, "--min-witnesses", "0"}, 2},
		{[]string{a, "--directory", dir, "--min-witnesses", "9", "--min-witnesses", "1"}, 0},
		{[]string{a, "--directory", dir, "--min-witnesses", "+1"}, 0},
		{[]string{a, "--directory", dir, "--threshold", "0x1p-1"}, 2},
		{[]string{a, "--directory", dir, "--threshold"}, 2},
		{[]string{a, "--directory", "does-not-exist.json", "--directory", dir}, 0},
		{[]string{a, "--directory", dir, "--directory", "does-not-exist.json"}, 2},
		{[]string{a, "--directory", ""}, 2},
		{[]string{a, "--directory", dir, "--subject-org", "--json"}, 2},
		{[]string{a, "--directory", dir, "--explain"}, 0},
		{[]string{a, "--directory", dir, "-h"}, 0},
		{[]string{"bind", a, a, "--jsn"}, 2},
		{[]string{"disclose", a, "0", a, strings.Repeat("00", 32), "--x"}, 2},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		if got := run(c.args, &stdout, &stderr); got != c.exit {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", c.args, got, c.exit, stderr.String())
		}
	}
}

// TestNoStrictIsGoneAndThresholdZero: --no-strict is a usage error
// wherever it stands (it was kept for one release after 0.5.0), and
// --threshold 0 is a zero fraction, not the default, as in the reference CLI.
func TestNoStrictIsGoneAndThresholdZero(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "native/dossier.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	d["witness_receipts"] = d["witness_receipts"].([]any)[:2]
	out, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "two-of-four.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{path, "--directory", filepath.Join(testdata, "native/trusted.json")}
	for _, c := range []struct {
		extra []string
		exit  int
	}{
		{[]string{"--min-witnesses", "2", "--no-strict", "--strict"}, 2},
		{[]string{"--min-witnesses", "2", "--strict", "--no-strict"}, 2},
		{[]string{"--min-witnesses", "2", "--strict"}, 11},
		{[]string{"--threshold", "0"}, 11},
		{nil, 10},
	} {
		var stdout, stderr bytes.Buffer
		if got := run(append(append([]string{}, base...), c.extra...), &stdout, &stderr); got != c.exit {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", c.extra, got, c.exit, stderr.String())
		}
	}
}
