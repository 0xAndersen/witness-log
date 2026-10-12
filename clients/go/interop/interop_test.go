// Package interop verifies witness-log's C2SP artefacts with the reference
// implementations other transparency logs and witnesses use, rather than
// with witness-log's own parsers: the corpus vector's signed note and, when
// the CLI is built, a freshly exported note with live cosignatures.
package interop

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

type vector10 struct {
	LogVkey     string `json:"log_vkey"`
	SignedNote  string `json:"signed_note"`
	Cosignature struct {
		WitnessVkey  string `json:"witness_vkey"`
		CosignedNote string `json:"cosigned_note"`
	} `json:"cosignature"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

// The committed corpus vector: the log's own signature verifies with
// x/mod's standard Ed25519 verifier, the cosignature with formats'
// cosignature/v1 verifier, and both at once with a verifier list.
func TestCorpusVector10VerifiesWithReferenceLibraries(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "corpus", "10_c2sp_checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vector10
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	logVkey, witnessVkey, cosignedNote := v.LogVkey, v.Cosignature.WitnessVkey, v.Cosignature.CosignedNote
	if cosignedNote == "" {
		t.Fatal("vector has no cosigned note")
	}

	logV, err := note.NewVerifier(logVkey)
	if err != nil {
		t.Fatalf("x/mod rejects the log vkey %q: %v", logVkey, err)
	}
	cosV, err := fnote.NewVerifierForCosignatureV1(witnessVkey)
	if err != nil {
		t.Fatalf("formats rejects the witness vkey %q: %v", witnessVkey, err)
	}
	n, err := note.Open([]byte(cosignedNote), note.VerifierList(logV, cosV))
	if err != nil {
		t.Fatalf("reference note.Open failed: %v\n%s", err, cosignedNote)
	}
	if len(n.Sigs) != 2 || len(n.UnverifiedSigs) != 0 {
		t.Fatalf("expected both signatures verified, got %d verified, %d unverified", len(n.Sigs), len(n.UnverifiedSigs))
	}
	if !strings.HasPrefix(n.Text, "corpus.witnesslog.example/vector-10\n6\n") {
		t.Fatalf("unexpected note text: %q", n.Text)
	}
	if _, err := fnote.CoSigV1Timestamp(n.Sigs[1]); err != nil {
		// order of Sigs follows the note; find the cosignature by name
		found := false
		for _, s := range n.Sigs {
			if _, err := fnote.CoSigV1Timestamp(s); err == nil {
				found = true
			}
		}
		if !found {
			t.Fatalf("no cosignature/v1 timestamp recoverable: %v", err)
		}
	}
	// Tampering with the body must fail under the same verifiers.
	bad := strings.Replace(cosignedNote, "\n6\n", "\n7\n", 1)
	if _, err := note.Open([]byte(bad), note.VerifierList(logV, cosV)); err == nil {
		t.Fatal("a tampered note verified")
	}
}

// A live round: testnet up, a journal, submit, `c2sp export`, then the
// exported note through the reference verifiers with the testnet witnesses'
// cosignature keys. Skipped when the CLI is not built.
func TestExportedNoteVerifiesWithReferenceLibraries(t *testing.T) {
	root := repoRoot(t)
	bin := os.Getenv("WL_BIN")
	if bin == "" {
		bin = filepath.Join(root, "target", "release", "witness-log")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("witness-log CLI not built; set WL_BIN")
	}
	work := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Dir = work
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	trusted := filepath.Join(work, "trusted.json")
	run("testnet", "up", "--witnesses", "3", "--dir", filepath.Join(work, "tn"), "--out", trusted)
	defer func() { _ = exec.Command(bin, "testnet", "down", "--dir", filepath.Join(work, "tn")).Run() }()
	journal := filepath.Join(work, "agent.jsonl")
	run("log", "init", journal)
	run("log", "append", journal, "--intent", `{"tool":"interop"}`)
	run("log", "append", journal, "--result", `{"ok":true}`, "--outcome", "ok")
	dossier := filepath.Join(work, "dossier.json")
	run("submit", journal, "--directory", trusted, "--out", dossier, "--min", "2")
	notePath := filepath.Join(work, "note.txt")
	run("c2sp", "export", dossier, "--directory", trusted, "--out", notePath)
	text, err := os.ReadFile(notePath)
	if err != nil {
		t.Fatal(err)
	}

	var dir struct {
		Witnesses []struct {
			Name   string `json:"name"`
			Pubkey string `json:"pubkey"`
		} `json:"witnesses"`
	}
	raw, _ := os.ReadFile(trusted)
	if err := json.Unmarshal(raw, &dir); err != nil {
		t.Fatal(err)
	}
	var d struct {
		IdentityPubkey string `json:"identity_pubkey"`
	}
	raw, _ = os.ReadFile(dossier)
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	origin := "witness-log/" + d.IdentityPubkey
	logV, err := note.NewVerifier(vkey(origin, 0x01, d.IdentityPubkey))
	if err != nil {
		t.Fatal(err)
	}
	verifiers := []note.Verifier{logV}
	for _, w := range dir.Witnesses {
		v, err := fnote.NewVerifierForCosignatureV1(vkey(w.Name, 0x04, w.Pubkey))
		if err != nil {
			t.Fatalf("witness %s: %v", w.Name, err)
		}
		verifiers = append(verifiers, v)
	}
	n, err := note.Open(text, note.VerifierList(verifiers...))
	if err != nil {
		t.Fatalf("reference note.Open failed on the exported note: %v\n%s", err, text)
	}
	if !strings.HasPrefix(n.Text, origin+"\n2\n") {
		t.Fatalf("note text %q", n.Text)
	}
	cosigs := 0
	for _, s := range n.Sigs {
		if _, err := fnote.CoSigV1Timestamp(s); err == nil {
			cosigs++
		}
	}
	if cosigs < 2 {
		t.Fatalf("expected at least two cosignature/v1 signatures verified by the reference library, got %d (verified %d, unverified %d)", cosigs, len(n.Sigs), len(n.UnverifiedSigs))
	}
}
