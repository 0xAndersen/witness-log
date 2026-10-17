package witnesslog

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

// TestCorpus14FleetAnchor runs every case of the RFC-0001 vector
// (EXPERIMENTAL) through the Go verifier: verdict, exit code, quorum
// counts, the fleet anchor's status and, with the opt-in only, the
// witnessed_via and witness_paths report fields.
func TestCorpus14FleetAnchor(t *testing.T) {
	var v struct {
		TrustedDirectory json.RawMessage            `json:"trusted_directory"`
		Dossiers         map[string]json.RawMessage `json:"dossiers"`
		FleetLog         struct {
			EntriesB64     []string `json:"entries_b64"`
			LeafHashesHex  []string `json:"leaf_hashes_hex"`
			TreeSize       uint64   `json:"tree_size"`
			RootHex        string   `json:"root_hex"`
			ProofHex       []string `json:"entry_2_inclusion_proof_hex"`
			FleetVkey      string   `json:"fleet_vkey"`
			CheckpointNote string   `json:"checkpoint_note"`
		} `json:"fleet_log"`
		Cases []struct {
			Name              string  `json:"name"`
			Dossier           string  `json:"dossier"`
			TrustedDirectory  bool    `json:"trusted_directory"`
			AcceptFleetAnchor bool    `json:"accept_fleet_anchor"`
			SubjectOrg        *string `json:"subject_org"`
			Threshold         float64 `json:"threshold"`
			MinWitnesses      *int    `json:"min_witnesses"`
			AllowSubMajority  bool    `json:"allow_sub_majority"`
			Expect            struct {
				Verdict              string          `json:"verdict"`
				ExitCode             int             `json:"exit_code"`
				SplitViewUnsafe      bool            `json:"split_view_unsafe"`
				ValidReceipts        *int            `json:"valid_receipts"`
				IndependentOperators *int            `json:"independent_operators"`
				FleetAnchorStatus    *string         `json:"fleet_anchor_status"`
				FleetTreeSize        *uint64         `json:"fleet_tree_size"`
				WitnessedVia         json.RawMessage `json:"witnessed_via"`
				WitnessPaths         json.RawMessage `json:"witness_paths"`
			} `json:"expect"`
		} `json:"cases"`
	}
	readCorpus(t, "14_fleet_anchor.json", &v)

	// The fleet log's own values.
	var leaves []Hash
	for i, e := range v.FleetLog.EntriesB64 {
		b, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			t.Fatal(err)
		}
		h := LeafHash(b)
		if hex.EncodeToString(h[:]) != v.FleetLog.LeafHashesHex[i] {
			t.Errorf("leaf hash %d", i)
		}
		leaves = append(leaves, h)
	}
	root := MerkleRoot(leaves)
	if uint64(len(leaves)) != v.FleetLog.TreeSize || hex.EncodeToString(root[:]) != v.FleetLog.RootHex {
		t.Errorf("fleet root")
	}
	var proofHex []string
	for _, p := range InclusionProof(leaves, 2) {
		proofHex = append(proofHex, hex.EncodeToString(p[:]))
	}
	if !reflect.DeepEqual(proofHex, v.FleetLog.ProofHex) {
		t.Errorf("inclusion proof for entry 2: %v want %v", proofHex, v.FleetLog.ProofHex)
	}
	vk, err := ParseVerifierKey(v.FleetLog.FleetVkey)
	if err != nil {
		t.Fatal(err)
	}
	note, err := ParseC2SPNote(v.FleetLog.CheckpointNote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Verify([]VerifierKey{vk}); err != nil {
		t.Errorf("fleet checkpoint note: %v", err)
	}

	dir, err := ParseDirectory(v.TrustedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	exits := map[int]bool{}
	for _, c := range v.Cases {
		d, err := ParseDossier(v.Dossiers[c.Dossier])
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		opts := Options{Threshold: c.Threshold, MinReceipts: c.MinWitnesses, AcceptFleetAnchor: c.AcceptFleetAnchor}
		if c.SubjectOrg != nil {
			opts.SubjectOrg = *c.SubjectOrg
		}
		var trusted *Directory
		if c.TrustedDirectory {
			trusted = dir
		}
		r := d.Verify(trusted, opts)
		e := c.Expect
		got, _ := json.Marshal(r.Verdict)
		if string(got) != `"`+e.Verdict+`"` {
			t.Errorf("%s: verdict %s want %s (failures %v)", c.Name, got, e.Verdict, r.Failures)
		}
		if code := r.ExitCode(c.AllowSubMajority); code != e.ExitCode {
			t.Errorf("%s: exit %d want %d", c.Name, code, e.ExitCode)
		}
		if r.SplitViewUnsafe != e.SplitViewUnsafe {
			t.Errorf("%s: split_view_unsafe %t", c.Name, r.SplitViewUnsafe)
		}
		if (r.Quorum == nil) != (e.ValidReceipts == nil) || (r.Quorum != nil && (r.Quorum.ValidReceipts != *e.ValidReceipts || r.Quorum.DistinctIndependentOperators != *e.IndependentOperators)) {
			t.Errorf("%s: quorum %+v, want valid %v independent %v", c.Name, r.Quorum, e.ValidReceipts, e.IndependentOperators)
		}
		if (r.FleetAnchor == nil) != (e.FleetAnchorStatus == nil) || (r.FleetAnchor != nil && r.FleetAnchor.Status != *e.FleetAnchorStatus) {
			t.Errorf("%s: fleet anchor %+v, want status %v", c.Name, r.FleetAnchor, e.FleetAnchorStatus)
		}
		var gotSize *uint64
		if r.FleetAnchor != nil {
			gotSize = r.FleetAnchor.FleetTreeSize
		}
		if (gotSize == nil) != (e.FleetTreeSize == nil) || (gotSize != nil && *gotSize != *e.FleetTreeSize) {
			t.Errorf("%s: fleet_tree_size %v want %v", c.Name, gotSize, e.FleetTreeSize)
		}
		report, _ := json.Marshal(r)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(report, &m)
		if c.AcceptFleetAnchor {
			if !jsonEqual(m["witnessed_via"], e.WitnessedVia) || !jsonEqual(m["witness_paths"], e.WitnessPaths) {
				t.Errorf("%s: witnessed_via %s paths %s, want %s %s", c.Name, m["witnessed_via"], m["witness_paths"], e.WitnessedVia, e.WitnessPaths)
			}
		} else if _, ok := m["witnessed_via"]; ok {
			t.Errorf("%s: witnessed_via present without the opt-in", c.Name)
		} else if _, ok := m["witness_paths"]; ok {
			t.Errorf("%s: witness_paths present without the opt-in", c.Name)
		}
		exits[e.ExitCode] = true
	}
	for _, code := range []int{0, 10, 11, 20} {
		if !exits[code] {
			t.Errorf("no case exits %d", code)
		}
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// A dossier without a fleet_anchor, or a caller without the opt-in, gets
// the report it got before: compare every corpus 13 case's report with an
// anchor attached and the opt-in off.
func TestFleetAnchorIgnoredWithoutOptIn(t *testing.T) {
	var v13 struct {
		TrustedDirectory json.RawMessage            `json:"trusted_directory"`
		Dossiers         map[string]json.RawMessage `json:"dossiers"`
	}
	readCorpus(t, "13_verdicts.json", &v13)
	var v14 struct {
		Dossiers map[string]map[string]json.RawMessage `json:"dossiers"`
	}
	readCorpus(t, "14_fleet_anchor.json", &v14)
	anchor := v14.Dossiers["fleet_only"]["fleet_anchor"]
	dir, err := ParseDirectory(v13.TrustedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	two := 2
	for name, raw := range v13.Dossiers {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["fleet_anchor"] = anchor
		anchored, _ := json.Marshal(m)
		for _, opts := range []Options{{}, {MinReceipts: &two, SubjectOrg: "corpus-operator-1"}} {
			_, plain, err := VerifyDossier(raw, dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			_, withAnchor, err := VerifyDossier(anchored, dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			if withAnchor.FleetAnchor == nil || withAnchor.FleetAnchor.Status != "ignored" {
				t.Errorf("%s: fleet anchor %+v", name, withAnchor.FleetAnchor)
			}
			withAnchor.FleetAnchor = nil
			a, _ := json.Marshal(plain)
			b, _ := json.Marshal(withAnchor)
			if string(a) != string(b) {
				t.Errorf("%s: report changed without the opt-in:\n%s\n%s", name, a, b)
			}
		}
	}
}
