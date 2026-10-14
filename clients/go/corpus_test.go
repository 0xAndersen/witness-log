package witnesslog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// corpusDir is <repo>/corpus, resolved relative to this package so that
// `go test ./...` works from clients/go without any setup.
const corpusDir = "../../corpus"

func readCorpus(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, name))
	if err != nil {
		t.Fatalf("corpus vector %s: %v (run from clients/go inside the repository)", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("corpus vector %s: %v", name, err)
	}
}

func hashFromHex(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var h Hash
	copy(h[:], b)
	return h
}

func hashesFromHex(t *testing.T, ss []string) []Hash {
	out := make([]Hash, len(ss))
	for i, s := range ss {
		out[i] = hashFromHex(t, s)
	}
	return out
}

// fixedLeaf reproduces generate_corpus.rs's fixed_leaf for the Merkle
// vectors, whose leaves are not spelled out in the files.
func fixedLeaf(index uint64, sessionPubkey string, payloadByte byte) Leaf {
	ph := make([]byte, 32)
	for i := range ph {
		ph[i] = payloadByte
	}
	return Leaf{
		Index:         index,
		LeafType:      LeafActiveIntent,
		TimestampMs:   1_700_000_000_000 + index*1000,
		SessionPubkey: sessionPubkey,
		PayloadHash:   hex.EncodeToString(ph),
	}
}

// fixedSessionPubkey is the public key of the corpus's FIXED_SEED.
func fixedSessionPubkey(t *testing.T) string {
	var v struct {
		SeedHex string `json:"seed_hex"`
	}
	readCorpus(t, "04_signed_tree_head.json", &v)
	seed, _ := hex.DecodeString(v.SeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

type leafVector struct {
	Leaf              json.RawMessage `json:"leaf"`
	CanonicalBytesHex string          `json:"canonical_bytes_hex"`
	LeafHashHex       string          `json:"leaf_hash_hex"`
}

func checkLeafVector(t *testing.T, name string, v leafVector) {
	t.Helper()
	leaf, err := ParseLeaf(v.Leaf)
	if err != nil {
		t.Fatalf("%s: parse: %v", name, err)
	}
	if got := hex.EncodeToString(leaf.CanonicalBytes()); got != v.CanonicalBytesHex {
		t.Errorf("%s: canonical bytes\n got %s\nwant %s", name, got, v.CanonicalBytesHex)
	}
	h := leaf.LeafHash()
	if got := hex.EncodeToString(h[:]); got != v.LeafHashHex {
		t.Errorf("%s: leaf hash got %s want %s", name, got, v.LeafHashHex)
	}
	if err := leaf.Validate(leaf.Index); err != nil {
		t.Errorf("%s: corpus leaf must validate: %v", name, err)
	}
	// Round trip through JSON preserves the canonical bytes.
	again, err := json.Marshal(leaf)
	if err != nil {
		t.Fatal(err)
	}
	re, err := ParseLeaf(again)
	if err != nil {
		t.Fatalf("%s: reparse: %v", name, err)
	}
	if hex.EncodeToString(re.CanonicalBytes()) != v.CanonicalBytesHex {
		t.Errorf("%s: canonical bytes changed after a JSON round trip", name)
	}
}

func TestCorpus01LeafEncoding(t *testing.T) {
	var v struct {
		Vectors []leafVector `json:"vectors"`
	}
	readCorpus(t, "01_leaf_encoding.json", &v)
	if len(v.Vectors) != 5 {
		t.Fatalf("expected 5 vectors, got %d", len(v.Vectors))
	}
	for i, vec := range v.Vectors {
		checkLeafVector(t, "01/"+string(rune('0'+i)), vec)
	}
}

func TestCorpus02MerkleRoots(t *testing.T) {
	var v struct {
		Vectors []struct {
			TreeSize uint64 `json:"tree_size"`
			RootHex  string `json:"root_hex"`
		} `json:"vectors"`
	}
	readCorpus(t, "02_merkle_roots.json", &v)
	session := fixedSessionPubkey(t)
	if len(v.Vectors) != 8 {
		t.Fatalf("expected 8 vectors, got %d", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		var hashes []Hash
		for i := uint64(0); i < vec.TreeSize; i++ {
			l := fixedLeaf(i, session, byte(i)+1)
			hashes = append(hashes, l.LeafHash())
		}
		root := MerkleRoot(hashes)
		if got := hex.EncodeToString(root[:]); got != vec.RootHex {
			t.Errorf("tree_size %d: root got %s want %s", vec.TreeSize, got, vec.RootHex)
		}
	}
	empty := EmptyRoot()
	if hex.EncodeToString(empty[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root must be SHA256(\"\")")
	}
}

func TestCorpus03InclusionProofs(t *testing.T) {
	var v struct {
		RootHex string `json:"root_hex"`
		Vectors []struct {
			LeafIndex   uint64   `json:"leaf_index"`
			TreeSize    uint64   `json:"tree_size"`
			LeafHashHex string   `json:"leaf_hash_hex"`
			ProofHex    []string `json:"proof_hex"`
		} `json:"vectors"`
	}
	readCorpus(t, "03_inclusion_proofs.json", &v)
	root := hashFromHex(t, v.RootHex)
	session := fixedSessionPubkey(t)
	if len(v.Vectors) != 7 {
		t.Fatalf("expected 7 vectors, got %d", len(v.Vectors))
	}
	var leaves []Hash
	for i := uint64(0); i < 7; i++ {
		l := fixedLeaf(i, session, byte(i)+1)
		leaves = append(leaves, l.LeafHash())
	}
	for _, vec := range v.Vectors {
		leaf := hashFromHex(t, vec.LeafHashHex)
		proof := hashesFromHex(t, vec.ProofHex)
		if !VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize, proof, root) {
			t.Errorf("index %d: corpus proof must verify", vec.LeafIndex)
		}
		// The generator side agrees too.
		gen := InclusionProof(leaves, vec.LeafIndex)
		if len(gen) != len(proof) {
			t.Fatalf("index %d: generated proof has %d elements, corpus %d", vec.LeafIndex, len(gen), len(proof))
		}
		for i := range gen {
			if gen[i] != proof[i] {
				t.Errorf("index %d: generated proof element %d differs from corpus", vec.LeafIndex, i)
			}
		}
		// Mutations fail: wrong index, wrong size, a flipped element, an
		// extra element at either end, a missing element.
		if VerifyInclusion(leaf, vec.LeafIndex+1, vec.TreeSize, proof, root) && vec.LeafIndex+1 < vec.TreeSize {
			if leaves[vec.LeafIndex+1] != leaf {
				t.Errorf("index %d: proof verified for a different index", vec.LeafIndex)
			}
		}
		// A size that changes the path shape (7 -> 8 does not for indices
		// below 6, and the reference accepts that too) must fail.
		if VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize*2, proof, root) {
			t.Errorf("index %d: proof verified for a different tree size", vec.LeafIndex)
		}
		bad := append([]Hash(nil), proof...)
		bad[0][0] ^= 1
		if VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize, bad, root) {
			t.Errorf("index %d: altered proof verified", vec.LeafIndex)
		}
		if VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize, append([]Hash{{}}, proof...), root) {
			t.Errorf("index %d: proof with a prepended element verified", vec.LeafIndex)
		}
		if VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize, append(append([]Hash(nil), proof...), Hash{}), root) {
			t.Errorf("index %d: proof with an appended element verified", vec.LeafIndex)
		}
		if VerifyInclusion(leaf, vec.LeafIndex, vec.TreeSize, proof[:len(proof)-1], root) {
			t.Errorf("index %d: truncated proof verified", vec.LeafIndex)
		}
	}
	if VerifyInclusion(leaves[6], 7, 7, hashesFromHex(t, v.Vectors[6].ProofHex), root) {
		t.Errorf("an index equal to the tree size must never verify")
	}
}

func TestCorpus04SignedTreeHead(t *testing.T) {
	var v struct {
		SeedHex string         `json:"seed_hex"`
		STH     SignedTreeHead `json:"sth"`
	}
	readCorpus(t, "04_signed_tree_head.json", &v)
	if err := v.STH.Verify(); err != nil {
		t.Fatalf("corpus STH must verify: %v", err)
	}
	// Reproduce the signature from the published seed: Ed25519 is
	// deterministic, so the bytes must match exactly.
	seed, _ := hex.DecodeString(v.SeedHex)
	key := ed25519.NewKeyFromSeed(seed)
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if pub != v.STH.SignerPubkey {
		t.Fatalf("seed public key %s != signer_pubkey %s", pub, v.STH.SignerPubkey)
	}
	msg := STHMessage(v.STH.SigAlg, v.STH.SignerPubkey, v.STH.TreeSize, hashFromHex(t, v.STH.RootHash), v.STH.TimestampMs)
	sig := ed25519.Sign(key, msg)
	if hex.EncodeToString(sig) != v.STH.Signature {
		t.Errorf("re-signed STH differs from corpus signature")
	}
	for name, mutate := range map[string]func(s *SignedTreeHead){
		"tree_size":     func(s *SignedTreeHead) { s.TreeSize++ },
		"root_hash":     func(s *SignedTreeHead) { s.RootHash = "00" + s.RootHash[2:] },
		"timestamp":     func(s *SignedTreeHead) { s.TimestampMs++ },
		"sig_alg":       func(s *SignedTreeHead) { s.SigAlg = "ml-dsa-65" },
		"signer_pubkey": func(s *SignedTreeHead) { s.SignerPubkey = "00" + s.SignerPubkey[2:] },
		"signature":     func(s *SignedTreeHead) { s.Signature = "00" + s.Signature[2:] },
		"uppercase_sig": func(s *SignedTreeHead) { s.Signature = s.Signature[:63] + "F" },
	} {
		s := v.STH
		mutate(&s)
		if s.Verify() == nil && name != "uppercase_sig" {
			t.Errorf("mutated %s still verified", name)
		}
	}
}

func TestCorpus05RedactionContinuity(t *testing.T) {
	var v struct {
		LeavesBefore  []json.RawMessage `json:"leaves_before_redaction"`
		RootBeforeHex string            `json:"root_before_hex"`
		Marker        json.RawMessage   `json:"redaction_marker_leaf"`
		RootAfterHex  string            `json:"root_after_hex"`
	}
	readCorpus(t, "05_redaction_continuity.json", &v)
	var hashes []Hash
	var leaves []Leaf
	for i, raw := range v.LeavesBefore {
		l, err := ParseLeaf(raw)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		leaves = append(leaves, *l)
		hashes = append(hashes, l.LeafHash())
	}
	before := MerkleRoot(hashes)
	if hex.EncodeToString(before[:]) != v.RootBeforeHex {
		t.Errorf("root before redaction differs")
	}
	marker, err := ParseLeaf(v.Marker)
	if err != nil {
		t.Fatal(err)
	}
	if marker.LeafType != LeafRedaction || marker.RedactedIndex == nil || *marker.RedactedIndex != 1 {
		t.Fatalf("marker is not a redaction of index 1")
	}
	leaves = append(leaves, *marker)
	if err := ValidateSequence(leaves); err != nil {
		t.Errorf("sequence with marker must validate: %v", err)
	}
	after := MerkleRoot(append(hashes, marker.LeafHash()))
	if hex.EncodeToString(after[:]) != v.RootAfterHex {
		t.Errorf("root after redaction differs")
	}
	// The old root is still provable from the new tree: consistency.
	proof := ConsistencyProof(append(hashes, marker.LeafHash()), 4)
	if !VerifyConsistency(4, before, 5, after, proof) {
		t.Errorf("redaction must be an append-only extension")
	}
}

func TestCorpus06ConsistencyProof(t *testing.T) {
	var v struct {
		OldSize    uint64   `json:"old_tree_size"`
		OldRootHex string   `json:"old_root_hex"`
		NewSize    uint64   `json:"new_tree_size"`
		NewRootHex string   `json:"new_root_hex"`
		ProofHex   []string `json:"proof_hex"`
	}
	readCorpus(t, "06_consistency_proof.json", &v)
	oldRoot := hashFromHex(t, v.OldRootHex)
	newRoot := hashFromHex(t, v.NewRootHex)
	proof := hashesFromHex(t, v.ProofHex)
	if !VerifyConsistency(v.OldSize, oldRoot, v.NewSize, newRoot, proof) {
		t.Fatalf("corpus consistency proof must verify")
	}
	session := fixedSessionPubkey(t)
	var leaves []Hash
	for i := uint64(0); i < v.NewSize; i++ {
		l := fixedLeaf(i, session, byte(i)+1)
		leaves = append(leaves, l.LeafHash())
	}
	gen := ConsistencyProof(leaves, v.OldSize)
	if len(gen) != len(proof) {
		t.Fatalf("generated proof has %d elements, corpus %d", len(gen), len(proof))
	}
	for i := range gen {
		if gen[i] != proof[i] {
			t.Errorf("generated proof element %d differs from corpus", i)
		}
	}
	// Every single-element alteration, and either root altered, must fail.
	for i := range proof {
		bad := append([]Hash(nil), proof...)
		bad[i][0] ^= 1
		if VerifyConsistency(v.OldSize, oldRoot, v.NewSize, newRoot, bad) {
			t.Errorf("altered proof element %d verified", i)
		}
	}
	badOld := oldRoot
	badOld[0] ^= 1
	if VerifyConsistency(v.OldSize, badOld, v.NewSize, newRoot, proof) {
		t.Errorf("altered old root verified")
	}
	badNew := newRoot
	badNew[0] ^= 1
	if VerifyConsistency(v.OldSize, oldRoot, v.NewSize, badNew, proof) {
		t.Errorf("altered new root verified")
	}
	if VerifyConsistency(v.OldSize, oldRoot, v.NewSize, newRoot, proof[:len(proof)-1]) {
		t.Errorf("truncated proof verified")
	}
	if VerifyConsistency(v.OldSize, oldRoot, v.NewSize, newRoot, append(append([]Hash(nil), proof...), Hash{})) {
		t.Errorf("extended proof verified")
	}
	// Trivial cases per RFC 9162.
	if !VerifyConsistency(0, EmptyRoot(), v.NewSize, newRoot, nil) {
		t.Errorf("first_size 0 with an empty proof must verify")
	}
	if VerifyConsistency(0, EmptyRoot(), v.NewSize, newRoot, proof) {
		t.Errorf("first_size 0 with a non-empty proof must not verify")
	}
	if !VerifyConsistency(v.NewSize, newRoot, v.NewSize, newRoot, nil) {
		t.Errorf("same size, same root, empty proof must verify")
	}
	if VerifyConsistency(v.NewSize, newRoot, v.OldSize, oldRoot, nil) {
		t.Errorf("first > second must not verify")
	}
}

// TestConsistencyRejectsForks is the exhaustive fork test SPEC.md §7.1 asks
// conforming implementations to include: for every 1 <= m < n <= 64, a
// tree whose first, middle or last old leaf was rewritten must not be
// accepted as an extension of the honest old tree.
func TestConsistencyRejectsForks(t *testing.T) {
	session := fixedSessionPubkey(t)
	var all []Hash
	for i := uint64(0); i < 64; i++ {
		l := fixedLeaf(i, session, byte(i)+1)
		all = append(all, l.LeafHash())
	}
	checked := 0
	for n := uint64(2); n <= 64; n++ {
		for m := uint64(1); m < n; m++ {
			oldRoot := MerkleRoot(all[:m])
			newRoot := MerkleRoot(all[:n])
			honest := ConsistencyProof(all[:n], m)
			if !VerifyConsistency(m, oldRoot, n, newRoot, honest) {
				t.Fatalf("honest proof m=%d n=%d failed", m, n)
			}
			for _, at := range []uint64{0, m / 2, m - 1} {
				forked := append([]Hash(nil), all[:n]...)
				forked[at][0] ^= 0xff
				forkRoot := MerkleRoot(forked)
				forkProof := ConsistencyProof(forked, m)
				if VerifyConsistency(m, oldRoot, n, forkRoot, forkProof) {
					t.Errorf("fork accepted: m=%d n=%d rewritten leaf %d", m, n, at)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no forks checked")
	}
}

func TestCorpus07HandoffAttestation(t *testing.T) {
	var v struct {
		Sender   string     `json:"sender_identity_pubkey"`
		Receiver string     `json:"receiver_identity_pubkey"`
		Sent     leafVector `json:"sent_leaf"`
		Received leafVector `json:"received_leaf"`
		Result   string     `json:"binding_result"`
	}
	readCorpus(t, "07_handoff_attestation.json", &v)
	checkLeafVector(t, "07/sent", v.Sent)
	checkLeafVector(t, "07/received", v.Received)
	sent, _ := ParseLeaf(v.Sent.Leaf)
	recv, _ := ParseLeaf(v.Received.Leaf)
	if v.Result != "ok" {
		t.Fatalf("corpus binding_result %q", v.Result)
	}
	if err := VerifyHandoffBinding(v.Sender, sent, v.Receiver, recv); err != nil {
		t.Errorf("matching pair must bind: %v", err)
	}
	// The worked mismatch: received leaf with an altered state hash.
	wrong := "9999999999999999999999999999999999999999999999999999999999999999"
	bad := *recv
	bad.HandoffStateHash = &wrong
	if err := VerifyHandoffBinding(v.Sender, sent, v.Receiver, &bad); err == nil {
		t.Errorf("mismatched state hash must not bind")
	}
	// Swapped roles, swapped identities, wrong counterparty.
	if VerifyHandoffBinding(v.Receiver, recv, v.Sender, sent) == nil {
		t.Errorf("swapped roles must not bind")
	}
	if VerifyHandoffBinding(v.Receiver, sent, v.Sender, recv) == nil {
		t.Errorf("swapped identities must not bind")
	}
	other := *recv
	cp := v.Receiver
	other.CounterpartyPubkey = &cp
	if VerifyHandoffBinding(v.Sender, sent, v.Receiver, &other) == nil {
		t.Errorf("wrong counterparty must not bind")
	}
}

func TestCorpus08AuthorizationEvent(t *testing.T) {
	var v struct {
		Granter  string     `json:"granter_identity_pubkey"`
		Grantee  string     `json:"grantee_identity_pubkey"`
		Granted  leafVector `json:"granted_leaf"`
		Received leafVector `json:"received_grant_leaf"`
		Result   string     `json:"binding_result"`
	}
	readCorpus(t, "08_authorization_event.json", &v)
	checkLeafVector(t, "08/granted", v.Granted)
	checkLeafVector(t, "08/received", v.Received)
	granted, _ := ParseLeaf(v.Granted.Leaf)
	recv, _ := ParseLeaf(v.Received.Leaf)
	if err := VerifyAuthorizationBinding(v.Granter, granted, v.Grantee, recv); err != nil {
		t.Errorf("matching pair must bind: %v", err)
	}
	// Binding is symmetric in who is called a and b.
	if err := VerifyAuthorizationBinding(v.Grantee, recv, v.Granter, granted); err != nil {
		t.Errorf("pair must bind from either side: %v", err)
	}
	wrong := "9999999999999999999999999999999999999999999999999999999999999999"
	bad := *recv
	bad.AuthorizationScopeHash = &wrong
	if VerifyAuthorizationBinding(v.Granter, granted, v.Grantee, &bad) == nil {
		t.Errorf("mismatched scope hash must not bind")
	}
	kind := RevokedToMe
	badKind := *recv
	badKind.AuthorizationEventKind = &kind
	if VerifyAuthorizationBinding(v.Granter, granted, v.Grantee, &badKind) == nil {
		t.Errorf("unpaired kinds must not bind")
	}
	for _, k := range []AuthorizationEventKind{GrantedByMe, RevokedByMe, ScopeChangedByMe} {
		if k.Paired() != k+1 || (k+1).Paired() != k {
			t.Errorf("pairing table broken for %s", k)
		}
	}
}

func TestCorpus09ExternalAnchor(t *testing.T) {
	var v struct {
		Anchor  leafVector `json:"anchor_leaf"`
		Swapped struct {
			leafVector
		} `json:"swapped_proof_case"`
	}
	readCorpus(t, "09_external_anchor.json", &v)
	checkLeafVector(t, "09/anchor", v.Anchor)
	checkLeafVector(t, "09/swapped", v.Swapped.leafVector)
	if v.Anchor.LeafHashHex == v.Swapped.LeafHashHex {
		t.Errorf("swapping the anchor proof must change the leaf hash")
	}
	anchor, _ := ParseLeaf(v.Anchor.Leaf)
	swapped, _ := ParseLeaf(v.Swapped.Leaf)
	// A leaf carrying the swapped JSON against the original committed
	// hash is exactly the substitution Validate must catch.
	tampered := *anchor
	tampered.AnchorProofJSON = swapped.AnchorProofJSON
	if err := tampered.Validate(0); err == nil {
		t.Errorf("anchor_proof_json that does not hash to anchor_proof_hash must fail validation")
	}
	noURL := *anchor
	bad := "ftp://example.invalid/anchor"
	noURL.AnchorURL = &bad
	if noURL.Validate(0) == nil {
		t.Errorf("non-http anchor_url must fail validation")
	}
}

func TestCorpus10C2SPCheckpoint(t *testing.T) {
	var v struct {
		Origin      string `json:"origin"`
		TreeSize    uint64 `json:"tree_size"`
		RootHashHex string `json:"root_hash_hex"`
		NoteText    string `json:"note_text"`
		LogVkey     string `json:"log_vkey"`
		SignedNote  string `json:"signed_note"`
		Cosignature struct {
			WitnessVkey   string `json:"witness_vkey"`
			Timestamp     uint64 `json:"timestamp"`
			SignedMessage string `json:"signed_message"`
			CosignedNote  string `json:"cosigned_note"`
		} `json:"cosignature"`
	}
	readCorpus(t, "10_c2sp_checkpoint.json", &v)

	cp := Checkpoint{Origin: v.Origin, TreeSize: v.TreeSize, RootHash: hashFromHex(t, v.RootHashHex)}
	body, err := cp.NoteText()
	if err != nil {
		t.Fatal(err)
	}
	if body != v.NoteText {
		t.Errorf("note text\n got %q\nwant %q", body, v.NoteText)
	}

	logVkey, err := ParseVerifierKey(v.LogVkey)
	if err != nil {
		t.Fatalf("log vkey: %v", err)
	}
	if logVkey.Encode() != v.LogVkey {
		t.Errorf("log vkey does not round-trip: %s", logVkey.Encode())
	}
	if logVkey.SigType != SigTypeEd25519 || logVkey.Name != v.Origin {
		t.Errorf("log vkey should be an Ed25519 (0x01) key named after the origin")
	}
	if KeyID(logVkey.Name, logVkey.SigType, logVkey.PublicKey) != logVkey.ID {
		t.Errorf("log vkey ID does not match SHA-256(name||0x0A||type||key)[:4]")
	}
	if NewEd25519VerifierKey(v.Origin, logVkey.PublicKey).Encode() != v.LogVkey {
		t.Errorf("rebuilt log vkey differs from corpus")
	}

	note, err := ParseC2SPNote(v.SignedNote)
	if err != nil {
		t.Fatalf("signed note: %v", err)
	}
	if note.Text != v.NoteText {
		t.Errorf("parsed note text differs")
	}
	names, err := note.Verify([]VerifierKey{logVkey})
	if err != nil || len(names) != 1 || names[0] != v.Origin {
		t.Errorf("note must verify under the log vkey: %v %v", names, err)
	}
	enc, err := note.Encode()
	if err != nil || enc != v.SignedNote {
		t.Errorf("note does not re-encode byte for byte")
	}
	parsedCp, err := CheckpointFromNote(note)
	if err != nil || parsedCp.Origin != v.Origin || parsedCp.TreeSize != v.TreeSize || parsedCp.RootHash != cp.RootHash {
		t.Errorf("checkpoint does not survive the round trip: %+v %v", parsedCp, err)
	}

	witnessVkey, err := ParseVerifierKey(v.Cosignature.WitnessVkey)
	if err != nil {
		t.Fatalf("witness vkey: %v", err)
	}
	if witnessVkey.SigType != SigTypeCosignatureV1 {
		t.Errorf("witness vkey should be a cosignature/v1 (0x04) key")
	}
	if NewCosignatureVerifierKey(witnessVkey.Name, witnessVkey.PublicKey).Encode() != v.Cosignature.WitnessVkey {
		t.Errorf("rebuilt witness vkey differs from corpus")
	}
	if CosignatureMessage(v.Cosignature.Timestamp, body) != v.Cosignature.SignedMessage {
		t.Errorf("cosignature message differs")
	}
	cosigned, err := ParseC2SPNote(v.Cosignature.CosignedNote)
	if err != nil {
		t.Fatalf("cosigned note: %v", err)
	}
	// The log's own verification ignores the unknown cosignature key.
	if _, err := cosigned.Verify([]VerifierKey{logVkey}); err != nil {
		t.Errorf("cosignatures must not break the log's own verification: %v", err)
	}
	if len(cosigned.Signatures) != 2 {
		t.Fatalf("expected 2 signature lines, got %d", len(cosigned.Signatures))
	}
	cosig, err := CosignatureFromNoteSignature(cosigned.Signatures[1])
	if err != nil {
		t.Fatal(err)
	}
	if cosig.Timestamp != v.Cosignature.Timestamp {
		t.Errorf("cosignature timestamp %d != %d", cosig.Timestamp, v.Cosignature.Timestamp)
	}
	if err := cosig.Verify(witnessVkey, body); err != nil {
		t.Errorf("cosignature must verify: %v", err)
	}
	if cosig.Verify(witnessVkey, CosignatureMessage(0, body)) == nil {
		t.Errorf("cosignature over a different body must not verify")
	}
	other := *cosig
	other.Timestamp++
	if other.Verify(witnessVkey, body) == nil {
		t.Errorf("cosignature with an altered timestamp must not verify")
	}
	if cosig.ToNoteSignature().Encode() != cosigned.Signatures[1].Encode() {
		t.Errorf("cosignature does not re-encode to the same line")
	}
	// Known key that fails rejects the whole note; no known key rejects.
	broken := *note
	broken.Text = "x" + note.Text
	if _, err := broken.Verify([]VerifierKey{logVkey}); err == nil {
		t.Errorf("a known key that fails must reject the note")
	}
	if _, err := note.Verify(nil); err == nil {
		t.Errorf("a note with no trusted signature must be rejected")
	}
}

func TestCorpus11PayloadHash(t *testing.T) {
	var v struct {
		Cases []struct {
			Name        string `json:"name"`
			PayloadHex  string `json:"payload_hex"`
			SaltHex     string `json:"salt_hex"`
			LeafIndex   uint64 `json:"leaf_index"`
			PayloadHash string `json:"payload_hash"`
		} `json:"cases"`
	}
	readCorpus(t, "11_payload_hash.json", &v)
	if len(v.Cases) != 6 {
		t.Fatalf("expected 6 cases, got %d", len(v.Cases))
	}
	for _, c := range v.Cases {
		payload, _ := hex.DecodeString(c.PayloadHex)
		salt := hashFromHex(t, c.SaltHex)
		got := PayloadHash(payload, salt, c.LeafIndex)
		if hex.EncodeToString(got[:]) != c.PayloadHash {
			t.Errorf("%s: payload hash got %x want %s", c.Name, got, c.PayloadHash)
		}
		leaf := Leaf{Index: c.LeafIndex, LeafType: LeafActiveIntent, PayloadHash: c.PayloadHash}
		if err := VerifyDisclosure(&leaf, payload, salt[:]); err != nil {
			t.Errorf("%s: disclosure must verify: %v", c.Name, err)
		}
		wrongIndex := leaf
		wrongIndex.Index++
		if VerifyDisclosure(&wrongIndex, payload, salt[:]) == nil {
			t.Errorf("%s: disclosure under another index must fail", c.Name)
		}
		if VerifyDisclosure(&leaf, append(payload, 0), salt[:]) == nil {
			t.Errorf("%s: disclosure of a different payload must fail", c.Name)
		}
		if VerifyDisclosure(&leaf, payload, salt[:31]) == nil {
			t.Errorf("%s: a 31-byte salt must be rejected", c.Name)
		}
	}
	for _, c := range []struct {
		n, want int
	}{{0, 264}, {1, 264}, {255, 264}, {256, 520}, {257, 520}, {511, 520}, {512, 776}} {
		if got := len(BucketPad(make([]byte, c.n))); got != c.want {
			t.Errorf("bucket_pad(%d bytes) = %d bytes, want %d", c.n, got, c.want)
		}
	}
}

// TestCorpusComplete makes sure every vector file in /corpus has a test
// here, so a new vector cannot be added without the Go side noticing.
func TestCorpusComplete(t *testing.T) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{
		"01_leaf_encoding.json": true, "02_merkle_roots.json": true, "03_inclusion_proofs.json": true,
		"04_signed_tree_head.json": true, "05_redaction_continuity.json": true, "06_consistency_proof.json": true,
		"07_handoff_attestation.json": true, "08_authorization_event.json": true, "09_external_anchor.json": true,
		"10_c2sp_checkpoint.json": true, "11_payload_hash.json": true, "12_revocation.json": true,
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		n++
		if !covered[e.Name()] {
			t.Errorf("corpus vector %s has no Go conformance test", e.Name())
		}
	}
	if n != len(covered) {
		t.Errorf("corpus has %d vectors, tests cover %d", n, len(covered))
	}
}

func TestCorpus12Revocation(t *testing.T) {
	var v struct {
		IdentityPubkey string `json:"identity_pubkey"`
		V1             struct {
			Statement  Revocation `json:"statement"`
			MessageHex string     `json:"message_hex"`
		} `json:"v1"`
		V2 struct {
			Statement  Revocation `json:"statement"`
			MessageHex string     `json:"message_hex"`
		} `json:"v2"`
		CutOffCases []struct {
			Revocation            string `json:"revocation"`
			CheckpointTreeSize    uint64 `json:"checkpoint_tree_size"`
			CheckpointTimestampMs uint64 `json:"checkpoint_timestamp_ms"`
			MaxLeafIndex          uint64 `json:"max_leaf_index"`
			Valid                 bool   `json:"valid"`
		} `json:"cut_off_cases"`
	}
	readCorpus(t, "12_revocation.json", &v)
	pk, _ := hex.DecodeString(v.IdentityPubkey)
	for name, c := range map[string]struct {
		r   Revocation
		msg string
	}{"v1": {v.V1.Statement, v.V1.MessageHex}, "v2": {v.V2.Statement, v.V2.MessageHex}} {
		got := RevocationMessage(pk, c.r.AsOfMs, c.r.AsOfIndex, c.r.Reason)
		if hex.EncodeToString(got) != c.msg {
			t.Errorf("%s: message %x want %s", name, got, c.msg)
		}
		if err := c.r.Verify(); err != nil {
			t.Errorf("%s: must verify: %v", name, err)
		}
	}
	stripped := v.V2.Statement
	stripped.AsOfIndex = nil
	if stripped.Verify() == nil {
		t.Error("v2 with the index stripped must not verify")
	}
	moved := v.V2.Statement
	n := *moved.AsOfIndex + 1
	moved.AsOfIndex = &n
	if moved.Verify() == nil {
		t.Error("v2 with a different index must not verify")
	}
	for i, c := range v.CutOffCases {
		rv := v.V1.Statement
		if c.Revocation == "v2" {
			rv = v.V2.Statement
		}
		leaves := make([]Leaf, 0, c.MaxLeafIndex+1)
		for j := uint64(0); j <= c.MaxLeafIndex; j++ {
			leaves = append(leaves, Leaf{Index: j, TimestampMs: 0, SessionPubkey: "s"})
		}
		// No bindings: only the revocation rules can fail, so bindings are
		// supplied as covering the placeholder session key.
		err := revocationCutOff([]Revocation{rv}, leaves, c.CheckpointTimestampMs, c.CheckpointTreeSize)
		if (err == nil) != c.Valid {
			t.Errorf("cut-off case %d: valid=%v want %v (%v)", i, err == nil, c.Valid, err)
		}
	}
}
