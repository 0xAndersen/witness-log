package witnesslog

import (
	"encoding/json"
	"fmt"
)

// Dossier is the offline-verifiable bundle of SPEC.md §9: the leaves, the
// signed checkpoint over them, and whatever receipts, directory entries,
// key bindings and revocations the exporting log chose to attach.
//
// Everything in a Dossier is supplied by the party being verified. Only
// identity_pubkey, key_bindings and revocations are checked for internal
// consistency; witness_directory is display-only and never scores a
// receipt (SPEC.md §9.1). Receipts are scored against the Directory the
// caller passes to VerifyDossier.
type Dossier struct {
	IdentityPubkey   string           `json:"identity_pubkey"`
	Leaves           []Leaf           `json:"leaves"`
	Checkpoint       SignedTreeHead   `json:"checkpoint"`
	WitnessReceipts  []WitnessReceipt `json:"witness_receipts"`
	WitnessDirectory Directory        `json:"witness_directory"`
	KeyBindings      []KeyBinding     `json:"key_bindings"`
	Revocations      []Revocation     `json:"revocations"`
}

// SignedTreeHead is a checkpoint (SPEC.md §6): the log identity's signed
// commitment to the root of the tree at tree_size.
type SignedTreeHead struct {
	TreeSize     uint64 `json:"tree_size"`
	RootHash     string `json:"root_hash"`
	TimestampMs  uint64 `json:"timestamp_ms"`
	SigAlg       string `json:"sig_alg"`
	SignerPubkey string `json:"signer_pubkey"`
	Signature    string `json:"signature"`
}

// WitnessReceipt is a witness's signed statement that it saw a checkpoint
// (SPEC.md §7). When C2SPOrigin is set the receipt carries a
// c2sp.org/tlog-cosignature rather than a native receipt signature, and
// the signed message is reconstructed from the checkpoint fields (§9.3).
type WitnessReceipt struct {
	WitnessPubkey string `json:"witness_pubkey"`
	TreeSize      uint64 `json:"tree_size"`
	RootHash      string `json:"root_hash"`
	WitnessedAtMs uint64 `json:"witnessed_at_ms"`
	Signature     string `json:"signature"`
	C2SPOrigin    string `json:"c2sp_origin,omitempty"`
}

// WitnessEntry is one row of a witness directory.
type WitnessEntry struct {
	Name              string  `json:"name"`
	OperatorOrg       string  `json:"operator_org"`
	URL               string  `json:"url"`
	Pubkey            string  `json:"pubkey"`
	Runtime           string  `json:"runtime"`
	ComputeProvider   *string `json:"compute_provider"`
	IsProjectOperated bool    `json:"is_project_operated"`
}

// Directory is a witness directory. The one passed to VerifyDossier must
// be obtained out-of-band, never read from the dossier under test.
type Directory struct {
	Witnesses []WitnessEntry `json:"witnesses"`
}

// KeyBinding is the identity key's signed statement that a session key may
// author leaves (SPEC.md §5). Custody is unsigned and self-asserted; it is
// surfaced, never a verdict input.
type KeyBinding struct {
	IdentityPubkey string  `json:"identity_pubkey"`
	SessionPubkey  string  `json:"session_pubkey"`
	SessionNumber  uint64  `json:"session_number"`
	TimestampMs    uint64  `json:"timestamp_ms"`
	Custody        Custody `json:"custody"`
	NotAfterMs     *uint64 `json:"not_after_ms"`
	Signature      string  `json:"signature"`
}

// Revocation is the identity key's signed statement that it is revoked as
// of as_of_ms (SPEC.md §5).
type Revocation struct {
	IdentityPubkey string `json:"identity_pubkey"`
	AsOfMs         uint64 `json:"as_of_ms"`
	Reason         string `json:"reason"`
	Signature      string `json:"signature"`
}

// Custody is how a session key's private half is held: one of the strings
// self_held, platform_held, hsm, kms, session_delegated, undisclosed, or
// a k-of-n threshold. Kind holds the string form ("threshold" for the
// object form); K and N are set only for thresholds.
type Custody struct {
	Kind string
	K    string
	N    string
}

// UnmarshalJSON accepts both the string form and {"threshold":{"k":..,"n":..}}.
func (c *Custody) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		switch s {
		case "self_held", "platform_held", "hsm", "kms", "session_delegated", "undisclosed":
			*c = Custody{Kind: s}
			return nil
		}
		return fmt.Errorf("custody: unknown variant %q", s)
	}
	var obj struct {
		Threshold *struct {
			K string `json:"k"`
			N string `json:"n"`
		} `json:"threshold"`
	}
	if err := json.Unmarshal(b, &obj); err != nil || obj.Threshold == nil {
		return fmt.Errorf("custody: expected a custody string or {\"threshold\":{\"k\",\"n\"}}")
	}
	*c = Custody{Kind: "threshold", K: obj.Threshold.K, N: obj.Threshold.N}
	return nil
}

// MarshalJSON writes the same shape the Rust implementation does.
func (c Custody) MarshalJSON() ([]byte, error) {
	if c.Kind == "threshold" {
		return json.Marshal(map[string]map[string]string{"threshold": {"k": c.K, "n": c.N}})
	}
	if c.Kind == "" {
		return json.Marshal("undisclosed")
	}
	return json.Marshal(c.Kind)
}

// String renders the custody tier for display.
func (c Custody) String() string {
	if c.Kind == "threshold" {
		return fmt.Sprintf("threshold %s-of-%s", c.K, c.N)
	}
	if c.Kind == "" {
		return "undisclosed"
	}
	return c.Kind
}

// requireKeys checks that every name in required is a key of the JSON
// object in raw. encoding/json leaves missing fields at their zero value;
// the reference implementation rejects a dossier with a missing required
// field as unparseable, and so does this package.
func requireKeys(raw json.RawMessage, what string, required ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s: expected a JSON object: %w", what, err)
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%s: missing field %q", what, k)
		}
	}
	return nil
}

// ParseDossier decodes a dossier, applying the reference implementation's
// required-field rules: a missing identity_pubkey, leaves or checkpoint is
// a parse error (not a verdict), witness_receipts, witness_directory,
// key_bindings and revocations default to empty.
func ParseDossier(dossierJSON []byte) (*Dossier, error) {
	var top struct {
		IdentityPubkey   *string           `json:"identity_pubkey"`
		Leaves           []json.RawMessage `json:"leaves"`
		Checkpoint       json.RawMessage   `json:"checkpoint"`
		WitnessReceipts  []json.RawMessage `json:"witness_receipts"`
		WitnessDirectory json.RawMessage   `json:"witness_directory"`
		KeyBindings      []json.RawMessage `json:"key_bindings"`
		Revocations      []json.RawMessage `json:"revocations"`
	}
	if err := json.Unmarshal(dossierJSON, &top); err != nil {
		return nil, fmt.Errorf("dossier: %w", err)
	}
	if top.IdentityPubkey == nil {
		return nil, fmt.Errorf("dossier: missing field \"identity_pubkey\"")
	}
	if top.Leaves == nil {
		if err := requireKeys(dossierJSON, "dossier", "leaves"); err != nil {
			return nil, err
		}
	}
	if len(top.Checkpoint) == 0 {
		return nil, fmt.Errorf("dossier: missing field \"checkpoint\"")
	}
	d := &Dossier{IdentityPubkey: *top.IdentityPubkey}
	for i, raw := range top.Leaves {
		leaf, err := ParseLeaf(raw)
		if err != nil {
			return nil, fmt.Errorf("dossier: leaves[%d]: %w", i, err)
		}
		d.Leaves = append(d.Leaves, *leaf)
	}
	if d.Leaves == nil {
		d.Leaves = []Leaf{}
	}
	if err := requireKeys(top.Checkpoint, "checkpoint", "tree_size", "root_hash", "timestamp_ms", "sig_alg", "signer_pubkey", "signature"); err != nil {
		return nil, fmt.Errorf("dossier: %w", err)
	}
	if err := json.Unmarshal(top.Checkpoint, &d.Checkpoint); err != nil {
		return nil, fmt.Errorf("dossier: checkpoint: %w", err)
	}
	for i, raw := range top.WitnessReceipts {
		if err := requireKeys(raw, "witness_receipt", "witness_pubkey", "tree_size", "root_hash", "witnessed_at_ms", "signature"); err != nil {
			return nil, fmt.Errorf("dossier: witness_receipts[%d]: %w", i, err)
		}
		var r WitnessReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("dossier: witness_receipts[%d]: %w", i, err)
		}
		d.WitnessReceipts = append(d.WitnessReceipts, r)
	}
	if d.WitnessReceipts == nil {
		d.WitnessReceipts = []WitnessReceipt{}
	}
	if len(top.WitnessDirectory) > 0 && string(top.WitnessDirectory) != "null" {
		dir, err := ParseDirectory(top.WitnessDirectory)
		if err != nil {
			return nil, fmt.Errorf("dossier: witness_directory: %w", err)
		}
		d.WitnessDirectory = *dir
	}
	if d.WitnessDirectory.Witnesses == nil {
		d.WitnessDirectory.Witnesses = []WitnessEntry{}
	}
	for i, raw := range top.KeyBindings {
		if err := requireKeys(raw, "key_binding", "identity_pubkey", "session_pubkey", "session_number", "timestamp_ms", "signature"); err != nil {
			return nil, fmt.Errorf("dossier: key_bindings[%d]: %w", i, err)
		}
		var b KeyBinding
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("dossier: key_bindings[%d]: %w", i, err)
		}
		if b.Custody.Kind == "" {
			b.Custody.Kind = "undisclosed"
		}
		d.KeyBindings = append(d.KeyBindings, b)
	}
	if d.KeyBindings == nil {
		d.KeyBindings = []KeyBinding{}
	}
	for i, raw := range top.Revocations {
		if err := requireKeys(raw, "revocation", "identity_pubkey", "as_of_ms", "reason", "signature"); err != nil {
			return nil, fmt.Errorf("dossier: revocations[%d]: %w", i, err)
		}
		var r Revocation
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("dossier: revocations[%d]: %w", i, err)
		}
		d.Revocations = append(d.Revocations, r)
	}
	if d.Revocations == nil {
		d.Revocations = []Revocation{}
	}
	return d, nil
}

// ParseDirectory decodes a witness directory. Like `witness-log verify
// --directory`, it accepts either {"witnesses": [...]} or a bare JSON array
// of the entries `witness-log witness init` prints.
func ParseDirectory(directoryJSON []byte) (*Directory, error) {
	var obj struct {
		Witnesses []json.RawMessage `json:"witnesses"`
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(directoryJSON, &obj); err == nil {
		if obj.Witnesses == nil {
			if err := requireKeys(directoryJSON, "directory", "witnesses"); err != nil {
				return nil, err
			}
		}
		entries = obj.Witnesses
	} else if err2 := json.Unmarshal(directoryJSON, &entries); err2 != nil {
		return nil, fmt.Errorf("directory: %w (expected {\"witnesses\": [...]} or a bare array of entries)", err)
	}
	dir := &Directory{Witnesses: []WitnessEntry{}}
	for i, raw := range entries {
		if err := requireKeys(raw, "witness_entry", "name", "operator_org", "url", "pubkey"); err != nil {
			return nil, fmt.Errorf("directory: witnesses[%d]: %w", i, err)
		}
		var e WitnessEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("directory: witnesses[%d]: %w", i, err)
		}
		switch e.Runtime {
		case "":
			e.Runtime = "human"
		case "human", "agent":
		default:
			return nil, fmt.Errorf("directory: witnesses[%d]: runtime must be \"human\" or \"agent\", got %q", i, e.Runtime)
		}
		dir.Witnesses = append(dir.Witnesses, e)
	}
	return dir, nil
}
