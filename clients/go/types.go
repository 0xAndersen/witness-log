package witnesslog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
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
	// FleetAnchor is RFC-0001's optional fleet_anchor (EXPERIMENTAL), kept
	// raw: it is read only with Options.AcceptFleetAnchor, and a malformed
	// one must not make the dossier unreadable to a caller who ignores it.
	FleetAnchor json.RawMessage `json:"fleet_anchor,omitempty"`
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
	// AsOfIndex (RFC-0005) is the tree size at which the revocation takes
	// effect; nil for a v1 statement.
	AsOfIndex *uint64 `json:"as_of_index,omitempty"`
	Reason    string  `json:"reason"`
	Signature string  `json:"signature"`
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

// UnmarshalJSON reads custody as the reference's serde enum does: a unit
// variant as its name or {"name": null}, or {"threshold": {"k": .., "n":
// ..}} with the threshold an object (never an array) of two strings.
func (c *Custody) UnmarshalJSON(b []byte) error {
	if key, val, ok := singleKeyObject(b); ok && key == "threshold" {
		var t struct {
			K string `json:"k"`
			N string `json:"n"`
		}
		if err := decodeStruct(val, thresholdSpec, &t); err != nil {
			return fmt.Errorf("custody: %w", err)
		}
		*c = Custody{Kind: "threshold", K: t.K, N: t.N}
		return nil
	}
	name, err := unitVariant(b, "custody", []string{"self_held", "platform_held", "hsm", "kms", "session_delegated", "undisclosed"})
	if err != nil {
		return err
	}
	*c = Custody{Kind: name}
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

// ParseDossier decodes a dossier exactly as the reference implementation
// deserialises one (wire.go): valid UTF-8 JSON; every struct an object
// whose fields appear once, are matched exactly (case-sensitive) and are
// null only where optional; identity_pubkey, leaves and checkpoint
// required; witness_receipts, witness_directory, key_bindings and
// revocations default to empty when absent. Anything else is a parse error
// (VerifyDossier: Invalid with the error), as corpus/17_dossier_parsing.json
// pins.
func ParseDossier(dossierJSON []byte) (*Dossier, error) {
	if !utf8.Valid(dossierJSON) {
		return nil, fmt.Errorf("dossier: not valid UTF-8")
	}
	if !json.Valid(dossierJSON) {
		var probe any
		err := json.Unmarshal(dossierJSON, &probe)
		return nil, fmt.Errorf("dossier: %w", err)
	}
	m, err := readStruct(dossierJSON, dossierSpec)
	if err != nil {
		return nil, err
	}
	d := &Dossier{
		Leaves:           []Leaf{},
		WitnessReceipts:  []WitnessReceipt{},
		WitnessDirectory: Directory{Witnesses: []WitnessEntry{}},
		KeyBindings:      []KeyBinding{},
		Revocations:      []Revocation{},
	}
	if err := json.Unmarshal(m["identity_pubkey"], &d.IdentityPubkey); err != nil {
		return nil, fmt.Errorf("dossier: identity_pubkey: %w", err)
	}
	list := func(field string) ([]json.RawMessage, error) {
		raw, ok := m[field]
		if !ok {
			return nil, nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("dossier: %s: %w", field, err)
		}
		return items, nil
	}
	leaves, err := list("leaves")
	if err != nil {
		return nil, err
	}
	for i, raw := range leaves {
		leaf, err := ParseLeaf(raw)
		if err != nil {
			return nil, fmt.Errorf("dossier: leaves[%d]: %w", i, err)
		}
		d.Leaves = append(d.Leaves, *leaf)
	}
	if err := decodeStruct(m["checkpoint"], checkpointSpec, &d.Checkpoint); err != nil {
		return nil, fmt.Errorf("dossier: %w", err)
	}
	receipts, err := list("witness_receipts")
	if err != nil {
		return nil, err
	}
	for i, raw := range receipts {
		var r WitnessReceipt
		if err := decodeStruct(raw, receiptSpec, &r); err != nil {
			return nil, fmt.Errorf("dossier: witness_receipts[%d]: %w", i, err)
		}
		d.WitnessReceipts = append(d.WitnessReceipts, r)
	}
	if raw, ok := m["witness_directory"]; ok {
		// The dossier's field is the struct, never the bare array that
		// --directory also accepts.
		dir, err := parseDirectoryObject(raw)
		if err != nil {
			return nil, fmt.Errorf("dossier: witness_directory: %w", err)
		}
		d.WitnessDirectory = *dir
	}
	bindings, err := list("key_bindings")
	if err != nil {
		return nil, err
	}
	for i, raw := range bindings {
		var b KeyBinding
		if err := decodeStruct(raw, bindingSpec, &b); err != nil {
			return nil, fmt.Errorf("dossier: key_bindings[%d]: %w", i, err)
		}
		if b.Custody.Kind == "" {
			b.Custody.Kind = "undisclosed"
		}
		d.KeyBindings = append(d.KeyBindings, b)
	}
	revocations, err := list("revocations")
	if err != nil {
		return nil, err
	}
	for i, raw := range revocations {
		var r Revocation
		if err := decodeStruct(raw, revocationSpec, &r); err != nil {
			return nil, fmt.Errorf("dossier: revocations[%d]: %w", i, err)
		}
		d.Revocations = append(d.Revocations, r)
	}
	if raw, ok := m["fleet_anchor"]; ok {
		// Read as a serde_json::Value would be; its shape is judged only
		// with Options.AcceptFleetAnchor (parseFleetAnchor).
		if err := checkJSONValue(raw, "dossier: fleet_anchor"); err != nil {
			return nil, err
		}
		d.FleetAnchor = append(json.RawMessage(nil), bytes.TrimSpace(raw)...)
	}
	return d, nil
}

// parseDirectoryObject reads {"witnesses": [...]}.
func parseDirectoryObject(raw []byte) (*Directory, error) {
	m, err := readStruct(raw, directorySpec)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(m["witnesses"], &entries); err != nil {
		return nil, fmt.Errorf("directory: witnesses: %w", err)
	}
	return parseEntries(entries)
}

func parseEntries(entries []json.RawMessage) (*Directory, error) {
	dir := &Directory{Witnesses: []WitnessEntry{}}
	for i, raw := range entries {
		m, err := readStruct(raw, entrySpec)
		if err != nil {
			return nil, fmt.Errorf("directory: witnesses[%d]: %w", i, err)
		}
		runtime := "human"
		if r, ok := m["runtime"]; ok {
			if runtime, err = unitVariant(r, "runtime", []string{"human", "agent"}); err != nil {
				return nil, fmt.Errorf("directory: witnesses[%d]: %w", i, err)
			}
			delete(m, "runtime")
		}
		var e WitnessEntry
		if err := decodeFields(m, "witness_entry", &e); err != nil {
			return nil, fmt.Errorf("directory: witnesses[%d]: %w", i, err)
		}
		e.Runtime = runtime
		dir.Witnesses = append(dir.Witnesses, e)
	}
	return dir, nil
}

// ParseDirectory decodes a witness directory. Like `witness-log verify
// --directory`, it accepts either {"witnesses": [...]} or a bare JSON array
// of the entries `witness-log witness init` prints; each is read as the
// reference reads it (see ParseDossier).
func ParseDirectory(directoryJSON []byte) (*Directory, error) {
	if !utf8.Valid(directoryJSON) || !json.Valid(directoryJSON) {
		return nil, fmt.Errorf("directory: not valid JSON")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(directoryJSON, &entries); err == nil {
		return parseEntries(entries)
	}
	return parseDirectoryObject(directoryJSON)
}

// ParseRevocations reads revocation statements as a JSON array or a single
// object, the two shapes `witness-log log revoke` and a dossier's
// `revocations` field produce.
func ParseRevocations(raw []byte) ([]Revocation, error) {
	trimmed := bytes.TrimSpace(raw)
	if !utf8.Valid(trimmed) || !json.Valid(trimmed) {
		return nil, fmt.Errorf("revocations: not valid JSON")
	}
	items := []json.RawMessage{trimmed}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("revocations: %w", err)
		}
	}
	many := []Revocation{}
	for i, item := range items {
		var r Revocation
		if err := decodeStruct(item, revocationSpec, &r); err != nil {
			return nil, fmt.Errorf("revocations[%d]: %w", i, err)
		}
		many = append(many, r)
	}
	return many, nil
}
