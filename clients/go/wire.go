package witnesslog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
)

// The reference reads a dossier with serde (crates/witness-log-network's
// Dossier and the types in it), and encoding/json reads JSON differently
// in ways that changed verdicts (outside review of 0.6.0, H2; corpus
// vector 17): it matches keys case-insensitively, so "TREE_SIZE" beside
// "tree_size" overwrote it; it keeps the last of two equal keys, where
// serde refuses a repeated field; it reads null into any field as "leave
// it", where serde refuses null for anything that is not an Option; and it
// turns an unpaired surrogate escape into U+FFFD, where serde refuses it.
// readStruct reads one struct the way serde does, and the parse functions
// in types.go, leaf.go and fleet.go go through it.

// fieldRule says how the reference's type reads one field of a struct.
type fieldRule uint8

const (
	// fRequired: the field must be present (a non-Option field without
	// #[serde(default)]).
	fRequired fieldRule = 1 << iota
	// fNullable: null reads as absent (an Option field).
	fNullable
	// fString: a string field: its value must be a JSON string without an
	// unpaired surrogate escape.
	fString
)

// structSpec is one of the reference's structs: its name for errors and
// its fields.
type structSpec struct {
	what   string
	fields map[string]fieldRule
}

// readStruct reads raw as serde reads a struct: a JSON object, never an
// array; every key free of unpaired surrogate escapes; a key naming a field
// at most once and matched exactly (other keys ignored, their values only
// syntax-checked); required fields present; null only where the field is
// an Option. It returns the struct's own fields, null ones dropped, so the
// caller can decode them without encoding/json's case-insensitive matching.
func readStruct(raw []byte, s structSpec) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.what, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%s: expected a JSON object", s.what)
	}
	out := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.what, err)
		}
		key, _ := tok.(string)
		if hasUnpairedSurrogate(raw[start:dec.InputOffset()]) {
			return nil, fmt.Errorf("%s: a key has an unpaired surrogate", s.what)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, fmt.Errorf("%s: %w", s.what, err)
		}
		rule, known := s.fields[key]
		if !known {
			continue
		}
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate field %q", s.what, key)
		}
		seen[key] = true
		if isNull(val) {
			if rule&fNullable == 0 {
				return nil, fmt.Errorf("%s: field %q is null", s.what, key)
			}
			continue
		}
		if rule&fString != 0 {
			if t := bytes.TrimSpace(val); len(t) == 0 || t[0] != '"' {
				return nil, fmt.Errorf("%s: field %q must be a string", s.what, key)
			}
			if hasUnpairedSurrogate(val) {
				return nil, fmt.Errorf("%s: field %q has an unpaired surrogate", s.what, key)
			}
		}
		out[key] = val
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%s: %w", s.what, err)
	}
	var missing []string
	for name, rule := range s.fields {
		if rule&fRequired != 0 && !seen[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s: missing field %q", s.what, missing[0])
	}
	return out, nil
}

// decodeStruct is readStruct, then the fields decoded into into.
func decodeStruct(raw []byte, s structSpec, into any) error {
	m, err := readStruct(raw, s)
	if err != nil {
		return err
	}
	return decodeFields(m, s.what, into)
}

func decodeFields(m map[string]json.RawMessage, what string, into any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func isNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// hasUnpairedSurrogate reports whether JSON text holds a \u escape of a
// UTF-16 surrogate that is not half of a high-low pair. encoding/json
// replaces one with U+FFFD; serde_json refuses it in every string it reads
// as a string (field values and struct keys).
func hasUnpairedSurrogate(raw []byte) bool {
	hex4 := func(i int) (uint16, bool) {
		if i+4 > len(raw) {
			return 0, false
		}
		v, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
		return uint16(v), err == nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			continue
		}
		if raw[i+1] != 'u' {
			i++ // a two-character escape, \\ included
			continue
		}
		c, ok := hex4(i + 2)
		if !ok {
			continue
		}
		switch {
		case c >= 0xdc00 && c <= 0xdfff:
			return true
		case c >= 0xd800 && c <= 0xdbff:
			if i+7 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return true
			}
			lo, ok := hex4(i + 8)
			if !ok || lo < 0xdc00 || lo > 0xdfff {
				return true
			}
			i += 11
		default:
			i += 5
		}
	}
	return false
}

// maxValueDepth is serde_json's nesting limit (128) less the dossier object
// and the field itself: how deep a value read as a serde_json::Value inside
// a dossier field may nest.
const maxValueDepth = 126

// checkJSONValue applies what reading raw as a serde_json::Value checks:
// no unpaired surrogate in any string or key, every number finite as a
// binary64, and at most maxValueDepth levels of nesting.
func checkJSONValue(raw []byte, what string) error {
	if hasUnpairedSurrogate(raw) {
		return fmt.Errorf("%s: a string has an unpaired surrogate", what)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				depth++
				if depth > maxValueDepth {
					return fmt.Errorf("%s: nested too deep", what)
				}
			} else {
				depth--
			}
		case json.Number:
			if f, _ := strconv.ParseFloat(string(t), 64); math.IsInf(f, 0) {
				return fmt.Errorf("%s: number out of range", what)
			}
		}
	}
}

// singleKeyObject returns the one member of raw when raw is a JSON object
// with exactly one member, as serde reads an enum written as a map.
func singleKeyObject(raw []byte) (string, json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", nil, false
	}
	if !dec.More() {
		return "", nil, false
	}
	tok, err := dec.Token()
	if err != nil {
		return "", nil, false
	}
	key, _ := tok.(string)
	var val json.RawMessage
	if err := dec.Decode(&val); err != nil || dec.More() {
		return "", nil, false
	}
	return key, val, true
}

// unitVariant reads a serde unit variant: its name as a string, or
// {"name": null}.
func unitVariant(raw []byte, what string, names []string) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		key, val, ok := singleKeyObject(raw)
		if !ok || !isNull(val) {
			return "", fmt.Errorf("%s: expected a variant name", what)
		}
		s = key
	}
	for _, n := range names {
		if n == s {
			return s, nil
		}
	}
	return "", fmt.Errorf("%s: unknown variant %q", what, s)
}

var (
	dossierSpec = structSpec{"dossier", map[string]fieldRule{
		"identity_pubkey":   fRequired | fString,
		"leaves":            fRequired,
		"checkpoint":        fRequired,
		"witness_receipts":  0,
		"witness_directory": 0,
		"key_bindings":      0,
		"revocations":       0,
		"fleet_anchor":      fNullable,
	}}
	checkpointSpec = structSpec{"checkpoint", map[string]fieldRule{
		"tree_size":     fRequired,
		"root_hash":     fRequired | fString,
		"timestamp_ms":  fRequired,
		"sig_alg":       fRequired | fString,
		"signer_pubkey": fRequired | fString,
		"signature":     fRequired | fString,
	}}
	leafSpec = structSpec{"leaf", map[string]fieldRule{
		"index":                    fRequired,
		"leaf_type":                fRequired,
		"timestamp_ms":             fRequired,
		"session_pubkey":           fRequired | fString,
		"payload_hash":             fRequired | fString,
		"redacted_index":           fNullable,
		"revoked_identity":         fNullable | fString,
		"handoff_direction":        fNullable,
		"counterparty_pubkey":      fNullable | fString,
		"handoff_state_hash":       fNullable | fString,
		"authorization_event_kind": fNullable,
		"authorization_scope_hash": fNullable | fString,
		"anchor_url":               fNullable | fString,
		"anchor_proof_json":        fNullable | fString,
		"anchor_proof_hash":        fNullable | fString,
	}}
	receiptSpec = structSpec{"witness_receipt", map[string]fieldRule{
		"witness_pubkey":  fRequired | fString,
		"tree_size":       fRequired,
		"root_hash":       fRequired | fString,
		"witnessed_at_ms": fRequired,
		"signature":       fRequired | fString,
		"c2sp_origin":     fNullable | fString,
		// Display only, and not kept here; serde still reads it as a string.
		"witness_name": fNullable | fString,
	}}
	directorySpec = structSpec{"directory", map[string]fieldRule{
		"witnesses": fRequired,
	}}
	entrySpec = structSpec{"witness_entry", map[string]fieldRule{
		"name":                fRequired | fString,
		"operator_org":        fRequired | fString,
		"url":                 fRequired | fString,
		"pubkey":              fRequired | fString,
		"runtime":             0,
		"compute_provider":    fNullable | fString,
		"is_project_operated": 0,
	}}
	bindingSpec = structSpec{"key_binding", map[string]fieldRule{
		"identity_pubkey": fRequired | fString,
		"session_pubkey":  fRequired | fString,
		"session_number":  fRequired,
		"timestamp_ms":    fRequired,
		"custody":         0,
		"not_after_ms":    fNullable,
		"signature":       fRequired | fString,
	}}
	revocationSpec = structSpec{"revocation", map[string]fieldRule{
		"identity_pubkey": fRequired | fString,
		"as_of_ms":        fRequired,
		"as_of_index":     fNullable,
		"reason":          fRequired | fString,
		"signature":       fRequired | fString,
	}}
	thresholdSpec = structSpec{"custody threshold", map[string]fieldRule{
		"k": fRequired | fString,
		"n": fRequired | fString,
	}}
	fleetAnchorSpec = structSpec{"fleet_anchor", map[string]fieldRule{
		"origin":                fRequired | fString,
		"entry_index":           fRequired,
		"entry_bytes_b64":       fRequired | fString,
		"inclusion_proof":       fRequired,
		"fleet_checkpoint_note": fRequired | fString,
	}}
)
