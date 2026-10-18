//go:build js && wasm

// Command witness-log-wasm is the Go verifier compiled for the browser
// (GOOS=js GOARCH=wasm). It exposes the same three calls as the Rust
// crate `crates/witness-log-wasm` on globalThis.__witnesslog, returning the
// same JSON shapes, so the static page in web/ can run either engine and a
// reader can cross-check one implementation against the other without
// leaving the browser. web/build-go.sh builds it into web/pkg-go/.
//
// Every function takes and returns strings (JSON); the JS wrapper parses.
package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"syscall/js"

	witnesslog "github.com/0xAndersen/witness-log/clients/go"
)

const version = "0.6.1"

type verifyOptions struct {
	ExpectedIdentityPubkey *string           `json:"expected_identity_pubkey"`
	Threshold              *float64          `json:"threshold"`
	MinReceipts            *int              `json:"min_receipts"`
	AllowSubMajority       bool              `json:"allow_sub_majority"`
	Revocations            json.RawMessage   `json:"revocations"`
	KnownHeads             []string          `json:"known_heads"`
	Evidence               []json.RawMessage `json:"evidence"`
	SubjectOrg             string            `json:"subject_org"`
	AcceptFleetAnchor      bool              `json:"accept_fleet_anchor"`
}

func fail(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

func leafRows(leaves []witnesslog.Leaf) []map[string]any {
	rows := make([]map[string]any, 0, len(leaves))
	for i := range leaves {
		l := &leaves[i]
		h := l.LeafHash()
		structural := l.Validate(uint64(i))
		var structuralErr any
		if structural != nil {
			structuralErr = structural.Error()
		}
		name := witnesslog.LeafTypeName(l.LeafType)
		if name == "" {
			name = "unrecognized"
		}
		var dir, kind any
		if l.HandoffDirection != nil {
			dir = l.HandoffDirection.String()
		}
		if l.AuthorizationEventKind != nil {
			kind = l.AuthorizationEventKind.SnakeCase()
		}
		rows = append(rows, map[string]any{
			"index": l.Index, "leaf_type": l.LeafType, "leaf_type_name": name,
			"timestamp_ms": l.TimestampMs, "session_pubkey": l.SessionPubkey, "payload_hash": l.PayloadHash,
			"leaf_hash": hex.EncodeToString(h[:]), "redacted_index": l.RedactedIndex, "revoked_identity": l.RevokedIdentity,
			"handoff_direction": dir, "counterparty_pubkey": l.CounterpartyPubkey, "handoff_state_hash": l.HandoffStateHash,
			"authorization_event_kind": kind, "authorization_scope_hash": l.AuthorizationScopeHash,
			"anchor_url": l.AnchorURL, "anchor_proof_hash": l.AnchorProofHash, "has_anchor_proof_json": l.AnchorProofJSON != nil,
			"structurally_valid": structural == nil, "structural_error": structuralErr,
		})
	}
	return rows
}

func findEntry(dir *witnesslog.Directory, key string) *witnesslog.WitnessEntry {
	if dir == nil {
		return nil
	}
	for i := range dir.Witnesses {
		if strings.EqualFold(dir.Witnesses[i].Pubkey, key) {
			return &dir.Witnesses[i]
		}
	}
	return nil
}

func receiptRows(d *witnesslog.Dossier, trusted *witnesslog.Directory) []map[string]any {
	rows := make([]map[string]any, 0, len(d.WitnessReceipts))
	for i := range d.WitnessReceipts {
		r := &d.WitnessReceipts[i]
		err := r.Verify(&d.Checkpoint)
		var sigErr, origin any
		if err != nil {
			sigErr = err.Error()
		}
		kind := "native"
		if r.C2SPOrigin != "" {
			kind = "c2sp-cosignature"
			origin = r.C2SPOrigin
		}
		row := map[string]any{
			"witness_pubkey": r.WitnessPubkey, "tree_size": r.TreeSize, "root_hash": r.RootHash,
			"witnessed_at_ms": r.WitnessedAtMs, "kind": kind, "c2sp_origin": origin,
			"signature_valid": err == nil, "signature_error": sigErr,
			"in_trusted_directory": false, "trusted_operator_org": nil, "trusted_is_project_operated": nil, "trusted_name": nil,
			"claimed_name": nil, "claimed_operator_org": nil,
		}
		if e := findEntry(trusted, r.WitnessPubkey); e != nil {
			row["in_trusted_directory"] = true
			row["trusted_operator_org"] = e.OperatorOrg
			row["trusted_is_project_operated"] = e.IsProjectOperated
			row["trusted_name"] = e.Name
		}
		if e := findEntry(&d.WitnessDirectory, r.WitnessPubkey); e != nil {
			row["claimed_name"] = e.Name
			row["claimed_operator_org"] = e.OperatorOrg
		}
		rows = append(rows, row)
	}
	return rows
}

func bindingRows(d *witnesslog.Dossier) []map[string]any {
	rows := make([]map[string]any, 0, len(d.KeyBindings))
	for i := range d.KeyBindings {
		b := &d.KeyBindings[i]
		rows = append(rows, map[string]any{
			"session_pubkey": b.SessionPubkey, "session_number": b.SessionNumber, "timestamp_ms": b.TimestampMs,
			"not_after_ms": b.NotAfterMs, "custody": b.Custody, "signature_valid": b.Verify() == nil,
			"names_this_identity": strings.EqualFold(b.IdentityPubkey, d.IdentityPubkey),
		})
	}
	return rows
}

func verifyDossier(dossierJSON string, directoryJSON *string, optionsJSON string) string {
	var opts verifyOptions
	if optionsJSON != "" {
		if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
			return fail("options: " + err.Error())
		}
	}
	d, err := witnesslog.ParseDossier([]byte(dossierJSON))
	if err != nil {
		return fail("not a dossier: " + err.Error())
	}
	var dir *witnesslog.Directory
	if directoryJSON != nil {
		dir, err = witnesslog.ParseDirectory([]byte(*directoryJSON))
		if err != nil {
			return fail(err.Error())
		}
	}
	o := witnesslog.Options{MinReceipts: opts.MinReceipts}
	if opts.ExpectedIdentityPubkey != nil {
		o.ExpectedIdentityPubkey = *opts.ExpectedIdentityPubkey
	}
	threshold := witnesslog.DefaultThreshold
	if opts.Threshold != nil {
		threshold = *opts.Threshold
		o.Threshold = threshold
		o.ThresholdSet = true
	}
	if len(opts.Revocations) > 0 && string(opts.Revocations) != "null" {
		revs, err := witnesslog.ParseRevocations(opts.Revocations)
		if err != nil {
			return fail("revocations: " + err.Error())
		}
		o.Revocations = revs
	}
	for _, h := range opts.KnownHeads {
		kh, err := witnesslog.ParseKnownHead(h)
		if err != nil {
			return fail("known head: " + err.Error())
		}
		o.KnownHeads = append(o.KnownHeads, kh)
	}
	for _, raw := range opts.Evidence {
		p, err := witnesslog.ParseEvidence(raw)
		if err != nil {
			return fail("not an equivocation proof: " + err.Error())
		}
		o.Evidence = append(o.Evidence, p)
	}
	o.SubjectOrg = opts.SubjectOrg
	o.AcceptFleetAnchor = opts.AcceptFleetAnchor
	report := d.Verify(dir, o)
	var origin any
	if pk, err := hex.DecodeString(d.Checkpoint.SignerPubkey); err == nil && len(pk) == 32 {
		origin = witnesslog.CanonicalOrigin(pk)
	}
	out := map[string]any{
		"verdict":           report.Verdict.String(),
		"exit_code":         report.ExitCode(opts.AllowSubMajority),
		"threshold_used":    threshold,
		"min_receipts_used": opts.MinReceipts,
		"identity_pinned":   opts.ExpectedIdentityPubkey != nil,
		"directory_pinned":  dir != nil,
		"report":            report,
		"summary": map[string]any{
			"identity_pubkey":        d.IdentityPubkey,
			"checkpoint":             d.Checkpoint,
			"canonical_origin":       origin,
			"leaves":                 leafRows(d.Leaves),
			"receipts":               receiptRows(d, dir),
			"key_bindings":           bindingRows(d),
			"revocations":            len(d.Revocations),
			"claimed_directory_size": len(d.WitnessDirectory.Witnesses),
		},
		"engine": "go",
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fail(err.Error())
	}
	return string(b)
}

func verifyDisclosure(leafJSON string, payload []byte, saltHex string) string {
	leaf, err := witnesslog.ParseLeaf([]byte(leafJSON))
	if err != nil {
		return fail("not a leaf: " + err.Error())
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return fail("salt must be hex")
	}
	if len(salt) != 32 {
		return fail("salt must be 32 bytes")
	}
	var s [32]byte
	copy(s[:], salt)
	got := witnesslog.PayloadHash(payload, s, leaf.Index)
	rec := hex.EncodeToString(got[:])
	b, _ := json.Marshal(map[string]any{
		"matches": rec == leaf.PayloadHash, "leaf_index": leaf.Index, "committed": leaf.PayloadHash, "recomputed": rec,
	})
	return string(b)
}

func bindDossiers(aJSON, bJSON string) string {
	a, err := witnesslog.ParseDossier([]byte(aJSON))
	if err != nil {
		return fail("a: not a dossier: " + err.Error())
	}
	b, err := witnesslog.ParseDossier([]byte(bJSON))
	if err != nil {
		return fail("b: not a dossier: " + err.Error())
	}
	res, err := witnesslog.Bind(a, b)
	if err != nil {
		return fail(err.Error())
	}
	// Same row shapes as the Rust crate's bind output.
	bound := make([]map[string]any, 0, len(res.Bound))
	for _, p := range res.Bound {
		if p.Kind == "handoff" {
			sLeaf, rLeaf := p.ALeaf, p.BLeaf
			if p.Sender != p.A {
				sLeaf, rLeaf = p.BLeaf, p.ALeaf
			}
			bound = append(bound, map[string]any{
				"kind": "handoff", "sender": p.Sender, "sender_leaf": sLeaf, "receiver": p.Receiver, "receiver_leaf": rLeaf, "state_hash": p.Hash,
			})
		} else {
			bound = append(bound, map[string]any{
				"kind": "authorization", "a": p.A, "a_leaf": p.ALeaf, "a_event": p.AEvent, "b": p.B, "b_leaf": p.BLeaf, "b_event": p.BEvent, "scope_hash": p.Hash,
			})
		}
	}
	failed := make([]map[string]any, 0, len(res.Failed))
	for _, f := range res.Failed {
		failed = append(failed, map[string]any{"kind": f.Kind, "side": f.Side, "leaf": f.Leaf, "reason": f.Reason})
	}
	out, _ := json.Marshal(map[string]any{
		"a": map[string]string{"identity": a.IdentityPubkey}, "b": map[string]string{"identity": b.IdentityPubkey},
		"bound": bound, "failed": failed, "exit": res.ExitCode(),
	})
	return string(out)
}

func optString(v js.Value) *string {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	s := v.String()
	return &s
}

func main() {
	api := js.Global().Get("Object").New()
	api.Set("verify_dossier", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return verifyDossier(args[0].String(), optString(args[1]), "")
	}))
	api.Set("verify_dossier_with_options", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return verifyDossier(args[0].String(), optString(args[1]), args[2].String())
	}))
	api.Set("verify_disclosure", js.FuncOf(func(_ js.Value, args []js.Value) any {
		payload := make([]byte, args[1].Get("length").Int())
		js.CopyBytesToGo(payload, args[1])
		return verifyDisclosure(args[0].String(), payload, args[2].String())
	}))
	api.Set("bind", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return bindDossiers(args[0].String(), args[1].String())
	}))
	api.Set("version", js.FuncOf(func(_ js.Value, _ []js.Value) any { return version }))
	js.Global().Set("__witnesslog", api)
	select {}
}
