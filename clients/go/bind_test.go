package witnesslog

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// One-to-one binding, as `witness-log bind` does it (the same cases run
// through the Rust CLI, Python, Go and wasm agree; see bind_command.rs).

var (
	bindA = strings.Repeat("aa", 32)
	bindB = strings.Repeat("bb", 32)
)

type bindLeaf map[string]any

func grant(kind, scope, counterparty string) bindLeaf {
	return bindLeaf{"leaf_type": 6, "authorization_event_kind": kind,
		"authorization_scope_hash": strings.Repeat(scope, 64), "counterparty_pubkey": counterparty}
}

func handoff(direction, state, counterparty string) bindLeaf {
	return bindLeaf{"leaf_type": 5, "handoff_direction": direction,
		"handoff_state_hash": strings.Repeat(state, 64), "counterparty_pubkey": counterparty}
}

func bindDossier(t *testing.T, identity string, specs ...bindLeaf) *Dossier {
	t.Helper()
	leaves := []map[string]any{}
	for i, s := range specs {
		l := map[string]any{"index": i, "leaf_type": 1, "timestamp_ms": 0, "session_pubkey": strings.Repeat("00", 32),
			"payload_hash": strings.Repeat("03", 32)}
		for k, v := range s {
			l[k] = v
		}
		leaves = append(leaves, l)
	}
	raw, _ := json.Marshal(map[string]any{"identity_pubkey": identity, "leaves": leaves,
		"checkpoint": map[string]any{"tree_size": len(leaves), "root_hash": strings.Repeat("00", 32), "timestamp_ms": 0,
			"sig_alg": "ed25519", "signer_pubkey": identity, "signature": strings.Repeat("00", 64)}})
	d, err := ParseDossier(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// bindOutcome runs Bind both ways and returns exit, bound pairs as
// "kind:A<leaf>~B<leaf>" and failures as "kind:<A|B><leaf>", named by the
// dossier that holds the leaf whatever the argument order. It fails the
// test if the two orders disagree.
func bindOutcome(t *testing.T, a, b *Dossier) (int, []string, []string) {
	t.Helper()
	norm := func(x, y *Dossier, swapped bool) (int, []string, []string) {
		r, err := Bind(x, y)
		if err != nil {
			t.Fatal(err)
		}
		name := map[string]string{"a": "A", "b": "B"}
		if swapped {
			name = map[string]string{"a": "B", "b": "A"}
		}
		var bound, failed []string
		for _, p := range r.Bound {
			la, lb := p.ALeaf, p.BLeaf
			if swapped {
				la, lb = lb, la
			}
			bound = append(bound, fmt.Sprintf("%s:A%d~B%d", p.Kind, la, lb))
		}
		for _, f := range r.Failed {
			failed = append(failed, fmt.Sprintf("%s:%s%d", f.Kind, name[f.Side], f.Leaf))
		}
		sort.Strings(bound)
		sort.Strings(failed)
		return r.ExitCode(), bound, failed
	}
	e1, b1, f1 := norm(a, b, false)
	e2, b2, f2 := norm(b, a, true)
	if e1 != e2 || !reflect.DeepEqual(b1, b2) || !reflect.DeepEqual(f1, f2) {
		t.Fatalf("Bind depends on argument order: (%d %v %v) vs (%d %v %v)", e1, b1, f1, e2, b2, f2)
	}
	return e1, b1, f1
}

func TestBindOneToOne(t *testing.T) {
	cases := []struct {
		name   string
		a, b   []bindLeaf
		exit   int
		failed []string
	}{
		{"re-grant only B logged", []bindLeaf{grant("GrantedByMe", "1", bindB), grant("RevokedByMe", "1", bindB)},
			[]bindLeaf{grant("GrantedToMe", "1", bindA), grant("RevokedToMe", "1", bindA), grant("GrantedToMe", "1", bindA)},
			ExitDiverged, []string{"authorization:B2"}},
		{"two identical grants in A, one in B", []bindLeaf{grant("GrantedByMe", "1", bindB), grant("GrantedByMe", "1", bindB)},
			[]bindLeaf{grant("GrantedToMe", "1", bindA)}, ExitDiverged, []string{"authorization:A1"}},
		{"re-grant on both sides", []bindLeaf{grant("GrantedByMe", "1", bindB), grant("RevokedByMe", "1", bindB), grant("GrantedByMe", "1", bindB)},
			[]bindLeaf{grant("GrantedToMe", "1", bindA), grant("RevokedToMe", "1", bindA), grant("GrantedToMe", "1", bindA)}, 0, nil},
		{"lone Received", nil, []bindLeaf{handoff("Received", "4", bindA)}, ExitDiverged, []string{"handoff:B0"}},
		{"one Sent, two identical Received", []bindLeaf{handoff("Sent", "4", bindB)},
			[]bindLeaf{handoff("Received", "4", bindA), handoff("Received", "4", bindA)}, ExitDiverged, []string{"handoff:B1"}},
		{"bound grant plus lone Received", []bindLeaf{grant("GrantedByMe", "1", bindB)},
			[]bindLeaf{grant("GrantedToMe", "1", bindA), handoff("Received", "5", bindA)}, ExitDiverged, []string{"handoff:B1"}},
		{"one-to-one mismatch reports both leaves", []bindLeaf{grant("GrantedByMe", "1", bindB)},
			[]bindLeaf{grant("GrantedToMe", "2", bindA)}, ExitDiverged, []string{"authorization:A0", "authorization:B0"}},
		{"handoffs both ways", []bindLeaf{handoff("Sent", "4", bindB), handoff("Received", "5", bindB)},
			[]bindLeaf{handoff("Received", "4", bindA), handoff("Sent", "5", bindA)}, 0, nil},
		{"nothing to bind", nil, nil, ExitConsistentUnwitnessed, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exit, _, failed := bindOutcome(t, bindDossier(t, bindA, c.a...), bindDossier(t, bindB, c.b...))
			if exit != c.exit || !reflect.DeepEqual(failed, c.failed) {
				t.Errorf("exit %d failed %v; want exit %d failed %v", exit, failed, c.exit, c.failed)
			}
		})
	}
	// The reason names the leaf that took the counterpart.
	r, _ := Bind(bindDossier(t, bindA, grant("GrantedByMe", "1", bindB), grant("GrantedByMe", "1", bindB)),
		bindDossier(t, bindB, grant("GrantedToMe", "1", bindA)))
	if len(r.Failed) != 1 || r.Failed[0].Reason != "b leaf 0: already bound to a leaf 0" {
		t.Errorf("reason: %+v", r.Failed)
	}
}
