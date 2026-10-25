package witnesslog

import (
	"fmt"
	"strings"
)

// BoundPair is one cross-log binding that held between two dossiers.
type BoundPair struct {
	// Kind is "handoff" or "authorization".
	Kind string `json:"kind"`
	// A and B are the two identities as `Bind` was called (A is the first
	// dossier); for a handoff, Sender/Receiver say which direction it went.
	A        string `json:"a"`
	ALeaf    uint64 `json:"a_leaf"`
	B        string `json:"b"`
	BLeaf    uint64 `json:"b_leaf"`
	Sender   string `json:"sender,omitempty"`
	Receiver string `json:"receiver,omitempty"`
	AEvent   string `json:"a_event,omitempty"`
	BEvent   string `json:"b_event,omitempty"`
	// Hash is the shared handoff_state_hash or authorization_scope_hash.
	Hash string `json:"hash"`
}

// FailedPair is a cross-log leaf that named the other party but found no
// counterpart that binds.
type FailedPair struct {
	Kind   string `json:"kind"`
	Side   string `json:"side"` // "a" or "b": whose leaf failed
	Leaf   uint64 `json:"leaf"`
	Reason string `json:"reason"`
}

// BindResult is what Bind reports. ExitCode follows `witness-log bind`:
// 0 when at least one pair bound and none failed, 30 when a candidate pair
// failed, 10 when neither dossier carries a cross-log leaf naming the other.
type BindResult struct {
	Bound  []BoundPair  `json:"bound"`
	Failed []FailedPair `json:"failed"`
}

// ExitCode maps the result to `witness-log bind`'s exit codes.
func (r *BindResult) ExitCode() int {
	switch {
	case len(r.Failed) > 0:
		return ExitDiverged
	case len(r.Bound) == 0:
		return ExitConsistentUnwitnessed
	}
	return 0
}

func namesOther(leaves []Leaf, other string, tag uint8) []*Leaf {
	var out []*Leaf
	for i := range leaves {
		l := &leaves[i]
		if l.LeafType == tag && l.CounterpartyPubkey != nil && *l.CounterpartyPubkey == other {
			out = append(out, l)
		}
	}
	return out
}

// Bind matches two DIFFERENT agents' dossiers against each other the way
// `witness-log bind` does: every Sent handoff in one log against the
// Received handoffs in the other that name it (both directions), and every
// AuthorizationEvent in a naming b against every AuthorizationEvent in b
// naming a. It does not verify either dossier; run VerifyDossier on each
// first, since a binding between two unverified logs proves nothing.
func Bind(a, b *Dossier) (*BindResult, error) {
	ia, ib := a.IdentityPubkey, b.IdentityPubkey
	if ia == ib {
		return nil, fmt.Errorf("both dossiers claim the same identity %s; bind is for two different agents", echo(ia))
	}
	res := &BindResult{Bound: []BoundPair{}, Failed: []FailedPair{}}

	type side struct {
		d    *Dossier
		id   string
		name string
	}
	sides := [2]side{{a, ia, "a"}, {b, ib, "b"}}
	for s := 0; s < 2; s++ {
		sender, receiver := sides[s], sides[1-s]
		sent := namesOther(sender.d.Leaves, receiver.id, LeafHandoffAttestation)
		var recv []*Leaf
		for _, l := range namesOther(receiver.d.Leaves, sender.id, LeafHandoffAttestation) {
			if l.HandoffDirection != nil && *l.HandoffDirection == HandoffReceived {
				recv = append(recv, l)
			}
		}
		for _, sl := range sent {
			if sl.HandoffDirection == nil || *sl.HandoffDirection != HandoffSent {
				continue
			}
			var hit *Leaf
			for _, rl := range recv {
				if VerifyHandoffBinding(sender.id, sl, receiver.id, rl) == nil {
					hit = rl
					break
				}
			}
			if hit != nil {
				p := BoundPair{Kind: "handoff", Sender: sender.id, Receiver: receiver.id, Hash: *sl.HandoffStateHash}
				if s == 0 {
					p.A, p.ALeaf, p.B, p.BLeaf = ia, sl.Index, ib, hit.Index
				} else {
					p.A, p.ALeaf, p.B, p.BLeaf = ia, hit.Index, ib, sl.Index
				}
				res.Bound = append(res.Bound, p)
				continue
			}
			var reasons []string
			for _, rl := range recv {
				reasons = append(reasons, fmt.Sprintf("receiver leaf %d: %v", rl.Index, VerifyHandoffBinding(sender.id, sl, receiver.id, rl)))
			}
			reason := "receiver logged no HandoffAttestation naming this sender"
			if len(reasons) > 0 {
				reason = strings.Join(reasons, "; ")
			}
			res.Failed = append(res.Failed, FailedPair{Kind: "handoff", Side: sender.name, Leaf: sl.Index, Reason: reason})
		}
	}

	authA := namesOther(a.Leaves, ib, LeafAuthorizationEvent)
	authB := namesOther(b.Leaves, ia, LeafAuthorizationEvent)
	failedBefore := len(res.Failed)
	for _, la := range authA {
		var hit *Leaf
		for _, lb := range authB {
			if VerifyAuthorizationBinding(ia, la, ib, lb) == nil {
				hit = lb
				break
			}
		}
		if hit != nil {
			res.Bound = append(res.Bound, BoundPair{
				Kind: "authorization", A: ia, ALeaf: la.Index, B: ib, BLeaf: hit.Index,
				AEvent: la.AuthorizationEventKind.SnakeCase(), BEvent: hit.AuthorizationEventKind.SnakeCase(),
				Hash: *la.AuthorizationScopeHash,
			})
			continue
		}
		reason := "the other log has no AuthorizationEvent naming this agent"
		if len(authB) > 0 {
			var reasons []string
			for _, lb := range authB {
				reasons = append(reasons, fmt.Sprintf("b leaf %d: %v", lb.Index, VerifyAuthorizationBinding(ia, la, ib, lb)))
			}
			reason = strings.Join(reasons, "; ")
		}
		res.Failed = append(res.Failed, FailedPair{Kind: "authorization", Side: "a", Leaf: la.Index, Reason: reason})
	}
	// And a b leaf naming a that no a leaf binds to: a grant, revocation or
	// scope change only b recorded. Without this the result depended on
	// argument order. When an a leaf already failed, its reason lists every
	// b leaf and the result is a mismatch either way, so they are not
	// reported twice. (Same rule as `witness-log bind`.)
	if len(res.Failed) == failedBefore {
		for _, lb := range authB {
			var reasons []string
			matched := false
			for _, la := range authA {
				err := VerifyAuthorizationBinding(ia, la, ib, lb)
				if err == nil {
					matched = true
					break
				}
				reasons = append(reasons, fmt.Sprintf("a leaf %d: %v", la.Index, err))
			}
			if matched {
				continue
			}
			reason := "the other log has no AuthorizationEvent naming this agent"
			if len(reasons) > 0 {
				reason = strings.Join(reasons, "; ")
			}
			res.Failed = append(res.Failed, FailedPair{Kind: "authorization", Side: "b", Leaf: lb.Index, Reason: reason})
		}
	}
	return res, nil
}
