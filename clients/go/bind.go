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
// 0 when at least one pair bound and none failed, 30 when a cross-log leaf
// on either side bound to nothing, 10 when neither dossier carries a
// cross-log leaf naming the other.
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

// matching is a one-to-one matching of two leaf lists, each in index order.
type matching struct {
	pairs        [][2]int
	leftPartner  []int // -1: bound to nothing
	rightPartner []int
}

// matchOneToOne binds each left leaf, in index order, to the first right
// leaf that check accepts and that no earlier left leaf took. A leaf binds
// at most once, so an event one side recorded twice and the other once
// leaves one over. Leaves that can bind each other form groups (same kind
// pair and hash) and each group pairs its i-th left leaf with its i-th
// right leaf, so what is bound and what is left over do not depend on which
// side is left. Same rule as `witness-log bind`.
func matchOneToOne(left, right []*Leaf, check func(l, r *Leaf) error) *matching {
	m := &matching{leftPartner: make([]int, len(left)), rightPartner: make([]int, len(right))}
	for j := range m.rightPartner {
		m.rightPartner[j] = -1
	}
	for i, l := range left {
		m.leftPartner[i] = -1
		for j, r := range right {
			if m.rightPartner[j] == -1 && check(l, r) == nil {
				m.leftPartner[i], m.rightPartner[j] = j, i
				m.pairs = append(m.pairs, [2]int{i, j})
				break
			}
		}
	}
	return m
}

// why explains why leaf k of the left (or right) list bound to nothing, one
// clause per leaf on the other side, in the CLI's wording.
func (m *matching) why(rightSide bool, k int, left, right []*Leaf, check func(l, r *Leaf) error, leftName, rightName, none string) string {
	others, otherPartner, otherName, ownName, own := right, m.rightPartner, rightName, leftName, left
	if rightSide {
		others, otherPartner, otherName, ownName, own = left, m.leftPartner, leftName, rightName, right
	}
	if len(others) == 0 {
		return none
	}
	var out []string
	for o, other := range others {
		var err error
		if rightSide {
			err = check(other, right[k])
		} else {
			err = check(left[k], other)
		}
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s leaf %d: %v", otherName, other.Index, err))
		case otherPartner[o] >= 0:
			out = append(out, fmt.Sprintf("%s leaf %d: already bound to %s leaf %d", otherName, other.Index, ownName, own[otherPartner[o]].Index))
		default:
			out = append(out, fmt.Sprintf("%s leaf %d: unbound", otherName, other.Index))
		}
	}
	return strings.Join(out, "; ")
}

// Bind matches two DIFFERENT agents' dossiers against each other the way
// `witness-log bind` does, one to one: the Sent handoffs in one log against
// the Received handoffs in the other that name it (both directions), and
// the AuthorizationEvents in a naming b against those in b naming a. Every
// such leaf, on either side, that binds to nothing is a FailedPair (Side
// says whose leaf): a Sent or Received handoff the other side never logged,
// a grant, revocation or scope change only one side recorded, or one
// recorded more times on one side than on the other. Bound pairs and
// failures are the same in either argument order. It does not verify either
// dossier; run VerifyDossier on each first, since a binding between two
// unverified logs proves nothing.
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
		var sent, recv []*Leaf
		for _, l := range namesOther(sender.d.Leaves, receiver.id, LeafHandoffAttestation) {
			if l.HandoffDirection != nil && *l.HandoffDirection == HandoffSent {
				sent = append(sent, l)
			}
		}
		for _, l := range namesOther(receiver.d.Leaves, sender.id, LeafHandoffAttestation) {
			if l.HandoffDirection != nil && *l.HandoffDirection == HandoffReceived {
				recv = append(recv, l)
			}
		}
		check := func(sl, rl *Leaf) error { return VerifyHandoffBinding(sender.id, sl, receiver.id, rl) }
		m := matchOneToOne(sent, recv, check)
		for _, p := range m.pairs {
			sl, rl := sent[p[0]], recv[p[1]]
			bp := BoundPair{Kind: "handoff", Sender: sender.id, Receiver: receiver.id, Hash: *sl.HandoffStateHash}
			if s == 0 {
				bp.A, bp.ALeaf, bp.B, bp.BLeaf = ia, sl.Index, ib, rl.Index
			} else {
				bp.A, bp.ALeaf, bp.B, bp.BLeaf = ia, rl.Index, ib, sl.Index
			}
			res.Bound = append(res.Bound, bp)
		}
		for i := range sent {
			if m.leftPartner[i] == -1 {
				res.Failed = append(res.Failed, FailedPair{Kind: "handoff", Side: sender.name, Leaf: sent[i].Index,
					Reason: m.why(false, i, sent, recv, check, "sender", "receiver", "receiver logged no HandoffAttestation naming this sender")})
			}
		}
		for j := range recv {
			if m.rightPartner[j] == -1 {
				res.Failed = append(res.Failed, FailedPair{Kind: "handoff", Side: receiver.name, Leaf: recv[j].Index,
					Reason: m.why(true, j, sent, recv, check, "sender", "receiver", "sender logged no HandoffAttestation (Sent) naming this receiver")})
			}
		}
	}

	authA := namesOther(a.Leaves, ib, LeafAuthorizationEvent)
	authB := namesOther(b.Leaves, ia, LeafAuthorizationEvent)
	check := func(la, lb *Leaf) error { return VerifyAuthorizationBinding(ia, la, ib, lb) }
	m := matchOneToOne(authA, authB, check)
	for _, p := range m.pairs {
		la, lb := authA[p[0]], authB[p[1]]
		res.Bound = append(res.Bound, BoundPair{
			Kind: "authorization", A: ia, ALeaf: la.Index, B: ib, BLeaf: lb.Index,
			AEvent: la.AuthorizationEventKind.SnakeCase(), BEvent: lb.AuthorizationEventKind.SnakeCase(),
			Hash: *la.AuthorizationScopeHash,
		})
	}
	const noAuth = "the other log has no AuthorizationEvent naming this agent"
	for i := range authA {
		if m.leftPartner[i] == -1 {
			res.Failed = append(res.Failed, FailedPair{Kind: "authorization", Side: "a", Leaf: authA[i].Index,
				Reason: m.why(false, i, authA, authB, check, "a", "b", noAuth)})
		}
	}
	for j := range authB {
		if m.rightPartner[j] == -1 {
			res.Failed = append(res.Failed, FailedPair{Kind: "authorization", Side: "b", Leaf: authB[j].Index,
				Reason: m.why(true, j, authA, authB, check, "a", "b", noAuth)})
		}
	}
	return res, nil
}
