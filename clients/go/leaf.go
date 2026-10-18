package witnesslog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Leaf type tags (SPEC.md §2). The tag is the first byte of the canonical
// encoding and is hashed into the tree.
const (
	LeafPassiveMemory      uint8 = 0x00
	LeafActiveIntent       uint8 = 0x01
	LeafActiveResult       uint8 = 0x02
	LeafRedaction          uint8 = 0x03
	LeafKeyRevocation      uint8 = 0x04
	LeafHandoffAttestation uint8 = 0x05
	LeafAuthorizationEvent uint8 = 0x06
	LeafExternalAnchor     uint8 = 0x07
)

// LeafTypeName returns the SPEC.md §2 name of a tag, or "" for an
// unrecognized tag.
func LeafTypeName(tag uint8) string {
	switch tag {
	case LeafPassiveMemory:
		return "PassiveMemory"
	case LeafActiveIntent:
		return "ActiveIntent"
	case LeafActiveResult:
		return "ActiveResult"
	case LeafRedaction:
		return "Redaction"
	case LeafKeyRevocation:
		return "KeyRevocation"
	case LeafHandoffAttestation:
		return "HandoffAttestation"
	case LeafAuthorizationEvent:
		return "AuthorizationEvent"
	case LeafExternalAnchor:
		return "ExternalAnchor"
	}
	return ""
}

// HandoffDirection is which side of a handoff a 0x05 leaf records.
type HandoffDirection uint8

// Handoff directions (SPEC.md §3.1).
const (
	HandoffSent     HandoffDirection = 0x00
	HandoffReceived HandoffDirection = 0x01
)

var handoffNames = map[HandoffDirection]string{HandoffSent: "Sent", HandoffReceived: "Received"}

func (d HandoffDirection) String() string { return handoffNames[d] }

// MarshalJSON writes the reference implementation's string form.
func (d HandoffDirection) MarshalJSON() ([]byte, error) {
	name, ok := handoffNames[d]
	if !ok {
		return nil, fmt.Errorf("handoff_direction: unknown tag %d", uint8(d))
	}
	return json.Marshal(name)
}

// UnmarshalJSON accepts "Sent" or "Received", or {"Sent": null} and
// {"Received": null}, the two forms serde reads a unit variant in.
func (d *HandoffDirection) UnmarshalJSON(b []byte) error {
	s, err := unitVariant(b, "handoff_direction", []string{"Sent", "Received"})
	if err != nil {
		return err
	}
	for tag, name := range handoffNames {
		if name == s {
			*d = tag
			return nil
		}
	}
	return fmt.Errorf("handoff_direction: unknown variant %q", s)
}

// AuthorizationEventKind combines "which side" and "what happened" for a
// 0x06 leaf (SPEC.md §3.2).
type AuthorizationEventKind uint8

// Authorization event kinds, in tag order.
const (
	GrantedByMe      AuthorizationEventKind = 0x00
	GrantedToMe      AuthorizationEventKind = 0x01
	RevokedByMe      AuthorizationEventKind = 0x02
	RevokedToMe      AuthorizationEventKind = 0x03
	ScopeChangedByMe AuthorizationEventKind = 0x04
	ScopeChangedToMe AuthorizationEventKind = 0x05
)

var authKindNames = map[AuthorizationEventKind]string{
	GrantedByMe:      "GrantedByMe",
	GrantedToMe:      "GrantedToMe",
	RevokedByMe:      "RevokedByMe",
	RevokedToMe:      "RevokedToMe",
	ScopeChangedByMe: "ScopeChangedByMe",
	ScopeChangedToMe: "ScopeChangedToMe",
}

func (k AuthorizationEventKind) String() string { return authKindNames[k] }

// SnakeCase is the name the CLI, Python and MCP surfaces use
// (granted_by_me, ...).
func (k AuthorizationEventKind) SnakeCase() string {
	name, ok := authKindNames[k]
	if !ok {
		return "unknown"
	}
	var b strings.Builder
	for i, r := range name {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Paired returns the kind an honest counterparty's own leaf carries:
// GrantedByMe pairs with GrantedToMe, and so on down the table.
func (k AuthorizationEventKind) Paired() AuthorizationEventKind {
	return k ^ 1
}

// MarshalJSON writes the reference implementation's string form.
func (k AuthorizationEventKind) MarshalJSON() ([]byte, error) {
	name, ok := authKindNames[k]
	if !ok {
		return nil, fmt.Errorf("authorization_event_kind: unknown tag %d", uint8(k))
	}
	return json.Marshal(name)
}

// UnmarshalJSON accepts the six CamelCase names, as strings or as
// {"Name": null} (serde's two forms of a unit variant).
func (k *AuthorizationEventKind) UnmarshalJSON(b []byte) error {
	names := make([]string, 0, len(authKindNames))
	for _, n := range authKindNames {
		names = append(names, n)
	}
	s, err := unitVariant(b, "authorization_event_kind", names)
	if err != nil {
		return err
	}
	for tag, name := range authKindNames {
		if name == s {
			*k = tag
			return nil
		}
	}
	return fmt.Errorf("authorization_event_kind: unknown variant %q", s)
}

// Leaf is one log entry (SPEC.md §3). Optional fields are pointers so that
// "absent" and "present" survive a JSON round trip; the canonical encoding
// writes a presence byte for each.
type Leaf struct {
	Index                  uint64                  `json:"index"`
	LeafType               uint8                   `json:"leaf_type"`
	TimestampMs            uint64                  `json:"timestamp_ms"`
	SessionPubkey          string                  `json:"session_pubkey"`
	PayloadHash            string                  `json:"payload_hash"`
	RedactedIndex          *uint64                 `json:"redacted_index"`
	RevokedIdentity        *string                 `json:"revoked_identity"`
	HandoffDirection       *HandoffDirection       `json:"handoff_direction"`
	CounterpartyPubkey     *string                 `json:"counterparty_pubkey"`
	HandoffStateHash       *string                 `json:"handoff_state_hash"`
	AuthorizationEventKind *AuthorizationEventKind `json:"authorization_event_kind"`
	AuthorizationScopeHash *string                 `json:"authorization_scope_hash"`
	AnchorURL              *string                 `json:"anchor_url"`
	AnchorProofJSON        *string                 `json:"anchor_proof_json"`
	AnchorProofHash        *string                 `json:"anchor_proof_hash"`
}

// ParseLeaf decodes one leaf, requiring the five mandatory fields.
func ParseLeaf(raw []byte) (*Leaf, error) {
	var l Leaf
	if err := decodeStruct(raw, leafSpec, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func putLP(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}

func putU64(buf []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(buf, v)
}

// CanonicalBytes is the exact byte string hashed into the tree for this
// leaf (SPEC.md §3): fixed field order, every variable-length field
// length-prefixed, every optional field preceded by a presence byte, and
// the type-specific fields emitted only for their own leaf type.
func (l *Leaf) CanonicalBytes() []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, l.LeafType)
	buf = putU64(buf, l.Index)
	buf = putU64(buf, l.TimestampMs)
	buf = putLP(buf, l.SessionPubkey)
	buf = putLP(buf, l.PayloadHash)
	if l.RedactedIndex != nil {
		buf = append(buf, 1)
		buf = putU64(buf, *l.RedactedIndex)
	} else {
		buf = append(buf, 0)
	}
	if l.RevokedIdentity != nil {
		buf = append(buf, 1)
		buf = putLP(buf, *l.RevokedIdentity)
	} else {
		buf = append(buf, 0)
	}
	if l.LeafType == LeafHandoffAttestation {
		if l.HandoffDirection != nil {
			buf = append(buf, 1, uint8(*l.HandoffDirection))
		} else {
			buf = append(buf, 0)
		}
		buf = optLP(buf, l.CounterpartyPubkey)
		buf = optLP(buf, l.HandoffStateHash)
	}
	if l.LeafType == LeafAuthorizationEvent {
		if l.AuthorizationEventKind != nil {
			buf = append(buf, 1, uint8(*l.AuthorizationEventKind))
		} else {
			buf = append(buf, 0)
		}
		buf = optLP(buf, l.CounterpartyPubkey)
		buf = optLP(buf, l.AuthorizationScopeHash)
	}
	if l.LeafType == LeafExternalAnchor {
		buf = optLP(buf, l.AnchorURL)
		buf = optLP(buf, l.AnchorProofHash)
	}
	return buf
}

func optLP(buf []byte, s *string) []byte {
	if s == nil {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	return putLP(buf, *s)
}

// LeafHash is the RFC 6962 leaf hash of this leaf's canonical bytes.
func (l *Leaf) LeafHash() [32]byte {
	return LeafHash(l.CanonicalBytes())
}

// isHex64Lower reports whether s is exactly 64 lowercase hex characters,
// the form every hash and key field in a leaf must take.
func isHex64Lower(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsHexPubkey reports whether s is a 32-byte key as 64 hex characters of
// either case.
func IsHexPubkey(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// IsValidAnchorURL is the rule applied to an ExternalAnchor's anchor_url.
func IsValidAnchorURL(url string) bool {
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")
}

// Validate checks the leaf's structure on its own terms, as the reference
// implementation's Leaf::validate does: index matches its position,
// recognized type, well-formed hex fields, the fields the type requires are
// present, and for 0x07 the anchor_proof_json (when carried) hashes to the
// committed anchor_proof_hash. It does not check signatures or Merkle
// membership.
// ZeroHashHex is the payload_hash every marker leaf (0x03, 0x04) commits.
const ZeroHashHex = "0000000000000000000000000000000000000000000000000000000000000000"

func (l *Leaf) Validate(expectedIndex uint64) error {
	if l.Index != expectedIndex {
		return fmt.Errorf("leaf index %d does not match its position %d", l.Index, expectedIndex)
	}
	if LeafTypeName(l.LeafType) == "" {
		return fmt.Errorf("unrecognized leaf_type tag: 0x%02x", l.LeafType)
	}
	if !isHex64Lower(l.SessionPubkey) {
		return fmt.Errorf("field `session_pubkey` must be exactly 64 lowercase hex characters, got %q", l.SessionPubkey)
	}
	if !isHex64Lower(l.PayloadHash) {
		return fmt.Errorf("field `payload_hash` must be exactly 64 lowercase hex characters, got %q", l.PayloadHash)
	}
	require := func(present bool, field string) error {
		if present {
			return nil
		}
		return fmt.Errorf("leaf_type 0x%02x requires field `%s` to be present", l.LeafType, field)
	}
	// Fields of another leaf type are not committed by the root, so they
	// are refused rather than displayed (SPEC §2, 0.4.2). Markers commit
	// the all-zero payload hash and a redaction names an earlier leaf.
	forbid := func(present bool, field string) error {
		if !present {
			return nil
		}
		return fmt.Errorf("leaf_type 0x%02x must not carry field `%s` (it is not committed by the root)", l.LeafType, field)
	}
	t := l.LeafType
	for _, c := range []struct {
		when  bool
		set   bool
		field string
	}{
		{t != LeafRedaction, l.RedactedIndex != nil, "redacted_index"},
		{t != LeafKeyRevocation, l.RevokedIdentity != nil, "revoked_identity"},
		{t != LeafHandoffAttestation, l.HandoffDirection != nil, "handoff_direction"},
		{t != LeafHandoffAttestation, l.HandoffStateHash != nil, "handoff_state_hash"},
		{t != LeafAuthorizationEvent, l.AuthorizationEventKind != nil, "authorization_event_kind"},
		{t != LeafAuthorizationEvent, l.AuthorizationScopeHash != nil, "authorization_scope_hash"},
		{t != LeafHandoffAttestation && t != LeafAuthorizationEvent, l.CounterpartyPubkey != nil, "counterparty_pubkey"},
		{t != LeafExternalAnchor, l.AnchorURL != nil, "anchor_url"},
		{t != LeafExternalAnchor, l.AnchorProofJSON != nil, "anchor_proof_json"},
		{t != LeafExternalAnchor, l.AnchorProofHash != nil, "anchor_proof_hash"},
	} {
		if c.when {
			if err := forbid(c.set, c.field); err != nil {
				return err
			}
		}
	}
	if (t == LeafRedaction || t == LeafKeyRevocation) && l.PayloadHash != ZeroHashHex {
		return fmt.Errorf("field `payload_hash` is invalid: markers commit the all-zero hash, got %q", l.PayloadHash)
	}
	if t == LeafRedaction && l.RedactedIndex != nil && *l.RedactedIndex >= expectedIndex {
		return fmt.Errorf("field `redacted_index` is invalid: must name an earlier leaf, got %d", *l.RedactedIndex)
	}
	switch l.LeafType {
	case LeafRedaction:
		if err := require(l.RedactedIndex != nil, "redacted_index"); err != nil {
			return err
		}
	case LeafKeyRevocation:
		if err := require(l.RevokedIdentity != nil, "revoked_identity"); err != nil {
			return err
		}
	case LeafHandoffAttestation:
		for _, c := range []struct {
			ok    bool
			field string
		}{{l.HandoffDirection != nil, "handoff_direction"}, {l.CounterpartyPubkey != nil, "counterparty_pubkey"}, {l.HandoffStateHash != nil, "handoff_state_hash"}} {
			if err := require(c.ok, c.field); err != nil {
				return err
			}
		}
	case LeafAuthorizationEvent:
		for _, c := range []struct {
			ok    bool
			field string
		}{{l.AuthorizationEventKind != nil, "authorization_event_kind"}, {l.CounterpartyPubkey != nil, "counterparty_pubkey"}, {l.AuthorizationScopeHash != nil, "authorization_scope_hash"}} {
			if err := require(c.ok, c.field); err != nil {
				return err
			}
		}
	case LeafExternalAnchor:
		if err := require(l.AnchorURL != nil, "anchor_url"); err != nil {
			return err
		}
		if err := require(l.AnchorProofHash != nil, "anchor_proof_hash"); err != nil {
			return err
		}
		if l.AnchorProofJSON != nil {
			sum := sha256.Sum256([]byte(*l.AnchorProofJSON))
			actual := hex.EncodeToString(sum[:])
			if actual != *l.AnchorProofHash {
				return fmt.Errorf("anchor_proof_json does not hash to the committed anchor_proof_hash (committed %s, actual %s); the anchor proof was swapped after the leaf was committed", *l.AnchorProofHash, actual)
			}
		}
		if !IsValidAnchorURL(*l.AnchorURL) {
			return fmt.Errorf("field `anchor_url` must be an http:// or https:// URL, got %q", *l.AnchorURL)
		}
	}
	return nil
}

// ValidateSequence validates every leaf against its position. Timestamps
// are deliberately not checked for monotonicity (clocks step backwards in
// honest deployments; the reference implementation does not check either).
func ValidateSequence(leaves []Leaf) error {
	for i := range leaves {
		if err := leaves[i].Validate(uint64(i)); err != nil {
			return fmt.Errorf("leaf %d: %w", i, err)
		}
	}
	return nil
}

// ErrNotBound is wrapped by every binding failure.
var ErrNotBound = errors.New("leaves do not bind")

func bindErr(msg string) error {
	return fmt.Errorf("%w: %s", ErrNotBound, msg)
}

// VerifyHandoffBinding is SPEC.md §3.1's verify_handoff_binding: the two
// leaves are 0x05, the sender's is Sent and the receiver's is Received,
// each names the other's identity as counterparty, and both committed to
// the same unsalted handoff_state_hash. The identity strings are compared
// byte for byte with the committed counterparty fields, as `witness-log
// bind` does.
func VerifyHandoffBinding(senderIdentity string, sender *Leaf, receiverIdentity string, receiver *Leaf) error {
	if sender.LeafType != LeafHandoffAttestation {
		return bindErr("sender_leaf is not a HandoffAttestation leaf")
	}
	if receiver.LeafType != LeafHandoffAttestation {
		return bindErr("receiver_leaf is not a HandoffAttestation leaf")
	}
	if sender.HandoffDirection == nil || *sender.HandoffDirection != HandoffSent {
		return bindErr("sender_leaf is not marked as the Sent side")
	}
	if receiver.HandoffDirection == nil || *receiver.HandoffDirection != HandoffReceived {
		return bindErr("receiver_leaf is not marked as the Received side")
	}
	if sender.CounterpartyPubkey == nil || *sender.CounterpartyPubkey != receiverIdentity {
		return bindErr("sender's named counterparty does not match the receiver's claimed identity")
	}
	if receiver.CounterpartyPubkey == nil || *receiver.CounterpartyPubkey != senderIdentity {
		return bindErr("receiver's named counterparty does not match the sender's claimed identity")
	}
	if sender.HandoffStateHash == nil || receiver.HandoffStateHash == nil {
		return bindErr("one or both leaves is missing a handoff_state_hash")
	}
	if *sender.HandoffStateHash != *receiver.HandoffStateHash {
		return bindErr("state hashes do not match: sender and receiver committed to different content")
	}
	return nil
}

// VerifyAuthorizationBinding is SPEC.md §3.2's verify_authorization_binding:
// both leaves are 0x06, b's kind is the pair of a's, each names the other,
// and both committed to the same unsalted authorization_scope_hash.
func VerifyAuthorizationBinding(aIdentity string, a *Leaf, bIdentity string, b *Leaf) error {
	if a.LeafType != LeafAuthorizationEvent {
		return bindErr("party_a_leaf is not an AuthorizationEvent leaf")
	}
	if b.LeafType != LeafAuthorizationEvent {
		return bindErr("party_b_leaf is not an AuthorizationEvent leaf")
	}
	if a.AuthorizationEventKind == nil || b.AuthorizationEventKind == nil {
		return bindErr("one or both leaves is missing an authorization_event_kind")
	}
	if *b.AuthorizationEventKind != a.AuthorizationEventKind.Paired() {
		return bindErr(fmt.Sprintf("mismatched event kinds: party_a is %s, party_b is %s, expected %s",
			*a.AuthorizationEventKind, *b.AuthorizationEventKind, a.AuthorizationEventKind.Paired()))
	}
	if a.CounterpartyPubkey == nil || *a.CounterpartyPubkey != bIdentity {
		return bindErr("party_a's named counterparty does not match party_b's claimed identity")
	}
	if b.CounterpartyPubkey == nil || *b.CounterpartyPubkey != aIdentity {
		return bindErr("party_b's named counterparty does not match party_a's claimed identity")
	}
	if a.AuthorizationScopeHash == nil || b.AuthorizationScopeHash == nil {
		return bindErr("one or both leaves is missing an authorization_scope_hash")
	}
	if *a.AuthorizationScopeHash != *b.AuthorizationScopeHash {
		return bindErr("scope hashes do not match: the two sides committed to different scope descriptions")
	}
	return nil
}
