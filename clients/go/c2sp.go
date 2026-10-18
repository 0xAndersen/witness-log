package witnesslog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// C2SP signature types (c2sp.org/signed-note, c2sp.org/tlog-cosignature).
const (
	SigTypeEd25519        uint8 = 0x01
	SigTypeCosignatureV1  uint8 = 0x04
	maxNoteSignatures           = 64
	CanonicalOriginPrefix       = "witness-log/"
)

// C2SP parsing errors.
var (
	ErrMalformedVkey        = errors.New("c2sp: malformed verifier key")
	ErrMalformedSignature   = errors.New("c2sp: malformed signature line")
	ErrMissingSeparator     = errors.New("c2sp: note has no blank separator line")
	ErrNoSignatures         = errors.New("c2sp: note has no signature lines")
	ErrInvalidCharacters    = errors.New("c2sp: note contains control characters")
	ErrMalformedOrigin      = errors.New("c2sp: malformed origin line")
	ErrMalformedTreeSize    = errors.New("c2sp: malformed tree size")
	ErrMalformedRootHash    = errors.New("c2sp: malformed root hash")
	ErrCheckpointTooShort   = errors.New("c2sp: checkpoint needs origin, size and root lines")
	ErrNoTrustedSignature   = errors.New("c2sp: no signature from a trusted key verified")
	ErrBadSignature         = errors.New("c2sp: a signature from a trusted key failed to verify")
	ErrMalformedCosignature = errors.New("c2sp: malformed cosignature payload")
)

// KeyID is the signed-note key ID: SHA-256(name || 0x0A || sig_type || public_key)[:4].
func KeyID(name string, sigType uint8, publicKey []byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0A, sigType})
	h.Write(publicKey)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

// VerifierKey is a signed-note verifier key, `<name>+<hex id>+<base64(type||key)>`.
type VerifierKey struct {
	Name      string
	ID        [4]byte
	SigType   uint8
	PublicKey []byte
}

// NewEd25519VerifierKey builds the vkey for plain note signatures (0x01).
func NewEd25519VerifierKey(name string, publicKey []byte) VerifierKey {
	pk := append([]byte(nil), publicKey...)
	return VerifierKey{Name: name, ID: KeyID(name, SigTypeEd25519, pk), SigType: SigTypeEd25519, PublicKey: pk}
}

// NewCosignatureVerifierKey builds the vkey for cosignature/v1 (0x04).
func NewCosignatureVerifierKey(name string, publicKey []byte) VerifierKey {
	pk := append([]byte(nil), publicKey...)
	return VerifierKey{Name: name, ID: KeyID(name, SigTypeCosignatureV1, pk), SigType: SigTypeCosignatureV1, PublicKey: pk}
}

// Encode renders the vkey in its textual form.
func (k VerifierKey) Encode() string {
	material := append([]byte{k.SigType}, k.PublicKey...)
	return k.Name + "+" + hex.EncodeToString(k.ID[:]) + "+" + base64.StdEncoding.EncodeToString(material)
}

// ParseVerifierKey splits at the first two '+' separators (the base64
// payload routinely contains '+' of its own).
func ParseVerifierKey(s string) (VerifierKey, error) {
	parts := strings.SplitN(s, "+", 3)
	if len(parts) != 3 || parts[0] == "" {
		return VerifierKey{}, ErrMalformedVkey
	}
	idB, err := hex.DecodeString(parts[1])
	if err != nil || len(idB) != 4 {
		return VerifierKey{}, ErrMalformedVkey
	}
	material, err := strictBase64.DecodeString(parts[2])
	if err != nil || len(material) < 1 {
		return VerifierKey{}, ErrMalformedVkey
	}
	k := VerifierKey{Name: parts[0], SigType: material[0], PublicKey: material[1:]}
	copy(k.ID[:], idB)
	return k, nil
}

// NoteSignature is one `— <name> <base64(key id || payload)>` line.
type NoteSignature struct {
	KeyName   string
	KeyID     [4]byte
	Signature []byte // payload after the 4-byte key ID
}

const emDash = "—"

// strictBase64 is standard base64 that rejects non-zero padding bits, so
// one value has one encoding, as in the reference (base64ct) and the
// TypeScript verifier. encoding/base64's StdEncoding accepts them, which
// made a note with a non-canonical root or signature line verify here and
// nowhere else (security review of 0.5.0, F5).
var strictBase64 = base64.StdEncoding.Strict()

// ValidKeyName reports whether name is a signed-note key name: non-empty,
// with no Unicode space (White_Space) and no '+'.
func ValidKeyName(name string) bool {
	return name != "" && !strings.ContainsRune(name, '+') && strings.IndexFunc(name, unicode.IsSpace) < 0
}

// Encode renders the signature line without its trailing newline.
func (s NoteSignature) Encode() string {
	payload := append(append([]byte(nil), s.KeyID[:]...), s.Signature...)
	return emDash + " " + s.KeyName + " " + base64.StdEncoding.EncodeToString(payload)
}

// ParseNoteSignature parses one signature line (no trailing newline).
func ParseNoteSignature(line string) (NoteSignature, error) {
	if !strings.HasPrefix(line, emDash+" ") {
		return NoteSignature{}, fmt.Errorf("%w: must begin with an em dash and a space", ErrMalformedSignature)
	}
	rest := strings.TrimPrefix(line, emDash+" ")
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) != 2 || parts[0] == "" {
		return NoteSignature{}, fmt.Errorf("%w: missing key name or signature", ErrMalformedSignature)
	}
	// signed-note §Format: key names contain no Unicode spaces and no '+'.
	// A line that breaks this is malformed whether or not its key is
	// known, so the note is rejected (as golang.org/x/mod/sumdb/note does)
	// rather than the line skipped as an unknown key. The reference and
	// TypeScript verifiers apply the same rule.
	if !ValidKeyName(parts[0]) {
		return NoteSignature{}, fmt.Errorf("%w: key name contains '+' or a Unicode space", ErrMalformedSignature)
	}
	payload, err := strictBase64.DecodeString(parts[1])
	if err != nil {
		return NoteSignature{}, fmt.Errorf("%w: signature is not valid base64", ErrMalformedSignature)
	}
	if len(payload) < 5 {
		return NoteSignature{}, fmt.Errorf("%w: payload shorter than a key ID plus one byte", ErrMalformedSignature)
	}
	s := NoteSignature{KeyName: parts[0], Signature: payload[4:]}
	copy(s.KeyID[:], payload[:4])
	return s, nil
}

// SignedNote is a c2sp.org/signed-note: the text (including its final
// newline, excluding the blank separator) plus signature lines.
type SignedNote struct {
	Text       string
	Signatures []NoteSignature
}

func checkNoteCharacters(s string) error {
	for _, r := range s {
		if r < 0x20 && r != '\n' {
			return ErrInvalidCharacters
		}
	}
	return nil
}

// ParseC2SPNote parses a signed note. The text is everything before the
// LAST blank line that has content after it; every non-empty line after
// it is a signature line.
func ParseC2SPNote(raw string) (*SignedNote, error) {
	if err := checkNoteCharacters(raw); err != nil {
		return nil, err
	}
	lines := strings.Split(raw, "\n")
	sep := -1
	for i, line := range lines {
		if line != "" {
			continue
		}
		hasContentAfter := false
		for _, l := range lines[i+1:] {
			if l != "" {
				hasContentAfter = true
				break
			}
		}
		if hasContentAfter {
			sep = i
		}
	}
	if sep < 0 {
		return nil, ErrMissingSeparator
	}
	note := &SignedNote{Text: strings.Join(lines[:sep], "\n") + "\n"}
	for _, line := range lines[sep+1:] {
		if line == "" {
			continue
		}
		if len(note.Signatures) >= maxNoteSignatures {
			return nil, fmt.Errorf("%w: more than %d signature lines", ErrMalformedSignature, maxNoteSignatures)
		}
		sig, err := ParseNoteSignature(line)
		if err != nil {
			return nil, err
		}
		note.Signatures = append(note.Signatures, sig)
	}
	if len(note.Signatures) == 0 {
		return nil, ErrNoSignatures
	}
	return note, nil
}

// Encode renders the note: text, blank line, one signature per line.
func (n *SignedNote) Encode() (string, error) {
	if err := checkNoteCharacters(n.Text); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(n.Text)
	if !strings.HasSuffix(n.Text, "\n") {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	for _, s := range n.Signatures {
		b.WriteString(s.Encode())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// Verify checks the note's plain (0x01) signatures against trusted keys.
// Unknown keys are ignored; a known key that fails rejects the note; at
// least one known key must verify. It returns the names that verified.
func (n *SignedNote) Verify(trusted []VerifierKey) ([]string, error) {
	var verified []string
	for _, sig := range n.Signatures {
		var vk *VerifierKey
		for i := range trusted {
			if trusted[i].Name == sig.KeyName && trusted[i].ID == sig.KeyID {
				vk = &trusted[i]
				break
			}
		}
		if vk == nil || vk.SigType != SigTypeEd25519 {
			continue
		}
		if len(sig.Signature) != 64 || len(vk.PublicKey) != 32 {
			return nil, ErrBadSignature
		}
		if !VerifyStrict(vk.PublicKey, []byte(n.Text), sig.Signature) {
			return nil, ErrBadSignature
		}
		verified = append(verified, vk.Name)
	}
	if len(verified) == 0 {
		return nil, ErrNoTrustedSignature
	}
	return verified, nil
}

// Checkpoint is a c2sp.org/tlog-checkpoint body.
type Checkpoint struct {
	Origin     string
	TreeSize   uint64
	RootHash   Hash
	Extensions []string
}

func validateOrigin(origin string) error {
	if origin == "" || strings.ContainsAny(origin, " +\n") {
		return ErrMalformedOrigin
	}
	return nil
}

// NoteText renders origin, decimal size, base64 root and extension lines,
// each newline-terminated.
func (c *Checkpoint) NoteText() (string, error) {
	if err := validateOrigin(c.Origin); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(c.Origin)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatUint(c.TreeSize, 10))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(c.RootHash[:]))
	b.WriteByte('\n')
	for _, ext := range c.Extensions {
		if ext == "" {
			return "", ErrMalformedOrigin
		}
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// CheckpointFromNote parses a checkpoint out of a signed note's text.
func CheckpointFromNote(n *SignedNote) (*Checkpoint, error) {
	lines := strings.Split(strings.TrimRight(n.Text, "\n"), "\n")
	if len(lines) < 3 {
		return nil, ErrCheckpointTooShort
	}
	if err := validateOrigin(lines[0]); err != nil {
		return nil, err
	}
	sizeStr := lines[1]
	if sizeStr == "" || (len(sizeStr) > 1 && sizeStr[0] == '0') {
		return nil, ErrMalformedTreeSize
	}
	for i := 0; i < len(sizeStr); i++ {
		if sizeStr[i] < '0' || sizeStr[i] > '9' {
			return nil, ErrMalformedTreeSize
		}
	}
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return nil, ErrMalformedTreeSize
	}
	rootB, err := strictBase64.DecodeString(lines[2])
	if err != nil || len(rootB) != 32 {
		return nil, ErrMalformedRootHash
	}
	cp := &Checkpoint{Origin: lines[0], TreeSize: size}
	copy(cp.RootHash[:], rootB)
	for _, ext := range lines[3:] {
		if ext == "" {
			return nil, ErrCheckpointTooShort
		}
		cp.Extensions = append(cp.Extensions, ext)
	}
	return cp, nil
}

// Cosignature is a c2sp.org/tlog-cosignature v1.
type Cosignature struct {
	KeyName   string
	KeyID     [4]byte
	Timestamp uint64 // unix seconds
	Signature []byte
}

// CosignatureMessage is the signed message: "cosignature/v1\ntime <ts>\n" + body.
func CosignatureMessage(timestamp uint64, checkpointNoteText string) string {
	return "cosignature/v1\ntime " + strconv.FormatUint(timestamp, 10) + "\n" + checkpointNoteText
}

// CosignatureFromNoteSignature decodes `timestamp (8B BE) || signature`.
func CosignatureFromNoteSignature(s NoteSignature) (*Cosignature, error) {
	if len(s.Signature) < 9 {
		return nil, ErrMalformedCosignature
	}
	return &Cosignature{
		KeyName:   s.KeyName,
		KeyID:     s.KeyID,
		Timestamp: binary.BigEndian.Uint64(s.Signature[:8]),
		Signature: append([]byte(nil), s.Signature[8:]...),
	}, nil
}

// ToNoteSignature renders the cosignature as a signature line payload.
func (c *Cosignature) ToNoteSignature() NoteSignature {
	payload := binary.BigEndian.AppendUint64(nil, c.Timestamp)
	payload = append(payload, c.Signature...)
	return NoteSignature{KeyName: c.KeyName, KeyID: c.KeyID, Signature: payload}
}

// Verify checks the cosignature under a 0x04 vkey over the checkpoint body.
func (c *Cosignature) Verify(vkey VerifierKey, checkpointNoteText string) error {
	if vkey.SigType != SigTypeCosignatureV1 || vkey.ID != c.KeyID || vkey.Name != c.KeyName {
		return ErrNoTrustedSignature
	}
	if len(vkey.PublicKey) != 32 || len(c.Signature) != 64 {
		return ErrBadSignature
	}
	if !VerifyStrict(vkey.PublicKey, []byte(CosignatureMessage(c.Timestamp, checkpointNoteText)), c.Signature) {
		return ErrBadSignature
	}
	return nil
}

// CanonicalOrigin is the only origin under which a cosignature counts
// toward a verdict: "witness-log/" + lowercase hex of the identity key.
func CanonicalOrigin(identityPubkey []byte) string {
	return CanonicalOriginPrefix + hex.EncodeToString(identityPubkey)
}

// IdentityFromCanonicalOrigin inverts CanonicalOrigin; ok is false for any
// other origin.
func IdentityFromCanonicalOrigin(origin string) (pub []byte, ok bool) {
	rest, found := strings.CutPrefix(origin, CanonicalOriginPrefix)
	if !found || len(rest) != 64 || strings.ToLower(rest) != rest {
		return nil, false
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return nil, false
	}
	return b, true
}

// CheckpointFromSTH renders a native checkpoint as a C2SP body under
// origin. The STH's self-asserted timestamp is dropped: in C2SP, time is
// asserted only by cosigners.
func CheckpointFromSTH(sth *SignedTreeHead, origin string) (*Checkpoint, error) {
	rootB, ok := hexN(sth.RootHash, 32)
	if !ok {
		return nil, ErrMalformedRootHash
	}
	if err := validateOrigin(origin); err != nil {
		return nil, err
	}
	cp := &Checkpoint{Origin: origin, TreeSize: sth.TreeSize}
	copy(cp.RootHash[:], rootB)
	return cp, nil
}
