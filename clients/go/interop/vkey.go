package interop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// vkey renders a signed-note verifier key (<name>+<keyid>+<base64(type||key)>)
// from a witness-log directory entry. Kept here, without importing
// clients/go, so the check is against the reference libraries alone.
func vkey(name string, sigType byte, pubkeyHex string) string {
	pk, _ := hex.DecodeString(pubkeyHex)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0A, sigType})
	h.Write(pk)
	id := h.Sum(nil)[:4]
	return name + "+" + hex.EncodeToString(id) + "+" + base64.StdEncoding.EncodeToString(append([]byte{sigType}, pk...))
}
