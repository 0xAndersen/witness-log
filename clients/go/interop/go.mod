// Interop check against the reference C2SP libraries (golang.org/x/mod's
// signed-note package and transparency-dev/formats, the code behind
// OmniWitness, Tessera and witness-network.org): a witness-log checkpoint
// note and its cosignatures must verify there unchanged. Separate module so
// clients/go itself stays standard-library only.
module github.com/0xAndersen/witness-log/clients/go/interop

go 1.24.0

toolchain go1.24.7

require (
	github.com/transparency-dev/formats v0.1.0
	golang.org/x/mod v0.32.0
)
