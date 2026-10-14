# witness-log Go verifier

`github.com/0xAndersen/witness-log/clients/go` is a second, independent
implementation of the witness-log verifier, written from `spec/SPEC.md`
with the Go standard library only. It verifies dossiers, cross-log bindings
and disclosures, and it is checked against the same conformance corpus and
against the Rust CLI's verdicts on every commit (`.github/workflows/go.yml`).

It does not write logs. Agents record with the Rust, Python or Node
packages; Go services verify what they are handed.

## Install

```sh
go get github.com/0xAndersen/witness-log/clients/go
go install github.com/0xAndersen/witness-log/clients/go/cmd/witness-log-verify@latest
```

## Verify a dossier

```go
import witnesslog "github.com/0xAndersen/witness-log/clients/go"

dossier, _ := os.ReadFile("dossier.json")
dirJSON, _ := os.ReadFile("trusted.json")        // a directory you trust, obtained out-of-band
dir, err := witnesslog.ParseDirectory(dirJSON)
if err != nil { log.Fatal(err) }

verdict, report, err := witnesslog.VerifyDossier(dossier, dir, witnesslog.Options{
    ExpectedIdentityPubkey: "9f6d…4d1e", // the log you expect, obtained out-of-band
    Threshold:              0.66,
})
if err != nil { log.Fatal(err) }
fmt.Println(verdict, report.ExitCode(false)) // WITNESSED 0
```

Verdicts and exit codes match the Rust CLI: `WITNESSED` 0 (11 when the
cosigners are not a strict majority of the directory),
`CONSISTENT-UNWITNESSED` 10, `UNANCHORED` 20, `DIVERGED` 30 (the dossier
is valid but contradicts a known head or an equivocation proof you
supplied), `INVALID` 40 (a check failed). `report.ExitCode(allowSubMajority)`
is what `witness-log verify` would return, 11 included; `Verdict.ExitCode()`
maps the verdict alone. An unparseable dossier returns `Invalid` with the
error (it returned `Diverged` before 0.5.0). `Report` has the same fields
as `witness-log verify --json`, including `SplitViewUnsafe`, `Failures`
(why `Invalid`), `Contradictions` (why `Diverged`) and
`KnownHeadsUnchecked`; the wording of the last three lists is this
implementation's own.

Evidence you already hold about the identity goes in `Options`:

```go
kh, err := witnesslog.ParseKnownHead("4:0f1e…9a2b") // a head you kept earlier
if err != nil { log.Fatal(err) }
var ev struct{ Proof witnesslog.EquivocationProof `json:"proof"` }
_ = json.Unmarshal(evidenceFile, &ev)               // as `witness serve` writes it
verdict, report, err = witnesslog.VerifyDossier(dossier, dir, witnesslog.Options{
    ExpectedIdentityPubkey: "9f6d…4d1e",
    Threshold:              0.66,
    KnownHeads:             []witnesslog.KnownHead{kh},
    Evidence:               []witnesslog.EquivocationProof{ev.Proof},
})
```

A dossier whose first `TreeSize` leaves do not reproduce a known head,
or a proof that verifies for this identity, makes the verdict `Diverged`.
`(*EquivocationProof).Verify()` checks a proof on its own: the key comes
from the canonical origin `witness-log/<identity hex>`, the proof's own
`log_vkey` must be that key, and both notes must verify under it with one
size and two roots.

Other entry points:

| Call | What it checks |
|---|---|
| `Bind(a, b *Dossier)` | two logs' handoff / authorization leaves commit to the same bytes (same matching as `witness-log bind`) |
| `VerifyHandoffBinding`, `VerifyAuthorizationBinding` | one leaf pair at a time |
| `VerifyDisclosure(leaf, payload, salt)` | SPEC §8: does a payload and salt reproduce `payload_hash` |
| `ParseC2SPNote`, `(*SignedNote).Verify(keys)` | c2sp.org signed notes and cosignatures |
| `VerifyInclusion`, `VerifyConsistency` | RFC 6962 proofs |

## Command line

```
witness-log-verify <dossier.json> [--identity <hex>] [--directory <dir.json>]
                   [--threshold 0.0-1.0 | --min-witnesses N]
                   [--allow-sub-majority | --no-strict] [--revocations <file>]
                   [--known-head <size>:<root>] [--evidence <file>] [--json]
witness-log-verify bind <a.json> <b.json> [--json]
```

The exit code is the verdict, as above: 0, 11, 10, 20, 30, 40; 2 means
unreadable input. `--known-head` and `--evidence` are repeatable and mean
what they mean to `witness-log verify`; `--allow-sub-majority` accepts a
sub-majority WITNESSED as 0, and `--no-strict` drops 11 for one release.

## Conformance

`go test ./...` runs every vector in `../../corpus` (leaf encoding, Merkle
roots, inclusion and consistency proofs, STH, redaction continuity,
handoff, authorization, external anchor, C2SP checkpoint, payload hash,
revocation, and the verification vector `13_verdicts.json`: 20 cases
over whole dossiers, each with the verdict, exit code and report fields
it must produce)
and the golden dossiers under `testdata/`, which `testdata/regen.sh`
produces with the Rust CLI. `testdata/compare-with-rust.sh` re-verifies
every golden with both implementations and diffs the reports.

One documented difference: Go's `crypto/ed25519` accepts a small set of
signatures the Rust verifier rejects (non-canonical encodings, SPEC §6).
`ed25519strict.go` closes that gap so the two agree on every corpus and
golden input; if you find an input where they disagree, that is a bug in
one of them — please open an issue with the dossier.

## Browser build

`cmd/witness-log-wasm` is the same verifier compiled with
`GOOS=js GOARCH=wasm`; `../../web/build-go.sh` builds it for the static
page in `web/`, where it serves as the second engine next to the Rust
wasm build.
