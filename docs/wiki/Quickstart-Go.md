# Quickstart: Go

Go services verify; they do not write logs. The module
`github.com/0xAndersen/witness-log/clients/go` is an independent
implementation of the verifier from the spec, standard library only,
checked against the conformance corpus and against the Rust CLI's verdicts
in CI.

## Install

```sh
go get github.com/0xAndersen/witness-log/clients/go@latest
```

## Verify a dossier an agent handed you

```go
package main

import (
    "fmt"
    "log"
    "os"

    witnesslog "github.com/0xAndersen/witness-log/clients/go"
)

func main() {
    dossier, err := os.ReadFile("dossier.json")
    if err != nil { log.Fatal(err) }
    dirJSON, err := os.ReadFile("trusted.json") // a directory you trust, not one the agent sent
    if err != nil { log.Fatal(err) }
    dir, err := witnesslog.ParseDirectory(dirJSON)
    if err != nil { log.Fatal(err) }

    verdict, report, err := witnesslog.VerifyDossier(dossier, dir, witnesslog.Options{
        ExpectedIdentityPubkey: os.Getenv("EXPECTED_IDENTITY"), // obtained out-of-band
    })
    if err != nil { log.Fatal(err) }
    code := report.ExitCode(false) // false: a sub-majority WITNESSED is 11, as the CLI returns
    fmt.Println(verdict, "exit", code, "valid receipts", report.Quorum.ValidReceipts)
    os.Exit(code)
}
```

Treat anything but `WITNESSED` with exit 0 as "not proven": 11 is WITNESSED
by less than a majority of your directory, 30 DIVERGED (valid, but
contradicts a head or proof you passed in `Options.KnownHeads` /
`Options.Evidence`), 40 INVALID (a check failed). The meanings are the
same as the CLI's: [Verification and verdicts](Verification-and-Verdicts).

## Bind two agents' logs

```go
a, _ := witnesslog.ParseDossier(aJSON)
b, _ := witnesslog.ParseDossier(bJSON)
res, err := witnesslog.Bind(a, b)   // same matching as `witness-log bind`
fmt.Println(res.ExitCode())         // 0 BOUND, 30 MISMATCH
```

## Check a disclosure

```go
err := witnesslog.VerifyDisclosure(&dossier.Leaves[i], payload, salt) // SPEC §8
```

## Command line

```sh
go install github.com/0xAndersen/witness-log/clients/go/cmd/witness-log-verify@latest
witness-log-verify dossier.json --directory trusted.json --identity <hex>; echo $?
```

Full API: [`clients/go/README.md`](https://github.com/0xAndersen/witness-log/blob/main/clients/go/README.md).
