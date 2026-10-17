# GitHub Action

`action.yml` at the root of this repository makes `witness-log verify` a
workflow step. It downloads the released CLI for the runner, checks it
against the release's `SHA256SUMS`, verifies a dossier offline against the
identity and witness directory *you* supply, and fails the step unless the
verdict is WITNESSED. The verdict, the exit code and the `--json` report
are step outputs, and the job summary says in plain words what each check
found.

```yaml
- uses: 0xAndersen/witness-log@v0.6.0
  with:
    dossier: dossier.json
    identity: ${{ vars.AGENT_IDENTITY }}
    directory: trusted-directory.json
```

The action ships with the repository from v0.6.0 and runs any CLI release
from v0.5.0 on. It is the [CLI](CLI-Reference#verify) underneath: the same
verdicts, the same exit codes, nothing sent anywhere.

`identity` and `directory` are what make the verdict mean something, so
they must come from you, not from whoever produced the dossier: the identity
from a repository variable or a file you committed, the directory from a
file you committed. A dossier and a directory downloaded together from the
agent's operator prove only that the operator agrees with itself.

---

## Inputs

| input | default | maps to | meaning |
|---|---|---|---|
| `dossier` | required | `<dossier.json>` | path to the dossier to verify |
| `identity` | | `--identity` | the identity public key you expect (64 hex). Without it the verdict says nothing about whose log this is |
| `directory` | | `--directory` | the witness directory you trust. Without it the best verdict is UNANCHORED |
| `min-witnesses` | | `--min-witnesses` | count gate as a number of witnesses |
| `threshold` | | `--threshold` | count gate as a fraction of the directory (the CLI default is 0.66) |
| `known-heads` | | `--known-head`, repeated | heads you already trust for this identity, `<size>:<root hex>`, separated by newlines or commas |
| `evidence` | | `--evidence`, repeated | witness equivocation proof files, one path per line |
| `revocations` | | `--revocations` | revocation statements you know of |
| `subject-org` | | `--subject-org` | the organisation that operates the log; its own witnesses never count as independent operators. Needs witness-log 0.6.0 or later (the step fails with that message on an older `version`) |
| `allow-sub-majority` | `false` | `--allow-sub-majority` | `true` accepts WITNESSED from fewer than a strict majority of the directory as exit 0 |
| `fail-on` | `not-witnessed` | | which outcomes fail the step (below) |
| `version` | | | the CLI release: `v0.5.0` or later, or `latest`. Empty: the action's own tag when it is a version, otherwise the latest release (below) |
| `token` | `github.token` | | read access to this repository's releases, used only to resolve `latest` and download the CLI |

Empty inputs are left out of the command line, so the CLI's defaults apply.

## Outputs

| output | value |
|---|---|
| `verdict` | `WITNESSED`, `CONSISTENT-UNWITNESSED`, `UNANCHORED`, `DIVERGED` or `INVALID`; empty when verify reached no verdict (exit 2) |
| `exit-code` | `0`, `10`, `11`, `20`, `30`, `40`, or `2` for a usage error |
| `report` | path to the `witness-log verify --json` output (in `runner.temp`); empty when there is none |
| `identity-pinned` | `true` when the verdict is about the `identity` you passed |
| `directory-pinned` | `true` when receipts were scored against the `directory` you passed |
| `split-view-unsafe` | `true` when the result is WITNESSED but the cosigners are not a strict majority of the directory |
| `valid-receipts` | valid witness receipts from your directory (`0` without a directory) |
| `independent-operators` | distinct independent operators among them (WITNESSED needs 2) |
| `version` | the CLI release that ran, e.g. `v0.5.0` |

`verdict` is WITNESSED for both exit 0 and exit 11, as in the CLI; read
`exit-code` or `split-view-unsafe` to tell them apart. The report's fields
are described under [`verify --json`](CLI-Reference#verify); the wording of
`failures` and `contradictions` is not part of the contract, their being
empty or not is.

## Which outcomes fail the step

| exit | verdict | `not-witnessed` (default) | `invalid-or-diverged` | `never` |
|---|---|---|---|---|
| 0 | WITNESSED | pass | pass | pass |
| 11 | WITNESSED by fewer than a strict majority | **fail** | pass | pass |
| 10 | CONSISTENT-UNWITNESSED | **fail** | pass | pass |
| 20 | UNANCHORED | **fail** | pass | pass |
| 30 | DIVERGED | **fail** | **fail** | pass |
| 40 | INVALID | **fail** | **fail** | pass |
| 2 | usage error: missing or unreadable input, bad flag value | **fail** | **fail** | **fail** |
| | the CLI could not be downloaded, or its SHA-256 does not match | **fail** | **fail** | **fail** |

A step that passes with a non-zero exit code leaves a warning annotation
naming the verdict, so a report-only run still shows it on the run page.
Outputs are set either way: a later step with `if: always()` or the
action step with `continue-on-error: true` can read them.

## The job summary

Each use of the action adds a section to the job summary: the verdict, one
sentence saying what it means, the exit code and whether the step passed,
then one row per check (checkpoint signature, identity, leaf structure, key
bindings and revocations, Merkle continuity, witness receipts and the gate,
independent operators, split view, known heads, evidence), the failures
behind an INVALID and the contradictions behind a DIVERGED, and the full
`witness-log explain <verdict>` text folded underneath. For the sample
dossier in `examples/`:

> **witness-log verify: WITNESSED**
>
> The record checks out, and witnesses from at least two independent organisations in your directory, a strict majority of it, cosigned this exact history.
>
> | Check | What it found |
> |---|---|
> | Identity | signed by the identity you pinned, `f7809c16...0506b3be` |
> | Merkle continuity | the 6 leaves reproduce the signed root |
> | Witness receipts | 3 valid, from the 4 witnesses in your directory; gate `count >= 2` met |
> | Independent operators | 2: example-infra-co, example-university |
> | Split view | ruled out: the cosigners are a strict majority of your directory |

The job log has `verify`'s own output, exactly as the CLI prints it.

---

## Which CLI runs

**Version.** `version` wins when set. Otherwise, when the action is used
at a version tag (`uses: 0xAndersen/witness-log@v0.6.0`), the CLI of that
release runs, so pinning the action pins the verifier. With a branch, a
commit SHA, or a local `uses: ./`, the latest release is resolved through
the GitHub API. **If you pin the action to a commit SHA, set `version` as
well**, or the verifier floats to the latest release. Releases before
v0.5.0 are refused: their exit codes differ (a failed check exited 30, and
a sub-majority WITNESSED exited 0).

**Platform.**

| runner | release build |
|---|---|
| Linux x64 | `x86_64-unknown-linux-gnu` (glibc 2.35 or newer) |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| macOS arm64 | `aarch64-apple-darwin` |
| macOS x64 | `x86_64-apple-darwin` |
| Windows x64 | `x86_64-pc-windows-msvc` |
| Windows arm64 | `x86_64-pc-windows-msvc`, run under Windows' x64 emulation (a notice says so) |

The Linux builds need glibc, so a job running in an Alpine (musl)
container cannot use them.

**Integrity.** The archive `witness-log-<version>-<target>.tar.gz` is
checked against the release's `SHA256SUMS` before anything is unpacked; a
mismatch or a missing entry fails the step and nothing runs. The archive is
cached with `actions/cache` under its version and target. `SHA256SUMS` is
fetched fresh on every run, so a cached archive is checked exactly like a
downloaded one; one that does not match is discarded with a warning and
downloaded again. The unpacked binary must report the expected version,
and its directory is added to `PATH` for later steps. `SHA256SUMS` lives in
the same release as the archive: the check catches a corrupted download, a
tampered cache or mirror, not a compromised release.

**Downloads** go through `gh release download` with `token` (preinstalled
on GitHub-hosted runners) and fall back to the public release URL. A
self-hosted runner needs `bash`, `tar`, `curl` or `gh`, one of
`sha256sum`, `shasum` or `openssl`, and `jq` or Python 3 to read the
report; GitHub-hosted runners have all of them. Using the action several
times in one job downloads the CLI once.

## Security notes

- Every input reaches the action's scripts through `env:`, never by
  `${{ }}` interpolation inside a script, so an input cannot inject shell
  code. Do the same with the outputs in your own `run:` steps (recipes
  below).
- Workflow commands are switched off while `verify` prints, because its
  output can quote the dossier; a crafted dossier cannot set outputs or
  annotations through the log.
- The token is only used to read this repository's releases;
  `permissions: contents: read` is enough, and the action works without it
  (`token: ''` falls back to anonymous downloads).
- Verification is offline. The dossier, the directory and the report stay
  on the runner unless you upload them.

---

## Recipe: gate a deploy on WITNESSED

The deploy job needs the verify job, which fails unless the dossier is
WITNESSED (exit 0) by a strict majority of your directory for the identity
you pinned.

```yaml
name: deploy
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-24.04
    outputs:
      verdict: ${{ steps.wl.outputs.verdict }}
    steps:
      - uses: actions/checkout@v7
      - uses: 0xAndersen/witness-log@v0.6.0
        id: wl
        with:
          dossier: audit/dossier.json
          identity: ${{ vars.AGENT_IDENTITY }}          # set once, in Settings -> Variables
          directory: audit/trusted-directory.json       # committed by you, not by the agent

  deploy:
    needs: verify                                       # skipped unless verify passed
    runs-on: ubuntu-24.04
    environment: production
    steps:
      - uses: actions/checkout@v7
      - run: ./deploy.sh
```

If the directory is large (a registry) and the agent submits to a curated
subset of it, verify against the subset: against the whole registry the
same cosignatures are a minority, which is exit 11 and fails this gate on
purpose ([split view](Verification-and-Verdicts)). Accept that weaker
guarantee explicitly with `allow-sub-majority: true` if you must.

## Recipe: record-only reporting

Verify every dossier, never block, keep the report, and fail only on
evidence that something is wrong with the record itself.

```yaml
      - uses: 0xAndersen/witness-log@v0.6.0
        id: wl
        with:
          dossier: dossier.json
          identity: ${{ vars.AGENT_IDENTITY }}
          directory: trusted-directory.json
          fail-on: never                 # or invalid-or-diverged: fail only on 30 and 40

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: witness-log-report
          path: ${{ steps.wl.outputs.report }}

      - name: Note anything short of WITNESSED
        if: steps.wl.outputs.exit-code != '0'
        env:
          VERDICT: ${{ steps.wl.outputs.verdict }}
          CODE: ${{ steps.wl.outputs.exit-code }}
          REPORT: ${{ steps.wl.outputs.report }}
        run: |
          echo "witness-log: $VERDICT (exit $CODE)"
          [ -z "$REPORT" ] || jq -r '.report.failures[], .report.contradictions[]' "$REPORT"
```

The job summary already carries the verdict and every check; the artifact
keeps the machine-readable report with the run.

## Recipe: pin a known head from a previous run's artifact

A WITNESSED dossier today does not show that the agent's history is the
one you saw last week. Keep the head of every dossier that verified, and
pass it to the next run: if the new dossier's first `<size>` leaves do not
reproduce it, the identity has signed two histories and the verdict is
DIVERGED.

```yaml
name: audit
on:
  schedule:
    - cron: "17 6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  actions: read                          # to list runs and download their artifacts

jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7

      - name: Head from the last successful run on main
        id: prev
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          run_id=$(gh run list --repo "$GITHUB_REPOSITORY" --workflow audit.yml --branch main \
            --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty')
          if [ -n "$run_id" ] && gh run download "$run_id" --repo "$GITHUB_REPOSITORY" \
            --name witnessed-head --dir prev; then
            echo "head=$(tr '\n' ',' < prev/head.txt)" >> "$GITHUB_OUTPUT"   # one head per line
          fi

      - uses: 0xAndersen/witness-log@v0.6.0
        id: wl
        with:
          dossier: dossier.json
          identity: ${{ vars.AGENT_IDENTITY }}
          directory: trusted-directory.json
          known-heads: ${{ steps.prev.outputs.head }}

      # A head larger than the dossier cannot be checked: the CLI lists it
      # as unchecked instead of failing. A log that shrank is a finding here.
      - name: The dossier is not shorter than the head we kept
        env:
          REPORT: ${{ steps.wl.outputs.report }}
        run: jq -e '.report.known_heads_unchecked == []' "$REPORT"

      - name: Keep this head for the next run
        run: jq -r '.checkpoint | "\(.tree_size):\(.root_hash)"' dossier.json > head.txt

      - uses: actions/upload-artifact@v7
        with:
          name: witnessed-head
          path: head.txt
          retention-days: 90
```

Only a run that passed (WITNESSED, and not shorter than the last head)
uploads a head, and only runs on `main` are read back, so a pull request
cannot plant one. A head lives as long as the artifact (at most 90 days
here); for a longer memory, commit `head.txt`, or append each new head to
the previous file instead of replacing it, so every head you ever saw is
checked.
