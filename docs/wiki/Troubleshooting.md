# Troubleshooting

Symptoms, what they mean, and what to do. Grouped by where you see them.
Each entry explains the cause, because most of these are the system doing
its job rather than failing.

## Verification

**`Verdict: UNANCHORED` (exit 20) when I expected WITNESSED.**
You did not pass `--directory`. Without a directory the verifier has no
witnesses to trust, so receipts are not scored at all; the file is checked
only against itself. Pass the directory *you* trust. If you also omitted
`--identity`, the identity line reads "self-consistent (not pinned)", which
means you have not said whose log this should be.

**`Verdict: CONSISTENT-UNWITNESSED` (exit 10).**
Cryptography is sound; coverage fell short. The quorum line says why:
- *1 independent operator*: all receipts come from one `operator_org`. Two organisations are required. Add witnesses run by someone else to your directory and resubmit.
- *below --min-witnesses N* or *below threshold*: fewer valid receipts than your gate. Either submit to more witnesses or lower the gate deliberately.
- *0 witness signatures valid* but the dossier shows receipts: the witnesses that cosigned are not in your directory. Receipts from unknown keys are ignored by design; add the entries if you trust those operators.

**Exit 11: WITNESSED, but not by a strict majority of your directory.**
The verdict is WITNESSED and the receipts verify, but the cosigners are
half your directory or fewer, so a conflicting history could have been
cosigned by the rest without any witness seeing both (split view). Strict
is the default since 0.5.0. Submit to more of your directory, verify
against a smaller directory you actually expect cosignatures from, or, if
a sub-majority is what you meant, pass `--allow-sub-majority` (exit 0,
warning still printed). `--no-strict` restores the 0.4 reading for one
release.

**`Verdict: INVALID` (exit 40).**
A check failed; the file establishes nothing about the identity. Up to
0.4.3 this was reported as `DIVERGED` (exit 30). Read the `✗` line:
- *Identity NOT bound: the checkpoint was signed by X, not the --identity you expected*: wrong `--identity`, or someone else's log. Check your configuration source.
- *Identity NOT bound: the dossier's identity_pubkey is not the key that signed its checkpoint*: the file's claimed identity and its signature disagree. Fabricated or corrupted.
- *Merkle continuity*: a leaf was altered after the checkpoint was signed, or leaves are missing/reordered.
- *Checkpoint signature*: the signature does not verify; corrupted or forged.
- *Key bindings*: a leaf's session key has no valid binding to the identity, or a revoked identity signed after `as_of`.
Run with `--explain` for one line under each check. `--json` lists the
same reasons in `report.failures`.

**`Verdict: DIVERGED` (exit 30).**
The dossier passed every check and contradicts evidence you supplied:
- *known head N:R is not what this dossier's first N leaves produce*: the history up to size N was rewritten after the head you passed with `--known-head` was signed. Both are signed by the identity.
- *witness evidence: this identity signed two different roots for one tree size*: an `--evidence` file verified for this identity. The identity equivocated, whatever this dossier says.
`--json` lists them in `report.contradictions`. A head you pass that is
larger than the dossier is not an error; it is reported as unchecked
(`report.known_heads_unchecked`).

**Exit 2 with a usage message.**
Malformed input: `--identity` not 64 hex characters, `--min-witnesses 0`
or non-integer, unreadable JSON, a directory file that is neither
`{"witnesses":[...]}` nor a bare array, a `--known-head` that is not
`<size>:<64 hex>`, an `--evidence` file that is not an equivocation proof.
The message names the field.

**`Large directory: 66% of N is M cosignatures per checkpoint ... gate on an absolute count with --min-witnesses N`.**
A hint, not an error: with a large directory a fraction threshold is weak
(2 of 60 operators is 3%). Set an absolute floor.

## Journals (Python, Rust)

**`OSError: journal is already open: lock file agent.jsonl.lock is held by a live process`.**
Another process has this journal. One writer per journal is enforced
because two writers would fork the history and witnesses would record the
identity as equivocating. Options: use one process; give each agent its own
journal; or, if you are *certain* the other process is gone (PID reuse after
a reboot, a container that was killed), `JournaledLog.force_unlock(path)`.
On Linux a lock whose PID is dead is reclaimed automatically; this error
only appears when the PID is alive.

**`journal is already open: lock file agent.jsonl.lock is held by a live process` and the live process is *you*.**
The lock records the PID that holds it. If your own process opens the
same journal twice (a notebook cell re-run, `witness_log.open()` called in
two places, a test that forgot `log.close()`), the second open sees a lock
held by a PID that is alive (its own) and refuses, because the lock cannot
tell "same process, second handle" from "another writer". Keep one handle
per journal, or `log.close()` the first before opening again. The lock is
never reclaimed while the PID lives, by design; `force_unlock` works but
means two handles, which is exactly the fork the lock exists to prevent.

**The Python `OSError` message mentions `JournaledLog::force_unlock`, Rust syntax.**
Same error as above, raised through the binding; the message text comes
from the Rust core (0.3.6). In Python the call is
`witness_log.JournaledLog.force_unlock(path)`. 0.4.0 plans to word the
message for the language it is raised in.

**`this journal is sealed (header holds only identity_pubkey_hex); resume it with the identity seed`.**
A sealed journal (`open(..., seal=True)` / `create_sealed`) stores no
seed, so a plain `open(path)` / `resume(path)` cannot derive the identity.
Pass the seed every time: `witness_log.open(path, identity_seed=seed)` in
Python, `JournaledLog::resume_with_identity(path, &seed)` in Rust. A wrong
seed fails with `supplied identity seed does not match the public key this
sealed journal was created with`: the header pins the public key, so a
stranger's seed cannot continue your history. In 0.3.6 the CLI
(`witness submit`, `c2sp show --sign-with`) cannot open a sealed journal at
all and exits 2; `--identity-seed-env NAME` / `--identity-seed-file PATH`
are planned for 0.4.0. Until then export a dossier from Python or Rust and
submit that, or keep the submitting process the one that holds the seed.

**`evidence_window(start, end)` returned fewer entries than the range.**
0.3.6 clamps the range to the tree: `evidence_window(100, 200)` on a
150-leaf log returns 50 entries and does not complain, and a range that
starts past the end returns an empty window whose `verify()` succeeds
(nothing to check). Compare `len(window.entries)` with what you asked for.
0.4.0 plans to refuse an out-of-range window with an error naming the tree
size.

**`resume` reports `dropped_trailing_lines > 0`.**
A crash tore the last line. The partial line was discarded and the file
truncated to the last complete leaf. You lost at most the event in flight.
Nothing to fix; if it recurs, call `sync()` more often or use `sync=True`.

**`forget(i)` returns `False` / `can_forget(i)` is `False`.**
Either the salt is already gone (erased earlier), or the leaf is a marker
type (Redaction, KeyRevocation) that never had one, or you are using the
in-memory `WitnessLog` across a restart (salts live only in memory there;
use `JournaledLog`). Also check that `agent.jsonl.salts` exists: if it was
not backed up with the journal, every salt is gone.

**`unsupported journal format_version X (this build supports Y)`.**
The journal was written by a different major on-disk format. The format is
versioned and refused, never reinterpreted. Use the version that wrote it
to export a dossier, then start a new journal with the same identity seed.

**Two machines, one identity: `409` loops or a `422` from a witness.**
You have two live journals under one identity, or restored one from a
backup after the other advanced. The witness remembers the larger head.
Stop one. If a `422` was already returned, the witness has recorded
equivocation evidence against your identity; that is permanent. See
[Keys and identity](Keys-and-Identity) for the safe migration order.

**`anchor_url must be an http:// or https:// URL` / `counterparty must be the other agent's identity public key as 64 hex characters`.**
Refused before anything is written (0.3.6+). Up to 0.3.5 these were
committed: a non-http anchor URL made every later dossier `DIVERGED`
(`INVALID` since 0.5.0) and
the journal could not be resumed; a counterparty that is not a key
produced a handoff that could never `bind`. Pass the other agent's
`identity_pubkey_hex()` (either case; it is stored lowercase).

**`resume` fails with `field anchor_url must be ...` on a 0.3.5 journal.**
That journal holds an invalid anchor leaf written by 0.3.5. Its history is
intact up to that leaf; export a dossier from a copy with the 0.3.5 wheel,
then start a new journal with the same identity seed.

**`WitnessLog.resume_with_ttl` logs gained extra key bindings.**
When the session binding's TTL passes, the next append rotates to a new
session key bound by the identity (0.3.6+); the old binding stays in the
dossier so earlier leaves still verify. Up to 0.3.5 the log kept writing
under the expired session and verified as `DIVERGED` (`INVALID` since
0.5.0).

**`from witness_log import *` and `open`.**
Since 0.3.6 the star import does not export `open` (it shadowed the
builtin). Call `witness_log.open(...)`.

**The Python wheel will not import / `No module named witness_log._core`.**
Wrong platform wheel or Python version. Wheels are built per platform for
CPython ≥3.9 (abi3). Install the one matching `python -c "import sysconfig;print(sysconfig.get_platform())"`.

## Submitting to witnesses

**`409` from a witness (`Content-Type: text/x.tlog.size`, body is a number).**
Normal: your checkpoint was stale relative to what the witness remembers,
or your `old` line was wrong. The body is the size it last cosigned for
your log, in decimal (`4\n`). The CLI and MCP server resend automatically
with a consistency proof from that size; if you wrote your own client,
resubmit with `old <that size>` and the proof lines
`consistency_proof(that_size)`. A 409 loop (the same 409 twice) means your
journal is *smaller* than what the witness holds: you restored a backup or
have two writers; see "Two machines, one identity" above. A witness never
cosigns on a 409; it only tells you where it is.

**`422` from a witness.**
Two different causes share the code, both "I will not cosign this":
- *consistency proof failed*, *same size, different root*, or a proof sent
  from size 0 for a log it already knows: your submitted history does not
  extend what the witness remembers. If you are the honest operator you
  restored a backup or ran two writers. If **both** checkpoints were signed
  by your key the witness has written an evidence file; that is permanent.
  A bad proof on its own is not recorded as evidence (anyone can attach a
  junk proof to an honest checkpoint).
- *unknown origin* on a witness without `--open-enrollment` is a `404`,
  not a 422; a 422 for a log the witness has never seen means the note's
  origin is not the canonical `witness-log/<identity hex>` of the key that
  signed it, or the size-0 checkpoint does not carry the empty-tree root.
`submit` in 0.3.6 prints the 422 per witness but exits 0 if at least
`--min` others cosigned (default 1); 0.4.0 plans to exit non-zero on any
422.

**`422 consistency proof failed`.**
Your submitted history does not extend what the witness remembers. If you
are the honest operator, you restored from a backup or ran two writers.
The witness has recorded evidence if both checkpoints were signed by your
key. See the entry above.

**`REFUSING TO SUBMIT: witnesses already cosigned size N for this identity, and <journal> (size M) does not extend it`.**
The local cache `agent.jsonl.witnesses.json` says a witness holds a larger
or different head than this journal. This is the guard that stops a
restored backup from equivocating. Find the current journal; do not delete
the cache to force it.

**`submit --min N` exits 1 with every witness line showing `✓ cosigned`.**
`N` is larger than the number of witnesses in the directory, so the gate
can never be met; 0.3.6 prints the per-witness lines and the summary and
exits 1 without naming the cause. Check `jq '.witnesses | length'
trusted.json`. The same happens when the directory is the (empty) public
registry: `0/0 witnesses cosigned`. 0.4.0 plans to default `--min` to a
majority of the directory and to say when `--min` exceeds it.

**`select_witnesses(...)` returns a JSON string, not a list / "expected a directory object".**
The Python helper takes the directory as a JSON *string* (`directory_json`),
the subject identity hex, and `want`, and returns a JSON string: a bare
array of directory entries, which `jq -s` or `json.loads` turn into a list.
Wrap it as `{"witnesses": json.loads(picked)}` before passing it to
`submit`/`verify` as a directory file, or pass the bare array (both shapes
are accepted). Passing a Python dict instead of a string raises a type
error. `select_diverse_witnesses` has the same shape and picks one witness
per operator only.

**`429` / `503` with `Retry-After`.**
Rate limited (default 16 connections and 600 enrollments per minute per
address; stricter if many clients share a NAT or proxy). Clients honour
`Retry-After` up to 60 s. Operators behind a reverse proxy should raise
`--max-conns-per-ip` and `--enroll-rate`.

**`404 unknown log`.**
The witness does not have open enrollment and your origin is not added.
Ask the operator to `witness add-log`, or use a witness with
`--open-enrollment`.

**`403 checkpoint signature not verified`.**
The note's signature does not verify under the key in its canonical origin.
Usually a non-canonical origin (you set a custom one) or a corrupted note.

**`Witnesser.flush()` returns `False`.**
Read `w.status().last_error`: `kind` is `no_cosignatures` (every witness
failed; `outcomes` says why per witness), `too_few` (fewer than
`min_cosignatures`), `refused` (the journal does not extend a head
witnesses already cosigned; same rule as the CLI's `REFUSING TO SUBMIT`)
or `exception` (for example the journal was closed). The thread keeps
retrying with exponential backoff; `flush` skips the backoff and tries now.

**`witness submit: unexpected argument "--..."`.**
Since 0.3.6 `submit` rejects flags it does not know (it used to ignore
them, so a typo such as `--mni 2` silently meant `--min 1`).

**`warning: trusted directory entry ... has a malformed pubkey`.**
That entry can never match a receipt. Fix the directory; `witness init`
prints a correct entry.

**The registry PR fails: `says operator_org is 'example org', entry says 'Example Org'`.**
`registry/validate.py` fetches `GET /` from the entry's URL and requires
`directory_entry.operator_org` to equal the file's `operator_org` byte for
byte: case, spacing, everything. Fix the file to match what the witness
serves (it is what you passed to `witness init --org`), or re-`init` with
the spelling you want. This is a registration rule so the file, the
witness and the operator agree on one string; the *verifier* folds case
and collapses whitespace when it scores operators, so `Example Org` and
`example org` are one operator to a verdict either way, and `verify` prints
labels lowercased. Public registry URLs must also be `https://` and not a
loopback address.

**All witnesses in my directory are mine; verdict stays CONSISTENT-UNWITNESSED.**
Correct. Independence is scored by `operator_org`, and a fleet of 100 under
one organisation is one voice. You need a second organisation:
[Getting witnessed](Getting-Witnessed), or ask a peer to follow
`deploy/witness/AGENT_OPERATOR.md`.

## Running a witness

**`witness.lock` names a PID that is alive but is not a witness.**
PID reuse after a reboot. Stop anything that could be serving this
directory, delete `witness.lock`, start again. Never run two processes on
one state directory.

**`WARNING: .../witness.key is readable by other users` at start.**
`chmod 600 witness.key`. The witness still starts; the warning is about
custody.

**I restored `witness.key` from backup and now verifiers dropped my entry.**
The backup did not include `logs/`, so the witness forgot its heads and
cosigned a conflicting one: it equivocated. This cannot be undone; retire
the key (`init` a new directory, publish the new entry). Back up `witness.key`,
`witness.json` and `logs/` as one snapshot, always.
[Running a witness](Running-a-Witness) §3.

**Clients get `429` constantly behind my TLS proxy.**
Every client arrives from the proxy's address. Start with
`--max-conns-per-ip 256 --enroll-rate 6000` (or `fleet.py serve --behind-proxy`).

**`witness verify-evidence` says the file does not prove equivocation (NOT PROVEN, exit 40; 30 before 0.5.0).**
The file is not two log-signed checkpoints for one size with different
roots, or the log's key could not be taken from a canonical origin (pass
`--vkey` with the key you know). A failed consistency proof alone is not evidence (anyone can attach a
junk proof to an honest checkpoint), and since 0.3.1 the witness does not
record it as such.

## MCP server

**`ModuleNotFoundError: mcp`.**
`pip install "witness-log[mcp]"`. The MCP SDK needs Python ≥3.10. The core
library works on 3.9; the server does not. crewai pins `mcp<2`, so the
`crewai` and `mcp` extras need separate environments.

**`verify_chain_integrity` said `consistent_unwitnessed` right after a successful `submit_to_witnesses`.**
Fixed in 0.3.6: the witnessed dossier is kept and its cosignatures count
while the head is unchanged. After the next append, `witnessed_size` and
`witnessed_verdict` report the witnessed prefix; submit again to witness
the new head.

**A tool error says only `Error executing tool ...`.**
Servers before 0.3.6 hid the reason. Upgrade; errors now carry it.

**`submit_to_witnesses` returns fewer receipts than `max_witnesses`.**
Some witnesses were unreachable or rate-limited; the result lists each
outcome. `min_witnesses` controls whether that counts as success.

## CI and builds

**`cargo publish` fails with `A verified email address is required to publish crates to crates.io`.**
Not a code problem. The crates.io account doing the publish (the owner of
the token in `CARGO_REGISTRY_TOKEN`) has no verified email. Log in to
crates.io, Account Settings → Email, add and verify an address, then
re-run the `publish-crates` workflow; no new tag is needed because nothing
was published. The same message appears for a token that belongs to a
different account than the one you expected.

**`cargo deny` fails.**
Run `cargo deny --config deny.toml check` from the workspace root; the
`--config` flag must precede `check`.

**The outside-swarm CI job is skipped on Python 3.9.**
Intentional; it needs the MCP SDK.

**`witness-log verify ... | head` panicked with a broken pipe in old versions.**
Fixed in 0.3.3 (SIGPIPE is reset to default on Unix).

## Still stuck

Open an issue with: the exact command, the full `verify --json` output (it
contains no payloads, only hashes and metadata), your witness-log version,
and the platform. For a suspected equivocation, attach the evidence file;
it is self-contained and safe to share.
