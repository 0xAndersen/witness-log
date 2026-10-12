# Quickstart: Rust

Rust is the reference implementation: the Python wheel, the CLI, the MCP
server and every witness are this code. This page walks through the two
crates the way a maintainer would explain them to a new contributor:
what each type is *for*, what invariant it protects, and why the API has the
shape it does. Code first, explanation under it.

MSRV 1.75. No `unsafe`. Dependencies are audited with `cargo deny` in CI.

Everything on this page compiles against this `Cargo.toml`. The three
crates after the witness-log ones are used directly by the snippets
(`ed25519_dalek::SigningKey` in §5, `serde_json` in §3 and §6, `hex` if
you print raw hashes); they are already dependencies of
`witness-log-core`, so they add nothing to your build, but Rust needs them
named to let you `use` them:

```toml
[dependencies]
witness-log-core    = "0.3.6"   # log, Merkle tree, identity, redaction, journal, C2SP encoding
witness-log-network = "0.3.6"   # witnesses, directories, quorum, dossiers, verification
ed25519-dalek       = "2.1"     # SigningKey, for evidence windows and embedding a witness (§5, §7)
serde_json          = "1"       # dossiers and directories are serde structs
hex                 = "0.4"     # only if you print or parse raw 32-byte hashes yourself
# from crates.io; or, for an unreleased fix:
# witness-log-core = { git = "https://github.com/0xAndersen/witness-log", tag = "v0.3.6" }
```

The versions of `ed25519-dalek`, `serde_json` and `hex` match the
workspace's own (`Cargo.toml` at the repository root), so there is one copy
of each in your dependency graph. The snippets below, pasted in order into
one `main.rs`, build and run against these versions; that check is part of
how this page is maintained.

**Why two crates.** `core` is everything a single process needs to keep a
provable history of itself, with no I/O beyond a file. `network` is
everything needed to make that history *mean something to someone else*:
talking to witnesses, deciding what counts as independent, exporting a
dossier and verifying one. A verifier only needs `network`; an embedded
agent that will be witnessed by a sidecar only needs `core`. Keeping the
trust logic out of the data structure also keeps the data structure small
enough to audit.

---

## 1. Create a log and record events

```rust
use witness_log_core::identity::IdentityKeypair;
use witness_log_core::journal::JournaledLog;

fn main() -> std::io::Result<()> {
    let identity = IdentityKeypair::generate();          // once, ever, per agent
    let mut log = JournaledLog::create("agent.jsonl", identity)?;

    log.append_intent(br#"{"tool":"transfer_funds","args":{"amount_usd":250}}"#)?;
    log.append_result(br#"{"status":"ok","tx_id":"tx_7ac31"}"#)?;
    log.sync()?;

    println!("{} leaves, root {}", log.log().tree_size(), log.log().root_hex());
    Ok(())
}
```

**`IdentityKeypair`** is an Ed25519 keypair that *is* the agent. It signs
checkpoints and key bindings and nothing else. `JournaledLog::create` writes
its seed into the journal header, so from now on the file is the identity;
there is no separate key file to lose or to desynchronise from the history.

**`JournaledLog` vs `WitnessLog`.** `WitnessLog` (in `log.rs`) is the pure
in-memory structure: leaves, Merkle tree, session key, salts. `JournaledLog`
wraps it and makes every mutation durable *before* returning: append the
JSON line, append the salt to the sidecar, then update memory. The wrapper
owns the lock file and the crash-recovery logic. You reach the inner log
with `log.log()` for anything read-only (proofs, checkpoints). The
in-memory type exists on its own for tests, for conformance vectors, and
for embedders who already have a durable store and only want the tree.

**Why `append_*` returns a `u64`.** That is the leaf index, the only handle
you ever need for a leaf: for `inclusion_proof(index)`, for `forget(index)`,
for `write_receipt(index)`. Indices are dense and never reused.

**Why `append_intent` and `append_result` are separate methods** rather than
one `append(kind, payload)`: the eight leaf types (§2 of the spec) have
different semantics to a verifier, and making the common two explicit in the
type signature keeps call sites honest about which they mean. The
less-common types have their own methods too: `append_memory`,
`append_handoff_sent/received` (which bind two logs together),
`append_authorization_event`, `append_external_anchor`.

---

## 2. Resume after a restart (or a crash)

```rust
let (mut log, report) = JournaledLog::resume("agent.jsonl")?;
if report.dropped_trailing_lines > 0 {
    eprintln!("healed a torn tail: {} partial line(s) dropped", report.dropped_trailing_lines);
}
```

**What `resume` guarantees.** It replays the journal, rebuilds the tree,
re-reads the salts, and derives a **new session key** bound to the stored
identity with `session_number + 1`. The binding is signed by the identity
key and appended to the journal, so a verifier can later prove every leaf
back to the identity even though each run used a different session key.

**The torn tail.** A process killed between `write` and the newline leaves
a partial last line. Rather than refuse to open (losing the whole file) or
guess (corrupting the tree), `resume` drops the incomplete line, truncates
the file to the last good byte, and tells you how much it dropped. The
invariant it protects: *every line in the journal is a leaf that is also in
the tree.* An append that did not finish never happened, and the Merkle
root agrees.

**The lock.** `create` and `resume` take `agent.jsonl.lock`, which records
the owning PID and a random token. A second process gets
`io::ErrorKind::WouldBlock`-style failure. On Linux the lock is checked
against `/proc`: a lock whose PID is dead is taken over with one log line.
This exists because the worst thing that can happen to a log is two honest
writers forking it; witnesses would then record your identity as having
equivocated, and that is unrecoverable by design.

---

## 3. Checkpoints, dossiers and the first verdict

```rust
use witness_log_network::{Dossier, VerifyContext};

let sth = log.log().checkpoint_self();               // (tree_size, root, now) signed by the identity key
let dossier = Dossier::from_log(log.log(), sth);     // the portable proof
let report = dossier.verify(0.66, &VerifyContext::default());
assert!(report.internally_consistent);
println!("{}", serde_json::to_string_pretty(&dossier).unwrap());
```

**`SignedTreeHead`.** The message that gets signed is
`"witness-log-sth-v2" || lp(sig_alg) || lp(signer_pubkey) || tree_size || root || timestamp_ms`.
Note that the algorithm name and the public key are *inside* the signed
bytes. An earlier draft had them alongside, and that is the textbook
setup for an algorithm-downgrade attack: nothing stops an attacker from
relabelling `sig_alg` after signing. Putting them inside the message closes
it. The `sig_alg` field exists for crypto-agility without a format break;
today the only accepted value is `"ed25519"`, and ML-DSA-44 is planned
with its identifier reserved but not yet assigned (spec §6).

**`Dossier`.** A plain `serde` struct, so it round-trips to JSON and is
checked against `spec/dossier.schema.json` in CI. It carries the identity,
leaves, checkpoint, bindings, revocations, receipts and a display copy of
the directory. It has no reference to any server, which is what makes
verification possible offline, years later, by someone who has never heard
of witness-log's witnesses.

**`VerifyContext::default()`** supplies nothing from outside. The verdict
is therefore `Unanchored`: internally consistent, but every input came from
the file. Read `DossierReport` fields rather than just the verdict when you
want to know *why*: `identity_pinned`, `internally_consistent`,
`bindings_asserted`, `quorum.*`.

---

## 4. Redaction: erase content, keep the proof

```rust
let i = log.append_memory(b"contact: alice@example.com")?;
assert!(log.can_forget(i));
assert!(log.forget(i)?);          // salt removed from agent.jsonl.salts; a Redaction leaf appended
assert!(!log.can_forget(i));
```

The leaf hash is `SHA256(bucket_pad(payload) || salt || index)`. The salt
lives in the `.salts` sidecar, behind the `SaltStore` trait
(`redaction.rs`), never in the tree. `forget` rewrites the sidecar without
that record (erased, not flagged) and appends a type-`0x03` leaf naming the
index. So:

- the forgotten leaf's hash, and every proof that includes it, is unchanged;
- every checkpoint any witness ever cosigned remains a true statement;
- the content is unrecoverable: the salt is 32 random bytes, so there is nothing to dictionary-attack even for a short payload;
- the erasure is itself on the record.

`SaltStore` is a trait so that embedders with their own secret store
(a KMS, a database with its own erasure semantics) can implement it;
`FileSaltStore` is the reference and the one the journal uses.

---

## 5. Proofs for a regulator, without handing over the whole log

```rust
let key = ed25519_dalek::SigningKey::from_bytes(&log.log().identity_bytes());

// Leaves 100..199 only, each with its own inclusion proof against one signed checkpoint.
let window = log.log().evidence_window(100..200, &key);
assert!(window.verify().is_ok());

let proof = log.log().inclusion_proof(42);              // Some(path) if leaf 42 exists, else None
let consistency = log.log().consistency_proof(1_000);   // Some(proof) size 1000 → now; None if 1000 > size
let receipt = log.log().write_receipt(42);              // Some(receipt): "I accepted this payload_hash at size N"
```

`inclusion_proof`, `consistency_proof` and `write_receipt` return `Option`:
`None` means the index or size does not exist in this tree, not an error.
`evidence_window` in 0.3.6 **clamps** a range that runs past the tree
(`100..200` on a 150-leaf log yields 50 entries, silently); 0.4.0 plans to
refuse an out-of-range window instead, so check `window.entries.len()`
against what you asked for until then.

**`EvidenceWindow`** answers the commonest compliance request: "show me
what the agent did between 09:00 and 09:05" without revealing anything
outside that range. Each leaf in the window carries an RFC 6962 inclusion
proof to one checkpoint; the recipient verifies with the identity public
key alone.

**`consistency_proof`** is what a witness demands: a proof that the tree of
size N is a prefix of the tree of size M. It is also what lets an auditor
who saved last month's checkpoint confirm that this month's log did not
rewrite anything from last month.

**`WriteReceipt`** is the answer to censorship-by-omission. A plain
checkpoint commits to no particular event, so it cannot prove an event was
*dropped*. A write receipt binds the identity to one `payload_hash` at one
`tree_size`; if witnessed checkpoints later advance past that size and the
leaf never appears, the receipt plus the checkpoints are evidence anyone
can check (§9.4).

---

## 6. Verify someone else's dossier (the deployment gate)

```rust
use witness_log_network::{Dossier, Verdict, VerifyContext, WitnessDirectory};

let dossier: Dossier = serde_json::from_str(&json)?;
let directory: WitnessDirectory = serde_json::from_str(&dir_json)?;   // YOURS, obtained out-of-band

let report = dossier.verify(0.66, &VerifyContext {
    expected_identity_pubkey: Some(&expected_hex),   // the agent you expected
    trusted_directory: Some(&directory),             // the witnesses you trust
    min_receipts: Some(3),                           // absolute gate; use it with large directories
});
match report.verdict {
    Verdict::Witnessed => {}
    other => return Err(format!("verdict {other:?}").into()),
}
```

**The trust boundary is the `VerifyContext`.** Everything in it must come
from *you*, never from the dossier: the identity you were told to expect,
and the list of witnesses you decided to trust. This is the single design
decision that makes a fabricated dossier top out at `Unanchored` however
many "independent auditors" it ships with. `Verdict::Witnessed` is
reachable only when receipts verify against keys in *your* directory and
at least two distinct `operator_org` values are represented.

**Why both a fraction and `min_receipts`.** The 1,000-agent test runs
showed that a fraction alone (`0.66` of known operators) stops being a
useful gate as directories grow: 2 of 3 is strict, 2 of 60 is not.
`min_receipts` is the absolute floor; `QuorumResult.count_gate` tells you
in words which gate applied.

---

## 7. Run a witness inside your own server

```rust
use witness_log_network::tlog_witness::{AddCheckpointRequest, WitnessService, WitnessState};

// `persisted_state: WitnessState` is what you wrote to disk last time (serde);
// `WitnessService::new().export_state()` for a brand-new witness.
let mut svc = WitnessService::from_state(&persisted_state)?;
// per POST /add-checkpoint, with `body: &str` the request body and
// `signing_key: &ed25519_dalek::SigningKey` the witness key:
let req = AddCheckpointRequest::parse(body)?;
let outcome = svc.handle_add_checkpoint(&req, "witness.example/w1", &signing_key, now_unix_seconds);
persist(&svc.export_state())?;                 // fsync BEFORE replying
let (status, (body, content_type)) = (outcome.http_status(), outcome.http_body());
```

`WitnessService` is the protocol state machine with **no I/O**: it never
opens a socket or a file. You feed it a request, it hands back an outcome
(200 cosignature, 409 with the size it expects, 422 equivocation with
evidence, 4xx bad input) and a new state. The one rule the embedder must
obey: **persist the state before the cosignature leaves the process.** A
witness that cosigns and then crashes before writing has promised something
it will not remember, and on restart it may cosign a contradicting head,
which is equivocation by the witness itself. The reference embedding,
`crates/witness-log-cli/src/witness_cmd.rs`, writes to a temp file, fsyncs,
renames, then replies. See [Running a witness](Running-a-Witness) and
[Witness protocol walkthrough](Witness-Protocol-Walkthrough).

---

## 8. Where to go next

- The byte-level path from `append` to `WITNESSED`: [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof).
- Every normative detail: `spec/SPEC.md`, and the conformance corpus you can test an independent implementation against ([Spec and interop](Spec-and-Interop)).
- `cargo doc --open -p witness-log-core -p witness-log-network` for the full API; rustdoc is built with `-D warnings`, so every public item is documented.
