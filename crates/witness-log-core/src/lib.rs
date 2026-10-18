//! witness-log-core: the cryptographic engine behind WitnessLog audit logs.
//!
//! This crate implements only the parts of the system that must be
//! byte-for-byte identical across independent implementations to
//! interoperate: leaf encoding, Merkle construction, checkpoint signing,
//! identity binding, salted redaction, and C2SP transparency-log
//! interoperability. See `/spec/SPEC.md` for the normative wire format
//! this code implements, and `/corpus/` for the conformance test vectors
//! any reimplementation should reproduce exactly.
//!
//! What this crate deliberately does NOT decide: transport, storage engine,
//! witness selection policy. Those are left to `witness-log-network` and to the
//! integrating application.
//!
//! # Integration contract
//!
//! This library is designed to sit inside someone else's agent, on their
//! hot path, and be invisible. It commits to the following, and each
//! point is enforced or tested rather than merely intended:
//!
//! - **It will not panic on explicit panic paths.** `unwrap`, `expect`,
//!   `panic!`, `todo!`, and `unimplemented!` are denied at compile time
//!   in this crate's non-test code, and library code contains none of
//!   them. Errors are returned, never thrown. A logging library that can
//!   abort its host process is not usable as infrastructure, and a panic
//!   in Rust library code bypasses the PyO3 boundary that would
//!   otherwise convert it into a catchable Python exception.
//!   Slice indexing is gated too: every indexing site in library code
//!   is a checked slice pattern or `get`, so out-of-bounds access is a
//!   compile-time impossibility.
//!   *Known gap:* arithmetic overflow is NOT yet gated — see the lint
//!   block below, which documents exactly what is and isn't proven.
//! - **`append` does not touch the disk or the network.** It is O(1)
//!   amortized: a salted hash, a leaf encoding, and a Merkle spine
//!   update. Durability is explicit and caller-scheduled — see
//!   [`journal::LeafJournal::sync`]. Nothing here blocks on I/O unless
//!   you asked it to.
//! - **`checkpoint` is O(log n), not O(n).** The Merkle tree maintains an
//!   incremental right spine, so `root()` on a million-leaf tree costs
//!   well under a microsecond rather than rehashing the tree. See
//!   [`merkle::MerkleTree`].
//! - **No ambient state.** No global allocator hooks, no background
//!   threads, no signal handlers, no environment reads at runtime.
//!
//! # What this crate does NOT promise
//!
//! - **Bounded memory.** Every leaf is retained in process memory so
//!   inclusion and consistency proofs can be produced on demand.
//!
//!   **Measured: ~500 bytes of resident memory per leaf**, stable and
//!   linear from 25k to 200k leaves (see
//!   `witness-log-network/tests/sybil_and_soak.rs`, which asserts both
//!   the figure and its linearity). Budget roughly **500 MB per million
//!   leaves**, inside your process.
//!
//!   An earlier version of this document said "~200 bytes per leaf",
//!   reasoning from the two 64-character hex strings each `Leaf`
//!   carries. That was a 2.5x under-estimate: it ignored `String`
//!   headers, the `Option` fields, `Vec` capacity slack, and allocator
//!   overhead. Anyone sizing a deployment from the old figure would have
//!   under-provisioned by more than half. The number above is measured,
//!   not derived, and there is a test that fails if it drifts by an
//!   order of magnitude.
//!
//!   For long-lived logs use [`journal::JournaledLog`], which streams
//!   every append to disk, and checkpoint-then-restart rather than
//!   growing without bound. A bounded mode retaining only the Merkle
//!   spine is planned but not implemented.
//! - **Arithmetic overflow safety.** See the lint block below.
//!
//! # Concurrency
//!
//! `WitnessLog` is `Send` but deliberately not `Sync`. A log has
//! single-writer semantics — two threads appending concurrently would
//! race on the leaf index and the Merkle spine — so the type system
//! refuses `Arc<WitnessLog>` on its own. Share one log across threads
//! with `Arc<Mutex<WitnessLog>>`; if you hit a compile error about
//! `Sync`, that is the intended fix, not a missing feature.
//!
//! A `JournaledLog` additionally holds an exclusive lock on its journal
//! file, so a second *process* opening the same journal fails cleanly
//! with `AlreadyExists` rather than interleaving writes.
//!
//! # Session numbers
//!
//! `WitnessLog::resume(identity, session_number)` trusts the number you
//! pass. Nothing enforces that it increases, and two sessions can share
//! one — verification still works, since each session has a distinct key
//! and a distinct signed binding, but `session_number` stops being a
//! reliable "which restart was this" signal. `JournaledLog` and
//! `load_snapshot` manage it for you; manage it yourself only if you call
//! `resume` directly.
//!
//! # Async callers
//!
//! Nothing in this crate is `async`, and nothing needs to be: `append`,
//! `checkpoint`, and `root` are pure CPU and complete in microseconds,
//! so calling them directly from an async task is correct and cheap.
//!
//! The one call that blocks is [`journal::LeafJournal::sync`], which
//! fsyncs. An fsync can take milliseconds and will stall the executor
//! thread it runs on. Call it from `tokio::task::spawn_blocking` (or
//! your runtime's equivalent):
//!
//! ```ignore
//! // append is cheap and never touches disk -- call it inline
//! log.append_intent(payload)?;
//!
//! // sync blocks on fsync -- move it off the async executor
//! let log = tokio::task::spawn_blocking(move || {
//!     log.sync()?;
//!     Ok::<_, std::io::Error>(log)
//! }).await??;
//! ```
//!
//! Durability cadence is deliberately yours to choose: sync every leaf
//! for maximum durability at the cost of an fsync per append, or once
//! per checkpoint, or on a timer. This crate imposes no policy.

// The no-panic contract above, enforced by the compiler rather than by
// discipline. These are `deny` rather than `warn` so a violation fails
// the build, not just CI's linting job. Test code is exempt (`test`
// cfg), where panicking IS the assertion mechanism.
//
// VERIFIED: library (non-test) code in this crate contains no `unwrap`,
// `expect`, `panic!`, `todo!`, or `unimplemented!` — checked
// exhaustively, module by module, excluding `#[cfg(test)]` blocks — and
// no slice indexing. Every former indexing site was converted to a slice
// pattern or a checked `get`, so out-of-bounds access is a compile-time
// impossibility rather than a runtime risk.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::todo))]
#![cfg_attr(not(test), deny(clippy::unimplemented))]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
//
// NOT YET ENABLED, deliberately: `clippy::arithmetic_side_effects` would
// still fail this crate. Unchecked arithmetic is pervasive in index and
// tree-size computation, and overflow panics in debug builds while
// silently wrapping in release — the second being the more dangerous for
// a hash-tree index. Converting every site to `checked_*` is contained
// but genuinely invasive work that has not been done or audited here.
//
// It is listed rather than silently omitted because the gap is the
// point: the no-panic claim above is proven for panic macros and slice
// indexing, and NOT for arithmetic overflow. Enabling the lint before
// doing that work would fail the build and teach whoever hits it to
// delete the lint.
//
// #![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub mod c2sp;
pub mod errors;
pub mod identity;
pub mod journal;
pub mod leaf;
pub mod log;
pub mod merkle;
#[doc(hidden)]
pub mod object_only;
pub mod redaction;
pub mod sth;

pub use errors::WitnessLogError;
pub use identity::{
    IdentityKeypair, KeyBindingStatement, KeyCustody, RevocationStatement, SessionKeypair,
};
pub use leaf::{
    verify_authorization_binding, verify_handoff_binding, AuthorizationEventKind, HandoffDirection,
    Leaf, LeafType,
};
pub use log::{VerifyError, WitnessLog};
pub use merkle::{verify_consistency, verify_inclusion, Hash, MerkleTree};
pub use redaction::{SaltManager, SaltStore};
pub use sth::SignedTreeHead;
