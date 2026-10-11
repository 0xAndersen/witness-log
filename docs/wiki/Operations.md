# Operations

## Agent side

**Files.** `agent.jsonl` (identity private key in line 1 + leaves),
`agent.jsonl.salts`, `agent.jsonl.lock`, `agent.jsonl.witnesses.json`.
The first two are key material: 0600, encrypted storage if your threat
model needs it, backed up **together**.

**Identity.** Generate once (`os.urandom(32)` / `IdentityKeypair::generate`),
keep the 32-byte seed in your secrets store, pass it to
`JournaledLog.create` the first time. Lose the seed and the log can still
be verified forever, but nothing new can be signed under that identity:
start a new one and, if the old one leaked, publish a revocation.

**Durability.** Appends are buffered by the OS; `sync()` fsyncs. Call it at
checkpoints you would regret losing (end of a tool call that moved money,
end of a session). Measured: ~115 µs per journaled append, 4–9 ms per sync
on ordinary disks.

**Locks and crashes.** One writer per journal. SIGKILL leaves a lock; on
Linux the next `resume` clears it when the PID is dead; elsewhere call
`force_unlock`. Torn tails are dropped and the file truncated on resume.

**Growth.** One line per leaf (~600 bytes). A million leaves is ~600 MB
and resumes in seconds; the Merkle root is maintained incrementally
(O(log n)); the soak test runs 200k leaves at ~500 B/leaf of memory.
Rotate by starting a new journal per period under the same identity;
dossiers reference the identity, and bindings carry over.

**Witnessing cadence.** Submit after each batch of consequential work;
each submission is one small request per witness with a consistency proof.
Keep `agent.jsonl.witnesses.json` with the journal (it is the guard
against publishing a rolled-back history).

## Witness side

See [Running a witness](Running-a-Witness) and `deploy/witness/OPERATORS.md`:
persist-before-cosign, the backup rule (`witness.key` + `witness.json` +
`logs/` as one object), proxy limits, SIGTERM/SIGKILL behaviour, key rotation
(= new witness), evidence files.

## Verifier side

Keep your directory under version control; pin `--identity` per agent in
config; gate on exit code; archive dossiers with the verify report. Use
`--min-witnesses` against large directories.

## Monitoring

Witness `GET /` exposes `logs`, `cosigned_since_start`,
`proven_equivocations_since_start`, `refused_unproven_since_start`. A
nonzero equivocation counter is an incident for the *log's* operator; the
evidence file under `evidence/` is publishable and self-contained.

## Upgrades

On-disk formats are versioned (journal header, witness state) and
refused, never reinterpreted, if they change. 0.3.x journals, dossiers and
states all load in 0.3.3. Release notes: `CHANGELOG.md`.
