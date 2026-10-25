# FAQ

**Is this a blockchain?** No. It is a Merkle transparency log (the
Certificate Transparency construction) with signatures and independent
witnesses. No consensus, no tokens, no fees; microseconds per entry, local.

**Do I have to run witnesses to use it?** No. Without witnesses you get a
signed, tamper-evident, offline-verifiable record (UNANCHORED). Witnesses
add the guarantee that the operator cannot show different histories to
different people (WITNESSED).

**Why does WITNESSED need two operators?** One operator cannot contradict
itself; equivocation is only detectable once two parties who share no
operator have both committed to the same head. Ten witnesses you run are
one operator.

**Where do the payloads go?** Wherever you keep them. The log commits to a
salted hash; you store or discard the content as your policy requires.

**Can an entry be deleted?** Its content can (erase the salt); its
existence cannot (the hash and a redaction marker remain). That is the
property GDPR erasure and audit integrity both need.

**What happens when the agent restarts?** A new session key, bound to the
same identity by a signed statement; the dossier carries every binding;
verification is unaffected. Crashes heal on resume.

**How big is a dossier?** ~600 bytes per leaf plus receipts. Use
`evidence_window` to export a slice with per-leaf proofs.

**Does it work with my framework?** If it has a tool hook, yes:
[Framework guides](Framework-Guides). If it speaks MCP, with zero code:
[MCP integration](MCP-Integration).

**TypeScript?** Via MCP or the CLI today; native bindings are on the
roadmap. [Other languages](Other-Languages).

**Can an attacker who steals the identity key forge history?** Going
forward, yes, until you revoke it; the past is protected by witness
cosignatures (a rewritten past would fail consistency at every witness).
Disclose key custody; keep the seed in a secrets store.

**Why Apache-2.0?** So the client library can go into any agent process,
including at organisations whose legal review does not admit copyleft
in-process (releases through 0.3.4 were AGPL-3.0). Openness of the
*network* comes from the protocol, not the license: the format is specified
with a conformance corpus and the witness protocol is public C2SP, so
anyone can run a witness or verifier. The name stays with the project.

**Who runs the witnesses today?** The registry starts empty; the project's
own witnesses are labelled `is_project_operated` and count as one bucket.
The first two independent operators are the network's first milestone.
Run one: [Running a witness](Running-a-Witness), or one click on Render
or Fly.io ([Operator onboarding](Operator-Onboarding#deploy-in-one-click)).

**How fast is it?** ~80 µs per decorated call in memory, ~115 µs journaled;
40k-leaf sync 28 ms; checkpoint 0.4 ms at 40k leaves; witness cosign p50
~100 ms under 128 concurrent agents on a two-core box.
