# Show HN draft

Draft only; not posted. Every number and claim below traces to a file in
the repository (listed at the end).

## Title

Show HN: Witness-log – an audit trail for AI agents that survives its operator

## URL

https://github.com/0xAndersen/witness-log

## First comment

witness-log is a per-agent RFC 6962 Merkle log. Every tool call becomes two
leaves, an intent before and a result after; the agent's identity key signs
checkpoints over the tree; independent witnesses cosign each head over
c2sp.org/tlog-witness, the Certificate Transparency witness protocol. Anyone
verifies a dossier offline with one command, and the exit code is the
verdict (0 WITNESSED, 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30
DIVERGED). Any entry can be erased by deleting its salt without breaking a
proof. Apache-2.0, Rust core, Python bindings, MCP server.

The experiment that matters: an independent evaluation had an operator
rewrite its agent's entire history and re-sign it with the agent's own key.
It reported that Signet, agent-receipts and Microsoft's Agent Governance
Toolkit accepted the rewritten log as valid, which is what their own docs
say happens without an external anchor. witness-log's witnesses refused the
rewritten head with HTTP 422 and each wrote a ~1 KB file proving the key
signed two different roots for one size. To reproduce on localhost:
`python3 examples/rewrite-attack/run.py` (two witnesses, the 422s, the
evidence verified, `diff` flagging equivocation; under a second).

What is proven: once two witnesses from different organisations have
cosigned size N, the operator cannot get a different size-N history past
them, and trying leaves portable evidence.

What is not, yet: the public registry of independent witness operators is
empty, so today WITNESSED means "witnesses you chose", possibly your own.
Split-view resistance needs a majority gate (the default 0.66 is one; 0.5
is not). ExternalAnchor proofs are recorded and hash-bound but not fetched or
checked against the provider. Leaves are not individually signed; the
identity-signed checkpoint over the tree is what carries the weight. The
salted-hash privacy scheme has had no external cryptographic review.

Try it: `pip install witness-log`, then a release binary or
`cargo install witness-log-cli`, then `witness-log demo` and
`witness-log demo --tamper`. No files, no network.

The ask: run a witness. It is one binary, about 200 bytes of state per log,
and `deploy/witness/AGENT_OPERATOR.md` is a playbook a coding agent can
execute on a free always-on VM. Two outside organisations in `registry/` is
the milestone that makes WITNESSED mean something.

## Counts

First comment: 354 words (target 250–400). Title: 78 characters (limit 80).
Recount after any edit:

```sh
python3 -c "t=open('docs/launch/show-hn.md').read(); print(len(t.split('## First comment')[1].split('## Counts')[0].split()))"
```

## Sources for every claim

- Construction, verdicts, exit codes, erasure: `README.md`, `spec/SPEC.md` §2–§9.2
- Evaluation result and the six fixed defects: `CHANGELOG.md` 0.3.4, `README.md` "Evidence"
- Other projects' documented behaviour: `docs/wiki/Comparison-Signet.md`, `Comparison-agent-receipts.md`, `Comparison-Microsoft-AGT.md`
- The repro and its real output: `examples/rewrite-attack/README.md` (evidence file was 980 bytes; run took 0.4 s)
- Limits: `THREAT_MODEL.md` (witness independence, split views), `CHANGELOG.md` 0.3.4 (anchors), `spec/SPEC.md` §5 and §10 (leaf signatures), `THREAT_MODEL.md` (low-entropy correlation, no external review)
- Witness memory "about 200 bytes per log": `docs/wiki/Witness-Protocol-Walkthrough.md`
- Empty registry: `README.md` "Run a witness", `registry/`
