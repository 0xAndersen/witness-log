# Founding operators: the ask, and three emails

witness-log's verdict WITNESSED needs two witnesses run by two
organisations other than the one whose agent is being checked. The code
will not let the project fake that: every project-run witness counts as a
single bucket, and a log's own operator never counts. So the network
starts when two real organisations each run one small service. This page
is what to send them. Post and send from the maintainer's own account,
not from automation; fill in the bracketed parts.

## The one-page ask

**What:** run one witness, a ~4 MB service that cosigns AI agents'
audit-log checkpoints after checking that each new one extends the last
one it signed. It speaks `c2sp.org/tlog-witness`, the protocol
Certificate Transparency witnesses already use.

**Why it matters:** an agent's operator holds the agent's signing key and
can rewrite its whole history with valid signatures. A witness that has
cosigned the old history refuses the rewrite and keeps a file proving it.
Two witnesses from two organisations are the difference between "the
operator says so" and "two parties who don't share an operator saw this
history first".

**What it costs:**
- a small always-on VM with a persistent disk: free on Google Cloud's
  e2-micro tier, about €6 a month on Hetzner, or a machine you have; or
  no VM at all: one click on Render (about USD 7.25 a month) or a few
  commands on Fly.io (about USD 2.35 a month), prices as checked in
  October 2026;
- about two minutes to start by hand, three to five minutes with the
  cloud-init file and no terminal, a few minutes of build after the
  Render button or `fly deploy`, or one sentence to a coding agent
  ("follow deploy/witness/AGENT_OPERATOR.md");
- no uptime commitment and no on-call. A witness that is down simply
  does not cosign.

**What it sees:** for each checkpoint, an origin
(`witness-log/<agent public key>`), a tree size, a root hash and a
consistency proof made of hashes. Never a payload, a prompt, a tool
argument or any customer data.

**What you promise:**
1. Keep the key, its config and its `logs/` directory together (back
   them up as one object). The software then never lets the key cosign
   two histories of one log.
2. Label the witness with your real organisation name.
3. Keep it up for seven days after registering, so it is listed as a
   founding operator.

**What you get:** your organisation listed as a founding operator in
`GOVERNANCE.md`, your witness in the public registry that verifiers
build their trust from, and your name on every verification that counts
your cosignature.

Start here: [Operator onboarding](https://github.com/0xAndersen/witness-log/wiki/Operator-Onboarding).
The three-organisation pilot, if you also want to log your own agents:
[Pilot: three organisations](https://github.com/0xAndersen/witness-log/wiki/Pilot-Three-Organisations).

## Email 1: an organisation that already runs always-on infrastructure

For node, validator or RPC operators, staking providers, exchange and
wallet infrastructure teams, security firms, university labs.

> Subject: Run one witness for an open agent-audit network? (~2 minutes, no data access)
>
> Hi [first name],
>
> I maintain witness-log, an open-source (Apache-2.0) audit log for AI
> agents: every tool call is a leaf in a per-agent Merkle log, and
> independent witnesses cosign each checkpoint so an operator cannot
> quietly rewrite history later. It uses the same witness protocol as
> Certificate Transparency.
>
> The verdict that matters needs two witnesses run by two different
> organisations, and the code won't let me count my own. I'm looking for
> the first two founding operators, and [org] came to mind because you
> already run always-on signing infrastructure.
>
> The ask: one small VM (free tier works) or one click on Render or
> Fly.io, about two minutes to start, no uptime commitment. The witness
> sees hashes only, never agent data.
> Your organisation would be listed as a founding operator.
>
> One-page summary: [link to this page]. Happy to do a 15-minute call or
> pair on the setup.
>
> Thanks,
> [name]

## Email 2: a pilot partner that also wants its agents logged

For a counterparty, customer or vendor whose agents act on your behalf
(or yours on theirs), where both sides want a record neither can rewrite.

> Subject: A shared audit trail for [the workflow] that neither of us can rewrite
>
> Hi [first name],
>
> Our agents and yours now [describe the joint workflow]. If something
> goes wrong, each side has its own logs and each could edit them. I'd
> like to try witness-log, an open-source audit log where every agent
> action is a leaf in a Merkle log and independent witnesses cosign each
> checkpoint, so a rewritten history is refused and provable.
>
> The pilot is three organisations, one small witness each ([org], us,
> and [third party, e.g. our auditor]). Each side's agent logs are
> cosigned by the other two, and each side verifies the other's with one
> command. Setup is about two minutes per witness, the witnesses see
> hashes only, and the whole thing runs on localhost first:
> `python3 examples/pilot-triangle/run.py`.
>
> Runbook: [link to Pilot-Three-Organisations]. Could we spend 30 minutes
> on it next week?
>
> Thanks,
> [name]

## Email 3: an operator of an existing transparency-log witness

For people who already run a `c2sp.org/tlog-witness` witness (OmniWitness,
litewitness, Sigsum, witness-network.org participants). They are the most
qualified operators anywhere; the honest framing is that their existing
witness enrolls logs one origin at a time, and witness-log origins are
per agent.

> Subject: witness-log: AI-agent logs over tlog-witness, would you run an open-enrollment witness beside yours?
>
> Hi [first name],
>
> witness-log is an Apache-2.0 per-agent transparency log for AI agents.
> Its checkpoints are ordinary c2sp.org/tlog-checkpoint notes with origin
> `witness-log/<agent ed25519 key>`, and its cosignatures are
> cosignature/v1; our CI checks both with x/mod's note package and
> transparency-dev/formats.
>
> Because every agent is its own origin, enrolling them in an existing
> witness one by one doesn't scale, so two asks, either of which helps:
>
> 1. Run witness-log's witness beside yours with open enrollment (the
>    origin names its own key, so no per-log configuration). It is a
>    ~4 MB binary; operator notes: [link to deploy/witness/OPERATORS.md].
> 2. Tell us whether you would enroll one log per organisation whose
>    entries are its agents' checkpoints. That design is RFC-0001
>    ([link]). An experimental prototype ships in 0.6.0 (`witness-log
>    fleet`), and an unmodified witness cosigns it after one `add-log`;
>    your answer decides whether it becomes part of the spec.
>
> Either way, corrections to how we use the protocol are very welcome.
>
> Thanks,
> [name]

## After someone says yes

1. Send them [Operator onboarding](https://github.com/0xAndersen/witness-log/wiki/Operator-Onboarding)
   and offer to pair.
2. When `https://<their witness>/health` answers, run Actions →
   *register-witness* with their URL, or merge their registry pull
   request (CI checks the live key and the organisation name).
3. After seven days on the
   [status page](https://github.com/0xAndersen/witness-log/blob/status/STATUS.md),
   add them to the founding-operators table in `GOVERNANCE.md`.
4. Comment on [issue #1](https://github.com/0xAndersen/witness-log/issues/1)
   so the next operator sees momentum.
