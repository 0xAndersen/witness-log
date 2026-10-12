# Roadmap

Ordered by what changes the product's meaning, not by effort.

1. **Independent witnesses in the registry.** Two organisations make
   WITNESSED reachable for anyone. The project's own fleet
   (`deploy-fleet` workflow) gives capacity; independence has to come from
   outside operators: the CT / transparency community, a university lab,
   a competing agent-infrastructure project.
2. **RFCs 1–4** (`docs/rfcs/`): a fleet checkpoint log, verdict strictness
   and an INVALID verdict, DNS-TXT self-registration, SCITT receipts. Each
   lands behind a flag with corpus vectors before the spec changes.
3. **Independent security review** of core, network and the witness
   (`docs/SECURITY-AUDIT-BRIEF.md`), and a C2SP interop test against a
   public CT-ecosystem witness.
4. **ML-DSA-44** as a second signature algorithm (identifier reserved in
   the spec, unassigned until the vectors exist).
5. **Write receipts and silence proofs in the CLI** (`silence_proof`
   exists in the library): prove an event was accepted and later omitted.
6. **Anchoring helpers** for ExternalAnchor leaves (Sigstore Rekor, RFC 3161).
7. **1.0**: wire format frozen, spec at 1.0, three independent
   implementations passing the corpus (Rust, TypeScript and Go verifiers
   agree today).

Shipped since the last revision of this page (0.4.0): framework adapters
for OpenAI Agents, LangChain, LangGraph, Google ADK, pydantic-ai, AutoGen,
LlamaIndex and CrewAI with a nightly live-framework run; the MCP proxy and
Claude Code hook; `@witness-log/node`, `@witness-log/ai-sdk`,
`create-witness-log`; the Go verifier; the browser verifier on GitHub
Pages; the CLI no-code path (`testnet`, `log`, `journal serve`,
`directory`); disclosure and `submit` in Python; commerce profiles.

Track progress in Discussions and the CHANGELOG.
