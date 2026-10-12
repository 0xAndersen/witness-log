# Roadmap

Ordered by what changes the product's meaning, not by effort.

1. **Independent witnesses in the registry.** Two organisations → WITNESSED
   becomes reachable for anyone. Target: founding operators from the CT /
   transparency community, a university lab, and at least one competing
   agent-infrastructure project.
2. **Framework adapters**: LangChain, OpenAI Agents SDK and CrewAI ship as
   extras since 0.3.6 (`pip install "witness-log[langchain]"`). Next:
   AutoGen, Google ADK, LlamaIndex and a Claude Code hook package, each
   with a test that runs the framework's own loop.
3. **In-browser verifier** (wasm build of the verifier, GitHub Pages): drop
   a dossier, see the verdict, registry as the default directory.
4. **Native TypeScript (`@witness-log/core`, napi-rs) and Go bindings** on
   the same Rust core. (`@witness-log/client`, a typed wrapper over the CLI
   and MCP server, exists in `clients/typescript`.)
5. **Independent security review** of core + network + witness (scoped
   brief: `docs/SECURITY-AUDIT-BRIEF.md`), and a
   C2SP interop test against a public CT-ecosystem witness.
6. **Write receipts and silence proofs in the CLI** (`silence_proof` exists
   in the library): prove an event was accepted and later omitted.
7. **Anchoring helpers** for ExternalAnchor leaves (Sigstore Rekor, RFC 3161).
8. **1.0**: wire format frozen, spec at 1.0, two independent implementations
   passing the corpus.

Track progress in Discussions and the CHANGELOG.
