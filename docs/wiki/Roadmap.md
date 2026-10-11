# Roadmap

Ordered by what changes the product's meaning, not by effort.

1. **Independent witnesses in the registry.** Two organisations → WITNESSED
   becomes reachable for anyone. Target: founding operators from the CT /
   transparency community, a university lab, and at least one competing
   agent-infrastructure project.
2. **Framework adapter packages**: `witness-log-langchain`,
   `witness-log-openai-agents`, CrewAI/AutoGen/ADK hooks, a Claude Code
   hook package; each 100 lines on `witness_log.step`, each exercised by
   the swarm.
3. **In-browser verifier** (wasm build of the verifier, GitHub Pages): drop
   a dossier, see the verdict, registry as the default directory.
4. **Native TypeScript (`@witness-log/core`, napi-rs) and Go bindings** on
   the same Rust core.
5. **Independent security review** of core + network + witness, and a
   C2SP interop test against a public CT-ecosystem witness.
6. **Write receipts and silence proofs in the CLI** (`silence_proof` exists
   in the library): prove an event was accepted and later omitted.
7. **Anchoring helpers** for ExternalAnchor leaves (Sigstore Rekor, RFC 3161).
8. **1.0**: wire format frozen, spec at 1.0, two independent implementations
   passing the corpus.

Track progress in Discussions and the CHANGELOG.
