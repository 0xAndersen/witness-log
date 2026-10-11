# witness-log wiki

**Witnessed, not trusted.** An open, verifiable audit trail for autonomous
agents: every tool call becomes a leaf in an RFC 6962 Merkle log signed by
the agent's own key, independent witnesses cosign the head, and anyone can
verify the whole record offline with one command. AGPL-3.0, Rust core,
Python bindings, MCP server, CLI.

| I want to… | Read |
|---|---|
| understand what this is and why it exists | [Why witness-log](Why-witness-log) · [Concepts](Concepts) |
| add it to a Python agent in three lines | [Quickstart: Python](Quickstart-Python) |
| use it from Rust | [Quickstart: Rust](Quickstart-Rust) |
| use it from the terminal or any language | [Quickstart: CLI](Quickstart-CLI) |
| give Claude Code / Claude Desktop / Cursor / any MCP host an audit trail with zero code | [MCP integration](MCP-Integration) |
| wire it into LangChain, LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, Google ADK, LlamaIndex | [Framework guides](Framework-Guides) |
| use it from TypeScript / Node / Go / anything else | [Other languages](Other-Languages) |
| know what WITNESSED actually proves, and read a verify report | [Verification and verdicts](Verification-and-Verdicts) |
| run a witness (one, a fleet, or let an agent do it) | [Running a witness](Running-a-Witness) |
| get my logs WITNESSED | [Getting witnessed](Getting-Witnessed) |
| use it for GDPR / SOC 2 / EU AI Act / audit evidence | [Compliance](Compliance) |
| know what it does *not* protect against | [Threat model](Threat-Model) |
| implement the wire format in another language | [Specification and interoperability](Spec-and-Interop) |
| operate it in production (backups, keys, locks, scale) | [Operations](Operations) |
| see the numbers (268 tests, 100 scenarios, 3,000 agents) | [Testing and evidence](Testing-and-Evidence) |
| answers to common questions | [FAQ](FAQ) |
| contribute, or see where it is going | [Contributing](Contributing) · [Roadmap](Roadmap) |

Repository: https://github.com/0xAndersen/witness-log · Releases: https://github.com/0xAndersen/witness-log/releases · Spec: `spec/SPEC.md`
