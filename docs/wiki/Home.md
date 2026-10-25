# witness-log wiki

**Witnessed, not trusted.** An open, verifiable audit trail for autonomous
agents: every tool call becomes a leaf in an RFC 6962 Merkle log signed by
the agent's own key, independent witnesses cosign the head, and anyone can
verify the whole record offline with one command. Apache-2.0, Rust core,
Python bindings, MCP server, CLI.

| I want to… | Read |
|---|---|
| understand what this is and why it exists | [Why witness-log](Why-witness-log) · [Concepts](Concepts) · [Comparison](Comparison) |
| understand how it is built and what makes it different | [Architecture](Architecture) · [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof) |
| add it to a Python agent in three lines | [Quickstart: Python](Quickstart-Python) |
| add it to a Node.js or Vercel AI SDK agent, no Rust toolchain | [Quickstart: TypeScript](Quickstart-TypeScript) |
| use it from Rust | [Quickstart: Rust](Quickstart-Rust) |
| use it from the terminal or any language | [Quickstart: CLI](Quickstart-CLI) |
| give Claude Code / Claude Desktop / Cursor / any MCP host an audit trail with zero code | [MCP integration](MCP-Integration) |
| audit an MCP server you already run, or record a coding agent's tool calls from its hooks | [MCP proxy](MCP-Proxy) · [Hooks](Hooks) |
| wire it into LangChain, LangGraph, OpenAI Agents SDK, Claude Agent SDK, CrewAI, AutoGen, Google ADK, LlamaIndex | [Framework guides](Framework-Guides) |
| verify from Go | [Quickstart: Go](Quickstart-Go) |
| verify in a browser, nothing installed | [Browser verifier](Browser-Verifier) |
| use it from Java / anything else | [Other languages](Other-Languages) |
| follow a complete worked example | [Tutorial: audit a payments agent](Tutorial-Audit-a-Payments-Agent) · [Tutorial: multi-agent handoff](Tutorial-Multi-Agent-Handoff) · [Tutorial: AP2 mandates](Tutorial-AP2-Mandates) |
| know what WITNESSED actually proves, and read a verify report | [Verification and verdicts](Verification-and-Verdicts) |
| gate a GitHub workflow on a verdict | [GitHub Action](GitHub-Action) (`uses: 0xAndersen/witness-log@v0.6.1`) |
| understand the witness protocol on the wire (200/409/422) | [Witness protocol walkthrough](Witness-Protocol-Walkthrough) |
| understand erasure, keys and sessions in depth | [Redaction explained](Redaction-Explained) · [Keys and identity](Keys-and-Identity) |
| run a witness in two minutes (one click on Render or Fly.io, docker one-liner, cloud-init paste, binary) | [Operator onboarding](Operator-Onboarding) · [Running a witness](Running-a-Witness) · [live status](https://github.com/0xAndersen/witness-log/blob/status/STATUS.md) |
| get my logs WITNESSED | [Getting witnessed](Getting-Witnessed) · [Pilot: three organisations, one witness each](Pilot-Three-Organisations) |
| use it for GDPR / SOC 2 / EU AI Act / audit evidence | [Compliance](Compliance) |
| know what it does *not* protect against | [Threat model](Threat-Model) |
| implement the wire format in another language, or map it to SCITT | [Specification and interoperability](Spec-and-Interop) · [SCITT mapping](SCITT-Mapping) |
| operate it in production (backups, keys, locks, scale) | [Operations](Operations) |
| see the numbers (268 tests, 100 scenarios, 3,000 agents) | [Testing and evidence](Testing-and-Evidence) |
| fix something that is not working | `witness-log doctor` first, then [Troubleshooting](Troubleshooting) |
| look up a term | [Glossary](Glossary) |
| answers to common questions | [FAQ](FAQ) |
| contribute, or see where it is going | [Contributing](Contributing) · [Roadmap](Roadmap) |

Repository: https://github.com/0xAndersen/witness-log · Releases: https://github.com/0xAndersen/witness-log/releases · Spec: `spec/SPEC.md`
