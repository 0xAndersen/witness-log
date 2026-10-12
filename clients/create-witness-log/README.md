# create-witness-log

```sh
npm create witness-log my-agent                          # plain template
npm create witness-log my-agent -- --template ai-sdk     # Vercel AI SDK template
cd my-agent && npm install && npm start && npm test
```

Generates a minimal Node.js project that appends to a
[witness-log](https://github.com/0xAndersen/witness-log), exports a
dossier and verifies it offline with both the pure-TypeScript verifier and
the Rust reference verifier. No Rust toolchain, no Python, no API key.

Templates:

- `plain`: an agent loop using `@witness-log/node` directly (`log.step`
  around two pretend tools, one of which fails), `src/verify.mjs` as a
  small verifier CLI whose exit code is the verdict, and a `node:test`
  suite that also checks tampering is caught and erasure keeps proofs.
- `ai-sdk`: the same with the Vercel AI SDK, `witnessTools()` around a
  tool, run against `MockLanguageModelV2` so it works without a provider
  key; swap in a real model when ready.

Options: `--template <plain|ai-sdk>`, `--install` (run `npm install`),
`--local <dir>` (use the packages from a checkout of `clients/`, for
development). The generated README explains how to get the record
cosigned by witnesses.

## Tests

`npm test` generates both templates into a temp directory with `--local`,
installs them, runs their test suites, `npm start` and `npm run verify`,
and checks the dossier verifies and the journal resumes. It needs
`clients/node` built first (`npm run build` there).

## License

Apache-2.0.
