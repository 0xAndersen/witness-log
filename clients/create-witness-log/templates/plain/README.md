# witness-log agent (plain template)

An agent whose tool calls are recorded in a [witness-log](https://github.com/0xAndersen/witness-log):
an append-only Merkle log signed by the agent's identity key, erasable per
entry, verifiable offline, and cosignable by independent witnesses.

```sh
npm install
npm start          # appends a few steps to agent.jsonl, writes dossier.json, verifies it
npm test
npm run verify     # node src/verify.mjs dossier.json
```

## What is where

- `agent.jsonl` is the journal (the identity key is in its header, mode 0600),
  `agent.jsonl.salts` the redaction salts, `agent.jsonl.payloads` the plaintext
  payloads (because `storePayloads: true`). Back the three up together; none
  of them belongs in version control.
- `dossier.json` is what you hand to anyone who wants to check the record.
  `UNANCHORED` means it is internally consistent; witnesses are what turn it
  into `WITNESSED`.

## Getting witnessed

Witnesses are independent servers that cosign your checkpoints and refuse a
history that does not extend what they already signed. You need a directory
of witnesses you trust (`{"witnesses": [...]}`); the project's registry is
at `registry/` in the repository, and you can run your own for development:

```sh
cargo install witness-log-cli            # or a release binary; the Docker image ghcr.io/0xandersen/witness-log also serves
witness-log testnet up                   # CLI 0.4.0+: two local witnesses (two "organisations") and a directory file
```

On an earlier CLI start them by hand (each `witness init` prints a directory
entry; a directory is `{"witnesses": [entry, entry]}`):

```sh
witness-log witness init ./w1 --name w1.local/witness --org "Org One" --url http://127.0.0.1:7381 > w1.json
witness-log witness init ./w2 --name w2.local/witness --org "Org Two" --url http://127.0.0.1:7382 > w2.json
witness-log witness serve ./w1 --listen 127.0.0.1:7381 --open-enrollment &
witness-log witness serve ./w2 --listen 127.0.0.1:7382 --open-enrollment &
jq -s '{witnesses: .}' w1.json w2.json > trusted.json
```

Then, in the agent:

```js
const r = await log.submit("trusted.json", { min: 2 });
if (r.ok) writeFileSync("dossier.json", JSON.stringify(r.dossier));
```

and verify with the same directory: `node src/verify.mjs dossier.json --directory trusted.json --min 2`.
