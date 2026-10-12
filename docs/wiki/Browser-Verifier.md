# Browser verifier

`web/` is a static page that verifies a dossier without installing anything:
drop `dossier.json` and the `trusted.json` you trust, read the verdict. It
runs the Rust verifier compiled to WebAssembly (and, as a cross-check, the
Go verifier compiled the same way). After the page loads, no network
request is made; your dossier never leaves the browser tab.

It is deployed to GitHub Pages from `main` by `.github/workflows/pages.yml`
(the URL appears on the repository page once the first deploy has run), or
run it locally:

```sh
sh web/build-go.sh                   # Go toolchain only
python3 -m http.server -d web 8000   # open http://localhost:8000
```

What the page shows:

- the verdict and the exit code `witness-log verify` would return, with
  what that verdict does and does not prove
- the checkpoint (tree size, root, signer) and every receipt with its status
  and operator, so you can see whether the two-operator rule was met
- the leaf table (type, timestamp, payload hash, redactions, handoffs,
  authorization events, anchors)
- the full JSON report, identical to `witness-log verify --json`
- a disclosure check: paste a payload and salt for one leaf, see whether
  they reproduce its `payload_hash` (SPEC §8)
- bind: drop a second dossier to check a handoff or authorization binding

The same inputs give the same verdict in the CLI, the Python package, the
Node package, the Go module and this page; the corpus in `corpus/` is what
keeps them in agreement.
