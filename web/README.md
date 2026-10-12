# Browser verifier

A single static page that verifies a witness-log dossier offline. Drop a
`dossier.json` and, optionally, the `trusted.json` directory you trust; the
page prints the verdict, the exit code the CLI would return, the checkpoint,
every receipt with its status, the leaf table, and the full JSON report.
It also checks a disclosure (payload + salt against a leaf) and binds two
dossiers. Nothing is sent anywhere after the page loads.

Two engines implement the same four calls:

- `pkg/` — the Rust verifier compiled with `wasm-bindgen` (`build.sh`, primary)
- `pkg-go/` — the Go verifier compiled with `GOOS=js GOARCH=wasm` (`build-go.sh`)

The page loads whichever is present, Rust first. Both are built from the
same spec and tested against the same corpus, so a reader who distrusts
one toolchain can rebuild the other.

```sh
sh web/build.sh          # needs wasm32 target + wasm-bindgen-cli 0.2.129
sh web/build-go.sh       # needs Go only
python3 -m http.server -d web 8000
python3 web/test/test_page.py   # Playwright: WITNESSED, tampered -> DIVERGED, bind
```

`.github/workflows/pages.yml` builds both engines and deploys this folder to
GitHub Pages on every push to `main` that touches the verifier.
