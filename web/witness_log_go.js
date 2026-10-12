// ES-module wrapper giving the Go build the same surface as the
// wasm-bindgen output: default() loads, then the four functions return
// parsed objects and throw on {"error": ...}.
let ready = null;

export default async function init() {
  if (ready) return ready;
  ready = (async () => {
    await import("./wasm_exec.js");
    const go = new globalThis.Go();
    const url = new URL("./witness_log_go.wasm", import.meta.url);
    const { instance } = await WebAssembly.instantiateStreaming(fetch(url), go.importObject);
    go.run(instance); // main() parks in select {}; the API is on globalThis.__witnesslog
    for (let i = 0; i < 200 && !globalThis.__witnesslog; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    if (!globalThis.__witnesslog) throw new Error("Go verifier did not start");
  })();
  return ready;
}

function unwrap(raw) {
  const v = JSON.parse(raw);
  if (v && typeof v === "object" && "error" in v && Object.keys(v).length === 1) {
    throw new Error(v.error);
  }
  return v;
}

const api = () => globalThis.__witnesslog;
export const verify_dossier = (json, directory) => unwrap(api().verify_dossier(json, directory ?? null));
export const verify_dossier_with_options = (json, directory, options) =>
  unwrap(api().verify_dossier_with_options(json, directory ?? null, options));
export const verify_disclosure = (leaf, payload, saltHex) => unwrap(api().verify_disclosure(leaf, payload, saltHex));
export const bind = (a, b) => unwrap(api().bind(a, b));
export const version = () => api().version();
