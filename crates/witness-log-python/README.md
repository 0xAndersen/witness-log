# witness-log (Python)

Python bindings for `witness-log-core`, built with PyO3/maturin. Same wire
format as the Rust crate and the same guarantees — see the root
`README.md` and `THREAT_MODEL.md` before using this for anything real.

## Install

```bash
pip install witness-log
```

(Not yet published to PyPI — build locally with `maturin build --release`
from this directory and `pip install target/wheels/*.whl` until it is.)

## Quickstart

```python
import witness_log

log = witness_log.WitnessLog.generate()
# Persist log.identity_bytes() somewhere safe if you want this identity
# to survive a process restart; use WitnessLog.resume(seed, session_number)
# next time.

log.append_intent(b'{"tool":"transfer_funds","args":{"amount_usd":250}}')
log.append_result(b'{"status":"ok","tx_id":"tx_7ac31"}')

pii_index = log.append_memory(b"contact: alice@example.com")
log.forget(pii_index)  # right-to-be-forgotten; tree continuity unaffected

checkpoint = log.checkpoint()       # JSON string, SPEC.md §6
log.verify_continuity(checkpoint)   # raises SignatureError or ContinuityError on mismatch (both subclass WitnessLogError)

dossier = log.to_dossier_json()     # full offline-verifiable bundle
```

Any dossier produced here verifies with the Rust CLI unmodified:

```bash
witness-log verify path/to/dossier.json
```

That cross-language round trip is exactly what the wire format
(`spec/SPEC.md`) and conformance corpus (`/corpus/`) exist to guarantee —
not just "looks similar," but byte-for-byte reproducible.

## API surface

| Method | Returns | Notes |
|---|---|---|
| `WitnessLog.generate()` | `WitnessLog` | Fresh identity. |
| `WitnessLog.resume(seed: bytes, session_number: int)` | `WitnessLog` | Resume a persisted identity. |
| `.identity_bytes()` | `bytes` | Persist this to resume later. Treat as a private key. |
| `.identity_pubkey_hex()` | `str` | Public, safe to share. |
| `.append_intent/.append_result/.append_memory(payload: bytes)` | `int` | Returns the new leaf's index. |
| `.forget(leaf_index: int)` | `bool` | `False` if nothing to forget at that index. |
| `.tree_size()` | `int` | |
| `.root_hex()` | `str` | |
| `.leaves_json()` | `str` | JSON array of all leaves. |
| `.checkpoint()` | `str` | Signed Tree Head, JSON. |
| `.verify_continuity(checkpoint_json: str)` | `None` | Raises `SignatureError` or `ContinuityError` (both subclass `WitnessLogError`) on any mismatch — NOT `ValueError`. `except ValueError:` around this call catches nothing. |
| `.to_dossier_json()` | `str` | Full dossier, unwitnessed (attach receipts separately). |

This crate is intentionally thin — it does not reimplement any
serialization logic; every JSON shape here is `witness-log-core`'s own `serde`
output, so it stays in lockstep with `spec/SPEC.md` by construction.
