"""Selective disclosure of one leaf's content.

A leaf commits to ``payload_hash = SHA-256(bucket_pad(payload) || salt ||
index)`` (SPEC §8). The journal stores neither the payload nor, in the
journal file itself, the salt: payloads are the caller's, salts live in
``<journal>.salts`` so that ``forget`` can erase one. Disclosing a leaf
therefore means handing over ``{leaf, payload, salt}``; the recipient
recomputes the hash and checks it against the leaf in a verified dossier.
This module does both halves in Python so a disclosure can be produced
and checked without the Rust core.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Mapping, Optional

__all__ = ["payload_hash_hex", "read_salts", "salts_path", "disclosure", "check_disclosure"]

BUCKET = 256


def _bucket_pad(payload: bytes) -> bytes:
    target = (len(payload) // BUCKET + 1) * BUCKET
    return len(payload).to_bytes(8, "big") + payload + b"\0" * (target - len(payload))


def payload_hash_hex(payload: bytes, salt: bytes, index: int) -> str:
    """SPEC §8 ``payload_hash``; corpus vector ``11_payload_hash.json`` pins it."""
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    h = hashlib.sha256()
    h.update(_bucket_pad(payload))
    h.update(salt)
    h.update(int(index).to_bytes(8, "big"))
    return h.hexdigest()


def salts_path(journal_path: str) -> str:
    return journal_path + ".salts"


def read_salts(journal_path: str) -> Dict[int, str]:
    """``{leaf_index: salt_hex}`` from the journal's salt sidecar. A
    forgotten leaf has no record. Missing file: no salts."""
    out: Dict[int, str] = {}
    p = salts_path(journal_path)
    if not os.path.exists(p):
        return out
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                out[int(rec["i"])] = str(rec["s"]).lower()
            except (ValueError, KeyError, TypeError):
                continue  # a torn tail; the core truncates it on resume
    return out


def disclosure(
    leaf: Mapping[str, Any],
    payload: Optional[bytes],
    salt_hex: Optional[str],
) -> Dict[str, Any]:
    """The disclosure record for one leaf. ``payload`` is given as UTF-8
    text when it decodes and as hex otherwise; ``complete`` says whether
    both the payload and the salt were available (a forgotten leaf, or
    one whose payload this process never saw, is disclosed as the bare
    leaf). ``verified`` is the recomputation against the leaf's hash."""
    rec: Dict[str, Any] = {"index": int(leaf["index"]), "leaf": dict(leaf), "complete": False, "verified": None}
    if payload is not None:
        try:
            rec["payload"] = payload.decode("utf-8")
            rec["payload_encoding"] = "utf-8"
        except UnicodeDecodeError:
            rec["payload"] = payload.hex()
            rec["payload_encoding"] = "hex"
    if salt_hex is not None:
        rec["salt"] = salt_hex
    if payload is not None and salt_hex is not None:
        rec["complete"] = True
        rec["verified"] = check_disclosure(rec)
    return rec


def _payload_bytes(rec: Mapping[str, Any]) -> bytes:
    if rec.get("payload_encoding") == "hex":
        return bytes.fromhex(rec["payload"])
    return str(rec["payload"]).encode("utf-8")


def check_disclosure(rec: Mapping[str, Any]) -> bool:
    """True when ``rec["payload"]`` and ``rec["salt"]`` recompute
    ``rec["leaf"]["payload_hash"]``. The leaf itself must come from a
    dossier the checker has verified; this only ties content to it."""
    try:
        leaf = rec["leaf"]
        got = payload_hash_hex(_payload_bytes(rec), bytes.fromhex(rec["salt"]), int(leaf["index"]))
        return got == str(leaf["payload_hash"]).lower()
    except (KeyError, ValueError, TypeError):
        return False
