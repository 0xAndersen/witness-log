#!/usr/bin/env python3
"""Why a mutable log is not an audit trail, in 60 seconds.

    pip install witness-log && python examples/verify_demo.py

An agent records three tool calls. Someone with write access to the
stored record (a compromised database, an insider, a bug) changes
entry #2 after the fact. A normal log would show the edited entry and
nothing else. Here the edit is caught, named, and the agent cannot be
blamed for a history it never signed.

Nothing in this script is mocked: it uses the same library and verifier
as production.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import witness_log as wl

BOLD, DIM, RED, GREEN, YELLOW, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
if not sys.stdout.isatty():
    BOLD = DIM = RED = GREEN = YELLOW = RESET = ""


def h(s: str) -> None:
    print(f"\n{BOLD}{s}{RESET}")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="witness-demo-")
    journal = os.path.join(tmp, "agent.jsonl")

    h("1. An agent runs three tool calls, each recorded as it happens")
    log = wl.open(journal)

    @wl.step(log)
    def lookup_customer(customer_id: str) -> dict:
        return {"customer_id": customer_id, "tier": "gold"}

    @wl.step(log)
    def approve_refund(customer_id: str, amount_usd: int) -> dict:
        return {"approved": True, "amount_usd": amount_usd}

    @wl.step(log)
    def send_email(to: str, subject: str) -> dict:
        return {"sent": True}

    lookup_customer("c-1042")
    approve_refund("c-1042", 250)
    send_email("c-1042@example.com", "Your refund")
    log.sync()
    identity = log.identity_pubkey_hex()
    for i, leaf in enumerate(json.loads(log.leaves_json())):
        kind = {1: "intent", 2: "result"}.get(leaf["leaf_type"], str(leaf["leaf_type"]))
        print(f"   leaf {i}  {kind:6}  payload_hash {leaf['payload_hash'][:16]}…")
    print(f"   identity  {identity[:16]}…   root {log.root_hex()[:16]}…")

    h("2. The agent exports its dossier: the record anyone can verify, offline")
    dossier_path = os.path.join(tmp, "dossier.json")
    with open(dossier_path, "w") as f:
        f.write(log.to_dossier_json())
    report = json.loads(wl.verify_dossier_json(open(dossier_path).read(), 0.66, identity))
    print(f"   verdict: {GREEN}{report['verdict'].upper()}{RESET}   "
          f"(signature ok: {report['checkpoint_signature_valid']}, "
          f"leaves rebuild the root: {report['merkle_continuity_valid']})")
    print(f"   {DIM}unanchored = internally consistent; add independent witnesses to reach WITNESSED{RESET}")

    h("3. Attack: someone with write access edits entry #2 in storage")
    print("   The refund was for $250. The stored record is changed to say $25,000,")
    print("   exactly as a compromised database or an insider would do.")
    doc = json.load(open(dossier_path))
    victim = doc["leaves"][2]
    original_hash = victim["payload_hash"]
    victim["payload_hash"] = "ab" * 32  # whatever hash the attacker's forged payload has
    with open(dossier_path, "w") as f:
        json.dump(doc, f)
    print(f"   leaf 2 payload_hash: {original_hash[:16]}… -> {victim['payload_hash'][:16]}…")
    print(f"   {DIM}In a conventional log, this is the end of the story: the record now says $25,000.{RESET}")

    h("4. Verification of the edited record")
    report = json.loads(wl.verify_dossier_json(open(dossier_path).read(), 0.66, identity))
    verdict = report["verdict"].upper()
    colour = RED if verdict == "DIVERGED" else YELLOW
    print(f"   verdict: {colour}{verdict}{RESET}")
    print(f"   checkpoint signature valid : {report['checkpoint_signature_valid']}")
    print(f"   leaves rebuild signed root : {RED if not report['merkle_continuity_valid'] else ''}"
          f"{report['merkle_continuity_valid']}{RESET}")
    print()
    print(f"   {RED}{BOLD}The leaves no longer reproduce the root the agent signed.{RESET}")
    print("   The agent's signature over the original root is intact, so the edit")
    print("   cannot be pinned on the agent: it happened after signing, in storage.")

    h("5. Exit codes make this a one-line gate")
    print("   witness-log verify dossier.json --identity <key>   # 0 WITNESSED, 10 CONSISTENT-UNWITNESSED,")
    print("                                                      # 20 UNANCHORED, 30 DIVERGED")
    print(f"\n   files in {tmp}")
    log.close()
    return 0 if verdict == "DIVERGED" else 1


if __name__ == "__main__":
    sys.exit(main())
