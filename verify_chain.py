#!/usr/bin/env python3
"""Public verifier for the Article 8 hash chain (task 5, D2). Run it
against a clone of the record repo:

    python3 verify_chain.py /path/to/record-clone

Reads chain.jsonl, law.txt (the constitution's canonical bytes -- the
chain's genesis anchor), journal/<entry>.txt canonical artifacts, and
journal/withheld.jsonl. Recomputes every link. Output on success:

    chain: N entries, M withheld, verified

On the first mismatch: `chain: mismatch at seq K (<what>)`, exit 1.
Hash definitions are harness/chain.py's; this file is copied into the
record so a verifier needs nothing but a clone and python3 (stdlib).
"""
import hashlib
import json
import sys
from pathlib import Path

REASON = "trade-secret"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(seq, what):
    print(f"chain: mismatch at seq {seq} ({what})")
    raise SystemExit(1)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_chain.py <record-clone-dir>")
    record = Path(sys.argv[1])

    chain_path = record / "chain.jsonl"
    records = [json.loads(line) for line in
               chain_path.read_text().splitlines() if line.strip()] \
        if chain_path.is_file() else []

    reasons = {}
    withheld_path = record / "journal" / "withheld.jsonl"
    if withheld_path.is_file():
        for line in withheld_path.read_text().splitlines():
            if line.strip():
                w = json.loads(line)
                reasons[w["filename"]] = w["reason"]

    genesis = sha256_hex((record / "law.txt").read_bytes())
    prev = genesis
    withheld_count = 0

    for i, r in enumerate(records):
        if r["seq"] != i:
            fail(i, f"seq field is {r['seq']}")
        if r["prev_hash"] != prev:
            fail(i, "prev_hash")
        if r["status"] == "published":
            txt = record / "journal" / (Path(r["filename"]).stem + ".txt")
            if not txt.is_file():
                fail(i, f"missing canonical artifact journal/{txt.name}")
            h = sha256_hex(r["prev_hash"].encode("ascii") + txt.read_bytes())
        elif r["status"] == "withheld":
            withheld_count += 1
            reason = reasons.get(r["filename"], REASON)
            h = sha256_hex(
                (r["prev_hash"] + r["filename"] + reason).encode("utf-8"))
        else:
            fail(i, f"unknown status {r['status']!r}")
        if h != r["hash"]:
            fail(i, "hash")
        prev = r["hash"]

    print(f"chain: {len(records)} entries, {withheld_count} withheld, verified")


if __name__ == "__main__":
    main()
