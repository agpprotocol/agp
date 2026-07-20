from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
from typing import Any

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def calc_hash(entry: dict) -> str:
    body = {k: entry[k] for k in sorted(entry) if k != "entry_hash"}
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()

def verify(data: dict) -> dict:
    entries = data.get("entries", [])
    errors = []
    seen = set()
    prev = "GENESIS"

    for expected_index, entry in enumerate(entries):
        idx = entry.get("index")
        if idx in seen:
            errors.append({"code": "DUPLICATE_INDEX", "index": idx})
        seen.add(idx)

        if idx != expected_index:
            errors.append({"code": "NON_CONTIGUOUS_INDEX", "index": idx})
        if entry.get("previous_hash") != prev:
            errors.append({"code": "PREVIOUS_HASH_MISMATCH", "index": idx})
        computed = calc_hash(entry)
        if entry.get("entry_hash") != computed:
            errors.append({"code": "ENTRY_HASH_MISMATCH", "index": idx})
        prev = entry.get("entry_hash", "")

    expected_checkpoint = data.get("expected_checkpoint")
    if expected_checkpoint is not None:
        actual = prev if entries else "GENESIS"
        if actual != expected_checkpoint:
            errors.append({"code": "CHECKPOINT_MISMATCH", "index": len(entries)-1})

    errors.sort(key=lambda x: (x["code"], -1 if x["index"] is None else x["index"]))
    return {
        "accepted": not errors,
        "checkpoint": prev if entries else "GENESIS",
        "entry_count": len(entries),
        "error_codes": errors,
        "log_id": data.get("log_id"),
    }

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: transparency.py INPUT OUTPUT")
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = verify(data)
    Path(sys.argv[2]).write_bytes(canonical_bytes(out)+b"\n")

if __name__ == "__main__":
    main()
