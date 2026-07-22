#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "decision_context/vectors"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64

BASE = {
    "object_type": "agp.decision-context/1",
    "context_id": "dc:procurement-2026-001",
    "created_at": "2026-07-22T20:00:00Z",
    "expires_at": "2026-07-23T20:00:00Z",
    "policy": {
        "id": "agp.policy.procurement/1",
        "version": 1,
        "digest": DIGEST_A,
    },
    "proposal": {
        "type": "agp.proposal.procurement/1",
        "payload": {
            "currency": "ARS",
            "supplier_id": "supplier-17",
            "total": 2500000,
        },
    },
    "participants": [
        {"id": "actor.finance", "role": "voter", "weight": 1},
        {"id": "actor.legal", "role": "reviewer", "weight": 1},
    ],
    "evidence": [
        {
            "id": "evidence.quote-1",
            "digest": DIGEST_B,
            "media_type": "application/pdf",
        }
    ],
    "constraints": [
        {
            "id": "constraint.budget",
            "kind": "agp.constraint.maximum-amount/1",
            "parameters": {"amount": 3000000, "currency": "ARS"},
        }
    ],
}

def encoded(value):
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )

cases = []

def add(name, raw, accepted, error_code=None):
    cases.append(
        {
            "name": name,
            "raw": raw,
            "accepted": accepted,
            "error_code": error_code,
        }
    )

add("authoritative_context", encoded(BASE), True)

def mutated(name, fn, error_code):
    value = copy.deepcopy(BASE)
    fn(value)
    add(name, encoded(value), False, error_code)

mutated(
    "unknown_top_level",
    lambda x: x.__setitem__("result", "accepted"),
    "UNKNOWN_TOP_LEVEL_MEMBER",
)
mutated(
    "wrong_object_type",
    lambda x: x.__setitem__("object_type", "agp.decision-context/2"),
    "INVALID_OBJECT_TYPE",
)
mutated(
    "invalid_context_id",
    lambda x: x.__setitem__("context_id", "Bad ID"),
    "INVALID_CONTEXT_ID",
)
mutated(
    "invalid_created_at",
    lambda x: x.__setitem__("created_at", "2026-02-30T20:00:00Z"),
    "INVALID_TIMESTAMP",
)
mutated(
    "expires_not_later",
    lambda x: x.__setitem__("expires_at", x["created_at"]),
    "INVALID_TIMESTAMP",
)
mutated(
    "invalid_policy_digest",
    lambda x: x["policy"].__setitem__("digest", "ABC"),
    "INVALID_POLICY",
)
mutated(
    "unsafe_policy_version",
    lambda x: x["policy"].__setitem__("version", 9007199254740992),
    "INVALID_SAFE_INTEGER",
)
mutated(
    "reserved_result_member",
    lambda x: x["proposal"]["payload"].__setitem__("outcome", "accepted"),
    "RESERVED_RESULT_MEMBER",
)
mutated(
    "empty_participants",
    lambda x: x.__setitem__("participants", []),
    "INVALID_PARTICIPANTS",
)
mutated(
    "duplicate_participant",
    lambda x: x["participants"].append(copy.deepcopy(x["participants"][0])),
    "DUPLICATE_IDENTIFIER",
)
mutated(
    "unsorted_participants",
    lambda x: x["participants"].reverse(),
    "UNSORTED_COLLECTION",
)
mutated(
    "invalid_evidence_digest",
    lambda x: x["evidence"][0].__setitem__("digest", "b" * 63),
    "INVALID_EVIDENCE",
)
mutated(
    "invalid_constraint_parameters",
    lambda x: x["constraints"][0].__setitem__("parameters", []),
    "INVALID_CONSTRAINTS",
)

add(
    "duplicate_json_member",
    b'{"object_type":"agp.decision-context/1",'
    b'"object_type":"agp.decision-context/1"}',
    False,
    "INVALID_JSON",
)
add("utf8_bom", b"\xef\xbb\xbf{}", False, "INVALID_JSON")
add(
    "decimal_number",
    encoded(BASE).replace(b'"total":2500000', b'"total":2500000.5'),
    False,
    "INVALID_JSON",
)
add(
    "nonfinite_number",
    encoded(BASE).replace(b'"total":2500000', b'"total":NaN'),
    False,
    "INVALID_JSON",
)

if VECTORS.exists():
    shutil.rmtree(VECTORS)
VECTORS.mkdir(parents=True)

manifest = {"profile": "AGP-DECISION-CONTEXT-0.9", "vectors": []}
for index, case in enumerate(cases, start=1):
    stem = f"{index:03d}_{case['name']}"
    input_name = f"{stem}.input.json"
    meta_name = f"{stem}.meta.json"
    (VECTORS / input_name).write_bytes(case["raw"])
    (VECTORS / meta_name).write_text(
        json.dumps(
            {
                "vector": case["name"],
                "accepted": case["accepted"],
                "error_code": case["error_code"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest["vectors"].append(
        {"name": case["name"], "input": input_name, "meta": meta_name}
    )

(VECTORS / "manifest.json").write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
)
print(f"Generated {len(cases)} Decision Context vectors")
