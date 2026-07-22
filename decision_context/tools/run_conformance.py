#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "decision_context/python/validate_decision_context.py"

spec = importlib.util.spec_from_file_location("validate_decision_context", VALIDATOR)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

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
        {"id": "evidence.quote-1", "digest": DIGEST_B, "media_type": "application/pdf"}
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
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

cases = []
def add(name, raw, accepted, error):
    cases.append((name, raw, accepted, error))

add("authoritative_context", encoded(BASE), True, None)

def mutate(name, fn, error):
    value = copy.deepcopy(BASE)
    fn(value)
    add(name, encoded(value), False, error)

mutate("unknown_top_level", lambda x: x.__setitem__("result", "accepted"), "UNKNOWN_TOP_LEVEL_MEMBER")
mutate("wrong_object_type", lambda x: x.__setitem__("object_type", "agp.decision-context/2"), "INVALID_OBJECT_TYPE")
mutate("invalid_context_id", lambda x: x.__setitem__("context_id", "Bad ID"), "INVALID_CONTEXT_ID")
mutate("invalid_created_at", lambda x: x.__setitem__("created_at", "2026-02-30T20:00:00Z"), "INVALID_TIMESTAMP")
mutate("expires_not_later", lambda x: x.__setitem__("expires_at", x["created_at"]), "INVALID_TIMESTAMP")
mutate("invalid_policy_digest", lambda x: x["policy"].__setitem__("digest", "ABC"), "INVALID_POLICY")
mutate("unsafe_policy_version", lambda x: x["policy"].__setitem__("version", 9007199254740992), "INVALID_SAFE_INTEGER")
mutate("reserved_result_member", lambda x: x["proposal"]["payload"].__setitem__("outcome", "accepted"), "RESERVED_RESULT_MEMBER")
mutate("empty_participants", lambda x: x.__setitem__("participants", []), "INVALID_PARTICIPANTS")
mutate("duplicate_participant", lambda x: x["participants"].append(copy.deepcopy(x["participants"][0])), "DUPLICATE_IDENTIFIER")
mutate("unsorted_participants", lambda x: x["participants"].reverse(), "UNSORTED_COLLECTION")
mutate("invalid_evidence_digest", lambda x: x["evidence"][0].__setitem__("digest", "b" * 63), "INVALID_EVIDENCE")
mutate("invalid_constraint_parameters", lambda x: x["constraints"][0].__setitem__("parameters", []), "INVALID_CONSTRAINTS")

add(
    "duplicate_json_member",
    b'{"object_type":"agp.decision-context/1","object_type":"agp.decision-context/1"}',
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

passed = 0
for name, raw, expected_accepted, expected_error in cases:
    result = module.validate_bytes(raw)
    ok = (
        result["accepted"] == expected_accepted
        and result["error_code"] == expected_error
    )
    passed += int(ok)
    print(
        f"{'PASS' if ok else 'FAIL'}  {name:<28} "
        f"accepted={result['accepted']} error={result['error_code']}"
    )

print(f"AGP Decision Context 0.9: {passed}/{len(cases)} passed")
raise SystemExit(0 if passed == len(cases) else 1)
