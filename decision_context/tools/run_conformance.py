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
    "policy": {"id": "agp.policy.procurement/1", "version": 1, "digest": DIGEST_A},
    "proposal": {
        "type": "agp.proposal.procurement/1",
        "payload": {"currency": "ARS", "supplier_id": "supplier-17", "total": 2500000},
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

BASE_V2 = copy.deepcopy(BASE)
BASE_V2["object_type"] = "agp.decision-context/2"
BASE_V2["evaluation_time"] = 1784894400

BASE_V3 = copy.deepcopy(BASE_V2)
BASE_V3["object_type"] = "agp.decision-context/3"
BASE_V3["evidence"][0].update(
    {
        "evidence_type": "agp.evidence.quote/1",
        "issuer_id": "authority:procurement",
    }
)

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

cases = []

def add(name, raw, accepted, error):
    cases.append((name, raw, accepted, error))

add("authoritative_context", encoded(BASE), True, None)
add("authoritative_context_v2", encoded(BASE_V2), True, None)
add("authoritative_context_v3", encoded(BASE_V3), True, None)

empty_v3 = copy.deepcopy(BASE_V3)
empty_v3["evidence"] = []
add("v3_empty_evidence", encoded(empty_v3), True, None)

multiple_v3 = copy.deepcopy(BASE_V3)
multiple_v3["evidence"].append(
    {
        "id": "evidence.security-review",
        "digest": DIGEST_A,
        "media_type": "application/json",
        "evidence_type": "agp.evidence.security-review/1",
        "issuer_id": "authority:security-lab",
    }
)
add("v3_multiple_sorted", encoded(multiple_v3), True, None)

def mutate_from(base, name, fn, error):
    value = copy.deepcopy(base)
    fn(value)
    add(name, encoded(value), False, error)

mutate_from(BASE, "unknown_top_level", lambda x: x.__setitem__("result", "accepted"), "UNKNOWN_TOP_LEVEL_MEMBER")
mutate_from(BASE, "wrong_object_type", lambda x: x.__setitem__("object_type", "agp.invalid/1"), "INVALID_OBJECT_TYPE")
mutate_from(BASE, "invalid_context_id", lambda x: x.__setitem__("context_id", "Bad ID"), "INVALID_CONTEXT_ID")
mutate_from(BASE, "invalid_created_at", lambda x: x.__setitem__("created_at", "2026-02-30T20:00:00Z"), "INVALID_TIMESTAMP")
mutate_from(BASE, "expires_not_later", lambda x: x.__setitem__("expires_at", x["created_at"]), "INVALID_TIMESTAMP")
mutate_from(BASE, "invalid_policy_digest", lambda x: x["policy"].__setitem__("digest", "ABC"), "INVALID_POLICY")
mutate_from(BASE, "unsafe_policy_version", lambda x: x["policy"].__setitem__("version", 9007199254740992), "INVALID_SAFE_INTEGER")
mutate_from(BASE, "reserved_result_member", lambda x: x["proposal"]["payload"].__setitem__("outcome", "accepted"), "RESERVED_RESULT_MEMBER")
mutate_from(BASE, "empty_participants", lambda x: x.__setitem__("participants", []), "INVALID_PARTICIPANTS")
mutate_from(BASE, "duplicate_participant", lambda x: x["participants"].append(copy.deepcopy(x["participants"][0])), "DUPLICATE_IDENTIFIER")
mutate_from(BASE, "unsorted_participants", lambda x: x["participants"].reverse(), "UNSORTED_COLLECTION")
mutate_from(BASE, "invalid_evidence_digest", lambda x: x["evidence"][0].__setitem__("digest", "b" * 63), "INVALID_EVIDENCE")
mutate_from(BASE, "invalid_constraint_parameters", lambda x: x["constraints"][0].__setitem__("parameters", []), "INVALID_CONSTRAINTS")

mutate_from(BASE_V2, "v2_missing_evaluation_time", lambda x: x.pop("evaluation_time"), "INVALID_OBJECT")
mutate_from(BASE_V2, "v2_boolean_evaluation_time", lambda x: x.__setitem__("evaluation_time", True), "INVALID_SAFE_INTEGER")
mutate_from(BASE_V2, "v2_negative_evaluation_time", lambda x: x.__setitem__("evaluation_time", -1), "INVALID_SAFE_INTEGER")
mutate_from(BASE_V2, "v2_unsafe_evaluation_time", lambda x: x.__setitem__("evaluation_time", 9007199254740992), "INVALID_SAFE_INTEGER")
mutate_from(BASE_V2, "v2_unknown_top_level", lambda x: x.__setitem__("extra", True), "UNKNOWN_TOP_LEVEL_MEMBER")

mutate_from(BASE_V3, "v3_missing_evidence_type", lambda x: x["evidence"][0].pop("evidence_type"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_missing_issuer_id", lambda x: x["evidence"][0].pop("issuer_id"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_unknown_evidence_member", lambda x: x["evidence"][0].__setitem__("extra", True), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_evidence_type_zero", lambda x: x["evidence"][0].__setitem__("evidence_type", "agp.evidence.quote/0"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_evidence_type_leading_zero", lambda x: x["evidence"][0].__setitem__("evidence_type", "agp.evidence.quote/01"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_evidence_type_missing_version", lambda x: x["evidence"][0].__setitem__("evidence_type", "agp.evidence.quote"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_evidence_type_too_long", lambda x: x["evidence"][0].__setitem__("evidence_type", "a" * 127 + "/1"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_invalid_issuer_id", lambda x: x["evidence"][0].__setitem__("issuer_id", "Bad Issuer"), "INVALID_EVIDENCE")
mutate_from(BASE_V3, "v3_duplicate_evidence", lambda x: x["evidence"].append(copy.deepcopy(x["evidence"][0])), "DUPLICATE_IDENTIFIER")
mutate_from(
    BASE_V3,
    "v3_unsorted_evidence",
    lambda x: x["evidence"].insert(
        0,
        {
            "id": "evidence.z-report",
            "digest": DIGEST_A,
            "media_type": "application/json",
            "evidence_type": "agp.evidence.report/1",
            "issuer_id": "authority:reporting",
        },
    ),
    "UNSORTED_COLLECTION",
)

add(
    "duplicate_json_member",
    b'{"object_type":"agp.decision-context/1","object_type":"agp.decision-context/1"}',
    False,
    "INVALID_JSON",
)
add("utf8_bom", b"\xef\xbb\xbf{}", False, "INVALID_JSON")
add("decimal_number", encoded(BASE).replace(b'"total":2500000', b'"total":2500000.5'), False, "INVALID_JSON")
add("nonfinite_number", encoded(BASE).replace(b'"total":2500000', b'"total":NaN'), False, "INVALID_JSON")
mutate_from(BASE, "duplicate_evidence", lambda x: x["evidence"].append(copy.deepcopy(x["evidence"][0])), "DUPLICATE_IDENTIFIER")
mutate_from(
    BASE,
    "unsorted_evidence",
    lambda x: x["evidence"].insert(
        0,
        {"id": "evidence.z-report", "digest": DIGEST_A, "media_type": "application/json"},
    ),
    "UNSORTED_COLLECTION",
)

passed = 0
for name, raw, expected_accepted, expected_error in cases:
    first = module.validate_bytes(raw)
    second = module.validate_bytes(raw)
    replay = first == second
    ok = (
        first["accepted"] == expected_accepted
        and first["error_code"] == expected_error
        and replay
    )
    passed += int(ok)
    print(
        f"{'PASS' if ok else 'FAIL'}  {name:<34} "
        f"accepted={first['accepted']} error={first['error_code']} replay={replay}"
    )

print(f"AGP Decision Context 1/2/3: {passed}/{len(cases)} passed")
raise SystemExit(0 if passed == len(cases) else 1)
