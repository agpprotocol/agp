#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "registry/python/validate_registry.py"
REGISTRY_PATH = ROOT / "registry/registry.json"

spec = importlib.util.spec_from_file_location("validate_registry", VALIDATOR_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

base = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

def case(name, mutate, expected, accepted=False):
    value = copy.deepcopy(base)
    mutate(value)
    result = module.validate_bytes(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    ok = result["accepted"] == accepted and result["error_code"] == expected
    print(f"{'PASS' if ok else 'FAIL'}  {name:<28} accepted={result['accepted']} error={result['error_code']}")
    return ok

def raw_case(name, raw, expected):
    result = module.validate_bytes(raw)
    ok = result["accepted"] is False and result["error_code"] == expected
    print(f"{'PASS' if ok else 'FAIL'}  {name:<28} accepted={result['accepted']} error={result['error_code']}")
    return ok

checks = []

valid = module.validate_bytes(REGISTRY_PATH.read_bytes())
ok = valid["accepted"] is True
print(f"{'PASS' if ok else 'FAIL'}  {'authoritative_registry':<28} accepted={valid['accepted']} error={valid['error_code']}")
checks.append(ok)

checks.append(case("unknown_top_level", lambda x: x.__setitem__("extra", True), "UNKNOWN_TOP_LEVEL_MEMBER"))
checks.append(case("wrong_registry_version", lambda x: x.__setitem__("registry_version", "0.9"), "INVALID_REGISTRY_VERSION"))
checks.append(case("collection_not_array", lambda x: x.__setitem__("objects", {}), "INVALID_COLLECTION"))
checks.append(case("invalid_identifier", lambda x: x["digest_algorithms"][0].__setitem__("id", "SHA 256"), "INVALID_IDENTIFIER"))
checks.append(case("duplicate_identifier", lambda x: x["signature_algorithms"].append(copy.deepcopy(x["signature_algorithms"][0])), "DUPLICATE_IDENTIFIER"))
checks.append(case("unsorted_collection", lambda x: x["objects"].reverse(), "UNSORTED_COLLECTION"))
checks.append(case("invalid_status", lambda x: x["digest_algorithms"][0].__setitem__("status", "experimental"), "INVALID_STATUS"))
checks.append(case("unsafe_integer", lambda x: x["digest_algorithms"][0].__setitem__("output_bits", 9007199254740992), "INVALID_SAFE_INTEGER"))
checks.append(case("object_version_mismatch", lambda x: x["objects"][0].__setitem__("schema_version", 2), "INVALID_OBJECT_ID"))
checks.append(case("missing_reference", lambda x: x["objects"][0].__setitem__("digest", "sha-999"), "MISSING_REFERENCE"))
checks.append(case("reserved_reference", lambda x: (
    x["digest_algorithms"].append({
        "id": "zz-reserved-digest",
        "status": "reserved",
        "spec": "spec/",
        "description": "Reserved test algorithm.",
        "output_bits": 256
    }),
    x["objects"][0].__setitem__("digest", "zz-reserved-digest")
), "RESERVED_REFERENCE"))

checks.append(raw_case(
    "duplicate_json_member",
    b'{"registry_version":"0.8","registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[]}',
    "INVALID_JSON",
))
checks.append(raw_case("utf8_bom", b"\xef\xbb\xbf{}", "INVALID_JSON"))
checks.append(raw_case(
    "decimal_number",
    b'{"registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[],"extra":1.5}',
    "INVALID_JSON",
))
checks.append(raw_case(
    "nonfinite_number",
    b'{"registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[],"extra":NaN}',
    "INVALID_JSON",
))

passed = sum(checks)
print(f"AGP v0.8 Schema Registry: {passed}/{len(checks)} passed")
raise SystemExit(0 if all(checks) else 1)
