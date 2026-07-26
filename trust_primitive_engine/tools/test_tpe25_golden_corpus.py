#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine/python"
EVAL = TPE / "evaluate_trust_policy_v2.py"
CORPUS = ROOT / "trust_primitive_engine/fixtures/golden/v2.5"

if str(TPE) not in sys.path:
    sys.path.insert(0, str(TPE))

from engine import build_policy_set_index


class TestFailure(Exception):
    pass


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def compact(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("tpe25_golden_test", EVAL)
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    ev = evaluator()
    manifest = load(CORPUS / "manifest.json")
    passed = 0

    if manifest["hash_algorithm"] != "sha-256":
        raise TestFailure("bad hash algorithm")
    if manifest["hash_serialization"] != "json-sort-keys-compact-utf8":
        raise TestFailure("bad serialization")

    for case in manifest["cases"]:
        case_dir = CORPUS / case["directory"]
        root = ev.validate_policy(load(case_dir / "root-policy.json"))
        policies = load(case_dir / "policy-set.json")
        evaluation_input = load(case_dir / "evaluation-input.json")
        expected = load(case_dir / "expected-evaluation.json")

        index = build_policy_set_index(
            policies,
            validate_policy=ev.validate_policy,
            compute_digest=ev.policy_digest,
        )
        ev.validate_policy_reference_graph(root, index)
        signature_ids = sorted(
            item["signature_id"]
            for item in evaluation_input["signatures"]
        )
        first = ev.evaluate_verified_object(
            evaluation_input,
            root,
            signature_ids,
            policy_set_index=index,
        )
        second = ev.evaluate_verified_object(
            evaluation_input,
            root,
            signature_ids,
            policy_set_index=index,
        )

        if first != second:
            raise TestFailure(f"{case['name']}: replay differs")
        if first != expected:
            raise TestFailure(f"{case['name']}: result differs")

        digest = hashlib.sha256(compact(first)).hexdigest()
        frozen = (case_dir / "expected-evaluation.sha256").read_text(
            encoding="ascii"
        ).strip()
        if digest != frozen or digest != case["expected_sha256"]:
            raise TestFailure(f"{case['name']}: digest differs")
        if first["status"] != case["expected_status"]:
            raise TestFailure(f"{case['name']}: status differs")

        print(
            f"PASS  {case['name']:<34} "
            f"status={first['status']} sha256={digest[:12]}..."
        )
        passed += 1

    if passed != 5:
        raise TestFailure(f"expected 5, observed {passed}")
    print("TPE 2.5 contextual predicates golden corpus: 5/5 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
