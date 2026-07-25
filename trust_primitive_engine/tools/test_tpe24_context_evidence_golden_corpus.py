#!/usr/bin/env python3
"""Golden end-to-end conformance corpus for TPE 2.4 context/evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"
CORPUS_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2.4"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_tpe24_golden",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main() -> int:
    evaluator = load_evaluator()
    manifest = load_json(MANIFEST_PATH)
    cases = manifest.get("cases")

    if manifest.get("hash_algorithm") != "sha-256":
        raise TestFailure("unsupported manifest hash algorithm")
    if manifest.get("hash_serialization") != "json-sort-keys-compact-utf8":
        raise TestFailure("unsupported manifest hash serialization")
    if not isinstance(cases, list) or not cases:
        raise TestFailure("manifest has no cases")

    seen: set[str] = set()
    passed = 0

    for case in cases:
        name = case["name"]
        directory = case["directory"]
        expected_status = case["expected_status"]
        manifest_digest = case["expected_sha256"]

        if name in seen:
            raise TestFailure(f"duplicate manifest case: {name}")
        seen.add(name)

        case_dir = CORPUS_DIR / directory
        required_files = (
            "root-policy.json",
            "policy-set.json",
            "evaluation-input.json",
            "expected-evaluation.json",
            "expected-evaluation.sha256",
        )
        for filename in required_files:
            if not (case_dir / filename).is_file():
                raise TestFailure(f"{name}: missing {filename}")

        root_policy = evaluator.validate_policy(
            load_json(case_dir / "root-policy.json")
        )
        policy_set = load_json(case_dir / "policy-set.json")
        evaluation_input = load_json(case_dir / "evaluation-input.json")
        expected = load_json(case_dir / "expected-evaluation.json")
        digest_file = (
            case_dir / "expected-evaluation.sha256"
        ).read_text(encoding="ascii").strip()

        index = build_policy_set_index(
            policy_set,
            validate_policy=evaluator.validate_policy,
            compute_digest=evaluator.policy_digest,
        )
        evaluator.validate_policy_reference_graph(root_policy, index)

        signature_ids = sorted(
            item["signature_id"]
            for item in evaluation_input["signatures"]
        )

        first = evaluator.evaluate_verified_object(
            evaluation_input,
            root_policy,
            signature_ids,
            policy_set_index=index,
        )
        second = evaluator.evaluate_verified_object(
            evaluation_input,
            root_policy,
            signature_ids,
            policy_set_index=index,
        )

        if first != second:
            raise TestFailure(f"{name}: deterministic replay differs")
        if first != expected:
            raise TestFailure(f"{name}: logical evaluation differs")

        first_bytes = compact_json(first)
        expected_bytes = compact_json(expected)
        if first_bytes != expected_bytes:
            raise TestFailure(f"{name}: compact serialization differs")

        actual_digest = hashlib.sha256(first_bytes).hexdigest()
        if actual_digest != digest_file:
            raise TestFailure(f"{name}: digest file differs")
        if actual_digest != manifest_digest:
            raise TestFailure(f"{name}: manifest digest differs")
        if first["status"] != expected_status:
            raise TestFailure(
                f"{name}: expected status={expected_status}, "
                f"actual={first['status']}"
            )

        print(
            f"PASS  {name:<34} "
            f"status={first['status']} "
            f"sha256={actual_digest[:12]}..."
        )
        passed += 1

    fixture_directories = {
        path.name
        for path in CORPUS_DIR.iterdir()
        if path.is_dir()
    }
    unlisted = sorted(fixture_directories - seen)
    missing = sorted(seen - fixture_directories)

    if unlisted:
        raise TestFailure(f"unlisted case directories: {unlisted}")
    if missing:
        raise TestFailure(f"manifest references missing cases: {missing}")

    print(
        "TPE 2.4 context/evidence golden corpus: "
        f"{passed}/{len(cases)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
