#!/usr/bin/env python3
"""Versioned golden compatibility corpus for AGP Trust Policy 2.0."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/agp.trust-policy-2.schema.json"
EVALUATOR_PATH = ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
CORPUS_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_golden",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_accepts(evaluator: Any, policy: Any) -> bool:
    try:
        evaluator.validate_policy(policy)
    except Exception:
        return False
    return True


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    evaluator = load_evaluator()

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise TestFailure("manifest has no cases")

    seen: set[str] = set()
    passed = 0

    for case in cases:
        filename = case["file"]
        expected_schema = case["schema"]
        expected_runtime = case["runtime"]

        if filename in seen:
            raise TestFailure(f"duplicate manifest entry: {filename}")
        seen.add(filename)

        path = CORPUS_DIR / filename
        if not path.is_file():
            raise TestFailure(f"missing fixture: {filename}")

        policy = json.loads(path.read_text(encoding="utf-8"))
        actual_schema = (
            "accept"
            if not any(validator.iter_errors(policy))
            else "reject"
        )
        actual_runtime = (
            "accept"
            if runtime_accepts(evaluator, policy)
            else "reject"
        )

        if actual_schema != expected_schema:
            raise TestFailure(
                f"{filename}: schema expected={expected_schema} "
                f"actual={actual_schema}"
            )
        if actual_runtime != expected_runtime:
            raise TestFailure(
                f"{filename}: runtime expected={expected_runtime} "
                f"actual={actual_runtime}"
            )

        print(
            f"PASS  {filename:<50} "
            f"schema={actual_schema} runtime={actual_runtime}"
        )
        passed += 1

    fixture_files = {
        path.name
        for path in CORPUS_DIR.glob("*.json")
        if path.name != "manifest.json"
    }
    unlisted = sorted(fixture_files - seen)
    missing = sorted(seen - fixture_files)
    if unlisted:
        raise TestFailure(f"unlisted fixtures: {unlisted}")
    if missing:
        raise TestFailure(f"manifest references missing fixtures: {missing}")

    print(
        "AGP Trust Policy 2.0 golden compatibility corpus: "
        f"{passed}/{len(cases)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
