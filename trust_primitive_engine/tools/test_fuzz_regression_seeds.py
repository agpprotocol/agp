#!/usr/bin/env python3
"""Replay committed AGP TPE 2.0 fuzz regression seeds."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
SEEDS_DIR = ROOT / "trust_primitive_engine/fuzz/seeds/v2"


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe_v2_fuzz_regression",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def outcome(module: Any, value: Any) -> tuple[str, str]:
    expected_failure = getattr(module, "EvaluationFailure", None)
    try:
        normalized = module.validate_policy(copy.deepcopy(value))
    except Exception as exc:
        if expected_failure is not None and isinstance(exc, expected_failure):
            code = getattr(exc, "code", type(exc).__name__)
            return ("reject", str(code))
        raise
    return ("accept", stable_json(normalized))


def main() -> int:
    module = load_evaluator()
    seed_paths = sorted(SEEDS_DIR.glob("*.json"))
    if not seed_paths:
        raise TestFailure(f"no fuzz regression seeds found in {SEEDS_DIR}")

    passed = 0
    for path in seed_paths:
        seed = json.loads(path.read_text(encoding="utf-8"))
        if seed.get("format") != "agp-tpe-v2-fuzz-seed":
            raise TestFailure(f"unsupported seed format: {path.name}")
        if seed.get("format_version") != 1:
            raise TestFailure(f"unsupported seed version: {path.name}")

        value = seed.get("value")
        expected = seed.get("expected_outcome")
        expected_code = seed.get("expected_error_code")

        first = outcome(module, value)
        second = outcome(module, value)

        if first != second:
            raise TestFailure(f"non-deterministic replay: {path.name}")
        if first[0] != expected:
            raise TestFailure(
                f"outcome mismatch {path.name}: expected={expected} actual={first[0]}"
            )
        if expected == "reject" and expected_code is not None and first[1] != expected_code:
            raise TestFailure(
                f"error code mismatch {path.name}: "
                f"expected={expected_code} actual={first[1]}"
            )

        print(f"PASS  {path.name:<44} outcome={first[0]}")
        passed += 1

    print(f"AGP TPE 2.0 fuzz regression seeds: {passed}/{len(seed_paths)} passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, TestFailure) as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
