#!/usr/bin/env python3
"""Focused unit-level conformance for deterministic time_window."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = ROOT / "trust_primitive_engine/python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from engine import EvaluationState
from primitives.time_window import TimeWindowPrimitive


class TestFailure(Exception):
    pass


def state(evaluation_time: int | None) -> EvaluationState:
    return EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        evaluation_time=evaluation_time,
    )


def main() -> int:
    primitive = TimeWindowPrimitive()
    requirement = primitive.validate(
        {
            "requirement_id": "requirement:deployment-window",
            "type": "time_window",
            "not_before": 100,
            "not_after": 200,
        }
    )

    cases = [
        ("missing", None, "missing", False),
        ("before", 99, "before", False),
        ("lower_boundary", 100, "inside", True),
        ("inside", 150, "inside", True),
        ("upper_boundary", 200, "inside", True),
        ("after", 201, "after", False),
    ]

    passed = 0
    for name, timestamp, position, satisfied in cases:
        result = primitive.evaluate(requirement, state(timestamp)).to_dict()
        if (result["status"] == "satisfied") != satisfied:
            raise TestFailure(f"{name}: unexpected status {result!r}")
        if result["observed"] != {
            "evaluation_time": timestamp,
            "position": position,
        }:
            raise TestFailure(f"{name}: unexpected observed {result!r}")
        expected_failure = None if satisfied else "TIME_WINDOW_NOT_SATISFIED"
        if result["failure_code"] != expected_failure:
            raise TestFailure(f"{name}: unexpected failure {result!r}")
        print(f"PASS  {name:<24} position={position}")
        passed += 1

    invalid = [
        ("boolean_not_before", True, 200),
        ("negative_not_before", -1, 200),
        ("unsafe_not_after", 100, 9007199254740992),
        ("inverted_window", 201, 200),
    ]
    for name, not_before, not_after in invalid:
        try:
            primitive.validate(
                {
                    "requirement_id": "requirement:deployment-window",
                    "type": "time_window",
                    "not_before": not_before,
                    "not_after": not_after,
                }
            )
        except ValueError:
            print(f"PASS  {name:<24} rejected")
            passed += 1
        else:
            raise TestFailure(f"{name}: invalid policy accepted")

    first = primitive.evaluate(requirement, state(150)).to_dict()
    second = primitive.evaluate(requirement, state(150)).to_dict()
    if first != second:
        raise TestFailure("deterministic_replay: outputs differ")
    print("PASS  deterministic_replay     outputs=identical")
    passed += 1

    print(f"AGP TPE 2.1 time_window conformance: {passed}/{passed} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
