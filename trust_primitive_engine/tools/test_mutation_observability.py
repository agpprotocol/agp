#!/usr/bin/env python3
"""Targeted mutation-observability tests for AGP TPE 2.0."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = (
    ROOT
    / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_mutation_observability",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise TestFailure(
            f"{label}: expected {expected!r}, got {actual!r}"
        )


def check_minimum_boundary(evaluator: Any) -> None:
    actual = evaluator.validate_safe_integer(
        1,
        "version",
        minimum=1,
    )
    assert_equal(actual, 1, "minimum boundary")


def check_maximum_boundary(evaluator: Any) -> None:
    actual = evaluator.validate_safe_integer(
        MAX_SAFE_INTEGER,
        "weight",
        minimum=0,
    )
    assert_equal(
        actual,
        MAX_SAFE_INTEGER,
        "maximum safe integer boundary",
    )


def call_main(
    evaluator: Any,
    argv: list[str],
) -> tuple[int | None, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code: int | None = None

    with patch.object(sys, "argv", argv):
        with contextlib.redirect_stdout(stdout):
            with contextlib.redirect_stderr(stderr):
                try:
                    exit_code = evaluator.main()
                except SystemExit as exc:
                    exit_code = int(exc.code)

    return exit_code, stdout.getvalue(), stderr.getvalue()


def check_policy_argument_required(evaluator: Any) -> None:
    code, _stdout, stderr = call_main(
        evaluator,
        [
            "evaluate_trust_policy_v2.py",
            "input.json",
            "--keyring",
            "keyring.json",
        ],
    )
    assert_equal(code, 2, "--policy missing exit code")
    if "--policy" not in stderr or "required" not in stderr:
        raise TestFailure(
            "--policy missing did not produce argparse required error"
        )


def check_keyring_argument_required(evaluator: Any) -> None:
    code, _stdout, stderr = call_main(
        evaluator,
        [
            "evaluate_trust_policy_v2.py",
            "input.json",
            "--policy",
            "policy.json",
        ],
    )
    assert_equal(code, 2, "--keyring missing exit code")
    if "--keyring" not in stderr or "required" not in stderr:
        raise TestFailure(
            "--keyring missing did not produce argparse required error"
        )


def run_serialization_main(evaluator: Any) -> tuple[int, str]:
    evaluation = {
        "z": 1,
        "status": "satisfied",
        "a": "á",
    }

    with patch.object(
        evaluator,
        "load_json",
        side_effect=[{}, {}],
    ):
        with patch.object(
            evaluator,
            "load_keyring",
            return_value={},
        ):
            with patch.object(
                evaluator,
                "evaluate",
                return_value=evaluation,
            ):
                code, stdout, stderr = call_main(
                    evaluator,
                    [
                        "evaluate_trust_policy_v2.py",
                        "input.json",
                        "--policy",
                        "policy.json",
                        "--keyring",
                        "keyring.json",
                    ],
                )

    if stderr:
        raise TestFailure(
            f"serialization CLI wrote unexpected stderr: {stderr!r}"
        )
    if code is None:
        raise TestFailure("serialization CLI returned no exit code")
    return code, stdout


def check_cli_unicode_is_unescaped(evaluator: Any) -> None:
    code, stdout = run_serialization_main(evaluator)
    assert_equal(code, 0, "serialization CLI exit code")
    if "á" not in stdout:
        raise TestFailure(
            "CLI JSON escaped non-ASCII text; ensure_ascii must be False"
        )
    if "\\u00e1" in stdout.lower():
        raise TestFailure(
            "CLI JSON contains escaped Unicode text"
        )


def check_cli_keys_are_sorted(evaluator: Any) -> None:
    code, stdout = run_serialization_main(evaluator)
    assert_equal(code, 0, "serialization CLI exit code")
    expected = '{"a":"á","status":"satisfied","z":1}\n'
    assert_equal(stdout, expected, "deterministic CLI JSON bytes")


def main() -> int:
    evaluator = load_evaluator()
    checks = [
        ("minimum_safe_integer_boundary_inclusive", check_minimum_boundary),
        ("maximum_safe_integer_boundary_inclusive", check_maximum_boundary),
        ("cli_policy_argument_required", check_policy_argument_required),
        ("cli_keyring_argument_required", check_keyring_argument_required),
        ("cli_unicode_unescaped", check_cli_unicode_is_unescaped),
        ("cli_keys_sorted", check_cli_keys_are_sorted),
    ]

    passed = 0
    for name, check in checks:
        check(evaluator)
        print(f"PASS  {name}")
        passed += 1

    print(
        "AGP TPE 2.0 mutation observability: "
        f"{passed}/{len(checks)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
