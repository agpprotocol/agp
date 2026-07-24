#!/usr/bin/env python3
"""Compare an AGP TPE 2.0 benchmark run against a stored baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_report(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    if value.get("format") != "agp-tpe-v2-benchmark":
        raise ValueError(f"{path} has unsupported benchmark format")
    if value.get("format_version") != 1:
        raise ValueError(f"{path} has unsupported format version")
    return value


def index_cases(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = report.get("cases")
    if not isinstance(cases, list):
        raise ValueError("benchmark report cases must be an array")

    indexed: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("benchmark case must be an object")
        name = case.get("name")
        if not isinstance(name, str):
            raise ValueError("benchmark case name must be a string")
        if name in indexed:
            raise ValueError(f"duplicate benchmark case: {name}")
        indexed[name] = case
    return indexed


def metric(case: dict[str, Any], name: str) -> float:
    metrics = case.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError(f"{case.get('name')} has no metrics object")
    value = metrics.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(
            f"{case.get('name')} has invalid metric {name!r}"
        )
    return float(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check TPE benchmark performance regression."
    )
    parser.add_argument("baseline", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument(
        "--max-regression-percent",
        type=float,
        default=30.0,
    )
    parser.add_argument(
        "--metric",
        choices=["median_ns", "p95_ns", "p99_ns"],
        default="median_ns",
    )
    args = parser.parse_args()

    if args.max_regression_percent < 0:
        parser.error("--max-regression-percent must not be negative")

    baseline = index_cases(load_report(args.baseline))
    current = index_cases(load_report(args.current))

    missing = sorted(set(baseline) - set(current))
    unexpected = sorted(set(current) - set(baseline))

    failed = False
    if missing:
        print(f"FAIL missing current cases: {missing}")
        failed = True
    if unexpected:
        print(f"FAIL unexpected current cases: {unexpected}")
        failed = True

    shared = sorted(set(baseline) & set(current))
    for name in shared:
        old = metric(baseline[name], args.metric)
        new = metric(current[name], args.metric)
        change = ((new - old) / old) * 100.0 if old else 0.0
        status = (
            "FAIL"
            if change > args.max_regression_percent
            else "PASS"
        )
        if status == "FAIL":
            failed = True
        print(
            f"{status} {name:<46} "
            f"baseline={old / 1_000:.1f} us "
            f"current={new / 1_000:.1f} us "
            f"change={change:+.1f}%"
        )

    if failed:
        return 1

    print(
        "AGP TPE 2.0 performance regression check: "
        f"{len(shared)}/{len(shared)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
