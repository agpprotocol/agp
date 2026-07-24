#!/usr/bin/env python3
"""Reproducible microbenchmark suite for AGP TPE 2.0 policy validation."""

from __future__ import annotations

import argparse
import gc
import importlib.util
import json
import math
import os
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = (
    ROOT
    / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)
GOLDEN_DIR = (
    ROOT
    / "trust_primitive_engine/fixtures/golden/v2"
)

DEFAULT_FIXTURES = [
    "valid_required_signer.json",
    "valid_signer_threshold.json",
    "valid_global_thresholds.json",
    "valid_role_thresholds.json",
    "valid_constraints.json",
    "valid_cardinality.json",
]


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe_v2_benchmark_evaluator",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def percentile(values: list[int], fraction: float) -> float:
    if not values:
        raise ValueError("percentile requires values")
    ordered = sorted(values)
    index = max(
        0,
        min(
            len(ordered) - 1,
            math.ceil(fraction * len(ordered)) - 1,
        ),
    )
    return float(ordered[index])


def read_policy(name: str) -> dict[str, Any]:
    path = GOLDEN_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"missing golden fixture: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"golden fixture must contain an object: {path}")
    return value


def scaled_policy(
    source: dict[str, Any],
    requirement_count: int,
) -> dict[str, Any]:
    requirements = source.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("source policy has no requirements")

    generated: list[dict[str, Any]] = []
    for index in range(requirement_count):
        template = dict(requirements[index % len(requirements)])
        template["requirement_id"] = f"bench-requirement-{index:06d}"
        generated.append(template)

    result = dict(source)
    result["policy_id"] = f"benchmark-policy-{requirement_count:06d}"
    result["requirements"] = generated
    return result


def benchmark_call(
    operation: Callable[[], Any],
    *,
    warmup: int,
    iterations: int,
) -> tuple[dict[str, float | int], Any]:
    for _ in range(warmup):
        operation()

    gc.collect()
    gc.disable()
    samples: list[int] = []
    last_value: Any = None

    try:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            last_value = operation()
            samples.append(time.perf_counter_ns() - start)
    finally:
        gc.enable()

    total_ns = sum(samples)
    median_ns = statistics.median(samples)

    return (
        {
            "iterations": iterations,
            "total_ns": total_ns,
            "min_ns": min(samples),
            "median_ns": float(median_ns),
            "mean_ns": float(statistics.fmean(samples)),
            "p95_ns": percentile(samples, 0.95),
            "p99_ns": percentile(samples, 0.99),
            "max_ns": max(samples),
            "operations_per_second": (
                iterations / (total_ns / 1_000_000_000)
            ),
        },
        last_value,
    )


def memory_peak(operation: Callable[[], Any]) -> int:
    gc.collect()
    tracemalloc.start()
    try:
        operation()
        _current, peak = tracemalloc.get_traced_memory()
        return int(peak)
    finally:
        tracemalloc.stop()


def machine_metadata() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "executable": sys.executable,
        "cpu_count": os.cpu_count(),
    }


def run_case(
    name: str,
    operation: Callable[[], Any],
    *,
    warmup: int,
    iterations: int,
) -> dict[str, Any]:
    metrics, value = benchmark_call(
        operation,
        warmup=warmup,
        iterations=iterations,
    )
    peak_bytes = memory_peak(operation)

    return {
        "name": name,
        "metrics": metrics,
        "peak_tracemalloc_bytes": peak_bytes,
        "result_type": type(value).__name__,
    }


def print_case(case: dict[str, Any]) -> None:
    metrics = case["metrics"]
    print(
        f"{case['name']:<46} "
        f"median={metrics['median_ns'] / 1_000:.1f} us "
        f"p95={metrics['p95_ns'] / 1_000:.1f} us "
        f"p99={metrics['p99_ns'] / 1_000:.1f} us "
        f"ops/s={metrics['operations_per_second']:.1f} "
        f"peak={case['peak_tracemalloc_bytes'] / 1024:.1f} KiB"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark AGP TPE 2.0 policy validation."
    )
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument(
        "--large-iterations",
        type=int,
        default=200,
        help="iterations for 100 and 1000 requirement policies",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write JSON result to this path",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        help="also write this run as a baseline JSON",
    )
    args = parser.parse_args()

    for value, label in [
        (args.warmup, "warmup"),
        (args.iterations, "iterations"),
        (args.large_iterations, "large-iterations"),
    ]:
        if value < 1:
            parser.error(f"--{label} must be at least 1")

    evaluator = load_evaluator()
    cases: list[dict[str, Any]] = []

    fixture_policies = {
        name: read_policy(name)
        for name in DEFAULT_FIXTURES
    }

    for fixture_name, policy in fixture_policies.items():
        case = run_case(
            f"validate:{fixture_name.removesuffix('.json')}",
            lambda policy=policy: evaluator.validate_policy(policy),
            warmup=args.warmup,
            iterations=args.iterations,
        )
        print_case(case)
        cases.append(case)

    source = fixture_policies["valid_constraints.json"]
    for requirement_count in [1, 10, 100, 1000]:
        policy = scaled_policy(source, requirement_count)
        iterations = (
            args.iterations
            if requirement_count <= 10
            else args.large_iterations
        )
        case = run_case(
            f"validate:scaled:{requirement_count:04d}-requirements",
            lambda policy=policy: evaluator.validate_policy(policy),
            warmup=min(args.warmup, max(10, iterations // 2)),
            iterations=iterations,
        )
        print_case(case)
        cases.append(case)

    report = {
        "format": "agp-tpe-v2-benchmark",
        "format_version": 1,
        "metadata": machine_metadata(),
        "configuration": {
            "warmup": args.warmup,
            "iterations": args.iterations,
            "large_iterations": args.large_iterations,
        },
        "cases": cases,
    }

    encoded = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"

    for output in [args.output, args.write_baseline]:
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded, encoding="utf-8")
            print(f"WROTE {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
