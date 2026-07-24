#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SUITES = [
    (
        "engine core",
        ROOT / "trust_primitive_engine/tools/test_engine_core.py",
        5,
    ),
    (
        "conformance",
        ROOT / "trust_primitive_engine/tools/run_conformance.py",
        75,
    ),
    (
        "time window conformance",
        ROOT / "trust_primitive_engine/tools/run_time_window_conformance.py",
        11,
    ),
    (
        "schema/runtime parity",
        ROOT / "trust_primitive_engine/tools/test_schema_runtime_parity.py",
        12,
    ),
    (
        "primitive validation matrix",
        ROOT / "trust_primitive_engine/tools/test_primitive_schema_runtime_matrix.py",
        140,
    ),
    (
        "property hardening",
        ROOT / "trust_primitive_engine/tools/test_property_hardening.py",
        4,
    ),
    (
        "golden compatibility corpus",
        ROOT / "trust_primitive_engine/tools/test_golden_policy_corpus.py",
        14,
    ),
    (
        "mutation observability",
        ROOT / "trust_primitive_engine/tools/test_mutation_observability.py",
        6,
    ),
    (
        "byte stability corpus",
        ROOT / "trust_primitive_engine/tools/test_byte_stability_corpus.py",
        6,
    ),
    (
        "fuzz regression seeds",
        ROOT / "trust_primitive_engine/tools/test_fuzz_regression_seeds.py",
        6,
    ),
]


def main() -> int:
    total = 0

    for name, script, checks in SUITES:
        print("=" * 88, flush=True)
        print(f"RUN  {name}", flush=True)
        print("=" * 88, flush=True)

        completed = subprocess.run(
            [sys.executable, str(script)],
            cwd=ROOT,
            check=False,
        )

        if completed.returncode != 0:
            print(
                f"FAIL  {name} exited with code {completed.returncode}",
                file=sys.stderr,
            )
            return completed.returncode

        total += checks

    print("=" * 88)
    print(f"AGP TPE 2.0 complete validation: {total}/{total} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
