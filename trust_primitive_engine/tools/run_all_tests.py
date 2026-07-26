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
        16,
    ),
    (
        "context projection and resolution",
        ROOT / "trust_primitive_engine/tools/test_context_resolution.py",
        20,
    ),
    (
        "context value primitives",
        ROOT / "trust_primitive_engine/tools/test_context_value_primitives.py",
        36,
    ),
    (
        "evidence_present primitive",
        ROOT / "trust_primitive_engine/tools/test_evidence_present_primitive.py",
        32,
    ),
    (
        "TPE 2.5 contextual predicates",
        ROOT / "trust_primitive_engine/tools/test_contextual_predicates.py",
        32,
    ),
    (
        "TPE 2.5 evidence count",
        ROOT / "trust_primitive_engine/tools/test_evidence_count_at_least.py",
        34,
    ),
    (
        "TPE 2.6 evidence provenance predicates",
        ROOT / "trust_primitive_engine/tools/test_evidence_provenance_predicates.py",
        9,
    ),
    (
        "TPE 2.5 formal integration",
        ROOT / "trust_primitive_engine/tools/test_tpe25_integration.py",
        12,
    ),
    (
        "TPE 2.6 formal integration",
        ROOT / "trust_primitive_engine/tools/test_tpe26_integration.py",
        14,
    ),
    (
        "policy-tree validation",
        ROOT / "trust_primitive_engine/tools/test_policy_tree_validation.py",
        20,
    ),
    (
        "composition evaluation",
        ROOT / "trust_primitive_engine/tools/test_composition_evaluation.py",
        17,
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
        26,
    ),
    (
        "primitive validation matrix",
        ROOT / "trust_primitive_engine/tools/test_primitive_schema_runtime_matrix.py",
        152,
    ),
    (
        "property hardening",
        ROOT / "trust_primitive_engine/tools/test_property_hardening.py",
        8,
    ),
    (
        "golden compatibility corpus",
        ROOT / "trust_primitive_engine/tools/test_golden_policy_corpus.py",
        22,
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
    (
        "policy-set indexing",
        ROOT / "trust_primitive_engine/tools/test_policy_set_indexing.py",
        8,
    ),
    (
        "policy-reference validation",
        ROOT / "trust_primitive_engine/tools/test_policy_reference_validation.py",
        15,
    ),
    (
        "policy-reference resolution",
        ROOT / "trust_primitive_engine/tools/test_policy_reference_resolution.py",
        8,
    ),
    (
        "policy-reference graph validation",
        ROOT / "trust_primitive_engine/tools/test_policy_reference_graph.py",
        11,
    ),
    (
        "structural dispatcher",
        ROOT / "trust_primitive_engine/tools/test_structural_dispatcher.py",
        6,
    ),
    (
        "recursive policy evaluation",
        ROOT / "trust_primitive_engine/tools/test_recursive_policy_evaluation.py",
        13,
    ),
    (
        "recursive policy failure projection",
        ROOT / "trust_primitive_engine/tools/test_recursive_policy_failure_projection.py",
        12,
    ),
    (
        "verified policy-set evaluation",
        ROOT / "trust_primitive_engine/tools/test_verified_policy_set_evaluation.py",
        9,
    ),
    (
        "policy-set CLI",
        ROOT / "trust_primitive_engine/tools/test_policy_set_cli.py",
        5,
    ),
    (
        "policy-reference conformance corpus",
        ROOT / "trust_primitive_engine/tools/test_policy_reference_conformance_corpus.py",
        8,
    ),
    (
        "TPE 2.4 context/evidence golden corpus",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe24_context_evidence_golden_corpus.py",
        10,
    ),
    (
        "TPE 2.5 contextual predicates golden corpus",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe25_golden_corpus.py",
        5,
    ),
    (
        "TPE 2.6 evidence provenance golden corpus",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_golden_corpus.py",
        7,
    ),
    (
        "public Python API",
        ROOT / "trust_primitive_engine/tools/test_public_api.py",
        9,
    ),
    (
        "TPE 2.6 external reproduction",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_external_reproduction.py",
        2,
    ),
    (
        "external package integration",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_external_package_integration.py",
        1,
    ),
    (
        "package installation and schema audit",
        ROOT / "trust_primitive_engine/tools/test_package_install.py",
        4,
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
    print(f"AGP TPE 2.6 development validation: {total}/{total} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
