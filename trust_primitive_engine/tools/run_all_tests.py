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
        "TPE mixed composition frozen coverage guard",
        ROOT
        / "trust_primitive_engine"
        / "tools"
        / "test_tpe_go_mixed_composition_coverage.py",
        24,
    ),
    (
        "TPE Python/Go mixed composition evaluation parity",
        ROOT
        / "trust_primitive_engine"
        / "tools"
        / "test_tpe_go_mixed_composition_evaluation.py",
        12,
    ),
    (
        "TPE Python/Go leaf primitive evaluation parity",
        ROOT
        / "trust_primitive_engine"
        / "tools"
        / "test_tpe_go_leaf_primitive_evaluation.py",
        54,
    ),
    (
        "TPE Python/Go leaf primitive inventory",
        ROOT
        / "trust_primitive_engine"
        / "tools"
        / "test_tpe_go_leaf_primitive_inventory.py",
        1,
    ),
    (
        "TPE 2.6 Python/Go frozen-profile reproduction",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_reproduction.py",
        7,
    ),
    (
        "TPE 2.6 Python/Go requirement validation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_validation.py",
        27,
    ),
    (
        "TPE 2.6 Python/Go leaf-policy validation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_policy_validation.py",
        22,
    ),
    (
        "TPE 2.6 Python/Go composition validation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_composition_validation.py",
        20,
    ),
    (
        "TPE 2.6 Python/Go composition evaluation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_composition_evaluation.py",
        12,
    ),
    (
        "TPE Python/Go mixed policy-reference evaluation parity",
        ROOT
        / "trust_primitive_engine"
        / "tools"
        / "test_tpe_go_mixed_policy_reference_evaluation.py",
        12,
    ),
    (
        "TPE 2.6 Python/Go composition + policy-reference evaluation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_composition_policy_reference_evaluation.py",
        8,
    ),
    (
        "TPE 2.6 Python/Go policy-reference graph validation parity",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe26_go_policy_reference_graph_validation.py",
        13,
    ),
    (
        "public Python API",
        ROOT / "trust_primitive_engine/tools/test_public_api.py",
        9,
    ),
    (
        "stable public Go API contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe_go_public_api_contract.py",
        12,
    ),
    (
        "public Go vanity import metadata",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_tpe_go_vanity_import_metadata.py",
        4,
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
        "Trust Primitive Engine Go v0.2.2 release contract",
        ROOT / "trust_primitive_engine/tools/test_tpe_go_v022_release_contract.py",
        7,
    ),
    (
        "public Go release alignment",
        ROOT / "trust_primitive_engine/tools/test_public_go_release_alignment.py",
        6,
    ),
    (
        "public Go signed end-to-end integration",
        ROOT / "trust_primitive_engine/tools/test_public_go_signed_end_to_end.py",
        8,
    ),
    (
        "Signed Decision Context Go public API contract",
        ROOT / "signed_decision_context/tools/test_sdc_go_public_api_contract.py",
        8,
    ),
    (
        "Signed Decision Context Go signer parity",
        ROOT / "signed_decision_context/tools/run_go_signer_parity.py",
        4,
    ),
    (
        "Go release integrity contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_go_release_integrity_contract.py",
        8,
    ),
    (
        "GitHub Actions runtime contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_actions_runtime_contract.py",
        9,
    ),
    (
        "GitHub Actions supply-chain contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_actions_supply_chain_contract.py",
        8,
    ),
    (
        "official Actions pinning contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_official_actions_pinning_contract.py",
        8,
    ),
    (
        "Actions execution bounds contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_actions_execution_bounds_contract.py",
        10,
    ),
    (
        "CI runtime reproducibility contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_ci_runtime_reproducibility_contract.py",
        10,
    ),
    (
        "Python dependency reproducibility contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_python_dependency_reproducibility_contract.py",
        12,
    ),
    (
        "Python transitive lock contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_python_transitive_lock_contract.py",
        14,
    ),
    (
        "Go module dependency integrity contract",
        ROOT
        / "trust_primitive_engine/tools/"
        "test_go_module_dependency_integrity_contract.py",
        12,
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
