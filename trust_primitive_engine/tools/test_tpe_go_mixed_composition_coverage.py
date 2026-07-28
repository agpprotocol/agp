#!/usr/bin/env python3
"""Guard the frozen mixed-composition parity corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine"
MANIFEST = (
    TPE
    / "fixtures"
    / "parity"
    / "mixed-compositions"
    / "manifest.json"
)
COMPOSITION_TEST = (
    TPE
    / "tools"
    / "test_tpe_go_mixed_composition_evaluation.py"
)
REFERENCE_TEST = (
    TPE
    / "tools"
    / "test_tpe_go_mixed_policy_reference_evaluation.py"
)


class TestFailure(Exception):
    pass


def load_module(name: str, path: Path) -> Any:
    tools = str(path.parent)
    if tools not in sys.path:
        sys.path.insert(0, tools)

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise TestFailure(f"could not load {path.name}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def contains_type(value: Any, expected_type: str) -> bool:
    if isinstance(value, dict):
        if value.get("type") == expected_type:
            return True
        return any(
            contains_type(item, expected_type)
            for item in value.values()
        )

    if isinstance(value, (list, tuple)):
        return any(
            contains_type(item, expected_type)
            for item in value
        )

    return False


def declared_vectors(
    suite: dict[str, Any],
) -> list[tuple[str, str]]:
    entries = suite.get("vectors")
    if not isinstance(entries, list):
        raise TestFailure("suite vectors must be an array")

    result: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise TestFailure("vector declaration must be an object")

        name = entry.get("name")
        status = entry.get("expected_status")

        if not isinstance(name, str) or not name:
            raise TestFailure("invalid vector name")

        if status not in {"satisfied", "unsatisfied"}:
            raise TestFailure(f"{name}: invalid expected_status")

        result.append((name, status))

    if suite.get("vector_count") != len(result):
        raise TestFailure(
            f"{suite.get('id')}: vector_count does not match"
        )

    return result


def observed_vectors(
    module: Any,
    suite_id: str,
) -> tuple[list[tuple[str, str]], list[Any]]:
    if suite_id == "mixed_composition":
        vectors = module.vectors()
    elif suite_id == "mixed_policy_reference":
        evaluator = module.load_evaluator()
        vectors = module.build_vectors(evaluator)
    else:
        raise TestFailure(f"unknown suite id: {suite_id}")

    observed = [
        (vector.name, vector.expected_status)
        for vector in vectors
    ]
    return observed, vectors


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    if manifest.get("object_type") != (
        "agp.tpe-python-go-mixed-composition-manifest/1"
    ):
        raise TestFailure("invalid manifest object_type")

    suites = manifest.get("suites")
    if not isinstance(suites, list) or len(suites) != 2:
        raise TestFailure("exactly two suites are required")

    modules = {
        "mixed_composition": load_module(
            "agp_tpe_guard_mixed_composition",
            COMPOSITION_TEST,
        ),
        "mixed_policy_reference": load_module(
            "agp_tpe_guard_mixed_reference",
            REFERENCE_TEST,
        ),
    }

    all_names: list[str] = []
    total = 0

    for suite in suites:
        suite_id = suite.get("id")
        if suite_id not in modules:
            raise TestFailure(f"invalid suite id: {suite_id}")

        declared = declared_vectors(suite)
        observed, vectors = observed_vectors(
            modules[suite_id],
            suite_id,
        )

        if declared != observed:
            raise TestFailure(
                f"{suite_id}: manifest differs from executable corpus"
            )

        for vector in vectors:
            has_reference = contains_type(
                vector.requirements
                if suite_id == "mixed_composition"
                else vector.root,
                "policy_reference",
            )

            if suite_id == "mixed_composition" and has_reference:
                raise TestFailure(
                    f"{vector.name}: unexpected policy_reference"
                )

            if (
                suite_id == "mixed_policy_reference"
                and not has_reference
            ):
                raise TestFailure(
                    f"{vector.name}: missing policy_reference"
                )

        statuses = {status for _, status in observed}
        if statuses != {"satisfied", "unsatisfied"}:
            raise TestFailure(
                f"{suite_id}: both statuses are required"
            )

        all_names.extend(name for name, _ in observed)
        total += len(observed)

        print(
            f"PASS  {suite_id:<28} "
            f"{len(observed)}/{len(observed)} frozen"
        )

    if len(all_names) != len(set(all_names)):
        raise TestFailure("vector names must be globally unique")

    if total != 24 or manifest.get("vector_count") != total:
        raise TestFailure(
            f"expected 24 frozen vectors, got {total}"
        )

    print(
        "TPE mixed composition frozen coverage guard: "
        f"{total}/{total} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}")
        raise SystemExit(1)
