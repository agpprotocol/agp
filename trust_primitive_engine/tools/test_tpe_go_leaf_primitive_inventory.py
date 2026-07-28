#!/usr/bin/env python3
"""Guard the complete Python/Go leaf primitive parity inventory."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine"
PYTHON_PRIMITIVES = TPE / "python/primitives"
GO_PRIMITIVES = TPE / "go/internal/primitives"
GO_VALIDATION = TPE / "go/internal/validation/validation.go"
MANIFEST = TPE / "fixtures/parity/leaf-primitives/manifest.json"

GO_TYPE_PATTERN = re.compile(
    r'(?:Type[A-Za-z0-9_]+|type[A-Za-z0-9_]+)\s*=\s*"([^"]+)"'
)

EXCLUDED_TYPES = {
    "all_of",
    "any_of",
    "not",
    "policy_reference",
}


class TestFailure(Exception):
    pass


def python_types() -> set[str]:
    discovered: set[str] = set()

    for path in sorted(PYTHON_PRIMITIVES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Constant):
                continue
            if not isinstance(node.value.value, str):
                continue

            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "TYPE"
                ):
                    discovered.add(node.value.value)

    return discovered


def go_types() -> set[str]:
    discovered: set[str] = set()

    paths = sorted(GO_PRIMITIVES.rglob("*.go"))
    paths.append(GO_VALIDATION)

    for path in paths:
        text = path.read_text(encoding="utf-8")
        discovered.update(GO_TYPE_PATTERN.findall(text))

    return discovered - EXCLUDED_TYPES


def manifest_types() -> tuple[list[str], dict[str, dict[str, str]]]:
    value = json.loads(MANIFEST.read_text(encoding="utf-8"))

    if value.get("object_type") != (
        "agp.tpe-python-go-leaf-parity-manifest/1"
    ):
        raise TestFailure("invalid manifest object_type")

    entries = value.get("primitives")
    if not isinstance(entries, list):
        raise TestFailure("manifest primitives must be an array")

    types: list[str] = []
    cases: dict[str, dict[str, str]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            raise TestFailure("manifest primitive must be an object")

        primitive_type = entry.get("type")
        if not isinstance(primitive_type, str) or not primitive_type:
            raise TestFailure("manifest primitive type is invalid")

        primitive_cases = entry.get("cases")
        if not isinstance(primitive_cases, dict):
            raise TestFailure(
                f"{primitive_type}: cases must be an object"
            )

        if set(primitive_cases) != {"satisfied", "unsatisfied"}:
            raise TestFailure(
                f"{primitive_type}: exact satisfied/unsatisfied "
                "case declarations required"
            )

        for outcome, name in primitive_cases.items():
            if not isinstance(name, str) or not name:
                raise TestFailure(
                    f"{primitive_type}: invalid {outcome} case name"
                )

        types.append(primitive_type)
        cases[primitive_type] = primitive_cases

    if types != sorted(types):
        raise TestFailure("manifest primitive types are not sorted")

    if len(types) != len(set(types)):
        raise TestFailure("manifest primitive types contain duplicates")

    if value.get("primitive_count") != len(types):
        raise TestFailure("manifest primitive_count does not match")

    return types, cases


def difference(
    label: str,
    expected: set[str],
    actual: set[str],
) -> None:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)

    if missing or extra:
        raise TestFailure(
            f"{label} differs: missing={missing} extra={extra}"
        )


def main() -> int:
    python = python_types()
    go = go_types()
    manifest_list, cases = manifest_types()
    manifest = set(manifest_list)

    difference("Python/manifest inventory", manifest, python)
    difference("Go/manifest inventory", manifest, go)
    difference("Python/Go inventory", python, go)

    if len(manifest) != 27:
        raise TestFailure(
            f"expected 27 leaf primitives, got {len(manifest)}"
        )

    for primitive_type in manifest_list:
        declared = cases[primitive_type]
        print(
            f"PASS  {primitive_type:<38} "
            f"satisfied={declared['satisfied']} "
            f"unsatisfied={declared['unsatisfied']}"
        )

    print(
        "TPE Python/Go leaf primitive inventory: "
        f"{len(manifest)}/{len(manifest)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}")
        raise SystemExit(1)
