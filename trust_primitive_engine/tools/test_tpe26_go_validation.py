#!/usr/bin/env python3
# Python/Go validation parity for the three TPE 2.6 predicates.

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine/python"
GO_DIR = ROOT / "trust_primitive_engine/go"
sys.path.insert(0, str(TPE))

from primitives.evidence_provenance import (  # noqa: E402
    EvidenceDistinctIssuersAtLeastPrimitive,
    EvidenceIssuerInPrimitive,
    EvidenceTypeInPrimitive,
)


@dataclass(frozen=True)
class Vector:
    name: str
    requirement: dict[str, Any]
    accepted: bool


def vectors() -> list[Vector]:
    sixty_five = [f"authority:{index:03d}" for index in range(65)]
    return [
        Vector("issuer_valid_minimal", {
            "requirement_id": "requirement:issuer-valid",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
        }, True),
        Vector("type_valid_minimal", {
            "requirement_id": "requirement:type-valid",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
        }, True),
        Vector("distinct_valid_minimal", {
            "requirement_id": "requirement:distinct-valid",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 1,
        }, True),
        Vector("issuer_missing_issuer_ids", {
            "requirement_id": "requirement:issuer-missing",
            "type": "evidence_issuer_in",
        }, False),
        Vector("issuer_unknown_member", {
            "requirement_id": "requirement:issuer-unknown",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
            "unknown": True,
        }, False),
        Vector("issuer_wrong_type_constant", {
            "requirement_id": "requirement:issuer-wrong-type",
            "type": "evidence_type_in",
            "issuer_ids": ["authority:lab-a"],
        }, False),
        Vector("issuer_invalid_requirement_id", {
            "requirement_id": "INVALID ID",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
        }, False),
        Vector("issuer_empty_set", {
            "requirement_id": "requirement:issuer-empty",
            "type": "evidence_issuer_in",
            "issuer_ids": [],
        }, False),
        Vector("issuer_set_above_64", {
            "requirement_id": "requirement:issuer-large",
            "type": "evidence_issuer_in",
            "issuer_ids": sixty_five,
        }, False),
        Vector("issuer_duplicate", {
            "requirement_id": "requirement:issuer-duplicate",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a", "authority:lab-a"],
        }, False),
        Vector("issuer_unordered", {
            "requirement_id": "requirement:issuer-unordered",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:z", "authority:a"],
        }, False),
        Vector("issuer_invalid_value", {
            "requirement_id": "requirement:issuer-invalid",
            "type": "evidence_issuer_in",
            "issuer_ids": ["INVALID"],
        }, False),
        Vector("issuer_evidence_types_wrong_type", {
            "requirement_id": "requirement:issuer-filter-type",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
            "evidence_types": "security:assessment/1",
        }, False),
        Vector("issuer_invalid_evidence_type", {
            "requirement_id": "requirement:issuer-filter-invalid",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
            "evidence_types": ["Security:Assessment/1"],
        }, False),
        Vector("type_missing_evidence_types", {
            "requirement_id": "requirement:type-missing",
            "type": "evidence_type_in",
        }, False),
        Vector("type_unknown_member", {
            "requirement_id": "requirement:type-unknown",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
            "unknown": True,
        }, False),
        Vector("type_empty_set", {
            "requirement_id": "requirement:type-empty",
            "type": "evidence_type_in",
            "evidence_types": [],
        }, False),
        Vector("type_duplicate", {
            "requirement_id": "requirement:type-duplicate",
            "type": "evidence_type_in",
            "evidence_types": [
                "security:assessment/1",
                "security:assessment/1",
            ],
        }, False),
        Vector("type_unordered", {
            "requirement_id": "requirement:type-unordered",
            "type": "evidence_type_in",
            "evidence_types": ["security:z/1", "security:a/1"],
        }, False),
        Vector("type_invalid_evidence_type", {
            "requirement_id": "requirement:type-invalid",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment"],
        }, False),
        Vector("type_issuer_ids_wrong_type", {
            "requirement_id": "requirement:type-filter-type",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
            "issuer_ids": "authority:lab-a",
        }, False),
        Vector("distinct_missing_minimum", {
            "requirement_id": "requirement:distinct-missing",
            "type": "evidence_distinct_issuers_at_least",
        }, False),
        Vector("distinct_boolean_minimum", {
            "requirement_id": "requirement:distinct-boolean",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": True,
        }, False),
        Vector("distinct_zero", {
            "requirement_id": "requirement:distinct-zero",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 0,
        }, False),
        Vector("distinct_above_256", {
            "requirement_id": "requirement:distinct-large",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 257,
        }, False),
        Vector("distinct_decimal", {
            "requirement_id": "requirement:distinct-decimal",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 1.5,
        }, False),
        Vector("distinct_evidence_types_duplicate", {
            "requirement_id": "requirement:distinct-duplicate",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 1,
            "evidence_types": [
                "security:assessment/1",
                "security:assessment/1",
            ],
        }, False),
    ]


def python_accepts(requirement: dict[str, Any]) -> bool:
    primitive = {
        "evidence_issuer_in": EvidenceIssuerInPrimitive(),
        "evidence_type_in": EvidenceTypeInPrimitive(),
        "evidence_distinct_issuers_at_least":
            EvidenceDistinctIssuersAtLeastPrimitive(),
    }.get(requirement.get("type"))
    if primitive is None:
        return False
    try:
        primitive.validate(requirement)
    except (TypeError, ValueError, KeyError):
        return False
    return True


def main() -> int:
    cases = vectors()
    if len(cases) != 27:
        raise AssertionError(f"expected 27 vectors, got {len(cases)}")

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-validation-"
    ) as raw:
        temp = Path(raw)
        binary = temp / "agp-tpe26-reproduce"
        subprocess.run(
            [
                "go", "build", "-trimpath", "-o", str(binary),
                "./cmd/agp-tpe26-reproduce",
            ],
            cwd=GO_DIR,
            check=True,
        )

        passed = 0
        for index, vector in enumerate(cases):
            input_path = temp / f"{index:02d}-{vector.name}.json"
            input_path.write_text(
                json.dumps(
                    vector.requirement,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(binary),
                    "--validate-requirement",
                    str(input_path),
                ],
                cwd=temp,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"{vector.name}: Go command failed: "
                    f"{completed.stderr}"
                )

            go_accepted = json.loads(completed.stdout)["accepted"]
            py_accepted = python_accepts(vector.requirement)

            if py_accepted != vector.accepted:
                raise AssertionError(
                    f"{vector.name}: Python expected={vector.accepted} "
                    f"actual={py_accepted}"
                )
            if go_accepted != vector.accepted:
                raise AssertionError(
                    f"{vector.name}: Go expected={vector.accepted} "
                    f"actual={go_accepted}"
                )
            if py_accepted != go_accepted:
                raise AssertionError(
                    f"{vector.name}: Python/Go acceptance differs"
                )

            print(
                f"PASS  {vector.name:<38} "
                f"accepted={py_accepted} python_go=True"
            )
            passed += 1

        print(
            "TPE 2.6 Python/Go requirement validation parity: "
            f"{passed}/{len(cases)} passed"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
