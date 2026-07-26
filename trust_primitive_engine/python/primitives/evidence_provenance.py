"""Deterministic Decision Context 3 evidence provenance predicates."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$")
EVIDENCE_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,123}[a-z0-9]/[1-9][0-9]*$"
)
MAX_SET_SIZE = 64


def _validate_requirement_id(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValueError("requirements[].requirement_id is not a valid identifier")
    return value


def _validate_exact_members(value, required, optional, primitive_type):
    unknown = sorted(set(value) - (required | optional))
    missing = sorted(required - set(value))
    if unknown:
        raise ValueError(f"{primitive_type} unknown members: {unknown}")
    if missing:
        raise ValueError(f"{primitive_type} missing members: {missing}")


def _validate_set(value, *, field, pattern):
    if not isinstance(value, list):
        raise ValueError(f"requirements[].{field} must be an array")
    if not 1 <= len(value) <= MAX_SET_SIZE:
        raise ValueError(f"requirements[].{field} must contain between 1 and 64 entries")
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        raise ValueError(f"requirements[].{field} contains an invalid value")
    if value != sorted(value):
        raise ValueError(f"requirements[].{field} must be in canonical order")
    if len(value) != len(set(value)):
        raise ValueError(f"requirements[].{field} must not contain duplicates")
    return list(value)


def _context(state):
    context = state.decision_context
    if not isinstance(context, Mapping):
        return "unavailable", ()
    if context.get("object_type") != "agp.decision-context/3":
        return "unavailable", ()
    manifest = context.get("evidence", ())
    return "available", manifest if isinstance(manifest, tuple) else ()


def _entries(manifest, issuer_ids=None, evidence_types=None):
    unique = {}
    for raw in manifest:
        if not isinstance(raw, Mapping):
            continue
        evidence_id = raw.get("id")
        issuer_id = raw.get("issuer_id")
        evidence_type = raw.get("evidence_type")
        if not all(isinstance(x, str) for x in (evidence_id, issuer_id, evidence_type)):
            continue
        unique.setdefault(evidence_id, (evidence_id, issuer_id, evidence_type))
    result = []
    for evidence_id in sorted(unique):
        entry = unique[evidence_id]
        if issuer_ids is not None and entry[1] not in issuer_ids:
            continue
        if evidence_types is not None and entry[2] not in evidence_types:
            continue
        result.append(entry)
    return result


def _observed(status, entries):
    return {
        "provenance_status": status,
        "evidence_ids": sorted({e[0] for e in entries}),
        "issuer_ids": sorted({e[1] for e in entries}),
        "evidence_types": sorted({e[2] for e in entries}),
    }


class EvidenceIssuerInPrimitive(Primitive):
    TYPE = "evidence_issuer_in"

    def validate(self, value):
        _validate_exact_members(
            value,
            {"requirement_id", "type", "issuer_ids"},
            {"evidence_types"},
            self.TYPE,
        )
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        normalized = {
            "requirement_id": _validate_requirement_id(value["requirement_id"]),
            "type": self.TYPE,
            "issuer_ids": _validate_set(
                value["issuer_ids"], field="issuer_ids", pattern=IDENTIFIER_RE
            ),
        }
        if "evidence_types" in value:
            normalized["evidence_types"] = _validate_set(
                value["evidence_types"],
                field="evidence_types",
                pattern=EVIDENCE_TYPE_RE,
            )
        return normalized

    def evaluate(self, requirement, state):
        status, manifest = _context(state)
        matched = _entries(
            manifest,
            issuer_ids=set(requirement["issuer_ids"]),
            evidence_types=(
                set(requirement["evidence_types"])
                if "evidence_types" in requirement
                else None
            ),
        )
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observed(status, matched),
            expected={
                "issuer_ids": requirement["issuer_ids"],
                "evidence_types": requirement.get("evidence_types"),
            },
        )
        if status == "available" and matched:
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs, failure_code="EVIDENCE_ISSUER_NOT_ALLOWED"
        )


class EvidenceTypeInPrimitive(Primitive):
    TYPE = "evidence_type_in"

    def validate(self, value):
        _validate_exact_members(
            value,
            {"requirement_id", "type", "evidence_types"},
            {"issuer_ids"},
            self.TYPE,
        )
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        normalized = {
            "requirement_id": _validate_requirement_id(value["requirement_id"]),
            "type": self.TYPE,
            "evidence_types": _validate_set(
                value["evidence_types"],
                field="evidence_types",
                pattern=EVIDENCE_TYPE_RE,
            ),
        }
        if "issuer_ids" in value:
            normalized["issuer_ids"] = _validate_set(
                value["issuer_ids"], field="issuer_ids", pattern=IDENTIFIER_RE
            )
        return normalized

    def evaluate(self, requirement, state):
        status, manifest = _context(state)
        matched = _entries(
            manifest,
            issuer_ids=(
                set(requirement["issuer_ids"])
                if "issuer_ids" in requirement
                else None
            ),
            evidence_types=set(requirement["evidence_types"]),
        )
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observed(status, matched),
            expected={
                "evidence_types": requirement["evidence_types"],
                "issuer_ids": requirement.get("issuer_ids"),
            },
        )
        if status == "available" and matched:
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs, failure_code="EVIDENCE_TYPE_NOT_ALLOWED"
        )


class EvidenceDistinctIssuersAtLeastPrimitive(Primitive):
    TYPE = "evidence_distinct_issuers_at_least"

    def validate(self, value):
        _validate_exact_members(
            value,
            {"requirement_id", "type", "minimum"},
            {"evidence_types"},
            self.TYPE,
        )
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        minimum = value["minimum"]
        if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= 256:
            raise ValueError("requirements[].minimum must be an integer between 1 and 256")
        normalized = {
            "requirement_id": _validate_requirement_id(value["requirement_id"]),
            "type": self.TYPE,
            "minimum": minimum,
        }
        if "evidence_types" in value:
            normalized["evidence_types"] = _validate_set(
                value["evidence_types"],
                field="evidence_types",
                pattern=EVIDENCE_TYPE_RE,
            )
        return normalized

    def evaluate(self, requirement, state):
        status, manifest = _context(state)
        matched = _entries(
            manifest,
            evidence_types=(
                set(requirement["evidence_types"])
                if "evidence_types" in requirement
                else None
            ),
        )
        issuer_ids = sorted({e[1] for e in matched})
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed={
                "provenance_status": status,
                "count": len(issuer_ids),
                "issuer_ids": issuer_ids,
                "evidence_ids": sorted({e[0] for e in matched}),
            },
            expected={
                "minimum": requirement["minimum"],
                "evidence_types": requirement.get("evidence_types"),
            },
        )
        if status == "available" and len(issuer_ids) >= requirement["minimum"]:
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs,
            failure_code="EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED",
        )
