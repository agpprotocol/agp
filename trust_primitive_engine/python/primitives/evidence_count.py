"""Deterministic minimum evidence-manifest cardinality primitive."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from engine import EvaluationState, Primitive, PrimitiveResult
from primitives.evidence_present import MEDIA_TYPE_RE, _validate_identifier

MINIMUM_COUNT = 1
MAXIMUM_COUNT = 256
FAILURE_CODE = "EVIDENCE_COUNT_NOT_REACHED"
REQUIRED_MEMBERS = {"requirement_id", "type", "minimum"}
OPTIONAL_MEMBERS = {"media_type"}
ALLOWED_MEMBERS = REQUIRED_MEMBERS | OPTIONAL_MEMBERS

class EvidenceCountAtLeastPrimitive(Primitive):
    TYPE = "evidence_count_at_least"

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - ALLOWED_MEMBERS)
        missing = sorted(REQUIRED_MEMBERS - set(value))
        if unknown:
            raise ValueError(f"{self.TYPE} unknown members: {unknown}")
        if missing:
            raise ValueError(f"{self.TYPE} missing members: {missing}")
        requirement_id = _validate_identifier(value["requirement_id"], "requirement_id")
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        minimum = value["minimum"]
        if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= 256:
            raise ValueError("requirements[].minimum must be an integer between 1 and 256")
        normalized = {"requirement_id": requirement_id, "type": self.TYPE, "minimum": minimum}
        if "media_type" in value:
            media_type = value["media_type"]
            if not isinstance(media_type, str) or not MEDIA_TYPE_RE.fullmatch(media_type):
                raise ValueError("requirements[].media_type is invalid")
            normalized["media_type"] = media_type
        return normalized

    def evaluate(self, requirement: dict[str, Any], state: EvaluationState) -> PrimitiveResult:
        context = state.decision_context
        manifest = context.get("evidence", ()) if isinstance(context, Mapping) else ()
        media_type_filter = requirement.get("media_type")
        media_types_by_id: dict[str, set[str]] = {}
        for entry in manifest:
            if not isinstance(entry, Mapping):
                continue
            evidence_id = entry.get("id")
            media_type = entry.get("media_type")
            if not isinstance(evidence_id, str):
                continue
            bucket = media_types_by_id.setdefault(evidence_id, set())
            if isinstance(media_type, str):
                bucket.add(media_type)
        if media_type_filter is None:
            evidence_ids = sorted(media_types_by_id)
        else:
            evidence_ids = sorted(eid for eid, types in media_types_by_id.items() if media_type_filter in types)
        observed = {"count": len(evidence_ids), "evidence_ids": evidence_ids}
        expected = {"minimum": requirement["minimum"], "media_type": media_type_filter}
        kwargs = dict(requirement_id=requirement["requirement_id"], primitive_type=self.TYPE, matched_signers=[], observed=observed, expected=expected)
        if len(evidence_ids) >= requirement["minimum"]:
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(**kwargs, failure_code=FAILURE_CODE)
