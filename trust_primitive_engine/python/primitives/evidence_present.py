"""Deterministic evidence-manifest presence trust primitive."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
MEDIA_TYPE_RE = re.compile(
    r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"
)

REQUIRED_MEMBERS = {
    "requirement_id",
    "type",
    "evidence_id",
}
OPTIONAL_MEMBERS = {
    "digest",
    "media_type",
}
ALLOWED_MEMBERS = REQUIRED_MEMBERS | OPTIONAL_MEMBERS

FAILURE_CODE = (
    "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED"
)


def _validate_identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not IDENTIFIER_RE.fullmatch(value)
    ):
        raise ValueError(
            f"requirements[].{field} is not a valid identifier"
        )
    return value


class EvidencePresentPrimitive(Primitive):
    """Require one exact signed evidence-manifest declaration."""

    TYPE = "evidence_present"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - ALLOWED_MEMBERS)
        missing = sorted(REQUIRED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"{self.TYPE} unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"{self.TYPE} missing members: {missing}"
            )

        requirement_id = _validate_identifier(
            value["requirement_id"],
            "requirement_id",
        )
        evidence_id = _validate_identifier(
            value["evidence_id"],
            "evidence_id",
        )

        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")

        normalized: dict[str, Any] = {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "evidence_id": evidence_id,
        }

        if "digest" in value:
            digest = value["digest"]
            if (
                not isinstance(digest, str)
                or not DIGEST_RE.fullmatch(digest)
            ):
                raise ValueError(
                    "requirements[].digest must be "
                    "64 lowercase hexadecimal characters"
                )
            normalized["digest"] = digest

        if "media_type" in value:
            media_type = value["media_type"]
            if (
                not isinstance(media_type, str)
                or not MEDIA_TYPE_RE.fullmatch(media_type)
            ):
                raise ValueError(
                    "requirements[].media_type is invalid"
                )
            normalized["media_type"] = media_type

        return normalized

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        evidence_id = requirement["evidence_id"]
        context = state.decision_context
        manifest = (
            context.get("evidence", ())
            if isinstance(context, Mapping)
            else ()
        )

        matches = [
            entry
            for entry in manifest
            if (
                isinstance(entry, Mapping)
                and entry.get("id") == evidence_id
            )
        ]

        if len(matches) != 1:
            status = "absent"
            present = False
            observed_digest = None
            observed_media_type = None
        else:
            entry = matches[0]
            present = True
            observed_digest = entry.get("digest")
            observed_media_type = entry.get("media_type")

            digest_mismatch = (
                "digest" in requirement
                and observed_digest != requirement["digest"]
            )
            media_type_mismatch = (
                "media_type" in requirement
                and observed_media_type != requirement["media_type"]
            )

            if digest_mismatch and media_type_mismatch:
                status = "digest_and_media_type_mismatch"
            elif digest_mismatch:
                status = "digest_mismatch"
            elif media_type_mismatch:
                status = "media_type_mismatch"
            else:
                status = "matched"

        observed = {
            "evidence_id": evidence_id,
            "match_status": status,
            "present": present,
            "digest": observed_digest,
            "media_type": observed_media_type,
        }
        expected = {
            "evidence_id": evidence_id,
        }

        if "digest" in requirement:
            expected["digest"] = requirement["digest"]

        if "media_type" in requirement:
            expected["media_type"] = requirement["media_type"]

        if status == "matched":
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=[],
                observed=observed,
                expected=expected,
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=observed,
            expected=expected,
            failure_code=FAILURE_CODE,
        )
