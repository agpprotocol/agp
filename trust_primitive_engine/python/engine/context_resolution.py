"""Restricted deterministic Decision Context projection and lookup."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_CONTEXT_PATH_LENGTH = 512
MAX_CONTEXT_PATH_SEGMENTS = 16
_CONTEXT_PATH_PREFIX = "/proposal/payload/"


class ContextPathError(ValueError):
    """Raised when a restricted context path is structurally invalid."""


@dataclass(frozen=True)
class ContextResolution:
    """Deterministic result of one restricted context lookup."""

    status: str
    value_type: str | None
    value: Any = None

    def __post_init__(self) -> None:
        if self.status not in {"found", "missing", "type_mismatch"}:
            raise ValueError(
                f"unsupported context resolution status: {self.status!r}"
            )

        if self.status != "found":
            if self.value_type is not None or self.value is not None:
                raise ValueError(
                    "non-found context resolutions cannot carry values"
                )


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze_json(item)
                for key, item in value.items()
            }
        )

    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)

    if value is None or isinstance(value, (bool, int, str)):
        return value

    raise TypeError(
        "Decision Context projection contains an unsupported "
        f"value type: {type(value).__name__}"
    )


def create_context_projection(
    decision_context: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Detach and deeply freeze the TPE 2.4-readable context subset."""

    if decision_context is None:
        return None

    if not isinstance(decision_context, Mapping):
        raise TypeError("decision_context must be a mapping or None")

    has_proposal = "proposal" in decision_context
    has_evidence = "evidence" in decision_context

    if not has_proposal and not has_evidence:
        return None

    if has_proposal != has_evidence:
        raise ValueError(
            "decision_context must contain both proposal and evidence"
        )

    proposal = decision_context.get("proposal")
    evidence = decision_context.get("evidence")

    if not isinstance(proposal, Mapping):
        raise ValueError("decision_context.proposal must be a mapping")

    payload = proposal.get("payload")

    if not isinstance(payload, Mapping):
        raise ValueError(
            "decision_context.proposal.payload must be a mapping"
        )

    if not isinstance(evidence, (list, tuple)):
        raise ValueError("decision_context.evidence must be an array")

    object_type = decision_context.get("object_type")
    if object_type is not None and not isinstance(object_type, str):
        raise ValueError("decision_context.object_type must be a string")

    projected = {
        "proposal": {"payload": payload},
        "evidence": evidence,
    }
    if object_type is not None:
        projected["object_type"] = object_type

    frozen = _freeze_json(projected)

    if not isinstance(frozen, Mapping):
        raise AssertionError("context projection did not freeze as mapping")

    return frozen


def _decode_segment(segment: str) -> str:
    output: list[str] = []
    index = 0

    while index < len(segment):
        character = segment[index]

        if character != "~":
            output.append(character)
            index += 1
            continue

        if index + 1 >= len(segment):
            raise ContextPathError(
                "context path contains an incomplete escape"
            )

        escaped = segment[index + 1]

        if escaped == "0":
            output.append("~")
        elif escaped == "1":
            output.append("/")
        else:
            raise ContextPathError(
                "context path contains an unsupported escape"
            )

        index += 2

    return "".join(output)


def _validate_index_like_segment(segment: str) -> None:
    if segment == "-":
        raise ContextPathError(
            "context path array append token is forbidden"
        )

    if segment.startswith("-") and segment[1:].isdigit():
        raise ContextPathError(
            "context path negative indexes are forbidden"
        )

    if not segment.isdigit():
        return

    if len(segment) > 1 and segment.startswith("0"):
        raise ContextPathError(
            "context path array indexes must be canonical"
        )

    if int(segment, 10) > MAX_SAFE_INTEGER:
        raise ContextPathError(
            "context path array index exceeds safe integer"
        )


def parse_context_path(path: str) -> tuple[str, ...]:
    """Validate and decode one restricted proposal-payload path."""

    if not isinstance(path, str):
        raise ContextPathError("context path must be a string")

    if (
        len(path) < len(_CONTEXT_PATH_PREFIX)
        or len(path) > MAX_CONTEXT_PATH_LENGTH
    ):
        raise ContextPathError(
            "context path length is outside the allowed range"
        )

    if not path.startswith(_CONTEXT_PATH_PREFIX):
        raise ContextPathError(
            "context path must begin with /proposal/payload/"
        )

    encoded_segments = path[len(_CONTEXT_PATH_PREFIX):].split("/")

    if (
        not encoded_segments
        or any(segment == "" for segment in encoded_segments)
    ):
        raise ContextPathError(
            "context path must contain non-empty descendant segments"
        )

    if len(encoded_segments) > MAX_CONTEXT_PATH_SEGMENTS:
        raise ContextPathError(
            "context path exceeds maximum descendant segments"
        )

    decoded: list[str] = []

    for encoded in encoded_segments:
        segment = _decode_segment(encoded)

        if segment == "":
            raise ContextPathError(
                "context path decoded to an empty segment"
            )

        _validate_index_like_segment(segment)
        decoded.append(segment)

    return ("proposal", "payload", *decoded)


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"

    raise TypeError(
        f"unsupported projected context value: {type(value).__name__}"
    )


def resolve_context_path(
    decision_context: Mapping[str, Any] | None,
    path: str,
) -> ContextResolution:
    """Resolve one validated restricted path deterministically."""

    segments = parse_context_path(path)

    if decision_context is None:
        return ContextResolution("missing", None, None)

    current: Any = decision_context

    for segment in segments:
        if isinstance(current, Mapping):
            if segment not in current:
                return ContextResolution("missing", None, None)
            current = current[segment]
            continue

        if isinstance(current, (list, tuple)):
            if not segment.isdigit():
                return ContextResolution("type_mismatch", None, None)

            index = int(segment, 10)

            if index >= len(current):
                return ContextResolution("missing", None, None)

            current = current[index]
            continue

        return ContextResolution("type_mismatch", None, None)

    return ContextResolution(
        "found",
        _value_type(current),
        current,
    )
