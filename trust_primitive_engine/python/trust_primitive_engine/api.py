"""Stable public Python API for AGP Trust Primitive Engine 2.3."""

from __future__ import annotations

import copy
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


PACKAGE_DIR = Path(__file__).resolve().parent
TPE_PYTHON = PACKAGE_DIR.parent
ROOT = TPE_PYTHON.parents[1]

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

SIGNED_CONTEXT_PYTHON = ROOT / "signed_decision_context" / "python"
if str(SIGNED_CONTEXT_PYTHON) not in sys.path:
    sys.path.insert(0, str(SIGNED_CONTEXT_PYTHON))

from evaluate_trust_policy_v2 import (  # noqa: E402
    EvaluationFailure,
    evaluate,
    policy_digest,
    validate_policy,
)
from engine import build_policy_set_index  # noqa: E402
from validate_signed_decision_context import ValidationFailure  # noqa: E402
from verify_signed_decision_context import VerificationFailure  # noqa: E402


_PACKAGED_SCHEMA_DIR = PACKAGE_DIR / "schemas"
_REPOSITORY_SCHEMA_DIR = ROOT / "registry" / "schemas"
DEFAULT_SCHEMA_DIR = (
    _PACKAGED_SCHEMA_DIR
    if _PACKAGED_SCHEMA_DIR.is_dir()
    else _REPOSITORY_SCHEMA_DIR
)


@dataclass(frozen=True, slots=True)
class TrustPolicyEvaluationError(Exception):
    """Fatal TPE input, verification, binding, or reference error."""

    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def _copy_mapping(
    value: Mapping[str, Any],
    *,
    name: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return copy.deepcopy(dict(value))


def _normalize_keyring(
    keyring: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    raw_keys: Any

    if isinstance(keyring, Mapping):
        if set(keyring) != {"keys"}:
            raise TypeError(
                "keyring mapping must contain exactly the 'keys' member"
            )
        raw_keys = keyring["keys"]
    else:
        raw_keys = keyring

    if isinstance(raw_keys, (str, bytes)) or not isinstance(
        raw_keys,
        Sequence,
    ):
        raise TypeError(
            "keyring must be a {'keys': [...]} mapping or a sequence"
        )

    normalized: list[dict[str, Any]] = []
    for position, entry in enumerate(raw_keys):
        if not isinstance(entry, Mapping):
            raise TypeError(
                f"keyring entry {position} must be a mapping"
            )
        normalized.append(copy.deepcopy(dict(entry)))

    return normalized


def _build_policy_set(
    policy_set: Sequence[Mapping[str, Any]] | None,
):
    if policy_set is None:
        return None

    if isinstance(policy_set, (str, bytes)) or not isinstance(
        policy_set,
        Sequence,
    ):
        raise TypeError("policy_set must be a sequence of policy mappings")

    raw_policy_set: list[dict[str, Any]] = []
    for position, policy in enumerate(policy_set):
        if not isinstance(policy, Mapping):
            raise TypeError(
                f"policy_set entry {position} must be a mapping"
            )
        raw_policy_set.append(copy.deepcopy(dict(policy)))

    try:
        return build_policy_set_index(
            raw_policy_set,
            validate_policy=validate_policy,
            compute_digest=policy_digest,
        )
    except ValueError as exc:
        raise TrustPolicyEvaluationError(
            "INVALID_TRUST_POLICY_SET",
            str(exc),
        ) from exc


def evaluate_trust_policy(
    *,
    signed_context: Mapping[str, Any],
    policy: Mapping[str, Any],
    keyring: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    policy_set: Sequence[Mapping[str, Any]] | None = None,
    schema_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Verify and evaluate one Trust Policy 2 object.

    Returns the same evaluation object emitted by the TPE CLI.

    Ordinary policy failure is returned as an ``unsatisfied`` evaluation.
    Fatal validation, verification, binding, policy-set, or reference errors
    raise :class:`TrustPolicyEvaluationError`.
    """

    normalized_context = _copy_mapping(
        signed_context,
        name="signed_context",
    )
    normalized_policy = _copy_mapping(policy, name="policy")
    normalized_keyring = _normalize_keyring(keyring)
    policy_set_index = _build_policy_set(policy_set)
    resolved_schema_dir = (
        DEFAULT_SCHEMA_DIR
        if schema_dir is None
        else Path(schema_dir)
    )

    try:
        return evaluate(
            normalized_context,
            normalized_policy,
            normalized_keyring,
            resolved_schema_dir,
            policy_set_index=policy_set_index,
        )
    except EvaluationFailure as exc:
        raise TrustPolicyEvaluationError(
            exc.code,
            exc.detail,
        ) from exc
    except ValidationFailure as exc:
        raise TrustPolicyEvaluationError(
            exc.code,
            exc.detail,
        ) from exc
    except VerificationFailure as exc:
        raise TrustPolicyEvaluationError(
            exc.code,
            exc.detail,
        ) from exc


__all__ = [
    "DEFAULT_SCHEMA_DIR",
    "TrustPolicyEvaluationError",
    "evaluate_trust_policy",
]
