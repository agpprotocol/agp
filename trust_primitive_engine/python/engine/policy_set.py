"""Deterministic indexing for explicit Trust Policy sets."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

PolicyValidator = Callable[[Any], dict[str, Any]]
PolicyDigestFunction = Callable[[dict[str, Any]], str]


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, order=True)
class PolicyReferenceIdentity:
    policy_id: str
    policy_version: int
    policy_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise ValueError("policy_id must be a non-empty string")
        if (not isinstance(self.policy_version, int)
                or isinstance(self.policy_version, bool)
                or self.policy_version < 1):
            raise ValueError("policy_version must be a positive integer")
        if (not isinstance(self.policy_digest, str)
                or len(self.policy_digest) != 64
                or any(character not in "0123456789abcdef" for character in self.policy_digest)):
            raise ValueError("policy_digest must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True)
class PolicySetEntry:
    identity: PolicyReferenceIdentity
    policy: Mapping[str, Any]

    def to_policy(self) -> dict[str, Any]:
        return _thaw_json(self.policy)


@dataclass(frozen=True)
class PolicySetIndex:
    entries: tuple[PolicySetEntry, ...]
    _by_policy_key: Mapping[tuple[str, int], PolicySetEntry]

    def __post_init__(self) -> None:
        normalized_entries = tuple(self.entries)
        if tuple(sorted(normalized_entries, key=lambda entry: entry.identity)) != normalized_entries:
            raise ValueError("policy-set entries must be sorted by complete identity")
        object.__setattr__(self, "entries", normalized_entries)
        object.__setattr__(self, "_by_policy_key", MappingProxyType(dict(self._by_policy_key)))

    @property
    def identities(self) -> tuple[PolicyReferenceIdentity, ...]:
        return tuple(entry.identity for entry in self.entries)

    def resolve(self, policy_id: str, policy_version: int) -> PolicySetEntry | None:
        return self._by_policy_key.get((policy_id, policy_version))

    def __len__(self) -> int:
        return len(self.entries)


def build_policy_set_index(
    raw_policy_set: Any,
    *,
    validate_policy: PolicyValidator,
    compute_digest: PolicyDigestFunction,
) -> PolicySetIndex:
    if not isinstance(raw_policy_set, list):
        raise ValueError("policy_set must be an array")
    if not callable(validate_policy):
        raise TypeError("validate_policy must be callable")
    if not callable(compute_digest):
        raise TypeError("compute_digest must be callable")

    entries: list[PolicySetEntry] = []
    by_policy_key: dict[tuple[str, int], PolicySetEntry] = {}
    for position, raw_policy in enumerate(raw_policy_set):
        try:
            normalized = validate_policy(raw_policy)
        except Exception as exc:
            raise ValueError(f"policy_set[{position}] is not a valid Trust Policy") from exc

        identity = PolicyReferenceIdentity(
            policy_id=normalized["policy_id"],
            policy_version=normalized["version"],
            policy_digest=compute_digest(normalized),
        )
        policy_key = (identity.policy_id, identity.policy_version)

        if policy_key in by_policy_key:
            raise ValueError(
                "policy_set contains duplicate policy_id/version: "
                f"{identity.policy_id!r} version {identity.policy_version}"
            )
            raise ValueError("policy_set contains duplicate canonical policy objects")

        entry = PolicySetEntry(identity=identity, policy=_freeze_json(normalized))
        entries.append(entry)
        by_policy_key[policy_key] = entry

    entries.sort(key=lambda entry: entry.identity)
    return PolicySetIndex(
        entries=tuple(entries),
        _by_policy_key={
            (entry.identity.policy_id, entry.identity.policy_version): entry
            for entry in entries
        },
    )
