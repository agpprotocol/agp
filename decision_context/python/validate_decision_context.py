#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SAFE_MAX = 9_007_199_254_740_991
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$")
CONTEXT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
ROLES = {"proposer", "voter", "reviewer", "approver", "observer"}
RESERVED_RESULT_MEMBERS = {
    "decision", "result", "outcome", "accepted", "approved",
    "rejected", "resolution", "execution_state",
}
TOP_LEVEL = {
    "object_type", "context_id", "created_at", "expires_at",
    "policy", "proposal", "participants", "evidence", "constraints",
}

class ValidationError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail

def reject(code: str, detail: str) -> None:
    raise ValidationError(code, detail)

def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            reject("INVALID_JSON", f"duplicate JSON member: {key}")
        result[key] = value
    return result

def reject_float(value: str) -> None:
    reject("INVALID_JSON", f"non-integer number is not supported: {value}")

def reject_constant(value: str) -> None:
    reject("INVALID_JSON", f"non-finite number is not supported: {value}")

def parse_bytes(raw: bytes) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        reject("INVALID_JSON", "UTF-8 BOM is not allowed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        reject("INVALID_JSON", f"invalid UTF-8: {exc}")
    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        reject("INVALID_JSON", str(exc))

def exact_object(value: Any, fields: set[str], code: str, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject(code, f"{where} must be an object")
    if set(value) != fields:
        reject(code, f"{where} has invalid fields")
    return value

def identifier(value: Any, where: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        reject("INVALID_IDENTIFIER", f"{where} is not a valid identifier")
    return value

def positive_safe_integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (1 <= value <= SAFE_MAX):
        reject("INVALID_SAFE_INTEGER", f"{where} must be a positive safe integer")
    return value

def timestamp(value: Any, where: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        reject("INVALID_TIMESTAMP", f"{where} must be a whole-second UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        reject("INVALID_TIMESTAMP", f"{where} is not a valid calendar timestamp")

def validate_sorted_unique(entries: list[dict[str, Any]], collection: str) -> None:
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        reject("DUPLICATE_IDENTIFIER", f"{collection} contains duplicate identifiers")
    if ids != sorted(ids):
        reject("UNSORTED_COLLECTION", f"{collection} must be sorted by id")

def validate_object(value: Any) -> None:
    if not isinstance(value, dict):
        reject("INVALID_OBJECT", "decision context must be an object")

    unknown = set(value) - TOP_LEVEL
    if unknown:
        reject("UNKNOWN_TOP_LEVEL_MEMBER", f"unknown top-level member: {sorted(unknown)[0]}")
    if set(value) != TOP_LEVEL:
        reject("INVALID_OBJECT", "decision context is missing required top-level members")

    if value["object_type"] != "agp.decision-context/1":
        reject("INVALID_OBJECT_TYPE", "object_type must be agp.decision-context/1")

    context_id = value["context_id"]
    if not isinstance(context_id, str) or not CONTEXT_ID_RE.fullmatch(context_id):
        reject("INVALID_CONTEXT_ID", "context_id is invalid")

    created = timestamp(value["created_at"], "created_at")
    expires_raw = value["expires_at"]
    if expires_raw is not None:
        expires = timestamp(expires_raw, "expires_at")
        if expires <= created:
            reject("INVALID_TIMESTAMP", "expires_at must be later than created_at")

    policy = exact_object(value["policy"], {"id", "version", "digest"}, "INVALID_POLICY", "policy")
    identifier(policy["id"], "policy.id")
    positive_safe_integer(policy["version"], "policy.version")
    if not isinstance(policy["digest"], str) or not DIGEST_RE.fullmatch(policy["digest"]):
        reject("INVALID_POLICY", "policy.digest must be lowercase SHA-256 hex")

    proposal = exact_object(value["proposal"], {"type", "payload"}, "INVALID_PROPOSAL", "proposal")
    identifier(proposal["type"], "proposal.type")
    if not isinstance(proposal["payload"], dict):
        reject("INVALID_PROPOSAL", "proposal.payload must be an object")
    prohibited = RESERVED_RESULT_MEMBERS.intersection(proposal["payload"])
    if prohibited:
        reject("RESERVED_RESULT_MEMBER", f"reserved proposal member: {sorted(prohibited)[0]}")

    participants_raw = value["participants"]
    if not isinstance(participants_raw, list) or not participants_raw:
        reject("INVALID_PARTICIPANTS", "participants must be a non-empty array")
    participants = []
    for index, raw in enumerate(participants_raw):
        entry = exact_object(raw, {"id", "role", "weight"}, "INVALID_PARTICIPANTS", f"participants[{index}]")
        identifier(entry["id"], f"participants[{index}].id")
        if entry["role"] not in ROLES:
            reject("INVALID_PARTICIPANTS", f"participants[{index}].role is invalid")
        positive_safe_integer(entry["weight"], f"participants[{index}].weight")
        participants.append(entry)
    validate_sorted_unique(participants, "participants")

    evidence_raw = value["evidence"]
    if not isinstance(evidence_raw, list):
        reject("INVALID_EVIDENCE", "evidence must be an array")
    evidence = []
    for index, raw in enumerate(evidence_raw):
        entry = exact_object(raw, {"id", "digest", "media_type"}, "INVALID_EVIDENCE", f"evidence[{index}]")
        identifier(entry["id"], f"evidence[{index}].id")
        if not isinstance(entry["digest"], str) or not DIGEST_RE.fullmatch(entry["digest"]):
            reject("INVALID_EVIDENCE", f"evidence[{index}].digest is invalid")
        if not isinstance(entry["media_type"], str) or not MEDIA_TYPE_RE.fullmatch(entry["media_type"]):
            reject("INVALID_EVIDENCE", f"evidence[{index}].media_type is invalid")
        evidence.append(entry)
    validate_sorted_unique(evidence, "evidence")

    constraints_raw = value["constraints"]
    if not isinstance(constraints_raw, list):
        reject("INVALID_CONSTRAINTS", "constraints must be an array")
    constraints = []
    for index, raw in enumerate(constraints_raw):
        entry = exact_object(raw, {"id", "kind", "parameters"}, "INVALID_CONSTRAINTS", f"constraints[{index}]")
        identifier(entry["id"], f"constraints[{index}].id")
        identifier(entry["kind"], f"constraints[{index}].kind")
        if not isinstance(entry["parameters"], dict):
            reject("INVALID_CONSTRAINTS", f"constraints[{index}].parameters must be an object")
        constraints.append(entry)
    validate_sorted_unique(constraints, "constraints")

def validate_bytes(raw: bytes) -> dict[str, Any]:
    try:
        validate_object(parse_bytes(raw))
        return {"accepted": True, "detail": None, "error_code": None}
    except ValidationError as exc:
        return {"accepted": False, "detail": exc.detail, "error_code": exc.code}

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_decision_context.py <context.json>", file=sys.stderr)
        return 2
    result = validate_bytes(Path(sys.argv[1]).read_bytes())
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["accepted"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
