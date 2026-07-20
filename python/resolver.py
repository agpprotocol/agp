from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


VALID_POSITIONS = {"approve", "reject", "abstain", "defer"}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def issue(code: str, object_id: str) -> dict:
    return {"code": code, "object_id": object_id}


def resolve(data: dict) -> dict:
    members = {m["member_id"]: m for m in data["members"]}
    rule = data["rule"]
    proposal_id = data["proposal_id"]
    snapshot_id = data["snapshot_id"]
    closing_time = data["closing_time"]
    evidence = data.get("active_evidence_manifest")
    revocations = {
        r["member_id"]: r
        for r in sorted(
            data.get("revocations", []),
            key=lambda x: (x["member_id"], x["effective_at"], x["revocation_id"]),
        )
        if r["effective_at"] <= closing_time
    }

    grouped: dict[str, list[dict]] = defaultdict(list)
    issues: list[dict] = []

    for b in data.get("ballots", []):
        bid = b["ballot_id"]
        voter = b["voter"]

        if voter not in members:
            issues.append(issue("NON_MEMBER_VOTE", bid))
            continue
        if b["proposal_id"] != proposal_id:
            issues.append(issue("WRONG_PROPOSAL", bid))
            continue
        if b["snapshot_id"] != snapshot_id:
            issues.append(issue("WRONG_SNAPSHOT", bid))
            continue
        if b["position"] not in VALID_POSITIONS:
            issues.append(issue("INVALID_POSITION", bid))
            continue

        rev = revocations.get(voter)
        if rev is not None:
            policy = rule.get("revocation_policy", "vote_remains_valid")
            before = b["issued_at"] < rev["effective_at"]
            if policy == "vote_invalidated":
                issues.append(issue("MEMBER_REVOKED", bid))
                continue
            if policy == "vote_remains_valid" and not before:
                issues.append(issue("VOTE_AFTER_REVOCATION", bid))
                continue
            if policy == "human_review_required":
                issues.append(issue("REVOCATION_REQUIRES_REVIEW", bid))
                continue

        evidence_policy = rule.get("evidence_change_policy", "votes_remain_valid")
        if evidence is not None and b.get("evidence_manifest") != evidence:
            if evidence_policy == "reconfirmation_required":
                issues.append(issue("STALE_EVIDENCE_MANIFEST", bid))
                continue
            if evidence_policy == "human_review_required":
                issues.append(issue("EVIDENCE_CHANGE_REQUIRES_REVIEW", bid))
                continue

        grouped[voter].append(b)

    valid_ballots: list[dict] = []
    for voter, ballots in grouped.items():
        seq_positions: dict[int, set[str]] = defaultdict(set)
        for b in ballots:
            seq_positions[int(b["sequence"])].add(b["position"])
        if any(len(v) > 1 for v in seq_positions.values()):
            issues.append(issue("EQUIVOCATION", voter))
            continue
        valid_ballots.append(
            max(ballots, key=lambda b: (int(b["sequence"]), b["issued_at"], b["ballot_id"]))
        )

    valid_objections = []
    for o in data.get("objections", []):
        oid = o["objection_id"]
        if o["objector"] not in members:
            issues.append(issue("NON_MEMBER_OBJECTION", oid))
            continue
        if o["proposal_id"] != proposal_id:
            issues.append(issue("WRONG_PROPOSAL", oid))
            continue
        valid_objections.append(o)

    valid_ballots.sort(key=lambda b: b["ballot_id"])
    valid_objections.sort(key=lambda o: o["objection_id"])
    issues.sort(key=lambda x: (x["code"], x["object_id"]))

    tally = {"abstain": 0, "approve": 0, "defer": 0, "reject": 0}
    for b in valid_ballots:
        tally[b["position"]] += int(members[b["voter"]].get("weight", 1))

    quorum_count = sum(
        1
        for b in valid_ballots
        if rule.get("abstention_counts_toward_quorum", True)
        or b["position"] != "abstain"
    )
    quorum_met = quorum_count >= int(rule["quorum_minimum"])

    veto_roles = set(rule.get("veto_roles", []))
    vetoes = sorted(
        b["ballot_id"]
        for b in valid_ballots
        if b["position"] == "reject"
        and veto_roles.intersection(members[b["voter"]].get("roles", []))
    )
    blocking = sorted(
        o["objection_id"]
        for o in valid_objections
        if o.get("severity") == "blocking"
    )

    review_codes = {
        "REVOCATION_REQUIRES_REVIEW",
        "EVIDENCE_CHANGE_REQUIRES_REVIEW",
    }
    issue_codes = {x["code"] for x in issues}

    if issue_codes & review_codes:
        outcome = "escalated"
    elif vetoes:
        outcome = "blocked"
    elif blocking:
        outcome = {
            "block": "blocked",
            "reject": "rejected",
            "escalate": "escalated",
        }.get(rule.get("formal_objection_effect", "escalate"), "escalated")
    elif not quorum_met:
        outcome = rule.get("quorum_failure", "inconclusive")
    elif tally["approve"] > tally["reject"]:
        outcome = "approved"
    elif tally["approve"] == tally["reject"]:
        outcome = {
            "human_escalation": "escalated",
            "reject": "rejected",
            "inconclusive": "inconclusive",
        }.get(rule.get("tie_resolution", "inconclusive"), "inconclusive")
    else:
        outcome = "rejected"

    normalized = {
        "active_evidence_manifest": evidence,
        "ballots": valid_ballots,
        "members": sorted(data["members"], key=lambda m: m["member_id"]),
        "objections": valid_objections,
        "proposal_id": proposal_id,
        "revocations": sorted(
            data.get("revocations", []),
            key=lambda r: (r["member_id"], r["effective_at"], r["revocation_id"]),
        ),
        "rule": rule,
        "snapshot_id": snapshot_id,
    }
    input_root = "sha256:" + hashlib.sha256(canonical_bytes(normalized)).hexdigest()

    return {
        "blocking_objections": blocking,
        "blocking_vetoes": vetoes,
        "input_root": input_root,
        "issues": issues,
        "outcome": outcome,
        "proposal_id": proposal_id,
        "snapshot_id": snapshot_id,
        "tally": tally,
        "valid_ballot_ids": [b["ballot_id"] for b in valid_ballots],
        "valid_objection_ids": [o["objection_id"] for o in valid_objections],
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: resolver.py INPUT.json|INPUT_DIR OUTPUT.json|OUTPUT_DIR")
    source, target = map(Path, sys.argv[1:])
    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        for item in sorted(source.glob("*.json")):
            result = resolve(json.loads(item.read_text(encoding="utf-8")))
            (target / item.name).write_bytes(canonical_bytes(result) + b"\n")
        return
    result = resolve(json.loads(source.read_text(encoding="utf-8")))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_bytes(result) + b"\n")


if __name__ == "__main__":
    main()
