from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated"


def base(name: str) -> dict:
    evidence = "urn:agp:evidence:v2"
    return {
        "name": name,
        "proposal_id": "urn:agp:proposal:p1",
        "snapshot_id": "urn:agp:snapshot:s1",
        "members": [
            {"member_id": "agent:finance", "roles": ["finance"], "weight": 1},
            {"member_id": "agent:security", "roles": ["security"], "weight": 1},
            {"member_id": "agent:legal", "roles": ["legal"], "weight": 1},
            {"member_id": "agent:ops", "roles": ["operations"], "weight": 1},
        ],
        "rule": {
            "quorum_minimum": 3,
            "abstention_counts_toward_quorum": True,
            "veto_roles": ["legal"],
            "formal_objection_effect": "escalate",
            "tie_resolution": "human_escalation",
            "quorum_failure": "inconclusive",
            "revocation_policy": "vote_remains_valid",
            "evidence_change_policy": "reconfirmation_required",
        },
        "ballots": [],
        "objections": [],
        "revocations": [],
        "active_evidence_manifest": evidence,
        "closing_time": "2026-07-20T15:00:00Z",
        "expected_outcome": "",
    }


def ballot(voter: str, position: str, seq: int = 1, evidence: str = "urn:agp:evidence:v2", issued: str = "2026-07-20T14:00:00Z") -> dict:
    return {
        "ballot_id": f"urn:agp:ballot:{voter.split(':')[-1]}:{seq}:{position}",
        "proposal_id": "urn:agp:proposal:p1",
        "snapshot_id": "urn:agp:snapshot:s1",
        "evidence_manifest": evidence,
        "voter": voter,
        "position": position,
        "sequence": seq,
        "issued_at": issued,
    }


def write_vector(index: int, data: dict) -> None:
    target = OUT / f"{index:04d}_{data['name']}.json"
    target.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def deterministic_vectors() -> list[dict]:
    vectors = []

    d = base("majority")
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "abstain")]
    d["expected_outcome"] = "approved"
    vectors.append(d)

    d = base("legal_veto")
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "reject")]
    d["expected_outcome"] = "blocked"
    vectors.append(d)

    d = base("tie")
    d["rule"]["veto_roles"] = []
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "reject"), ballot("agent:ops", "reject")]
    d["expected_outcome"] = "escalated"
    vectors.append(d)

    d = base("blocking_objection")
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["objections"] = [{"objection_id": "urn:agp:obj:1", "proposal_id": d["proposal_id"], "objector": "agent:legal", "severity": "blocking"}]
    d["expected_outcome"] = "escalated"
    vectors.append(d)

    d = base("revoked_vote")
    d["rule"]["veto_roles"] = []
    d["rule"]["revocation_policy"] = "vote_invalidated"
    d["revocations"] = [{"revocation_id": "urn:agp:rev:1", "member_id": "agent:security", "effective_at": "2026-07-20T14:30:00Z"}]
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["expected_outcome"] = "inconclusive"
    vectors.append(d)

    d = base("stale_evidence")
    d["rule"]["veto_roles"] = []
    d["ballots"] = [ballot("agent:finance", "approve", evidence="urn:agp:evidence:v1"), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["expected_outcome"] = "inconclusive"
    vectors.append(d)

    d = base("equivocation")
    d["rule"]["veto_roles"] = []
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:finance", "reject"), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["expected_outcome"] = "inconclusive"
    vectors.append(d)

    d = base("replacement")
    d["rule"]["veto_roles"] = []
    d["ballots"] = [ballot("agent:finance", "reject", 1), ballot("agent:finance", "approve", 2), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["expected_outcome"] = "approved"
    vectors.append(d)

    d = base("review_revocation")
    d["rule"]["revocation_policy"] = "human_review_required"
    d["revocations"] = [{"revocation_id": "urn:agp:rev:2", "member_id": "agent:security", "effective_at": "2026-07-20T14:30:00Z"}]
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:legal", "approve")]
    d["expected_outcome"] = "escalated"
    vectors.append(d)

    d = base("non_member")
    d["rule"]["veto_roles"] = []
    d["ballots"] = [ballot("agent:finance", "approve"), ballot("agent:security", "approve"), ballot("agent:intruder", "approve")]
    d["expected_outcome"] = "inconclusive"
    vectors.append(d)

    return vectors


def fuzz_vectors(count: int = 250) -> list[dict]:
    rng = random.Random(3003)
    voters = ["agent:finance", "agent:security", "agent:legal", "agent:ops"]
    positions = ["approve", "reject", "abstain", "defer"]
    result = []

    for idx in range(count):
        d = base(f"fuzz_{idx:03d}")
        d["rule"]["veto_roles"] = ["legal"] if rng.random() < 0.45 else []
        d["rule"]["quorum_minimum"] = rng.choice([2, 3, 4])
        d["rule"]["tie_resolution"] = rng.choice(["human_escalation", "reject", "inconclusive"])
        d["rule"]["quorum_failure"] = rng.choice(["inconclusive", "rejected", "escalated"])

        selected = rng.sample(voters, rng.randint(1, 4))
        for voter in selected:
            position = rng.choice(positions)
            evidence = "urn:agp:evidence:v1" if rng.random() < 0.12 else "urn:agp:evidence:v2"
            d["ballots"].append(ballot(voter, position, evidence=evidence))
            if rng.random() < 0.08:
                d["ballots"].append(ballot(voter, rng.choice(positions), seq=1, evidence=evidence))
            elif rng.random() < 0.10:
                d["ballots"].append(ballot(voter, rng.choice(positions), seq=2, evidence="urn:agp:evidence:v2"))

        if rng.random() < 0.15:
            member = rng.choice(voters)
            d["revocations"].append({
                "revocation_id": f"urn:agp:rev:{idx}",
                "member_id": member,
                "effective_at": "2026-07-20T14:30:00Z",
            })
            d["rule"]["revocation_policy"] = rng.choice(
                ["vote_invalidated", "vote_remains_valid", "human_review_required"]
            )

        if rng.random() < 0.12:
            d["objections"].append({
                "objection_id": f"urn:agp:obj:{idx}",
                "proposal_id": d["proposal_id"],
                "objector": rng.choice(voters),
                "severity": rng.choice(["advisory", "blocking"]),
            })

        d["expected_outcome"] = None
        result.append(d)

    return result


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    vectors = deterministic_vectors() + fuzz_vectors()
    for i, vector in enumerate(vectors, 1):
        write_vector(i, vector)
    print(f"Generated {len(vectors)} vectors")


if __name__ == "__main__":
    main()
