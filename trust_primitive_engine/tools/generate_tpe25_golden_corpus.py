#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine/python"
EVAL = TPE / "evaluate_trust_policy_v2.py"
OUT = ROOT / "trust_primitive_engine/fixtures/golden/v2.5"

if str(TPE) not in sys.path:
    sys.path.insert(0, str(TPE))

from engine import build_policy_set_index


def evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("tpe25_golden_gen", EVAL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dump(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def compact(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def policy(ev: Any, name: str, requirements: list[dict[str, Any]], roles=None):
    return ev.validate_policy({
        "object_type": "agp.trust-policy/2",
        "policy_id": f"policy:golden:tpe25:{name}",
        "version": 1,
        "eligible_roles": roles or ["approver"],
        "requirements": requirements,
    })


def reqs() -> list[dict[str, Any]]:
    return [
        {
            "requirement_id": "requirement:01-environment",
            "type": "context_value_in",
            "path": "/proposal/payload/environment",
            "values": ["canary", "production"],
        },
        {
            "requirement_id": "requirement:02-version-match",
            "type": "context_path_equals",
            "left_path": "/proposal/payload/requested_version",
            "right_path": "/proposal/payload/approved_version",
        },
        {
            "requirement_id": "requirement:03-evidence-count",
            "type": "evidence_count_at_least",
            "minimum": 2,
            "media_type": "application/json",
        },
    ]


def context(ev: Any, root: dict[str, Any], name: str, payload, evidence):
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:tpe-2.5:{name}",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": f"context:tpe-2.5:{name}",
            "evaluation_time": 1700000000,
            "policy": {
                "id": root["policy_id"],
                "version": root["version"],
                "digest": ev.policy_digest(root),
            },
            "proposal": {
                "type": "proposal:tpe-2.5:golden",
                "payload": payload,
            },
            "participants": [
                {"id": "authority:alpha", "role": "approver", "weight": 1}
            ],
            "evidence": evidence,
            "constraints": [],
        },
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {"signer_id": "authority:alpha"},
            }
        ],
    }


def add(ev, cases, name, root, policies, payload, evidence, status):
    evaluation_input = context(ev, root, name, payload, evidence)
    index = build_policy_set_index(
        policies,
        validate_policy=ev.validate_policy,
        compute_digest=ev.policy_digest,
    )
    ev.validate_policy_reference_graph(root, index)
    result = ev.evaluate_verified_object(
        evaluation_input,
        root,
        ["signature:alpha"],
        policy_set_index=index,
    )
    if result["status"] != status:
        raise RuntimeError(f"{name}: {result['status']} != {status}")

    case_dir = OUT / name
    case_dir.mkdir(parents=True, exist_ok=True)
    dump(case_dir / "root-policy.json", root)
    dump(case_dir / "policy-set.json", policies)
    dump(case_dir / "evaluation-input.json", evaluation_input)
    dump(case_dir / "expected-evaluation.json", result)

    digest = hashlib.sha256(compact(result)).hexdigest()
    (case_dir / "expected-evaluation.sha256").write_text(
        digest + "\n",
        encoding="ascii",
    )
    cases.append({
        "name": name,
        "directory": name,
        "expected_status": status,
        "expected_sha256": digest,
    })


def main() -> int:
    ev = evaluator()
    if OUT.exists():
        for path in OUT.iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            elif path.name != "README.md":
                path.unlink()

    cases = []
    payload = {
        "environment": "production",
        "requested_version": "3.0.0",
        "approved_version": "3.0.0",
    }
    evidence = [
        {
            "id": "evidence.architecture",
            "digest": "a" * 64,
            "media_type": "application/json",
        },
        {
            "id": "evidence.security",
            "digest": "b" * 64,
            "media_type": "application/json",
        },
    ]

    add(ev, cases, "satisfied-all", policy(ev, "satisfied-all", reqs()), [], payload, evidence, "satisfied")
    add(ev, cases, "context-value-not-in-set", policy(ev, "context-value-not-in-set", [reqs()[0]]), [], {**payload, "environment": "staging"}, [], "unsatisfied")
    add(ev, cases, "context-path-values-not-equal", policy(ev, "context-path-values-not-equal", [reqs()[1]]), [], {**payload, "approved_version": "3.1.0"}, [], "unsatisfied")
    add(ev, cases, "evidence-count-not-reached", policy(ev, "evidence-count-not-reached", [reqs()[2]]), [], {}, evidence[:1], "unsatisfied")

    leaf = policy(ev, "recursive-leaf", reqs(), ["reviewer"])
    root = policy(ev, "recursive-root", [{
        "requirement_id": "requirement:recursive-reference",
        "type": "policy_reference",
        "policy_id": leaf["policy_id"],
        "policy_version": leaf["version"],
        "policy_digest": ev.policy_digest(leaf),
    }])
    add(ev, cases, "recursive-reference-projection", root, [leaf], {**payload, "environment": "staging"}, evidence, "unsatisfied")

    dump(OUT / "manifest.json", {
        "corpus": "agp.tpe-contextual-predicates-conformance/2.5",
        "hash_serialization": "json-sort-keys-compact-utf8",
        "hash_algorithm": "sha-256",
        "cases": cases,
    })
    print(f"GENERATED TPE 2.5 golden corpus: {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
