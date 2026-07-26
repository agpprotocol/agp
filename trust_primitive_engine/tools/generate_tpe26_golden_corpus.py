#!/usr/bin/env python3
from __future__ import annotations
import hashlib, importlib.util, json, shutil, sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine/python"
EVAL = TPE / "evaluate_trust_policy_v2.py"
OUT = ROOT / "trust_primitive_engine/fixtures/golden/v2.6"
sys.path.insert(0, str(TPE))
from engine import build_policy_set_index

def evaluator():
    spec = importlib.util.spec_from_file_location("tpe26_golden_gen", EVAL)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()

def policy(ev, name, requirements, roles=None):
    return ev.validate_policy({
        "object_type": "agp.trust-policy/2",
        "policy_id": f"policy:golden:tpe26:{name}",
        "version": 1,
        "eligible_roles": roles or ["approver"],
        "requirements": requirements,
    })

def reqs():
    return [
        {"requirement_id":"requirement:01-approved-issuer","type":"evidence_issuer_in","issuer_ids":["authority:lab-a","authority:lab-b"],"evidence_types":["security:assessment/1"]},
        {"requirement_id":"requirement:02-approved-type","type":"evidence_type_in","evidence_types":["security:assessment/1"],"issuer_ids":["authority:lab-a","authority:lab-b"]},
        {"requirement_id":"requirement:03-distinct-issuers","type":"evidence_distinct_issuers_at_least","minimum":2,"evidence_types":["security:assessment/1"]},
    ]

def evidence():
    return [
        {"id":"evidence.assessment-a","digest":"a"*64,"media_type":"application/json","evidence_type":"security:assessment/1","issuer_id":"authority:lab-a"},
        {"id":"evidence.assessment-b","digest":"b"*64,"media_type":"application/json","evidence_type":"security:assessment/1","issuer_id":"authority:lab-b"},
    ]

def context(ev, root, name, manifest, generation=3):
    ctx = {
        "object_type": f"agp.decision-context/{generation}",
        "context_id": f"context:tpe-2.6:{name}",
        "policy":{"id":root["policy_id"],"version":root["version"],"digest":ev.policy_digest(root)},
        "proposal":{"type":"proposal:tpe-2.6:golden","payload":{"environment":"production"}},
        "participants":[{"id":"authority:alpha","role":"approver","weight":1}],
        "evidence":manifest,
        "constraints":[],
    }
    if generation >= 2: ctx["evaluation_time"] = 1700000000
    return {
        "object_type":f"agp.signed-decision-context/{generation}",
        "context_digest":f"context-digest:tpe-2.6:{name}",
        "context":ctx,
        "signatures":[{"signature_id":"signature:alpha","statement":{"signer_id":"authority:alpha"}}],
    }

def add(ev, cases, name, root, policies, manifest, status, generation=3):
    inp = context(ev, root, name, manifest, generation)
    index = build_policy_set_index(policies, validate_policy=ev.validate_policy, compute_digest=ev.policy_digest)
    ev.validate_policy_reference_graph(root, index)
    result = ev.evaluate_verified_object(inp, root, ["signature:alpha"], policy_set_index=index)
    assert result["status"] == status, (name, result)
    d = OUT / name; d.mkdir(parents=True, exist_ok=True)
    dump(d/"root-policy.json", root); dump(d/"policy-set.json", policies)
    dump(d/"evaluation-input.json", inp); dump(d/"expected-evaluation.json", result)
    digest = hashlib.sha256(compact(result)).hexdigest()
    (d/"expected-evaluation.sha256").write_text(digest+"\n", encoding="ascii")
    cases.append({"name":name,"directory":name,"expected_status":status,"expected_sha256":digest})

def main():
    ev = evaluator()
    if OUT.exists():
        for p in OUT.iterdir():
            if p.is_dir(): shutil.rmtree(p)
            elif p.name != "README.md": p.unlink()
    OUT.mkdir(parents=True, exist_ok=True)
    cases=[]; manifest=evidence()
    add(ev,cases,"satisfied-all",policy(ev,"satisfied-all",reqs()),[],manifest,"satisfied")
    unapproved=[{**x,"issuer_id":"authority:unapproved"} for x in manifest]
    add(ev,cases,"issuer-not-allowed",policy(ev,"issuer-not-allowed",[reqs()[0]]),[],unapproved,"unsatisfied")
    wrong_type=[{**x,"evidence_type":"security:penetration-test/1"} for x in manifest]
    add(ev,cases,"type-not-allowed",policy(ev,"type-not-allowed",[reqs()[1]]),[],wrong_type,"unsatisfied")
    add(ev,cases,"distinct-minimum-not-reached",policy(ev,"distinct-minimum-not-reached",[reqs()[2]]),[],manifest[:1],"unsatisfied")
    add(ev,cases,"empty-dc3-manifest",policy(ev,"empty-dc3-manifest",reqs()),[],[],"unsatisfied")
    add(ev,cases,"dc2-provenance-unavailable",policy(ev,"dc2-provenance-unavailable",[reqs()[0]]),[],[],"unsatisfied",2)
    leaf=policy(ev,"recursive-leaf",reqs(),["reviewer"])
    root=policy(ev,"recursive-root",[{"requirement_id":"requirement:recursive-reference","type":"policy_reference","policy_id":leaf["policy_id"],"policy_version":leaf["version"],"policy_digest":ev.policy_digest(leaf)}])
    add(ev,cases,"recursive-reference-projection",root,[leaf],unapproved,"unsatisfied")
    dump(OUT/"manifest.json",{"corpus":"agp.tpe-evidence-provenance-conformance/2.6","hash_serialization":"json-sort-keys-compact-utf8","hash_algorithm":"sha-256","cases":cases})
    print(f"GENERATED TPE 2.6 golden corpus: {len(cases)} cases")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
