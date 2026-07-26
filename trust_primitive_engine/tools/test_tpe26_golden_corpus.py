#!/usr/bin/env python3
from __future__ import annotations
import hashlib, importlib.util, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
TPE=ROOT/"trust_primitive_engine/python"
EVAL=TPE/"evaluate_trust_policy_v2.py"
CORPUS=ROOT/"trust_primitive_engine/fixtures/golden/v2.6"
sys.path.insert(0,str(TPE))
from engine import build_policy_set_index

class TestFailure(Exception): pass

def load(path): return json.loads(path.read_text(encoding="utf-8"))
def compact(value): return json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()

def evaluator():
    spec=importlib.util.spec_from_file_location("tpe26_golden_test",EVAL)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def main():
    ev=evaluator(); manifest=load(CORPUS/"manifest.json"); passed=0
    assert manifest["corpus"]=="agp.tpe-evidence-provenance-conformance/2.6"
    assert manifest["hash_algorithm"]=="sha-256"
    assert manifest["hash_serialization"]=="json-sort-keys-compact-utf8"
    for case in manifest["cases"]:
        d=CORPUS/case["directory"]
        root=ev.validate_policy(load(d/"root-policy.json"))
        policies=load(d/"policy-set.json")
        inp=load(d/"evaluation-input.json")
        expected=load(d/"expected-evaluation.json")
        index=build_policy_set_index(policies,validate_policy=ev.validate_policy,compute_digest=ev.policy_digest)
        ev.validate_policy_reference_graph(root,index)
        sigs=sorted(x["signature_id"] for x in inp["signatures"])
        first=ev.evaluate_verified_object(inp,root,sigs,policy_set_index=index)
        second=ev.evaluate_verified_object(inp,root,sigs,policy_set_index=index)
        if first!=second or first!=expected: raise TestFailure(f"{case['name']}: replay/result differs")
        digest=hashlib.sha256(compact(first)).hexdigest()
        frozen=(d/"expected-evaluation.sha256").read_text().strip()
        if digest!=frozen or digest!=case["expected_sha256"]: raise TestFailure(f"{case['name']}: digest differs")
        if first["status"]!=case["expected_status"]: raise TestFailure(f"{case['name']}: status differs")
        print(f"PASS  {case['name']:<34} status={first['status']} sha256={digest[:12]}...")
        passed+=1
    if passed!=7: raise TestFailure(f"expected 7, observed {passed}")
    print("TPE 2.6 evidence provenance golden corpus: 7/7 passed")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
