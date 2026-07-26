#!/usr/bin/env python3
"""Focused checks for TPE 2.5 evidence_count_at_least."""
from __future__ import annotations
import json, sys
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator
ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
SCHEMA_PATH = ROOT / "registry/schemas/agp.trust-policy-2.schema.json"
if str(TPE_PYTHON) not in sys.path: sys.path.insert(0, str(TPE_PYTHON))
from engine import EvaluationState, PrimitiveRegistry
from primitives.evidence_count import EvidenceCountAtLeastPrimitive
P = EvidenceCountAtLeastPrimitive(); R = PrimitiveRegistry([P])
class TestFailure(Exception): pass

def req(minimum: Any, media_type: Any = ..., **extra: Any):
    value = {"requirement_id":"requirement:minimum-evidence","type":"evidence_count_at_least","minimum":minimum, **extra}
    if media_type is not ...: value["media_type"] = media_type
    return value

def ev(eid, media): return {"id":eid,"digest":"a"*64,"media_type":media}
def state(entries): return EvaluationState.create(matched_signers=[],participants={},weight=0,decision_context={"proposal":{"payload":{}},"evidence":entries})
def evaluate(s, value): return P.evaluate(P.validate(value), s)
def policy(value): return {"object_type":"agp.trust-policy/2","policy_id":"policy:tpe-2.5-evidence-count","version":1,"eligible_roles":["approver"],"requirements":[value]}
def reject(name, value):
    try: P.validate(value)
    except ValueError: print(f"PASS  {name:<48} rejected"); return
    raise TestFailure(f"{name}: accepted")

def main():
    passed = 0
    entries=[ev("evidence.architecture","application/json"),ev("evidence.security","application/json"),ev("evidence.report","text/plain")]
    s=state(entries)
    cases=[
      ("unfiltered_at_boundary",req(3),True,None,3),("unfiltered_below_boundary",req(4),False,"EVIDENCE_COUNT_NOT_REACHED",3),
      ("unfiltered_above_boundary",req(2),True,None,3),("filtered_at_boundary",req(2,"application/json"),True,None,2),
      ("filtered_below_boundary",req(3,"application/json"),False,"EVIDENCE_COUNT_NOT_REACHED",2),
      ("filtered_absent_type",req(1,"image/png"),False,"EVIDENCE_COUNT_NOT_REACHED",0),
      ("empty_manifest",req(1),False,"EVIDENCE_COUNT_NOT_REACHED",0)]
    for name,value,sat,fail,count in cases:
        result=evaluate(state([]) if name=="empty_manifest" else s,value)
        if result.satisfied is not sat or (None if sat else result.failure_code)!=fail or result.observed["count"]!=count: raise TestFailure(name)
        print(f"PASS  {name:<48} correct"); passed+=1
    result=evaluate(s,req(1))
    if result.observed["evidence_ids"] != ["evidence.architecture","evidence.report","evidence.security"] or result.expected != {"minimum":1,"media_type":None}: raise TestFailure("canonical output")
    print("PASS  canonical_ids_and_null_filter                    correct"); passed+=1
    filtered=evaluate(s,req(1,"application/json"))
    if filtered.observed["evidence_ids"] != ["evidence.architecture","evidence.security"]: raise TestFailure("filtered ids")
    print("PASS  filtered_contributing_ids                       correct"); passed+=1
    dup=state([ev("evidence.same","text/plain"),ev("evidence.same","application/json"),ev("evidence.other","application/json")])
    if evaluate(dup,req(2)).observed["count"] != 2: raise TestFailure("duplicate inflation")
    print("PASS  defensive_unique_id_count                       correct"); passed+=1
    if evaluate(dup,req(2,"application/json")).observed["evidence_ids"] != ["evidence.other","evidence.same"]: raise TestFailure("duplicate filtering")
    print("PASS  duplicate_filter_order_independent              correct"); passed+=1
    if evaluate(state(list(reversed(entries))),req(2,"application/json")).to_dict()!=evaluate(s,req(2,"application/json")).to_dict(): raise TestFailure("order")
    print("PASS  evidence_insertion_order                        independent"); passed+=1
    no_context=EvaluationState.create(matched_signers=[],participants={},weight=0)
    if evaluate(no_context,req(1)).observed != {"count":0,"evidence_ids":[]}: raise TestFailure("missing context")
    print("PASS  missing_context                                 count=0"); passed+=1
    malformed=state([None,{"id":1,"media_type":"application/json"},{"id":"evidence.valid"},ev("evidence.valid","application/json")])
    if evaluate(malformed,req(1,"application/json")).observed["evidence_ids"] != ["evidence.valid"]: raise TestFailure("malformed")
    print("PASS  malformed_unvalidated_entries                   ignored"); passed+=1
    invalid=[("minimum_boolean",req(True)),("minimum_zero",req(0)),("minimum_negative",req(-1)),("minimum_above_256",req(257)),("minimum_decimal",req(1.5)),("invalid_media_type_uppercase",req(1,"Application/json")),("invalid_media_type_missing_slash",req(1,"application-json")),("unknown_member",req(1,extra=True)),("missing_minimum",{"requirement_id":"requirement:minimum-evidence","type":"evidence_count_at_least"}),("wrong_type",{**req(1),"type":"evidence_present"}),("invalid_requirement_id",{**req(1),"requirement_id":"INVALID"})]
    for name,value in invalid: reject(name,value); passed+=1
    validator=Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    for i,value in enumerate([req(1),req(256),req(2,"application/json")],1):
        errors=list(validator.iter_errors(policy(value)))
        if errors: raise TestFailure(f"schema valid {i}: {errors[0].message}")
        print(f"PASS  schema_accepts_evidence_count_{i:<18} accepted"); passed+=1
    for i,value in enumerate([req(0),req(257),req(True),req(1,"Application/json")],1):
        if not list(validator.iter_errors(policy(value))): raise TestFailure(f"schema invalid {i}")
        print(f"PASS  schema_rejects_evidence_count_{i:<18} rejected"); passed+=1
    if R.types() != ("evidence_count_at_least",): raise TestFailure("registry")
    print("PASS  registry_contains_evidence_count                correct"); passed+=1
    if evaluate(s,req(2,"application/json")).to_dict()!=evaluate(s,req(2,"application/json")).to_dict(): raise TestFailure("replay")
    print("PASS  deterministic_replay                           identical"); passed+=1
    if passed != 34: raise TestFailure(f"expected 34, observed {passed}")
    print(f"TPE 2.5 evidence_count_at_least: {passed}/{passed} passed")
    return 0
if __name__ == "__main__": raise SystemExit(main())
