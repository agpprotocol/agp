from __future__ import annotations
import json, sys, hashlib
from pathlib import Path

def cbytes(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def verify_chain(entries):
    errs=[]; prev="GENESIS"
    for i,e in enumerate(entries):
        body={k:e[k] for k in sorted(e) if k!="entry_hash"}
        calc="sha256:"+hashlib.sha256(cbytes(body)).hexdigest()
        if e.get("index")!=i: errs.append("NON_CONTIGUOUS_INDEX")
        if e.get("previous_hash")!=prev: errs.append("PREVIOUS_HASH_MISMATCH")
        if e.get("entry_hash")!=calc: errs.append("ENTRY_HASH_MISMATCH")
        prev=e.get("entry_hash","")
    return sorted(set(errs)), prev

def resolve(case):
    agp=case["agp_state"]
    errs, checkpoint=verify_chain(agp["entries"])
    ballots=agp["ballots"]
    valid=[]
    detected=[]

    if agp.get("expected_checkpoint") and checkpoint!=agp["expected_checkpoint"]:
        errs.append("CHECKPOINT_MISMATCH")

    seen=set()
    for b in ballots:
        bid=b["ballot_id"]
        if bid in seen:
            detected.append("DUPLICATE_BALLOT")
            continue
        seen.add(bid)
        if b.get("member_revoked"):
            detected.append("REVOKED_VOTER")
            continue
        if b.get("evidence_version") != agp["current_evidence_version"]:
            detected.append("STALE_EVIDENCE")
            continue
        valid.append(b)

    if agp.get("declared_input_root") != agp.get("computed_input_root"):
        detected.append("REPLACED_DECISION_ROOT")

    if errs:
        detected.append("HISTORY_TAMPERING")

    approvals=[b for b in valid if b["position"]=="approve"]
    rejects=[b for b in valid if b["position"]=="reject"]
    veto_roles=set(agp["veto_roles"])
    veto=any(b["role"] in veto_roles for b in rejects)
    outcome="approved" if len(approvals)>=agp["quorum"] and not veto else "rejected"

    return {
        "engine":"agp",
        "outcome":outcome,
        "approval_count":len(approvals),
        "rejection_count":len(rejects),
        "audit_ok":not errs and not detected,
        "detected_attacks":sorted(set(detected)),
        "notes":"Coordinator state independently verified."
    }

def main():
    data=json.loads(Path(sys.argv[1]).read_text())
    out=resolve(data)
    Path(sys.argv[2]).write_text(json.dumps(out,sort_keys=True,separators=(",",":"))+"\n")
if __name__=="__main__":
    main()
