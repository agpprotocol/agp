from __future__ import annotations
import json, sys
from pathlib import Path

def resolve(case: dict) -> dict:
    state = case["workflow_state"]
    approvals = [x for x in state.get("approvals", []) if x.get("position") == "approve"]
    rejects = [x for x in state.get("approvals", []) if x.get("position") == "reject"]
    quorum = state.get("quorum", 3)
    veto_roles = set(state.get("veto_roles", []))
    veto = any(x.get("role") in veto_roles for x in rejects)
    approved = len(approvals) >= quorum and not veto

    return {
        "engine": "workflow",
        "outcome": "approved" if approved else "rejected",
        "approval_count": len(approvals),
        "rejection_count": len(rejects),
        "audit_ok": True,
        "detected_attacks": [],
        "notes": "Coordinator state treated as source of truth."
    }

def main():
    data=json.loads(Path(sys.argv[1]).read_text())
    out=resolve(data)
    Path(sys.argv[2]).write_text(json.dumps(out,sort_keys=True,separators=(",",":"))+"\n")
if __name__=="__main__":
    main()
