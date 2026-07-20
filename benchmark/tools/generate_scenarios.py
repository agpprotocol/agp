from pathlib import Path
import json, copy, hashlib
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"benchmark/scenarios"
OUT.mkdir(parents=True,exist_ok=True)

def cb(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def seal(entries):
    prev="GENESIS"
    for i,e in enumerate(entries):
        e["index"]=i
        e["previous_hash"]=prev
        body={k:e[k] for k in sorted(e) if k!="entry_hash"}
        e["entry_hash"]="sha256:"+hashlib.sha256(cb(body)).hexdigest()
        prev=e["entry_hash"]
    return prev

base_events=[
 {"event_type":"proposal.created","event":{"proposal":"deploy payments-api 2.4.0"}},
 {"event_type":"evidence.published","event":{"version":"evidence-v2"}},
 {"event_type":"ballot.cast","event":{"ballot_id":"b-sec","role":"security","position":"approve"}},
 {"event_type":"ballot.cast","event":{"ballot_id":"b-legal","role":"legal","position":"approve"}},
 {"event_type":"ballot.cast","event":{"ballot_id":"b-ops","role":"operations","position":"approve"}},
 {"event_type":"resolution.issued","event":{"outcome":"approved"}},
]
entries=copy.deepcopy(base_events)
checkpoint=seal(entries)
ballots=[
 {"ballot_id":"b-sec","role":"security","position":"approve","evidence_version":"evidence-v2","member_revoked":False},
 {"ballot_id":"b-legal","role":"legal","position":"approve","evidence_version":"evidence-v2","member_revoked":False},
 {"ballot_id":"b-ops","role":"operations","position":"approve","evidence_version":"evidence-v2","member_revoked":False},
]
base={
 "workflow_state":{"approvals":[{"role":"security","position":"approve"},{"role":"legal","position":"approve"},{"role":"operations","position":"approve"}],"quorum":3,"veto_roles":["security","legal"]},
 "agp_state":{"entries":entries,"expected_checkpoint":checkpoint,"ballots":ballots,"current_evidence_version":"evidence-v2","declared_input_root":"sha256:root-v2","computed_input_root":"sha256:root-v2","quorum":3,"veto_roles":["security","legal"]},
 "expected":{"workflow_outcome":"approved","agp_outcome":"approved"}
}
cases=[]

def add(name,mutate,expected_detect):
    c=copy.deepcopy(base); mutate(c)
    c["name"]=name;c["expected_detection"]=expected_detect
    cases.append(c)

add("clean",lambda c:None,False)
def omitted(c):
    c["workflow_state"]["approvals"].pop()
    c["agp_state"]["entries"].pop(4)
    c["agp_state"]["ballots"].pop(2)
add("omitted_ballot",omitted,True)
def altered(c):
    c["workflow_state"]["approvals"][0]={"role":"security","position":"reject"}
    c["agp_state"]["entries"][2]["event"]["position"]="reject"
    c["agp_state"]["ballots"][0]["position"]="reject"
add("altered_ballot",altered,True)

def reorder(c):
    c["agp_state"]["entries"][2],c["agp_state"]["entries"][3]=c["agp_state"]["entries"][3],c["agp_state"]["entries"][2]
add("reordered_history",reorder,True)

def trunc(c):
    c["agp_state"]["entries"]=c["agp_state"]["entries"][:-1]
add("truncated_history",trunc,True)

def stale(c):
    c["agp_state"]["ballots"][1]["evidence_version"]="evidence-v1"
add("stale_evidence",stale,True)

def revoked(c):
    c["agp_state"]["ballots"][2]["member_revoked"]=True
add("revoked_voter",revoked,True)

def root(c):
    c["agp_state"]["declared_input_root"]="sha256:fake"
add("replaced_root",root,True)

def dup(c):
    c["agp_state"]["ballots"].append(copy.deepcopy(c["agp_state"]["ballots"][0]))
add("duplicate_ballot",dup,True)

for i,c in enumerate(cases,1):
    (OUT/f"{i:02d}_{c['name']}.json").write_text(json.dumps(c,indent=2,sort_keys=True))
print(f"Generated {len(cases)} benchmark scenarios")
