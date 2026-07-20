from pathlib import Path
import copy, hashlib, json

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"transparency/vectors"
OUT.mkdir(parents=True,exist_ok=True)

def cbytes(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def seal(entry):
    body={k:entry[k] for k in sorted(entry) if k!="entry_hash"}
    entry["entry_hash"]="sha256:"+hashlib.sha256(cbytes(body)).hexdigest()
    return entry

events=[
 ("proposal.created","evt-001",{"proposal_id":"deploy-2026-07-20","target":"payments-api","version":"2.4.0"}),
 ("evidence.published","evt-002",{"manifest":"evidence-v1","tests_passed":412,"critical_findings":0}),
 ("ballot.cast","evt-003",{"issuer":"agent:security","position":"approve"}),
 ("ballot.cast","evt-004",{"issuer":"agent:legal","position":"approve"}),
 ("ballot.cast","evt-005",{"issuer":"agent:operations","position":"approve"}),
 ("resolution.issued","evt-006",{"outcome":"approved","input_root":"sha256:demo"}),
]
entries=[];prev="GENESIS"
for i,(typ,eid,event) in enumerate(events):
    e={"index":i,"timestamp":f"2026-07-20T15:0{i}:00Z","event_type":typ,"event_id":eid,"event":event,"previous_hash":prev}
    seal(e);entries.append(e);prev=e["entry_hash"]
checkpoint=prev

def write(i,name,ents,expected_cp,expected):
    obj={"name":name,"log_id":"urn:agp:log:deployment-demo","entries":ents,"expected_checkpoint":expected_cp,"expected":expected}
    (OUT/f"{i:03d}_{name}.json").write_text(json.dumps(obj,indent=2,sort_keys=True))

write(1,"valid_log",copy.deepcopy(entries),checkpoint,True)

x=copy.deepcopy(entries);x[2]["event"]["position"]="reject"
write(2,"tampered_event",x,checkpoint,False)

x=copy.deepcopy(entries);x.pop(3)
write(3,"deleted_entry",x,checkpoint,False)

x=copy.deepcopy(entries);x[2],x[3]=x[3],x[2]
write(4,"reordered_entries",x,checkpoint,False)

x=copy.deepcopy(entries);x=x[:-1]
write(5,"truncated_log",x,checkpoint,False)

x=copy.deepcopy(entries);x[4]["previous_hash"]="sha256:fake";seal(x[4])
write(6,"forked_history",x,checkpoint,False)

x=copy.deepcopy(entries);x[3]["entry_hash"]="sha256:"+"0"*64
write(7,"replaced_hash",x,checkpoint,False)

x=copy.deepcopy(entries);x[3]["index"]=2
write(8,"duplicate_index",x,checkpoint,False)

print("Generated 8 transparency vectors")
