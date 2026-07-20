from pathlib import Path
import json, subprocess, sys, time, statistics, inspect
ROOT=Path(__file__).resolve().parents[2]
SC=ROOT/"benchmark/scenarios";RES=ROOT/"benchmark/results"
WF=ROOT/"benchmark/workflow/workflow_engine.py";AGP=ROOT/"benchmark/agp/agp_engine.py"

def run_one(engine,src,out):
    t=time.perf_counter()
    subprocess.run([sys.executable,str(engine),str(src),str(out)],check=True)
    return (time.perf_counter()-t)*1000

def loc(path):
    return sum(1 for line in Path(path).read_text().splitlines() if line.strip() and not line.lstrip().startswith("#"))

def main():
    subprocess.run([sys.executable,str(ROOT/"benchmark/tools/generate_scenarios.py")],check=True)
    rows=[];wf_times=[];agp_times=[]
    for f in sorted(SC.glob("*.json")):
        wo=RES/(f.stem+"_workflow.json");ao=RES/(f.stem+"_agp.json")
        wt=run_one(WF,f,wo);at=run_one(AGP,f,ao)
        wf_times.append(wt);agp_times.append(at)
        w=json.loads(wo.read_text());a=json.loads(ao.read_text());src=json.loads(f.read_text())
        attack=src["expected_detection"]
        rows.append({
          "scenario":src["name"],
          "attack_expected":attack,
          "workflow_detected":bool(w["detected_attacks"]),
          "agp_detected":bool(a["detected_attacks"]),
          "workflow_outcome":w["outcome"],
          "agp_outcome":a["outcome"],
          "workflow_audit_ok":w["audit_ok"],
          "agp_audit_ok":a["audit_ok"],
          "workflow_ms":round(wt,3),
          "agp_ms":round(at,3),
          "agp_errors":a["detected_attacks"],
        })
    attack_rows=[r for r in rows if r["attack_expected"]]
    summary={
      "benchmark":"AGP-vs-Workflow-0.1",
      "scenarios":len(rows),
      "attack_scenarios":len(attack_rows),
      "workflow_attacks_detected":sum(r["workflow_detected"] for r in attack_rows),
      "agp_attacks_detected":sum(r["agp_detected"] for r in attack_rows),
      "workflow_detection_rate":sum(r["workflow_detected"] for r in attack_rows)/len(attack_rows),
      "agp_detection_rate":sum(r["agp_detected"] for r in attack_rows)/len(attack_rows),
      "workflow_loc":loc(WF),
      "agp_loc":loc(AGP),
      "workflow_median_ms":round(statistics.median(wf_times),3),
      "agp_median_ms":round(statistics.median(agp_times),3),
      "rows":rows,
      "interpretation":{
        "workflow":"Simpler and faster, but trusts coordinator state.",
        "agp":"More code and verification cost, but independently detects governance tampering."
      }
    }
    (RES/"benchmark_summary.json").write_text(json.dumps(summary,indent=2))
    print(f"Scenarios: {summary['scenarios']}")
    print(f"Workflow attack detection: {summary['workflow_attacks_detected']}/{summary['attack_scenarios']}")
    print(f"AGP attack detection: {summary['agp_attacks_detected']}/{summary['attack_scenarios']}")
    print(f"Workflow LOC: {summary['workflow_loc']} | AGP LOC: {summary['agp_loc']}")
    print(f"Median runtime ms — workflow: {summary['workflow_median_ms']} | AGP: {summary['agp_median_ms']}")
    if summary["agp_attacks_detected"] != summary["attack_scenarios"]:
        raise SystemExit(1)
if __name__=="__main__": main()
