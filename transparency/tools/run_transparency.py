from pathlib import Path
import json, subprocess, shutil, sys
ROOT=Path(__file__).resolve().parents[2]
V=ROOT/"transparency/vectors";RP=ROOT/"transparency/results/python";RG=ROOT/"transparency/results/go"
BIN=ROOT/"transparency/results/agp-log-go"
def run(c,cwd=None): subprocess.run(c,cwd=cwd,check=True)
def main():
    run([sys.executable,str(ROOT/"transparency/tools/generate_vectors.py")])
    for d in [RP,RG]:
        if d.exists(): shutil.rmtree(d)
        d.mkdir(parents=True)
    run(["go","build","-o",str(BIN),"./cmd/agp-log"],cwd=ROOT/"transparency/go")
    rows=[]
    for f in sorted(V.glob("*.json")):
        po,go=RP/f.name,RG/f.name
        run([sys.executable,str(ROOT/"transparency/python/transparency.py"),str(f),str(po)])
        run([str(BIN),str(f),str(go)])
        pb,gb=po.read_bytes(),go.read_bytes()
        src=json.loads(f.read_text());rec=json.loads(pb)
        ok=(pb==gb and rec["accepted"]==src["expected"])
        rows.append({"vector":f.name,"accepted":rec["accepted"],"expected":src["expected"],"byte_identical":pb==gb,"passed":ok,"errors":rec["error_codes"]})
    summary={"profile":"AGP-Transparency-0.5","vectors":len(rows),"passed":sum(x["passed"] for x in rows),"failed":sum(not x["passed"] for x in rows),"byte_identical":all(x["byte_identical"] for x in rows),"rows":rows}
    (ROOT/"transparency/results/summary.json").write_text(json.dumps(summary,indent=2))
    print(f"AGP v0.5 Transparency: {summary['passed']}/{summary['vectors']} passed")
    print(f"Byte-identical audit receipts: {summary['byte_identical']}")
    if summary["failed"]: raise SystemExit(1)
if __name__=="__main__": main()
