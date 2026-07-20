from pathlib import Path
import subprocess,sys,json,shutil
R=Path(__file__).resolve().parents[2];V=R/'signed/vectors';P=R/'signed/results/python';G=R/'signed/results/go';B=R/'signed/results/agp-signed-go'
subprocess.run([sys.executable,str(R/'signed/tools/generate_signed_vectors.py')],check=True)
for d in(P,G):shutil.rmtree(d,ignore_errors=True);d.mkdir(parents=True)
subprocess.run(['go','build','-o',str(B),'./cmd/agp-signed'],cwd=R/'signed/go',check=True)
rows=[]
for f in sorted(V.glob('*.json')):
 po=P/f.name;go=G/f.name
 subprocess.run([sys.executable,str(R/'signed/python/signed.py'),str(f),str(po)],check=True)
 subprocess.run([str(B),str(f),str(go)],check=True)
 a,b=po.read_bytes(),go.read_bytes();src=json.loads(f.read_text());rec=json.loads(a);ok=a==b and rec['accepted']==src['expected'];rows.append({'vector':f.name,'accepted':rec['accepted'],'expected':src['expected'],'byte_identical':a==b,'passed':ok,'errors':rec['error_codes']})
s={'profile':'AGP-Signed-Conformance-0.4','vectors':len(rows),'passed':sum(x['passed'] for x in rows),'failed':sum(not x['passed'] for x in rows),'byte_identical':all(x['byte_identical'] for x in rows),'rows':rows};(R/'signed/results/summary.json').write_text(json.dumps(s,indent=2));print(f"AGP v0.4 Signed Conformance: {s['passed']}/{s['vectors']} passed");print(f"Byte-identical verification receipts: {s['byte_identical']}");raise SystemExit(1 if s['failed'] else 0)
