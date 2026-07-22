#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('vr',ROOT/'registry/python/validate_registry.py')
m=importlib.util.module_from_spec(spec); assert spec.loader is not None; spec.loader.exec_module(m)
BIN=ROOT/'registry/results/agp-registry-validate-go'; BIN.parent.mkdir(parents=True,exist_ok=True)
subprocess.run(['go','build','-o',str(BIN),'./cmd/agp-registry-validate'],cwd=ROOT/'registry/go',check=True)
V=ROOT/'registry/vectors'; man=json.loads((V/'manifest.json').read_text()); rows=[]
for item in man['vectors']:
    p=V/item['input']; meta=json.loads((V/item['meta']).read_text()); py=m.validate_bytes(p.read_bytes())
    gp=subprocess.run([str(BIN),str(p)],capture_output=True,text=True); go=json.loads(gp.stdout)
    same=py['accepted']==go['accepted'] and py['error_code']==go['error_code']
    expected=py['accepted']==meta['accepted'] and py['error_code']==meta['error_code']
    ok=same and expected
    rows.append({'vector':meta['vector'],'passed':ok,'python':{'accepted':py['accepted'],'error_code':py['error_code']},'go':{'accepted':go['accepted'],'error_code':go['error_code']},'cross_language_identical':same})
    print(f"{'PASS' if ok else 'FAIL'}  {meta['vector']:<28} accepted={py['accepted']} error={py['error_code']} python_go={same}")
passed=sum(r['passed'] for r in rows)
summary={'profile':man['profile'],'vectors':len(rows),'passed':passed,'failed':len(rows)-passed,'cross_language_identical':all(r['cross_language_identical'] for r in rows),'results':rows}
(ROOT/'registry/results/summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(f'AGP v0.8 Schema Registry cross-language: {passed}/{len(rows)} passed')
print(f"Python/Go acceptance and error codes identical: {summary['cross_language_identical']}")
raise SystemExit(0 if passed==len(rows) else 1)
