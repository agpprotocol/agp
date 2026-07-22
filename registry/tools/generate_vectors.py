#!/usr/bin/env python3
from __future__ import annotations
import copy, json, shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
REG=json.loads((ROOT/'registry/registry.json').read_text())
V=ROOT/'registry/vectors'
def enc(x): return json.dumps(x,ensure_ascii=False,indent=2).encode()+b'\n'
cases=[]
def add(name,raw,accepted,error=None): cases.append((name,raw,accepted,error))
def mut(name,fn,error):
    x=copy.deepcopy(REG); fn(x); add(name,enc(x),False,error)
add('authoritative_registry',enc(REG),True,None)
mut('unknown_top_level',lambda x:x.__setitem__('extra',True),'UNKNOWN_TOP_LEVEL_MEMBER')
mut('wrong_registry_version',lambda x:x.__setitem__('registry_version','0.9'),'INVALID_REGISTRY_VERSION')
mut('collection_not_array',lambda x:x.__setitem__('objects',{}),'INVALID_COLLECTION')
mut('invalid_identifier',lambda x:x['digest_algorithms'][0].__setitem__('id','SHA 256'),'INVALID_IDENTIFIER')
mut('duplicate_identifier',lambda x:x['signature_algorithms'].append(copy.deepcopy(x['signature_algorithms'][0])),'DUPLICATE_IDENTIFIER')
mut('unsorted_collection',lambda x:x['objects'].reverse(),'UNSORTED_COLLECTION')
mut('invalid_status',lambda x:x['digest_algorithms'][0].__setitem__('status','experimental'),'INVALID_STATUS')
mut('unsafe_integer',lambda x:x['digest_algorithms'][0].__setitem__('output_bits',9007199254740992),'INVALID_SAFE_INTEGER')
mut('object_version_mismatch',lambda x:x['objects'][0].__setitem__('schema_version',2),'INVALID_OBJECT_ID')
mut('missing_reference',lambda x:x['objects'][0].__setitem__('digest','sha-999'),'MISSING_REFERENCE')
def rr(x):
    x['digest_algorithms'].append({'id':'zz-reserved-digest','status':'reserved','spec':'spec/','description':'Reserved test algorithm.','output_bits':256})
    x['objects'][0]['digest']='zz-reserved-digest'
mut('reserved_reference',rr,'RESERVED_REFERENCE')
add('duplicate_json_member',b'{"registry_version":"0.8","registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[]}',False,'INVALID_JSON')
add('utf8_bom',b'\xef\xbb\xbf{}',False,'INVALID_JSON')
add('decimal_number',b'{"registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[],"extra":1.5}',False,'INVALID_JSON')
add('nonfinite_number',b'{"registry_version":"0.8","objects":[],"canonicalization_algorithms":[],"digest_algorithms":[],"signature_algorithms":[],"extra":NaN}',False,'INVALID_JSON')
if V.exists(): shutil.rmtree(V)
V.mkdir(parents=True)
man={'profile':'AGP-SCHEMA-REGISTRY-0.8','vectors':[]}
for i,(name,raw,accepted,error) in enumerate(cases,1):
    stem=f'{i:03d}_{name}'
    (V/f'{stem}.input.json').write_bytes(raw)
    (V/f'{stem}.meta.json').write_text(json.dumps({'vector':name,'accepted':accepted,'error_code':error},indent=2)+'\n')
    man['vectors'].append({'name':name,'input':f'{stem}.input.json','meta':f'{stem}.meta.json'})
(V/'manifest.json').write_text(json.dumps(man,indent=2)+'\n')
print(f'Generated {len(cases)} schema-registry vectors')
