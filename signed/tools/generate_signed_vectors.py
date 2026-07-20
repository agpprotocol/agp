from pathlib import Path
import base64,json,copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'signed/vectors';OUT.mkdir(exist_ok=True)
def cb(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def key(b):
 p=Ed25519PrivateKey.from_private_bytes(bytes([b])*32);return p,base64.b64encode(p.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
P1,U1=key(1);P2,U2=key(2)
def env(iss,k,n):return {'envelope_id':'urn:agp:env:'+n,'object_type':'ballot','issuer':iss,'key_id':k,'issued_at':'2026-07-20T14:00:00Z','expires_at':'2026-07-20T16:00:00Z','nonce':n,'payload':{'ballot_id':'urn:agp:ballot:'+n,'position':'approve','sequence':1}}
def sign(e,p):
 x=dict(e);x['signature']=base64.b64encode(p.sign(cb(e))).decode();return x
def kr(rev=None):return [{'key_id':'py-key-1','issuer':'agent:python','algorithm':'Ed25519','public_key':U1,'valid_from':'2026-01-01T00:00:00Z','valid_until':'2027-01-01T00:00:00Z','revoked_at':rev},{'key_id':'go-key-1','issuer':'agent:go','algorithm':'Ed25519','public_key':U2,'valid_from':'2026-01-01T00:00:00Z','valid_until':'2027-01-01T00:00:00Z','revoked_at':None}]
def w(i,n,e,k,seen,exp):
 (OUT/f'{i:03d}_{n}.json').write_text(json.dumps({'name':n,'envelope':e,'keyring':k,'verification_time':'2026-07-20T15:00:00Z','seen_nonces':seen,'expected':exp},indent=2,sort_keys=True))
w(1,'python_signed_valid',sign(env('agent:python','py-key-1','n1'),P1),kr(),[],True)
w(2,'go_key_signed_valid',sign(env('agent:go','go-key-1','n2'),P2),kr(),[],True)
e=sign(env('agent:python','py-key-1','n3'),P1);e['payload']['position']='reject';w(3,'tampered_payload',e,kr(),[],False)
e=sign(env('agent:python','py-key-1','n4'),P1);x=bytearray(base64.b64decode(e['signature']));x[0]^=1;e['signature']=base64.b64encode(x).decode();w(4,'tampered_signature',e,kr(),[],False)
e=sign(env('agent:python','py-key-1','n5'),P1);e['key_id']='missing';w(5,'unknown_key',e,kr(),[],False)
e=env('agent:python','py-key-1','n6');e['expires_at']='2026-07-20T14:30:00Z';w(6,'expired_envelope',sign(e,P1),kr(),[],False)
e=sign(env('agent:python','py-key-1','n7'),P1);w(7,'replay',e,kr(),['agent:python|n7'],False)
e=sign(env('agent:python','py-key-1','n8'),P1);w(8,'revoked_key',e,kr('2026-07-20T14:30:00Z'),[],False)
k=kr();k[0]['valid_from']='2026-07-21T00:00:00Z';w(9,'key_not_yet_valid',sign(env('agent:python','py-key-1','n9'),P1),k,[],False)
k=kr();k[0]['public_key']=U2;w(10,'wrong_public_key',sign(env('agent:python','py-key-1','n10'),P1),k,[],False)
print('Generated 10 signed vectors')
