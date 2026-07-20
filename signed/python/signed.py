from __future__ import annotations
import base64, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def cb(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def signable(e): return {k:e[k] for k in sorted(e) if k!="signature"}
def verify(v):
 e=v["envelope"]; now=v["verification_time"]; errors=[]
 req=["envelope_id","object_type","issuer","key_id","issued_at","expires_at","nonce","payload","signature"]
 miss=sorted(x for x in req if x not in e)
 if miss: errors.append("MISSING_FIELDS:"+",".join(miss))
 key=next((k for k in v["keyring"] if k["key_id"]==e.get("key_id") and k["issuer"]==e.get("issuer")),None)
 if not errors and key is None: errors.append("UNKNOWN_KEY")
 if not errors and key["algorithm"]!="Ed25519": errors.append("UNSUPPORTED_ALGORITHM")
 if not errors and key.get("revoked_at") and key["revoked_at"]<=now: errors.append("KEY_REVOKED")
 if not errors and key.get("valid_from") and now<key["valid_from"]: errors.append("KEY_NOT_YET_VALID")
 if not errors and key.get("valid_until") and now>key["valid_until"]: errors.append("KEY_EXPIRED")
 if not errors and now<e["issued_at"]: errors.append("ENVELOPE_NOT_YET_VALID")
 if not errors and now>e["expires_at"]: errors.append("ENVELOPE_EXPIRED")
 replay=e.get("issuer","")+"|"+e.get("nonce","")
 if not errors and replay in v.get("seen_nonces",[]): errors.append("REPLAY_DETECTED")
 if not errors:
  try:
   Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"])).verify(base64.b64decode(e["signature"]),cb(signable(e)))
  except (InvalidSignature,ValueError): errors.append("INVALID_SIGNATURE")
 return {"accepted":not errors,"envelope_id":e.get("envelope_id"),"error_codes":errors,"issuer":e.get("issuer"),"key_id":e.get("key_id"),"object_type":e.get("object_type"),"payload_digest":"sha256:"+hashlib.sha256(cb(e.get("payload"))).hexdigest(),"replay_token":replay}
if __name__=="__main__":
 v=json.loads(Path(sys.argv[1]).read_text()); Path(sys.argv[2]).write_bytes(cb(verify(v))+b"\n")
