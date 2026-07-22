from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "decision" / "python"))

from decision import verify as verify_decision  # noqa: E402


REQUIRED_ENVELOPE_FIELDS = [
    "envelope_id",
    "object_type",
    "issuer",
    "key_id",
    "issued_at",
    "expires_at",
    "nonce",
    "payload",
    "signature",
]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def signable(envelope: dict) -> dict:
    return {
        key: envelope[key]
        for key in sorted(envelope)
        if key != "signature"
    }


def payload_digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_bytes(payload)
    ).hexdigest()


def find_key(vector: dict, envelope: dict) -> dict | None:
    return next(
        (
            key
            for key in vector.get("keyring", [])
            if key.get("key_id") == envelope.get("key_id")
            and key.get("issuer") == envelope.get("issuer")
        ),
        None,
    )


def signed_errors(vector: dict) -> list[str]:
    envelope = vector.get("envelope")

    if not isinstance(envelope, dict):
        return ["INVALID_ENVELOPE"]

    missing = sorted(
        field
        for field in REQUIRED_ENVELOPE_FIELDS
        if field not in envelope
    )

    if missing:
        return ["MISSING_FIELDS:" + ",".join(missing)]

    verification_time = vector.get("verification_time")

    if not isinstance(verification_time, str):
        return ["INVALID_VERIFICATION_TIME"]

    key = find_key(vector, envelope)

    if key is None:
        return ["UNKNOWN_KEY"]

    if key.get("algorithm") != "Ed25519":
        return ["UNSUPPORTED_ALGORITHM"]

    if (
        key.get("revoked_at")
        and key["revoked_at"] <= verification_time
    ):
        return ["KEY_REVOKED"]

    if (
        key.get("valid_from")
        and verification_time < key["valid_from"]
    ):
        return ["KEY_NOT_YET_VALID"]

    if (
        key.get("valid_until")
        and verification_time > key["valid_until"]
    ):
        return ["KEY_EXPIRED"]

    if verification_time < envelope["issued_at"]:
        return ["ENVELOPE_NOT_YET_VALID"]

    if verification_time > envelope["expires_at"]:
        return ["ENVELOPE_EXPIRED"]

    replay_token = (
        envelope.get("issuer", "")
        + "|"
        + envelope.get("nonce", "")
    )

    if replay_token in vector.get("seen_nonces", []):
        return ["REPLAY_DETECTED"]

    try:
        public_key = base64.b64decode(
            key["public_key"],
            validate=True,
        )
        signature = base64.b64decode(
            envelope["signature"],
            validate=True,
        )

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            canonical_bytes(signable(envelope)),
        )
    except (InvalidSignature, TypeError, ValueError):
        return ["INVALID_SIGNATURE"]

    return []


def empty_decision_fields() -> dict:
    return {
        "authority_set_digest": None,
        "decision_root": None,
        "execution_domain": None,
        "policy_digest": None,
        "proposal_root": None,
    }


def verify(vector: dict) -> dict:
    envelope = vector.get("envelope", {})
    payload = envelope.get("payload")
    replay_token = (
        str(envelope.get("issuer", ""))
        + "|"
        + str(envelope.get("nonce", ""))
    )

    errors = signed_errors(vector)

    base_receipt = {
        "accepted": False,
        "envelope_id": envelope.get("envelope_id"),
        "error_codes": errors,
        "issuer": envelope.get("issuer"),
        "key_id": envelope.get("key_id"),
        "object_type": envelope.get("object_type"),
        "payload_digest": payload_digest(payload),
        "replay_token": replay_token,
    }

    if errors:
        return {
            **base_receipt,
            **empty_decision_fields(),
        }

    if envelope.get("object_type") != "decision_context":
        return {
            **base_receipt,
            **empty_decision_fields(),
            "error_codes": ["WRONG_OBJECT_TYPE"],
        }

    if not isinstance(payload, dict):
        return {
            **base_receipt,
            **empty_decision_fields(),
            "error_codes": ["INVALID_DECISION_PAYLOAD"],
        }

    decision_input = {
        "proposal": payload.get("proposal"),
        "policy": payload.get("policy"),
        "authority_set": payload.get("authority_set"),
        "decision_context": payload.get("decision_context"),
        "verification_time": vector.get("verification_time"),
        "expected_execution_domain": vector.get(
            "expected_execution_domain"
        ),
    }

    decision_receipt = verify_decision(decision_input)

    return {
        "accepted": decision_receipt["accepted"],
        "authority_set_digest": decision_receipt[
            "authority_set_digest"
        ],
        "decision_root": decision_receipt["decision_root"],
        "envelope_id": envelope.get("envelope_id"),
        "error_codes": decision_receipt["error_codes"],
        "execution_domain": decision_receipt[
            "execution_domain"
        ],
        "issuer": envelope.get("issuer"),
        "key_id": envelope.get("key_id"),
        "object_type": envelope.get("object_type"),
        "payload_digest": payload_digest(payload),
        "policy_digest": decision_receipt["policy_digest"],
        "proposal_root": decision_receipt["proposal_root"],
        "replay_token": replay_token,
    }


def process_file(source: Path, target: Path) -> None:
    try:
        vector = json.loads(source.read_text(encoding="utf-8"))
        receipt = verify(vector)
    except (json.JSONDecodeError, OSError):
        receipt = {
            "accepted": False,
            "authority_set_digest": None,
            "decision_root": None,
            "envelope_id": None,
            "error_codes": ["INVALID_INPUT"],
            "execution_domain": None,
            "issuer": None,
            "key_id": None,
            "object_type": None,
            "payload_digest": payload_digest(None),
            "policy_digest": None,
            "proposal_root": None,
            "replay_token": "|",
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_bytes(receipt) + b"\n")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: verify_signed_decision.py "
            "INPUT.json|INPUT_DIR OUTPUT.json|OUTPUT_DIR"
        )

    source = Path(sys.argv[1])
    target = Path(sys.argv[2])

    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)

        for item in sorted(source.glob("*.json")):
            process_file(item, target / item.name)

        return

    process_file(source, target)


if __name__ == "__main__":
    main()
