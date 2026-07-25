#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_DIR="$ROOT/trust_primitive_engine/examples/policy-references"
SIGNER="$ROOT/signed_decision_context/python/sign_decision_context.py"
EVALUATOR="$ROOT/trust_primitive_engine/python/evaluate_trust_policy_v2.py"

cd "$ROOT"

echo "===== GENERATE DETERMINISTIC EXAMPLE ====="
python "$EXAMPLE_DIR/generate_example.py"

echo
echo "===== SIGN AS OPERATIONS APPROVER ====="
python "$SIGNER"   "$EXAMPLE_DIR/decision-context.json"   --private-key "$EXAMPLE_DIR/operations-private-key.json"   --signer-id "authority:operations"   --key-id "key:operations:example"   --signature-id "sig:operations:example:001"   --signed-at "2026-07-24T20:01:00Z"   --output "$EXAMPLE_DIR/signed-context.json"

echo
echo "===== APPEND SECURITY REVIEWER SIGNATURE ====="
python "$SIGNER"   "$EXAMPLE_DIR/signed-context.json"   --append   --private-key "$EXAMPLE_DIR/security-private-key.json"   --signer-id "authority:security"   --key-id "key:security:example"   --signature-id "sig:security:example:001"   --signed-at "2026-07-24T20:02:00Z"   --output "$EXAMPLE_DIR/signed-context.json"

echo
echo "===== EVALUATE ROOT POLICY WITH POLICY SET ====="
python "$EVALUATOR"   "$EXAMPLE_DIR/signed-context.json"   --policy "$EXAMPLE_DIR/root-policy.json"   --policy-set "$EXAMPLE_DIR/policy-set.json"   --keyring "$EXAMPLE_DIR/keyring.json"   > "$EXAMPLE_DIR/evaluation-result.json"

cat "$EXAMPLE_DIR/evaluation-result.json"

echo
echo "===== VERIFY EXPECTED RESULT ====="
python - "$EXAMPLE_DIR/evaluation-result.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
result = json.loads(path.read_text(encoding="utf-8"))

assert result["status"] == "satisfied", result
assert result["failure_codes"] == [], result

requirements = {
    item["requirement_id"]: item
    for item in result["requirement_results"]
}

operations = requirements["requirement:operations-approval"]
reference = requirements["requirement:security-policy"]

assert operations["status"] == "satisfied", operations
assert operations["matched_signers"] == ["authority:operations"], operations

assert reference["status"] == "satisfied", reference
assert reference["matched_signers"] == ["authority:security"], reference
assert reference["referenced_policy"]["status"] == "satisfied", reference
assert reference["referenced_policy"]["failure_codes"] == [], reference

print("POLICY_REFERENCE_EXAMPLE_PASS")
PY
