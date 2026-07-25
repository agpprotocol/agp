#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/trust_primitive_engine/examples/policy-reference-failures/run_examples.py"

cd "$ROOT"
python "$SCRIPT"
