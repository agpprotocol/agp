# AGP Trust Policy 1.0

Package contents:

- `spec/AGP-TRUST-POLICY-1.0.md`
- `registry/schemas/agp.trust-policy-1.schema.json`
- `trust_policy/README.md`

The specification is aligned with the current evaluator behavior: policy binding by identifier, version and canonical SHA-256 digest; signature verification before evaluation; deduplication by signer identity; participant and role eligibility; required signers; one flat any-of set; minimum distinct signer count; minimum combined participant weight; and deterministic failure ordering.

Copy the files into the repository root, preserving paths. Then run:

```bash
python -m json.tool registry/schemas/agp.trust-policy-1.schema.json >/dev/null
python trust_policy/tools/run_conformance.py
git diff --check
git status --short
```
