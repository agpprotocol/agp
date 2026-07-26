# TPE 2.6 Independent External Reproduction

This standalone package consumes only the stable public API:

```python
from trust_primitive_engine import evaluate_trust_policy
```

It contains two frozen, cryptographically signed Decision Context 3 cases:

- a satisfied evidence-provenance evaluation;
- an unsatisfied evaluation with deterministic provenance failure projection.

The automated reproduction test builds the `agp-tpe==2.6.0` wheel and this
package, installs both in a clean temporary virtual environment, removes
`PYTHONPATH`, runs outside the AGP repository, verifies that the imported TPE
module came from `site-packages`, and checks both compact sorted-key JSON
SHA-256 result hashes.

Run from the repository root:

```bash
python trust_primitive_engine/tools/test_tpe26_external_reproduction.py
```

Expected final marker:

```text
TPE 2.6 external reproduction: 2/2 passed
```

The bundled keys and signatures are public deterministic demonstration
material and must never be used in production.
