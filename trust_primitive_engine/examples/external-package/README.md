# TPE 2.4 External Package Example

This standalone Python package consumes the public `agp-tpe==2.4.0` API.

It imports only:

```python
from trust_primitive_engine import evaluate_trust_policy
```

The application evaluates a deterministic, cryptographically signed Decision
Context 2 with TPE 2.4 context and evidence requirements, then compares the
compact sorted-key JSON result against a frozen SHA-256 digest.

Run from the AGP repository root:

```bash
python trust_primitive_engine/tools/test_external_package_integration.py
```

The isolated test builds both wheels, installs them in a clean temporary
virtual environment, removes `PYTHONPATH`, executes outside the repository,
checks that `trust_primitive_engine` came from `site-packages`, and verifies
the deterministic result hash.

Expected final marker:

```text
TPE 2.4 external package integration: 1/1 passed
```

The bundled keys and signatures are public deterministic demonstration
material and must never be used in production.
