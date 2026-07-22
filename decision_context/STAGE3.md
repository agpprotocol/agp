# AGP Decision Context 0.9 — Stage 3

This stage adds:

- GitHub Actions conformance for Decision Context and Schema Registry.
- A guarded script that activates `agp.decision-context/1`.
- The final verification path before opening the pull request.

Apply from the repository root:

```bash
python decision_context/tools/activate_registry_entry.py
python registry/tools/generate_vectors.py
```

Then run the verification commands supplied with the package.
