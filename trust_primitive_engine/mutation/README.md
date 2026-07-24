# Mutation Resilience Probe

This is a safe, repository-local mutation testing harness for the Trust
Primitive Engine evaluator.

It does not edit the working tree. Each mutant is applied to a temporary copy
of the repository and exercised against:

- engine core
- conformance
- schema/runtime parity
- primitive validation matrix
- golden compatibility corpus

## First calibration run

```bash
python trust_primitive_engine/tools/test_mutation_resilience.py   --max-mutants 30   --min-score 0
```

The first run is observational. Review surviving mutants before choosing a
quality threshold because some may be equivalent or outside externally
observable behavior.

## Full run

```bash
python trust_primitive_engine/tools/test_mutation_resilience.py   --max-mutants 0   --min-score 0
```

After classifying survivors, add targeted tests and then enforce a stable
minimum score.
