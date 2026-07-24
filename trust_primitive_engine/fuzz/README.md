# AGP TPE 2.0 fuzzing

This phase adds two complementary layers:

1. `fuzz_trust_policy_v2.py` performs deterministic structural mutation of
   valid golden policies.
2. `test_fuzz_regression_seeds.py` replays committed examples that must never
   regress.

The fuzzer checks that every generated input either:

- validates deterministically, or
- is rejected deterministically with `EvaluationFailure`.

Any other exception or repeated-run disagreement is saved under
`trust_primitive_engine/fuzz/failures/`.

## Local campaign

```bash
python trust_primitive_engine/tools/fuzz_trust_policy_v2.py \
  --seed 20260723 \
  --examples 5000
```

A heavier campaign can combine multiple mutations:

```bash
python trust_primitive_engine/tools/fuzz_trust_policy_v2.py \
  --seed 20260724 \
  --examples 20000 \
  --mutations-per-example 3
```

## Regression seeds

```bash
python trust_primitive_engine/tools/test_fuzz_regression_seeds.py
```

When a fuzz campaign discovers a genuine defect, minimize the failing value,
add it as a seed, fix the engine, and keep the seed permanently.
