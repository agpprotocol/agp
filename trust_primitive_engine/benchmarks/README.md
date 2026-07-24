# AGP TPE 2.0 performance benchmarks

This phase establishes a reproducible local performance baseline for Trust
Policy 2.0 validation.

The benchmark deliberately remains outside `run_all_tests.py`. Timing tests
are sensitive to CPU load, power state, thermal throttling, Python version,
and hardware. Functional validation must stay deterministic and fast.

## Cases

The benchmark measures:

- every valid policy in the versioned golden corpus;
- synthetic policies containing 1, 10, 100, and 1000 requirements;
- median, mean, minimum, p95, p99, and maximum elapsed time;
- operations per second;
- peak Python allocation observed by `tracemalloc`;
- machine and Python metadata.

## Create the first baseline

Run from the repository root:

```bash
python trust_primitive_engine/tools/benchmark_tpe_v2.py \
  --write-baseline \
  trust_primitive_engine/benchmarks/baselines/mac-local.json
```

Run the benchmark while the machine is idle and connected to power. For a
more stable baseline, run it three times and retain the middle result by
median rather than the fastest result.

## Compare a later run

```bash
python trust_primitive_engine/tools/benchmark_tpe_v2.py \
  --output /tmp/agp-tpe-current.json

python trust_primitive_engine/tools/test_performance_regression.py \
  trust_primitive_engine/benchmarks/baselines/mac-local.json \
  /tmp/agp-tpe-current.json \
  --max-regression-percent 30
```

A 30 percent threshold is intentionally conservative for local development.
Do not enforce a tighter threshold until the same runner and hardware are
used consistently in CI.

## Baseline policy

A committed baseline is evidence, not a universal performance promise.
Baselines should include the runner identity in the filename when more than
one machine is used.
