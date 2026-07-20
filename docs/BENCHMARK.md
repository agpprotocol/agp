# AGP vs Workflow Benchmark

## Hypothesis

A conventional workflow coordinates state transitions. AGP adds independent
verification of authority, evidence, resolution and history.

## Scenarios

1. clean approval;
2. omitted ballot;
3. altered ballot;
4. reordered history;
5. truncated history;
6. stale evidence;
7. revoked voter;
8. replaced decision root;
9. duplicate ballot.

## Current result

```text
Workflow attack detection: 0/8
AGP attack detection:      8/8
```

## Interpretation

The workflow baseline is intentionally small and trusts coordinator state. The
result demonstrates the value of AGP's explicit verification model, not
universal superiority over all workflow products.

A production comparison should include a mature workflow engine, equivalent
custom security controls, implementation effort, operational complexity,
latency, storage overhead and independent reviewers.
