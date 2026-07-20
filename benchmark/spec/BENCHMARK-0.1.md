# AGP vs Conventional Workflow Benchmark 0.1

## Goal

Compare the same production-deployment approval process implemented as:

1. a conventional stateful workflow;
2. AGP governance with deterministic resolution, signatures and transparency log.

## Hypothesis

A workflow coordinates steps. AGP additionally makes authority, evidence,
decision rules and history independently verifiable without trusting the
coordinator.

## Measurements

- correct decision outcome;
- attack detection;
- independent auditability;
- deterministic replay;
- tamper evidence;
- implementation size;
- runtime;
- trust assumptions.

## Attack scenarios

- omitted ballot;
- altered ballot;
- reordered history;
- truncated history;
- stale evidence;
- revoked voter;
- replaced decision root;
- duplicated ballot.

The benchmark does not claim that AGP is universally superior. It asks whether
its stronger guarantees justify its additional complexity for high-assurance
multi-agent decisions.
