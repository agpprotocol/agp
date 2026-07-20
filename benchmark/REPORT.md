# AGP vs Workflow — Benchmark Report

## Question

Does AGP provide a measurable advantage over a conventional workflow for
high-assurance multi-agent decisions?

## Result interpretation

The conventional workflow is expected to be smaller and faster. That is not a
failure: coordination engines are optimized for routing state.

AGP is expected to detect attacks that remain invisible when the coordinator's
database is trusted as the sole source of truth.

## Decision rule

AGP is justified only when all of the following matter:

- multiple independent authorities participate;
- the coordinator cannot be fully trusted;
- evidence may change over time;
- revocation and veto semantics matter;
- external audit or dispute reconstruction is required;
- tamper-evident history has business value.

For low-risk internal automations, a workflow is probably the better choice.
For regulated, adversarial or high-impact decisions, AGP may justify its
additional cost.
