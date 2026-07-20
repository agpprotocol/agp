# Deployment Approval Demo

A release coordinator proposes deployment of `payments-api 2.4.0`.

Security, legal and operations approve. Finance abstains. AGP resolves the
proposal and commits every governance event to an append-only hash chain.

## Why this is not just a workflow

A conventional workflow can route approvals. AGP additionally defines:

- who possessed authority at the decision snapshot;
- how vetoes and objections affect the result;
- which exact evidence each ballot referenced;
- a deterministic resolution;
- independently verifiable signatures;
- a tamper-evident history;
- identical audit results across implementations.

## Demonstrated attacks

The conformance suite detects:

- deletion;
- replacement;
- reordering;
- truncation;
- forked history;
- duplicate indices.
