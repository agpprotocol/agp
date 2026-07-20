# AGP 120-Second Challenge

A dependency-free demonstration of the core AGP idea:

> An approval must remain bound to the exact proposal that was reviewed.

## Run

From the repository root:

    python3 examples/120_second_demo/demo.py

Or:

    cd examples/120_second_demo
    python3 demo.py

No external packages are required.

## Scenario

1. A release agent proposes deploying `payment-service:2.4.1`.
2. Security and Operations approve that exact proposal.
3. The coordinator changes the artifact to an unreviewed version.
4. A minimal workflow baseline sees two approvals and accepts the deployment.
5. AGP recomputes the proposal root and detects the mismatch.
6. An independent auditor reproduces the result.

## Expected result

    WORKFLOW BASELINE

    ✓ Deployment approved
      Reason: required approval count is present.

    AGP VERIFICATION

    ✓ Approval records are valid
    ✗ INPUT_ROOT_MISMATCH
      The executed payload differs from the reviewed proposal.

    DEMO RESULT: TAMPERING DETECTED

## Valid scenario

    python3 demo.py --happy-path

## Fast mode

    python3 demo.py --fast

## Scope

This is an explanatory quickstart, not the normative AGP implementation.

It deliberately uses HMAC from Python's standard library so that it can run
without installing dependencies. The signed AGP conformance experiments in
the main repository use Ed25519, signed envelopes, replay controls,
revocation, deterministic receipts, and transparency-log verification.

## What this demo proves

It demonstrates that approvals can be cryptographically bound to a specific
canonical proposal representation, allowing a verifier to detect when a
coordinator executes a different payload.

## What this demo does not prove

It does not establish that:

- AGP is production ready;
- the canonicalization rules are complete;
- HMAC is the AGP signature mechanism;
- the benchmark represents every workflow system;
- AGP prevents undisclosed actions that no observer can see.
