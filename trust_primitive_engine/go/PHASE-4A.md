# Go TPE Phase 4A Final Evaluation Assembly

## Scope

This increment:

- promotes signature and evaluation-input representations into
  `internal/model`;
- extracts deterministic signer projection into `internal/engine`;
- extracts complete TPE 2 evaluation-object assembly into `internal/engine`;
- keeps the bounded CLI as decoding, receipt, and output glue.

The public `tpe.Evaluate` facade remains intentionally unfrozen for Phase 4B.
