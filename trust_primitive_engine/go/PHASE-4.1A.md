# Go TPE Phase 4.1A Basic Signer Primitives

This increment ports `required_signer` and `signer_threshold`.

The engine now threads the root policy's deterministic authorized and
role-eligible signer projection through recursive requirement evaluation,
including composition and policy references.

The existing signer-free `EvaluateRequirements` function remains available for
bounded compatibility callers. Public `tpe.Evaluate` and `tpe.EvaluateSigned`
use the signer-aware path.
