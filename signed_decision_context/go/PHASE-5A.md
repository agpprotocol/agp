# Signed Decision Context Go Phase 5A Reusable Verification API

## Scope

This increment extracts the existing strict JSON, canonicalization, structural
validation, keyring resolution, and Ed25519 verification implementation into
the reusable module package:

```text
agpprotocol.org/agp/signed-decision-context/verify
```

The command remains a compatibility wrapper and preserves the observable
`valid`, `verified`, `invalid`, and `unverified` receipts and error codes.

TPE integration remains deferred to Phase 5B.
