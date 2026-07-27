# Signed Decision Context Go Phase 5B-1 In-Memory API

## Scope

This increment removes filesystem coupling from the reusable verifier by adding:

```go
func ParseKeyring(raw []byte) (Keyring, error)
func VerifyTyped(value any, keyring Keyring) (VerificationResult, error)
```

`LoadKeyring` and the original map-shaped `Verify` remain as compatibility
surfaces. TPE module integration remains deferred to Phase 5B-2.
