# Go TPE Phase 2B Structural Validation

## Scope

This increment extracts reusable TPE 2.6 validation for:

- evidence-provenance requirements;
- recursive `all_of`, `any_of`, and `not` trees;
- Trust Policy 2 root objects.

The bounded CLI retains its existing local function names as thin delegates.

Policy-reference graph validation remains in the CLI because it is still
coupled to the CLI-local policy model and controlled fixture digests.
