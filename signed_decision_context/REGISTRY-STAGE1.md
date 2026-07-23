# Registry changes for Stage 1

Do not activate the reserved entry yet.

Update only these fields in `registry/registry.json` for
`agp.signed-decision-context/1`:

```json
{
  "status": "reserved",
  "spec": "spec/AGP-SIGNED-DECISION-CONTEXT-1.0.md",
  "description": "Self-contained Decision Context with one or more independent cryptographic attestations.",
  "schema": "registry/schemas/agp.signed-decision-context-1.schema.json"
}
```

Add a separate reserved object entry for:

```json
{
  "id": "agp.signature-statement/1",
  "status": "reserved",
  "spec": "spec/AGP-SIGNED-DECISION-CONTEXT-1.0.md",
  "description": "Typed canonical statement signed by an AGP authority over a Decision Context digest.",
  "schema_version": 1,
  "canonicalization": "agp-c14n/0.7",
  "digest": "sha-256",
  "schema": "registry/schemas/agp.signature-statement-1.schema.json"
}
```

The package does not replace `registry/registry.json` automatically because object
ordering and repository-side registry validation should be inspected first.
