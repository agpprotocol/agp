# AGP Schema Registry

Status: Draft
Version: 0.8

## 1. Purpose

The AGP Schema Registry defines stable identifiers for protocol object types,
canonicalization profiles, digest algorithms, and signature algorithms.

The registry prevents implementations from assigning different meanings to the
same identifier and provides deterministic validation rules for registry data.

## 2. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as normative requirements.

## 3. Registry document

A registry document MUST be a JSON object accepted by AGP Canonicalization 0.7.

It MUST contain exactly these top-level members:

- `registry_version`
- `objects`
- `canonicalization_algorithms`
- `digest_algorithms`
- `signature_algorithms`

Unknown top-level members MUST be rejected.

`registry_version` MUST be the string `0.8`.

Each registry collection MUST be an array. Entries MUST be ordered
lexicographically by their `id` value. Duplicate identifiers MUST be rejected.

## 4. Common entry fields

Every registry entry MUST contain:

- `id`: stable lowercase identifier
- `status`: `active`, `deprecated`, or `reserved`
- `spec`: repository-relative specification path
- `description`: non-empty human-readable description

Identifiers MUST:

- contain only lowercase ASCII letters, digits, `.`, `/`, `_`, and `-`;
- begin and end with a lowercase ASCII letter or digit;
- be between 3 and 96 bytes in UTF-8;
- remain permanently bound to one meaning.

An identifier MUST NOT be reused after deprecation.

## 5. Object type entries

An object entry MUST additionally contain:

- `schema_version`: positive safe integer
- `canonicalization`: registered canonicalization algorithm identifier
- `digest`: registered digest algorithm identifier
- `schema`: repository-relative JSON Schema path

Object IDs use the form:

`agp.<name>/<major-version>`

The numeric suffix MUST equal `schema_version`.

An active object entry MUST reference active or deprecated algorithms, but MUST
NOT reference reserved algorithms.

## 6. Algorithm entries

Canonicalization algorithm entries MUST contain:

- `receipt_version`: positive safe integer

Digest algorithm entries MUST contain:

- `output_bits`: positive safe integer

Signature algorithm entries MUST contain:

- `key_type`
- `signature_encoding`

Algorithm identifiers are opaque stable strings. Implementations MUST compare
them byte-for-byte and MUST NOT infer compatibility from similar names.

## 7. Referential integrity

Every object entry MUST reference an existing canonicalization algorithm and an
existing digest algorithm.

References to missing identifiers MUST be rejected.

Reserved algorithms MUST NOT be used by active object entries.

## 8. Ordering

All registry arrays MUST be sorted by Unicode code point order of the `id`
member. Since registry identifiers are restricted to ASCII, this is equivalent
to bytewise UTF-8 ordering.

A registry with correct content but incorrect entry order MUST be rejected.

## 9. Extension policy

New entries MAY be added without changing `registry_version` when the registry
document structure and validation rules remain unchanged.

A breaking change to the registry document or validation rules requires a new
registry version.

Existing identifiers MUST NOT be deleted. They MAY transition:

- `reserved` to `active`
- `active` to `deprecated`

A deprecated identifier MUST NOT return to active status.

## 10. Canonical digest

The authoritative registry document MUST be canonicalized under
`agp-c14n/0.7`.

Its identity is:

`sha256:<lowercase hexadecimal SHA-256 of canonical bytes>`

The digest is informational in version 0.8. A later profile MAY define signed
registry releases.

## 11. Initial registry

The initial registry defines:

- `agp-c14n/0.7`
- `sha-256`
- `ed25519`
- reserved historical object identifiers for AGP profiles 0.3 through 0.6

Historical object identifiers remain reserved until their schemas are
normatively imported into this registry.

## 12. Validation errors

A conforming validator MUST return one of these stable error codes:

- `INVALID_JSON`
- `INVALID_REGISTRY`
- `UNKNOWN_TOP_LEVEL_MEMBER`
- `INVALID_REGISTRY_VERSION`
- `INVALID_COLLECTION`
- `INVALID_ENTRY`
- `INVALID_IDENTIFIER`
- `DUPLICATE_IDENTIFIER`
- `UNSORTED_COLLECTION`
- `INVALID_STATUS`
- `INVALID_SAFE_INTEGER`
- `INVALID_OBJECT_ID`
- `MISSING_REFERENCE`
- `RESERVED_REFERENCE`

A validator MAY include human-readable details, but automated conformance MUST
use the stable error code.

## 13. Conformance

A conforming implementation MUST:

1. accept the authoritative registry;
2. reject all official negative vectors with the expected error code;
3. preserve identifier meanings;
4. verify ordering and referential integrity;
5. operate without network access.
