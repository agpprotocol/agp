# Agent Governance Protocol (AGP)
## Canonicalization Profile 0.7

Status: Draft
Version: 0.7
Profile identifier: `AGP-Canonicalization-0.7`

## 1. Purpose

This document defines the deterministic JSON parsing and serialization rules used by AGP implementations when computing digests, signing objects, verifying signatures, linking transparency entries, and comparing protocol receipts.

The profile intentionally supports a restricted JSON domain. Implementations MUST reject values whose interoperable representation is not defined by this document.

## 2. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are to be interpreted as normative requirements.

## 3. Processing model

A conforming implementation MUST process an input document in this order:

1. enforce the input byte limit;
2. validate the byte encoding;
3. parse exactly one JSON value;
4. reject prohibited or ambiguous constructs;
5. validate nesting depth and value constraints;
6. serialize the parsed value using the canonical output rules;
7. compute any requested digest over the canonical bytes only.

An implementation MUST NOT compute an AGP digest directly over the original source bytes.

## 4. Input encoding

### 4.1 UTF-8

Input MUST be valid UTF-8.

A UTF-8 byte order mark (`EF BB BF`) MUST NOT be present.

Invalid UTF-8 MUST be rejected with:

`INVALID_UTF8`

A UTF-8 byte order mark MUST be rejected with:

`UTF8_BOM_NOT_ALLOWED`

### 4.2 Input size

The maximum input size is 1,048,576 bytes.

An input larger than this limit MUST be rejected with:

`INPUT_TOO_LARGE`

The byte limit applies to the original input before decoding or parsing.

## 5. JSON document constraints

### 5.1 Single value

The input MUST contain exactly one JSON value, optionally surrounded by JSON whitespace.

Any non-whitespace data following the first value MUST be rejected with:

`INVALID_JSON`

### 5.2 Objects and duplicate names

Object member names MUST be strings.

Duplicate object member names MUST be rejected. An implementation MUST NOT silently retain the first or last occurrence.

Duplicate names MUST be rejected with:

`DUPLICATE_KEY`

Duplicate detection applies after JSON escape processing. For example, the names `"a"` and `"\u0061"` are duplicates.

### 5.3 Arrays

Array element order is semantically significant and MUST be preserved exactly.

Implementations MUST NOT sort, deduplicate, or otherwise reorder arrays during canonicalization.

### 5.4 Nesting depth

The maximum permitted structural depth is 64.

The root value has depth 0. Each value contained directly inside an array or object has a depth one greater than its containing value.

A value at depth 64 is permitted. A value at depth 65 or greater MUST be rejected with:

`MAX_DEPTH_EXCEEDED`

### 5.5 Invalid JSON

Malformed JSON not covered by a more specific error in this profile MUST be rejected with:

`INVALID_JSON`

## 6. Strings and Unicode

### 6.1 Unicode scalar values

After JSON escape processing, strings MUST contain only Unicode scalar values.

A valid UTF-16 surrogate pair represented through JSON escapes MUST be combined into its corresponding Unicode scalar value.

An unpaired high or low surrogate MUST be rejected with:

`INVALID_UNICODE`

### 6.2 Unicode normalization

This profile MUST NOT apply NFC, NFD, NFKC, NFKD, case folding, locale transformations, or any other Unicode normalization.

Different sequences of Unicode scalar values remain distinct even when they appear visually equivalent.

### 6.3 Canonical string escaping

Canonical strings MUST:

- begin and end with U+0022 quotation marks;
- escape U+0022 as `\"`;
- escape U+005C as `\\`;
- encode backspace as `\b`;
- encode horizontal tab as `\t`;
- encode line feed as `\n`;
- encode form feed as `\f`;
- encode carriage return as `\r`;
- encode all other code points U+0000 through U+001F as lowercase `\u00xx`;
- emit all other Unicode scalar values directly as UTF-8.

Implementations MUST NOT escape `/`, `<`, `>`, `&`, or non-ASCII scalar values unless required by the preceding rules.

Hexadecimal digits in canonical `\u` escapes MUST be lowercase.

## 7. Numbers

### 7.1 Integers only

This profile supports integers only.

Decimal fractions and exponent notation MUST be rejected with:

`DECIMAL_NOT_SUPPORTED`

This means that syntactically different JSON numbers such as `1.0`, `1e0`, and `10e-1` are not accepted even when mathematically integral.

### 7.2 Safe integer range

Permitted integers are in the inclusive range:

`-9007199254740991` through `9007199254740991`

An integer outside this range MUST be rejected with:

`INTEGER_OUT_OF_RANGE`

Canonical integers MUST be emitted in base 10 with:

- no leading plus sign;
- no unnecessary leading zeroes;
- no exponent;
- no decimal point.

### 7.3 Non-finite values

`NaN`, `Infinity`, and `-Infinity` are not JSON numbers and MUST be rejected with:

`INVALID_NUMBER`

Those character sequences remain valid when they occur inside JSON strings.

## 8. Other JSON values

The canonical spellings are:

- null: `null`
- true: `true`
- false: `false`

No alternative spelling is permitted.

## 9. Object member ordering

Object member names MUST be ordered lexicographically by Unicode scalar value sequence.

Ordering is based on the decoded member name, not on its original escaped source representation.

No locale-aware comparison may be used.

## 10. Canonical serialization

Canonical output MUST:

- be valid UTF-8;
- contain no byte order mark;
- contain no insignificant whitespace;
- contain no indentation;
- contain no line breaks within the serialized value;
- preserve array order;
- order object members as specified in Section 9;
- use the string escaping rules in Section 6.3;
- use the value spellings defined by this profile.

The canonical value itself does not include a terminating line feed.

A command-line tool MAY append one U+000A line feed to a receipt file. That line feed MUST NOT be included in the digest of the canonicalized input value.

## 11. Digest construction

When this profile is used to produce an AGP SHA-256 digest:

1. canonicalize the value according to this document;
2. encode the canonical value as UTF-8;
3. compute SHA-256 over those bytes;
4. encode the digest as lowercase hexadecimal;
5. prefix the result with `sha256:`.

The resulting form is:

`sha256:<64 lowercase hexadecimal digits>`

## 12. Canonicalization receipt

The reference command-line interface emits a receipt containing:

- `accepted`: boolean;
- `canonical`: canonical JSON text when accepted, otherwise null;
- `digest`: SHA-256 digest when accepted, otherwise null;
- `error_codes`: an array of stable error-code strings.

Receipt object members are themselves serialized canonically and the receipt file terminates with one line feed.

A rejected input MUST have:

- `accepted` equal to false;
- `canonical` equal to null;
- `digest` equal to null;
- exactly one primary error code in `error_codes`.

## 13. Error codes

The profile defines:

- `DECIMAL_NOT_SUPPORTED`
- `DUPLICATE_KEY`
- `INPUT_TOO_LARGE`
- `INTEGER_OUT_OF_RANGE`
- `INVALID_JSON`
- `INVALID_NUMBER`
- `INVALID_UNICODE`
- `INVALID_UTF8`
- `MAX_DEPTH_EXCEEDED`
- `UTF8_BOM_NOT_ALLOWED`

Implementations MUST use these exact uppercase identifiers for the corresponding failures.

When more than one defect is present, an implementation MUST report the first failure encountered according to the processing order in Section 3.

## 14. Security considerations

Canonicalization is a security boundary.

Implementations MUST reject ambiguous input rather than relying on parser-specific recovery behavior. In particular:

- duplicate object names MUST NOT be accepted;
- malformed Unicode MUST NOT be replaced silently;
- numbers MUST NOT be rounded through binary floating-point conversion;
- digests and signatures MUST use canonical bytes rather than original source bytes;
- resource limits MUST be applied before expensive processing;
- implementations MUST avoid recursive behavior that bypasses the depth limit.

Unicode normalization is intentionally excluded because normalization can change identifiers and signed content. Applications requiring normalized identifiers MUST define that constraint in an AGP schema before canonicalization.

## 15. Conformance

A conforming implementation MUST pass the official vectors under:

`canonicalization/vectors/`

Implementations are conformant only when they:

1. match the expected acceptance result;
2. match the expected primary error code;
3. emit byte-identical canonicalization receipts for accepted and rejected vectors.

The reference suite includes independent Python and Go implementations.

## 16. Relationship to earlier AGP profiles

This profile defines the canonicalization rules to be used by later AGP profiles.

Existing v0.3 through v0.6 behavior remains unchanged until those profiles explicitly adopt `AGP-Canonicalization-0.7` or a compatible successor.

Implementations MUST NOT silently reinterpret historical digests or signatures under this profile.
