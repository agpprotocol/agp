# AGP TPE 2.0 byte stability

This corpus freezes the exact UTF-8 bytes produced when the runtime validates
and normalizes each valid Trust Policy 2.0 golden fixture.

It protects compatibility properties that semantic equality alone cannot
detect:

- object member ordering;
- compact JSON separators;
- Unicode encoding;
- trailing newline convention;
- normalization behavior;
- repeated-run determinism.

## Generate the initial corpus

```bash
python trust_primitive_engine/tools/generate_byte_stability_corpus.py
```

Generation refuses to overwrite an existing manifest unless `--force` is
provided. Regeneration must be an explicit compatibility decision and should
be reviewed as a byte-level API change.

## Verify

```bash
python trust_primitive_engine/tools/test_byte_stability_corpus.py
```

## Review a corpus change

When regeneration is intentional:

```bash
python trust_primitive_engine/tools/generate_byte_stability_corpus.py --force
git diff --word-diff \
  trust_primitive_engine/fixtures/byte_stability/v2
```

A changed digest is not automatically a defect, but it must be explained in
the commit or release notes.
