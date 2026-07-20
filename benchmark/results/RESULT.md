# Benchmark Result

- Scenarios: 9
- Attack scenarios: 8
- Workflow detected: 0/8
- AGP detected: 8/8
- Workflow LOC: 26
- AGP LOC: 60
- Workflow median runtime: 1195.708 ms
- AGP median runtime: 1257.399 ms

## Conclusion

The workflow is simpler and slightly faster but trusts coordinator state. AGP adds implementation and runtime cost in exchange for independent detection of governance tampering and reconstructible audit evidence.
