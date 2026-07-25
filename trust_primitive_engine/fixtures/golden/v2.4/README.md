# TPE 2.4 Context and Evidence Golden Corpus

This corpus freezes deterministic end-to-end behavior for the five TPE 2.4
context and evidence requirements.

Each case contains:

- `root-policy.json`
- `policy-set.json`
- `evaluation-input.json`
- `expected-evaluation.json`
- `expected-evaluation.sha256`

The SHA-256 digest is computed over UTF-8 JSON serialized with sorted keys and
compact separators, without a trailing newline.

The corpus covers:

- all five TPE 2.4 requirements in a satisfied policy;
- absent and unequal context values;
- integer minimum and maximum failures;
- all four unsatisfied evidence match states;
- recursive failure projection through `policy_reference`;
- deterministic replay;
- logical result equality;
- compact byte equality;
- frozen result hashes.

`expected-evaluation.json` and `expected-evaluation.sha256` are authoritative.
