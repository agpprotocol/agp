# Contributing to AGP

AGP is experimental. Critical feedback, counterexamples and competing designs
are especially valuable.

## Good first contributions

- reproduce the test suites on another platform;
- report ambiguous specification language;
- add adversarial vectors;
- implement an independent resolver;
- challenge the benchmark assumptions;
- propose a real deployment scenario.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-v0.4.txt
python3 run_benchmark_all.py
```

Pull requests should explain the governance or security property being changed,
add or update deterministic vectors, preserve byte-identical cross-language
receipts and avoid generated outputs or compiled binaries.
