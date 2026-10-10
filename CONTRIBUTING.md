# Contributing

Thanks for helping. The project has no runtime dependencies and aims to keep it that way.

```bash
git clone https://github.com/nirholas/agent-guard && cd agent-guard
npm test          # Node 20+, uses the built-in test runner
```

## Pull requests

- One topic per PR. Explain the problem, not only the change.
- Every behavior change needs a test in `test/guard.test.js` that fails without it.
- New scanner rules need a positive example and a false-positive check against ordinary text.
- Do not add dependencies. If you believe you must, open an issue first.
- Docs change with code: update `README.md`, `docs/`, and `CHANGELOG.md`.

## Adding a scanner rule

Rules live in `src/scanner.js` as `[name, regex]`. Keep patterns narrow and bounded (no unbounded nested quantifiers, the scanner runs on untrusted text). Add the name to the table in `docs/threat-model.md` if it covers a new class.

## Conduct

Be kind. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
