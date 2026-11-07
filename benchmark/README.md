# Benchmark

Deliberately small corpus of MCP-shaped code, one directory per case, so a rule change can be scored instead of eyeballed.

```bash
node benchmark/bench.mjs     # exits 1 on any miss
npm test                     # includes this as a test
```

Each case carries an `expected.json`:

```json
{ "rule": "shell-injection", "expect": ["shell-injection/critical"], "note": "why", "knownGap": false }
```

`expect` is the exact list of `rule/severity` pairs the scanner must return. An empty list means the case must scan clean.

## Shape

- `*/direct-*`, `*/bare` — the plain vulnerability
- `*/clamped`, `*/fixed-*`, `*/with-terminator` — the safe twin
- `*/bypass-*` — the same bug wearing a guard that looks like it applies
- `caps/*` — capability declaration versus handler reality

## Scoring

`bench.mjs` prints precision, recall and accuracy, and exits non-zero if any case misses. Precision counts cases with at least one unexpected finding, so a case that returns the right thing *plus* noise still counts against it.

## Honesty

This corpus was written by the same people who write the rules, so 100% here means "no regression", not "solved". Every case is a shape the current heuristics were designed to see. The next useful thing is a corpus the rules were *not* written against, which is why cases marked `knownGap` stay in the tree after they start passing: they are the shapes that broke the first attempt.

## Gap ledger

Shapes a static reader of this kind is expected to miss, kept so the misses are visible rather than silent:

- taint through a helper function the scanner does not follow
- a `startsWith` clamp on a literal that is not the root it is joined to
- guards that run before the join, on the raw input rather than the result
- anything assembled at runtime (spread capabilities, dynamic registration)
- non-JavaScript beyond the narrow Python path rules

A clean run is a floor, not a certificate.