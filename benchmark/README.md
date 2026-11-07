# Benchmark

A small, deliberately shaped corpus of MCP server code, one directory per case. It exists so a rule change can be scored instead of eyeballed.

```bash
node benchmark/bench.mjs           # report; exits 1 on any regression
node benchmark/bench.mjs --json    # same numbers, machine readable
npm test                           # runs it as a test
```

## Bias, stated up front

The same people who write the rules write the fixtures. **100% here means "no regression against shapes the rules were written to see", not "this finds real vulnerabilities".** The report prints that provenance above the numbers, per family, every run, so the figure cannot be quoted without it.

## A case is a directory

```
cases/<family>/<name>/
  index.ts        the code under test
  expected.json   schemaVersion 2
```

`index.ts` marks each sink it expects to be reported:

```ts
/* @mcpbench:path-0:start */path.join(ROOT, args.file)/* @mcpbench:path-0:end */
```

and `expected.json` names that marker:

```json
{
  "schemaVersion": 2,
  "id": "path/join-bare",
  "family": "path-traversal",
  "caseType": "positive",
  "note": "root joined to caller input, never clamped",
  "expectedFindings": [
    { "id": "path-0", "rule": "path-traversal", "severity": "high", "anchor": { "file": "index.ts", "marker": "path-0" } }
  ]
}
```

Markers are masked to spaces before scanning, so they never shift a finding. A negative case carries `"expectedFindings": []` and still needs a source file.

## Three measurements, not one score

| Measure | Question it answers |
| --- | --- |
| Exact-case | Did this case match completely, severity included? |
| Precision / recall | Was each expected finding found, and only those? |
| Severity agreement | When it was found, was the grade right? |

Detection and grading are separate. A case that finds the vulnerability *and* adds an unrelated finding is a recall hit and a precision miss — not a false negative. That distinction is the point of the split; the old scorer conflated them.

Matching is one-to-one and span-based: a reported finding must fall inside the marker for the expected one. Two findings inside one anchor cannot both satisfy it.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | valid corpus, all cases exact |
| `1` | valid corpus, at least one case regressed |
| `2` | invalid harness: bad schema, dangling marker, unreadable case |

A broken benchmark exits 2, never a falsy 0. Invalid evaluation is a harness failure, not a clean bill of health.

## Shape of the corpus

- `*/direct-*`, `*/bare` — the plain vulnerability
- `*/clamped`, `*/fixed-*`, `*/with-terminator` — the safe twin
- `*/bypass-*` — the same bug wearing a guard that looks like it applies
- `caps/*` — capability declaration against handler reality

## What is still missing

The corpus contains no independently authored cases and no held-out split. Until it does, treat the numbers as regression conformance, and expect the misses below:

- taint through a helper the scanner does not follow
- a clamp on a literal that is not the root it is joined to
- guards running before the join, on the raw input
- anything assembled at runtime (spread capabilities, dynamic registration)
- non-JavaScript beyond the narrow Python path rules

A clean run is a floor, not a certificate.
