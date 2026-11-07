# Benchmark

A deliberately shaped corpus of MCP server code, one directory per case. It exists so a rule change is scored rather than eyeballed.

```bash
npm run bench                # report; 1 on any regression
npm run bench:check-lock     # verify the corpus has not drifted
npm run bench:update-lock    # accept a deliberate fixture change
npm test                     # runs the scoring as a test
```

## Bias, stated up front

The same people write the fixtures and the rules. **100% means "no regression against shapes the rules were written to see", not "this finds real vulnerabilities".** The report prints that provenance above the numbers, per family, on every run, so the figure cannot be quoted without it.

There is no independent corpus and no held-out split yet. Until there is, this is conformance, not accuracy.

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

`expected.json` names that marker:

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

A case is **flat**. A subdirectory inside it is rejected rather than skipped, because the lock hashes case bytes by name and a nested tree it does not read would be a hole the digest cannot see.

**Symlinks are rejected anywhere in the corpus**, in case discovery and in the file lists. `statSync` follows links, so a link back to an ancestor recurses until the stack runs out and a link out of the tree pulls in files that were never locked. Every entry is `lstat`ed instead, and a link is a hard error:

```
error: symlink not permitted at path/junction; bytes are not hashed
```

That matters most in CI, where the corpus arrives from an untrusted fork. A contributor's symlink is not silently trusted to point somewhere sane; it is a malformed harness (exit `2`) until it is replaced by a real directory.

The check covers the paths a link would be most useful on, not just the entries inside a case:

- `benchmark/cases` itself, so the whole corpus can be redirected at once;
- every case directory, including the intermediate `cases/<family>` level;
- `expected.json`, for every case;
- `manifest.lock.json`.

Metadata is also required to be a regular file, not merely link-free — a directory where `expected.json` belongs is a malformed case, not an unreadable one.

Rejected as malformed: unknown `family`, unknown `rule`, unknown `severity`, `caseType` outside `positive|negative|bypass`, an `id` that disagrees with the directory, duplicate finding ids, a reused marker, a marker that is never closed or is empty, an expectation on a `negative` case, and **two anchors for the same rule overlapping in one file** (overlap makes a match ambiguous, so it is refused rather than guessed at).

## Three measurements, not one score

| Measure | Question it answers |
| --- | --- |
| Exact-case | Did this case match completely, severity included? |
| Precision / recall | Was each expected finding found, and only those? |
| Severity agreement | When it was found, was the grade right? |

Detection and grading are separate. A case that finds the vulnerability *and* adds an unrelated finding is a recall hit and a precision miss — not a false negative. That distinction is the whole point of the split; the old scorer conflated them.

Matching is one-to-one, span-based and maximum-cardinality: a reported finding must fall inside the marker for an expected one, and no reported finding satisfies two expectations.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | valid corpus, every case exact |
| `1` | valid corpus, at least one case regressed |
| `2` | invalid harness: bad schema, dangling marker, overlapping anchor |
| `3` | corpus drifted from the lock |

A broken benchmark exits `2`, a drifted one `3`, never a falsy `0`. Invalid evaluation is a harness failure, not a clean bill of health.

Schema is checked before integrity on purpose: a fixture that is structurally wrong reports `2` whether or not the lock also disagrees.

## The lock

`manifest.lock.json` records a full SHA-256 per file and a length-prefixed digest per case, over the source bytes as well as the metadata. It is written only by `bench:update-lock`.

`bench` verifies it before scoring and refuses to run on a mismatch. All of these exit `3`:

- a fixture edited without relocking, including a whitespace-only change or a note edit
- a case deleted
- a case added but never locked
- a new file inside a locked case
- the manifest missing

This is what stops the corpus from being quietly weakened to make a bad rule look good. It is a hash, not a signature — someone rewriting both fixture and lock still wins, which is why the corpus wants `CODEOWNERS` and a second reviewer.

## Shape of the corpus

- `*/direct-*`, `*/bare` — the plain vulnerability
- `*/clamped`, `*/fixed-*`, `*/with-terminator` — the safe twin
- `*/bypass-*` — the same bug wearing a guard that looks like it applies
- `caps/*` — capability declaration against handler reality

## What is still missing

No independent cases, no held-out split. Expect misses on:

- taint through a helper the scanner does not follow
- a clamp on a literal that is not the root it is joined to
- guards running before the join, on the raw input
- anything assembled at runtime (spread capabilities, dynamic registration)
- non-JavaScript beyond the narrow Python path rules

A clean run is a floor, not a certificate.
