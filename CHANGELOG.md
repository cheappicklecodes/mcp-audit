# Changelog

## 0.5.1

The benchmark can no longer be weakened quietly.

A review of 0.5.0 found three things, and all three were right.

- **per-case `exact` was always false.** `run()` called `exactCase(m, expected.length)` while the function read `row.expected`, which `m` did not carry. `summarize()` recomputed it, so the headline stayed correct while the exported rows lied. Rows are now built first and scored whole.
- **greedy matching could lose a real detection.** With nested anchors the first pleasing pair could consume the only finding a second expectation could ever match. Matching is now maximum-cardinality by augmenting path, severity agreement only choosing among equal-length solutions. Overlapping anchors for the same rule are additionally refused as malformed rather than silently interpreted.
- **the "digest" was inventory, not content.** It hashed case name and finding count, so a changed severity, a changed anchor or any source edit left it identical. It is now a real content digest, and `manifest.lock.json` hashes every file.

New:

- `benchmark/manifest.lock.json` - full SHA-256 per file plus a length-prefixed per-case digest, over source bytes as well as metadata. Verified before scoring; any drift exits 3.
- `npm run bench:check-lock` and `npm run bench:update-lock`. Only the update command writes the manifest.
- schema loading now validates `id`, `caseType`, `severity`, `rule`, duplicate ids and reused markers, and rejects an expectation on a negative case. Schema is checked before integrity so a malformed fixture reports 2, not 3.
- 14 harness tests that spawn the real CLI against a mutated corpus copy and pin every exit code, plus manifest coverage and content-digest tests.
- the CI `lock-check` job now runs `bench:check-lock`.

README and `benchmark/README.md` rewritten around the three measurements and the lock contract.

## 0.5.0


The benchmark stops scoring detection and grading as the same bit, and findings gain real source spans.

Previous scoring demanded an exact set match per case. If a case expected one finding and the scanner returned
that finding **plus** an unrelated one, the case counted as a false negative - the vulnerability *was* detected.
Severity was part of the match too, so "found it" and "graded it right" collapsed into one pass/fail.

- **three separate measurements.** Exact-case conformance, finding-level precision and recall, and severity
  agreement. Detection is no longer a function of noise or of the grade.
- **anchored expectations.** A case marks its sinks with `/* @mcpbench:<id>:start */` comments; a reported
  finding matches by falling inside the marker. Rewrapping a fixture no longer invalidates it, and matching is
  one-to-one, so two findings inside one anchor cannot both count.
- **`expected.json` is `schemaVersion` 2** with `id`, `family`, `caseType` and `expectedFindings`. The old shape is
  rejected, not silently zero-scored. `knownGap` is gone: a case either matches or it does not.
- **exit codes.** `0` clean, `1` regression, `2` broken harness (bad schema, dangling marker). A malformed corpus
  used to be able to look like a clean run.
- **provenance in the output.** Maintainer-authored, no independent or held-out cases, said above the numbers
  every run, so a bare "100%" cannot be quoted without it.
- every anchored rule now emits `location` with offsets and columns. `capability-mismatch` anchors on the
  capabilities block instead of the whole file, and the Python path sink spans the join expression.
- fix: the argument rule read an argv array with a parenthesis matcher, so its span ran long. Arrays now balance
  on brackets.

## 0.4.0


The guards now follow the value, and the scanner says how sure it is.

All three open defects from the review of `893208a` are closed, each with a regression test and a benchmark case.

- **A. guards were block-wide.** A `_flow.js` provenance layer binds a sink to the variable that actually feeds it.
  `allowedCommands.includes("ls")` sitting above `execSync(command)` no longer clears the finding — the review's
  exact case. Guards are graded `strong` (mentions the value and rejects), `partial` (mentions it, never rejects)
  and `unrelated` (an allowlist of something else). Partial and unrelated still report, at a lower severity.
- **B. argument injection was over-broad.** Only programs known to honour `--` are reported, the program name is
  quoted in the finding, and `execFile` sinks are covered alongside `spawn`.
- **C. capability heuristics.** `tools/call` is now required, anchored on the string or on `registerTool`/`.tool`;
  a bare `case` or `name ===` no longer proves a handler exists.
- path guards had the same block-wide bug. They are now sink-specific, and a clamp is only accepted when it is on
  the joined value and anchored on the root it was joined to, so `/srv/app-sibling` fails a check against `/srv/app`.
  `path.relative(...).startsWith('..')` is recognised as a real clamp.
- a plain parameter is caller data even without an `args.` prefix.
- every finding carries `confidence`: `confirmed`, `likely` or `inconclusive`. The text report tags the last two and
  says how many findings were pattern-matched rather than parsed; JSON and SARIF carry it too.
- **new `benchmark/` corpus** — 36 cases: vuln, safe twin and bypass variant per rule family, scored in `npm test`
  and CI for precision, recall and accuracy. The README states the gap ledger rather than implying coverage.
- grade A now reads "reads clean, not proven".
## 0.3.0

Fixes dangerous false confidence: a clamp anywhere in a file no longer silences every sink in it.

- `path-traversal` is now per-sink and scope-aware. It finds the variable a join is bound to and looks for the
  clamp in the enclosing block; an unrelated `startsWith` elsewhere no longer suppresses the finding.
- a separator-less `startsWith(ROOT)` is downgraded to medium instead of passing — `/safe-evil` starts with
  `/safe`. `path.relative`, `realpath` and `is_relative_to` are treated as real clamps.
- `raw-shell-interpolation` split into three rules with their own severities: `shell-injection` (critical),
  `caller-executable` (high), `argument-injection` (low). `execFile` with a fixed program is no longer
  reported as shell injection.
- `capability-mismatch` classifies four states, including advertised-but-unimplemented, and reports dynamic
  registration as inconclusive rather than safe.
- `unused-allowlist` ignores comments, so a name mentioned only in prose does not read as used.
- 15 adversarial tests: bypasses, partial fixes and comment-only guards.

## 0.2.0

- new rule `path-traversal` — `path.join`/`resolve` on caller input with no containment check
- new rule `raw-shell-interpolation` — caller string reaching a shell with no allowlist in front of it
- new rule `capability-mismatch` — empty `capabilities` next to tools that are actually served
- new rule `unused-allowlist` — a declared allowlist that nothing applies
- `hardcoded-credential` guidance now says to rotate at the provider, not just move the value
- `good-server` fixture now clamps paths and declares its capabilities, so it earns the grade it gets

## 0.1.0

Initial release.

- 27 rules across poisoning, supply-chain, reach, capability, secrets, transport, network, hygiene
- 0–100 grade with A–F letters
- `--explain`, `--format json|sarif|md`, `--fail-on` for CI
- `agents.lock` pinning with `--lock` and `--check`
- custom rules via `--rules-from`
- zero dependencies