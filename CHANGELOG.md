# Changelog

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