# Changelog

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