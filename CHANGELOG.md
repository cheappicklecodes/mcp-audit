# Changelog

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