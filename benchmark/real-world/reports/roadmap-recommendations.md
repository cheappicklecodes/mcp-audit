# Roadmap recommendations

What the evidence justifies, in order. Each item names the demonstration, the change, the cost of not doing it, and the test that proves the fix.

Every recommendation here comes from a target that broke the current rules, not from what a scanner "ought" to have. Items with no demonstration are left out.

## The one-sentence version

Fix the four calibration bugs that cost nothing (receiver-blindness, comments, word lists, liveness), then port shell analysis to Python, then do a scoped AST for provenance — and do not add a new detection family until the `path-traversal` and `shell-injection` rules can promote anything.

## P0 — calibration, no new machinery

These are cheap, they are measured, and together they address 175 of the 182 false positives (the remaining 7 are shell-exec rows with no recognisable receiver).

### 1. Make `exec` receiver-aware

**Evidence:** 16 false positives; 5 of 6 `shell-injection` rows are `RegExp.exec` at critical.
**Change:** require a child-process receiver or a bare call; skip `.exec(` on regex literals and DB handles.
**Cost of delay:** the critical severity stays right about 1 time in 6.
**Test:** `cases/exec/regexp-exec-not-shell`, `cases/exec/db-exec-not-shell`.

### 2. Require a call, not an import, for `shell-exec`

**Evidence:** 46 of 69 `shell-exec` false positives are `import { spawn } from 'child_process'`.
**Change:** skip a match that sits on an `import` / `from … import` line.
**Cost of delay:** the highest-volume rule stays a third noise.
**Test:** `cases/exec/import-only`.

### 3. Strip comments in `reach.js`, `transport.js`, `secrets.js`

**Evidence:** 39 false positives (`reads-credentials` 10, `remote-no-auth` 23, `public-bind` 6) are comment lines. `stripComments()` already exists and two other rules use it.
**Change:** apply the existing helper.
**Cost of delay:** the reach family reports reach the code does not have.
**Test:** one keyword-in-comment fixture per rule.

### 4. Tighten the `telemetry` word list

**Evidence:** 56 of 61 false; the rule matches `plausible` in a docstring and as a JSON glossary key.
**Change:** require the identifier in an import, a dependency list, or a config key.
**Cost of delay:** a low-severity rule with 6.7% precision trains people to skip it.
**Test:** `cases/telemetry/prose-only` (no finding) beside a real SDK import (finding).

### 5. Require auth references to be live and wired

**Evidence:** 23 false positives, and the `mcpserve` miss where the middleware is commented out.
**Change:** uncommented line **and** reaching the constructor or transport options.
**Cost of delay:** one rule produces both the noise and the false negative.
**Test:** `cases/transport/middleware-commented-out`.

### 6. Stop reading React routes and Dependabot paths as filesystem roots

**Evidence:** the only 2 `broad-fs-access` false positives; 9 more inconclusive rows are spec fixtures.
**Change:** ignore `path="/"` under `<Route`, and `directory: "/"` in `.github/`.
**Cost of delay:** the rule never confirms anything.
**Test:** `cases/reach/react-route-root`.

## P1 — close the demonstrated false negatives

### 7. Add the asyncio subprocess sinks

**Evidence:** `cmd-line-executor-MCP`, grade A/100, `create_subprocess_exec(*caller_argv)`.
**Change:** add `create_subprocess_exec` / `create_subprocess_shell` (and the `asyncio.` forms) to the capability sinks; `shell-exec` for the first, `shell-injection` for the second.
**Cost of delay:** a server can hand out arbitrary execution and score 100.
**Test:** `cases/exec/aio-exec-caller`, `cases/exec/aio-shell-caller`.

### 8. Port `shell-injection` to Python

**Evidence:** `fastfs-mcp` `subprocess.run(cmd, shell=True)` with caller strings built at line 340; Python is 184 findings and cannot reach the rule.
**Change:** Python sinks, `shlex.quote` and argv arrays as mitigation.
**Cost of delay:** the largest language in the sample has no critical-severity coverage.
**Test:** `cases/shell/py-shell-true-caller` with a `shlex.quote` twin.

### 9. Expand template literals before the caller test

**Evidence:** `wsl-filesystem` lines 594 → 600 → 271 → 274; `$(id)` reaches `sh -c`.
**Change:** one-hop expansion of `${…}`, plus `execAsync` in the sink set.
**Cost of delay:** the biggest `inconclusive` cluster in the TypeScript sample.
**Test:** `cases/shell/via-template`.

### 10. Model "resolved elsewhere, prefix-tested here"

**Evidence:** `javillegasna` (A/100, live bug at `config.py:17`), `wsl-filesystem` (458/467/479).
**Change:** anchor on `abspath`/`resolve`/`realpath` assignments and on `.some(d => x.startsWith(d))`; reuse `separatorAware()`.
**Cost of delay:** the scanner's highest grade goes to the file with the bug.
**Test:** `cases/path/bypass-resolved-prefix`, `cases/path/bypass-resolved-some`.

### 11. Match `os.getenv` in any binding position

**Evidence:** `mcpserve main.py:16`, `MCP_API_KEY = os.getenv("MCP_API_KEY", 'test1234')`.
**Change:** allow assignment and destructure positions.
**Test:** `cases/secrets/getenv-const-default`.

### 12. Split `shell-exec` into its three real claims

**Evidence:** the rule calls everything "Executes shell commands", including `execFile` argv arrays (`execfile-array` in the existing corpus) and quoted Ruby.
**Change:** descriptor (`spawns a process`) / `shell-injection` (string reaches a parser) / `argument-injection` (caller argv, no `--`). Credit `shlex.quote`, allowlists and argv arrays.
**Cost of delay:** no finding currently means "this one is fine", which is what a reader wants most.
**Test:** `cases/exec/quoted-caller` expecting the descriptor and no critical.

## P2 — structural

### 13. Scoped AST for JS/TS, then Python

**Evidence:** 130 inconclusive rows that only a scope can settle; four of the six in-scope misses need a value followed across a function boundary.
**Change:** parser (Babel or `@typescript-eslint/typescript-estree`; `ast` for Python), lexical scope table, source-to-sink pass. Keep the descriptor rules textual — `write-capability` at 97.7% and `unpinned-dependency` at 100% do not need a parser and should not pay for one.
**Trade-off:** the current zero-dependency install is a real property. A parser is the first dependency this project would take; it should be optional, behind a flag, so `npx` stays instant.
**Cost of delay:** #3, #4, #5, #7 and #9 all remain partial forever.
**Test:** swap the four `bypass-*` cases in `benchmark/cases/path` and `cases/shell` from regex fixtures to AST fixtures; they must keep passing.

### 14. Publish a per-rule precision figure

**Evidence:** this study. Two rules are exact, two are below 10%, and the grade treats them the same.
**Change:** carry a measured precision and a known false-positive shape in each rule's metadata, print it under `--explain`.
**Cost of delay:** users cannot tell which of 33 rules deserve attention.

## Not recommended yet

- **New rule families.** The existing weakness rules cannot promote; another family adds surface to a problem that is depth.
- **Ecosystem prevalence claims.** Fourteen risk-enriched repos do not support them; keep saying so.
- **A hand-written parser.** The dependency is cheaper than the maintenance.
- **Lowering `path-traversal` severity to hide the promotion problem.** It is the rule people install the tool for. Fix it.

## Sequencing

| Phase | Items | Why here |
| --- | --- | --- |
| 0.6.0 | 1-6 | measured noise, existing helpers, no new concepts |
| 0.6.1 | 7-12 | the confirmed misses, still regex-sized |
| 0.7.0 | 13-14 | the parser, once the regex layer is honest |

Splitting it this way means each release is testable against the corpus as it stands, and the benchmark can only gain cases — the lock keeps it from losing any.
