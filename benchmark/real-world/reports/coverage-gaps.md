# Coverage gaps

Where the scanner has no eyes. Each gap is written as: what is uncovered, who demonstrated it, what the scanner did, and what change closes it.

Sorted by how much it costs in this sample, not by how interesting it is.

## Summary

| # | Gap | Demonstrated by | Rule that should fire | Status |
| ---: | --- | --- | --- | --- |
| 1 | `asyncio.create_subprocess_*` not modelled | `cmd-line-executor-MCP` | `shell-exec` | no rule |
| 2 | Python never reaches `shell-injection` | `fastfs-mcp` | `shell-injection` | gated out |
| 3 | Template literal breaks caller tracking | `wsl-filesystem` | `shell-injection` | blind |
| 4 | Resolved-then-prefix-tested path | `javillegasna`, `wsl-filesystem` | `path-traversal` | blind |
| 5 | Auth defined but not wired | `mcpserve` | `remote-no-auth` | blind |
| 6 | `os.getenv` assigned to a constant | `mcpserve` | `hardcoded-credential-default` | blind |
| 7 | Receiver-blind `exec` matching | 6 targets, 16 FPs | `shell-exec`, `shell-injection` | wrong |
| 8 | Comment lines treated as code | 39 FPs across 4 rules | several | wrong |
| 9 | `shlex.quote` / argv not recognised as mitigation | `debug-mcp`, `sonirico` | `shell-exec` | missing credit |
| 10 | No Python AST, no interprocedural provenance | all Python targets | many | architectural |

## 1. `asyncio.create_subprocess_exec` / `_shell` are in no rule

**Demonstrated by:** `MarkusPfundstein/cmd-line-executor-MCP` (group A, 3 files, grade A/100).

**Code:** `src/cmd_line_executor/server.py:36` — `await asyncio.create_subprocess_exec(*cmd_list, ...)`, with `cmd_list` built from two tool arguments at lines 31-33.

**Scanner behaviour:** zero findings. `capability.js:14` lists `execSync|exec|spawn|spawnSync|execFile|subprocess.run|os.system|Command::new|sh -c|bash -c`. The asyncio constructors are absent from that regex and from every other rule.

**Why it fails:** the sink list was written against synchronous Node and Python idioms. `asyncio` is a different import and a different call shape, and nothing in `_flow.js` or `_scope.js` knows the name.

**Change:** add both names to the capability sink list. Emit `shell-exec` (executable/argument choice) for `create_subprocess_exec` and `shell-injection` for `create_subprocess_shell`, matching how `spawn` and `exec` are already treated. Same for `asyncio.create_subprocess_shell`.

**Cost of the gap:** two whole targets can grade A while executing anything the caller asks.

**Regression test:** `benchmark/cases/exec/aio-exec-caller` and `.../aio-shell-caller`.

## 2. Python cannot reach `shell-injection` at all

**Demonstrated by:** `aj-geddes/fastfs-mcp`.

**Code:** `server.py:340` builds a command by quoting a part only when it contains a space; `server.py:42` runs it with `subprocess.run(cmd, shell=True)`.

**Scanner behaviour:** five `shell-exec` rows at `high`, one of them on line 42 with the detail "argv process spawn" — which is wrong, that call is `shell=True`. No `shell-injection`.

**Why it fails:** `shell-input.js:41` opens with `if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];`. Python has no path to the critical rule; the only thing it can reach is the generic capability line.

**Change:** port the caller-argument test to Python sinks (`subprocess.run/check_output/call/Popen` with `shell=True`, `os.system`, `os.popen`) and use the existing `shlex.quote` / argv-array signals as mitigation rather than absence of shell.

**Cost of the gap:** Python is 184 of 890 findings and the biggest single uncovered language for the critical rule. Marking every `shell=True` critical would be wrong; marking none is worse.

**Regression test:** `benchmark/cases/shell/py-shell-true-caller` plus a safe twin using `shlex.quote`.

## 3. A template literal stops caller tracking

**Demonstrated by:** `webconsulting/mcp-server-wsl-filesystem` — but the shape is ordinary and appears across the sample.

**Code:** `index.ts:600` interpolates the untrusted `pattern` into a grep argument; `index.ts:271` joins the pipeline; `index.ts:274` wraps it in `sh -c "…"`; `index.ts:276` runs it. Only `"` is escaped. `pattern = "$(id)"` executes.

**Scanner behaviour:** three `shell-exec` rows, all `inconclusive`, detail "pattern match only". No `shell-injection`.

**Why it fails:** `CALLER_ARG` takes the first argument, sees a template literal, and stops — the literal is not a caller identifier and the interpolations are not followed. The sink is also `execAsync`, whose first argument is a template, so the rule never gets as far as asking whether anything in it is caller-derived.

**Change:** expand a template literal's `${…}` holes one hop before the caller test, and add `execAsync` to the sink set.

**Cost of the gap:** removing this single blind spot would clear the largest cluster of `inconclusive` rows in the TypeScript sample.

**Regression test:** `benchmark/cases/shell/via-template` — `const c = \`grep "${p}"\`; execAsync(c)`.

## 4. Path resolved by a helper, then prefix-tested

**Demonstrated by:** `javillegasna/filesystem` (0 findings) and `mcp-server-wsl-filesystem` (3 sites).

**Code:** `javillegasna/src/core/config.py:17` — `any(path.startswith(d) for d in self.__allowed_paths)`, reached from `validations.py:27` with a path made absolute at `validations.py:35`.

**Scanner behaviour:** no `path-traversal` in either repository. In `javillegasna`, no findings at all.

**Why it fails:** `traversal.js` anchors on a join *expression* (`path.join(`, `Path /`). When the join is `os.path.abspath` in another module and the containment test is `startswith` on the result, there is nothing in the sink file to anchor to. `separatorAware()` exists and would grade this correctly, but it is only reached from a join.

**Change:** treat a local built from an absolute-path normaliser and later passed to an allowlist prefix test as a traversal sink, then reuse `separatorAware()`. Recognise `.some(d => x.startsWith(d))` as a containment test by shape.

**Cost of the gap:** the most common Python filesystem shape in the sample, and the scanner's most confident grade goes to the file with the bug.

**Regression test:** `benchmark/cases/path/bypass-resolved-prefix` and `.../bypass-resolved-some`.

## 5. Auth defined but never wired

**Demonstrated by:** `mark-oori/mcpserve`. `main.py:19-22` defines an `x-api-key` check; `main.py:29` is `# 'middleware': middleware,` inside the settings dict; the server runs over SSE on port 8005.

**Scanner behaviour:** no `remote-no-auth`. Suppressed by the presence of the strings.

**Why it fails:** `transport.js:31` is a whole-file `\b(authorization|bearer|api[_-]?key|…)\b` test with no notion of live code, no comment stripping and no wiring.

**Change:** require the containment reference to sit on an uncommented line and to reach the server constructor or transport options.

**Cost of the gap:** it produces the false positives *and* the miss from one line of code, which makes it the highest-leverage single fix in the study.

**Regression test:** `benchmark/cases/transport/middleware-commented-out` vs the existing safe case.

## 6. `os.getenv` with a default, assigned to a name

**Demonstrated by:** `mcpserve main.py:16` — `MCP_API_KEY = os.getenv("MCP_API_KEY", 'test1234')`.

**Scanner behaviour:** no finding.

**Why it fails:** `secrets.js:44` matches `os.environ.get("X", '…')` inline and `process.env.X || '…'`. A module-level `os.getenv` call with a second argument is the same fact in a different position, and the pattern is positional.

**Change:** match the call in any binding position — assignment, destructure, constant.

**Cost of the gap:** trivial to evade by moving the identical expression to a constant, which is exactly what this target does.

**Regression test:** `benchmark/cases/secrets/getenv-const-default`.

## 7. `exec` matching is receiver-blind

**Demonstrated by:** 16 false positives at two severities.

**Code:** `explainAnalyzePattern.exec(...)`, `/^(\d+)\.(\d+)\.(\d+)/.exec(version)`, `dbAdapter.exec(query)`, `re.exec(command)`, `/^---[ \t]*\r?\n/.exec(text)`.

**Scanner behaviour:** five `shell-injection` *criticals* on `RegExp.exec`. `shell-exec` matches on the same token.

**Why it fails:** `shell-input.js` uses `/\b(execSync|exec)\s*\(/`. Any `.exec(` matches, whatever the receiver is. In a database and regex-heavy sample that is most `exec` occurrences.

**Change:** require the receiver to be a child-process binding or absent (bare `exec(`), and skip `.exec(` when the receiver resolves to a `RegExp` literal or a known DB handle.

**Cost of the gap:** a critical severity that is right 1 time in 6 burns the reader's attention budget.

**Regression test:** `benchmark/cases/exec/regexp-exec-not-shell` and `.../db-exec-not-shell`, both expecting no `shell-injection`.

## 8. Comment lines count as code

**Demonstrated by:** 39 false positives across `reads-credentials` (10), `remote-no-auth` (23) and `public-bind` (6).

**Code:** `// Try to parse SSH config for this host, default to ~/.ssh/config`; `* Returns the host with "0.0.0.0" as the default`.

**Why it fails:** `stripComments()` exists in `_scope.js` and `traversal.js`/`shell-input.js` use it. `reach.js`, `transport.js` and `secrets.js` read `file.text` raw.

**Change:** apply `stripComments()` in those three rules at minimum. It is an existing helper, not new machinery.

**Cost of the gap:** nearly free to fix, and these are the rules whose subject is reach and exposure — where over-claiming is most annoying.

**Regression test:** one fixture per rule with the keyword only in a comment, expecting no finding.

## 9. Correct mitigations are not credited

**Demonstrated by:** `rira100000000/debug-mcp` (Ruby, argv exec with quoting) and `sonirico/mcp-shell` (Go, argv exec with allowlist).

**Scanner behaviour:** `shell-exec` on every spawn site at `high`, with no distinction between `exec(cmd)` on a string and `execFile(bin, [args])` with `shlex.quote` applied.

**Why it fails:** the rule cannot tell the three categories apart — shell parsing, executable choice, argument injection — even though the finding title says "Executes shell commands" for all three.

**Change:** split the rule. `shell-exec` becomes a capability descriptor for "spawns a process"; `shell-injection` stays the critical for caller-controlled strings reaching a shell parser; a third `argument-injection` covers caller-controlled argv where `--` is meaningful. Credit `shlex.quote`, `quote_shell_arg`, argv arrays and allowlists in the detail.

**Cost of the gap:** the current output has no notion of "this one is fine", which is the single thing a reader most wants.

**Regression test:** `benchmark/cases/exec/quoted-caller` (expect descriptor only, no critical).

## 10. Architectural: no AST, no interprocedural provenance

Everything above except #8 is a scoping problem, and scoping needs a parser.

Concretely, the sample shows these needing more than a regex:

- following a value across a function boundary and a module boundary (#3, #4)
- knowing which `exec` is which (#7)
- knowing whether a middleware reference is live and wired (#5)
- resolving a tool name to its handler through a registration table (`capability-mismatch`: 14 of 14 inconclusive)
- trusting a `switch` statement only when it is the `tools/call` handler (the synthetic `bypass-unrelated-switch` case already encodes this)

Regex can be patched case by case indefinitely and will keep missing the same class. The break-even is visible in this data: 130 rows landed `inconclusive` precisely because the decision needs a scope (67 `shell-exec`, 32 `path-traversal`, 14 `capability-mismatch`, 9 `broad-fs-access`, 4 `weak-allowlist`, 2 `object-merge`, 2 `remote-no-auth`). The other 92 inconclusive rows are `outbound-network`, which needs an egress policy rather than a parser.

**Change:** a real parser, scoped to the two languages that dominate the sample (JS/TS and Python), with a lexical scope table and a source-to-sink pass. Keep regex for the descriptor rules (`write-capability`, `unpinned-dependency`, `hidden-unicode` run near-perfect and cost nothing).

This is the 0.5.0 line in the changelog's own terms. It is not a nice-to-have; it is where #3 to #7 live.

## What is genuinely well covered

Worth saying plainly, because the list above is long:

- install-time execution (`install-script`, `hygiene`)
- dependency pinning (`unpinned-dependency`, 51/51)
- hidden Unicode in tool descriptions (`hidden-unicode`, 4/4)
- transport identification (`transport`, 13/15)
- capability advertisement vs implementation mismatch, as far as a regex can take it
- the tool-poisoning family, which is the project's origin and still its strongest area
