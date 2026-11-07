# Rule performance

Per-rule outcomes across all 890 findings. Precision is `confirmed / (confirmed + false positive)`; a blank means no confirmed rows.

**Headline:** precision over everything is **69.9%**; precision over the 421 weakness findings alone — the rows that claim something is *wrong* — is **37.5%**. The difference is 469 capability descriptors ("can write files") that are true, useful and not defects. Read the weakness block, and read the capability block as inventory rather than as findings.

Some control figures, so the shape of the corpus is visible: 890 findings over 171,711 scanned code lines, which is **5.18 per 1,000 lines** overall and **2.45 per 1,000** if only weakness rows count.

## The weakness rules

These are the rules that make a claim about safety. Sorted by volume.

| Rule | Sev | Rows | Conf. | Likely | Inconcl. | FP | FP rate | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `shell-exec` | high | 219 | 83 | 0 | 67 | 69 | 31.5% | 54.6% |
| `telemetry` | low | 61 | 4 | 1 | 0 | 56 | 91.8% | 6.7% |
| `path-traversal` | high | 34 | 0 | 2 | 32 | 0 | 0.0% | — |
| `object-merge` | medium | 34 | 0 | 32 | 2 | 0 | 0.0% | — |
| `remote-no-auth` | high | 31 | 6 | 0 | 2 | 23 | 74.2% | 20.7% |
| `capability-mismatch` | info/med | 14 | 0 | 0 | 14 | 0 | 0.0% | — |
| `broad-fs-access` | high | 13 | 0 | 2 | 9 | 2 | 15.4% | 0.0% |
| `shell-injection` | critical | 6 | 0 | 1 | 0 | 5 | 83.3% | 0.0% |
| `weak-allowlist` | high | 4 | 0 | 0 | 4 | 0 | 0.0% | — |
| `hardcoded-secret` | high | 2 | 0 | 2 | 0 | 0 | 0.0% | — |
| `hardcoded-credential-default` | med | 2 | 0 | 2 | 0 | 0 | 0.0% | — |
| `unused-allowlist` | med | 1 | 0 | 1 | 0 | 0 | 0.0% | — |

Four rules produced **zero confirmed findings**: `path-traversal`, `object-merge`, `capability-mismatch` and `broad-fs-access` (plus `shell-injection`, `weak-allowlist` and the two credential rules at tiny volume). That is the most important fact in this file. These rules are the reason a reader would install the tool, and in this sample none of them ever reached a confirmation.

## The capability rules

Descriptors. True means "the server really does this", not "this is a bug".

| Rule | Sev | Rows | Conf. | Inconcl. | FP | FP rate | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `write-capability` | med | 222 | 217 | 0 | 5 | 2.3% | 97.7% |
| `outbound-network` | med | 95 | 0 | 92 | 3 | 3.2% | 0.0% |
| `unpinned-dependency` | med | 51 | 51 | 0 | 0 | 0.0% | 100% |
| `public-bind` | med | 29 | 23 | 0 | 6 | 20.7% | 79.3% |
| `reads-credentials` | high | 27 | 5 | 0 | 10 | 37.0% | 33.3% |
| `transport` | info | 15 | 13 | 0 | 2 | 13.3% | 86.7% |
| `dynamic-eval` | med | 14 | 13 | 0 | 1 | 7.1% | 92.9% |
| `install-script` | med | 6 | 0 | 0 | 0 | 0.0% | — |
| `hidden-unicode` | med | 4 | 4 | 0 | 0 | 0.0% | 100% |
| `sensitive-fallback` | med | 3 | 0 | 3 | 0 | 0.0% | — |
| `transient-host` | med | 3 | 3 | 0 | 0 | 0.0% | 100% |

`write-capability` at 217/222 is the best-behaved rule in the tool and a quarter of all output. `unpinned-dependency`, `hidden-unicode` and `transient-host` are exact — a caret range, a zero-width character and a `.ngrok` URL are facts, not judgements.

`outbound-network` deserves a note rather than a score: 92 of 95 rows are inconclusive and none are confirmed, because whether a fetch URL matters depends on egress policy the file does not contain. Scoring it 0% on precision is arithmetically fair and semantically misleading. `install-script` has the same property in reverse — 6 rows, all *likely*, no confirmation possible without running the install.

## Failure modes, in the rules' own terms

Every false positive below was verified by opening the line.

**`shell-exec` — 69 false positives.** 46 are `import { spawn } from 'node:child_process'`. An import is not a launch. 16 more are `RegExp.exec()` or `this.db.exec(...)`, which share the substring `exec` and nothing else. The rule is receiver-blind: it matches the token, not the call. Another 67 rows are `inconclusive` with detail "pattern match only", almost all of them sinks it cannot classify. On one of the 83 it confirmed, the detail is flatly wrong — `fastfs-mcp server.py:42` is `subprocess.run(..., shell=True)` and is described as "argv process spawn".

**`telemetry` — 56 of 61 false.** The rule is a word list including `segment` and `plausible`. It matches the English word *plausible* in a docstring, and `"plausible"` as a JSON glossary key. It also fires once per file, so a repository of prose produces a stack of them.

**`remote-no-auth` — 23 of 31 false.** The auth test is `/\b(authorization|bearer|api[_-]?key|…)\b/` over the whole file text, comments included. A socket-level `createServer()` in a unit test counts as an HTTP MCP endpoint. A commented-out middleware counts as auth — and in `mcpserve` that is exactly the real bug, so the same blind spot produces both the false positives and the miss.

**`reads-credentials` — 10 of 27 false.** `~/.ssh/config` in a doc comment is not a read.

**`broad-fs-access` — the only two false positives are `<Route path="/">` and `path: "/"` in a React app.** The nine inconclusive rows are mostly Ruby spec fixtures like `{ file: "/gems/x.rb" }`.

**`shell-injection` — 5 of 6 false, at critical.** `explainAnalyzePattern.exec(...)`, `/^(\d+)\.(\d+)\.(\d+)/.exec(version)`, `dbAdapter.exec(query)`, `re.exec(command)`, `/^---[ \t]*\r?\n/.exec(text)`. Not one is a shell. The only non-false row is itself mislabelled `likely`. A critical severity attached to regex matching is the most expensive calibration error in the sample, because critical is what a reader acts on.

## What worked

- `write-capability`, `unpinned-dependency`, `hidden-unicode`, `transient-host`, `dynamic-eval` and `transport` all hold above 85% precision. They are cheap, textual and correct.
- `shell-exec` found the two real command sinks worth finding (`ffmpeg-mcp:146`, `mcpserve:38`) and reached three more.
- Nothing in the sample produced a confirmed finding that turned out to be invented. The failure is over-reporting and under-committing, not fabrication.

## What to fix first

In order of evidence, not ambition:

1. **`shell-exec` receiver-blindness** — 46 import lines and 16 `RegExp` matches are free to remove. Require a call, not a token; exclude `.exec(` when the receiver is not a child-process binding.
2. **`telemetry` word list** — require the identifier to sit in an import, a dependency list or a config key, not anywhere in prose.
3. **`remote-no-auth` liveness** — the reference must be on an uncommented line and reach the server constructor.
4. **`shell-injection` receiver check** — the same fix as 1, applied to the critical rule, where it costs the most credibility.
5. **`path-traversal` promotion** — 32 of 34 rows are scripts and tests with no confirmed promotion. Either damp testish files or close the cross-function gap in `missed-patterns.json` MP-1/MP-2.

Full per-row evidence: [`../triage/false-positives.json`](../triage/false-positives.json).
