# MCP-Audit: Real-World Security Evaluation

**Date:** 2026-11-07 · **Scanner:** mcp-audit 0.5.3 (`35e3bbb`), 33 rules, unmodified · **Targets:** 14 public MCP repositories, pinned to exact commits · **Method:** static source reading; nothing installed, built or executed · **Reviewer:** AI-assisted source review with automated triage, one pass

---

## 1. Executive summary

`mcp-audit` is useful, and its headline number is inflated by its own output mix.

Of 890 findings against 14 third-party MCP codebases, 422 were confirmed, 61 likely, 225 inconclusive and **182 false positive**. That is 69.9% confirmed-only precision — but **469 of the 890 findings are capability descriptors** ("this server can write files"), which are true and useful and not defects. Score only the 421 rows that claim something is wrong, and precision is **37.5%**.

Both numbers are real. The first is what a dashboard would show. The second is what a reader experiences: for every two weakness findings worth reading, there is more than one that is noise.

The failure mode is uniform and diagnosable. **The rules match text where they mean a call.** 46 `shell-exec` false positives are `import … from 'child_process'`; 16 more are `RegExp.exec`. Five of six `shell-injection` rows — **critical** severity — are regex `.exec()` on a version string or a JSON delimiter. `telemetry` matched the English word *plausible* 56 times.

The false negatives follow the same axis. Seven hand-found misses, six of them in-scope failures of a rule that exists:

- Two repositories graded **A, 100/100** while (a) executing `create_subprocess_exec(*caller_argv)` unconditionally and (b) shipping a `startswith` allowlist with no separator, one of which is the scanner's own documented "nearly right" example.
- Two live command-injection sinks in Python that never reach the critical rule, because `shell-injection` is gated to JS/TS.
- An auth middleware commented out of the settings dict, which the auth rule suppressed on the word "api_key".

What it does well, it does well: `unpinned-dependency` 51/51, `hidden-unicode` 4/4, `write-capability` 217/222, `dynamic-eval` 13/14. The descriptors are cheap, textual and correct. The weakness rules are where the work is.

**Verdict:** a good blast-radius reader and a weak arbiter of safety. It narrows what a human must read. It does not yet tell them what is fine, and its grades are not a safety signal — the two worst-graded-reality results in the study were both A/100.

## 2. Methodology

Fourteen repositories, three groups, cloned at `--depth 1` and checked out to a pinned SHA. No dependency install, no build, no execution. One scan per repository in JSON and SARIF, all 14 exit 0 with empty stderr. Every finding classified by reading the cited line, into `CONFIRMED` / `LIKELY` / `INCONCLUSIVE` / `FALSE_POSITIVE`, plus a `kind` axis separating capability descriptors from weakness findings.

Full procedure and its limits: [`../methodology.md`](../methodology.md). Selection is by shape and language, not random.

## 3. Repository selection rationale

Group A targets the population most likely to be installed blind: seven small community servers, six of them command or filesystem, where the interesting shapes are. Group B is established third-party code, raised from the planned three to five to keep Ruby, Go and Python in the sample instead of collapsing it to TypeScript. Group C is official reference code as a control — what the rules look like on code written by the protocol authors.

Group membership is about public assurance signals, not quality. None of the fourteen is called unsafe here.

## 4. Trustworthiness assessment methodology

Not a scored model. Each target was read for publisher transparency, maintenance signal, dependency pinning, permission model, credential handling and the tool descriptions themselves. Those readings are folded into the distribution of findings rather than into a ranking, because a score would imply an ordering fourteen repos cannot support.

## 5. Exact versions

In [`../targets.json`](../targets.json), full 40-character SHAs, with branch and licence. All MIT or Apache-2.0 except `sonirico/mcp-shell` (GPL-3.0), represented by output only. Results apply to those commits and no later ones.

## 6. Language coverage

| Language | Findings | Confirmed | False pos. |
| --- | ---: | ---: | ---: |
| TypeScript (`.ts`) | 321 | 143 | 74 |
| JavaScript (`.mjs`) | 251 | 138 | 57 |
| Python (`.py`) | 184 | 60 | 30 |
| Ruby (`.rb`) | 38 | 22 | 0 |
| Go (`.go`) | 9 | 2 | 3 |
| JSON / YAML / TOML | 72 | 46 | 15 |

Python is the largest single language (184 findings, 60 confirmed) and **cannot reach the critical `shell-injection` rule at all** — it is gated to JS/TS. Ruby and Go findings are almost entirely descriptor rows; there is no Ruby or Go shell analysis either.

## 7. Scan results

14 selected, 14 scanned, 0 failures. 2,992 files in the trees, 1,911 scanned, 1,081 unsupported by extension. 890 findings: 1 critical, 197 high, 397 medium, 61 low, 26 info. 5.18 findings per 1,000 scanned lines overall, 2.45 for weakness rows.

## 8. Human review methodology

One AI-assisted pass, automated triage then line-by-line reading, with the scanner's `why`/`fix` as hypothesis rather than conclusion. A row was confirmed only after the code was opened. **No independent human second pass, no inter-rater figure.** This is the weakest part of the study and it is stated plainly rather than papered over.

## 9. Confirmed findings

422, of which 93 are weakness rows (write-capability alone accounts for 217 confirmed descriptors). Real weakness worth naming: four caller-to-shell sinks (`ffmpeg-mcp:146` critical, `mcpserve:38`, `fastfs-mcp:42`, `wsl-filesystem:273/274`), unpinned dependencies across five targets, two enabled `eval`-class sinks, and one `install-script` set of six.

## 10. False positives

182. By rule: `shell-exec` 69, `telemetry` 56, `remote-no-auth` 23, `reads-credentials` 10, `public-bind` 6, `shell-injection` 5, `write-capability` 5, `broad-fs-access` 2, `transport` 2, `dynamic-eval` 1, `outbound-network` 3.

175 of the 182 fall to six fixes that need no new machinery: receiver-awareness on `exec`, skip import lines, strip comments in three rules, require live wiring for auth, tighten the telemetry word list, ignore React routes. Per-row evidence: [`../triage/false-positives.json`](../triage/false-positives.json).

## 11. Inconclusive findings

225. `outbound-network` 92 (needs an egress policy, not a parser), `shell-exec` 67, `path-traversal` 32, `capability-mismatch` 14, `broad-fs-access` 9, `weak-allowlist` 4, `object-merge` 2, `remote-no-auth` 2, `sensitive-fallback` 3.

That 130 of them are scope problems is the strongest single argument for a parser.

## 12. Missed vulnerability patterns

Seven, in [`../triage/missed-patterns.json`](../triage/missed-patterns.json), each with sink, input path, why the rule failed and a proposed test. Headline cases: `javillegasna` A/100 with a live traversal bug, `cmd-line-executor` A/100 executing arbitrary commands, `mcpserve` auth inert, `fastfs-mcp` injection on an unquoted pattern.

This is a lower bound. There is no independent vulnerability denominator, so **recall is N/A**.

## 13. Group comparisons

| Group | Repos | Findings | Confirmed | Likely | FP | Inconcl. | Precision (all) | Precision (weak only) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A community | 7 | 37 | 25 | 2 | 5 | 5 | 83.3% | 58.3% |
| B established | 5 | 256 | 100 | 24 | 52 | 80 | 65.8% | 26.0% |
| C official | 2 | 597 | 297 | 35 | 125 | 140 | 70.4% | 39.2% |

Group A's advantage is partly composition (small command and filesystem servers, zero test files). Group B is dragged down by `dbhub`, a 45,894-line application with a frontend and seven connectors where most findings land off the MCP surface. Group C is a monorepo plus an SDK; 386 of its rows are in testish files.

## 14. Rule performance

Two rules are exact (`unpinned-dependency`, `hidden-unicode`), `write-capability` is 97.7%, and two weakness rules are below 10% (`telemetry` 6.7%, `shell-injection` 0%). Four weakness rules produced zero confirmed findings: `path-traversal`, `object-merge`, `capability-mismatch`, `broad-fs-access`.

Full tables: [`rule-performance.md`](rule-performance.md).

## 15. Technical limitations

- 14 risk-enriched repos, not a sample; precision is not an ecosystem rate
- one reviewer, one pass, one day, one scanner version; no inter-rater agreement
- a "confirmed" finding means the shape is real, not that an exploit was demonstrated
- no recall figure; the seven misses are a floor, not a rate
- severity is the scanner's own and was not re-graded
- two repositories produce 67% of the findings, so pooled rates are dominated by two large trees
- `testish` rows are 607 of 890, and the rules cannot distinguish a fixture from a tool

## 16. Development priorities

P0, all cheap and measured: receiver-aware `exec`, skip imports, strip comments in `reach`/`transport`/`secrets`, live-wire auth, tighten `telemetry`, ignore React routes — 175 of 182 false positives.

P1: asyncio subprocess sinks, Python `shell-injection`, template-literal expansion, resolved-path prefix tests, `os.getenv` binding positions, split `shell-exec` into descriptor / injection / argument three ways.

P2: scoped JS/TS then Python AST, optional and flag-gated so `npx` stays instant.

Detail and sequencing: [`roadmap-recommendations.md`](roadmap-recommendations.md), [`coverage-gaps.md`](coverage-gaps.md).

---

**The claim this study supports:** mcp-audit reliably tells you what a server can reach, and gives you a checklist of every place it might be wrong. It does not reliably tell you which of those places are wrong, and a high grade is not evidence of safety. Read the criticals. Then read the code.

**The claim it does not support:** that these fourteen repositories are a vulnerability prevalence study, or that 69.9% means anything outside this sample.
