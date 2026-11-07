# Real-world evaluation

**What mcp-audit does when it meets code nobody wrote for it.**

Fourteen public MCP repositories, pinned to exact commits, scanned once, and then *read* — every finding classified against the source. The question is not "how many findings did it produce" but "how many of them are true, how many are noise, and what did it walk straight past".

Evaluation date 2026-11-07 · scanner 0.5.3 (`35e3bbb`) · 33 rules · no rule changed for this run · **nothing was installed or executed**

## Result

| | All findings | Weakness findings only |
| --- | ---: | ---: |
| Findings | 890 | 421 |
| Confirmed | 422 | 93 |
| Likely | 61 | 43 |
| Inconclusive | 225 | 130 |
| False positive | 182 | 155 |
| **Confirmed-only precision** | **69.9%** | **37.5%** |
| **Human-validated rate** | **72.6%** | **46.7%** |

Two numbers, and the gap between them is the story. Most of what the scanner emits is a *capability descriptor* — "this server can write files", true and useful, not a defect. Score it all together and you get 69.9%. Strip the descriptors and score only the 421 findings that claim something is wrong, and precision falls to **37.5%**: for every two real weakness findings there is more than one false one.

| Measurement | Value | Provenance |
| --- | --- | --- |
| Synthetic benchmark accuracy | 36/36 exact cases | `benchmark/cases`, written by the same hands as the rules |
| Real-world precision (all) | 69.9% | 890 findings, 182 rejected |
| Real-world precision (weakness only) | 37.5% | 421 findings, 155 rejected |
| Independently verified recall | **N/A** | no independent vulnerability denominator |
| Human-validated rate (all) | 72.6% | 890 findings; 665 scored, 225 inconclusive excluded |

Recall is **not** reported. Nobody has the true list of bugs in these fourteen repositories, so a recall percentage would be invented. The seven misses in [`triage/missed-patterns.json`](triage/missed-patterns.json) are a lower bound on false negatives, found by reading — not a rate.

## By group

Kept separate, because pooling them lets the largest trees set the number.

| Group | Repos | Findings | Confirmed | Likely | False pos. | Inconcl. | Precision (all) | Precision (weak only) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A — community | 7 | 37 | 25 | 2 | 5 | 5 | 83.3% | 58.3% |
| B — established | 5 | 256 | 100 | 24 | 52 | 80 | 65.8% | 26.0% |
| C — official controls | 2 | 597 | 297 | 35 | 125 | 140 | 70.4% | 39.2% |

Group A looks best and that is partly an artifact: seven small servers produce 37 findings, and six of the seven run commands or serve files - the shapes the rules were built around. Group C is SDK and reference code, where a lot of the matched text is library plumbing rather than a server doing something.

Per-repository detail, including the two repositories that produced **zero** findings while executing caller-supplied commands and reading caller-supplied paths: [`summary.json`](summary.json), [`reports/repository-comparisons.md`](reports/repository-comparisons.md).

## What it got right

One finding escalated correctly all the way:

- `ffmpeg-mcp` — `spawn(args.command, { shell: true })` where the model supplies the entire command string. **Critical**, and the only critical in the sample.

Three more real caller-to-shell sinks were *reached* but left at `high`, and one of them is the interesting case:

- `mcpserve` — `subprocess.check_output(cmd, shell=True)` behind a tool literally named `shell_command`; `high`, detail "string reaches a shell". Right call, wrong ceiling.
- `fastfs-mcp` — `server.py:42`, real `shell=True` with caller-built strings, but reported as `high` with the detail **"argv process spawn"**. The detail is wrong: this call is not argv.
- `mcp-server-wsl-filesystem` — lines 273/274/317 reach `exec` with caller values, but all three land on `inconclusive` / "pattern match only".

That is the pattern of the whole sample: the scanner notices the shape and then will not commit to it. Exactly one sink in 890 findings got both the detection and the severity right.

Two well-built servers were graded correctly low: `portertech/filesystem-mcp-server` (separator-aware `HasPrefix` plus `EvalSymlinks`) scored A/96, and `sonirico/mcp-shell` (argv exec, allowlist, explicit unsafe gate) scored B/82. Portertech's only two findings were both false positives — the grade was right, the findings were not the reason.

## What it missed

Seven hand-found misses, six of them in-scope failures of a rule that already exists:

1. **`javillegasna/filesystem` — grade A, 100/100, with a live traversal bug.** `path.startswith(d)` with no separator: an allowlist of `/home/user/safe` admits `/home/user/safe-evil/secret.txt`. The rule fires on join *expressions*; here the path is resolved by a helper in another module and only prefix-tested.
2. **Same bug three times in `mcp-server-wsl-filesystem`**, on the requested, symlink-resolved and parent paths alike (lines 458, 467, 479) — and it produced 11 other findings without noticing.
3. **`mcp-server-wsl-filesystem` command injection**: the pattern escapes `"` but not `$`, reaching `sh -c` alive.
4. **`cmd-line-executor-MCP` — grade A, 0 findings**, on a server whose entire job is `asyncio.create_subprocess_exec(*caller_argv)`. `create_subprocess_*` is in no rule.
5. **`mcpserve` auth is never wired** — `# 'middleware': middleware,` is commented out of the settings dict, and `remote-no-auth` suppressed itself on the word "api_key".
6. **`mcpserve` hardcoded default key** (`test1234`) assigned from `os.getenv` to a module constant, which the rule does not match.
7. **`fastfs-mcp` shell injection** — quoting applied only when the value contains a space; `pattern="*.py;id"` runs `id`. Python never reaches the critical shell rule at all.

Full detail with sinks, input paths and proposed fixes: [`triage/missed-patterns.json`](triage/missed-patterns.json).

## The false positives

Not noise in the vague sense — they are one bug repeated: rules matching **text** where they mean **a call**.

| Rule | Findings | FP | FP rate |
| --- | ---: | ---: | ---: |
| `telemetry` | 61 | 56 | 91.8% |
| `shell-injection` | 6 | 5 | 83.3% |
| `remote-no-auth` | 31 | 23 | 74.2% |
| `reads-credentials` | 27 | 10 | 37.0% |
| `shell-exec` | 219 | 69 | 31.5% |

- `shell-exec`: 46 of 69 false positives are `import { spawn } from 'child_process'` — an import is not a launch. Another 16 are `RegExp.exec()` or `db.exec()`.
- `shell-injection`: 5 of 6 are `RegExp.exec`, a **critical** severity on a regex match.
- `telemetry`: matches the bare English words *plausible* and *segment* in prose and glossary JSON.
- `remote-no-auth`: greps the file for `api_key`; a commented-out middleware satisfies it.
- `broad-fs-access`: `<Route path="/">` in a React app and `directory: "/"` in Dependabot config.

## Files

```
targets.json                  the 14 repositories, pinned, with licence and group
summary.json                  every metric above, with its denominator
methodology.md                how it was run, and what it cannot support
scans/<repo>/metadata.json    commit, languages, counts, classification tally
scans/<repo>/findings.json    verbatim scanner output, path-normalised
scans/<repo>/findings.sarif   the same run as SARIF
triage/findings.json          all 890 findings + the classification and reason
triage/false-positives.json   the 182 rejections, by rule
triage/missed-patterns.json   the 7 hand-found misses
reports/                      executive summary, comparisons, rules, gaps, roadmap
```

Machine output is kept separate from review so anyone can re-classify without the scanner's edit history. To reproduce, clone each SHA in `targets.json` and rerun the two commands in [`methodology.md`](methodology.md).

## How to read this

- A confirmed finding means **the shape is real**, not that an exploit was demonstrated. Nothing was executed.
- Precision here is a property of *this sample on this day*, enriched toward command and filesystem servers. It is not an ecosystem rate.
- Group membership is about public assurance signals — publisher size, review surface, maintenance — not about quality. A low-popularity project is not thereby untrustworthy, and none of these fourteen is being called unsafe.
- The 14 targets are AI-assisted-reviewed once. There is no independent human second pass and no inter-rater figure.

The synthetic corpus in `benchmark/cases` answers "does it still do what it was built for". This directory answers "what happens when nobody built the input for it" — and the answer is: the capability findings hold up, the weakness findings need a reader, and the misses cluster exactly where the rules are textual.
