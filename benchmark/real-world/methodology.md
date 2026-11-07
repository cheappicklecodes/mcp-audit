# Methodology

How this evaluation was run, what it can support, and what it cannot.

Evaluation date **2026-11-07**. Scanner **mcp-audit 0.5.3** (`35e3bbb`), 33 rules, **no rule was changed for this run**.

## The question

Does `mcp-audit` help a person read an MCP server they are about to trust?

That decomposes into four questions that need four different kinds of evidence, and only the first one is cheap:

| Question | Evidence needed | Status here |
| --- | --- | --- |
| Does it still catch what it was written to catch? | a corpus, held fixed | measured — `benchmark/cases`, 36 cases |
| Does it say true things about code it did not write? | classification of real findings | measured — 890 findings classified |
| Does it find the bugs that matter? | an independent denominator | **not measured** |
| Would a person get the same answers? | a second human pass | **not measured** |

The last two are where a scanner normally over-claims. Both are marked *N/A* rather than estimated.

## Target selection

Fourteen public repositories, pinned in [`targets.json`](targets.json), full SHAs. Three groups are kept separate throughout:

- **Group A — 7 low-assurance community servers.** Small publishers, no visible org backing, often a single author. Selected *because* they are the population a person is most likely to install blind, and because six of the seven are command or filesystem servers, which is where the interesting shapes are.
- **Group B — 5 established third-party servers.** Larger, maintained, still third-party. Raised from the planned 3 so that Ruby (debug-mcp), Go (mcp-shell, and portertech under A) and Python execution/query servers stayed in the sample instead of collapsing it to TypeScript.
- **Group C — 2 official/reference implementations** (`modelcontextprotocol/servers`, `modelcontextprotocol/python-sdk`). Controls: what the rules look like against code written by the protocol authors themselves.

Selection was by shape and language first, publisher profile second. It is **not** a random sample.

### What the sample cannot say

- not a prevalence study — you cannot read "x% of MCP servers are vulnerable" off this
- Group A is risk-enriched (six of seven are shell or filesystem servers), so group A precision is not the ecosystem's precision
- two repositories (dbhub, mcp/servers) produce 67% of all findings, so pooling everything into one rate lets the biggest trees set the number
- Group C includes SDK and reference code, not only runnable servers

## Acquisition and isolation

```
git clone --depth 1 --filter=blob:none <url>
git -C <clone> checkout <pinned sha>
```

Verified SHA per clone before scanning. Then, per brief: **no `npm install`, no `pip install`, no build, no test run — the servers are never executed.** Everything below is file reading.

Clones live outside the repository; only scan output is committed. No third-party source tree is vendored here. All 14 are MIT or Apache-2.0 except `sonirico/mcp-shell`, which is GPL-3.0 and is therefore represented only by output, never by copied source.

## Scanning

One run per repository, `--format json` and `--format sarif`, exit code recorded.

```
mcp-audit <clone> --format json  > scans/<repo>/findings.json
mcp-audit <clone> --format sarif > scans/<repo>/findings.sarif
```

All 14 exited `0` (findings do not fail the build unless `--fail-on` is set) and none wrote to stderr. Raw output is preserved verbatim, with one edit: the absolute clone path in `root` is rewritten to `src/<repo>` so the files are machine-independent.

## Review

Every one of the 890 findings was classified by reading the cited line and enough surrounding code to decide what it is. Four classes, and the split matters more than the labels:

| Class | Meaning |
| --- | --- |
| `CONFIRMED` | the described operation is really there and really does what the rule says |
| `LIKELY` | the shape is real; whether it is dangerous depends on context the file does not settle |
| `INCONCLUSIVE` | the rule matched, but static reading cannot settle it either way |
| `FALSE_POSITIVE` | the rule matched something that is not the thing the rule is about |

A fifth axis cuts across all of them: `kind`.

- **`capability`** (469 findings) — a descriptor. *This server can write files.* True and useful, but not a defect. Counting them as vulnerabilities is the single easiest way to inflate a number.
- **`weakness`** (421 findings) — a shape that can go wrong. This is the set precision should be computed over.

Precision over all 890 and precision over the 421 weakness rows are both reported, because the first flatters and the second is the one that matters.

The reviewer is **AI-assisted**: automated triage first, then line-by-line reading with the scanner's own `why`/`fix` text as hypothesis, not conclusion. A finding was only confirmed after the code was read. **This is not an independent human second pass**, and no inter-rater agreement figure exists.

## Metrics and denominators

- Human-validated rate `= 100 × (confirmed + likely) / (confirmed + likely + falsePositive)`. Inconclusive rows are excluded, not scored either way.
- Confirmed-only precision `= 100 × confirmed / (confirmed + falsePositive)`.
- **Recall is not reported.** There is no independent list of the real vulnerabilities in these 14 targets, so any recall figure would be a guess. The 7 misses in [`triage/missed-patterns.json`](triage/missed-patterns.json) are a *lower bound* on false negatives, found by hand, not a rate.

## Independent miss-hunting

Scan output was not treated as the answer. Each server's entry point, tool schemas and path handling were read directly, and seven places where a real weakness exists *and* the scanner said nothing were recorded with sink, input path, and the reason the rule failed.

Two of those seven are outside the current ruleset (no rule covers the pattern); five are in-scope failures of a rule that exists. They are graded by hand and reproduce the target's own string building in a throwaway script — the target is still never executed.

## Known limits of this document

- One reviewer, one day, one scanner version.
- Severity is the scanner's, not re-graded here. A confirmed finding can still be a low-impact one.
- A confirmed finding means "the shape is real", not "there is a live exploitable bug". Nobody ran an exploit.
- Third-party repositories move. The SHAs in `targets.json` are the only versions these statements apply to.
