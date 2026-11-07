# Repository comparisons

Fourteen targets, three groups, and what the scanner did with each. Every row is a real run against a pinned commit; the per-repository scan, its metadata and its SARIF are under [`../scans/`](../scans/).

Group A = low-assurance community projects. Group B = established third-party projects. Group C = official reference code, used as a control. Group membership is a statement about public assurance, not quality.

## All fourteen

| Repository | Grp | Files | Findings | Conf. | Lik. | Inconcl. | FP | Weak. | Prec. | Grade | Missed |
| --- | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: | ---: |
| `mrdainami/ffmpeg-mcp` | A | 6 | 12 | 8 | 1 | 1 | 2 | 5 | 80.0% | C/69 | 0 |
| `MarkusPfundstein/cmd-line-executor-MCP` | A | 3 | **0** | 0 | 0 | 0 | 0 | 0 | — | A/100 | **1** |
| `javillegasna/filesystem` | A | 26 | **0** | 0 | 0 | 0 | 0 | 0 | — | A/100 | **1** |
| `webconsulting/mcp-server-wsl-filesystem` | A | 4 | 11 | 5 | 1 | 4 | 1 | 5 | 83.3% | C/65 | **2** |
| `portertech/filesystem-mcp-server` | A | 38 | 2 | 0 | 0 | 0 | 2 | 2 | 0.0% | A/96 | 0 |
| `aj-geddes/fastfs-mcp` | A | 8 | 8 | 8 | 0 | 0 | 0 | 5 | 100% | C/73 | **1** |
| `mark-oori/mcpserve` | A | 5 | 4 | 4 | 0 | 0 | 0 | 1 | 100% | B/81 | **2** |
| `sonirico/mcp-shell` | B | 31 | 8 | 3 | 0 | 4 | 1 | 5 | 75.0% | B/82 | 0 |
| `rira100000000/debug-mcp` | B | 130 | 40 | 24 | 0 | 16 | 0 | 15 | 100% | C/71 | 0 |
| `bytebase/dbhub` | B | 259 | 138 | 51 | 23 | 20 | 44 | 66 | 53.7% | D/49 | 0 |
| `executeautomation/mcp-database-server` | B | 32 | 25 | 12 | 1 | 9 | 3 | 12 | 80.0% | C/70 | 0 |
| `blazickjp/arxiv-mcp-server` | B | 103 | 45 | 10 | 0 | 31 | 4 | 7 | 71.4% | C/72 | 0 |
| `modelcontextprotocol/servers` | C | 328 | 494 | 267 | 29 | 110 | 88 | 229 | 75.2% | F/12 | 0 |
| `modelcontextprotocol/python-sdk` | C | 938 | 103 | 30 | 6 | 30 | 37 | 69 | 44.8% | C/68 | 0 |

Precision = confirmed / (confirmed + false positive); it is blank where both are zero.

## The two zero-finding repositories

Both are grade **A, 100/100**. Both contain real weaknesses.

### `javillegasna/filesystem` — 26 files, 0 findings, live traversal bug

Advertises itself as a secure filesystem server. The allowlist test is:

```python
# src/core/config.py:17
return any(path.startswith(d) for d in self.__allowed_paths)
```

No separator. With `/home/user/safe` in the allowlist, `/home/user/safe-evil/secret.txt` passes and is read at `src/tools/read_file.py:32`. The scanner's `path-traversal` rule fires on join expressions; the join here is `os.path.abspath` two modules away and the test is `startswith` on the result.

Also produced **zero** of: `reads-credentials`, `write-capability`, `remote-no-auth`. It is stdio-only with a narrow allowlist, so that is defensible — but the grade does not distinguish "narrow and correct" from "narrow and broken".

### `cmd-line-executor-MCP` — 3 files, 0 findings, arbitrary command execution

The server's whole job:

```python
# src/cmd_line_executor/server.py:36
process = await asyncio.create_subprocess_exec(*cmd_list, ...)
```

`cmd` and `args` are tool arguments (server.py:110-113), neither constrained. `asyncio.create_subprocess_exec` is not in any rule. A tool that hands the model a shell and reports 100/100 is the worst possible outcome for a reader.

Both of these are recorded with full evidence as MP-1 and MP-4 in [`../triage/missed-patterns.json`](../triage/missed-patterns.json).

## Where the grade tracked reality

**`portertech/filesystem-mcp-server` — A/96, and it earned it.** The path logic is the textbook version: `filepath.EvalSymlinks` before comparison, and a separator-aware containment test at `internal/security/validate.go:227`:

```go
if strings.HasPrefix(cleanPath, cleanAllowed+string(filepath.Separator)) {
```

The two findings it did produce were both `telemetry` false positives (the words *plausible* and *segment* in prose). So: right grade, wrong reasons, and a reader who trusts the findings rather than the grade gets nothing.

`sonirico/mcp-shell` — B/82. Argv exec, a real command allowlist, an explicit `MCP_SHELL_ALLOW_UNSAFE` gate. Eight findings, one false.

## Where the grade did not

| Repository | Grade | What the grade misses |
| --- | :---: | --- |
| `javillegasna/filesystem` | A/100 | a real traversal bug |
| `cmd-line-executor-MCP` | A/100 | arbitrary command execution by design |
| `fastfs-mcp` | C/73 | found the shell, not that the shell is unquoted |
| `mcpserve` | B/81 | auth defined and commented out; default key `test1234` |

The two grade-A failures share a cause: **the scanner reads what is written, and both servers do their work through an API it does not model** (`os.path.abspath` + `startswith`, `create_subprocess_exec`). Neither is a regex tuning problem.

## Volume is not quality

`modelcontextprotocol/servers` grades **F/12** on 494 findings — 267 confirmed, which is 63% of every confirmed finding in the study. It is a monorepo of ~14 servers and a large test tree; 328 of the 390 files were scanned, and `write-capability` alone fires 177 times on legitimate write code. F here means "broad surface", not "bad", which is what the grade is documented to mean.

`bytebase/dbhub` is the opposite lesson: 138 findings, only 51 confirmed, 44 false, and 66 weakness rows — the highest absolute false-positive count in the study (44 of 182). It is also the largest TypeScript app (259 scanned files, 45,894 lines) with a frontend, a CLI, an MCPB build script and seven connector dialects, so most findings land on code that is not the MCP tool surface. Reading a `D` on a monorepo and a `D` on a 130-line server as equivalent is the mistake the grade invites.

## Test and script noise

`testish` rows (files under test/spec/scripts) are 607 of 890 findings — 68%. For `path-traversal` it is 32 of 34. Scripts and tests do join paths and spawn processes, and the rules cannot tell a fixture from a tool. Two consequences worth naming: a repository with a big test tree looks worse than the same server without one, and the confirmed rate drops because a fixture's `path.join(REPO, rel)` needs no clamp.

Weighted per group, group C carries the most testish rows (443 - it is a monorepo and an SDK), then B (164). Group A has exactly zero: 7 small servers, no test tree at all. That is a large part of why C's weakness-only precision (39.2%) sits below A's (58.3%), and it means the two are not measuring the same kind of file.

## Per-repository verdicts

- **A, and deserved:** `portertech` (correct implementation, noisy findings)
- **A, and not deserved:** `javillegasna`, `cmd-line-executor` (both missed the whole point of the server)
- **B, roughly fair:** `mcpserve` (real shell sink found, auth miss offsets it), `sonirico` (correctly low)
- **C, mostly fair:** `ffmpeg` (the critical is right, the traversal miss is not), `wsl-filesystem` (found the shell, missed both the escaping gap and the prefix bug), `fastfs` (found the sinks, under-rated them), `arxiv`, `mcp-database-server`, `debug-mcp`
- **Grade dominated by breadth:** `dbhub` (D), `mcp/servers` (F)
