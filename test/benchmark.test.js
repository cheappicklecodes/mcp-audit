import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { run, summarize, corpusDigest } from "../benchmark/bench.mjs";

const rows = run();
const summary = summarize(rows);

test("every fixture in the corpus scores exactly", () => {
  assert.deepEqual(summary.failed.map((r) => r.case), [], "regression in the locked corpus");
  assert.equal(summary.exact, rows.length);
});

test("per-row exactness agrees with the aggregate", () => {
  assert.equal(rows.filter((r) => r.exact).length, summary.exact);
  for (const r of rows) assert.equal(r.exact, summary.failed.every((f) => f.case !== r.case));
});

test("no finding is missed and no phantom finding is produced", () => {
  assert.equal(summary.fp, 0, "unexpected findings");
  assert.equal(summary.fn, 0, "missed findings");
});

test("severity agrees everywhere", () => {
  assert.equal(summary.severity, 1);
  assert.equal(summary.under + summary.over, 0);
});

test("each rule family is represented by every case type", () => {
  for (const [family, row] of Object.entries(summary.perFamily)) {
    const types = new Set(rows.filter((r) => r.family === family).map((r) => r.type));
    assert.ok(types.has("positive"), `${family} has no positive case`);
    assert.ok(types.has("negative"), `${family} has no negative case`);
    assert.equal(row.recall, 1, `${family} recall`);
    assert.equal(row.precision, 1, `${family} precision`);
  }
  assert.equal(Object.keys(summary.perFamily).length, 5);
});

test("bypass cases exist and all of them are caught", () => {
  const bypass = rows.filter((r) => r.type === "bypass");
  assert.ok(bypass.length >= 3, "the corpus needs bypass variants");
  for (const r of bypass) assert.ok(r.tp > 0, `${r.case} is not detected`);
});

test("corpus size is stable enough to be meaningful", () => {
  assert.ok(rows.length >= 35);
  assert.ok(summary.tp >= 20);
});

test("matched findings never share a reported finding", () => {
  for (const r of rows) {
    const ids = r.pairs.map((p) => p.got.id);
    assert.equal(new Set(ids).size, ids.length, `${r.case} matched one finding twice`);
  }
});

test("detection survives an extra unrelated finding", () => {
  const row = rows.find((r) => r.tp === 1);
  const noisy = {
    ...row,
    reported: [...row.reported, { id: 99, rule: "path-traversal", severity: "low", file: "x", line: 1, start: 0, end: 1 }],
  };
  const s = summarize([noisy]);
  assert.equal(s.fn, 0, "a detected vulnerability must not count as a miss");
  assert.equal(s.fp, 1);
  assert.equal(s.recall, 1);
  assert.equal(s.exact, 0);
});

test("severity drift is not a detection failure", () => {
  const row = rows.find((r) => r.pairs.length === 1);
  const [pair] = row.pairs;
  const worse = { ...row, pairs: [{ ...pair, exactSeverity: false, got: { ...pair.got, severity: "info" } }] };
  worse.drift = [{ want: pair.want.severity, got: "info", direction: "under" }];
  const s = summarize([worse]);
  assert.equal(s.tp, 1);
  assert.equal(s.fn, 0);
  assert.equal(s.under, 1);
  assert.equal(s.severity, 0);
});

test("the digest is content addressed, not inventory addressed", () => {
  const digest = corpusDigest();
  assert.match(digest, /^[0-9a-f]{64}$/);
  const other = corpusDigest({
    cases: [{ id: "x", sha256: "0".repeat(64) }, ...buildCases()],
  });
  assert.notEqual(digest, other);

  function buildCases() {
    return JSON.parse(fs.readFileSync("benchmark/manifest.lock.json", "utf8")).cases;
  }
});

test("the manifest covers every case and every file", () => {
  const manifest = JSON.parse(fs.readFileSync("benchmark/manifest.lock.json", "utf8"));
  assert.equal(manifest.algorithm, "sha256");
  assert.equal(manifest.caseCount, manifest.cases.length);
  assert.equal(manifest.caseCount, rows.length);
  for (const entry of manifest.cases) {
    const dir = path.join("benchmark", entry.path);
    assert.ok(fs.existsSync(dir), `${entry.id} has no directory`);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/, `${entry.id} case digest is not a full hash`);
    assert.ok(Object.keys(entry.files).includes("expected.json"), `${entry.id} does not hash its expectation`);
    for (const [name, hash] of Object.entries(entry.files)) {
      assert.match(hash, /^[0-9a-f]{64}$/, `${entry.id}/${name} digest is not a full hash`);
    }
  }
});
