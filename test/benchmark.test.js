import { test } from "node:test";
import assert from "node:assert/strict";
import { run, summarize, manifestDigest } from "../benchmark/bench.mjs";

const rows = run();
const summary = summarize(rows);

test("every fixture in the corpus scores exactly", () => {
  assert.deepEqual(summary.failed.map((r) => r.case), [], "regression in the locked corpus");
  assert.equal(summary.exact, rows.length);
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
    assert.ok(row.recall === 1, `${family} recall ${row.recall}`);
    assert.ok(row.precision === 1, `${family} precision ${row.precision}`);
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

test("detection survives an extra unrelated finding", () => {
  const row = rows.find((r) => r.tp === 1);
  const noisy = { ...row, reported: [...row.reported, { id: 99, rule: "path-traversal", severity: "low", file: "x", line: 1, start: 0, end: 1 }] };
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

test("digest changes when the corpus changes", () => {
  const digest = manifestDigest(rows);
  assert.match(digest, /^[0-9a-f]{16}$/);
  assert.notEqual(digest, manifestDigest([...rows, { case: "extra", expected: [] }]));
});
