import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run, summarize } from '../benchmark/bench.mjs';

const rows = run();
const summary = summarize(rows);

test('benchmark corpus is fully accounted for', () => {
  const known = rows.filter((r) => r.ok === false);
  assert.deepEqual(known.map((r) => r.case), [], `regressed: ${known.map((r) => r.case).join(', ')}`);
});

test('benchmark keeps recall above zero on every rule family', () => {
  const families = [...new Set(rows.map((r) => r.rule))].sort();
  assert.equal(families.length, 5);
  for (const rule of families) {
    const positives = rows.filter((r) => r.rule === rule && r.want.length > 0);
    const caught = positives.filter((r) => r.ok).length;
    assert.ok(positives.length >= 2, `${rule} has too few positive cases`);
    assert.ok(caught >= 2, `${rule} catches ${caught}/${positives.length}`);
  }
});

test('benchmark has both safe twins and bypass variants', () => {
  assert.ok(summary.tn >= 8, `only ${summary.tn} negative cases`);
  const bypass = rows.filter((r) => r.case.includes('bypass'));
  assert.ok(bypass.length >= 3, 'each rule family needs a bypass variant');
});

test('benchmark corpus size is stable enough to be meaningful', () => {
  assert.ok(rows.length >= 30);
});