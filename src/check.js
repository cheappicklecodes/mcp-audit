import path from 'node:path';
import { scan, grade, counts } from './engine.js';
import { discover } from './discover.js';
import { LOCK_NAME, readLock, fingerprint, serverKey } from './lock.js';

const log = (...args) => process.stderr.write(`${args.join(' ')}\n`);

export function checkLock(root, opts) {
  const lock = readLock(path.join(root, LOCK_NAME));
  if (!lock) {
    log(`error: no ${LOCK_NAME} in ${root} — run \`mcp-audit . --lock\` first`);
    return 2;
  }

  const key = serverKey(root);
  const stored = lock.servers[key];
  if (!stored) {
    log(`error: ${key} is not listed in ${LOCK_NAME}`);
    return 2;
  }

  const { files } = discover(root, { exclude: opts.exclude, include: opts.include });
  const changed = stored.fingerprint !== fingerprint(root, files);
  const result = scan(root, opts);
  const regressed = result.score < stored.score - 5;

  if (!changed && !regressed) {
    if (!opts.quiet) process.stdout.write(`ok — ${key} matches ${LOCK_NAME} (${result.score}/100)\n`);
    return 0;
  }

  if (changed) log(`\n${key} changed since it was audited on ${stored.auditedAt}`);
  if (regressed) log(`grade fell ${stored.score} → ${result.score} (${stored.grade} → ${grade(result.score).letter})`);

  const tally = counts(result.findings);
  const worse = ['critical', 'high', 'medium'].filter((s) => (tally[s] ?? 0) > (stored.counts?.[s] ?? 0));
  if (worse.length) log(`new findings: ${worse.map((s) => `${tally[s]} ${s}`).join(', ')}`);

  log(`\nreview the diff, then accept with \`mcp-audit . --lock\`\n`);
  return 1;
}