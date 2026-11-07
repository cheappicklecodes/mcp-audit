import { createHash } from 'node:crypto';
import { discover, MANIFESTS } from './discover.js';
import { severityRank } from './util.js';
import * as poisoning from './rules/tool-poisoning.js';
import * as supply from './rules/supply-chain.js';
import * as reach from './rules/reach.js';
import * as capability from './rules/capability.js';
import * as secrets from './rules/secrets.js';
import * as transport from './rules/transport.js';
import * as network from './rules/network.js';
import * as hygiene from './rules/hygiene.js';

export const ALL_RULES = [
  ...poisoning.rules,
  ...supply.rules,
  ...reach.rules,
  ...capability.rules,
  ...secrets.rules,
  ...transport.rules,
  ...network.rules,
  ...hygiene.rules,
];

export const RULE_MAP = new Map(ALL_RULES.map((r) => [r.id, r]));

const MAX_PER_RULE_FILE = 4;

export function scan(root, options = {}) {
  const { files, truncated } = discover(root, options);
  const disabled = new Set(options.disable ?? []);
  const only = options.only?.length ? new Set(options.only) : null;
  const active = ALL_RULES.filter((r) => !disabled.has(r.id) && (!only || only.has(r.id)));

  const findings = [];
  const perFileRule = new Map();
  const seen = new Set();

  for (const file of files) {
    const ctx = { root, files };
    for (const rule of active) {
      let produced;
      try {
        produced = rule.check(file, ctx) ?? [];
      } catch (err) {
        produced = [];
        if (options.verbose) console.error(`rule ${rule.id} failed on ${file.relative}: ${err.message}`);
      }
      const key = `${rule.id}\u0000${file.relative}`;
      const count = perFileRule.get(key) ?? 0;
      if (count >= MAX_PER_RULE_FILE) continue;
      for (const finding of produced) {
        if ((perFileRule.get(key) ?? 0) >= MAX_PER_RULE_FILE) break;
        const lineKey = `${rule.id}\u0000${finding.file}\u0000${finding.line}`;
        if (seen.has(lineKey)) continue;
        seen.add(lineKey);
        findings.push(finding);
        perFileRule.set(key, (perFileRule.get(key) ?? 0) + 1);
      }
    }
  }

  if (options.minSeverity) {
    const min = severityRank(options.minSeverity);
    findings.splice(0, findings.length, ...findings.filter((f) => severityRank(f.severity) >= min));
  }

  findings.sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  return {
    findings,
    filesScanned: files.length,
    truncated,
    rulesRun: active.length,
    score: score(findings, files.length),
    manifest: detectManifest(files),
  };
}

function detectManifest(files) {
  const names = new Set(files.map((f) => f.name));
  const kinds = [...names].filter((n) => MANIFESTS.has(n));
  const hasMcp = files.some((f) => /\b(Server|McpServer|FastMCP|@modelcontextprotocol)\b/.test(f.text));
  return { looksLikeMcpServer: hasMcp, manifests: kinds.slice(0, 10) };
}

const WEIGHT = { critical: 6, high: 3, medium: 1.5, low: 0.5, info: 0 };

export function score(findings, filesScanned) {
  const penalty = findings.reduce((sum, f) => sum + (WEIGHT[f.severity] ?? 0), 0);
  const density = penalty / Math.max(3, filesScanned);
  const raw = 100 - 11 * Math.sqrt(density) - 2.2 * Math.sqrt(penalty);
  return Math.max(0, Math.min(100, Math.round(raw)));
}

export function grade(value) {
  if (value >= 90) return { letter: 'A', ansi: '\x1b[92m', note: 'reads clean' };
  if (value >= 75) return { letter: 'B', ansi: '\x1b[92m', note: 'normal risk' };
  if (value >= 60) return { letter: 'C', ansi: '\x1b[93m', note: 'read before trusting' };
  if (value >= 40) return { letter: 'D', ansi: '\x1b[91m', note: 'broad reach' };
  return { letter: 'F', ansi: '\x1b[41;97m', note: 'assume it can do anything' };
}

export function digest(root, findings) {
  const body = findings
    .map((f) => `${f.rule}:${f.file}:${f.line}`)
    .sort()
    .join('\n');
  return createHash('sha256').update(root).update(body).digest('hex');
}

export function counts(findings) {
  const tally = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) tally[f.severity] = (tally[f.severity] ?? 0) + 1;
  return tally;
}