#!/usr/bin/env node
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scan, ALL_RULES, grade, counts, RULE_MAP } from '../src/engine.js';
import { renderText, renderJson, renderSarif, renderMarkdown } from '../src/report.js';
import { SEVERITY, severityRank } from '../src/util.js';
import { LOCK_NAME, emptyLock, readLock, writeLock, diffLock, serverKey, fingerprint } from '../src/lock.js';
import { discover } from '../src/discover.js';
import { checkLock } from '../src/check.js';
import { loadConfig, mergeConfig } from '../src/config.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8'));
const COMMANDS = new Set(['rules']);

const USAGE = `
mcp-audit ${pkg.version} — read an MCP server before you trust it

  mcp-audit <dir> [dir...]          audit directories
  mcp-audit . --explain             show why it matters and how to fix
  mcp-audit . --format sarif        machine output (text|json|sarif|md)
  mcp-audit . --fail-on high        exit 1 for CI
  mcp-audit . --lock                write agents.lock
  mcp-audit . --check               fail if the server changed since the lock
  mcp-audit rules                   list every rule
  mcp-audit --rules-from ./r.js     load custom rules

  --exclude <glob>     skip paths (repeatable)
  --include <glob>     only these paths
  --disable <id>       mute a rule (repeatable)
  --only <id>          run one rule only (repeatable)
  --min-severity <s>   drop findings below this level
  --quiet              no report, exit code only
  --no-color
  --verbose            report rule crashes
  --help  --version

Exit: 0 clean · 1 failing findings · 2 usage error
`.trim();

const FORMATS = new Set(['text', 'json', 'sarif', 'md']);

function usageError(message) {
  const err = new Error(message);
  err.usage = true;
  return err;
}

function parseArgs(argv) {
  const opts = {
    paths: [], exclude: [], include: [], disable: [], only: [],
    format: 'text', failOn: null, minSeverity: null, lock: false, check: false,
    explain: false, quiet: false, verbose: false,
    color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
    rulesFrom: null, help: false, version: false, command: null,
  };
  const takesValue = new Set(['--exclude', '--include', '--disable', '--only', '--format', '--fail-on', '--min-severity', '--rules-from']);

  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];
    let inline = null;
    if (arg.startsWith('--') && arg.includes('=')) {
      inline = arg.slice(arg.indexOf('=') + 1);
      arg = arg.slice(0, arg.indexOf('='));
    }
    const value = () => {
      if (inline !== null) return inline;
      const next = argv[i + 1];
      if (next === undefined || (next.startsWith('--') && !takesValue.has(arg))) throw usageError(`${arg} needs a value`);
      i += 1;
      return next;
    };
    const severity = () => {
      const s = value();
      if (!Object.hasOwn(SEVERITY, s)) throw usageError(`unknown severity: ${s}`);
      return s;
    };

    switch (arg) {
      case '--help': case '-h': opts.help = true; break;
      case '--version': case '-v': opts.version = true; break;
      case '--exclude': opts.exclude.push(value()); break;
      case '--include': opts.include.push(value()); break;
      case '--disable': opts.disable.push(value()); break;
      case '--only': opts.only.push(value()); break;
      case '--rules-from': opts.rulesFrom = value(); break;
      case '--min-severity': opts.minSeverity = severity(); break;
      case '--fail-on': opts.failOn = severity(); break;
      case '--format': {
        const f = value();
        if (!FORMATS.has(f)) throw usageError(`unknown format: ${f}`);
        opts.format = f;
        break;
      }
      case '--lock': opts.lock = true; break;
      case '--check': opts.check = true; break;
      case '--explain': opts.explain = true; break;
      case '--quiet': opts.quiet = true; break;
      case '--verbose': opts.verbose = true; break;
      case '--no-color': opts.color = false; break;
      default:
        if (arg.startsWith('-')) throw usageError(`unknown flag: ${arg}`);
        if (COMMANDS.has(arg) && opts.paths.length === 0 && !opts.command) opts.command = arg;
        else opts.paths.push(arg);
    }
  }
  return opts;
}

async function loadCustomRules(spec) {
  const url = new URL(`file://${path.resolve(spec).split(path.sep).join('/')}`);
  const mod = await import(url.href);
  const list = mod.rules ?? mod.default;
  if (!Array.isArray(list)) throw usageError('custom rules file must export an array named `rules`');
  for (const rule of list) {
    if (!rule.id || typeof rule.check !== 'function') throw usageError('every custom rule needs an id and a check()');
    if (RULE_MAP.has(rule.id)) throw usageError(`duplicate rule id: ${rule.id}`);
    rule.severity = Object.hasOwn(SEVERITY, rule.severity) ? rule.severity : 'medium';
    rule.title ??= rule.id;
    rule.why ??= '';
    rule.fix ??= '';
    ALL_RULES.push(rule);
    RULE_MAP.set(rule.id, rule);
  }
}

const log = (...args) => process.stderr.write(`${args.join(' ')}\n`);

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    log(`error: ${err.message}\n\n${USAGE}`);
    process.exit(2);
  }

  if (opts.help) return void process.stdout.write(`${USAGE}\n`);
  if (opts.version) return void process.stdout.write(`${pkg.version}\n`);
  if (opts.command === 'rules') return void listRules();

  for (const id of [...opts.only, ...opts.disable]) {
    if (!RULE_MAP.has(id)) {
      log(`error: unknown rule: ${id} (see \`mcp-audit rules\`)`);
      process.exit(2);
    }
  }

  if (opts.rulesFrom) {
    try {
      await loadCustomRules(opts.rulesFrom);
    } catch (err) {
      log(`error: could not load custom rules: ${err.message}`);
      process.exit(2);
    }
  }

  const targets = opts.paths.length ? opts.paths : ['.'];
  let exit = 0;

  for (const target of targets) {
    const root = path.resolve(target);
    let stat;
    try {
      stat = fs.statSync(root);
    } catch {
      log(`error: no such path: ${target}`);
      process.exit(2);
    }
    if (!stat.isDirectory()) {
      log(`error: not a directory: ${target}`);
      process.exit(2);
    }

    let effective = opts;
    try {
      effective = mergeConfig(opts, loadConfig(root));
    } catch (err) {
      log(`error: ${err.message}`);
      process.exit(2);
    }

    if (effective.check) {
      exit = Math.max(exit, checkLock(root, effective));
      continue;
    }

    const result = scan(root, effective);
    const context = { version: pkg.version, root };

    if (!opts.quiet) {
      if (opts.format === 'json') process.stdout.write(`${renderJson(result, context)}\n`);
      else if (opts.format === 'sarif') process.stdout.write(`${renderSarif(result, context)}\n`);
      else if (opts.format === 'md') process.stdout.write(`${renderMarkdown(result, context)}\n`);
      else process.stdout.write(renderText(result, { ...context, color: opts.color, explain: opts.explain }));
    }

    if (effective.lock && !effective.check) writeLockfile(root, result, effective);

    if (effective.failOn && result.findings.some((f) => severityRank(f.severity) >= severityRank(effective.failOn))) {
      exit = 1;
      if (!opts.quiet) log(`failing: findings at or above ${effective.failOn}`);
    }
  }

  process.exit(exit);
}

function writeLockfile(root, result, opts) {
  const lockPath = path.join(root, LOCK_NAME);
  const lock = readLock(lockPath) ?? emptyLock();
  const key = serverKey(root);
  const before = lock.servers[key];
  const { files } = discover(root, { exclude: opts.exclude, include: opts.include });
  lock.servers[key] = {
    fingerprint: fingerprint(root, files),
    score: result.score,
    grade: grade(result.score).letter,
    counts: counts(result.findings),
    auditedAt: new Date().toISOString().slice(0, 10),
    ruleset: pkg.version,
  };
  writeLock(lockPath, lock);
  log(before && before.fingerprint !== lock.servers[key].fingerprint ? `updated ${LOCK_NAME} (${key})` : `wrote ${LOCK_NAME} (${key})`);
}

function listRules() {
  const width = Math.max(...ALL_RULES.map((r) => r.id.length));
  process.stdout.write(`\nmcp-audit ${pkg.version} — ${ALL_RULES.length} rules\n\n`);
  for (const rule of ALL_RULES) {
    process.stdout.write(`  ${rule.id.padEnd(width)}  ${rule.severity.padEnd(9)}  ${rule.title}\n`);
  }
  process.stdout.write('\n');
}

main().catch((err) => {
  log(`error: ${err.stack ?? err.message}`);
  process.exit(2);
});