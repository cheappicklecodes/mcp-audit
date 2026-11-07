import { SEVERITY, severityRank } from './util.js';
import { counts, grade } from './engine.js';

const ESC = '\x1b[';
const R = `${ESC}0m`;
const LABEL_WIDTH = 9;

export function color(enabled) {
  const wrap = (code) => (enabled ? code : '');
  return {
    dim: (s) => `${wrap(`${ESC}2m`)}${s}${wrap(R)}`,
    bold: (s) => `${wrap(`${ESC}1m`)}${s}${wrap(R)}`,
    green: (s) => `${wrap(`${ESC}92m`)}${s}${wrap(R)}`,
    yellow: (s) => `${wrap(`${ESC}93m`)}${s}${wrap(R)}`,
    under: (s) => `${wrap(`${ESC}4m`)}${s}${wrap(R)}`,
    sev: (sev, s) => `${wrap(SEVERITY[sev]?.ansi ?? '')}${s}${wrap(R)}`,
    grade: (g) => `${wrap(g.ansi)}${g.letter}${wrap(R)}`,
  };
}

export function renderText(result, opts = {}) {
  const c = color(opts.color ?? false);
  const out = [];
  const tallies = counts(result.findings);

  out.push('');
  out.push(`${c.bold('mcp-audit')} ${c.dim(`v${opts.version ?? '0.1.0'}`)}  ${c.dim(opts.root ?? '')}`);
  out.push(c.dim('─'.repeat(66)));

  if (!result.findings.length) {
    out.push('');
    out.push(`  ${c.green('✓ no findings')} ${c.dim(`(${result.filesScanned} files, ${result.rulesRun} rules)`)}`);
    out.push('');
  } else {
    out.push('');
    out.push(
      `  ${c.sev('critical', ` ${tallies.critical} critical `)} ${c.sev('high', ` ${tallies.high} high `)} ` +
        `${c.sev('medium', ` ${tallies.medium} medium `)} ${c.sev('low', ` ${tallies.low} low `)} ` +
        c.dim(`· ${result.filesScanned} files · ${result.rulesRun} rules`),
    );
    out.push('');

    for (const [file, group] of groupByFile(result.findings)) {
      const worst = group[0].severity;
      out.push(`  ${c.under(file)} ${c.sev(worst, SEVERITY[worst].label)}`);
      for (const f of group) {
        const tag = (SEVERITY[f.severity]?.label ?? f.severity.toUpperCase()).padEnd(LABEL_WIDTH);
        out.push(`    ${c.sev(f.severity, tag)} ${c.dim(`L${f.line}`)} ${f.title}`);
        out.push(`      ${c.dim(f.evidence)}`);
        if (opts.explain) {
          out.push(`      ${c.dim('why:')} ${wrapText(f.why, 60, 6)}`);
          out.push(`      ${c.dim('fix:')} ${wrapText(f.fix, 60, 6)}`);
        }
      }
      out.push('');
    }
    out.push('');
  }

  const g = grade(result.score);
  out.push(c.dim('─'.repeat(66)));
  out.push(`  ${c.bold('Grade')} ${c.grade(g)}${c.dim(` (${result.score}/100) — ${g.note}`)}`);

  if (opts.advice !== false) {
    out.push('');
    out.push(`  ${c.dim('This grades shape, not intent. It cannot tell you the author is honest.')}`);
    out.push(`  ${c.dim('Read the criticals before you hand it a token.')}`);
  }
  if (result.truncated) out.push(`\n  ${c.yellow('! file limit hit, results partial')}`);
  out.push('');
  return out.join('\n');
}

export function wrapText(text, width, indent) {
  const lines = [];
  let line = '';
  for (const word of String(text ?? '').split(/\s+/)) {
    if ((line + word).length > width) {
      lines.push(line.trimEnd());
      line = '';
    }
    line += `${word} `;
  }
  if (line.trim()) lines.push(line.trimEnd());
  return lines.join(`\n${' '.repeat(indent)}`);
}

export function renderJson(result, opts = {}) {
  return JSON.stringify(
    {
      tool: 'mcp-audit',
      version: opts.version ?? '0.1.0',
      root: opts.root,
      score: result.score,
      grade: grade(result.score).letter,
      filesScanned: result.filesScanned,
      rulesRun: result.rulesRun,
      counts: counts(result.findings),
      truncated: result.truncated,
      findings: result.findings,
    },
    null,
    2,
  );
}

export function renderSarif(result, opts = {}) {
  const rules = new Map();
  for (const f of result.findings) {
    if (rules.has(f.rule)) continue;
    rules.set(f.rule, {
      id: f.rule,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.why },
      help: { text: f.fix },
      defaultConfiguration: { level: sarifLevel(f.severity) },
    });
  }
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'mcp-audit',
              version: opts.version ?? '0.1.0',
              informationUri: 'https://github.com/cheappicklecodes/mcp-audit',
              rules: [...rules.values()],
            },
          },
          results: result.findings.map((f) => ({
            ruleId: f.rule,
            level: sarifLevel(f.severity),
            message: { text: [f.title, f.evidence].filter(Boolean).join(' — ') },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: { startLine: Math.max(1, f.line) },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}

function sarifLevel(sev) {
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'medium') return 'warning';
  return 'note';
}

export function renderMarkdown(result) {
  const lines = ['# mcp-audit report', ''];
  lines.push(`Score: **${result.score}/100 (${grade(result.score).letter})** · ${result.filesScanned} files`, '');
  if (!result.findings.length) {
    lines.push('No findings.');
    return lines.join('\n');
  }
  lines.push('| Severity | File | Line | Finding |', '| --- | --- | --- | --- |');
  for (const f of [...result.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    lines.push(`| ${f.severity} | \`${f.file}\` | ${f.line} | ${f.title} |`);
  }
  return lines.join('\n');
}


function groupByFile(findings) {
  const order = [];
  const groups = new Map();
  for (const f of findings) {
    if (!groups.has(f.file)) {
      groups.set(f.file, []);
      order.push(f.file);
    }
    groups.get(f.file).push(f);
  }
  return order.map((file) => [file, groups.get(file)]);
}