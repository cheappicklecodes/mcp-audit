import { RULE_MAP } from './engine.js';

const ESC = '\x1b[';
const R = `${ESC}0m`;

export function explainAll(ids) {
  if (!ids.length) return '';
  const out = ['', `${ESC}2m${'─'.repeat(66)}${R}`, `${ESC}1mWhat these mean${R}`, ''];
  for (const id of ids) {
    const rule = RULE_MAP.get(id);
    if (!rule) continue;
    out.push(`  ${ESC}1m${rule.id}${R} ${ESC}2m[${rule.severity}]${R}`);
    out.push(`  ${wrap(rule.why, 62, 2)}`);
    out.push(`  ${ESC}92mfix${R} ${wrap(rule.fix, 62, 6)}`);
    out.push('');
  }
  out.push(`  ${ESC}2mEverything here is a heuristic on shape. A clean grade is not a guarantee.${R}`);
  out.push('');
  return out.join('\n');
}

function wrap(text, width, indent) {
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