import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments, enclosingBlock, assignedTo, matchesBalanced } from './_scope.js';
import { isCallerish, guardFor } from './_flow.js';

const JS_JOIN = /\bpath\.(?:join|resolve)\s*\(/g;
const PY_JOIN = /(?:\bPath\s*\([^)\n]*\)|\b(?:ROOT|ROOT_DIR|BASE|BASE_DIR|base|baseDir|root|home|dest|destDir|target)\b)\s*\/\s*[\w$[(]/g;

export const pathTraversal = {
  id: 'path-traversal',
  group: 'reach',
  title: 'Joins caller-supplied paths without a containment check',
  severity: 'high',
  why:
    '`path.join(ROOT, args.path)` looks confined but is not: `../../etc/passwd` walks straight out of ROOT, ' +
    'and an absolute segment discards the prefix entirely. The model writes that string, and so does anything ' +
    'else that can call the tool.',
  fix:
    'Resolve, then compare with a separator: `const p = path.resolve(ROOT, input); ' +
    'if (!p.startsWith(ROOT + path.sep)) throw`. On Windows use `path.relative` and reject a leading `..`.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|mts|cts|py|rb|go|rs)$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    const py = /\.py$/.test(file.ext);

    const out = [];
    for (const m of text.matchAll(new RegExp((py ? PY_JOIN : JS_JOIN).source, 'g'))) {
      const anchor = py ? text.indexOf('/', m.index) : text.indexOf('(', m.index);
      if (anchor < 0) continue;
      const parts = py ? null : matchesBalanced(text, anchor).split(',');
      const userPart = py
        ? (/\/\s*([\w$.]+)/.exec(text.slice(anchor, anchor + 120)) ?? [])[1]
        : (parts[1] ?? '').trim();
      if (!userPart || !isCallerish(text, userPart, m.index)) continue;
      const root = py
        ? (/\/\s*([\w$.]+)/.exec(text.slice(anchor, anchor + 120)) ?? [])[1] && rootBefore(text, anchor)
        : (parts[0] ?? '').trim();

      const target = assignedTo(text, m.index);
      const guard = target ? guardFor(text, m.index, target, { after: true }) : { state: 'none' };
      const state = settle(text, m.index, target, guard, root);
      if (state === 'strong') continue;

      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          severity: state === 'none' ? 'high' : 'medium',
          detail: describe(state, guard, target, Boolean(target && clampOn(text, m.index, target))),
        }),
      );
      if (out.length >= 4) break;
    }
    return out;
  },
};

function rootBefore(text, anchor) {
  const before = text.slice(Math.max(0, anchor - 80), anchor).replace(/\([^()]*\)/g, ' ');
  const hits = [...before.matchAll(/[\w$.]+/g)];
  return hits.length ? hits[hits.length - 1][0] : '';
}

function settle(text, index, target, guard, root) {
  if (guard.state !== 'strong') return guard.state;
  if (!target || !root) return 'partial';
  if (isRelativeTo(text, index, target) || relativeForm(text, index, target)) return 'strong';
  return separatorAware(text, index, target, root) ? 'strong' : 'partial';
}

function clampOn(text, index, target) {
  const [start, end] = enclosingBlock(text, index);
  const scope = text.slice(start, end);
  const at = index - start;
  const pattern = new RegExp(String.raw`\b` + target + String.raw`\b[^\n]{0,40}?(startsWith|startswith|is_relative_to)\s*\(([^)\n]{0,80})`, 'g');
  const hits = [];
  for (const m of scope.matchAll(pattern)) hits.push({ call: m[1], arg: m[2], at: m.index });
  const before = hits.filter((h) => h.at < at).pop();
  const after = hits.find((h) => h.at > at);
  return before ?? after ?? null;
}

function relativeForm(text, index, target) {
  const [start, end] = enclosingBlock(text, index);
  const before = text.slice(start, end);
  const pattern = String.raw`path\.relative\s*\([^)\n]{0,120}\b` + target + String.raw`\b[^)\n]{0,40}\)\s*\.\s*startsWith\s*\(\s*.{0,3}\.\.`;
  return new RegExp(pattern).test(before);
}
function isRelativeTo(text, index, target) {
  return clampOn(text, index, target)?.call === 'is_relative_to';
}

function separatorAware(text, index, target, root) {
  const hit = clampOn(text, index, target);
  if (!hit) return false;
  const key = root.split('.').pop();
  if (!new RegExp(String.raw`\b` + key + String.raw`\b`).test(hit.arg)) return false;
  if (/path\.sep|\bsep\b/.test(hit.arg)) return true;
  const literal = /["'`]([^"'`]{1,80})["'`]/.exec(hit.arg);
  return Boolean(literal) && /[\\/]$/.test(literal[1]);
}

function describe(state, guard, target, clamped) {
  if (state === 'unrelated') return `an allowlist is checked (${guard.other ?? 'another value'}), not the joined path`;
  if (state === 'partial') {
    if (!clamped) return 'a clamp exists but not on this result';
    return `clamp on ${target} is not separator-aware: /srv/app-sibling passes a check against /srv/app`;
  }
  return 'root is joined to caller input, never clamped';
}

export const rules = [pathTraversal];