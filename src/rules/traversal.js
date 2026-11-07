import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments, enclosingBlock, assignedTo, matchesBalanced } from './_scope.js';

const CALLER = /\b(?:args|arguments|params|req|request|input|body|ctx|context)\b\s*(?:\.|\[|\))/;
const JS_JOIN = /\bpath\.(?:join|resolve)\s*\(/g;
const PY_IDENT = /^\/\s*(?:[\w$.]+|\[)/;
const PY_JOIN = /(?:\bPath\s*\([^)\n]*\)|\b(?:ROOT|ROOT_DIR|BASE|BASE_DIR|base|baseDir|root|home|dest|destDir|target)\b)\s*\/\s*[\w$[(]/g;

const WEAK_CLAMP = /\.(?:startsWith|startswith)\s*\(/;
const STRONG_CLAMP = /\.\.\/|path\.relative\(|realpath|\.is_relative_to\(/;

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
    const hits = py ? PY_JOIN : JS_JOIN;

    const out = [];
    for (const m of text.matchAll(new RegExp(hits.source, 'g'))) {
      const open = text.indexOf('(', m.index);
      const callArgs = py ? '' : matchesBalanced(text, open);
      const after = text.slice(py ? text.indexOf('/', m.index) : open, (py ? text.indexOf('/', m.index) : open) + 120);
      if (py ? !PY_IDENT.test(after) : !CALLER.test(callArgs)) continue;

      const verdict = guardFor(text, m.index);
      if (verdict.strength === 'strong') continue;

      out.push(
        makeFinding(this, file.relative, lineOf(text, m.index), snippet(text, m.index, 55), {
          severity: verdict.strength === 'weak' ? 'medium' : 'high',
          detail: verdict.strength === 'weak' ? verdict.detail : 'root is joined to caller input, never clamped',
        }),
      );
      if (out.length >= 4) break;
    }
    return out;
  },
};

function guardFor(text, index) {
  const bound = assignedTo(text, index);
  const [start, end] = enclosingBlock(text, index);
  const scope = text.slice(start, Math.min(end, index + 2500));
  if (STRONG_CLAMP.test(scope)) return { strength: 'strong' };

  const weak = WEAK_CLAMP.exec(scope);
  if (!weak) return { strength: 'none' };

  const operand = /(?:startsWith|startswith)\s*\(\s*([^)\n]{1,60})/.exec(scope.slice(weak.index, weak.index + 120));
  const testVar = lastWord(scope, weak.index);
  if (!operand) return { strength: 'weak', detail: 'clamp present but uninspectable' };

  const needle = operand[1];
  const separatorAware = /path\.sep|\bsep\b|["'`]\//.test(needle) || /\\\\/.test(needle);
  const sameVariable = Boolean(bound) && (needle.includes(bound) || testVar === bound);
  if (separatorAware && sameVariable) return { strength: 'strong' };
  if (!sameVariable) {
    const whom = testVar ?? 'another value';
    return { strength: 'weak', detail: `clamp guards ${whom}, not the joined path` };
  }
  return { strength: 'weak', detail: 'startsWith without a separator: `/safe-evil` passes a check against `/safe`' };
}

function lastWord(text, index) {
  let i = index - 1;
  while (i >= 0 && /\s/.test(text[i])) i -= 1;
  const end = i + 1;
  while (i >= 0 && /[\w$.]/.test(text[i])) i -= 1;
  return text.slice(i + 1, end).replace(/^\./, '') || null;
}

export const rules = [pathTraversal];
