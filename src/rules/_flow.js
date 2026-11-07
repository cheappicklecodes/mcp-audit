import { enclosingBlock, matchesBalanced } from './_scope.js';

const CALLER = /\b(?:args|arguments|params|req|request|input|body|ctx|context)\b\s*(?:\.|\[)/;
const IDENT = /[A-Za-z_$][\w$]*/g;
const KEYWORDS = new Set(['if', 'else', 'return', 'throw', 'new', 'typeof', 'const', 'let', 'var', 'true', 'false', 'null', 'undefined', 'function', 'await', 'async']);
const ALLOWLIST_SHAPE = /\.(?:test|includes|has|indexOf|is_relative_to|startsWith|startswith)\s*\(|\b[A-Z][A-Z0-9_]{2,}\b/;
const REJECTS = /\b(?:throw|raise|continue|return)\b/;
const RANK = { none: 0, unrelated: 1, partial: 2, strong: 3 };

export function isCaller(expr) {
  return CALLER.test(String(expr ?? ''));
}

export function symbolOf(expr) {
  const all = [...String(expr ?? '').split(',')[0].matchAll(IDENT)];
  return all.length ? all[all.length - 1][0] : null;
}

export function tracesToCaller(text, symbol, index) {
  if (!symbol) return false;
  const [start] = enclosingBlock(text, index);
  const before = text.slice(start, index);
  const decl = new RegExp(
    '\\b(?:const|let|var)\\s+(?:\\{[^}]*\\b' + symbol + '\\b[^}]*\\}|' + symbol + ')\\s*=\\s*([^;\\n]{1,160})',
    'g',
  );
  for (const m of before.matchAll(decl)) {
    if (isCaller(m[1])) return true;
    const hop = symbolOf(m[1]);
    if (hop && hop !== symbol && tracesToCaller(text.slice(0, start + m.index + 1), hop, m.index)) return true;
  }
  return false;
}

export function paramNames(text, index) {
  const before = text.slice(Math.max(0, index - 3000), index);
  let signature = null;
  for (const m of before.matchAll(/(?:def\s+[\w$]+\s*|function\s*[\w$]*\s*|(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?)\(([^()]{0,200})\)/g)) {
    signature = m[1];
  }
  for (const m of before.matchAll(/\(([^()]{0,200})\)\s*=>/g)) signature = m[1];
  const names = new Set();
  if (signature) for (const id of signature.matchAll(IDENT)) if (!KEYWORDS.has(id[0])) names.add(id[0]);
  return names;
}

export function isCallerish(text, expr, index) {
  const raw = String(expr ?? '').trim();
  if (!raw) return false;
  if (isCaller(raw)) return true;
  if (!/^[A-Za-z_$][\w$]*$/.test(raw)) return false;
  if (paramNames(text, index).has(raw)) return true;
  return tracesToCaller(text, raw, index);
}

function declaredNames(scope) {
  const names = new Set();
  for (const m of scope.matchAll(/\b(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of scope.matchAll(/\(([^)]*)\)\s*(?:=>|\{)/g)) {
    for (const id of m[1].matchAll(IDENT)) names.add(id[0]);
  }
  return names;
}

function boundNames(scope) {
  const names = new Set();
  for (const m of scope.matchAll(/\b(?:const|let|var)\s+(?:\{([^}]*)\}|([A-Za-z_$][\w$]*))\s*=\s*([^;\n]{1,160})/g)) {
    const rhs = m[3] ?? '';
    if (!isCaller(rhs) && !/\b(?:command|cmd|program|prog|exec)\b/.test(rhs)) continue;
    if (m[1]) for (const id of m[1].matchAll(IDENT)) names.add(id[0]);
    else if (m[2]) names.add(m[2]);
  }
  return names;
}

function valueNames(cond) {
  const found = [];
  for (const m of cond.matchAll(IDENT)) {
    const name = m[0];
    const after = cond.slice(m.index + name.length).trimStart();
    if (after.startsWith('.') || after.startsWith('(')) continue;
    if (KEYWORDS.has(name)) continue;
    if (!found.includes(name)) found.push(name);
  }
  return found;
}

function conditionAt(chunk, from) {
  let i = from;
  while (i < chunk.length && /[ \t!]/.test(chunk[i])) i += 1;
  if (chunk[i] === '(') {
    const text = matchesBalanced(chunk, i, 300);
    return { text, end: i + text.length + 2 };
  }
  let depth = 0;
  for (let j = i; j < chunk.length && j < i + 300; j += 1) {
    const c = chunk[j];
    if (c === '(' || c === '[') depth += 1;
    else if (c === ')' || c === ']') depth -= 1;
    else if (c === ':' && depth === 0) return { text: chunk.slice(i, j), end: j + 1 };
    else if (c === '\n' && depth === 0) return null;
  }
  return null;
}

export function guardFor(text, index, symbol, opts = {}) {
  const [start, end] = enclosingBlock(text, index);
  const regions = [text.slice(start, index)];
  if (opts.after) regions.push(text.slice(index, end));

  const names = [symbol, ...boundNames(text.slice(start, index))].filter(Boolean);
  const declared = declaredNames(text.slice(start, end));
  let best = { state: 'none', other: null };

  for (const region of regions) {
    for (const m of region.matchAll(/\b(?:if|elif)\b/g)) {
      const cond = conditionAt(region, m.index + m[0].length);
      if (cond === null || !ALLOWLIST_SHAPE.test(cond.text)) continue;

      const tail = region.slice(cond.end, cond.end + 320);
      const stop = tail.search(/\n\s*(?:if|elif|const|let|var|return|[A-Za-z_$][\w$]*\s*[.(=])/);
      const rejects = REJECTS.test(stop > -1 ? tail.slice(0, stop) : tail);

      const mentions = names.some((n) => new RegExp(String.raw`\b` + n + String.raw`\b`).test(cond.text));
      const literal = /["'`][^"'`]{1,40}["'`]/.test(cond.text);
      const strangers = valueNames(cond.text.replace(/["'][^"']*["']/g, ' '))
        .filter((n) => !declared.has(n) && !names.includes(n));

      let verdict;
      if (mentions) verdict = rejects ? 'strong' : 'partial';
      else if (literal) verdict = 'unrelated';
      else if (strangers.length === 1) verdict = rejects ? 'strong' : 'partial';
      else verdict = 'unrelated';

      const other = mentions ? null : (strangers[0] ?? null);
      if (RANK[verdict] > RANK[best.state]) best = { state: verdict, other };
    }

    for (const m of region.matchAll(/(?:^|\n)\s*(?:assert|invariant|expect)\s*\(/g)) {
      const cond = conditionAt(region, m.index + m[0].length - 1);
      if (cond === null) continue;
      if (!names.some((n) => new RegExp(String.raw`\b` + n + String.raw`\b`).test(cond.text))) continue;
      if (RANK.partial > RANK[best.state]) best = { state: 'partial', other: null };
    }
  }
  return best;
}