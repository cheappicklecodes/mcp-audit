const OPEN = '(';
const IDENT = /[A-Za-z_$][\w$]*/;

export function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:\\])\/\/[^\n]*/g, (m, lead) => lead + ' '.repeat(m.length - lead.length));
}

export function enclosingBlock(text, index) {
  let depth = 0;
  let start = 0;
  for (let i = index; i >= 0; i -= 1) {
    const c = text[i];
    if (c === '}') depth += 1;
    else if (c === '{') {
      if (depth === 0) { start = i; break; }
      depth -= 1;
    }
  }
  depth = 0;
  let end = text.length;
  for (let i = index; i < text.length; i += 1) {
    const c = text[i];
    if (c === '{') depth += 1;
    else if (c === '}') {
      if (depth === 0) { end = i; break; }
      depth -= 1;
    }
  }
  return [start, end];
}

export function assignedTo(text, index) {
  let i = index - 1;
  let depth = 0;
  while (i >= 0) {
    const c = text[i];
    if (c === ')' || c === ']') depth += 1;
    else if (c === '(' || c === '[') {
      if (depth === 0) { i -= 1; continue; }
      depth -= 1;
    } else if (c === ';' || c === '{' || c === '}') break;
    else if (depth === 0 && c === '=' && text[i - 1] !== '=' && text[i + 1] !== '=') {
      const before = text.slice(Math.max(0, i - 80), i).replace(/[=+\-*/%&|?:,]\s*$/, '');
      const id = IDENT.exec(before.split(/[^\w$]/).filter(Boolean).pop() ?? '');
      return id ? id[0] : null;
    }
    i -= 1;
  }
  return null;
}

export function lastIdent(expr) {
  const all = [...expr.matchAll(new RegExp(IDENT.source, 'g'))];
  return all.length ? all[all.length - 1][0] : null;
}

export function matchesBalanced(text, openIndex, limit = 400) {
  let depth = 0;
  const stop = Math.min(text.length, openIndex + limit);
  for (let i = openIndex; i < stop; i += 1) {
    if (text[i] === OPEN) depth += 1;
    else if (text[i] === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex + 1, i);
    }
  }
  return text.slice(openIndex + 1, stop);
}
