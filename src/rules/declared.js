import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments } from './_scope.js';

const EMPTY_CAPS = /capabilities\s*:\s*\{\s*(?:tools\s*:\s*\{\s*\}\s*,?\s*)?\}/;
const DECLARED_TOOLS = /capabilities\s*:\s*\{[^}]*tools\s*:\s*\{\s*[\w$]+\s*:/;
const SERVES = /\btools\/list\b|\bsetRequestHandler\s*\(|\bregisterTool\s*\(|\blistTools\s*\(/;
const IMPLEMENTS = /["']tools\/call["']|\bcase\s+["']|\bname\s*===\s*["']/;
const DYNAMIC = /\.\.\.|\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+of\b/;
const LOOKS_SERVER = /\b(?:McpServer|Server\b|registerTool\s*\(|setRequestHandler\s*\(|capabilities\s*:)/;

export const capabilityMismatch = {
  id: 'capability-mismatch',
  group: 'capability',
  title: 'Capability declaration does not match what the server serves',
  severity: 'medium',
  why:
    'The capabilities block is the contract the host negotiates with. Declaring `tools: {}` and then answering ' +
    '`tools/list` means the client never agreed to tools, so list-change notifications go nowhere and some hosts ' +
    'keep a stale catalog.',
  fix: 'Declare what the server really serves: `capabilities: { tools: { listChanged: true } }`.',
  check(file) {
    if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    if (!LOOKS_SERVER.test(text)) return [];
    if (DECLARED_TOOLS.test(text) && SERVES.test(text) && !IMPLEMENTS.test(text)) {
      return [
        makeFinding(this, file.relative, lineOf(text, 0), 'tools advertised, no tools/call handler', {
          severity: 'low',
          detail: 'advertised but possibly not implemented',
        }),
      ];
    }
    const dynamicCaps = /capabilities\s*:\s*(?!\{)[\w$]+|\.\.\.[\s\S]{0,200}?capabilities/.test(text);
    if (dynamicCaps && !DECLARED_TOOLS.test(text) && !EMPTY_CAPS.test(text)) {
      return [
        makeFinding(this, file.relative, lineOf(text, 0), 'capabilities assembled at runtime', {
          severity: 'info',
          detail: 'inconclusive: registration is dynamic, read it by hand',
        }),
      ];
    }
    const empty = EMPTY_CAPS.exec(text);
    if (empty && SERVES.test(text)) {
      return [
        makeFinding(this, file.relative, lineOf(text, empty.index), snippet(text, empty.index, 45), {
          detail: 'declared empty, tools served anyway',
        }),
      ];
    }
    return [];
  },
};

export const rules = [capabilityMismatch];
