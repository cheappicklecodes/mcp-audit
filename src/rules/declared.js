import { makeFinding, lineOf, snippet } from '../util.js';
import { stripComments } from './_scope.js';

const EMPTY_CAPS = /capabilities\s*:\s*\{\s*(?:tools\s*:\s*\{\s*\}\s*,?\s*)?\}/;
const DECLARED_TOOLS = /capabilities\s*:\s*\{[^}]*tools\s*:\s*\{\s*[\w$]+\s*:/;
const SERVES = /\btools\/list\b|\bsetRequestHandler\s*\(|\bregisterTool\s*\(|\blistTools\s*\(/;
const HANDLES_CALL = /["'`]tools\/call["'`]|\bregisterTool\s*\(|\bserver\.tool\s*\(/;
const DYNAMIC_CAPS = /capabilities\s*:\s*(?!\{)[\w$]+|\.\.\.[\s\S]{0,200}?capabilities/;
const LOOKS_SERVER = /\b(?:McpServer|Server\b|registerTool\s*\(|setRequestHandler\s*\(|capabilities\s*:)/;

export const capabilityMismatch = {
  id: 'capability-mismatch',
  group: 'capability',
  title: 'Capability declaration does not match what the server serves',
  severity: 'medium',
  why:
    'The capabilities block is the contract the host negotiates with. Declaring \`tools: {}\` and then answering ' +
    '\`tools/list\` means the client never agreed to tools, so list-change notifications go nowhere and some hosts ' +
    'keep a stale catalog. The reverse — advertising tools with no \`tools/call\` handler — gives the model a ' +
    'catalog it cannot invoke.',
  fix: 'Declare what the server really serves: \`capabilities: { tools: { listChanged: true } }\`, and implement every tool listed.',
  check(file) {
    if (!/\.[mc]?[jt]s$/.test(file.ext)) return [];
    const text = stripComments(file.text);
    if (!LOOKS_SERVER.test(text)) return [];

    const empty = EMPTY_CAPS.exec(text);
    const serves = SERVES.test(text);
    if (empty && serves) {
      return [
        makeFinding(this, file.relative, lineOf(text, empty.index), snippet(text, empty.index, 45), {
          detail: 'declared empty, tools served anyway',
          confidence: 'confirmed',
        }),
      ];
    }

    if (DECLARED_TOOLS.test(text) && serves && !HANDLES_CALL.test(text)) {
      return [
        makeFinding(this, file.relative, lineOf(text, 0), 'tools advertised, no tools/call handler seen', {
          severity: 'low',
          detail: 'advertised but possibly not implemented',
          confidence: 'inconclusive',
        }),
      ];
    }

    if (DYNAMIC_CAPS.test(text) && !DECLARED_TOOLS.test(text) && !empty) {
      return [
        makeFinding(this, file.relative, lineOf(text, 0), 'capabilities assembled at runtime', {
          severity: 'info',
          detail: 'inconclusive: registration is dynamic, read it by hand',
          confidence: 'inconclusive',
        }),
      ];
    }
    return [];
  },
};

export const rules = [capabilityMismatch];
