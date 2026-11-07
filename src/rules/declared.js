import { makeFinding, lineOf, snippet } from '../util.js';

const EMPTY_CAPS = /capabilities\s*:\s*\{\s*(?:tools\s*:\s*\{\s*\}\s*,?\s*)?\}/;
const SERVES_TOOLS = /\btools\/list\b|\bsetRequestHandler\s*\(|\bregisterTool\s*\(|\binputSchema\b/;

export const capabilityMismatch = {
  id: 'capability-mismatch',
  group: 'capability',
  title: 'Advertises empty capabilities but serves tools',
  severity: 'medium',
  why:
    'The capabilities block is the contract the host negotiates with. Declaring \`tools: {}\` — or declaring ' +
    'nothing and then answering \`tools/list\` — means the client never agreed to tools, so list-change ' +
    'notifications go nowhere and some hosts keep a stale catalog.',
  fix: 'Declare what you serve: \`capabilities: { tools: { listChanged: true } }\`, and resources or prompts if used.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|mts|cts|py)$/.test(file.ext)) return [];
    const m = EMPTY_CAPS.exec(file.text);
    if (!m) return [];
    if (!SERVES_TOOLS.test(file.text)) return [];
    return [
      makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 45), {
        detail: 'declared empty, tools served anyway',
      }),
    ];
  },
};

export const rules = [capabilityMismatch];

