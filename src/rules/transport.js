import { makeFinding, lineOf, snippet } from '../util.js';

export const transport = {
  id: 'transport',
  group: 'transport',
  title: 'Uses stdio transport',
  severity: 'info',
  why: 'Local stdio servers inherit your user account. There is no sandbox between the server and your files.',
  fix: 'Prefer stdio for local work and HTTP with auth for remote.',
  check(file) {
    const m = /"transport"\s*:\s*"(stdio|sse|http|streamable-http)"/.exec(file.text) ??
      /\b(StdioServerTransport|SSEServerTransport|StreamableHTTPServerTransport)\b/.exec(file.text);
    if (!m) return [];
    return [makeFinding(this, file.relative, lineOf(file.text, m.index), m[0], { detail: m[1] ?? m[0] })];
  },
};

export const remoteNoAuth = {
  id: 'remote-no-auth',
  group: 'transport',
  title: 'HTTP server bound without obvious auth',
  severity: 'high',
  why:
    'An MCP server speaking HTTP with tools attached and no token check is an unauthenticated API into your ' +
    'filesystem or accounts for anything on the network.',
  fix: 'Require a bearer token; bind to localhost when the server is local-only.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|py|go|rs)$/.test(file.ext)) return [];
    const isHttp = /\b(StreamableHTTPServerTransport|SSEServerTransport|express\(|FastAPI\(|Flask\(|http\.createServer|createServer\()/.test(file.text);
    if (!isHttp) return [];
    const hasAuth = /\b(authorization|bearer|api[_-]?key|verify[_-]?token|jwt|bearerAuth)\b/i.test(file.text);
    if (hasAuth) return [];
    const m = /\b(StreamableHTTPServerTransport|SSEServerTransport|createServer\()/.exec(file.text);
    return [
      makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 60), {
        detail: 'no auth reference in file',
      }),
    ];
  },
};

export const publicBind = {
  id: 'public-bind',
  group: 'transport',
  title: 'Listens on all interfaces',
  severity: 'medium',
  why: '`0.0.0.0` exposes the port to the LAN and any container network, not just this machine.',
  fix: 'Bind `127.0.0.1` unless remote access is the point.',
  check(file) {
    const re = /(0\.0\.0\.0|listen\(\s*port|\bhost\s*[:=]\s*["']0\.0\.0\.0["'])/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40)));
      if (out.length >= 2) break;
    }
    return out;
  },
};

export const rules = [transport, remoteNoAuth, publicBind];