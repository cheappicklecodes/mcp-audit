import { makeFinding, lineOf, snippet, isLocalHost } from '../util.js';

const SECRET_PATHS = [
  { re: /\.ssh\// }, { re: /\.aws\// }, { re: /\.npmrc/ }, { re: /\.netrc/ },
  { re: /\.git-credentials/ }, { re: /\.config\/gh/ }, { re: /\.kube\/config/ },
  { re: /id_rsa/ }, { re: /id_ed25519/ }, { re: /\.pypirc/ }, { re: /\.gnupg/ },
  { re: /Library\/Keychains/ }, { re: /\.azure\// },
  { re: /["'`]\.env(?:\.\w+)?["'`]|path\.join\([^)]*\.env\b|homedir\(\)[^;]{0,40}\.env\b/, skip: /process\.env/ },
];

const SENSITIVE_CONFIG = [/\.(npmrc|netrc|pypirc|env)$/, /credentials/i, /secrets?\.(json|ya?ml|toml)$/i];

export const broadFilesystem = {
  id: 'broad-fs-access',
  group: 'reach',
  title: 'Server can reach the whole filesystem or home directory',
  severity: 'high',
  why:
    'A server scoped to a project can be compromised for the cost of the project. One scoped to `~` or `/` can ' +
    'read every repo, key and note on the machine — including files it never advertised.',
  fix: 'Scope roots to the directories the server actually serves.',
  check(file) {
    const out = [];
    const re = /["'\]]?\b(root|root[s]?|basePath|base_path|cwd|directory|workspace|path)\b["'\]]?\s*[:=]\s*\[?\s*["']([^"']{1,64})["']/gi;
    let m;
    while ((m = re.exec(file.text))) {
      const value = m[2];
      const isBroad = /^(\/|~\/?|(?:[A-Za-z]:[\\/])?)$/.test(value.trim()) ||
        /^(\/home\/[^/]+\/?|\/Users\/[^/]+\/?|[A-Z]:[\\/]Users[\\/][^\\/]+[\\/]?)$/.test(value.trim());
      if (!isBroad) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), `${m[1]}: ${value}`, {
          detail: 'broad root',
        }),
      );
    }
    return out;
  },
};

export const secretAccess = {
  id: 'reads-credentials',
  group: 'reach',
  title: 'Reads credential or key material',
  severity: 'high',
  why:
    'Reading your private keys and cloud config means a bug in this server is a bug in everything you are logged ' +
    'into. Most servers need one secret and touch ten.',
  fix: 'Pass the single secret the server needs instead of letting it crawl config directories.',
  check(file) {
    const out = [];
    for (const { re, skip } of SECRET_PATHS) {
      const probe = new RegExp(re.source, 'g');
      let m;
      while ((m = probe.exec(file.text))) {
        const around = file.text.slice(Math.max(0, m.index - 8), m.index + m[0].length + 2);
        if (skip && skip.test(around)) continue;
        out.push(
          makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 50), {
            detail: m[0],
          }),
        );
        break;
      }
      if (out.length >= 6) break;
    }
    return out;
  },
};

export const sensitiveFileFallback = {
  id: 'sensitive-fallback',
  group: 'reach',
  title: 'Falls back to a sensitive config file',
  severity: 'low',
  why: 'Configs like `.npmrc` hold publish tokens; silently reading them widens the blast radius beyond MCP.',
  fix: 'Document which config file is read and consider a dedicated credential.',
  check(file) {
    if (!SENSITIVE_CONFIG.some((re) => re.test(file.name))) return [];
    return [
      makeFinding(this, file.relative, 1, file.name, { detail: 'credential-bearing file shipped' }),
    ];
  },
};

const NET_CALL = /\b(fetch|axios|got|node-fetch|requests\.|httpx\.|urllib\.|http\.request|curl\s)/;

export const outboundNetwork = {
  id: 'outbound-network',
  group: 'reach',
  title: 'Makes outbound network calls',
  severity: 'medium',
  why:
    'An MCP server with data access and an outbound socket can ship that data anywhere. Worth knowing which ' +
    'endpoints, and whether a local-first tool is quietly phoning home.',
  fix: 'Confirm the endpoint. For privacy-sensitive servers prefer opt-out telemetry or none.',
  check(file) {
    if (!/\.(js|mjs|cjs|ts|py|rb|go|rs|sh)$/.test(file.ext)) return [];
    const out = [];
    for (const m of file.text.matchAll(new RegExp(NET_CALL.source, 'g'))) {
      const window = file.text.slice(m.index, m.index + 400);
      const url = /https?:\/\/([^/\s"'`)]+)/.exec(window);
      if (!url) continue;
      const host = url[1];
      if (isLocalHost(host)) continue;
      out.push(
        makeFinding(this, file.relative, lineOf(file.text, m.index), host, { detail: host }),
      );
      if (out.length >= 5) break;
    }
    return out;
  },
};

export const telemetry = {
  id: 'telemetry',
  group: 'reach',
  title: 'Analytics or telemetry SDK present',
  severity: 'low',
  why: 'Telemetry decides what leaves the machine before you have asked the tool anything.',
  fix: 'Look for a documented off switch and confirm the endpoint.',
  check(file) {
    const re = /\b(posthog|sentry|segment|mixpanel|amplitude|datadog|otel|opentelemetry|statsd|umami|plausible)\b/i;
    const m = re.exec(file.text);
    if (!m) return [];
    return [makeFinding(this, file.relative, lineOf(file.text, m.index), m[0], { detail: m[0] })];
  },
};

export const rules = [broadFilesystem, secretAccess, sensitiveFileFallback, outboundNetwork, telemetry];