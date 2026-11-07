import { makeFinding, lineOf, snippet } from '../util.js';

const PHISH_HOSTS = [
  'pastebin.com', 'gist.github.com', 'raw.githubusercontent.com', 'transfer.sh',
  '0x0.st', 'file.io', 'ngrok.io', 'trycloudflare.com', 'webhook.site',
  'requestbin.net', 'pipedream.net', 'vercel.app', 'workers.dev',
];

export const phishyHosts = {
  id: 'transient-host',
  group: 'network',
  title: 'Talks to a transient or free-hosting endpoint',
  severity: 'medium',
  why:
    'Tunnels, pastes and run-as-a-service hosts change owners and content. A tool that pulls payloads from one ' +
    'is only as trustworthy as a URL nobody pinned.',
  fix: 'Prefer static delivery (tagged release, raw file at a commit SHA) over dynamic endpoints.',
  check(file) {
    const out = [];
    for (const host of PHISH_HOSTS) {
      const idx = file.text.indexOf(host);
      if (idx < 0) continue;
      out.push(makeFinding(this, file.relative, lineOf(file.text, idx), snippet(file.text, idx, 55), { detail: host }));
      if (out.length >= 4) break;
    }
    return out;
  },
};

export const postInstallDownload = {
  id: 'install-time-download',
  group: 'network',
  title: 'Install step downloads a binary at build time',
  severity: 'high',
  why:
    'A postinstall/prepare step that fetches a binary means the artifact you audit is not the artifact that runs, ' +
    'and the URL can serve different bytes later.',
  fix: 'Verify a checksum, or vendor the binary.',
  check(file) {
    if (!['package.json', 'Dockerfile', 'Makefile'].includes(file.name)) return [];
    const re = /"(?:preinstall|install|postinstall|prepare)"\s*:\s*"([^"]*\b(?:curl|wget|node-gyp|node-pre-gyp|download)\b[^"]*)"/g;
    const out = [];
    for (const m of file.text.matchAll(re)) {
      out.push(makeFinding(this, file.relative, lineOf(file.text, m.index), m[1].slice(0, 120), { detail: 'download at install' }));
    }
    return out;
  },
};

export const remoteEgressDocs = {
  id: 'egress-documented',
  group: 'network',
  title: 'README describes network egress',
  severity: 'info',
  why: 'Positive signal: the project says what it sends and where.',
  fix: 'Nothing to fix.',
  check(file) {
    if (!/README/i.test(file.name)) return [];
    const m = /\b(outbound|egress|phoning home|telemetry|network (?:calls|requests))\b/i.exec(file.text);
    if (!m) return [];
    return [makeFinding(this, file.relative, lineOf(file.text, m.index), snippet(file.text, m.index, 40), { detail: 'documented' })];
  },
};

export const rules = [phishyHosts, postInstallDownload, remoteEgressDocs];