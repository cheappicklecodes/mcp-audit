import fs from 'node:fs';
import path from 'node:path';

export const CONFIG_NAME = '.mcp-audit.json';

const KNOWN = new Set(['exclude', 'include', 'disable', 'only', 'minSeverity', 'failOn']);

export function loadConfig(root) {
  const file = path.join(root, CONFIG_NAME);
  if (!fs.existsSync(file)) return {};

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`${CONFIG_NAME} is not valid JSON: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${CONFIG_NAME} must be a JSON object`);
  }

  for (const key of Object.keys(parsed)) {
    if (!KNOWN.has(key)) throw new Error(`unknown key in ${CONFIG_NAME}: ${key}`);
  }

  const config = {};
  for (const key of ['exclude', 'include', 'disable', 'only']) {
    if (parsed[key] === undefined) continue;
    if (!Array.isArray(parsed[key])) throw new Error(`${key} in ${CONFIG_NAME} must be an array`);
    config[key] = parsed[key].map(String);
  }
  for (const key of ['minSeverity', 'failOn']) {
    if (parsed[key] !== undefined) config[key] = String(parsed[key]);
  }
  return config;
}

export function mergeConfig(opts, config) {
  return {
    ...opts,
    exclude: [...(config.exclude ?? []), ...(opts.exclude ?? [])],
    include: (opts.include ?? []).length ? opts.include : (config.include ?? []),
    disable: [...(config.disable ?? []), ...(opts.disable ?? [])],
    only: (opts.only ?? []).length ? opts.only : (config.only ?? []),
    minSeverity: opts.minSeverity ?? config.minSeverity ?? null,
    failOn: opts.failOn ?? config.failOn ?? null,
  };
}