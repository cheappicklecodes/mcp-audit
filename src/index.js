import { scan, ALL_RULES, RULE_MAP, score, grade, counts } from './engine.js';
import { renderText, renderJson, renderSarif, renderMarkdown } from './report.js';
import { SEVERITY } from './util.js';

export { scan, ALL_RULES, RULE_MAP, score, grade, counts, SEVERITY };
export { renderText, renderJson, renderSarif, renderMarkdown };

export function audit(root, options = {}) {
  const result = scan(root, options);
  return { ...result, grade: grade(result.score).letter };
}