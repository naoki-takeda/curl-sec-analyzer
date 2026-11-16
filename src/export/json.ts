// export/json.ts：Finding の配列、版、生成日時、例外一覧
import type { Coverage, Finding, Profile, Suppression } from '../model';
import { RULESET_VERSION, TOOL_VERSION } from '../rules/ruleset';
import { standardsTable } from '../engine/standards';

export function toJson(fs: Finding[], cov: Coverage[], suppressions: Suppression[], generatedAt = new Date(), profile?: Profile): string {
  return JSON.stringify({ tool: 'curl-sec-analyzer', toolVersion: TOOL_VERSION, rulesetVersion: RULESET_VERSION,
    generatedAt: generatedAt.toISOString(), profile, findings: fs, coverage: cov, suppressions, standards: standardsTable() }, null, 2);
}

export const suppressionsJson = (list: Suppression[]) => JSON.stringify({ suppressions: list }, null, 2);
