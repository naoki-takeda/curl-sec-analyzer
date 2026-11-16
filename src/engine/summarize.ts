// engine/summarize.ts：主な指標は重要度別のfail件数。全体は「項目×条件」（ルールID）で一意に数える
import type { Finding, Severity } from '../model';

export const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];
export const SEVERITY_LABEL: Record<Severity, string> = { high: '高', medium: '中', low: '低', info: '情報' };

export interface OverallRow { ruleId: string; item: string; condition?: number; title: string; severity: Severity; targets: string[]; }

/** 同じルールIDの fail をまとめ、該当ターゲットを列挙する */
export function overall(fs: Finding[]): OverallRow[] {
  const m = new Map<string, OverallRow>();
  for (const f of fs) {
    if (f.status !== 'fail') continue;
    const row = m.get(f.ruleId) ?? { ruleId: f.ruleId, item: f.item, condition: f.condition, title: f.title, severity: f.severity, targets: [] };
    if (!row.targets.includes(f.target)) row.targets.push(f.target);
    if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(row.severity)) row.severity = f.severity;
    m.set(f.ruleId, row);
  }
  return [...m.values()].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.ruleId.localeCompare(b.ruleId));
}

export function countBySeverity(rows: OverallRow[]): Record<Severity, number> {
  const c: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of rows) c[r.severity]++;
  return c;
}

/** 丸数字（第8章の「該当条件」列） */
export const circled = (n?: number) => (n && n >= 1 && n <= 20 ? String.fromCodePoint(0x245f + n) : '');
