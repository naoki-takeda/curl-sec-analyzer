// engine/summarize.ts：主な指標は重要度別のfail件数。全体は「項目×条件」（ルールID）で一意に数える
import type { Finding, Severity } from '../model';

export const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];
export const SEVERITY_LABEL: Record<Severity, string> = { high: '高', medium: '中', low: '低', info: '情報' };

interface OverallRow { ruleId: string; item: string; condition?: number; title: string; severity: Severity; targets: string[]; }

/** 同じルールIDの fail をまとめ、該当ターゲットを列挙する */
export function overall(fs: Finding[]): OverallRow[] {
  const m = new Map<string, OverallRow>();
  const seen = new Set<string>();   // ルールID×ターゲット（配列の includes では、数万件の HAR でターゲット数の2乗の時間になる）
  for (const f of fs) {
    if (f.status !== 'fail') continue;
    const row = m.get(f.ruleId) ?? { ruleId: f.ruleId, item: f.item, condition: f.condition, title: f.title, severity: f.severity, targets: [] };
    const k = `${f.ruleId}\u0000${f.target}`;
    if (!seen.has(k)) { seen.add(k); row.targets.push(f.target); }
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

/**
 * 判定不能（na）の行のうち、証跡と推奨対応が同じものを1行にまとめる（項目の列に項目IDを並べる）。本文を採取していないページでは、
 * E-02・E-07〜E-10・E-12 が同じ理由の na になるので、1つのターゲットに6行並べない
 */
export function mergeNa(fs: Finding[]): (Finding & { items?: string[] })[] {
  const out: (Finding & { items?: string[] })[] = []; const byReason = new Map<string, Finding & { items?: string[] }>();
  for (const f of fs) {
    if (f.status !== 'na') { out.push(f); continue; }
    // ターゲット（ホスト）が違うものはまとめない（ホスト単位・横断の表で、別のホストの判定不能を1行にしない）
    const k = JSON.stringify([f.target, f.evidence, f.recommendation]); const g = byReason.get(k);
    if (!g) { const row = { ...f }; byReason.set(k, row); out.push(row); continue; }
    g.items = [...new Set([...(g.items ?? [g.item]), f.item])];
  }
  return out;
}
