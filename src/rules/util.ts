import type { Finding, Rule, RuleContext, Severity, Status } from '../model';

export function mk(rule: Rule, ctx: RuleContext, cond: number | 'ok' | 'na', severity: Severity, status: Status,
                   evidence: string, recommendation: string, extra: Partial<Finding> = {}): Finding {
  return { ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined,
           title: rule.title, severity, status, target: ctx.target.label, evidence, recommendation,
           references: rule.basis, score: 0, ...extra };
}

export const header = (ctx: RuleContext, name: string): string[] => ctx.final?.headers.get(name) ?? [];

/** CSP 値をディレクティブ名→値の Map にする（同名の最初の指定が有効） */
export function parseCsp(v: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const part of v.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && /^[a-z-]+$/i.test(name) && !m.has(name.toLowerCase())) m.set(name.toLowerCase(), vals);
  }
  return m;
}

/** HSTS のディレクティブ（includesubdomains・preload）があるか。H-01・H-02・横断ルール・画面の案内で同じ読み方にする（部分一致にしない） */
export const hstsDirective = (v: string | undefined, name: 'includesubdomains' | 'preload'): boolean =>
  (v ?? '').split(';').some(d => d.trim().toLowerCase() === name);
