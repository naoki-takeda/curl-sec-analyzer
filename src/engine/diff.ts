// engine/diff.ts：前回の結果（JSONエクスポート）との差分（v0.4）
import type { Finding, Profile, Severity } from '../model';
import { parseProfile } from './profile';
import { maskKey } from '../mask';

export type DiffKind = 'new' | 'resolved' | 'continuing' | 'severity-changed' | 'not-rechecked' | 'suppressed';
export interface DiffRow { kind: DiffKind; ruleId: string; item: string; condition?: number; title: string; target: string; severity: Severity; before?: Severity; }
export interface Baseline { generatedAt: string; toolVersion?: string; rulesetVersion?: string; findings: Finding[]; profile?: Profile; }

const RULE_ID = /^([HCRTEA]-\d\d)\.(\d+|ok|na)$/;
const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];
const STATUSES: Finding['status'][] = ['pass', 'fail', 'na', 'suppressed'];

/** 前回の結果の指摘1件を確かめる。形式が合わなければ undefined（手で編集したJSONや別のツールのJSONでも、表示を崩さないため） */
function validFinding(x: unknown): Finding | undefined {
  if (!x || typeof x !== 'object') return undefined;
  const f = x as Partial<Finding>;
  const m = typeof f.ruleId === 'string' ? f.ruleId.match(RULE_ID) : null;
  if (!m || typeof f.target !== 'string' || !f.target) return undefined;
  if (!SEVERITIES.includes(f.severity as Severity) || !STATUSES.includes(f.status as Finding['status'])) return undefined;
  if (f.item !== undefined && f.item !== m[1]) return undefined;               // ruleId と item が食い違うものは信用しない
  const condition = /^\d+$/.test(m[2]) ? Number(m[2]) : undefined;              // 条件番号は ruleId から作り直す
  return { ...(f as Finding), item: m[1], condition, title: typeof f.title === 'string' ? f.title : '',
           targetKey: typeof f.targetKey === 'string' ? f.targetKey : undefined };
}

export function parseBaseline(text: string): { baseline?: Baseline; error?: string; skipped: number } {
  let d: { generatedAt?: unknown; toolVersion?: unknown; rulesetVersion?: unknown; findings?: unknown; profile?: unknown };
  try { d = JSON.parse(text); } catch { return { error: 'JSONとして読めません', skipped: 0 }; }
  if (!d || typeof d !== 'object' || !Array.isArray(d.findings)) return { error: 'このツールでエクスポートしたJSONを選んでください（findings がありません）', skipped: 0 };
  const all = d.findings as unknown[];
  const findings = all.map(validFinding).filter((f): f is Finding => !!f);
  // プロファイルも組織プロファイルと同じ検査を通す（壊れた値で差分の警告の比較が落ちないように）
  const profile = d.profile && typeof d.profile === 'object' ? parseProfile(JSON.stringify(d.profile)).profile : undefined;
  return { baseline: { generatedAt: typeof d.generatedAt === 'string' ? d.generatedAt : '', toolVersion: typeof d.toolVersion === 'string' ? d.toolVersion : undefined,
                       rulesetVersion: typeof d.rulesetVersion === 'string' ? d.rulesetVersion : undefined, findings, profile },
           skipped: all.length - findings.length };
}

/** 突き合わせのキー。targetKey がない以前のJSONはラベルで突き合わせる */
const tkey = (f: Finding) => f.targetKey ?? f.target;
const key = (f: Finding) => `${f.ruleId}\u0000${tkey(f)}`;
/** 指摘として残っているもの。例外を適用した指摘（suppressed）も、直ってはいないので含める */
const isOpen = (f: Finding) => f.status === 'fail' || f.status === 'suppressed';

/**
 * 指摘（fail・suppressed）を「ルールID×ターゲット」で突き合わせる。
 * - 今回 suppressed：前回 fail（または前回なし）なら「例外登録」。前回も suppressed なら変化なしとして出さない
 * - 今回 fail：前回なしなら「新規」。前回 suppressed（例外の期限切れなど）は既知の指摘なので「継続」か「重要度の変化」
 * - 前回の指摘が今回ない場合、同じターゲットで同じ項目を判定していれば「解消」、判定していなければ「再診断していない」とする
 */
/**
 * 以前の版の形式のキー。今のキーは maskKey の出力なので、キーの URL の部分にもう一度 maskKey をかけても変わらない。変わるものは以前の形式
 * （v0.4.26〜v0.4.28：伏せた値の「…」やクエリの値、v0.4.29：パス引数の値や並べ替えていない名前、v0.4.30：残す形が違うパスの部分）。
 * 形式ごとに見分けると、パスの部分の伏せ方が変わったキーを見逃し、黙って突き合わなくなった。読み込んだときに件数を知らせる
 */
export function legacyHarKey(k?: string): boolean {
  const m = k?.match(/^(?:HAR \S+|\S+) ((?:https?:\/\/|\/)\S*)/);
  return !!m && maskKey(m[1]) !== m[1];
}

export function diff(before: Finding[], after: Finding[]): DiffRow[] {
  const prev = new Map(before.filter(isOpen).map(f => [key(f), f]));
  const now = new Map(after.filter(isOpen).map(f => [key(f), f]));
  const evaluatedNow = new Set(after.filter(f => f.status !== 'na' || f.dedupedBy).flatMap(f => [`${f.item}\u0000${tkey(f)}`, ...(tkey(f).startsWith('HAR ') ? [] : [`${f.item}\u0000${f.target}`])]));
  const rows: DiffRow[] = [];
  const row = (kind: DiffKind, f: Finding, before?: Severity): DiffRow => ({ kind, ruleId: f.ruleId, item: f.item, condition: f.condition, title: f.title, target: f.target, severity: f.severity, before });
  // 1回目はキーで突き合わせる。2回目に、残ったものをラベルで突き合わせる：同じラベルの2つ目を足すと、1つ目のキーが「top」から
  // 「top https://…」に変わる。v0.4.27 以前の結果（キーは top・top#2）とも、ラベルで突き合う
  const pairs = new Map<string, Finding | undefined>();
  const used = new Set<string>();
  for (const k of now.keys()) if (prev.has(k)) { pairs.set(k, prev.get(k)); used.add(k); }
  // HAR のラベル（har-4）は記録し直すと別の応答を指すので、ラベルでは突き合わせない
  const isHar = (f: Finding) => tkey(f).startsWith('HAR ');
  const byLabel = new Map<string, string>();
  for (const [k, f] of prev) if (!used.has(k) && !isHar(f)) { const l = `${f.ruleId}\u0000${f.target}`; if (!byLabel.has(l)) byLabel.set(l, k); }
  for (const [k, f] of now) {
    if (pairs.has(k)) continue;
    const pk = isHar(f) ? undefined : byLabel.get(`${f.ruleId}\u0000${f.target}`);
    if (pk && !used.has(pk)) { pairs.set(k, prev.get(pk)); used.add(pk); } else pairs.set(k, undefined);
  }
  for (const [k, f] of now) {
    const p = pairs.get(k);
    if (f.status === 'suppressed') { if (p?.status !== 'suppressed') rows.push(row('suppressed', f)); continue; }
    rows.push(!p ? row('new', f) : p.severity !== f.severity ? row('severity-changed', f, p.severity) : row('continuing', f));
  }
  for (const [k, f] of prev) if (!used.has(k)) rows.push(row(evaluatedNow.has(`${f.item}\u0000${tkey(f)}`) || evaluatedNow.has(`${f.item}\u0000${f.target}`) ? 'resolved' : 'not-rechecked', f));
  const order: DiffKind[] = ['new', 'severity-changed', 'suppressed', 'resolved', 'not-rechecked', 'continuing'];
  return rows.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.ruleId.localeCompare(b.ruleId));
}

export function diffSummary(rows: DiffRow[]): Record<DiffKind, number> {
  const c: Record<DiffKind, number> = { new: 0, resolved: 0, continuing: 0, 'severity-changed': 0, 'not-rechecked': 0, suppressed: 0 };
  for (const r of rows) c[r.kind]++;
  return c;
}

/** 前回と今回でプロファイル（重要度・対象外の項目）が違うか。違えば「重要度の変化」に設定の違いが混ざる */
export function profileDiffers(before?: Profile, now?: Profile): boolean {
  const norm = (p?: Profile) => JSON.stringify({ severity: p?.severity ?? {}, exclude: [...(p?.exclude ?? [])].sort(), names: [...(p?.sessionCookieNames ?? [])].sort(), hours: p?.sessionMaxAgeHours ?? 24, origins: [...(p?.trustedScriptOrigins ?? [])].sort() });
  return norm(before) !== norm(now);
}
