// engine/labels.ts：ラベルと適用する項目の対応表（labels.json）を引く
import type { Finding } from '../model';
import table from './labels.json';
import { baseLabel } from '../parser/target';

interface LabelRow { match: 'default' | 'exact' | 'prefix'; label?: string; name: string; nameEn: string; items: string[]; har: boolean; }
const ROWS = table as LabelRow[];

export function labelRow(raw: string): LabelRow {
  const label = baseLabel(raw);   // 同じラベルを付け直した http#2 なども、http と同じ項目を判定する
  return ROWS.find(r => r.match === 'exact' && r.label === label)
      ?? ROWS.find(r => r.match === 'prefix' && label.startsWith(r.label!))
      ?? ROWS.find(r => r.match === 'default')!;
}

export interface Allow { name: string; allowsItem(item: string): boolean; allowsFinding(f: Finding): boolean; }

/** 項目単位（H-01）と条件単位（T-05.2）の指定を判定する */
export function allowedItems(label: string): Allow {
  const row = labelRow(label);
  const items = new Set<string>(), conds = new Map<string, Set<number>>();
  for (const spec of row.items) {
    const [item, c] = spec.split('.');
    if (c) { const s = conds.get(item) ?? new Set<number>(); s.add(Number(c)); conds.set(item, s); }
    else items.add(item);
  }
  return {
    name: row.name,
    allowsItem: item => items.has(item) || conds.has(item),
    allowsFinding: f => items.has(f.item) || f.condition === undefined || (conds.get(f.item)?.has(f.condition) ?? false),
  };
}

/** HARのエントリに付けられるラベルか（parser/har.ts が使う） */
export const allowedForHar = (label: string) => labelRow(label).har;

/** 片方だけあると横断ルールを判定できない予約ラベルの組 [あるラベル, 足りないラベル, 項目]。CROSS_REQUIRES の2つのラベルの組と合わせる */
export const RESERVED_HINTS: [string, string, string][] = [
  ['login', 'pre-login', 'C-09'], ['pre-login', 'login', 'C-09'], ['logout', 'after-logout', 'C-12'], ['after-logout', 'logout', 'C-12'],
];

/** 横断ルールが必要とするラベル（labels.json の対応表では表せないもの） */
const CROSS_REQUIRES: Record<string, string[]> = {
  'C-07': ['session-sample-*（2つ以上）'], 'C-09': ['pre-login', 'login'], 'C-12': ['logout', 'after-logout'],
  'H-02': ['apex'], 'H-04': ['csp-sample-*（2つ以上）'], 'A-10': ['error-*（APIのエラー応答を2つ以上）'],
};

/**
 * 診断カバレッジで案内する「必要なラベル」。labels.json から作り、横断ルールの分を足す。
 * csp-sample-* は一般ターゲットと同じ項目を判定するが、案内は H-04⑤ のためだけにするので除く
 */
export function requiredLabels(item: string): string[] {
  const out: string[] = [];
  for (const r of ROWS) {
    if (r.label === 'csp-sample-') continue;
    if (!r.items.some(i => i.split('.')[0] === item)) continue;
    out.push(r.match === 'default' ? '（一般）' : r.match === 'prefix' ? `${r.label}*` : r.label!);
  }
  for (const l of CROSS_REQUIRES[item] ?? []) {          // 同じラベルがあれば、横断ルールの条件（2つ以上など）付きの表記に置き換える
    const i = out.findIndex(o => o !== '（一般）' && l.startsWith(o.replace(/\*$/, '')));
    if (i >= 0) out[i] = l; else out.push(l);
  }
  return [...new Set(out)];
}
