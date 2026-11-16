// engine/coverage.ts：診断カバレッジ（ツール設計2）
import type { Coverage, Finding, ItemInfo } from '../model';
import items from './items.json';
import { requiredLabels } from './labels';

export const ITEMS = items as ItemInfo[];

export function coverage(fs: Finding[], implemented: Set<string>, list: ItemInfo[] = ITEMS, excluded: string[] = []): Coverage[] {
  return list.map(it => {
    const base = { item: it.id, title: it.title, chapter: it.chapter };
    if (excluded.includes(it.id)) return { ...base, status: 'excluded', reasons: ['組織プロファイルで対象外'], fails: 0 };
    if (it.manual) return { ...base, status: 'manual', reasons: [], fails: 0 };
    if (!implemented.has(it.id)) return { ...base, status: 'not-implemented', reasons: [it.phase], fails: 0 };
    const mine = fs.filter(f => f.item === it.id);
    const done = mine.filter(f => f.status !== 'na' || f.dedupedBy);   // 二重計上の防止で na にしたものは判定済み
    if (done.length) return { ...base, status: 'evaluated', reasons: [], fails: done.filter(f => f.status === 'fail').length };
    const reasons = [...new Set(mine.map(f => f.recommendation || f.evidence).filter(Boolean))];   // na の Finding が持つ理由
    return { ...base, status: 'missing-input', reasons: reasons.length ? reasons : [`必要なラベル: ${requiredLabels(it.id).join(', ')}`], fails: 0 };
  });
}

/** カバレッジ率：判定済みの項目数 ÷ 実装済みの自動判定項目の数（手動確認と未対応を除く） */
export function coverageRate(cs: Coverage[]): { evaluated: number; denominator: number; notImplemented: number } {
  const auto = cs.filter(c => c.status === 'evaluated' || c.status === 'missing-input');
  return { evaluated: auto.filter(c => c.status === 'evaluated').length, denominator: auto.length,
           notImplemented: cs.filter(c => c.status === 'not-implemented').length };
}
