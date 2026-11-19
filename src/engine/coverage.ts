// engine/coverage.ts：診断カバレッジ（ツール設計2）
import type { Coverage, Finding, ItemInfo } from '../model';
import items from './items.json';
import { requiredLabels } from './labels';

export const ITEMS = items as ItemInfo[];
export const PARTIAL = '一部の条件（ほかのラベルと比べる条件、ホスト単位の条件）は入力不足';
/** 機密でない応答（静的リソースなど）だけで判定した項目の理由（H-12 の①を判定していないのに「判定済み・0件」とだけ見せない） */
export const LIMITED = '機密応答では判定していない（静的リソース・機密でない応答だけ）';
/** ターゲットごとの条件が、一部のターゲットで入力不足（本文を採取していないページなど）。件数はターゲットの数 */
export const someTargets = (n: number) => `一部のターゲット（${n}件）は入力不足`;
/** ほかの項目に任せた na（「HSTSがない（H-01で判定）」「…（HSTSの構文の誤り。H-01③で判定）」「強制モードのCSPがない（H-03で判定）」）。入力不足ではないので、上の件数に数えない */
const DELEGATED = /[（。][A-Z]-\d{2}[①-⑳]?で判定）$/;

export function coverage(fs: Finding[], implemented: Set<string>, list: ItemInfo[] = ITEMS, excluded: string[] = []): Coverage[] {
  return list.map(it => {
    const base = { item: it.id, title: it.title, chapter: it.chapter };
    if (excluded.includes(it.id)) return { ...base, status: 'excluded', reasons: ['組織プロファイルで対象外'], fails: 0 };
    if (it.manual) return { ...base, status: 'manual', reasons: [], fails: 0 };
    if (!implemented.has(it.id)) return { ...base, status: 'not-implemented', reasons: [it.phase], fails: 0 };
    const mine = fs.filter(f => f.item === it.id);
    const done = mine.filter(f => f.status !== 'na' || f.dedupedBy);   // 二重計上の防止で na にしたものは判定済み
    if (done.length) {
      const fails = done.filter(f => f.status === 'fail').length;
      // 横断・ホスト単位の条件が入力不足（ルールが付けた印 partial）なら、判定済みのまま理由に示す（login だけで C-09 が「判定済み・0件」と
      // 見えないように）。指摘があっても示す（T-09 の②だけで、①を確かめていないとき）
      const partial = [...new Set(mine.filter(f => f.status === 'na' && !f.dedupedBy && f.partial).map(f => f.recommendation || f.evidence).filter(Boolean))];
      const limited = done.every(f => f.limited) ? [LIMITED] : [];
      // ターゲットごとのルールの na（本文を採取していないページの E-07 など）も、ほかのターゲットで判定していれば判定済みのまま、件数と理由を示す
      // （本文を採取した HTML が1つあっても、本文のない機密のページを調べていないことが見えるように）
      const naTargets = mine.filter(f => f.status === 'na' && !f.dedupedBy && !f.partial && !DELEGATED.test(f.evidence));
      const perTarget = naTargets.length ? [someTargets(new Set(naTargets.map(f => f.target)).size),
        ...new Set(naTargets.map(f => f.recommendation || f.evidence).filter(Boolean))] : [];
      return { ...base, status: 'evaluated', reasons: [...limited, ...(partial.length ? [PARTIAL, ...partial] : []), ...perTarget], fails };
    }
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
