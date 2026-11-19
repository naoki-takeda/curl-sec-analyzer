// engine/standards.ts：チェックリストの項目と、OWASP ASVS 5.0.0・IPA「安全なウェブサイトの作り方」の対応
// - 対応は items.json の asvs・ipa に持つ。「関連する要件」であり、その要件の合否を判定するものではない
// - ASVS の要件の文言は CC BY-SA 4.0 のため取り込まず、要件IDとレベルだけを持つ（asvs-levels.json は原典の v5.0.0 タグから生成）
// - IPA の項番：第1章は「4-(iii)」「4-(iv)-a」、第2章は節番号と番号を「2.3-1)」のようにつなぐ
import type { ItemInfo } from '../model';
import items from './items.json';
import levels from './asvs-levels.json';

/** OWASP API Security Top 10 2023 との対応（画面とエクスポートに表示） */
export const API_TOP10: Record<string, string> = {
  'A-01': 'API2:2023', 'A-02': 'API2:2023・API8:2023', 'A-03': 'API2:2023', 'A-04': 'API4:2023', 'A-05': 'API4:2023', 'A-06': 'API4:2023',
  'A-07': 'API3:2023', 'A-08': 'API8:2023', 'A-09': 'API8:2023', 'A-10': 'API8:2023', 'A-11': 'API5:2023・API9:2023',
};

export const ASVS_VERSION = '5.0.0';
export const IPA_EDITION = '安全なウェブサイトの作り方 改訂第7版';
export const IPA_EDITION_EN = 'IPA "How to Secure Your Web Site", 7th edition (Japanese)';

const BY_ID = new Map((items as ItemInfo[]).map(i => [i.id, i]));
const LEVELS = levels as Record<string, number>;

export interface Standards { asvs: string[]; ipa: string[]; }
export const standardsOf = (item: string): Standards => {
  const it = BY_ID.get(item);
  return { asvs: it?.asvs ?? [], ipa: it?.ipa ?? [] };
};

/** ASVS が推奨する引用の形（v<version>-<要件ID>）。レベルを添える：v5.0.0-3.4.1 (L1) */
export const asvsRef = (id: string) => `v${ASVS_VERSION}-${id}${LEVELS[id] ? ` (L${LEVELS[id]})` : ''}`;
export const asvsLevel = (id: string): number | undefined => LEVELS[id];

/** 表のセル用の短い表記：「ASVS 3.4.1・IPA 2.3-1)」。対応がなければ空文字 */
export function standardsShort(item: string): string {
  const s = standardsOf(item);
  return [s.asvs.length ? `ASVS ${s.asvs.join(', ')}` : '', s.ipa.length ? `IPA ${s.ipa.join(', ')}` : ''].filter(Boolean).join('・');
}

/** JSON エクスポート用の対応表（ほかのツールで読み込めるように、版とレベルも入れる） */
export function standardsTable() {
  return {
    asvs: { version: ASVS_VERSION, format: 'v<version>-<requirement>', levels: LEVELS },
    ipa: { edition: IPA_EDITION },
    items: Object.fromEntries([...BY_ID.values()].map(i => [i.id, { asvs: i.asvs, ipa: i.ipa }])),
  };
}
