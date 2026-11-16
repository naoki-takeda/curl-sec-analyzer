// engine/suppress.ts：例外登録（suppressions.json）の適用
import type { Finding, Suppression } from '../model';
import { baseLabel } from '../parser/target';
import { urlKey } from './targetKey';

/**
 * URL のパターン照合（* は任意の文字列）。正規表現に変換すると、* の多いパターンでバックトラックが爆発する（ReDoS）ため、
 * 最後の * の位置だけを覚えて戻る方式で照合する。時間はパターン長×文字列長以内で必ず終わる
 */
export function wildcardMatch(pattern: string, text: string): boolean {
  let p = 0, t = 0, star = -1, mark = 0;
  while (t < text.length) {
    if (p < pattern.length && pattern[p] !== '*' && pattern[p] === text[t]) { p++; t++; }
    else if (p < pattern.length && pattern[p] === '*') { star = p++; mark = t; }
    else if (star >= 0) { p = star + 1; t = ++mark; }
    else return false;
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}
const MAX_PATTERN = 500;
/** 「/」で区切った部分ごとに照合する（部分の数が同じで、各部分が * を含めて一致する）。* が「/」をまたがない */
function segmentMatch(pattern: string, text: string): boolean {
  const p = pattern.split('/'), t = text.split('/');
  return p.length === t.length && p.every((x, i) => wildcardMatch(x, t[i]));
}

export function matches(s: Suppression, f: Finding): boolean {
  const ruleOk = s.ruleId === f.item || s.ruleId === f.ruleId;
  // URL のパターンは、画面に出す（マスクした）URL のほかに、突き合わせのキーの URL（マスクとは別に作る。マスクの一覧を変えても変わらない）とも照合する。
  // マスクした URL とだけ比べると、マスクの一覧を変えるたびに、伏せ方の変わった URL のパターンが黙って外れた
  // キーの最後の絶対 URL（「 #2」を除く）。ラベルの中の「/admin」のような語は URL にしない
  const keyUrl = f.targetKey?.match(/(?:^|\s)(https?:\/\/\S*)(?: #\d+)?$/)?.[1];
  const pattern = s.target.length <= MAX_PATTERN;
  const targetOk = s.target === f.target || s.target === f.targetKey || (pattern && !!f.url && wildcardMatch(s.target, f.url))
    || (pattern && !!keyUrl && wildcardMatch(s.target, keyUrl))
    // 以前の版のキー（HAR GET https://www.example.jp/*）も、キーの全体と照合する（キーの形を変えると、例外が黙って外れた）。照合するのは URL を持つキー
    // だけで、* は「/」で区切った1つの部分の中だけに一致させる（画面で1つのターゲットに登録したキーの *（伏せたパスの部分）が、同じホストの
    // ほかのページにも効いた。ラベルだけのキーと照合すると、*login* が login ラベルの指摘も抑止した）
    || (pattern && !!f.targetKey && f.targetKey.includes('://') && s.target.includes('*') && segmentMatch(s.target, f.targetKey))
    // 同じラベルが1つに減って、キーが「ラベル URL」からラベルだけになったもの（page https://a.example/b で登録した例外が外れた）
    || (!!f.url && s.target === `${baseLabel(f.target)} ${urlKey(f.url)}`)
    || s.target === '*';   // HAR は「HAR メソッド URL」で照合
  return ruleOk && targetOk;
}

/** 手元の日付（YYYY-MM-DD）。toISOString は UTC なので、日本では 0〜9時に前日の日付になる */
export const localDate = (d = new Date()) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** 期限内（当日を含む）なら有効。期限は手元の日付で比べる */
export const isActive = (s: Suppression, today = localDate()) => !s.until || s.until >= today;

export function applySuppressions(fs: Finding[], list: Suppression[], today?: string): Finding[] {
  const active = list.filter(s => isActive(s, today));
  return fs.map(f => {
    if (f.status !== 'fail') return f;
    const s = active.find(x => matches(x, f));
    return s ? { ...f, status: 'suppressed', suppressedBy: s } : f;
  });
}

/** suppressions.json を検証して読み込む。形式が違う項目は理由付きで返す */
export function parseSuppressions(text: string): { list: Suppression[]; errors: string[] } {
  const errors: string[] = []; const list: Suppression[] = [];
  let data: unknown;
  try { data = JSON.parse(text); } catch { return { list, errors: ['JSONとして読めません'] }; }
  const arr = Array.isArray(data) ? data : (data as { suppressions?: unknown })?.suppressions;
  if (!Array.isArray(arr)) return { list, errors: ['配列、または suppressions を持つオブジェクトが必要です'] };
  arr.forEach((x, i) => {
    const s = (x && typeof x === 'object' ? x : {}) as Partial<Suppression>;   // null や数値の要素でも落ちない（fast-check で検出）
    if (typeof s.ruleId !== 'string' || !/^[A-Z]-\d\d(\.\d+)?$/.test(s.ruleId)) errors.push(`${i + 1}件目：ruleId が不正です`);
    else if (typeof s.target !== 'string' || !s.target) errors.push(`${i + 1}件目：target がありません`);
    else if (s.target.length > MAX_PATTERN) errors.push(`${i + 1}件目：target が長すぎます（${MAX_PATTERN}文字まで）`);
    else if (typeof s.reason !== 'string' || !s.reason.trim()) errors.push(`${i + 1}件目：reason（理由）がありません`);
    else if (s.approver !== undefined && typeof s.approver !== 'string') errors.push(`${i + 1}件目：approver は文字列で書きます`);
    else if (s.until && !/^\d{4}-\d{2}-\d{2}$/.test(s.until)) errors.push(`${i + 1}件目：until は YYYY-MM-DD で書きます`);
    else list.push({ ruleId: s.ruleId, target: s.target, reason: s.reason, approver: s.approver ?? '', until: s.until ?? '' });
  });
  return { list, errors };
}
