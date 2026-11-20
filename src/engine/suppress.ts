// engine/suppress.ts：例外登録（suppressions.json）の適用
import type { Finding, Suppression } from '../model';
import { baseLabel } from '../parser/target';
import { isCurrentKey, KEY_LABEL } from './targetKey';
import { idProblemText, knownItem } from './profile';

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
/** 読み込む例外の数の上限。判定のたびに例外の数×指摘の数だけ照合するので、多すぎると画面が止まる（2,000件で約2秒） */
export const MAX_SUPPRESSIONS = 1000;
/** 実在する日付（YYYY-MM-DD）か。期限は文字列で比べるので、2026-13-45 を受け付けると期限が意図とずれる */
const realDate = (s: string) => {
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/); if (!m) return false;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3];
};
// 「ラベル URL」の形の target
const LABEL_URL = new RegExp(String.raw`^${KEY_LABEL} https?:\/\/`);

/** 例外の対象が今の形式のキーか（例外ごとに1回だけ調べる。指摘×例外の組ごとに urlKey をかけると遅い） */
const currentKeyCache = new Map<string, boolean>();
const isKeyTarget = (target: string): boolean => {
  let v = currentKeyCache.get(target);
  if (v === undefined) { if (currentKeyCache.size > 5000) currentKeyCache.clear(); v = isCurrentKey(target); currentKeyCache.set(target, v); }
  return v;
};

/**
 * 例外が指摘に当てはまるか。currentKeys は今回の結果のキーの一覧（applySuppressions が渡す）。
 * 例外の target が今の形式のキー（画面で登録したもの）か、今回のどれかのキーと同じなら、キーの完全一致（と、キーがラベルだけになった指摘の
 * 「ラベル URL」）だけで判定する（画面で1つのターゲットに
 * 登録したキー HAR GET https://a.example/* の *（伏せたパスの部分）で、/login・/admin・/ の指摘まで抑止しない。そのページを含まない回の入力でも
 * 同じなので、今回のキーにあるかではなく、キーの形で見分ける）。それ以外の target（以前の版の形式のキー、手で書いたパターン HAR GET *）は、
 * * を任意の文字列として、キーの全体と照合する（1つの部分の中だけにすると、HAR GET * や log* が効かない）
 */
export function matches(s: Suppression, f: Finding, currentKeys?: ReadonlySet<string>): boolean {
  const ruleOk = s.ruleId === f.item || s.ruleId === f.ruleId;
  if (!ruleOk) return false;   // 項目が違えば対象（パターンの照合）を見ない
  // URL のパターンは、画面に出す（マスクした）URL のほかに、突き合わせのキーの URL（マスクとは別に作る）とも照合する（マスクの一覧を変えても
  // 外れない）。キーの最後の絶対 URL（「 #2」を除く）を使う。ラベルの中の「/admin」のような語は URL にしない
  const keyUrl = f.targetKey?.match(/(?:^|\s)(https?:\/\/\S*)(?: #\d+)?$/)?.[1];
  const pattern = s.target.length <= MAX_PATTERN;
  const targetOk = s.target === f.target || s.target === f.targetKey || (pattern && !!f.url && wildcardMatch(s.target, f.url))
    || (pattern && !!keyUrl && wildcardMatch(s.target, keyUrl))
    // 照合するのは URL を持つキーだけ（ラベルだけのキーと照合すると、*login* が login・pre-login ラベルの指摘も抑止する）
    || (pattern && !!f.targetKey && f.targetKey.includes('://') && s.target.includes('*') && !currentKeys?.has(s.target) && !isKeyTarget(s.target) && wildcardMatch(s.target, f.targetKey))
    // 同じラベルが1つに減って、キーが「ラベル URL」からラベルだけになったもの（page https://a.example/b で登録した例外を外さない）。URL のキーは、
    // 生の URL から作ったもの（f.keyUrl）を使う（マスクした URL では ASP.NET の (S(…)) が * になる）。形が「ラベル 空白 URL」のときだけ比べる
    // （組ごとに URL を解析し直すと、例外の照合が大きく遅くなる）。今のキーがラベルだけのときに限る（同じラベル・URL の2つ目の top#2 には
    // 「 #2」を付けたキーがあるので、1つ目に登録した例外を当てない）
    || (!!f.keyUrl && f.targetKey === f.target && LABEL_URL.test(s.target) && s.target === `${baseLabel(f.target)} ${f.keyUrl}`)
    || s.target === '*';   // 対象「*」はすべての指摘に当てる
  return targetOk;
}

/** 手元の日付（YYYY-MM-DD）。toISOString は UTC なので、日本では 0〜9時に前日の日付になる */
export const localDate = (d = new Date()) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** 期限内（当日を含む）なら有効。期限は手元の日付で比べる */
export const isActive = (s: Suppression, today = localDate()) => !s.until || s.until >= today;

export function applySuppressions(fs: Finding[], list: Suppression[], today?: string): Finding[] {
  const active = list.filter(s => isActive(s, today));
  const currentKeys = new Set(fs.map(f => f.targetKey).filter((k): k is string => !!k));
  return fs.map(f => {
    if (f.status !== 'fail') return f;
    const s = active.find(x => matches(x, f, currentKeys));
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
  if (arr.length > MAX_SUPPRESSIONS) errors.push(`例外は${MAX_SUPPRESSIONS}件までです（${arr.length}件のうち、${MAX_SUPPRESSIONS + 1}件目からは読みません）`);
  arr.slice(0, MAX_SUPPRESSIONS).forEach((x, i) => {
    const s = (x && typeof x === 'object' ? x : {}) as Partial<Suppression>;   // null や数値の要素でも落ちない
    if (typeof s.ruleId !== 'string') errors.push(`${i + 1}件目：ruleId が不正です`);
    // チェックリストにない項目（H-99・Z-99）は受け付けない（組織プロファイルと同じ。綴りを誤った例外が黙って効かないことを防ぐ）
    else if (!knownItem(s.ruleId)) errors.push(`${i + 1}件目：ruleId「${s.ruleId}」${idProblemText(s.ruleId)}`);
    else if (typeof s.target !== 'string' || !s.target) errors.push(`${i + 1}件目：target がありません`);
    else if (s.target.length > MAX_PATTERN) errors.push(`${i + 1}件目：target が長すぎます（${MAX_PATTERN}文字まで）`);
    else if (typeof s.reason !== 'string' || !s.reason.trim()) errors.push(`${i + 1}件目：reason（理由）がありません`);
    else if (s.approver !== undefined && typeof s.approver !== 'string') errors.push(`${i + 1}件目：approver は文字列で書きます`);
    // 期限なしは、書かないか空の文字列（null も）。false・0 のような値は期限なしとして受け付けない
    else if (s.until !== undefined && s.until !== null && s.until !== '' && (typeof s.until !== 'string' || !realDate(s.until))) errors.push(`${i + 1}件目：until は YYYY-MM-DD で書きます`);
    else list.push({ ruleId: s.ruleId, target: s.target, reason: s.reason, approver: s.approver ?? '', until: s.until ?? '' });
  });
  return { list, errors };
}
