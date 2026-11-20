// engine/diff.ts：前回の結果（JSONエクスポート）との差分
import type { Finding, Profile, Severity } from '../model';
import { parseProfile } from './profile';
import { SEVERITIES } from './summarize';
import { baseLabel } from '../parser/target';

export type DiffKind = 'new' | 'resolved' | 'continuing' | 'severity-changed' | 'not-rechecked' | 'suppressed';
export interface DiffRow { kind: DiffKind; ruleId: string; item: string; condition?: number; title: string; target: string; severity: Severity; before?: Severity; }
export interface Baseline { generatedAt: string; rulesetVersion?: string; findings: Finding[]; profile?: Profile; }

const RULE_ID = /^([HCRTEA]-\d\d)\.(\d+|ok|na)$/;
const STATUSES: Finding['status'][] = ['pass', 'fail', 'na', 'suppressed'];
const GENERATED_AT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;

/** 前回の結果の指摘1件を確かめる。形式が合わなければ undefined（手で編集したJSONや別のツールのJSONでも、表示を崩さないため） */
function validFinding(x: unknown): Finding | undefined {
  if (!x || typeof x !== 'object') return undefined;
  const f = x as Partial<Finding>;
  const m = typeof f.ruleId === 'string' ? f.ruleId.match(RULE_ID) : null;
  if (!m || typeof f.target !== 'string' || !f.target) return undefined;
  if (!SEVERITIES.includes(f.severity as Severity) || !STATUSES.includes(f.status as Finding['status'])) return undefined;
  if (f.item !== undefined && f.item !== m[1]) return undefined;               // ruleId と item が食い違うものは信用しない
  const condition = /^\d+$/.test(m[2]) ? Number(m[2]) : undefined;              // 条件番号は ruleId から作り直す
  // 差分で使う項目だけを、型を確かめて取り出す（"evidence": 1 のような値で差分の計算を例外にしない）。
  // 長さは切らない（大きな CSP の証跡の後ろのホスト名が前回のキーからだけ落ち、同じ結果どうしが新規と解消に分かれるため）
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  return { ruleId: f.ruleId!, item: m[1], condition, title: str(f.title), severity: f.severity!, status: f.status!, target: f.target,
           targetKey: typeof f.targetKey === 'string' ? f.targetKey : undefined, evidence: str(f.evidence), recommendation: '', references: [] };
}

export function parseBaseline(text: string): { baseline?: Baseline; error?: string; skipped: number } {
  let d: { generatedAt?: unknown; rulesetVersion?: unknown; findings?: unknown; profile?: unknown };
  try { d = JSON.parse(text); } catch { return { error: 'JSONとして読めません', skipped: 0 }; }
  if (!d || typeof d !== 'object' || !Array.isArray(d.findings)) return { error: 'このツールでエクスポートしたJSONを選んでください（findings がありません）', skipped: 0 };
  const all = d.findings as unknown[];
  const findings = all.map(validFinding).filter((f): f is Finding => !!f);
  // プロファイルも組織プロファイルと同じ検査を通す（壊れた値で差分の警告の比較が落ちないように）
  const profile = d.profile && typeof d.profile === 'object' ? parseProfile(JSON.stringify(d.profile)).profile : undefined;
  // 日時は toJson が出す形だけを受け付ける（ファイルに書かれた任意の文字列を、差分の見出し・設定の欄・Markdown にそのまま出さない）
  return { baseline: { generatedAt: typeof d.generatedAt === 'string' && GENERATED_AT.test(d.generatedAt) ? d.generatedAt : '',
                       rulesetVersion: typeof d.rulesetVersion === 'string' ? d.rulesetVersion : undefined, findings, profile },
           skipped: all.length - findings.length };
}

/** 突き合わせのキー。targetKey がない以前のJSONはラベルで突き合わせる */
const tkey = (f: Finding) => f.targetKey ?? f.target;
/**
 * 証跡の突き合わせの形：証跡に出てくるホスト名（URL・CSP の配信元）の一覧。同じルール・ターゲットで別の配信元の指摘（E-08 の cdn-a と cdn-b、
 * E-07 の読み込み先）を別の指摘として突き合わせる（cdn-a を直して cdn-b が増えたことを「継続」の1行にしない）。
 * ホスト名だけを使うのは、証跡のほかの部分は画面のマスク（mask.ts・shownText.ts）で形が変わるため（マスクの規則を変えただけで、変わらない指摘を
 * 新規と解消にしにくくする）。ホスト名は「//」（スキームのあるものもないものも）のあとのものを取る。showText はふつうのホスト名を伏せないが、
 * ユーザー名らしいもの（後ろに @ が続く）とスキームのない大文字・決まっていない最上位ドメインのものは伏せるので、マスクに依存しないのはそれ以外
 * ホスト名はサイトにまとめない（ajax.googleapis.com に storage.googleapis.com のスクリプトが増えたことや、*.github.io・*.cloudfront.net の
 * 別の持ち主の配信元を、1つの「継続」にしない）。そのため、A-01② の転送先が同じサイトの別のサーバ（web-03 → web-07）に変わっただけでも
 * 「解消」と「新規」に分かれる（見逃すより安全なので、そのままにする）
 */
// 「//」の位置ごとに、その後ろの決まった長さだけを見る（正規表現で任意のスキームから探すと、長い英数字の並びで入力の長さの2乗の時間がかかる）
const AFTER_SLASHES = /^(?:[^/\s@]{0,256}@)?([a-z0-9.-]{1,253}\.[a-z]{2,63})/i;
const evidenceKey = (e: unknown): string => {
  const s = typeof e === 'string' ? e : '';
  const hosts = new Set<string>();
  for (let i = s.indexOf('//'); i >= 0; i = s.indexOf('//', i + 2)) {
    const m = AFTER_SLASHES.exec(s.slice(i + 2, i + 600));
    if (m) hosts.add(m[1].toLowerCase());
  }
  return [...hosts].sort().join(',');
};
const key = (f: Finding) => `${f.ruleId}\u0000${tkey(f)}\u0000${evidenceKey(f.evidence)}`;
/** HAR のターゲット（ラベル har-4 は記録し直すと別の応答を指すので、ラベルでは突き合わせない） */
const isHar = (f: Finding) => tkey(f).startsWith('HAR ');
/** キーがラベルだけ（top、以前の版の top#2）。同じラベルが複数あるときの「ラベル＋URL」（top https://…）は末尾が URL（ラベルは空白を含みうるので、空白の有無では見ない） */
const labelOnly = (f: Finding) => !isHar(f) && !/ (?:[a-z][\w+.-]*:\/\/|\/)\S*(?: #\d+)?$/i.test(tkey(f));
/** 「ラベル＋URL」の形のキー（同じラベルが複数あったときのキー。今回はラベルだけのキーになったものを、前回と URL で突き合わせる） */
const altKey = (f: Finding): string | undefined => (f.keyUrl && labelOnly(f) ? `${baseLabel(f.target)} ${f.keyUrl}` : undefined);
/** 指摘として残っているもの。例外を適用した指摘（suppressed）も、直ってはいないので含める */
const isOpen = (f: Finding) => f.status === 'fail' || f.status === 'suppressed';

/**
 * 指摘（fail・suppressed）を「ルールID×ターゲット×証跡のホスト」（key）で突き合わせる。
 * - 今回 suppressed：前回 fail（または前回なし）なら「例外登録」。前回も suppressed なら変化なしとして出さない
 * - 今回 fail：前回なしなら「新規」。前回 suppressed（例外の期限切れなど）は既知の指摘なので「継続」か「重要度の変化」
 * - 前回の指摘が今回ない場合、同じターゲットで同じ項目を判定していれば「解消」、判定していなければ「再診断していない」とする
 */
export function diff(before: Finding[], after: Finding[]): DiffRow[] {
  const prev = new Map(before.filter(isOpen).map(f => [key(f), f]));
  const now = new Map(after.filter(isOpen).map(f => [key(f), f]));
  // 判定済みの項目×ターゲット。同じ項目・ターゲットに na（入力不足の条件。横断・ホスト単位の条件を含む）があれば、確かめていない条件があるので
  // 判定済みにしない（T-09② だけを判定し①を確かめていないときに、前回の①を「解消」にしない）
  const ids = (f: Finding) => [`${f.item}\u0000${tkey(f)}`, ...(isHar(f) ? [] : [`${f.item}\u0000${f.target}`]), ...(altKey(f) ? [`${f.item}\u0000${altKey(f)}`] : [])];
  const naNow = new Set(after.filter(f => f.status === 'na' && !f.dedupedBy).flatMap(ids));
  // 機密でない応答だけで判定した合格（H-12 の limited）は、機密応答の条件（①）を確かめていないので判定済みに数えない。同じ項目・ターゲットに
  // 今回の fail があれば、途中で返すルール（H-01 は②で返し④を見ない）が前回の条件を確かめていないことがあるので、前回の別の条件を「解消」にしない
  const failNow = new Map<string, Set<string>>();
  for (const f of after.filter(isOpen)) for (const k of ids(f)) (failNow.get(k) ?? failNow.set(k, new Set()).get(k)!).add(f.ruleId);
  const evaluatedNow = new Set(after.filter(f => (f.status !== 'na' || f.dedupedBy) && !f.limited).flatMap(ids).filter(k => !naNow.has(k)));
  /** 同じ項目・ターゲットに、前回の条件より前の番号の条件の今回の fail があるか（同じ条件の別の配信元 cdn-a → cdn-b は、条件を確かめているので「解消」でよい） */
  const condOf = (r: string) => Number(r.split('.').pop()) || 0;
  const otherCondFail = (f: Finding) => ids(f).some(k => [...(failNow.get(k) ?? [])].some(r => r !== f.ruleId && condOf(r) > 0 && condOf(r) < condOf(f.ruleId)));
  const rows: DiffRow[] = [];
  const row = (kind: DiffKind, f: Finding, before?: Severity): DiffRow => ({ kind, ruleId: f.ruleId, item: f.item, condition: f.condition, title: f.title, target: f.target, severity: f.severity, before });
  // 1回目はキーで突き合わせる。2回目に、残ったものをラベルで突き合わせる：同じラベルの2つ目を足すと、1つ目のキーが「top」から
  // 「top https://…」に変わる。キーが top・top#2 の古い形式の結果とも、ラベルで突き合う
  const pairs = new Map<string, Finding | undefined>();
  const used = new Set<string>();
  for (const [k, f] of now) {
    if (prev.has(k)) { pairs.set(k, prev.get(k)); used.add(k); continue; }
    // 同じラベルのターゲットが減って、今回のキーがラベルだけ（top）になったもの：前回の「ラベル＋URL」（top https://a.example/）と URL で突き合わせる
    const a = altKey(f) ? `${f.ruleId}\u0000${altKey(f)}\u0000${evidenceKey(f.evidence)}` : undefined;
    if (a && prev.has(a) && !used.has(a)) { pairs.set(k, prev.get(a)); used.add(a); }
  }
  const byLabel = new Map<string, string>();
  const labelKey = (f: Finding) => `${f.ruleId}\u0000${f.target}\u0000${evidenceKey(f.evidence)}`;
  // ラベルで突き合わせるのは、前回のキーがラベルだけ（top・以前の版の top#2）のものだけ。前回が「ラベル＋URL」なら、URL の違う今回の同じラベルの
  // ターゲットと組にしない（a.example の前回の指摘を、b.example の今回の指摘と「継続」にしない）
  for (const [k, f] of prev) if (!used.has(k) && labelOnly(f)) { const l = labelKey(f); if (!byLabel.has(l)) byLabel.set(l, k); }
  for (const [k, f] of now) {
    if (pairs.has(k)) continue;
    const pk = isHar(f) ? undefined : byLabel.get(labelKey(f));
    if (pk && !used.has(pk)) { pairs.set(k, prev.get(pk)); used.add(pk); } else pairs.set(k, undefined);
  }
  for (const [k, f] of now) {
    const p = pairs.get(k);
    if (f.status === 'suppressed') { if (p?.status !== 'suppressed') rows.push(row('suppressed', f)); continue; }
    rows.push(!p ? row('new', f) : p.severity !== f.severity ? row('severity-changed', f, p.severity) : row('continuing', f));
  }
  // ラベルだけでの判定済みの照合も、前回のキーがラベルだけのものに限る（前回が top https://a.example/ で、今回は b.example の top だけを
  // 判定したときに「解消」にしない）
  for (const [k, f] of prev) if (!used.has(k)) rows.push(row(!otherCondFail(f) && (evaluatedNow.has(`${f.item}\u0000${tkey(f)}`) || (labelOnly(f) && evaluatedNow.has(`${f.item}\u0000${f.target}`))) ? 'resolved' : 'not-rechecked', f));
  const order: DiffKind[] = ['new', 'severity-changed', 'suppressed', 'resolved', 'not-rechecked', 'continuing'];
  return rows.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.ruleId.localeCompare(b.ruleId));
}

export function diffSummary(rows: DiffRow[]): Record<DiffKind, number> {
  const c: Record<DiffKind, number> = { new: 0, resolved: 0, continuing: 0, 'severity-changed': 0, 'not-rechecked': 0, suppressed: 0 };
  for (const r of rows) c[r.kind]++;
  return c;
}

/** 前回と今回でプロファイル（重要度・対象外の項目・セッションCookieの指定・自社の配信元。名前は除く）が違うか。違えば「重要度の変化」に設定の違いが混ざる */
export function profileDiffers(before?: Profile, now?: Profile): boolean {
  // 重要度はキーの順番をそろえる（キーの順番だけが違う同じ設定を「プロファイルが違う」と警告しない）
  const norm = (p?: Profile) => JSON.stringify({ severity: Object.entries(p?.severity ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)), exclude: [...(p?.exclude ?? [])].sort(), names: [...(p?.sessionCookieNames ?? [])].sort(), hours: p?.sessionMaxAgeHours ?? 24, origins: [...(p?.trustedScriptOrigins ?? [])].sort() });
  return norm(before) !== norm(now);
}
