// engine/run.ts：評価の順序（ツール設計2）
// ①ラベル対応表で項目を絞る → ②ターゲット単位（⑤条件単位の絞り込みと⑥API応答での重要度の引き下げは、この結果に続けて行う）→ ③ホスト単位
// → ④横断 → ⑦組織プロファイルの除外 → ⑧二重減点の除去 → ⑨重要度の上書き → ⑩例外の適用（docs/design.md「評価の順序」）。
// ルールどうしは結果を参照しない。複数のルールが使う値（ホストの HSTS・SameSite）は先に求めて文脈に入れる
import type { CrossContext, Finding, Profile, Rule, RuleContext, Suppression, Target } from '../model';
import { showText } from '../shownText';
import { targetKeys, urlKey } from './targetKey';
import { baseLabel, capturedAt, chainOf, finalResponse, hostOf, isHttps, isRedirectWithLocation, isSensitive, responseKind, siteResponses } from '../parser/target';
import { looksLikeSession, parseSetCookie, sentAuthOf } from '../parser/setCookie';
import { parseHsts } from '../rules/util';
import { apexHop } from '../rules/headers';
import { ALL_CROSS_RULES, HOST_RULES, TARGET_RULES } from '../rules/ruleset';
import { allowedItems } from './labels';
import { applySuppressions } from './suppress';
import { excludeItems, overrideSeverity, withProfile } from './profile';

/** API 応答で重要度を「情報」に下げる HTML 向けの項目（第0章 0.3） */
const HTML_ONLY_ITEMS = new Set(['H-03', 'H-04', 'H-05', 'H-06', 'H-07', 'H-09', 'H-10', 'H-11', 'H-14']);

/**
 * 二重減点の除去（第0章 0.2「同じ事象は1つの項目でだけ減点」、評価順序の⑧）。
 * 同じターゲットで keep が fail のとき、drop の fail は数えない（status を na にし、dedupedBy に keep を残す）。
 * perCookie は Cookie ごとの指摘で、同じ Cookie（証跡の末尾の「（…）」の注記を除いて同じ）のときだけ数えない
 */
const DEDUPE: { keep: string; drop: string; why: string; perCookie?: boolean }[] = [
  { keep: 'A-09.2', drop: 'H-08.1', why: 'API応答の nosniff なしは A-09② で数える' },
  { keep: 'A-09.3', drop: 'H-03.1', why: 'API応答の CSP なしは A-09③ で数える' },
  { keep: 'A-09.3', drop: 'H-03.2', why: 'API応答の CSP なし（Report-Only だけ）は A-09③ で数える' },
  { keep: 'A-09.3', drop: 'H-03.3', why: 'API応答の CSP なし（効く指定がない）は A-09③ で数える' },
  { keep: 'A-09.1', drop: 'H-13.2', why: 'JSON を text/html で返す件は A-09① で数える（第0章 0.2）' },
  // http から -L で https に転送したターゲットの、http のホップが発行した Secure のない Cookie（C-01 は https のターゲットのすべてのホップを見る）
  { keep: 'C-01.1', drop: 'C-10.1', why: 'http のホップが発行した Secure のない Cookie は C-01 で数える', perCookie: true },
  { keep: 'C-01.2', drop: 'C-10.2', why: 'http のホップが発行した Secure のない Cookie は C-01 で数える', perCookie: true },
  { keep: 'C-01.3', drop: 'C-10.2', why: 'http のホップが発行した Secure のない Cookie は C-01 で数える', perCookie: true },
  // Secure のない __Host-・__Secure- と SameSite=None の Cookie は、ブラウザが拒否して保存しない（平文で送られることはない）。拒否される理由の項目で数える
  ...['C-01.1', 'C-01.2', 'C-01.3'].flatMap(drop => [
    { keep: 'C-06.2', drop, why: 'Secure のない __Host-・__Secure- の Cookie はブラウザが拒否する（C-06② で数える）', perCookie: true },
    { keep: 'C-03.4', drop, why: 'Secure のない SameSite=None の Cookie はブラウザが拒否する（C-03④ で数える）', perCookie: true }]),
];
/** perCookie の突き合わせのキー：Cookie の証跡（C-01②③の「（ホストのHSTSなし…）」の注記を除く） */
const cookieKey = (ev: string) => ev.replace(/（[^（）]*）$/, '');
function dedupe(fs: Finding[]): Finding[] {
  const fails = new Set(fs.filter(f => f.status === 'fail').flatMap(f => [`${f.ruleId}\u0000${f.target}`, `${f.ruleId}\u0000${f.target}\u0000${cookieKey(f.evidence)}`]));
  return fs.map(f => {
    if (f.status !== 'fail') return f;
    const d = DEDUPE.find(x => x.drop === f.ruleId && fails.has(`${x.keep}\u0000${f.target}${x.perCookie ? `\u0000${cookieKey(f.evidence)}` : ''}`));
    return d ? { ...f, status: 'na', dedupedBy: d.keep, recommendation: `${d.keep} として数える（${d.why}）` } : f;
  });
}

/** ホストごとにHSTSが有効か（C-01②③の依存先。ログイン関連ターゲットではH-01を実行しないため、ホスト単位で先に求める） */
function hostHstsMap(targets: Target[]): Map<string, boolean> {
  const m = new Map<string, boolean>();
  for (const t of targets) {
    // apex は H-01 と同じく apex 自身の https の応答で見る（http から -L で www へ転送した採取の www の HSTS を apex のものとしない）
    const host = hostOf(t); const f = baseLabel(t.label) === 'apex' ? apexHop(t) : finalResponse(t);
    if (!host || isHttps(t) !== true || !f) continue;
    const age = parseHsts(f.headers.get('strict-transport-security')?.[0]).maxAge;   // H-01 と同じ読み方（無効なヘッダは HSTS なし）
    m.set(host, (m.get(host) ?? false) || age > 0);
  }
  return m;
}

/**
 * ホストごとに、セッションCookieがすべて SameSite=Lax/Strict か（E-12 が使う。CSRFトークンのないフォームでも、これなら①にしない）。
 * セッションCookieが1つも見えないホストは入れない（分からない）
 */
export function hostSameSiteMap(targets: Target[]): Map<string, boolean> {
  const m = new Map<string, boolean>();
  for (const t of targets) {
    const host = hostOf(t); if (!host) continue;
    const now = capturedAt(t);
    // 同じサイトの応答だけ（-L で転送した先の IdP などの Cookie の SameSite で、対象のホストを決めない。C-01〜C-07 と同じ siteResponses）
    for (const raw of siteResponses(t).flatMap(r => r.headers.get('set-cookie') ?? [])) {
      const c = parseSetCookie(raw);
      if (!looksLikeSession(c, now)) continue;
      const ss = String(c.attrs.get('samesite') ?? '').toLowerCase();
      m.set(host, (m.get(host) ?? true) && (ss === 'lax' || ss === 'strict'));
    }
  }
  return m;
}

interface HostMaps { hsts: Map<string, boolean>; sameSite: Map<string, boolean>; }

function contextOf(t: Target, maps: HostMaps, profile?: Profile): RuleContext {
  const final = finalResponse(t); const host = hostOf(t);
  return { target: t, final, chain: chainOf(t), isHttps: isHttps(t), responseKind: responseKind(t, final),
           sensitive: isSensitive(t), hostHsts: host ? maps.hsts.get(host) : undefined,
           hostSessionSameSite: host ? maps.sameSite.get(host) : undefined, profile, now: capturedAt(t) };
}

function crossContext(targets: Target[]): CrossContext {
  return {
    targets,
    byLabel: l => targets.find(t => t.label === l),
    // 付け直したラベル（csp-sample-1#2 など）は除く。横断の判定には最初のものだけを使う（parser/target.ts の uniqueLabels）
    withPrefix: p => targets.filter(t => t.label.startsWith(p) && !/#\d+$/.test(t.label)),
    byHost: () => {
      const m = new Map<string, Target[]>();
      for (const t of targets) { const h = hostOf(t); if (!h) continue; const list = m.get(h); if (list) list.push(t); else m.set(h, [t]); }   // 配列をコピーしない（ターゲット数の2乗の時間になる）
      return m;
    },
  };
}

interface RunOptions { rules?: Rule[]; hostRules?: Rule[]; crossRules?: Rule[]; suppressions?: Suppression[]; profile?: Profile; }

export function runAll(targets: Target[], opt: RunOptions = {}): Finding[] {
  return withProfile(opt.profile, () => {
    // 機密応答の推定（送ったセッションCookie）は、組織プロファイルのセッションCookieの名前で作り直す（パーサはプロファイルを知らない）
    for (const t of targets) if (t.sentCookieNames || t.sentAuthorization) t.sentAuth = sentAuthOf(!!t.sentAuthorization, t.sentCookieNames ?? []);
    const kept = excludeItems(evaluate(targets, opt), opt.profile);
    return applySuppressions(overrideSeverity(dedupe(kept), opt.profile), opt.suppressions ?? []);
  });
}

/**
 * ルールを1つ実行する。診断対象の応答（細工した JWT のヘッダなど）でルールが例外を投げても、判定全体を止めずに、
 * そのルールだけを na にする（止めると、ほかのすべての結果が消える）
 */
function safeRun(rule: Rule, run: () => Finding[] | undefined, target: string): Finding[] {
  try { return run() ?? []; } catch {
    return [{ ruleId: `${rule.id}.na`, item: rule.id, title: rule.title, severity: 'info', status: 'na', target,
              evidence: 'ルールの実行中にエラーが発生した（入力の形式が想定外）', recommendation: '', references: rule.basis }];
  }
}

/** ラベルで許可していない条件の指摘だけが出たとき、合格を残してよいルール（すべての条件を一度に判定するもの） */
const SYNTH_OK = new Set(['T-05', 'A-01', 'E-04']);
function evaluate(targets: Target[], opt: RunOptions): Finding[] {
  const { rules = TARGET_RULES, hostRules = HOST_RULES, crossRules = ALL_CROSS_RULES } = opt;
  const findings: Finding[] = [];
  const maps: HostMaps = { hsts: hostHstsMap(targets), sameSite: hostSameSiteMap(targets) };
  // ターゲットごとの文脈・許可・URL・キーは一度だけ作る（ルール数 × ターゲット数の時間をかけない）。
  // 差分・例外の突き合わせのキーは、マスクと切り離して engine/targetKey.ts で作る
  const keys = targetKeys(targets);
  // showText は重い（マスクと許可リストを繰り返す）。証跡・推奨・URL は同じ文字列が多い（数万件の指摘でも数千種類）ので、結果を使い回す
  const cache = new Map<string, string>();
  const shown = (s: string) => { let v = cache.get(s); if (v === undefined) cache.set(s, v = showText(s)); return v; };
  const per = targets.map((t, i) => ({ t, url: t.url ? shown(t.url) : undefined, keyUrl: t.url ? urlKey(t.url) : undefined, targetKey: keys[i], host: hostOf(t), allow: allowedItems(t.label),
                                       ctx: contextOf(t, maps, opt.profile) }));
  for (const rule of rules) {                                // ルールごとに全ターゲット（出力の順序）
    for (const { t, url, keyUrl, targetKey, host, allow, ctx } of per) {
      if (!allow.allowsItem(rule.id)) continue;               // ①
      if (rule.appliesTo === 'html' && ctx.responseKind === 'other') continue;
      // Location のある 3xx の本文（nginx の 301 の HTML、Rails の「You are being redirected」）は、ブラウザが表示しないので HTML の項目
      // （ヘッダ・描画。H-03①・H-06①・H-14① など）を判定しない。本文の秘密（E-09）は利用者に届くので判定する（H-08・H-13 も転送を除いている）
      if (rule.appliesTo === 'html' && rule.id !== 'E-09' && isRedirectWithLocation(ctx.final)) continue;
      if (rule.appliesTo === 'api' && ctx.responseKind !== 'api') continue;
      const raw = safeRun(rule, () => rule.run?.(ctx), t.label);
      const kept = raw.filter(x => allow.allowsFinding(x));
      // ラベルで許可していない条件の指摘（一般ラベルの T-05①）だけが出た：許可した条件（T-05②）は判定して指摘がなかったので、合格として残す
      // （何も残さないと、すでにあるラベルを「必要なラベル」と案内してしまう）。合成するのは、すべての条件を一度に判定するルールだけ
      // （条件ごとに途中で返すルール（E-13）では、判定していない条件まで合格になる）
      if (!kept.length && SYNTH_OK.has(rule.id) && raw.some(x => x.status === 'fail'))
        kept.push({ ...raw[0], ruleId: `${rule.id}.ok`, condition: undefined, severity: 'info', status: 'pass', evidence: 'このラベルで判定する条件には指摘なし', recommendation: '' });
      for (const f of kept) {   // ②⑤
        // 推奨対応も許可リストを通す（C-09 の推奨対応には入力の Cookie の名前が入るので、証跡で伏せた名前を画面・エクスポートに出さない）。
        // 決まった文言は変わらないことを tests/regression/review26.test.ts で確かめる
        const g: Finding = { ...f, url, keyUrl, host, targetKey, evidence: shown(f.evidence), recommendation: shown(f.recommendation) };
        if (ctx.responseKind === 'api' && HTML_ONLY_ITEMS.has(g.item) && g.status === 'fail') { g.severity = 'info'; g.apiInfo = true; }   // ⑥
        findings.push(g);
      }
    }
  }
  const x = crossContext(targets);
  for (const rule of [...hostRules, ...crossRules])           // ③④
    // 横断・ホスト単位のルールの na は、その条件だけが入力不足（ほかの条件はターゲット単位で判定しているかもしれない）。カバレッジで示すため印を付ける
    for (const f of safeRun(rule, () => rule.runCross?.(x), '-')) findings.push({ ...f, evidence: shown(f.evidence), recommendation: shown(f.recommendation), ...(f.status === 'na' ? { partial: true } : {}) });
  return findings;
}
