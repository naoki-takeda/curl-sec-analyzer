// engine/run.ts：評価の順序（ツール設計2）
// ①ラベル対応表で項目を絞る → ②ターゲット単位 → ③ホスト単位 → ④横断（各スコープ内は dependsOn の順に並べてある）
// → ⑤条件単位の絞り込み（ターゲット単位の結果）→ ⑥API応答での重要度の引き下げ → ⑦例外の適用
import type { CrossContext, Finding, Profile, Rule, RuleContext, Suppression, Target } from '../model';
import { maskKey, maskText } from '../mask';
import { baseLabel, capturedAt, chainOf, finalResponse, hostOf, isHttps, isSensitive, ownChain, responseKind } from '../parser/target';
import { looksLikeSession, parseSetCookie, sentAuthOf } from '../parser/setCookie';
import { ALL_CROSS_RULES, HOST_RULES, TARGET_RULES } from '../rules/ruleset';
import { allowedItems } from './labels';
import { applySuppressions } from './suppress';
import { excludeItems, overrideSeverity, withProfile } from './profile';

const HTML_ONLY_ITEMS = new Set(['H-03', 'H-04', 'H-05', 'H-06', 'H-07', 'H-09', 'H-10', 'H-11', 'H-14']);

/**
 * 二重減点の除去（第0章 0.2「同じ事象は1つの項目でだけ減点」、評価順序の⑦）。
 * 同じターゲットで keep が fail のとき、drop の fail は数えない（status を na にし、dedupedBy に keep を残す）
 */
export const DEDUPE: { keep: string; drop: string; why: string }[] = [
  { keep: 'A-09.2', drop: 'H-08.1', why: 'API応答の nosniff なしは A-09② で数える' },
  { keep: 'A-09.3', drop: 'H-03.1', why: 'API応答の CSP なしは A-09③ で数える' },
  { keep: 'A-09.1', drop: 'H-13.2', why: 'JSON を text/html で返す件は A-09① で数える（第0章 0.2）' },
];
export function dedupe(fs: Finding[]): Finding[] {
  const fails = new Set(fs.filter(f => f.status === 'fail').map(f => `${f.ruleId}\u0000${f.target}`));
  return fs.map(f => {
    if (f.status !== 'fail') return f;
    const d = DEDUPE.find(x => x.drop === f.ruleId && fails.has(`${x.keep}\u0000${f.target}`));
    return d ? { ...f, status: 'na', dedupedBy: d.keep, recommendation: `${d.keep} として数える（${d.why}）` } : f;
  });
}

/** ホストごとにHSTSが有効か（C-01②③の依存先。ログイン関連ターゲットではH-01を実行しないため、ホスト単位で先に求める） */
export function hostHstsMap(targets: Target[]): Map<string, boolean> {
  const m = new Map<string, boolean>();
  for (const t of targets) {
    // apex は、apex 自身の応答（転送の最初のホップ）で見る（rules/headers.ts の H-01 と同じ）
    const host = hostOf(t); const f = baseLabel(t.label) === 'apex' ? ownChain(t)[0] : finalResponse(t);
    if (!host || isHttps(t) !== true || !f) continue;
    const age = Number(f.headers.get('strict-transport-security')?.[0]?.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
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
    for (const raw of t.responses.flatMap(r => r.headers.get('set-cookie') ?? [])) {
      const c = parseSetCookie(raw);
      if (!looksLikeSession(c, now)) continue;
      const ss = String(c.attrs.get('samesite') ?? '').toLowerCase();
      m.set(host, (m.get(host) ?? true) && (ss === 'lax' || ss === 'strict'));
    }
  }
  return m;
}

export interface HostMaps { hsts: Map<string, boolean>; sameSite: Map<string, boolean>; }

export function contextOf(t: Target, findings: Finding[], maps: HostMaps, profile?: Profile): RuleContext {
  const final = finalResponse(t); const host = hostOf(t);
  return { target: t, final, chain: chainOf(t), isHttps: isHttps(t), responseKind: responseKind(t, final),
           sensitive: isSensitive(t), hostHsts: host ? maps.hsts.get(host) : undefined,
           hostSessionSameSite: host ? maps.sameSite.get(host) : undefined, profile, now: capturedAt(t), findings };
}

export function crossContext(targets: Target[], findings: Finding[]): CrossContext {
  return {
    targets, findings,
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

export interface RunOptions { rules?: Rule[]; hostRules?: Rule[]; crossRules?: Rule[]; suppressions?: Suppression[]; today?: string; profile?: Profile; }

export function runAll(targets: Target[], opt: RunOptions = {}): Finding[] {
  // ⑦ プロファイルの除外 → 二重減点の除去 → 重要度の上書き → 例外
  return withProfile(opt.profile, () => {
    // 機密応答の推定（送ったセッションCookie）は、組織プロファイルのセッションCookieの名前で作り直す（パーサはプロファイルを知らない）
    for (const t of targets) if (t.sentCookieNames || t.sentAuthorization) t.sentAuth = sentAuthOf(!!t.sentAuthorization, t.sentCookieNames ?? []);
    const kept = excludeItems(evaluate(targets, opt), opt.profile);
    return applySuppressions(overrideSeverity(dedupe(kept), opt.profile), opt.suppressions ?? [], opt.today);
  });
}

/**
 * ルールを1つ実行する。診断対象の応答（細工した JWT のヘッダなど）でルールが例外を投げても、判定全体を止めずに、
 * そのルールだけを na にする（止めると、ほかのすべての結果が消える）
 */
function safeRun(rule: Rule, run: () => Finding[] | undefined, target: string): Finding[] {
  try { return run() ?? []; } catch {
    return [{ ruleId: `${rule.id}.na`, item: rule.id, title: rule.title, severity: 'info', status: 'na', target,
              evidence: 'ルールの実行中にエラーが発生した（入力の形式が想定外）', recommendation: '', references: rule.basis, score: 0 }];
  }
}

function evaluate(targets: Target[], opt: RunOptions): Finding[] {
  const { rules = TARGET_RULES, hostRules = HOST_RULES, crossRules = ALL_CROSS_RULES } = opt;
  const findings: Finding[] = [];
  const maps: HostMaps = { hsts: hostHstsMap(targets), sameSite: hostSameSiteMap(targets) };
  // ターゲットごとの文脈・許可・URL・キーは一度だけ作る（ルールごとに作り直すと、ルール数 × ターゲット数の時間がかかる）。
  // 文脈の findings は同じ配列を指すので、依存先のルールの結果も見える
  // 同じラベルが2つ以上あるラベル（付け直した top#2 があるもの）。付け直しの番号は入力の順番で決まるので、突き合わせには使わない
  const duplicated = new Set(targets.filter(t => /#\d+$/.test(t.label)).map(t => baseLabel(t.label)));
  const per = targets.map(t => {
    const url = t.url ? maskText(t.url) : undefined;
    // 差分・例外の突き合わせ：HAR のラベル（har-4 など）は記録し直すと番号が変わるため、メソッドとURLで突き合わせる。
    // URL は、マスクと切り離して URL の形だけで作る（maskKey。パラメータは名前だけ、パスのトークンは *）。マスクの一覧を変えてもキーは変わらない。
    // curl でも、同じラベルが複数あれば「元のラベル＋URL」にする（貼り付けの順番を変えると top と top#2 が入れ替わり、差分と例外がずれるため）
    const targetKey = t.meta.source === 'har' ? `HAR ${t.meta.method ?? 'GET'} ${t.url ? maskKey(t.url) : t.label}`
      : duplicated.has(baseLabel(t.label)) && t.url ? `${baseLabel(t.label)} ${maskKey(t.url)}` : t.label;
    return { t, url, targetKey, host: hostOf(t), allow: allowedItems(t.label), ctx: contextOf(t, findings, maps, opt.profile) };
  });
  // キーが重なるターゲットには、2つ目から「 #2」を付ける（重なったままだと、差分で片方の指摘が消え、例外が両方に効く）：
  // - curl の同じラベルで同じ URL（Cookie の有無を変えて2回採取したなど）
  // - HAR で、URL は違うがキーが同じになるもの（値を持たないパラメータの値だけが違う ?q=a と ?q=b）
  // HAR で URL まで同じもの（ポーリングで同じ URL を何度も取得した）には付けない。同じページなので、例外はすべてに効き、記録し直して回数が
  // 変わっても差分がずれない。番号は貼り付け・記録の順番で決まるので、付けるのは見分けられないときだけにする
  const seenKeys = new Map<string, number>(); const seenUrls = new Map<string, Set<string>>();
  for (const p of per) {
    if (p.targetKey === p.t.label) continue;
    if (p.t.meta.source === 'har') {
      const urls = seenUrls.get(p.targetKey) ?? new Set<string>(); seenUrls.set(p.targetKey, urls);
      if (urls.has(p.t.url ?? '')) continue;
      urls.add(p.t.url ?? '');
    }
    const n = (seenKeys.get(p.targetKey) ?? 0) + 1; seenKeys.set(p.targetKey, n);
    if (n > 1) p.targetKey = `${p.targetKey} #${n}`;
  }
  for (const rule of rules) {                                // ルールごとに全ターゲット（依存先の結果が先にそろう）
    for (const { t, url, targetKey, host, allow, ctx } of per) {
      if (!allow.allowsItem(rule.id)) continue;               // ①
      if (rule.appliesTo === 'html' && ctx.responseKind === 'other') continue;
      if (rule.appliesTo === 'api' && ctx.responseKind !== 'api') continue;
      for (const f of safeRun(rule, () => rule.run?.(ctx), t.label).filter(x => allow.allowsFinding(x))) {   // ②⑤
        const g: Finding = { ...f, url, host, targetKey, evidence: maskText(f.evidence) };
        if (ctx.responseKind === 'api' && HTML_ONLY_ITEMS.has(g.item) && g.status === 'fail') g.severity = 'info';   // ⑥
        findings.push(g);
      }
    }
  }
  const x = crossContext(targets, findings);
  for (const rule of [...hostRules, ...crossRules])           // ③④
    // 横断・ホスト単位のルールの na は、その条件だけが入力不足（ほかの条件はターゲット単位で判定しているかもしれない）。カバレッジで示すため印を付ける
    for (const f of safeRun(rule, () => rule.runCross?.(x), '-')) findings.push({ ...f, evidence: maskText(f.evidence), ...(f.status === 'na' ? { partial: true } : {}) });
  return findings;
}
