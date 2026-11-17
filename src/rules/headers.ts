// rules/headers.ts：第1章 HTTPレスポンスヘッダ（H-01〜H-17。H-02③・H-04⑤は横断ルール rules/cross.ts）
import type { Rule, RuleContext } from '../model';
import { LOGOUT_FAILED_REC, NO_BODY_REC, cspPolicies, header, hstsDirective, isNosniff, isStaticResource, mk, parseCsp, parseHsts, sensitiveUnlessStatic, splitPolicies } from './util';
import { clip, maskValue } from '../mask';
import { baseLabel, firstStatus, logoutFailed, ownChain, siteResponses } from '../parser/target';
import { htmlBody, metaCspPolicies, mixedContent } from './html';
import { type CspIssue, EVALUATOR_ERROR, evaluateCsp, issueEvidence } from './csp';

/**
 * 判定に使う HSTS ヘッダ。apex は、apex 自身の応答（転送の最初のホップ）で見る。
 * -L や HAR で www への転送をたどった最後の応答は www のもの（H-02「apex自身もHSTSを返す」）
 */
const hstsOf = (ctx: RuleContext) => (baseLabel(ctx.target.label) === 'apex' ? ownChain(ctx.target)[0] : ctx.final)?.headers.get('strict-transport-security')?.[0];

export const hsts: Rule = { id: 'H-01', title: 'Strict-Transport-Security', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS', 'MDN HTTP Observatory'],
  run(ctx) {
    if (ctx.isHttps === false) return [];               // http のターゲットは適用外（T-04 で評価）
    if (ctx.isHttps === undefined || !ctx.final) return [mk(hsts, ctx, 'na', 'info', 'na', 'HTTPSかどうか判定できない', '#TARGET に url= を付ける')];
    const v = hstsOf(ctx);
    const rec = 'Strict-Transport-Security: max-age=63072000; includeSubDomains';
    if (!v) return [mk(hsts, ctx, 1, 'high', 'fail', '(ヘッダなし)', rec, { obsId: 'hsts-not-implemented', score: -20 })];
    const parsed = parseHsts(v); const age = parsed.maxAge;
    if (!parsed.valid) return [mk(hsts, ctx, 3, 'high', 'fail', `${v}（構文の誤り・ディレクティブの重複。ブラウザはこのヘッダを無視する）`, rec, { obsId: 'hsts-header-invalid', score: -20 })];
    // max-age=0 は、ブラウザに HSTS の記録を消させる指定（RFC 6797 6.1.1）。ヘッダがないのと同じなので①にする（②の「短い」ではない）
    if (age === 0) return [mk(hsts, ctx, 1, 'high', 'fail', `${v}（max-age=0 は HSTS を解除する指定）`, rec, { obsId: 'hsts-not-implemented', score: -20 })];
    // ②の基準は ASVS 5.0.0 3.4.1 に合わせて1年（31536000秒）。obsId は Observatory の区切り（6か月）のまま付ける
    const obs = age < 15768000 ? { obsId: 'hsts-implemented-max-age-less-than-six-months', score: -10 } : { obsId: 'hsts-implemented-max-age-at-least-six-months' };
    if (age < 31536000) return [mk(hsts, ctx, 2, 'medium', 'fail', v, rec, obs)];
    // ④ ASVS 5.0.0 3.4.1 は L2 以上で includeSubDomains を求める
    if (!hstsDirective(v, 'includesubdomains')) return [mk(hsts, ctx, 4, 'low', 'fail', v, rec, obs)];
    return [mk(hsts, ctx, 'ok', 'info', 'pass', v, '', obs)];
  } };

export const cspPresence: Rule = { id: 'H-03', title: 'CSP（存在・強制）', appliesTo: 'html', scope: 'target',
  basis: ['OWASP CSP CS', 'MDN HTTP Observatory'],
  run(ctx) {
    if (!ctx.final) return [mk(cspPresence, ctx, 'na', 'info', 'na', '応答がない', '')];
    const rawEnforce = header(ctx, 'content-security-policy'); const enforce = cspPolicies(ctx);
    const ro = header(ctx, 'content-security-policy-report-only');
    const rec = "Content-Security-Policy: default-src 'self'; script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
    // ヘッダがなくても <meta http-equiv> の CSP があれば、ブラウザは強制するので①②にしない（frame-ancestors などは meta では効かないことを証跡に書く）
    const meta = rawEnforce.length ? [] : metaCspPolicies(ctx);
    if (meta.length) return [mk(cspPresence, ctx, 'ok', 'info', 'pass', `<meta http-equiv> の CSP: ${meta.join(' / ')}（frame-ancestors・report-uri・sandbox は meta では効かない）`, '')];
    // ヘッダがなく本文も採取していない（-D - -o /dev/null、-v）なら、<meta> の CSP があるかが分からないので①にしない（同じ URL を -i で採取すると
    // meta の CSP で合格になり、採取の方法で結果が食い違った）
    // HTML の応答だけ（JSON の API の応答には本文があっても htmlBody は空。API は①を情報に下げ、A-09③ として数える（DEDUPE））
    if (!rawEnforce.length && !ro.length && ctx.responseKind === 'html' && !htmlBody(ctx)) return [mk(cspPresence, ctx, 'na', 'info', 'na', 'CSP のヘッダなし（本文を採取していないので、<meta> の CSP があるかは分からない）', NO_BODY_REC)];
    if (!rawEnforce.length && !ro.length) return [mk(cspPresence, ctx, 1, 'high', 'fail', '(ヘッダなし)', rec)];
    if (!rawEnforce.length) return [mk(cspPresence, ctx, 2, 'medium', 'fail', `Report-Onlyのみ: ${ro[0]}`, '確認できたら強制モードの Content-Security-Policy に切り替える')];
    // ③は、ヘッダ値のどのポリシーにもディレクティブがないとき。カンマのあとのかけら（report-uri の URL の中のカンマなど）だけが
    // 読めなくても、前のポリシーは効いているので③にしない（構文の誤りは H-07④）
    if (rawEnforce.some(v => !splitPolicies([v]).some(p => parseCsp(p).size > 0))) return [mk(cspPresence, ctx, 3, 'high', 'fail', rawEnforce.join(' / '), rec)];
    return [mk(cspPresence, ctx, 'ok', 'info', 'pass', enforce.join(' / '), '')];
  } };

export const clickjacking: Rule = { id: 'H-06', title: 'クリックジャッキング対策（frame-ancestors・X-Frame-Options）', appliesTo: 'html', scope: 'target',
  basis: ['MDN', 'OWASP Secure Headers'],
  run(ctx) {
    if (!ctx.final) return [mk(clickjacking, ctx, 'na', 'info', 'na', '応答がない', '')];
    // 複数のポリシーは、すべてを満たすものだけが許される（制限が重なる）。frame-ancestors を指定したポリシーのうち、
    // 1つでも広くないものがあれば、埋め込みはそれで制限される（* のポリシーと 'none' のポリシーが両方あれば 'none'）
    const fas = cspPolicies(ctx).map(parseCsp).filter(m => m.has('frame-ancestors')).map(m => m.get('frame-ancestors')!);
    // frame-ancestors は X-Frame-Options より優先されるので、広い指定（*、https: などのスキームだけ、*.example.com）は④にする
    // ホストが * だけのもの（https://*、*:443、https://*:*）も、どのサイトにも埋め込みを許すので広い指定とする
    const isBroad = (fa: string[]) => fa.some(s => s === '*' || /^[a-z][\w+.-]*:$/i.test(s) || /^(?:[a-z][\w+.-]*:\/\/)?\*(?:\.|:(?:\d+|\*)\/?$|\/?$)/i.test(s));
    const strict = fas.find(fa => !isBroad(fa));
    if (fas.length && !strict) return [mk(clickjacking, ctx, 4, 'medium', 'fail', fas.map(fa => `frame-ancestors ${fa.join(' ')}`).join(' / '), "frame-ancestors は 'none' か 'self'（埋め込みを許す相手は個別のオリジン）にする")];
    if (strict) return [mk(clickjacking, ctx, 'ok', 'info', 'pass', `frame-ancestors ${strict.join(' ')}`, '')];
    const rec = "Content-Security-Policy: frame-ancestors 'none'（旧ブラウザ向けに X-Frame-Options: DENY も併用）";
    // X-Frame-Options は HTML Standard の手順で読む：すべての値をカンマで分けて小文字の集合にし、2つ以上で deny・sameorigin・allowall の
    // どれかを含めば埋め込みを拒否する。1つなら deny・sameorigin だけが有効で、それ以外（ALLOWALL、綴りの誤りなど）はブラウザが無視する
    const raw = header(ctx, 'x-frame-options').join(', ').trim();
    const xfo = new Set(raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
    if (!xfo.size) return [mk(clickjacking, ctx, 1, 'medium', 'fail', '(frame-ancestors も X-Frame-Options もない)', rec)];
    const one = [...xfo][0];
    const blocks = xfo.size > 1 ? [...xfo].some(s => ['deny', 'sameorigin', 'allowall'].includes(s)) : one === 'deny' || one === 'sameorigin';
    if (blocks) return [mk(clickjacking, ctx, 3, 'info', 'fail', `X-Frame-Options: ${raw}（frame-ancestors なし）`, rec)];
    if (xfo.size === 1 && /^allow-from\b/.test(one)) return [mk(clickjacking, ctx, 2, 'medium', 'fail', `X-Frame-Options: ${raw}`, rec)];
    return [mk(clickjacking, ctx, 1, 'medium', 'fail', `X-Frame-Options: ${raw}（不正な値。ブラウザは無視する）`, rec)];
  } };

// 本文のない応答（204 No Content、304 Not Modified）。キャッシュに残す内容も、ほかのオリジンに読ませる内容もないので、H-12・H-11・H-08 の対象外（MIME スニッフィングする本文もない）
// （ログインした HAR では、ビーコンや XHR の 204 のたびに H-12①（高）が出た。H-13 も同じ応答を除いている）
const NO_CONTENT_REC = '本文のある応答（200 など）で採取する（204・304 は対象外）';
const NO_CONTENT = (ctx: RuleContext) => ctx.final?.status === 204 || ctx.final?.status === 304;
/** 経験的にキャッシュしてよいステータス（RFC 9110 15.1。これ以外は、鮮度の指定がなければキャッシュに保存されない） */
const HEURISTIC_CACHEABLE = new Set([200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501]);
export const nosniff: Rule = { id: 'H-08', title: 'X-Content-Type-Options', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS'],
  run(ctx) {
    if (!ctx.final) return [mk(nosniff, ctx, 'na', 'info', 'na', '応答がない', '')];
    // 本文のない転送（Location のある 3xx）と Content-Length: 0 の応答も、スニッフィングする本文がない（ブラウザは 3xx の本文を表示しない）
    const empty = NO_CONTENT(ctx) || (ctx.final.status >= 300 && ctx.final.status < 400 && ctx.final.headers.has('location')) || header(ctx, 'content-length').some(x => /^\s*0\s*$/.test(x));
    if (empty) return [mk(nosniff, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（本文のない応答）`, NO_CONTENT_REC)];
    const v = header(ctx, 'x-content-type-options').join(', ');
    if (isNosniff(ctx)) return [mk(nosniff, ctx, 'ok', 'info', 'pass', v, '')];
    return [mk(nosniff, ctx, 1, 'medium', 'fail', v || '(ヘッダなし)', 'X-Content-Type-Options: nosniff')];
  } };

export const cacheControl: Rule = { id: 'H-12', title: 'Cache-Control', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS', 'OWASP REST Security CS'],
  run(ctx) {
    if (!ctx.final) return [mk(cacheControl, ctx, 'na', 'info', 'na', '応答がない', '')];
    if (NO_CONTENT(ctx)) return [mk(cacheControl, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（本文のない応答）`, NO_CONTENT_REC)];
    const cc = header(ctx, 'cache-control').join(', ').toLowerCase();
    const dirs = new Set(cc.split(',').map(s => s.trim().split('=')[0]).filter(Boolean));
    const ev = cc || (header(ctx, 'pragma').length ? `(Cache-Controlなし、Pragma: ${header(ctx, 'pragma')[0]})` : '(ヘッダなし)');
    const isStatic = isStaticResource(ctx);
    if (dirs.has('no-store')) return [mk(cacheControl, ctx, 'ok', 'info', 'pass', cc, '')];
    // 経験的にキャッシュしてよいステータスでないもの（302・303・307 などの転送、401・403・500）は、鮮度の指定（max-age・s-maxage・public・Expires）がなければキャッシュに保存されない（RFC 9111 4.2.2。
    // 経験的にキャッシュしてよいステータスではない）。ログイン後の 302 で H-12①（高）を出していた
    // 401・403・500 なども同じ（経験的にキャッシュしてよいのは 200・203・204・206・300・301・308・404・405・410・414・501 だけ）
    // private も保存を許す指定（私的キャッシュは private があれば 201・403 も保存できる）
    // ただし Location のある 3xx では private を数えない（ASP.NET は既定ですべての応答に private を付け、転送のたびに②を出した）
    const redirect = ctx.final.status >= 300 && ctx.final.status < 400 && ctx.final.headers.has('location');
    if (!HEURISTIC_CACHEABLE.has(ctx.final.status) && !['max-age', 's-maxage', 'public', ...(redirect ? [] : ['private'])].some(d => dirs.has(d)) && !header(ctx, 'expires').length)
      return [mk(cacheControl, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（鮮度の指定がなく、キャッシュされない応答）`, '機密データを返す 200 の応答（認証後ページなど）で採取する')];
    const limited = (f: ReturnType<typeof mk>) => ({ ...f, limited: true });
    // 静的リソース・公開ファイルは、sensitive=1 を明示したときだけ機密応答として扱う（rules/util.ts の sensitiveUnlessStatic）
    const sensitive = sensitiveUnlessStatic(ctx);
    if (sensitive === undefined) {
      if (isStatic && !cc) return [limited(mk(cacheControl, ctx, 3, 'info', 'fail', ev, '静的リソースにもキャッシュ方針（max-age など）を明示する'))];
      if (isStatic) return [limited(mk(cacheControl, ctx, 'ok', 'info', 'pass', ev, ''))];
      return [mk(cacheControl, ctx, 'na', 'info', 'na', `機密応答かどうか分からない（${ev}）`, '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける')];
    }
    if (!sensitive) {
      if (isStatic && !cc) return [limited(mk(cacheControl, ctx, 3, 'info', 'fail', ev, '静的リソースにもキャッシュ方針（max-age など）を明示する'))];
      return [limited(mk(cacheControl, ctx, 'ok', 'info', 'pass', ev || '(機密でない応答)', ''))];
    }
    if (dirs.has('private') && !dirs.has('public')) return [mk(cacheControl, ctx, 2, 'medium', 'fail', ev, 'Cache-Control: no-store')];
    return [mk(cacheControl, ctx, 1, 'high', 'fail', ev, 'Cache-Control: no-store')];
  } };

// ---- 以下 MVP で追加（H-02、H-04、H-05、H-07、H-09〜H-11、H-13〜H-17） ----

// ヘッダの CSP と、HTML の <meta> の CSP（ブラウザは両方を強制する）。H-06 の frame-ancestors はヘッダだけ（cspPolicies）で見る
const enforcedPolicies = (ctx: RuleContext) => [...cspPolicies(ctx), ...metaCspPolicies(ctx)].map(parseCsp).filter(p => p.size > 0);

export const hstsPreload: Rule = { id: 'H-02', title: 'HSTS preload', appliesTo: 'any', scope: 'target',
  basis: ['hstspreload.org', 'MDN'],
  run(ctx) {
    if (ctx.isHttps === false) return [];
    const v = hstsOf(ctx);
    if (!ctx.final || !v) return [mk(hstsPreload, ctx, 'na', 'info', 'na', 'HSTSがない（H-01で判定）', '')];
    // 構文の誤ったヘッダ（カンマ区切りの max-age=…, includeSubDomains, preload など）はブラウザが無視する。H-01③ で指摘するので、
    // ここで「preload なし」とは言わない（preload と書いてあるのに「なし」の証跡になった）
    if (!parseHsts(v).valid) return [mk(hstsPreload, ctx, 'na', 'info', 'na', `${v}（HSTSの構文の誤り。H-01③で判定）`, '')];
    const age = parseHsts(v).maxAge;
    if (!hstsDirective(v, 'preload')) return [mk(hstsPreload, ctx, 2, 'info', 'fail', v, 'preload リストへの登録を検討する（max-age 31536000 以上＋includeSubDomains＋preload）')];
    if (age < 31536000 || !hstsDirective(v, 'includesubdomains')) return [mk(hstsPreload, ctx, 1, 'low', 'fail', v, 'preload には max-age 31536000 以上と includeSubDomains が必要')];
    return [mk(hstsPreload, ctx, 'ok', 'info', 'pass', v, '')];
  } };

/**
 * 複数の強制モードのポリシーは、すべてを満たすものだけが許される（制限が重なる）。あるポリシーにないディレクティブ（MISSING_DIRECTIVES）や、
 * default-src へのフォールバックの指摘は、別のポリシーがそのディレクティブ（スクリプト・object は default-src でも可）を指定していれば出さない。
 * 例：厳しいポリシーとは別に frame-ancestors だけのヘッダがあっても、H-04②・H-05① にしない。
 * ただし、その別のポリシーが同じ項目・条件の指摘を持つ（同じくらい緩い。アプリとプロキシが同じヘッダを2回付けた場合など）なら、制限にならないので出す
 */
interface Policy { dirs: Map<string, string[]>; issues: CspIssue[]; }
// H-04 の指摘（unsafe-inline・広い指定・unsafe-eval・JSONP のホスト）も同じ考え方で見る。別のポリシーがスクリプトを制限していて
// （script-src か default-src があり）、同じ条件の指摘がなければ、ブラウザはそちらで止める（default-src 'self' のポリシーと
// script-src 'unsafe-inline' https: のポリシーの組で、H-04①②（高）を出していた）
function coveredByOther(i: CspIssue, others: Policy[]): boolean {
  if (i.item !== 'H-04' && i.type !== 'MISSING_DIRECTIVES' && i.directive !== 'default-src') return false;
  const d = i.item === 'H-04' ? 'script-src' : i.item === 'H-05' ? (i.condition === 1 ? 'object-src' : 'base-uri') : undefined;
  return !!d && others.some(p => (p.dirs.has(d) || (d !== 'base-uri' && p.dirs.has('default-src')))
    && !p.issues.some(x => (x.item === i.item && x.condition === i.condition) || x.type === EVALUATOR_ERROR));
}

/** 強制モードの各ポリシーを csp_evaluator で評価する（ポリシーごとのディレクティブと指摘） */
// ヘッダの CSP と <meta> の CSP（enforcedPolicies と同じ）を csp_evaluator で見る
const policiesOf = (ctx: RuleContext): Policy[] => [...cspPolicies(ctx), ...metaCspPolicies(ctx)].map(v => ({ dirs: parseCsp(v), issues: evaluateCsp(v) })).filter(p => p.dirs.size > 0);

/** 指定した項目の指摘だけを返す（同じ条件・ディレクティブ・値は1件にまとめる） */
function cspIssues(ctx: RuleContext, item: CspIssue['item']): CspIssue[] {
  const seen = new Set<string>(); const out: CspIssue[] = [];
  const ps = policiesOf(ctx);
  ps.forEach((p, n) => {
    const others = ps.filter((_, m) => m !== n);
    for (const i of p.issues) {
      const k = `${i.item}|${i.condition}|${i.directive}|${i.value ?? ''}|${i.type}`;
      if (i.item === item && !seen.has(k) && !coveredByOther(i, others)) { seen.add(k); out.push(i); }
    }
  });
  return out;
}
/** csp_evaluator で評価できなかったポリシーがあるか（H-04 を合格にしない） */
const unevaluated = (ctx: RuleContext) => policiesOf(ctx).some(p => p.issues.some(i => i.type === EVALUATOR_ERROR));
const CSP_REC: Record<number, string> = {
  1: "'unsafe-inline' をやめ、nonce か hash を使う",
  2: "* や https: などの広い指定をやめ、nonce＋'strict-dynamic' にする",
  3: "'unsafe-eval' を使わないようにする",
  4: 'JSONPを提供するホストを許可リストから外すか、nonce＋strict-dynamic にする',
  6: 'csp_evaluator の指摘に従って修正する（nonce は十分な長さの乱数にする、IPアドレスでの許可や unsafe-hashes を使わない など）',
};

export const cspScript: Rule = { id: 'H-04', title: 'CSP：script-src', appliesTo: 'html', scope: 'target',
  basis: ['Google csp_evaluator', 'OWASP CSP CS'],
  run(ctx) {
    if (!enforcedPolicies(ctx).length) return [mk(cspScript, ctx, 'na', 'info', 'na', '強制モードのCSPがない（H-03で判定）', '')];
    const issues = cspIssues(ctx, 'H-04');
    if (!issues.length && unevaluated(ctx)) return [mk(cspScript, ctx, 'na', 'info', 'na', 'csp_evaluator で解析できないポリシーがある（H-07④）', '')];
    if (!issues.length) return [mk(cspScript, ctx, 'ok', 'info', 'pass', enforcedPolicies(ctx).filter(p => p.has('script-src') || p.has('default-src')).map(p => `script-src ${(p.get('script-src') ?? p.get('default-src') ?? []).join(' ')}`).join(' / '), '')];
    return issues.map(i => mk(cspScript, ctx, i.condition, i.severity, 'fail', issueEvidence(i), CSP_REC[i.condition]));
  } };

export const cspObjectBase: Rule = { id: 'H-05', title: 'CSP：object-src・base-uri', appliesTo: 'html', scope: 'target',
  basis: ['Chrome Lighthouse csp-xss', 'Google csp_evaluator'],
  run(ctx) {
    const ps = enforcedPolicies(ctx);
    if (!ps.length) return [mk(cspObjectBase, ctx, 'na', 'info', 'na', '強制モードのCSPがない（H-03で判定）', '')];
    const ev = cspIssues(ctx, 'H-05');
    const out = [];
    // ①：object-src も default-src もない（自前の判定）、または csp_evaluator が object-src の問題を指摘
    const obj = ev.find(i => i.condition === 1);
    if (!ps.some(p => p.has('object-src') || p.has('default-src'))) out.push(mk(cspObjectBase, ctx, 1, 'medium', 'fail', 'object-src も default-src もない', "object-src 'none'"));
    else if (obj) out.push(mk(cspObjectBase, ctx, 1, 'medium', 'fail', issueEvidence(obj), "object-src 'none'"));
    // ②：base-uri は default-src にフォールバックしないため、常に確認する
    if (!ps.some(p => p.has('base-uri'))) out.push(mk(cspObjectBase, ctx, 2, 'medium', 'fail', 'base-uri がない（default-src にはフォールバックしない）', "base-uri 'none'（または 'self'）"));
    return out.length ? out : [mk(cspObjectBase, ctx, 'ok', 'info', 'pass', 'object-src・base-uri あり', '')];
  } };

export const cspDeprecated: Rule = { id: 'H-07', title: 'CSP：非推奨ディレクティブ・混在コンテンツ・構文', appliesTo: 'html', scope: 'target',
  basis: ['MDN', 'Google csp_evaluator'],
  run(ctx) {
    const ps = enforcedPolicies(ctx);
    if (!ps.length) return [mk(cspDeprecated, ctx, 'na', 'info', 'na', '強制モードのCSPがない（H-03で判定）', '')];
    const out = [];
    const ev = cspIssues(ctx, 'H-07');
    const old = [...new Set([...['block-all-mixed-content', 'referrer', 'plugin-types'].filter(d => ps.some(p => p.has(d))), ...ev.filter(i => i.condition === 1).map(i => i.directive)])];
    if (old.length) out.push(mk(cspDeprecated, ctx, 1, 'low', 'fail', old.join(', '), '非推奨のディレクティブを削除する'));
    if (ps.some(p => p.has('report-uri')) && !ps.some(p => p.has('report-to'))) out.push(mk(cspDeprecated, ctx, 2, 'info', 'fail', 'report-uri のみ', 'report-to（Reporting API）を併記する'));
    // ③は E-07 と同じ判定で混在コンテンツを見る。http のページには「混在」がなく、upgrade-insecure-requests も要らない（E-07 と同じく適用外）
    const html = ctx.isHttps === false ? undefined : htmlBody(ctx);
    if (html && !ps.some(p => p.has('upgrade-insecure-requests'))) {
      const m = mixedContent(html);
      if (m.active.length + m.passive.length) out.push(mk(cspDeprecated, ctx, 3, 'low', 'fail', `混在コンテンツ${m.active.length + m.passive.length}件、upgrade-insecure-requests なし`, 'http:// の資源を直すまで upgrade-insecure-requests を付ける'));
    }
    for (const i of ev.filter(x => x.condition === 4)) out.push(mk(cspDeprecated, ctx, 4, 'low', 'fail', issueEvidence(i), 'CSPの構文の誤り（不明なディレクティブ、キーワードの引用符、セミコロン、nonceの文字種）を直す。誤った指定はブラウザに無視される'));
    return out.length ? out : [mk(cspDeprecated, ctx, 'ok', 'info', 'pass', '非推奨ディレクティブ・構文の誤りなし', '')];
  } };

const RP_GOOD = ['strict-origin-when-cross-origin', 'strict-origin', 'same-origin', 'no-referrer'];
const RP_WEAK = ['no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin'];
export const referrerPolicy: Rule = { id: 'H-09', title: 'Referrer-Policy', appliesTo: 'html', scope: 'target',
  basis: ['MDN', 'OWASP HTTP Headers CS'],
  run(ctx) {
    if (!ctx.final) return [mk(referrerPolicy, ctx, 'na', 'info', 'na', '応答がない', '')];
    const raw = header(ctx, 'referrer-policy').join(',');
    if (!raw) return [mk(referrerPolicy, ctx, 3, 'info', 'fail', '(ヘッダなし。ブラウザの既定は strict-origin-when-cross-origin)', 'Referrer-Policy: strict-origin-when-cross-origin')];
    const known = [...RP_GOOD, ...RP_WEAK, 'unsafe-url'];
    const toks = raw.toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const eff = toks.filter(t => known.includes(t)).at(-1);         // 認識できる最後の値が有効
    if (!eff) return [mk(referrerPolicy, ctx, 4, 'low', 'fail', raw, 'Referrer-Policy: strict-origin-when-cross-origin')];
    if (eff === 'unsafe-url') return [mk(referrerPolicy, ctx, 1, 'medium', 'fail', raw, 'Referrer-Policy: strict-origin-when-cross-origin')];
    if (RP_WEAK.includes(eff)) return [mk(referrerPolicy, ctx, 2, 'low', 'fail', raw, 'Referrer-Policy: strict-origin-when-cross-origin')];
    return [mk(referrerPolicy, ctx, 'ok', 'info', 'pass', raw, '')];
  } };

export const permissionsPolicy: Rule = { id: 'H-10', title: 'Permissions-Policy', appliesTo: 'html', scope: 'target',
  basis: ['MDN', 'OWASP Secure Headers'],
  run(ctx) {
    if (!ctx.final) return [mk(permissionsPolicy, ctx, 'na', 'info', 'na', '応答がない', '')];
    const pp = header(ctx, 'permissions-policy')[0];
    if (pp) return [mk(permissionsPolicy, ctx, 'ok', 'info', 'pass', pp, '')];
    const fp = header(ctx, 'feature-policy')[0];
    const rec = 'Permissions-Policy: camera=(), microphone=(), geolocation=()';
    return fp ? [mk(permissionsPolicy, ctx, 2, 'low', 'fail', `Feature-Policy のみ: ${fp}`, rec)]
              : [mk(permissionsPolicy, ctx, 1, 'info', 'fail', '(ヘッダなし)', rec)];
  } };

export const crossOriginIsolation: Rule = { id: 'H-11', title: 'COOP・COEP・CORP', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'OWASP Secure Headers'],
  run(ctx) {
    if (!ctx.final) return [mk(crossOriginIsolation, ctx, 'na', 'info', 'na', '応答がない', '')];
    if (NO_CONTENT(ctx)) return [mk(crossOriginIsolation, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（本文のない応答）`, NO_CONTENT_REC)];
    const out = []; const sensitive = sensitiveUnlessStatic(ctx);
    // 守りにならない値は、ないのと同じ：CORP の cross-origin（どのサイトからも読み込める）、COOP の unsafe-none（既定の動作）と、
    // 知らない値・2つ以上の値（ブラウザは読めずに無視する）。あるだけで合格にすると、cross-origin を付けた機密応答を見逃した
    const policy = (name: string) => { const v = header(ctx, name); return v.length === 1 ? v[0].split(';')[0].trim().toLowerCase() : v.length ? 'invalid' : undefined; };
    const corp = policy('cross-origin-resource-policy'), coop = policy('cross-origin-opener-policy');
    if (sensitive && corp === undefined)
      out.push(mk(crossOriginIsolation, ctx, 1, 'low', 'fail', '機密応答に Cross-Origin-Resource-Policy なし', 'Cross-Origin-Resource-Policy: same-origin'));
    else if (sensitive && corp !== 'same-origin' && corp !== 'same-site')
      out.push(mk(crossOriginIsolation, ctx, 1, 'low', 'fail', `機密応答の Cross-Origin-Resource-Policy が ${header(ctx, 'cross-origin-resource-policy').join(', ')}（ほかのサイトから読み込める・無効な値）`, 'Cross-Origin-Resource-Policy: same-origin'));
    if (ctx.responseKind === 'html' && coop === undefined)
      out.push(mk(crossOriginIsolation, ctx, 2, 'info', 'fail', 'Cross-Origin-Opener-Policy なし', 'Cross-Origin-Opener-Policy: same-origin'));
    else if (ctx.responseKind === 'html' && !['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'].includes(coop!))
      out.push(mk(crossOriginIsolation, ctx, 2, 'info', 'fail', `Cross-Origin-Opener-Policy が ${header(ctx, 'cross-origin-opener-policy').join(', ')}（分離しない・無効な値）`, 'Cross-Origin-Opener-Policy: same-origin'));
    if (out.length) return out;
    // 機密かどうか分からず CORP もなければ、①を判定していない。COOP（②）があっても合格にしない（カバレッジの水増しになる）
    if (sensitive === undefined && !header(ctx, 'cross-origin-resource-policy').length)
      return [mk(crossOriginIsolation, ctx, 'na', 'info', 'na', `機密応答かどうか分からない（CORP なし${ctx.responseKind === 'html' ? '、COOP あり' : ''}）`, '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける')];
    return [mk(crossOriginIsolation, ctx, 'ok', 'info', 'pass', [...header(ctx, 'cross-origin-opener-policy'), ...header(ctx, 'cross-origin-resource-policy')].join(' / ') || '(該当なし)', '')];
  } };

export const contentType: Rule = { id: 'H-13', title: 'Content-Typeとcharset', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS'],
  run(ctx) {
    const f = ctx.final;
    if (!f) return [mk(contentType, ctx, 'na', 'info', 'na', '応答がない', '')];
    // 別のサイトへの転送で終わったターゲット（-L で転送先を採取していても、転送先は対象の応答として判定しない）は、ヘッダの項目を判定できないことを示す
    // （何も出さないと、H-03・H-13 が黙って消えた）
    if (f.status >= 300 && f.status < 400 && ctx.target.responses.filter(r => r.kind === 'redirect' || r.kind === 'final').at(-1) !== f)
      return [mk(contentType, ctx, 'na', 'info', 'na', `HTTP ${f.status}（別のサイトへの転送で終わる。転送先の応答は判定しない）`, '転送先の URL を別のターゲットとして採取する')];
    if (f.status === 204 || f.status === 304 || (f.status >= 300 && f.status < 400)) return [];   // 本文のない応答は適用外
    const ct = header(ctx, 'content-type')[0];
    // 本文が空の応答（Content-Length: 0 の 401・201 など。Spring Security の API の 401）は、型を示す本文がないので①の対象外
    // HTTP/2 は Content-Length を付けないことがあるので、本文がない（空・採取していない）201・202・401・403 も対象外にする（本文のない
    // 認証の拒否・作成の応答が多い。本文があれば①）
    if (!ct && (header(ctx, 'content-length').some(v => /^\s*0\s*$/.test(v)) || ([201, 202, 401, 403].includes(f.status) && !f.body?.trim()))) return [];
    if (!ct) return [mk(contentType, ctx, 1, 'medium', 'fail', '(Content-Typeなし)', 'Content-Type を必ず付ける（HTML は text/html; charset=utf-8）')];
    if (/^text\/html/i.test(ct) && !/charset=/i.test(ct)) return [mk(contentType, ctx, 2, 'medium', 'fail', ct, 'Content-Type: text/html; charset=utf-8')];
    return [mk(contentType, ctx, 'ok', 'info', 'pass', ct, '')];
  } };

export const xpcdp: Rule = { id: 'H-14', title: 'X-Permitted-Cross-Domain-Policies', appliesTo: 'html', scope: 'target',
  basis: ['OWASP Secure Headers'],
  run(ctx) {
    if (!ctx.final) return [mk(xpcdp, ctx, 'na', 'info', 'na', '応答がない', '')];
    const v = header(ctx, 'x-permitted-cross-domain-policies')[0];
    if (!v) return [mk(xpcdp, ctx, 1, 'low', 'fail', '(ヘッダなし)', 'X-Permitted-Cross-Domain-Policies: none')];
    // ② none・master-only 以外（all、by-content-type など）はポリシーファイルによる読み込みを許す
    return /^\s*(?:none|master-only)\s*$/i.test(v) ? [mk(xpcdp, ctx, 'ok', 'info', 'pass', v, '')]
      : [mk(xpcdp, ctx, 2, 'low', 'fail', v, 'X-Permitted-Cross-Domain-Policies: none')];
  } };

export const clearSiteData: Rule = { id: 'H-15', title: 'Clear-Site-Data', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'OWASP Secure Headers'],
  run(ctx) {
    if (baseLabel(ctx.target.label) !== 'logout') return [];          // ログアウト応答だけ
    if (!ctx.final) return [mk(clearSiteData, ctx, 'na', 'info', 'na', '応答がない', '')];
    if (logoutFailed(ctx.target)) return [mk(clearSiteData, ctx, 'na', 'info', 'na', `ログアウトの応答が HTTP ${firstStatus(ctx.target)}（ログアウトできていない）`, LOGOUT_FAILED_REC)];
    const csd = siteResponses(ctx.target).flatMap(r => r.headers.get('clear-site-data') ?? [])[0];
    return csd ? [mk(clearSiteData, ctx, 'ok', 'info', 'pass', csd, '')]
               : [mk(clearSiteData, ctx, 1, 'info', 'fail', '(ヘッダなし)', 'Clear-Site-Data: "cache", "cookies", "storage"')];
  } };

const PRODUCT_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];
// プロトコルの名前（HTTP・HTTPS・SPDY・S-HTTP）と版は製品の版ではない
const VIA_PRODUCT = /(?<![\w.-])(?!(?:HTTPS?|SPDY|SHTTP)\/)[A-Za-z][\w.-]*\/\d+\.\d+/i;
// 内部のホスト名は、ホスト名の最後が internal・local などのもの（edge01.local.example-cdn.net の .local. は公開のホスト名）
const INTERNAL = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)\b|\b[\w-]+\.(?:internal|local|lan|corp|intra)(?![\w.-])/i;
// CDN が付ける Server-Timing の項目（Cloudflare の cfL4・cfExtPri、CloudFront の cdn-*、Akamai の edge・origin・ak_p、Fastly）。アプリの内部処理ではない
const CDN_TIMING = /^(?:cf[A-Z]\w*|cdn-[\w-]+|cdn|edge|origin|ak_p|fastly[\w-]*|x-cache|cache)$/;
/**
 * Server-Timing の項目の名前（RFC の token の形のものだけ）。カンマで分けるのは引用符の外だけ（desc="user lookup, bob@example.com" の
 * カンマで分けると、desc の残りを項目の名前として証跡に出し、CDN の項目だけなのに⑤にもした）
 */
const appTimings = (v: string): string[] => {
  const names: string[] = []; let start = 0, quoted = false;
  for (let i = 0; i <= v.length; i++) {
    const c = v[i];
    if (c === '"' && v[i - 1] !== '\\') quoted = !quoted;
    else if ((c === ',' && !quoted) || i === v.length) { names.push(v.slice(start, i).split(';')[0].trim()); start = i + 1; }
  }
  return names.filter(n => /^[!#$%&'*+.^_`|~\w-]+$/.test(n) && !CDN_TIMING.test(n));
};
export const productInfo: Rule = { id: 'H-16', title: '製品・バージョン・デバッグ情報の露出', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-INFO-02', 'IPA'],
  run(ctx) {
    if (!ctx.final) return [mk(productInfo, ctx, 'na', 'info', 'na', '応答がない', '')];
    const out = [];
    for (const h of PRODUCT_HEADERS) for (const v of header(ctx, h)) {
      // X-Generator は「Drupal 10 (https://www.drupal.org)」のように主な版だけを出す。Server・X-Powered-By は「AmazonS3」の
      // ような製品名の数字があるので、「1.2」の形だけを版とみなす
      if (h === 'x-generator' ? /\b\d+\b/.test(v) : /\d+\.\d+/.test(v)) out.push(mk(productInfo, ctx, 1, 'low', 'fail', `${h}: ${v}`, 'バージョン番号を出さない（可能ならヘッダごと削除）'));
      else out.push(mk(productInfo, ctx, 2, 'info', 'fail', `${h}: ${v}`, '製品名も出さないか、汎用的な値にする'));
    }
    // 値はマスクする（トークンと、記録したリクエスト（Cookie を含む）を見られるプロファイラのURL）
    for (const h of ['x-debug-token', 'x-debug-token-link']) for (const v of header(ctx, h))
      out.push(mk(productInfo, ctx, 3, 'medium', 'fail', `${h}: ${maskValue(v.trim())}`, '本番でデバッグ用のヘッダ・プロファイラを無効にする'));
    // Via の製品の版（1.1 varnish (Varnish/7.4)、squid/4.10）。先頭のプロトコルの版（1.1、HTTP/1.1）は製品の版ではないので、「名前/版」の形だけを見る。
    // 製品名だけ（1.1 vegur、(CloudFront)）は②にしない（ほとんどの CDN・プロキシが付けるので、指摘しても対処できない）
    for (const v of header(ctx, 'via')) if (VIA_PRODUCT.test(v)) out.push(mk(productInfo, ctx, 1, 'low', 'fail', `via: ${v}`, 'バージョン番号を出さない（可能ならヘッダごと削除）'));
    for (const h of ['via', 'x-backend-server', 'x-served-by', 'x-host']) for (const v of header(ctx, h))
      if (INTERNAL.test(v)) out.push(mk(productInfo, ctx, 4, 'low', 'fail', `${h}: ${v}`, '内部ホスト名・IPアドレスを出さない'));
    // Server-Timing の証跡は項目の名前だけにする（desc に SQL・メールアドレス・キーを入れる実装がある）
    for (const v of header(ctx, 'server-timing')) { const names = appTimings(v);
      if (names.length) out.push(mk(productInfo, ctx, 5, 'low', 'fail', `server-timing: ${names.map(n => clip(n, 40)).join(', ')}（desc・dur の値は表示しない）`, '本番では内部処理の名前や時間を外部に返さない')); }
    for (const v of header(ctx, 'x-runtime')) out.push(mk(productInfo, ctx, 5, 'low', 'fail', `x-runtime: ${clip(v, 40)}`, '本番では内部処理の名前や時間を外部に返さない'));
    return out.length ? out : [mk(productInfo, ctx, 'ok', 'info', 'pass', '製品・デバッグ情報のヘッダなし', '')];
  } };

export const deprecatedHeaders: Rule = { id: 'H-17', title: '廃止・非推奨ヘッダ', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Secure Headers', 'MDN'],
  run(ctx) {
    if (!ctx.final) return [mk(deprecatedHeaders, ctx, 'na', 'info', 'na', '応答がない', '')];
    const out = [];
    const xss = header(ctx, 'x-xss-protection')[0];
    if (xss && /^1/.test(xss.trim())) out.push(mk(deprecatedHeaders, ctx, 1, 'low', 'fail', `x-xss-protection: ${xss}`, 'X-XSS-Protection は送らないか 0 にする（CSPで対策する）'));
    for (const h of ['expect-ct', 'public-key-pins', 'public-key-pins-report-only', 'feature-policy', 'pragma']) for (const v of header(ctx, h))
      out.push(mk(deprecatedHeaders, ctx, 2, 'info', 'fail', `${h}: ${v}`, '廃止・非推奨のヘッダを削除する'));
    return out.length ? out : [mk(deprecatedHeaders, ctx, 'ok', 'info', 'pass', '廃止・非推奨ヘッダなし', '')];
  } };
