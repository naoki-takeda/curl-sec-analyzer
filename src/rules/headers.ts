// rules/headers.ts：第1章 HTTPレスポンスヘッダ（H-01〜H-17。H-02③・H-04⑤は横断ルール rules/cross.ts）
import type { Rule, RuleContext } from '../model';
import { LOGOUT_FAILED_REC, header, hstsDirective, isStaticResource, mk, parseCsp, sensitiveUnlessStatic } from './util';
import { maskValue } from '../mask';
import { baseLabel, firstStatus, logoutFailed, ownChain } from '../parser/target';
import { htmlBody, mixedContent } from './html';
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
    const age = Number(v.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? NaN);
    if (Number.isNaN(age)) return [mk(hsts, ctx, 3, 'high', 'fail', v, rec, { obsId: 'hsts-header-invalid', score: -20 })];
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
    const enforce = header(ctx, 'content-security-policy');
    const ro = header(ctx, 'content-security-policy-report-only');
    const rec = "Content-Security-Policy: default-src 'self'; script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
    if (!enforce.length && !ro.length) return [mk(cspPresence, ctx, 1, 'high', 'fail', '(ヘッダなし)', rec)];
    if (!enforce.length) return [mk(cspPresence, ctx, 2, 'medium', 'fail', `Report-Onlyのみ: ${ro[0]}`, '確認できたら強制モードの Content-Security-Policy に切り替える')];
    if (enforce.some(v => parseCsp(v).size === 0)) return [mk(cspPresence, ctx, 3, 'high', 'fail', enforce.join(' / '), rec)];
    return [mk(cspPresence, ctx, 'ok', 'info', 'pass', enforce.join(' / '), '')];
  } };

export const clickjacking: Rule = { id: 'H-06', title: 'クリックジャッキング対策（frame-ancestors・X-Frame-Options）', appliesTo: 'html', scope: 'target',
  basis: ['MDN', 'OWASP Secure Headers'],
  run(ctx) {
    if (!ctx.final) return [mk(clickjacking, ctx, 'na', 'info', 'na', '応答がない', '')];
    const fa = header(ctx, 'content-security-policy').map(parseCsp).find(m => m.has('frame-ancestors'))?.get('frame-ancestors');
    const xfo = header(ctx, 'x-frame-options')[0]?.trim();
    // frame-ancestors は X-Frame-Options より優先されるので、広い指定（*、https: などのスキームだけ、*.example.com）は④にする
    const broad = fa?.find(s => s === '*' || /^[a-z][\w+.-]*:$/i.test(s) || /^(?:[a-z][\w+.-]*:\/\/)?\*\./i.test(s));
    if (fa && broad) return [mk(clickjacking, ctx, 4, 'medium', 'fail', `frame-ancestors ${fa.join(' ')}`, "frame-ancestors は 'none' か 'self'（埋め込みを許す相手は個別のオリジン）にする")];
    if (fa) return [mk(clickjacking, ctx, 'ok', 'info', 'pass', `frame-ancestors ${fa.join(' ')}`, '')];
    const rec = "Content-Security-Policy: frame-ancestors 'none'（旧ブラウザ向けに X-Frame-Options: DENY も併用）";
    if (!xfo) return [mk(clickjacking, ctx, 1, 'medium', 'fail', '(frame-ancestors も X-Frame-Options もない)', rec)];
    if (/^allow-from/i.test(xfo)) return [mk(clickjacking, ctx, 2, 'medium', 'fail', `X-Frame-Options: ${xfo}`, rec)];
    return [mk(clickjacking, ctx, 3, 'info', 'fail', `X-Frame-Options: ${xfo}（frame-ancestors なし）`, rec)];
  } };

export const nosniff: Rule = { id: 'H-08', title: 'X-Content-Type-Options', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS'],
  run(ctx) {
    if (!ctx.final) return [mk(nosniff, ctx, 'na', 'info', 'na', '応答がない', '')];
    const v = header(ctx, 'x-content-type-options')[0];
    if (v?.trim().toLowerCase() === 'nosniff') return [mk(nosniff, ctx, 'ok', 'info', 'pass', v, '')];
    return [mk(nosniff, ctx, 1, 'medium', 'fail', v ?? '(ヘッダなし)', 'X-Content-Type-Options: nosniff')];
  } };

export const cacheControl: Rule = { id: 'H-12', title: 'Cache-Control', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS', 'OWASP REST Security CS'],
  run(ctx) {
    if (!ctx.final) return [mk(cacheControl, ctx, 'na', 'info', 'na', '応答がない', '')];
    const cc = header(ctx, 'cache-control').join(', ').toLowerCase();
    const dirs = new Set(cc.split(',').map(s => s.trim().split('=')[0]).filter(Boolean));
    const ev = cc || (header(ctx, 'pragma').length ? `(Cache-Controlなし、Pragma: ${header(ctx, 'pragma')[0]})` : '(ヘッダなし)');
    const isStatic = isStaticResource(ctx);
    if (dirs.has('no-store')) return [mk(cacheControl, ctx, 'ok', 'info', 'pass', cc, '')];
    // 静的リソース・公開ファイルは、sensitive=1 を明示したときだけ機密応答として扱う（rules/util.ts の sensitiveUnlessStatic）
    const sensitive = sensitiveUnlessStatic(ctx);
    if (sensitive === undefined) {
      if (isStatic && !cc) return [mk(cacheControl, ctx, 3, 'info', 'fail', ev, '静的リソースにもキャッシュ方針（max-age など）を明示する')];
      if (isStatic) return [mk(cacheControl, ctx, 'ok', 'info', 'pass', ev, '')];
      return [mk(cacheControl, ctx, 'na', 'info', 'na', `機密応答かどうか分からない（${ev}）`, '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける')];
    }
    if (!sensitive) {
      if (isStatic && !cc) return [mk(cacheControl, ctx, 3, 'info', 'fail', ev, '静的リソースにもキャッシュ方針（max-age など）を明示する')];
      return [mk(cacheControl, ctx, 'ok', 'info', 'pass', ev || '(機密でない応答)', '')];
    }
    if (dirs.has('private') && !dirs.has('public')) return [mk(cacheControl, ctx, 2, 'medium', 'fail', ev, 'Cache-Control: no-store')];
    return [mk(cacheControl, ctx, 1, 'high', 'fail', ev, 'Cache-Control: no-store')];
  } };

// ---- 以下 MVP で追加（H-02、H-04、H-05、H-07、H-09〜H-11、H-13〜H-17） ----

const enforcedPolicies = (ctx: RuleContext) => header(ctx, 'content-security-policy').map(parseCsp);

export const hstsPreload: Rule = { id: 'H-02', title: 'HSTS preload', appliesTo: 'any', scope: 'target',
  basis: ['hstspreload.org', 'MDN'],
  run(ctx) {
    if (ctx.isHttps === false) return [];
    const v = hstsOf(ctx);
    if (!ctx.final || !v) return [mk(hstsPreload, ctx, 'na', 'info', 'na', 'HSTSがない（H-01で判定）', '')];
    const age = Number(v.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
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
function coveredByOther(i: CspIssue, others: Policy[]): boolean {
  if (i.type !== 'MISSING_DIRECTIVES' && i.directive !== 'default-src') return false;
  const d = i.item === 'H-04' ? 'script-src' : i.item === 'H-05' ? (i.condition === 1 ? 'object-src' : 'base-uri') : undefined;
  return !!d && others.some(p => (p.dirs.has(d) || (d !== 'base-uri' && p.dirs.has('default-src')))
    && !p.issues.some(x => (x.item === i.item && x.condition === i.condition) || x.type === EVALUATOR_ERROR));
}

/** 強制モードの各ポリシーを csp_evaluator で評価する（ポリシーごとのディレクティブと指摘） */
const policiesOf = (ctx: RuleContext): Policy[] => header(ctx, 'content-security-policy').map(v => ({ dirs: parseCsp(v), issues: evaluateCsp(v) }));

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
    if (!issues.length) return [mk(cspScript, ctx, 'ok', 'info', 'pass', enforcedPolicies(ctx).map(p => `script-src ${(p.get('script-src') ?? p.get('default-src') ?? []).join(' ')}`).join(' / '), '')];
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
    const html = htmlBody(ctx);                                // ③は E-07 と同じ判定で混在コンテンツを見る
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
    const out = []; const sensitive = sensitiveUnlessStatic(ctx);
    if (sensitive && !header(ctx, 'cross-origin-resource-policy').length)
      out.push(mk(crossOriginIsolation, ctx, 1, 'low', 'fail', '機密応答に Cross-Origin-Resource-Policy なし', 'Cross-Origin-Resource-Policy: same-origin'));
    if (ctx.responseKind === 'html' && !header(ctx, 'cross-origin-opener-policy').length)
      out.push(mk(crossOriginIsolation, ctx, 2, 'info', 'fail', 'Cross-Origin-Opener-Policy なし', 'Cross-Origin-Opener-Policy: same-origin'));
    if (out.length) return out;
    if (sensitive === undefined && ctx.responseKind !== 'html') return [mk(crossOriginIsolation, ctx, 'na', 'info', 'na', '機密応答かどうか分からない', 'sensitive=1 を付ける')];
    return [mk(crossOriginIsolation, ctx, 'ok', 'info', 'pass', [...header(ctx, 'cross-origin-opener-policy'), ...header(ctx, 'cross-origin-resource-policy')].join(' / ') || '(該当なし)', '')];
  } };

export const contentType: Rule = { id: 'H-13', title: 'Content-Typeとcharset', appliesTo: 'any', scope: 'target',
  basis: ['OWASP HTTP Headers CS'],
  run(ctx) {
    const f = ctx.final;
    if (!f) return [mk(contentType, ctx, 'na', 'info', 'na', '応答がない', '')];
    if (f.status === 204 || f.status === 304 || (f.status >= 300 && f.status < 400)) return [];   // 本文のない応答は適用外
    const ct = header(ctx, 'content-type')[0];
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
    const csd = ctx.target.responses.flatMap(r => r.headers.get('clear-site-data') ?? [])[0];
    return csd ? [mk(clearSiteData, ctx, 'ok', 'info', 'pass', csd, '')]
               : [mk(clearSiteData, ctx, 1, 'info', 'fail', '(ヘッダなし)', 'Clear-Site-Data: "cache", "cookies", "storage"')];
  } };

const PRODUCT_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];
const INTERNAL = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost|[\w-]+\.(?:internal|local|lan|corp|intra))\b/i;
export const productInfo: Rule = { id: 'H-16', title: '製品・バージョン・デバッグ情報の露出', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-INFO-02', 'IPA'],
  run(ctx) {
    if (!ctx.final) return [mk(productInfo, ctx, 'na', 'info', 'na', '応答がない', '')];
    const out = [];
    for (const h of PRODUCT_HEADERS) for (const v of header(ctx, h)) {
      if (/\d+\.\d+/.test(v)) out.push(mk(productInfo, ctx, 1, 'low', 'fail', `${h}: ${v}`, 'バージョン番号を出さない（可能ならヘッダごと削除）'));
      else if (h === 'server' || h === 'x-powered-by') out.push(mk(productInfo, ctx, 2, 'info', 'fail', `${h}: ${v}`, '製品名も出さないか、汎用的な値にする'));
    }
    // 値はマスクする（トークンと、記録したリクエスト（Cookie を含む）を見られるプロファイラのURL）
    for (const h of ['x-debug-token', 'x-debug-token-link']) for (const v of header(ctx, h))
      out.push(mk(productInfo, ctx, 3, 'medium', 'fail', `${h}: ${maskValue(v.trim())}`, '本番でデバッグ用のヘッダ・プロファイラを無効にする'));
    for (const h of ['via', 'x-backend-server', 'x-served-by', 'x-host']) for (const v of header(ctx, h))
      if (INTERNAL.test(v)) out.push(mk(productInfo, ctx, 4, 'low', 'fail', `${h}: ${v}`, '内部ホスト名・IPアドレスを出さない'));
    for (const h of ['server-timing', 'x-runtime']) for (const v of header(ctx, h))
      out.push(mk(productInfo, ctx, 5, 'low', 'fail', `${h}: ${v}`, '本番では内部処理の名前や時間を外部に返さない'));
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
