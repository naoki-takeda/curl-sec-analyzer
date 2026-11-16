// rules/cookies.ts：第2章 Cookie（C-01〜C-13。C-07②・C-09①・C-12①は横断ルール rules/cross.ts）
import type { Finding, Rule, RuleContext } from '../model';
import { SESSION_PARAM_NAMES, maskValue, paramRegex } from '../mask';
import { isDeletion, looksLikeSession, parseSetCookie, sessionConfig, type SetCookie } from '../parser/setCookie';
import { baseLabel, hostOf } from '../parser/target';
import { mk } from './util';

/** ターゲットの全応答（-L のホップを含む）から、削除用でない Set-Cookie を取り出す */
export function cookiesOf(ctx: RuleContext): SetCookie[] {
  return ctx.target.responses.flatMap(r => r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, ctx.now));
}
/** 証跡：値はマスクし、属性はそのまま出す */
export const cookieEvidence = (c: SetCookie) => c.raw.trim().replace(/^([^=;]*=)([^;]*)/, (_, k: string, v: string) => k + maskValue(v.trim()));

/** Cookie ごとの判定を集める。指摘が1件もなければ .ok を1件返す。Set-Cookie がなければ適用外（空配列） */
function perCookie(rule: Rule, ctx: RuleContext, judge: (c: SetCookie) => Finding | undefined, subset = (_: SetCookie) => true): Finding[] {
  if (ctx.isHttps === false) return [];                // HTTP応答のCookieは C-10 で扱う（MVP）
  const cs = cookiesOf(ctx).filter(subset);
  if (!cs.length) return [];
  const fails = cs.map(judge).filter((f): f is Finding => !!f);
  return fails.length ? fails : [mk(rule, ctx, 'ok', 'info', 'pass', cs.map(c => c.name).join(', '), '')];
}

export const cookieSecure: Rule = { id: 'C-01', title: 'Cookie の Secure 属性', appliesTo: 'any', scope: 'target', dependsOn: ['H-01'],
  basis: ['MDN HTTP Observatory'],
  run(ctx) {
    return perCookie(cookieSecure, ctx, c => {
      if (c.attrs.has('secure')) return undefined;
      const rec = 'Secure 属性を付ける';
      if (looksLikeSession(c, ctx.now)) return mk(cookieSecure, ctx, 1, 'high', 'fail', cookieEvidence(c), rec);
      return ctx.hostHsts
        ? mk(cookieSecure, ctx, 3, 'low', 'fail', `${cookieEvidence(c)}（ホストはHSTSあり）`, rec)
        : mk(cookieSecure, ctx, 2, 'medium', 'fail', `${cookieEvidence(c)}（ホストのHSTSなし、または不明）`, rec);
    });
  } };

export const cookieHttpOnly: Rule = { id: 'C-02', title: 'Cookie の HttpOnly 属性', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(cookieHttpOnly, ctx,
      c => (c.attrs.has('httponly') ? undefined : mk(cookieHttpOnly, ctx, 1, 'high', 'fail', cookieEvidence(c), 'セッションCookieに HttpOnly 属性を付ける')),
      c => looksLikeSession(c, ctx.now));
  } };

export const cookieSameSite: Rule = { id: 'C-03', title: 'Cookie の SameSite 属性', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS', 'MDN HTTP Observatory'],
  run(ctx) {
    return perCookie(cookieSameSite, ctx, c => {
      const ss = c.attrs.get('samesite');
      const ev = cookieEvidence(c);
      if (ss === undefined) return looksLikeSession(c, ctx.now) ? mk(cookieSameSite, ctx, 1, 'medium', 'fail', ev, 'SameSite=Lax（または Strict）を付ける') : undefined;
      const v = typeof ss === 'string' ? ss.toLowerCase() : '';
      if (!['lax', 'strict', 'none'].includes(v)) return mk(cookieSameSite, ctx, 2, 'medium', 'fail', ev, 'SameSite の値は Lax・Strict・None のいずれか');
      if (v === 'none' && !c.attrs.has('secure')) return mk(cookieSameSite, ctx, 4, 'low', 'fail', ev, 'SameSite=None には Secure が必須（ブラウザが拒否する）');
      if (v === 'none') return mk(cookieSameSite, ctx, 3, 'medium', 'fail', ev, 'クロスサイトで送る必要がなければ Lax にする（必要なら理由を記録して例外登録）');
      return undefined;
    });
  } };

// ---- 以下 MVP で追加（C-04〜C-10、C-12②、C-13） ----

export const cookieDomain: Rule = { id: 'C-04', title: 'Domain・Path', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS', 'RFC 6265'],
  run(ctx) {
    const host = hostOf(ctx.target)?.replace(/:\d+$/, '');
    return perCookie(cookieDomain, ctx, c => {
      const d = c.attrs.get('domain');
      if (typeof d !== 'string' || !host) return undefined;
      const dom = d.replace(/^\./, '').toLowerCase();
      return dom !== host.toLowerCase()
        ? mk(cookieDomain, ctx, 1, 'medium', 'fail', `${cookieEvidence(c)}（ホスト ${host}）`, 'Domain 属性を付けない（発行したホストだけに送られる）')
        : undefined;
    });
  } };

export const cookieLifetime: Rule = { id: 'C-05', title: 'Expires・Max-Age', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(cookieLifetime, ctx, c => {
      const ma = c.attrs.get('max-age'), ex = c.attrs.get('expires');
      const sec = typeof ma === 'string' ? Number(ma) : typeof ex === 'string' ? (Date.parse(ex) - ctx.now) / 1000 : 0;
      const limit = sessionConfig.maxAgeHours * 3600;
      return sec > limit
        ? mk(cookieLifetime, ctx, 1, 'medium', 'fail', `${cookieEvidence(c)}（期限 約${Math.round(sec / 3600)}時間、基準 ${sessionConfig.maxAgeHours}時間）`, 'セッションIDに長い期限を付けない（基準は組織プロファイルの sessionMaxAgeHours で変えられる）')
        : undefined;
    }, c => looksLikeSession(c, ctx.now));
  } };

export const cookiePrefix: Rule = { id: 'C-06', title: '__Host-・__Secure-プレフィックス', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(cookiePrefix, ctx, c => {
      const ev = cookieEvidence(c);
      if (c.name.startsWith('__Host-')) {
        const ok = c.attrs.has('secure') && c.attrs.get('path') === '/' && !c.attrs.has('domain');
        return ok ? undefined : mk(cookiePrefix, ctx, 2, 'low', 'fail', ev, '__Host- には Secure・Path=/ が必要で、Domain は付けられない（ブラウザが拒否する）');
      }
      if (c.name.startsWith('__Secure-')) return c.attrs.has('secure') ? undefined : mk(cookiePrefix, ctx, 2, 'low', 'fail', ev, '__Secure- には Secure が必要（ブラウザが拒否する）');
      return looksLikeSession(c, ctx.now) ? mk(cookiePrefix, ctx, 1, 'info', 'fail', ev, 'セッションCookieには __Host- プレフィックスを付ける') : undefined;
    });
  } };

/** 値の文字種から推定したエントロピー（ビット）。実際の乱数性は分からないため目安 */
export function estimateBits(v: string): number {
  const size = /^[0-9]+$/.test(v) ? 10 : /^[0-9a-f]+$/i.test(v) ? 16 : /^[0-9A-Za-z]+$/.test(v) ? 62 : 64;
  return Math.floor(v.length * Math.log2(size));
}
export const sessionIdStrength: Rule = { id: 'C-07', title: 'セッションIDの長さ・推測可能性', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(sessionIdStrength, ctx, c => {
      const bits = estimateBits(c.value);
      return bits < 128 ? mk(sessionIdStrength, ctx, 1, 'high', 'fail', `${cookieEvidence(c)}（推定 約${bits}bit）`, '128bit以上のエントロピーを持つ乱数をセッションIDにする（ASVS 5.0.0 7.2.3）') : undefined;
    }, c => looksLikeSession(c, ctx.now));
  } };

const DEFAULT_NAMES = /^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|laravel_session|CFID|CFTOKEN)$/i;
export const defaultCookieName: Rule = { id: 'C-08', title: '既定のCookie名', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(defaultCookieName, ctx, c => (DEFAULT_NAMES.test(c.name)
      ? mk(defaultCookieName, ctx, 1, 'info', 'fail', c.name, '汎用的な名前に変える（例：__Host-sid）') : undefined));
  } };

const SESSION_IN_URL = paramRegex(SESSION_PARAM_NAMES);   // マスキングと同じ一覧（mask.ts）
export const sessionInUrl: Rule = { id: 'C-09', title: 'セッション固定化', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    const urls = [ctx.target.url ?? '', ...ctx.target.responses.flatMap(r => r.headers.get('location') ?? [])];
    const hit = urls.find(u => SESSION_IN_URL.test(u));
    return hit ? [mk(sessionInUrl, ctx, 2, 'high', 'fail', hit, 'セッションIDをURLに入れない（Cookieだけで受け渡す）')]
               : [mk(sessionInUrl, ctx, 'ok', 'info', 'pass', 'URLにセッションIDなし', '')];
  } };

export const cookieOverHttp: Rule = { id: 'C-10', title: 'HTTP応答でのCookie発行', appliesTo: 'any', scope: 'target',
  basis: ['MDN'],
  run(ctx) {
    const httpResponses = /^http:\/\//i.test(ctx.target.url ?? '') ? [ctx.chain[0]].filter(Boolean) : [];
    if (!httpResponses.length) return [];
    const cs = httpResponses.flatMap(r => r!.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, ctx.now));
    if (!cs.length) return [mk(cookieOverHttp, ctx, 'ok', 'info', 'pass', 'HTTP応答でCookieを発行していない', '')];
    return cs.map(c => looksLikeSession(c, ctx.now) && !c.attrs.has('secure')
      ? mk(cookieOverHttp, ctx, 1, 'high', 'fail', cookieEvidence(c), 'HTTPではCookieを発行せず、まずHTTPSへ転送する')
      : mk(cookieOverHttp, ctx, 2, 'medium', 'fail', cookieEvidence(c), 'HTTPではCookieを発行せず、まずHTTPSへ転送する'));
  } };

export const logoutDeletesCookie: Rule = { id: 'C-12', title: 'ログアウト後のセッション無効化', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    if (baseLabel(ctx.target.label) !== 'logout') return [];            // ①は横断ルール（logout と after-logout）
    if (!ctx.final) return [mk(logoutDeletesCookie, ctx, 'na', 'info', 'na', '応答がない', '')];
    const del = ctx.target.responses.flatMap(r => r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => isDeletion(c, ctx.now));
    return del.length ? [mk(logoutDeletesCookie, ctx, 'ok', 'info', 'pass', del.map(cookieEvidence).join(' / '), '')]
                      : [mk(logoutDeletesCookie, ctx, 2, 'low', 'fail', 'ログアウト応答でCookieを削除していない', 'ログアウト応答で Max-Age=0 のSet-Cookieを返し、サーバ側のセッションも破棄する')];
  } };

export const cookieSharedCache: Rule = { id: 'C-13', title: 'Set-Cookieと共有キャッシュ', appliesTo: 'any', scope: 'target',
  basis: ['RFC 9111', 'OWASP HTTP Headers CS'],
  run(ctx) {
    const out: Finding[] = []; let any = false;
    for (const r of ctx.target.responses) {
      const cs = (r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, ctx.now));
      if (!cs.length) continue;
      any = true;
      const cc = (r.headers.get('cache-control') ?? []).join(', ').toLowerCase();
      const shared = /\bpublic\b|s-maxage/.test(cc);
      if (!shared) continue;
      if (cs.some(c => looksLikeSession(c, ctx.now))) out.push(mk(cookieSharedCache, ctx, 1, 'high', 'fail', `Cache-Control: ${cc}`, 'Set-Cookie を含む応答は Cache-Control: no-store（少なくとも private）にする'));
      else if (/\bpublic\b/.test(cc)) out.push(mk(cookieSharedCache, ctx, 2, 'low', 'fail', `Cache-Control: ${cc}`, 'Set-Cookie を含む応答を public にしない'));
    }
    if (!any) return [];
    return out.length ? out : [mk(cookieSharedCache, ctx, 'ok', 'info', 'pass', '共有キャッシュの指定なし', '')];
  } };

// ---- 以下 v0.3 で追加（C-11） ----
export const cookiePartitioned: Rule = { id: 'C-11', title: 'Partitioned（CHIPS）', appliesTo: 'any', scope: 'target',
  basis: ['MDN: CHIPS'],
  run(ctx) {
    return perCookie(cookiePartitioned, ctx, c => (c.attrs.get('samesite')?.toString().toLowerCase() === 'none' && !c.attrs.has('partitioned')
      ? mk(cookiePartitioned, ctx, 1, 'info', 'fail', cookieEvidence(c), '第三者として埋め込まれる用途なら Partitioned を付ける（サードパーティCookieの廃止に備える）') : undefined));
  } };
