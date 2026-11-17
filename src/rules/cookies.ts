// rules/cookies.ts：第2章 Cookie（C-01〜C-13。C-07②・C-09①・C-12①は横断ルール rules/cross.ts）
import type { Finding, Rule, RuleContext } from '../model';
import { SESSION_PARAM_NAMES, maskValue, paramRegex } from '../mask';
import { cookieDate, isChunkMarker, isChunkPiece, isDeletion, isInfraCookie, looksLikeSession, looksLikeSessionName, parseSetCookie, sessionConfig, type SetCookie } from '../parser/setCookie';
import { baseLabel, firstStatus, hostOf, logoutFailed, siteResponses } from '../parser/target';
import { LOGOUT_FAILED_REC, mk } from './util';

/** ターゲットの全応答（-L のホップを含む）から、削除用でない Set-Cookie を取り出す */
export function cookiesOf(ctx: RuleContext): SetCookie[] {
  return siteResponses(ctx.target).flatMap(r => r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, ctx.now));
}
/** 名前のない Cookie（値だけの Set-Cookie）の表示名 */
export const cookieName = (c: SetCookie) => c.name || '（名前なし）';
const KNOWN_ATTRS = new Set(['expires', 'max-age', 'domain', 'path', 'samesite', 'priority', 'secure', 'httponly', 'partitioned', 'version', 'comment']);
/**
 * 属性の証跡。既知の属性はそのまま出すが、値の中のカンマのあと（1行にまとめた Set-Cookie で分けられなかった、名前のない2つ目の Cookie。
 * 「Path=/, <値>」）と、未知の属性・名前だけのかけらの値は伏せる。Expires の日付のカンマ（Wed, 21 Oct …）はそのまま
 */
const attrEvidence = (part: string): string => {
  const p = part.trim(); if (!p) return part;
  const i = p.indexOf('='); const name = (i >= 0 ? p.slice(0, i) : p).trim(); const lower = name.toLowerCase();
  if (!KNOWN_ATTRS.has(lower)) return i >= 0 ? ` ${name}=${maskValue(p.slice(i + 1).trim())}` : ` ${maskValue(p)}`;
  if (i < 0) return ` ${p}`;
  const v = p.slice(i + 1);
  // Expires の日付は曜日のあとに1つだけカンマを含む（Wed, 21 Oct 2026 07:28:00 GMT）。2つ目のカンマのあとは別の Cookie
  const comma = lower === 'expires' ? v.indexOf(',', v.indexOf(',') + 1) : v.indexOf(',');
  return comma < 0 ? ` ${p}` : ` ${name}=${v.slice(0, comma)}, ${maskValue(v.slice(comma + 1).trim())}`;
};
/** 証跡：値はマスクし、属性は既知のものだけそのまま出す。名前のない Cookie は「（名前なし）=」に続けて値を伏せる */
export const cookieEvidence = (c: SetCookie) => {
  const raw = c.raw.trim(); const semi = raw.indexOf(';');
  const attrs = semi >= 0 ? raw.slice(semi + 1).split(';').map(a => `;${attrEvidence(a)}`).join('') : '';
  return `${cookieName(c)}=${maskValue(c.value)}${attrs}`;
};

/** Cookie ごとの判定を集める。指摘が1件もなければ .ok を1件返す。Set-Cookie がなければ適用外（空配列） */
function perCookie(rule: Rule, ctx: RuleContext, judge: (c: SetCookie) => Finding | undefined, subset = (_: SetCookie) => true): Finding[] {
  if (ctx.isHttps === false) return [];                // HTTP応答のCookieは C-10 で扱う（MVP）
  // 分割の印（.AspNetCore.Cookies=chunks-2）は、同じ応答に中身（…C1）があれば数えない（1つの Cookie を印と中身で2回指摘しない）
  const all = cookiesOf(ctx); const names = new Set(all.map(c => c.name));
  const cs = all.filter(c => !(isChunkMarker(c) && names.has(`${c.name}C1`))).filter(subset);
  if (!cs.length) return [];
  const fails = cs.map(judge).filter((f): f is Finding => !!f);
  return fails.length ? fails : [mk(rule, ctx, 'ok', 'info', 'pass', cs.map(cookieName).join(', '), '')];
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
      // 負荷分散・WAF・CDN の Cookie（AWSALBCORS・ARRAffinitySameSite・__cf_bm）は、CORS のリクエストでも同じサーバに届けるため、仕組み上 None にしている
      if (v === 'none' && isInfraCookie(c.name)) return undefined;
      if (v === 'none') return mk(cookieSameSite, ctx, 3, 'medium', 'fail', ev, 'クロスサイトで送る必要がなければ Lax にする（必要なら理由を記録して例外登録）');
      return undefined;
    });
  } };

// ---- 以下 MVP で追加（C-04〜C-10、C-12②、C-13） ----
// C-04 は、Cookie を発行したホップのホストと比べるため、perCookie を使わない

export const cookieDomain: Rule = { id: 'C-04', title: 'Domain・Path', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS', 'RFC 6265'],
  run(ctx) {
    if (ctx.isHttps === false) return [];                // HTTP応答のCookieは C-10 で扱う（perCookie と同じ）
    // Cookie ごとに、それを発行したホップのホストと比べる。-L で a.example から www.a.example に転送し、www が
    // Domain=www.a.example で発行した Cookie を、ターゲットの URL のホスト（a.example）と比べて①にしないため
    const targetHost = hostOf(ctx.target)?.replace(/:\d+$/, '');
    const hopHost = (u?: string) => { try { return u ? new URL(u).hostname : undefined; } catch { return undefined; } };
    const cs = siteResponses(ctx.target).flatMap(r => { const host = hopHost(r.url) ?? targetHost;
      return (r.headers.get('set-cookie') ?? []).map(raw => ({ c: parseSetCookie(raw), host })); }).filter(x => !isDeletion(x.c, ctx.now));
    if (!cs.length) return [];
    const fails = cs.flatMap(({ c, host }) => {
      const d = c.attrs.get('domain');
      if (typeof d !== 'string' || !host || isInfraCookie(c.name)) return [];   // CDN の Cookie（__cf_bm など）は CDN が Domain を決める
      const dom = d.replace(/^\./, '').toLowerCase();
      if (!dom) return [];                                  // 空の Domain はブラウザが無視する（ホストだけに送られる）
      if (dom !== host.toLowerCase()) return [mk(cookieDomain, ctx, 1, 'medium', 'fail', `${cookieEvidence(c)}（ホスト ${host}）`, 'Domain 属性を付けない（発行したホストだけに送られる）')];
      // ホストと同じ値でも、Domain を付けるとサブドメインにも送られる（付けなければ発行したホストだけ）
      return [mk(cookieDomain, ctx, 3, 'low', 'fail', `${cookieEvidence(c)}（ホスト ${host}。サブドメインにも送られる）`, 'Domain 属性を付けない（ホストと同じ値でもサブドメインに送られる）')];
    });
    return fails.length ? fails : [mk(cookieDomain, ctx, 'ok', 'info', 'pass', cs.map(x => cookieName(x.c)).join(', '), '')];
  } };

export const cookieLifetime: Rule = { id: 'C-05', title: 'Expires・Max-Age', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(cookieLifetime, ctx, c => {
      // 空や数字でない Max-Age はブラウザが無視し、Expires が効く（RFC 6265 5.2.2。parser/setCookie.ts の isDeletion と同じ）
      const ma = c.attrs.get('max-age'), ex = c.attrs.get('expires');
      const validMa = typeof ma === 'string' && /^-?\d+$/.test(ma.trim());
      const exSec = typeof ex === 'string' ? (cookieDate(ex) - ctx.now) / 1000 : NaN;
      const sec = validMa ? Number(ma) : Number.isNaN(exSec) ? 0 : exSec;
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
      // プレフィックスは大文字小文字を区別しない（RFC 6265bis。今の Chrome・Firefox は __host-sid にも __Host- の条件を求め、満たさなければ拒否する）
      if (/^__host-/i.test(c.name)) {
        const ok = c.attrs.has('secure') && c.attrs.get('path') === '/' && !c.attrs.has('domain');
        return ok ? undefined : mk(cookiePrefix, ctx, 2, 'low', 'fail', ev, '__Host- には Secure・Path=/ が必要で、Domain は付けられない（ブラウザが拒否する）');
      }
      if (/^__secure-/i.test(c.name)) return c.attrs.has('secure') ? undefined : mk(cookiePrefix, ctx, 2, 'low', 'fail', ev, '__Secure- には Secure が必要（ブラウザが拒否する）');
      return looksLikeSession(c, ctx.now) ? mk(cookiePrefix, ctx, 1, 'info', 'fail', ev, 'セッションCookieには __Host- プレフィックスを付ける') : undefined;
    });
  } };

/** 値の文字種から推定したエントロピー（ビット）。実際の乱数性は分からないため目安 */
export function estimateBits(raw: string): number {
  // 値を囲む引用符（sid="…"。RFC 6265 の DQUOTE）と、パーセントエンコード（%2B は1文字）は乱数の量に数えない（数えると、記号を含むとみなして
  // 64種で数え、20桁の16進数（80bit）を約132bitとして合格にした）
  let v = raw.replace(/^"(.*)"$/s, '$1');
  try { v = decodeURIComponent(v); } catch { /* 壊れた %XX はそのまま */ }
  // 小文字と数字だけ（ASP.NET_SessionId の base32 など）・大文字と数字だけは36種で数える（62種で数えると、24文字の約120bitを約142bitとして見逃した）
  const size = /^[0-9]+$/.test(v) ? 10 : /^[0-9a-f]+$/i.test(v) ? 16 : /^[0-9a-z]+$/.test(v) || /^[0-9A-Z]+$/.test(v) ? 36 : /^[0-9A-Za-z]+$/.test(v) ? 62 : 64;
  return Math.floor(v.length * Math.log2(size));
}
/**
 * 時刻から作る UUID の版と、乱数の部分のビット数。v1・v2・v6 は時刻とノード（MAC アドレス）から作り、乱数はクロックシーケンスの14bitだけ。
 * v7 は先頭48bitが時刻で、乱数は74bit。文字種から推定すると、どれも約216bitになり、推測できる値を合格にしてしまう。
 * v4（乱数122bit）は今までどおり文字種で推定する（ASVS の128bitとの差をどう扱うかは別に決める）
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function timeBasedUuid(v: string): { version: number; bits: number } | undefined {
  const ver = Number.parseInt(v.match(UUID)?.[1] ?? '', 16);
  return ver === 1 || ver === 2 || ver === 6 ? { version: ver, bits: 14 } : ver === 7 ? { version: 7, bits: 74 } : undefined;
}
export const sessionIdStrength: Rule = { id: 'C-07', title: 'セッションIDの長さ・推測可能性', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Session Mgmt CS'],
  run(ctx) {
    return perCookie(sessionIdStrength, ctx, c => {
      const uuid = timeBasedUuid(c.value);
      const bits = uuid?.bits ?? estimateBits(c.value);
      return bits < 128 ? mk(sessionIdStrength, ctx, 1, 'high', 'fail', `${cookieEvidence(c)}（推定 約${bits}bit${uuid ? `。時刻から作る UUID v${uuid.version}` : ''}）`, '128bit以上のエントロピーを持つ乱数をセッションIDにする（ASVS 5.0.0 7.2.3）') : undefined;
    }, c => looksLikeSession(c, ctx.now) && !isChunkMarker(c) && !isChunkPiece(c));   // 分割の印（chunks-2）と2つ目以降のかけら（…C2）は値を見ない
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
    // http のホップすべて（http://…/app → http://…/app/ → https の2つ目のホップで発行した Cookie も平文で送られる）。
    // 各ホップの URL はパーサ・HAR の取り込みが付ける（parser/target.ts の assignHopUrls）。URL の分からないホップは最初のものだけ
    const httpResponses = /^http:\/\//i.test(ctx.target.url ?? '') ? ctx.chain.filter((r, i) => i === 0 || /^http:\/\//i.test(r.url ?? '')) : [];
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
    if (logoutFailed(ctx.target)) return [mk(logoutDeletesCookie, ctx, 'na', 'info', 'na', `ログアウトの応答が HTTP ${firstStatus(ctx.target)}（ログアウトできていない）`, LOGOUT_FAILED_REC)];
    const del = siteResponses(ctx.target).flatMap(r => r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => isDeletion(c, ctx.now));
    // 消したのがセッションCookieらしい名前のものか（Spring Security の既定のログアウトは remember-me だけを消し、セッションCookie は残す）
    // Clear-Site-Data: "cookies"（か "*"）で消すログアウトは、名前を挙げずにすべての Cookie を消す（H-15 と同じ扱い）
    const csd = siteResponses(ctx.target).flatMap(r => r.headers.get('clear-site-data') ?? []).join(',');
    if (/"(?:cookies|\*)"/i.test(csd)) return [mk(logoutDeletesCookie, ctx, 'ok', 'info', 'pass', `Clear-Site-Data: ${csd}`, '')];
    const sessionDel = del.filter(c => looksLikeSessionName(c.name));
    // セッションを作り直すログアウト（Laravel の invalidate、Rails の reset_session）は、セッションCookie を消さずに新しい値で発行し直す（②にしていた）。
    // 値を持たないので、新しい値か（期限を延ばしただけの同じ値か）は分からない。合格にも不合格にもせず、古いセッションの無効化は①で確かめる
    const sent = ctx.target.sentCookieNames;
    const reissued = sessionDel.length ? [] : cookiesOf(ctx).filter(c => c.value && looksLikeSessionName(c.name) && (!sent?.length || sent.includes(c.name)));
    if (reissued.length)
      return [mk(logoutDeletesCookie, ctx, 'na', 'info', 'na', `${[...new Set(reissued.map(cookieName))].join(', ')} を削除せずに発行し直した（新しい値かは分からない）`, 'after-logout を採取し、古いセッションCookieが使えないかを C-12① で確かめる')];
    if (del.length && !sessionDel.length)
      return [mk(logoutDeletesCookie, ctx, 2, 'low', 'fail', `削除したのは ${del.map(c => c.name).join(', ')} だけ（セッションCookieらしい名前ではない）`, 'ログアウト応答で Max-Age=0 のSet-Cookieを返し、サーバ側のセッションも破棄する')];
    return del.length ? [mk(logoutDeletesCookie, ctx, 'ok', 'info', 'pass', sessionDel.map(cookieEvidence).join(' / '), '')]
                      : [mk(logoutDeletesCookie, ctx, 2, 'low', 'fail', 'ログアウト応答でCookieを削除していない', 'ログアウト応答で Max-Age=0 のSet-Cookieを返し、サーバ側のセッションも破棄する')];
  } };

export const cookieSharedCache: Rule = { id: 'C-13', title: 'Set-Cookieと共有キャッシュ', appliesTo: 'any', scope: 'target',
  basis: ['RFC 9111', 'OWASP HTTP Headers CS'],
  run(ctx) {
    const out: Finding[] = []; let any = false;
    for (const r of siteResponses(ctx.target)) {
      const cs = (r.headers.get('set-cookie') ?? []).map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, ctx.now));
      if (!cs.length) continue;
      any = true;
      const cc = (r.headers.get('cache-control') ?? []).join(', ').toLowerCase();
      // no-store・private があれば共有キャッシュは保存しない（no-store, s-maxage=0 のような組み合わせも共有キャッシュには残らない）
      const shared = /\bpublic\b|s-maxage/.test(cc) && !/\bno-store\b|\bprivate\b/.test(cc);
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
