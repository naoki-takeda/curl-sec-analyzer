// rules/api.ts：第6章 WebAPI（A-01〜A-03、A-07〜A-11。A-04〜A-06は手動確認）
import type { CrossContext, Finding, Rule, RuleContext } from '../model';
import { baseLabel, finalResponse, responseKind, sameDocumentHop } from '../parser/target';
import { TOKEN_PARAM_NAMES, paramRegex } from '../mask';
import { NO_BODY_REC, graphqlError as graphqlErrorOf, header, isLabelText, isNosniff, isPlaceholderValue, isPublicClientValue, mk, noDataJson, notSecretFormat, notSecretText } from './util';
import { loginForm } from './html';

export const jsonHeaders: Rule = { id: 'A-09', title: 'JSON応答のヘッダ', appliesTo: 'any', scope: 'target',
  basis: ['OWASP REST Security CS', 'OWASP Secure Headers'],
  run(ctx) {
    const f = ctx.final;
    if (!f) return [mk(jsonHeaders, ctx, 'na', 'info', 'na', '応答がない', '')];
    const ct = header(ctx, 'content-type')[0] ?? '';
    const looksJson = /^\s*[{[]/.test(f.body ?? '');
    if (ctx.responseKind !== 'api') {
      return /^text\/html/i.test(ct) && looksJson
        ? [mk(jsonHeaders, ctx, 1, 'medium', 'fail', `Content-Type: ${ct}（本文はJSON）`, 'JSONは application/json で返す（text/html だとXSSの原因になる）')]
        : [];                                                  // API応答ではないターゲットは適用外
    }
    const out = [];
    // kind=api を明示したターゲットでも、text/html で返していれば①（自動判定では text/html は API 応答にならないため、上の分岐で見る）
    if (/^\s*text\/html/i.test(ct)) out.push(mk(jsonHeaders, ctx, 1, 'medium', 'fail', `Content-Type: ${ct}（API応答）`, 'JSONは application/json で返す（text/html だとXSSの原因になる）'));
    // 本文のない応答（204・304、Location のある 3xx、Content-Length: 0）は、スニッフィングされる本文がない（H-08 と同じ）
    const empty = f.status === 204 || f.status === 304 || (f.status >= 300 && f.status < 400 && f.headers.has('location')) || header(ctx, 'content-length').some(x => /^\s*0\s*$/.test(x));
    if (empty) return out.length ? out : [mk(jsonHeaders, ctx, 'na', 'info', 'na', `HTTP ${f.status}（本文のない応答）`, '本文のある応答（200 など）で採取する（204・304 は対象外）')];
    if (!isNosniff(ctx)) out.push(mk(jsonHeaders, ctx, 2, 'medium', 'fail', 'nosniff なし', 'X-Content-Type-Options: nosniff'));
    if (!header(ctx, 'content-security-policy').length) out.push(mk(jsonHeaders, ctx, 3, 'info', 'fail', 'CSPなし', "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'"));
    return out.length ? out : [mk(jsonHeaders, ctx, 'ok', 'info', 'pass', ct, '')];
  } };

/** OWASP API Security Top 10 2023 との対応（画面とエクスポートに表示） */
export const API_TOP10: Record<string, string> = {
  'A-01': 'API2:2023', 'A-02': 'API2:2023・API8:2023', 'A-03': 'API2:2023', 'A-04': 'API4:2023', 'A-05': 'API4:2023', 'A-06': 'API4:2023',
  'A-07': 'API3:2023', 'A-08': 'API8:2023', 'A-09': 'API8:2023', 'A-10': 'API8:2023', 'A-11': 'API5:2023・API9:2023',
};

// 同じページへの転送（末尾の / への 307 など）はたどった先のステータスで見る。たどれないときは 0（判定しない）にして、呼び出し側で na にする
const status = (ctx: RuleContext) => { const { hop, unfollowed } = sameDocumentHop(ctx.target); return unfollowed ? 0 : hop?.status ?? ctx.final?.status ?? 0; };
const UNFOLLOWED = (ctx: RuleContext) => sameDocumentHop(ctx.target).unfollowed;
/**
 * API の URL に HTML の画面を 200 で返したか（どのパスにも index.html を返す SPA、ログイン画面）。A-01・A-11 では、データを返したかが
 * 分からないので①②にしない（E-05 の HTML の 200 と同じ考え方）。ログインのフォームなら、認証を求めたのと同じ
 */
const htmlPage = (ctx: RuleContext): 'login' | 'html' | 'unknown' | undefined => {
  const r = sameDocumentHop(ctx.target).hop ?? ctx.final;
  const ct = r?.headers.get('content-type')?.[0] ?? ''; const b = r?.body ?? '';
  // HTML の画面とみなすのは、本文が HTML の形のものだけ。Content-Type が text/html でも、本文が JSON・CSV・平文のもの（PHP の既定の
  // Content-Type のまま返す API）は HTML の画面ではない
  const htmlCt = /^\s*(?:text\/html|application\/xhtml\+xml)/i.test(ct);
  // 本文を採取していない text/html（curl -I、-o /dev/null）は、SPA の画面かデータかが分からない
  if (!b.trim()) return htmlCt ? 'unknown' : undefined;
  // 本文が JSON（{・[ で始まる）なら HTML の画面ではない（JSON の文字列に入れた "<!DOCTYPE html>…" があっても）
  if (/^\s*[{[]/.test(b)) return undefined;
  // 先頭の 1KB に <!doctype html>・<html があるもの（PHP の Notice の行のあとに続く HTML も）か、タグで始まるもの
  const head = b.slice(0, 1024);
  if (!/<!doctype html|<html\b/i.test(head) && !(htmlCt && /^\s*<(?!\?xml\b)/i.test(b))) return undefined;
  return loginForm(b) ? 'login' : 'html';
};
/** 判定に使う応答（同じページへの転送をたどった先）の本文。データのない JSON・GraphQL のエラー（util.ts）をこの本文で見る */
const hopBody = (ctx: RuleContext) => (sameDocumentHop(ctx.target).hop ?? ctx.final)?.body;
const emptyJson = (ctx: RuleContext): boolean => noDataJson(hopBody(ctx));
const graphqlError = (ctx: RuleContext) => graphqlErrorOf(hopBody(ctx));

/**
 * A-01③：HTTP の応答で Basic 認証を求めているか。-L の転送をたどり、URL が http のホップの WWW-Authenticate だけを見る
 * （http から https に転送した先の Basic は HTTPS なので対象外）。チャレンジは複数のヘッダ・カンマ区切りのどれにあってもよい
 */
function basicOverHttp(ctx: RuleContext): string | undefined {
  let url = ctx.target.url ?? ctx.target.meta.url_effective;
  for (const r of ctx.chain) {
    if (!url || !/^http:/i.test(url)) return undefined;
    const www = r.headers.get('www-authenticate') ?? [];
    if (www.some(v => /(?:^|,)\s*basic\b/i.test(v))) return www.join(', ');
    const loc = r.headers.get('location')?.[0];
    if (r.kind !== 'redirect' || !loc) return undefined;
    try { url = new URL(loc, url).href; } catch { return undefined; }
  }
  return undefined;
}

export const unauthAccess: Rule = { id: 'A-01', title: '未認証アクセス', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API2'],
  run(ctx) {
    const f = ctx.final; if (!f) return [];
    const www = (f.headers.get('www-authenticate') ?? []).join(', ');
    const basic = ctx.isHttps === false ? basicOverHttp(ctx) : undefined;
    if (basic) return [mk(unauthAccess, ctx, 3, 'high', 'fail', `HTTPで WWW-Authenticate: ${basic}`, 'Basic認証はHTTPSだけで受け付ける')];
    if (!ctx.target.label.startsWith('unauth-')) return [];   // ①②は認証情報を付けずに送ったターゲット（unauth-*）だけ
    if (ctx.target.sentAuth) return [mk(unauthAccess, ctx, 'na', 'info', 'na', '認証情報（Cookie・Authorization）を送っている', 'unauth-* は認証情報を付けずに採取する')];
    const s = status(ctx);
    if (UNFOLLOWED(ctx)) return [mk(unauthAccess, ctx, 'na', 'info', 'na', '同じページへの転送（末尾の / など）。転送先を採取していない', '-L を付けて、転送先まで採取し直す')];
    // ステータスが分からない応答（%{header_json} だけで #META response_code がない）は判定しない（第0章 0.2）
    if (!s) return [mk(unauthAccess, ctx, 'na', 'info', 'na', 'ステータスが分からない', '-w に #META response_code=%{response_code} を加えて採取する')];
    if (s >= 200 && s < 300) {
      const page = htmlPage(ctx);
      // ログインのフォームがあっても合格にはしない（ゲスト用のログイン欄と利用者のデータを並べる画面がある）
      if (page === 'unknown') return [mk(unauthAccess, ctx, 'na', 'info', 'na', `HTTP ${s}（text/html。本文を採取していないので、データを返したかは分からない）`, NO_BODY_REC)];
      if (page) return [mk(unauthAccess, ctx, 'na', 'info', 'na', `HTTP ${s}（HTML の画面${page === 'login' ? '。ログインのフォームを含む' : '。どのパスにも同じ画面を返す SPA の可能性'}。データを返したかは分からない）`, 'API の URL（JSON を返すもの）で採取し直す')];
      // GraphQL は認証のエラーも 200 で返す（{"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}],"data":{"me":null}}）。データを返していない
      const gql = graphqlError(ctx);
      if (gql === 'denied') return [mk(unauthAccess, ctx, 'ok', 'info', 'pass', `HTTP ${s}（GraphQL の認証エラー。データは null）`, '')];
      if (gql) return [mk(unauthAccess, ctx, 'na', 'info', 'na', `HTTP ${s}（GraphQL のエラー。データは null で、認証で断られたかは分からない）`, '認証が必要なクエリ（me など）で採取し直す')];
      // データのない JSON（{}・[]・null・値がすべて null のもの。NextAuth の未認証の /api/auth/session は {} を返す）は、保護データを返していない
      if (emptyJson(ctx)) return [mk(unauthAccess, ctx, 'na', 'info', 'na', `HTTP ${s}（データのない JSON。保護データを返したかは分からない）`, '認証が必要なデータを返す API の URL で採取し直す')];
      // 本文のない応答（204、content-length: 0）はデータを返していない。本文を採取していない（-o /dev/null）なら、データを返したかが分からない
      if (!hopBody(ctx)?.trim()) {
        const empty = s === 204 || header(ctx, 'content-length')[0]?.trim() === '0';
        return [mk(unauthAccess, ctx, 'na', 'info', 'na', empty ? `HTTP ${s}（本文のない応答。データを返していない）` : `HTTP ${s}（本文を採取していないので、データを返したかは分からない）`,
          empty ? '認証が必要なデータを返す API の URL で採取し直す' : NO_BODY_REC)];
      }
      return [mk(unauthAccess, ctx, 1, 'high', 'fail', `認証なしで HTTP ${s}`, '未認証のリクエストには 401 と WWW-Authenticate を返す（保護すべきデータかを確認する）')];
    }
    if (s >= 300 && s < 400) return [mk(unauthAccess, ctx, 2, 'low', 'fail', `HTTP ${s} → ${sameDocumentHop(ctx.target).hop?.headers.get('location')?.[0] ?? ''}`, 'APIはログイン画面へ転送せず 401 を返す')];
    // 合格は、認証を求めた・断られた応答（401・403）と、メソッドで断られた応答（405）だけ。404（URL の誤りの可能性）と 5xx（認証の前に
    // 落ちた可能性）、400・429 などは、認証で守られているかが分からない（A-08 と同じ考え方）
    if (s !== 401 && s !== 403 && s !== 405) return [mk(unauthAccess, ctx, 'na', 'info', 'na', `HTTP ${s}（認証で守られているかは分からない）`, '存在する API の URL で、認証情報を付けずに採取し直す')];
    if (s === 401 && !www) return [mk(unauthAccess, ctx, 'ok', 'info', 'pass', 'HTTP 401（WWW-Authenticate なし）', '')];
    return [mk(unauthAccess, ctx, 'ok', 'info', 'pass', `HTTP ${s}${www ? ` / WWW-Authenticate: ${www}` : ''}`, '')];
  } };

const TOKEN_PARAM = paramRegex(TOKEN_PARAM_NAMES, 'gi');     // マスキングと同じ一覧（mask.ts）
/**
 * 値がトークンらしいか。名前が一致しても、値が状態を伝える短い語（?session=expired、?auth=required、?token=invalid）や
 * 真偽値なら、トークンを URL に入れているのではないので、A-02① にしない。除くのは「小文字の英字（- _ でつないだもの）で16文字以下」、
 * 真偽値、5桁以下の数字（?session=12 のような番号）だけ。大文字を含む英字だけの値（QxZrTbWmPnLk…）、長い値、
 * 6桁以上の数字（ワンタイムの番号）はトークンとして扱う
 */
const tokenLikeValue = (v: string) => !/^(?:true|false|yes|no|on|off|[01]|none|null)$/i.test(v) && !(/^[a-z]+(?:[-_][a-z]+)*$/.test(v) && v.length <= 16) && !/^\d{1,5}$/.test(v);
const hasTokenParam = (u: string) => [...u.matchAll(TOKEN_PARAM)].some(m => tokenLikeValue(m[2]));
export const tokenExposure: Rule = { id: 'A-02', title: 'トークンの露出', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API2', 'RFC 6750 2.3'],
  run(ctx) {
    if (!ctx.final) return [];
    const out = [];
    const urls = [ctx.target.url ?? '', ...ctx.target.responses.flatMap(r => r.headers.get('location') ?? [])];
    const inUrl = urls.find(hasTokenParam);
    if (inUrl) out.push(mk(tokenExposure, ctx, 1, 'high', 'fail', inUrl, 'トークンはURLに入れず Authorization ヘッダで送る（ログやRefererに残る）'));
    const body = ctx.final.body ?? '';
    // トークンを発行するエンドポイント（/oauth/token、/connect/token、Keycloak の …/openid-connect/token）は、refresh_token を返すのが仕事
    const tokenEndpoint = (() => { try { return /\/token\/?$/i.test(new URL(ctx.target.url ?? '').pathname); } catch { return false; } })();
    if (!['login', 'pre-login'].includes(baseLabel(ctx.target.label)) && !tokenEndpoint && /"refresh_token"\s*:\s*"[^"]{16,}"/.test(body))
      out.push(mk(tokenExposure, ctx, 2, 'medium', 'fail', '本文に refresh_token（値は表示しない）', 'ログイン・トークン発行以外の応答で長期トークンを返さない'));
    return out.length ? out : [mk(tokenExposure, ctx, 'ok', 'info', 'pass', 'URL・Location・本文にトークンなし', '')];
  } };

const b64url = (s: string) => { try { return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0)))) as Record<string, unknown>; } catch { return undefined; } };
/** JWT の header と payload をデコードする（署名は検証しない。値は画面に出さない） */
export function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | undefined {
  const [h, p] = token.split('.');
  const header = h ? b64url(h) : undefined, payload = p ? b64url(p) : undefined;
  return header && payload ? { header, payload } : undefined;
}
const ID_TOKEN_FIELD = /["']?\bid_token["']?\s*[:=]\s*["']?(eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*)/g;
const PII_CLAIMS = /^(email|email_address|name|given_name|family_name|phone|phone_number|address|birthdate|birthday|tel|zip|postal_code)$/i;
export const jwtClaims: Rule = { id: 'A-03', title: 'JWTの中身', appliesTo: 'any', scope: 'target',
  basis: ['OWASP JWT CS', 'RFC 8725'],
  run(ctx) {
    const found = new Set<string>(ctx.target.sentTokens);
    const idTokens = new Set<string>();   // id_token の欄・Cookie の値として返した JWT
    for (const r of ctx.target.responses) {
      // JWT の始まりは直前が英数字・ハイフンでないところだけ（\b は「-eyJ」の繰り返しの各位置から並びの終わりまで読み直し、2乗の時間になる）
      for (const v of r.headers.get('set-cookie') ?? []) for (const m of v.match(/(?<![\w-])eyJ[\w-]+\.[\w-]+\.[\w-]*/g) ?? []) found.add(m);
      for (const m of (r.body ?? '').match(/(?<![\w-])eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*/g) ?? []) found.add(m);
      for (const v of [r.body ?? '', ...(r.headers.get('set-cookie') ?? [])]) for (const m of v.matchAll(ID_TOKEN_FIELD)) idTokens.add(m[1]);
    }
    const jwts = [...found].flatMap(token => { const d = decodeJwt(token); return d ? [{ ...d, token }] : []; });
    if (!jwts.length) return [];
    const out = [];
    for (const { header, payload, token } of jwts) {
      // alg は文字列のときだけ使う（{"alg":{"toString":1}} のような細工した JWT で例外を投げないため）
      const alg = typeof header.alg === 'string' ? header.alg : '';
      if (/^none$/i.test(alg)) out.push(mk(jwtClaims, ctx, 1, 'high', 'fail', 'alg: none', '署名付きのアルゴリズム（RS256・ES256など）を使い、none を受け付けない'));
      if (payload.exp === undefined) out.push(mk(jwtClaims, ctx, 2, 'medium', 'fail', `exp なし（alg: ${alg}）`, '短い有効期限（exp）を付ける'));
      // OpenID Connect の ID トークン（id_token の欄で返したもの、または iss・aud と nonce・at_hash があり typ が Bearer でないもの）は、仕様上ユーザーの
      // 属性を運ぶものなので③にしない。azp・auth_time はアクセストークン（Keycloak・Entra ID）にもあるので、ID トークンの印にしない
      const idToken = idTokens.has(token) || (payload.iss !== undefined && payload.aud !== undefined && payload.typ !== 'Bearer' && (payload.nonce !== undefined || payload.at_hash !== undefined));
      const pii = idToken ? [] : Object.keys(payload).filter(k => PII_CLAIMS.test(k));
      if (pii.length) out.push(mk(jwtClaims, ctx, 3, 'medium', 'fail', `個人情報らしきクレーム: ${pii.join(', ')}（値は表示しない）`, 'JWTに個人情報を入れない（JWTは暗号化されず誰でも読める）'));
    }
    return out.length ? out : [mk(jwtClaims, ctx, 'ok', 'info', 'pass', `JWT ${jwts.length}件：alg・exp・クレームに問題なし`, '')];
  } };

/**
 * 証跡に出すキーの名前。データの値をキーにしたもの（{"users":{"alice@example.com":{…}}}、{"keys":{"sk_live_…":{…}}}、ID）は「*」にする。
 * 識別子らしい名前（英数字か _ で始まる128文字までの英数字・_・-・.・$。Spring の spring.datasource.password のようにドットを含むものも残す）で、
 * 秘密の値・IDらしくない（数字だけ、数字を含む区切りのない16文字以上の英数字、24文字以上の16進数、AWS のアクセスキー、sk_live_・ghp_ などの接頭辞）
 * ものだけを残す。判定（SECRET_KEY・INTERNAL_KEY）は元のキーで行い、これは証跡を作るときだけ使う
 */
const SECRET_KEY_NAME = /^(?:[spr]k_(?:live|test)_|whsec_|gh[pousr]_|xox[abprs]-)|^[0-9a-f-]{24,}$|^(?:AKIA|ASIA)[0-9A-Z]{16}$|^\d+$|^(?=[A-Za-z0-9]{16,}$)(?=.*\d)/i;
/**
 * 区切り（- _ .）を含む名前の秘密らしさ（sk-proj-<20文字>、glpat-<20文字>、npm_<36文字>、AIzaSy…-…）。SECRET_KEY_NAME は区切りのない形だけを見る。
 * 既知の接頭辞か、かけらが英大文字・小文字・数字をすべて含む16文字以上か、名前全体が英大文字・小文字・数字をすべて含む20文字以上なら、値をキーにしたものとみなす
 */
const mixed = (p: string) => /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p);
const secretKeyName = (k: string) => SECRET_KEY_NAME.test(k) || /^(?:sk-(?:proj|live|test|svcacct)-|glpat-|npm_|AIza)/.test(k)
  || k.split(/[-_.]/).some(p => p.length >= 16 && mixed(p)) || (k.length >= 20 && mixed(k));
export const safeKey = (k: string) => (/^[A-Za-z0-9_$][\w$.-]{0,127}$/.test(k) && !secretKeyName(k) ? k : '*');
/** JSONのキーを「a.b[0].c」の形で列挙する */
export function jsonKeys(v: unknown, prefix = '', out: string[] = [], depth = 0): string[] {
  if (depth > 20 || out.length > 2000) return out;
  if (Array.isArray(v)) v.slice(0, 50).forEach((x, i) => jsonKeys(x, `${prefix}[${i}]`, out, depth + 1));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { const p = prefix ? `${prefix}.${k}` : k; out.push(p); jsonKeys(x, p, out, depth + 1); }
  return out;
}
/** 証跡に出すキーの経路（配列の番号は [] にそろえる）。元の経路（jsonKeys と同じ形で [] にそろえたもの）から、safeKey を通した経路への対応 */
function shownPaths(v: unknown, raw = '', shown = '', out = new Map<string, string>(), depth = 0): Map<string, string> {
  if (depth > 20 || out.size > 2000) return out;
  if (Array.isArray(v)) v.slice(0, 50).forEach(x => shownPaths(x, `${raw}[]`, `${shown}[]`, out, depth + 1));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) {
    const r = raw ? `${raw}.${k}` : k, s = shown ? `${shown}.${safeKey(k)}` : safeKey(k);
    out.set(r, s); shownPaths(x, r, s, out, depth + 1);
  }
  return out;
}
/**
 * 値が「秘密情報らしい文字列」のキー（配列の番号は [] にそろえる）。空白や ASCII 以外の文字を含む文字列は画面の文言（i18n の
 * {"password":"パスワード"} など）とみなし、null・数値・真偽値・オブジェクトも値を露出していないので除く
 */
export function secretValuedKeys(v: unknown, prefix = '', out = new Set<string>(), depth = 0): Set<string> {
  if (depth > 20 || out.size > 2000) return out;
  if (Array.isArray(v)) v.slice(0, 50).forEach(x => secretValuedKeys(x, `${prefix}[]`, out, depth + 1));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) {
    const p = prefix ? `${prefix}.${k}` : k;
    // 検索専用のキー（searchOnlyApiKey・search_api_key と、DocSearch の apiKey）は、ブラウザから使う公開のキー（HTML の docsearch と同じ）。
    // Algolia・Meilisearch・Typesense の apiKey は、管理用・マスターのキーも同じ名前なので除かない
    if (typeof x === 'string' && (/^search_?(?:only_?)?(?:api_?)?key$/i.test(k) || (/(?:^|\.)docsearch(?:\[\])?$/i.test(prefix) && /^api_?key$/i.test(k)))) continue;
    // 秘密の値ではないもの（E-09 と同じ判定）：画面の文言、公開のキー、伏せ字、状態の語、入力の検証の規則・autocomplete の値・正規表現、
    // パス・URL・項目の名前（{"menu":{"password":"/settings/password"}}）、errors・validation の直下の値（errors.password の TOO_SHORT）
    if (typeof x === 'string' && x && !/[\s\u0080-￿]/.test(x) && !isLabelText(k, x) && !isPublicClientValue(x) && !isPlaceholderValue(x) && !stateWord(x)
      && !notSecretFormat(x) && !notSecretText(x) && !/(?:^|\.)(?:errors?|validation(?:_?errors)?)(?:\[\])?$/i.test(prefix)) out.add(p);
    secretValuedKeys(x, p, out, depth + 1);
  }
  return out;
}
/**
 * 秘密の値を入れるキーか。キーの最後の部分を語（_ - とキャメルケースの境目）に分けて見る：password・passwd・passphrase を含むもの
 * （Rails の password_digest、hashedPassword・dbPassword・userPassword）と、secret・api_key・private_key・secret_key・secret_access_key などで
 * 終わるもの（stripeSecretKey・awsSecretAccessKey）。最後の語が状態・設定を表すもの（password_policy・password_updated_at・passwordLength）と、
 * has・is で始まるもの（hasPassword）は除く
 */
const NOT_SECRET_LAST = new Set(['policy', 'policies', 'updated', 'changed', 'at', 'on', 'date', 'time', 'length', 'len', 'expiry', 'expires', 'expired', 'expiration',
  'required', 'reset', 'set', 'hint', 'strength', 'rules', 'rule', 'min', 'max', 'last', 'age', 'count', 'type', 'method', 'enabled', 'exists', 'status', 'state', 'version', 'url', 'link', 'id',
  // 設定・画面の部品・パスの名前（passwordPattern・changePasswordUri・passwordEncoder・passwordComplexity・forgotPasswordPath・password_regex）
  'uri', 'path', 'route', 'endpoint', 'page', 'encoder', 'encoding', 'algorithm', 'algo', 'complexity', 'pattern', 'regex', 'regexp', 'format', 'validator',
  'validation', 'validators', 'field', 'label', 'placeholder', 'input', 'form', 'mode', 'prompt', 'message', 'msg', 'text', 'title', 'error', 'errors', 'help', 'requirements', 'options', 'config', 'settings',
  // ハッシュの方式・変更した人（passwordScheme・password_hasher・password_changed_by・passwordRounds）
  'scheme', 'schemes', 'hasher', 'kdf', 'cost', 'rounds', 'iterations', 'by',
  // password_salt は②（内部属性。INTERNAL_KEY）で数える（salt は秘密ではない。事前認証の API が返す設計もある）
  'salt']);
// 操作と password の2語の名前（forgotPassword・lostPassword：画面・API のパスを入れる）。resetPassword・changePassword・updatePassword は、
// 管理者がリセットした仮のパスワードや、送ったパスワードを返す API があるので①のまま。resetAdminPassword・forgotPasswordToken も①のまま
const PASSWORD_ACTION = new Set(['forgot', 'forgotten', 'lost', 'recover', 'show', 'toggle', 'request']);
// 公開して使う API キー（publicApiKey、browserApiKey、Supabase の anonKey）。値をブラウザに渡す設計。search は語として除くと、
// Bing・Azure AI Search・Elastic などのサーバ側の秘密のキー（azureSearchApiKey）を見逃すので、Algolia などの検索専用キーの名前だけ
const PUBLIC_KEY_WORD = new Set(['public', 'publishable', 'anon', 'browser']);
const SEARCH_ONLY_KEY = /^(?:algolia_|typesense_|meili(?:search)?_)?search(?:_only)?_api_?key$/;
const SECRET_KEY = { test: (path: string): boolean => {
  const last = path.split(/[.[\]]+/).filter(Boolean).pop() ?? '';   // キーの区切りは . と []（_ はキーの中の語の区切り）
  // 大文字の略語の並びも、続く語との境目で分ける（DBPassword・SMTPPassword・AWSSecretKey を1語の dbpassword などと読まない）
  const words = last.replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[_-]+/).filter(Boolean);
  if (!words.length || NOT_SECRET_LAST.has(words[words.length - 1]) || words[0] === 'has' || words[0] === 'is') return false;
  const j = words.join('_');
  if (words.length === 2 && PASSWORD_ACTION.has(words[0]) && /^pass(?:word|wd|phrase)$/.test(words[1])) return false;
  if (/(?:^|_)(?:api_?key|apikey)$/.test(j) && (words.some(w => PUBLIC_KEY_WORD.has(w)) || SEARCH_ONLY_KEY.test(j))) return false;
  // Django のフォームの password1・password2・new_password1、db_pwd・user_pwd（pwd だけの名前は、環境変数の PWD（作業ディレクトリ）と
  // 区別できないので見ない）、WordPress の user_pass などのアカウントの _pass
  return words.some(w => w === 'password' || w === 'passwd' || w === 'passphrase' || /^pass(?:word|wd)\d$/.test(w)) || (words.length > 1 && words.includes('pwd'))
    || /(?:^|_)(?:pass_?hash|secret|api_?key|apikey|private_?key|secret_?key|secret_access_key|access_secret|otp_secret|mfa_secret)$/.test(j)
    // Rails の secret_key_base・secret_token・master_key、Laravel の remember_token（APP_KEY は Pusher の公開の app_key と区別できないので見ない）、
    // Supabase の service_role_key（service_role だけはロールの名前（"viewer"）と区別できないので見ない）
    || /(?:^|_)(?:secret_key_base|secret_token|master_key|service_role_key|remember_token)$/.test(j)
    || /^(?:user|db|database|smtp|mail|ftp|login|admin)_pass$/.test(j);
} };
/**
 * 状態を表す短い語・真偽値の文字列（{"password":"set"}、{"otp_secret":"configured"}、{"password":"true"}）。値を出していないので①にしない。
 * 決まった状態の語と真偽値だけ（英小文字の語をすべて除くと、英小文字だけのパスワード（"hunter"）を見逃す）
 */
const stateWord = (v: string) => /^(?:true|false|yes|no|on|off|[01]|none|null|nil|empty|set|unset|not[-_ ]?set|configured|unconfigured|enabled|disabled|required|optional|present|missing|active|inactive|pending|changed|unchanged|valid|invalid|expired)$/i.test(v);
// __ で始まるキーは内部属性とみなす。ただし GraphQL の __typename と Mongoose の __v（版の番号）は、ライブラリが必ず付けるもので内部情報ではない
const INTERNAL_KEY = /(^|[._[\]])(is_?admin|is_?super(user)?|is_?staff|role_?id|internal_\w+|_internal\w*|debug\w*|salt|password_?salt|__(?!(?:typename|v)$)\w+)$/i;
export const excessiveData: Rule = { id: 'A-07', title: '過剰なデータ露出', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API3'],
  run(ctx) {
    const f = ctx.final;
    if (!f?.body || ctx.responseKind !== 'api') return [];
    let data: unknown;
    try { data = JSON.parse(f.body); } catch { return [mk(excessiveData, ctx, 'na', 'info', 'na', 'JSONを解析できない（64KBを超えて切れた可能性）', '')]; }
    const keys = jsonKeys(data).map(k => k.replace(/\[\d+\]/g, '[]'));
    const uniq = [...new Set(keys)];
    const valued = secretValuedKeys(data);
    const secret = uniq.filter(k => SECRET_KEY.test(k) && valued.has(k)), internal = uniq.filter(k => INTERNAL_KEY.test(k));
    const out = [];
    // 証跡のキーの経路は、データの値をキーにした部分（メールアドレス・秘密の値・ID）を「*」にしたもの
    const paths = shownPaths(data);
    const show = (ks: string[]) => [...new Set(ks.map(k => paths.get(k) ?? '*'))].slice(0, 8).join(', ');
    if (secret.length) out.push(mk(excessiveData, ctx, 1, 'high', 'fail', `キー: ${show(secret)}（値は表示しない）`, 'パスワードやシークレットを応答に含めない（応答用のDTOで必要な項目だけ返す）'));
    if (internal.length) out.push(mk(excessiveData, ctx, 2, 'medium', 'fail', `キー: ${show(internal)}`, '内部属性を応答に含めない'));
    return out.length ? out : [mk(excessiveData, ctx, 'ok', 'info', 'pass', `キー${uniq.length}種に秘密情報・内部属性らしきものなし`, '')];
  } };

export const requestContentType: Rule = { id: 'A-08', title: 'リクエストのContent-Type', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API8', 'OWASP CSRF Prevention CS'],
  run(ctx) {
    if (baseLabel(ctx.target.label) !== 'ctype') return [];
    const s = status(ctx);
    if (UNFOLLOWED(ctx)) return [mk(requestContentType, ctx, 'na', 'info', 'na', '同じページへの転送（末尾の / など）。転送先を採取していない', '-L を付けて、転送先まで採取し直す')];
    if (!s) return [mk(requestContentType, ctx, 'na', 'info', 'na', '応答がない', '')];
    // 認証・認可・パスで断られた応答（401・403・404）は、Content-Type を確かめるところまで届いていない
    if (s === 401 || s === 403 || s === 404) return [mk(requestContentType, ctx, 'na', 'info', 'na', `HTTP ${s}（Content-Type を確かめる前に断られた）`, '認証情報を付けて、存在する API の URL で採取し直す')];
    if (s >= 200 && s < 300)
      return [mk(requestContentType, ctx, 1, 'medium', 'fail', `Content-Type: text/plain のJSONが HTTP ${s} で処理された`, 'application/json 以外は 415 で拒否する（CSRFの単純リクエスト対策）')];
    // 合格は、Content-Type で断ったと分かる応答（415）と、それ以外の 4xx（405 を除く）。ログイン画面への転送（3xx）・5xx・405 は、
    // Content-Type を確かめるところまで届いたかが分からない（A-11 と同じ考え方）
    if ((s >= 300 && s < 400) || s >= 500 || s === 405)
      return [mk(requestContentType, ctx, 'na', 'info', 'na', `HTTP ${s}（Content-Type を確かめるところまで届いたかが分からない）`, '認証情報を付けて、存在する API の URL で採取し直す')];
    return [mk(requestContentType, ctx, 'ok', 'info', 'pass', `HTTP ${s}`, '')];
  } };

const A11_REC = '認証情報を付けて採取し直す（401・403・ログイン画面への転送では、認証の内側で動くかが分からない）';
export const methodControl: Rule = { id: 'A-11', title: 'メソッド制御・旧版', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API5・API9'],
  run(ctx) {
    const l = ctx.target.label;
    if (!l.startsWith('method-') && !l.startsWith('old-')) return [];
    const s = status(ctx);
    if (UNFOLLOWED(ctx)) return [mk(methodControl, ctx, 'na', 'info', 'na', '同じページへの転送（末尾の / など）。転送先を採取していない', '-L を付けて、転送先まで採取し直す')];
    if (!s) return [mk(methodControl, ctx, 'na', 'info', 'na', '応答がない', '')];
    const ok2xx = s >= 200 && s < 300;
    // HTML の画面の 200（SPA の index.html・ログイン画面）は、そのメソッド・旧版の API が動いたかが分からない
    const page = ok2xx ? htmlPage(ctx) : undefined;
    if (page === 'unknown') return [mk(methodControl, ctx, 'na', 'info', 'na', `HTTP ${s}（text/html。本文を採取していないので、API が処理したかは分からない）`, NO_BODY_REC)];
    if (page) return [mk(methodControl, ctx, 'na', 'info', 'na', `HTTP ${s}（${page === 'login' ? 'ログイン画面' : 'HTML の画面。どのパスにも同じ画面を返す SPA の可能性'}。API が処理したかは分からない）`, 'API の URL（JSON を返すもの）で採取し直す')];
    // 合格にするのは、メソッド・版そのものを断った応答だけ（メソッドは 405・501、旧版は 404・410）。401・403（認証で断られた。認証の内側で
    // 動くかは分からない）、3xx（ログイン画面への転送など）、そのほかの 4xx・5xx は na（A-08 の 401・403・404 と同じ考え方）
    if (l.startsWith('method-')) return ok2xx
      ? [mk(methodControl, ctx, 1, 'medium', 'fail', `想定外のメソッドが HTTP ${s}`, '使わないメソッドは 405 と Allow を返す（権限の確認も行う）')]
      : s === 405 || s === 501 ? [mk(methodControl, ctx, 'ok', 'info', 'pass', `HTTP ${s}${ctx.final?.headers.get('allow') ? ` / Allow: ${ctx.final.headers.get('allow')![0]}` : ''}`, '')]
      : [mk(methodControl, ctx, 'na', 'info', 'na', `HTTP ${s}（メソッドを断ったかは分からない）`, A11_REC)];
    return ok2xx
      ? [mk(methodControl, ctx, 2, 'medium', 'fail', `旧版のAPIが HTTP ${s}`, '廃止した版は 410 か 404 にする（API一覧で管理する）')]
      : s === 404 || s === 410 ? [mk(methodControl, ctx, 'ok', 'info', 'pass', `HTTP ${s}`, '')]
      : [mk(methodControl, ctx, 'na', 'info', 'na', `HTTP ${s}（旧版が動いているかは分からない）`, A11_REC)];
  } };

const normCt = (ct: string) => ct.split(';')[0].trim().toLowerCase() || '(なし)';
export const errorFormat: Rule = { id: 'A-10', title: 'エラー形式', appliesTo: 'any', scope: 'cross',
  basis: ['RFC 9457', 'OWASP API Security Top 10 2023: API8'],
  runCross(x: CrossContext): Finding[] {
    // error-* ラベルの、ステータス400以上で HTML 以外の応答だけを比べる。
    // ブラウザ向けのHTMLのエラーページ（error-url など）は対象外（情報の露出は E-01 で判定）。unauth-* の 401 なども含めない
    // 付け直したラベル（error-api#2）は除く。横断の判定には最初のものだけを使う（parser/target.ts の uniqueLabels）
    const errs = x.targets.filter(t => { const f = finalResponse(t); return t.label.startsWith('error-') && !/#\d+$/.test(t.label) && f && f.status >= 400 && responseKind(t, f) !== 'html'; });
    const base = { item: 'A-10', title: errorFormat.title, target: 'error-*', references: errorFormat.basis };
    if (errs.length < 2) return [{ ...base, ruleId: 'A-10.na', severity: 'info', status: 'na', evidence: '', recommendation: '必要なラベル: error-*（APIのエラー応答を2つ以上）' }];
    const types = new Map<string, string[]>();
    for (const t of errs) { const ct = normCt(finalResponse(t)!.headers.get('content-type')?.[0] ?? ''); types.set(ct, [...(types.get(ct) ?? []), t.label]); }
    return types.size > 1
      ? [{ ...base, ruleId: 'A-10.1', condition: 1, severity: 'info', status: 'fail', evidence: [...types].map(([k, v]) => `${k}: ${v.join(', ')}`).join(' / '), recommendation: 'エラー応答を1つの形式（例：application/problem+json）にそろえる' }]
      : [{ ...base, ruleId: 'A-10.ok', severity: 'info', status: 'pass', evidence: `${[...types.keys()][0]}（${errs.length}件）`, recommendation: '' }];
  } };
