// rules/api.ts：第6章 WebAPI（A-01〜A-03、A-07〜A-11。A-04〜A-06は手動確認）
import type { CrossContext, Finding, Rule, RuleContext } from '../model';
import { baseLabel, finalResponse, ownChain, responseKind } from '../parser/target';
import { TOKEN_PARAM_NAMES, paramRegex } from '../mask';
import { header, isLabelText, isNosniff, isPublicClientValue, mk } from './util';

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
    if (!isNosniff(ctx)) out.push(mk(jsonHeaders, ctx, 2, 'medium', 'fail', 'nosniff なし', 'X-Content-Type-Options: nosniff'));
    if (!header(ctx, 'content-security-policy').length) out.push(mk(jsonHeaders, ctx, 3, 'info', 'fail', 'CSPなし', "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'"));
    return out.length ? out : [mk(jsonHeaders, ctx, 'ok', 'info', 'pass', ct, '')];
  } };

// ---- 以下 v0.3 で追加（A-01〜A-03、A-07、A-08、A-10、A-11） ----

/** OWASP API Security Top 10 2023 との対応（画面とエクスポートに表示） */
export const API_TOP10: Record<string, string> = {
  'A-01': 'API2:2023', 'A-02': 'API2:2023・API8:2023', 'A-03': 'API2:2023', 'A-04': 'API4:2023', 'A-05': 'API4:2023', 'A-06': 'API4:2023',
  'A-07': 'API3:2023', 'A-08': 'API8:2023', 'A-09': 'API8:2023', 'A-10': 'API8:2023', 'A-11': 'API5:2023・API9:2023',
};

const status = (ctx: RuleContext) => ownChain(ctx.target)[0]?.status ?? ctx.final?.status ?? 0;

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
    // ステータスが分からない応答（%{header_json} だけで #META response_code がない）は判定しない（第0章 0.2）
    if (!s) return [mk(unauthAccess, ctx, 'na', 'info', 'na', 'ステータスが分からない', '-w に #META response_code=%{response_code} を加えて採取する')];
    if (s >= 200 && s < 300) return [mk(unauthAccess, ctx, 1, 'high', 'fail', `認証なしで HTTP ${s}`, '未認証のリクエストには 401 と WWW-Authenticate を返す（保護すべきデータかを確認する）')];
    if (s >= 300 && s < 400) return [mk(unauthAccess, ctx, 2, 'low', 'fail', `HTTP ${s} → ${ownChain(ctx.target)[0]?.headers.get('location')?.[0] ?? ''}`, 'APIはログイン画面へ転送せず 401 を返す')];
    if (s === 401 && !www) return [mk(unauthAccess, ctx, 'ok', 'info', 'pass', 'HTTP 401（WWW-Authenticate なし）', '')];
    return [mk(unauthAccess, ctx, 'ok', 'info', 'pass', `HTTP ${s}${www ? ` / WWW-Authenticate: ${www}` : ''}`, '')];
  } };

const TOKEN_PARAM = paramRegex(TOKEN_PARAM_NAMES, 'gi');     // マスキングと同じ一覧（mask.ts）
/**
 * 値がトークンらしいか。名前が一致しても、値が状態を伝える短い語（?session=expired、?auth=required、?token=invalid）や
 * 真偽値なら、トークンを URL に入れているのではないので、A-02① にしない。除くのは「小文字の英字（- _ でつないだもの）で16文字以下」と
 * 真偽値だけ。大文字を含む英字だけの値（QxZrTbWmPnLk…）、長い値、数字だけの値（ワンタイムの番号）はトークンとして扱う
 */
const tokenLikeValue = (v: string) => !/^(?:true|false|yes|no|on|off|[01]|none|null)$/i.test(v) && !(/^[a-z]+(?:[-_][a-z]+)*$/.test(v) && v.length <= 16);
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
const PII_CLAIMS = /^(email|email_address|name|given_name|family_name|phone|phone_number|address|birthdate|birthday|tel|zip|postal_code)$/i;
export const jwtClaims: Rule = { id: 'A-03', title: 'JWTの中身', appliesTo: 'any', scope: 'target',
  basis: ['OWASP JWT CS', 'RFC 8725'],
  run(ctx) {
    const found = new Set<string>(ctx.target.sentTokens);
    for (const r of ctx.target.responses) {
      for (const v of r.headers.get('set-cookie') ?? []) for (const m of v.match(/\beyJ[\w-]+\.[\w-]+\.[\w-]*/g) ?? []) found.add(m);
      for (const m of (r.body ?? '').match(/\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]*/g) ?? []) found.add(m);
    }
    const jwts = [...found].map(decodeJwt).filter((x): x is NonNullable<typeof x> => !!x);
    if (!jwts.length) return [];
    const out = [];
    for (const { header, payload } of jwts) {
      // alg は文字列のときだけ使う（{"alg":{"toString":1}} のような細工した JWT で String() が例外を投げ、判定全体が止まった）
      const alg = typeof header.alg === 'string' ? header.alg : '';
      if (/^none$/i.test(alg)) out.push(mk(jwtClaims, ctx, 1, 'high', 'fail', 'alg: none', '署名付きのアルゴリズム（RS256・ES256など）を使い、none を受け付けない'));
      if (payload.exp === undefined) out.push(mk(jwtClaims, ctx, 2, 'medium', 'fail', `exp なし（alg: ${alg}）`, '短い有効期限（exp）を付ける'));
      const pii = Object.keys(payload).filter(k => PII_CLAIMS.test(k));
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
 * - _ . で区切った名前のかけらで見る秘密らしさ（sk-proj-<20文字>、glpat-<20文字>、npm_<36文字>、AIzaSy…-…）。区切りを含むキーは、
 * 区切りのない形だけを見る SECRET_KEY_NAME では一致しない。かけらが英大文字・小文字・数字をすべて含む16文字以上か、
 * 名前全体が英大文字・小文字・数字をすべて含む20文字以上なら、値をキーにしたものとみなす
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
    if (typeof x === 'string' && x && !/[\s\u0080-￿]/.test(x) && !isLabelText(k, x) && !isPublicClientValue(x)) out.add(p);
    secretValuedKeys(x, p, out, depth + 1);
  }
  return out;
}
const SECRET_KEY = /(^|[._[\]])(password|passwd|password_?hash|pass_?hash|secret|client_?secret|api_?key|private_?key|salt|otp_?secret|mfa_?secret)$/i;
// __ で始まるキーは内部属性とみなす。ただし GraphQL の __typename と Mongoose の __v（版の番号）は、ライブラリが必ず付けるもので内部情報ではない
const INTERNAL_KEY = /(^|[._[\]])(is_?admin|is_?super(user)?|is_?staff|role_?id|internal_\w+|_internal\w*|debug\w*|__(?!(?:typename|v)$)\w+)$/i;
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
    if (!s) return [mk(requestContentType, ctx, 'na', 'info', 'na', '応答がない', '')];
    return s >= 200 && s < 300
      ? [mk(requestContentType, ctx, 1, 'medium', 'fail', `Content-Type: text/plain のJSONが HTTP ${s} で処理された`, 'application/json 以外は 415 で拒否する（CSRFの単純リクエスト対策）')]
      : [mk(requestContentType, ctx, 'ok', 'info', 'pass', `HTTP ${s}`, '')];
  } };

export const methodControl: Rule = { id: 'A-11', title: 'メソッド制御・旧版', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API5・API9'],
  run(ctx) {
    const l = ctx.target.label;
    if (!l.startsWith('method-') && !l.startsWith('old-')) return [];
    const s = status(ctx);
    if (!s) return [mk(methodControl, ctx, 'na', 'info', 'na', '応答がない', '')];
    const ok2xx = s >= 200 && s < 300;
    if (l.startsWith('method-')) return ok2xx
      ? [mk(methodControl, ctx, 1, 'medium', 'fail', `想定外のメソッドが HTTP ${s}`, '使わないメソッドは 405 と Allow を返す（権限の確認も行う）')]
      : [mk(methodControl, ctx, 'ok', 'info', 'pass', `HTTP ${s}${ctx.final?.headers.get('allow') ? ` / Allow: ${ctx.final.headers.get('allow')![0]}` : ''}`, '')];
    return ok2xx
      ? [mk(methodControl, ctx, 2, 'medium', 'fail', `旧版のAPIが HTTP ${s}`, '廃止した版は 410 か 404 にする（API一覧で管理する）')]
      : [mk(methodControl, ctx, 'ok', 'info', 'pass', `HTTP ${s}`, '')];
  } };

const normCt = (ct: string) => ct.split(';')[0].trim().toLowerCase() || '(なし)';
export const errorFormat: Rule = { id: 'A-10', title: 'エラー形式', appliesTo: 'any', scope: 'cross',
  basis: ['RFC 9457', 'OWASP API Security Top 10 2023: API8'],
  runCross(x: CrossContext): Finding[] {
    // error-* ラベルの、ステータス400以上で HTML 以外の応答だけを比べる。
    // ブラウザ向けのHTMLのエラーページ（error-url など）は対象外（情報の露出は E-01 で判定）。unauth-* の 401 なども含めない
    // 付け直したラベル（error-api#2）は除く。横断の判定には最初のものだけを使う（parser/target.ts の uniqueLabels）
    const errs = x.targets.filter(t => { const f = finalResponse(t); return t.label.startsWith('error-') && !/#\d+$/.test(t.label) && f && f.status >= 400 && responseKind(t, f) !== 'html'; });
    const base = { item: 'A-10', title: errorFormat.title, target: 'error-*', references: errorFormat.basis, score: 0 };
    if (errs.length < 2) return [{ ...base, ruleId: 'A-10.na', severity: 'info', status: 'na', evidence: '', recommendation: '必要なラベル: error-*（APIのエラー応答を2つ以上）' }];
    const types = new Map<string, string[]>();
    for (const t of errs) { const ct = normCt(finalResponse(t)!.headers.get('content-type')?.[0] ?? ''); types.set(ct, [...(types.get(ct) ?? []), t.label]); }
    return types.size > 1
      ? [{ ...base, ruleId: 'A-10.1', condition: 1, severity: 'info', status: 'fail', evidence: [...types].map(([k, v]) => `${k}: ${v.join(', ')}`).join(' / '), recommendation: 'エラー応答を1つの形式（例：application/problem+json）にそろえる' }]
      : [{ ...base, ruleId: 'A-10.ok', severity: 'info', status: 'pass', evidence: `${[...types.keys()][0]}（${errs.length}件）`, recommendation: '' }];
  } };
