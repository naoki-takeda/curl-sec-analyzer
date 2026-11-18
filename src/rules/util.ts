import type { Finding, Rule, RuleContext, Severity, Status } from '../model';

export function mk(rule: Rule, ctx: RuleContext, cond: number | 'ok' | 'na', severity: Severity, status: Status,
                   evidence: string, recommendation: string, extra: Partial<Finding> = {}): Finding {
  return { ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined,
           title: rule.title, severity, status, target: ctx.target.label, evidence, recommendation,
           references: rule.basis, ...extra };
}

export const header = (ctx: RuleContext, name: string): string[] => ctx.final?.headers.get(name) ?? [];

/**
 * CSP のヘッダ値を、ポリシーごとに分ける。1つのヘッダ値の中のカンマは、ポリシーの区切り（CSP3 の serialized-policy-list）。
 * プロキシが2つのヘッダを「a, b」にまとめた場合も同じ。分けないと、カンマのあとのディレクティブ（, frame-ancestors 'none'）を
 * 前のディレクティブの値として読み、H-06① などを誤検知する
 */
export const splitPolicies = (values: string[]): string[] => values.flatMap(v => v.split(',')).map(s => s.trim()).filter(Boolean);
/**
 * 強制モードの CSP（ポリシーごと）。ディレクティブが1つもないかけら（report-uri の URL の中のカンマのあとの「2」、
 * 「img-src 'self', data:」の「data:」）は、ブラウザも何も制限しないポリシーとして扱うので除く（H-03③ は rules/headers.ts でヘッダ値ごとに見る）
 */
export const cspPolicies = (ctx: RuleContext): string[] => splitPolicies(header(ctx, 'content-security-policy')).filter(p => parseCsp(p).size > 0);
/**
 * X-Content-Type-Options が nosniff か。Fetch Standard の「determine nosniff」のとおり、すべての値をカンマで分けた最初の値で見る
 * （プロキシが付け足した「nosniff, nosniff」も nosniff。H-08 と A-09② で同じ読み方にする）
 */
export const isNosniff = (ctx: RuleContext): boolean =>
  header(ctx, 'x-content-type-options').join(',').split(',')[0].trim().toLowerCase() === 'nosniff';

// 静的リソース（JS・CSS・画像・フォント）と、誰にでも同じ内容を返す公開ファイル（robots.txt、sitemap.xml、/.well-known/ の下など）
// 拡張子はパスの末尾だけで見る（クエリの ?avatar=me.png・?format=x.css で、利用者ごとの API を静的リソースとし、H-12①（高）を見逃さない）
// 動画・音声・WebAssembly・旧式のフォント（eot）も含める（ログインした HAR で、Cookie を送っただけの mp4・wasm を機密応答として H-12①（高）にした）
const STATIC_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|map|wasm|mp4|m4v|webm|ogv|mov|mp3|m4a|aac|oga|ogg|opus|wav|flac)$/i;
const STATIC_CT = /^\s*(?:text\/css|(?:text|application)\/(?:x-)?(?:java|ecma)script|image\/|font\/|video\/|audio\/|application\/wasm\b)/i;
const PUBLIC_FILE = /\/(?:robots\.txt|sitemap[\w-]*\.xml(?:\.gz)?|favicon\.ico|(?:app-)?ads\.txt|humans\.txt|security\.txt|crossdomain\.xml|browserconfig\.xml|manifest\.json|[\w-]+\.webmanifest)$|\/\.well-known\//i;
const pathOf = (u: string) => { try { return new URL(u).pathname; } catch { return u.replace(/[?#].*$/s, ''); } };
// JSONP（?callback=）は Content-Type が JS でも、利用者ごとのデータを返す動的な応答なので、静的リソースとしない
const JSONP_PARAM = /[?&](?:callback|jsonp)=/i;
export const isStaticResource = (ctx: RuleContext): boolean => {
  const u = ctx.target.url ?? '';
  const p = pathOf(u);
  // JSONP（?callback=）は、拡張子が .js（/api/user.js?callback=）でも、Content-Type が JS でも静的リソースとしない
  return PUBLIC_FILE.test(p) || (!JSONP_PARAM.test(u) && (STATIC_RE.test(p) || STATIC_CT.test(header(ctx, 'content-type')[0] ?? '')));
};
/**
 * 機密応答かどうか（第0章 0.3）。ただし静的リソースと公開ファイルは、sensitive=1 を明示したときだけ機密とする。
 * ブラウザは JS・フォント・robots.txt にもセッションCookie を送るので、Cookie を送っただけ（推定）で機密とすると、
 * H-11①・H-12①（高）・R-04①・R-08① がすべての静的リソースに出る。JSONP（E-06）は JS で利用者のデータを返すので、これを使わない
 */
export const sensitiveUnlessStatic = (ctx: RuleContext): boolean | undefined =>
  isStaticResource(ctx) && ctx.target.sensitive !== true ? false : ctx.sensitive;

/** CSP 値をディレクティブ名→値の Map にする（同名の最初の指定が有効） */
export function parseCsp(v: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const part of v.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && /^[a-z-]+$/i.test(name) && !m.has(name.toLowerCase())) m.set(name.toLowerCase(), vals);
  }
  return m;
}

/** HSTS のディレクティブ（includesubdomains・preload）があるか。H-01・H-02・横断ルール・画面の案内で同じ読み方にする（部分一致にしない） */
/**
 * HSTS のヘッダを RFC 6797 6.1 のとおりに読む。「;」で分けた各ディレクティブが「名前」か「名前=値」（値はトークンか引用符の文字列）で、
 * 同じディレクティブが2回なく、max-age が数字であるときだけ有効（ブラウザは無効なヘッダを無視する（8.1））。
 * max-age を正規表現で拾うだけでは、カンマ区切り（max-age=31536000, includeSubDomains）・「;」のないもの・max-age の重複を有効とみなした
 */
export function parseHsts(v: string | undefined): { valid: boolean; maxAge: number } {
  if (!v) return { valid: false, maxAge: 0 };
  const seen = new Set<string>(); let maxAge: number | undefined;
  for (const raw of hstsParts(v)) {
    const d = raw.trim(); if (!d) continue;
    const m = d.match(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([!#$%&'*+.^_`|~0-9A-Za-z-]+)))?$/);
    if (!m) return { valid: false, maxAge: 0 };
    const name = m[1].toLowerCase();
    if (seen.has(name)) return { valid: false, maxAge: 0 };
    seen.add(name);
    if (name === 'max-age') { const val = (m[2] ?? m[3] ?? '').replace(/\\(.)/g, '$1'); if (!/^\d+$/.test(val)) return { valid: false, maxAge: 0 }; maxAge = Number(val); }
  }
  return maxAge === undefined ? { valid: false, maxAge: 0 } : { valid: true, maxAge };
}
/**
 * HSTS のディレクティブを「;」で分ける。引用符の文字列（\ のエスケープを含む）の中の「;」では分けない（foo="a;b" を2つに分け、
 * ブラウザが受け付けるヘッダを H-01③（高）にした）
 */
function hstsParts(v: string): string[] {
  const out: string[] = []; let start = 0, q = false;
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (q) { if (c === '\\') i++; else if (c === '"') q = false; }
    else if (c === '"') q = true;
    else if (c === ';') { out.push(v.slice(start, i)); start = i + 1; }
  }
  out.push(v.slice(start));
  return out;
}
/** ブラウザが受け付ける（parseHsts で有効な）ヘッダにそのディレクティブがあるか。無効なヘッダはブラウザが無視するので、ないのと同じ */
export const hstsDirective = (v: string | undefined, name: 'includesubdomains' | 'preload'): boolean =>
  !!v && parseHsts(v).valid && hstsParts(v).some(d => d.trim().toLowerCase() === name);

/** ログイン・ログアウトに失敗した採取での判定不能（na）の推奨対応（C-09・C-12・H-15） */
export const LOGOUT_FAILED_REC = 'ログアウトの方法（POST など）に合わせて logout を採取し直す';
export const LOGIN_FAILED_REC = 'テスト用アカウントでログインできることを確かめて、login を採取し直す';
/**
 * 本文を見て判定するルールで、本文を採取していないとき（-v、-D - -o /dev/null、HAR の本文なし）の推奨。
 * 本文がないのに「反映されない」「参照なし」と合格にすると、見逃しになり、カバレッジも水増しになる
 */
export const NO_BODY_REC = '本文も含めて採取し直す（curl は -v ではなく -i で、-o /dev/null を付けない）';
/** プローブ（C13）のコードが 000（接続できなかった）のときの推奨。ファイルがあるかどうかは分からないので、合格にしない（E-03・E-04・E-13） */
export const PROBE_UNREACHED_REC = 'ネットワークの状態を確かめて C13 を実行し直す（HTTP 000 は接続できなかったことを示す）';
/** 本文の上限（パーサが残す先頭64KB）に達しているか。末尾にある記述（sourceMappingURL など）は、なくても「ない」とは言えない */
/**
 * データのない JSON の本文（{}・[]・null、値がすべて null・false・空のもの。NextAuth の未認証の /api/auth/session の {}、{"authenticated":false,"user":null}）。
 * 保護データを返していないので、A-01①・C-12①（高）にしない
 */
const AUTH_FLAG = /^(?:is_?)?(?:authenticated|authorized|logged_?in|signed_?in|auth|ok|success|valid)$/i;
// false を空とみなすのは、ログインの状態を表す名前（authenticated・loggedIn・isAuthenticated など）だけ（{"isAdmin":false,"mfaEnabled":false} は利用者のデータ）
const blank = (v: unknown, k?: string) => v === null || v === '' || (v === false && (k === undefined || AUTH_FLAG.test(k)))
  || (Array.isArray(v) && v.length === 0) || (typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 0);
const parseJson = (body: string | undefined): unknown => {
  const b = (body ?? '').trim();
  if (!/^[{[]|^null$/.test(b)) return undefined;
  try { return JSON.parse(b); } catch { return undefined; }
};
export const noDataJson = (body: string | undefined): boolean => {
  const j = parseJson(body);
  if (j === undefined) return false;
  return blank(j) || (typeof j === 'object' && j !== null && !Array.isArray(j) && (Object.entries(j as Record<string, unknown>).every(([k, v]) => blank(v, k)) || errorEnvelope(j as Record<string, unknown>, blank)));
};
/**
 * エラーだけを返した JSON か（errorEnvelope。{"success":false,"error":"invalid_credentials"}）。空の {} や値がすべて空のものは含めない
 * （ログインの成功でも {} を返すアプリがある）。C-09 で、200 の JSON で返したログインの失敗を見分けるのに使う
 */
export const errorJson = (body: string | undefined): boolean => {
  const j = parseJson(body);
  return typeof j === 'object' && j !== null && !Array.isArray(j) && errorEnvelope(j as Record<string, unknown>, blank);
};
/**
 * エラーだけを返した JSON（200 で {"success":false,"error":"Unauthorized","message":"Please log in"}）。エラーの項目（error・errors など）か
 * success:false・ok:false があり、ほかの項目がエラーの包みの決まった名前（message・code・status・timestamp など。値は文字・数値・真偽値）だけで、
 * data・result は空のもの。エラーの文言はデータではないので、空でない値があっても保護データとしない（A-01①（高）にした）
 */
const ERROR_KEYS = /^(?:error|errors|err|fault|error_?(?:code|message|description|type)|errorcode|errormessage)$/i;
const ENVELOPE_KEYS = /^(?:message|msg|status|status_?code|statuscode|code|success|ok|timestamp|time|path|request_?id|trace_?id|correlation_?id|detail|title|type|instance)$/i;
const errorEnvelope = (j: Record<string, unknown>, blank: (v: unknown, k?: string) => boolean): boolean => {
  const entries = Object.entries(j);
  // 状態の番号だけのエラー（{"status":401,"message":"Unauthorized"}・{"code":401,"msg":"not logged in"}・{"status":"fail"}）も含める
  const failed = entries.some(([k, v]) => (ERROR_KEYS.test(k) && !blank(v)) || (/^(?:success|ok)$/i.test(k) && v === false)
    || (/^(?:status|status_?code|statuscode|code)$/i.test(k) && ((typeof v === 'number' && v >= 400 && v < 600) || (typeof v === 'string' && /^(?:[45]\d\d|fail(?:ed|ure)?|error|unauthori[sz]ed|forbidden|denied)$/i.test(v)))));
  return failed && entries.every(([k, v]) => ERROR_KEYS.test(k)
    || (/^(?:data|result)$/i.test(k) && blank(v))
    || (ENVELOPE_KEYS.test(k) && (v === null || ['string', 'number', 'boolean'].includes(typeof v))));
};
/**
 * GraphQL のエラーの応答（200 で {"errors":[…],"data":null}）。errors があり、data が null か値がすべて null のもの。
 * 認証・認可の拒否（UNAUTHENTICATED・FORBIDDEN・not authenticated など）なら 'denied'、それ以外は 'error'
 */
export const graphqlError = (body: string | undefined): 'denied' | 'error' | undefined => {
  const b = body ?? '';
  if (!/^\s*\{/.test(b) || !/"errors"\s*:/.test(b)) return undefined;
  let j: { errors?: unknown; data?: unknown };
  try { j = JSON.parse(b) as typeof j; } catch { return undefined; }
  if (!Array.isArray(j.errors) || !j.errors.length) return undefined;
  const d = j.data;
  if (!(d === null || d === undefined || (typeof d === 'object' && Object.values(d as Record<string, unknown>).every(v => v === null)))) return undefined;
  return /UNAUTHENTICATED|UNAUTHORIZED|FORBIDDEN|not authenticated|unauthori[sz]ed|authentication required|access denied|not logged in|login required/i.test(JSON.stringify(j.errors)) ? 'denied' : 'error';
};
export const bodyTruncated = (ctx: RuleContext) => (ctx.final?.body?.length ?? 0) >= 64 * 1024;

/**
 * 英語の画面の文言らしい値（{"password":"Password"}、{"apiKey":"ApiKey"}、{"secret":"Secret"}）。値がキーの名前と同じ語か、
 * 先頭だけ大文字の語をつないだもの（Password、NewPassword）なら、文言とみなす。秘密の値は、数字や記号を含むか、すべて小文字であることが多い
 */
export const isLabelText = (key: string, v: string): boolean => {
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z]/g, '');
  return norm(v) === norm(key) || /^(?:[A-Z][a-z]+)+$/.test(v);
};
/**
 * 公開を前提にした値（ブラウザに渡すために API が返す）。Stripe の PaymentIntent・SetupIntent の client_secret（pi_…_secret_…。Stripe.js に渡す）、
 * Stripe の公開キー（pk_live_・pk_test_）、Firebase の設定の Google API キー（AIza…。権限はセキュリティルールで絞る）。A-07①（高）にしない
 */
export const isPublicClientValue = (v: string): boolean =>
  /^(?:pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$/.test(v) || /^pk_(?:live|test)_[A-Za-z0-9]+$/.test(v) || /^AIza[0-9A-Za-z_-]{35}$/.test(v);
/**
 * 伏せ字の値（"********"、"***"、"•••"、"[REDACTED]"、Rails の "[FILTERED]"、"<hidden>"）。値を出していないので、秘密情報の露出（A-07①・E-09①）にしない
 */
export const isPlaceholderValue = (v: string): boolean =>
  /^(?:([*•●xX#.\-_])\1{2,}|[[(<{]?\s*(?:redacted|filtered|hidden|masked|protected|removed|omitted)\s*[\])>}]?)$/i.test(v.trim());
