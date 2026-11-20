import type { Finding, Rule, RuleContext, Severity, Status } from '../model';
import { wordLike } from '../tokenShape';
import { BODY_LIMIT, TCHAR, isRedirectWithLocation } from '../parser/target';

/** 送ったテスト値のホスト（既知のテスト値。ツール設計1。生成するコマンド（src/commands.ts）と同じ値） */
export const TEST_HOST = 'evil.example';
export const TEST_HOST_RE = new RegExp(TEST_HOST.replace(/\./g, '\\.'), 'i');
/** 指摘を作る（target はラベルかホスト。ホスト単位のルールは host も付ける） */
export const cf = (rule: Rule, target: string, cond: number | 'ok' | 'na', severity: Severity, status: Status, evidence: string, recommendation: string, host?: string): Finding =>
  ({ ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined, title: rule.title, severity, status,
     target, ...(host === undefined ? {} : { host }), evidence, recommendation, references: rule.basis });
/** ターゲット単位のルールの指摘 */
export const mk = (rule: Rule, ctx: RuleContext, cond: number | 'ok' | 'na', severity: Severity, status: Status,
                   evidence: string, recommendation: string, extra: Partial<Finding> = {}): Finding =>
  ({ ...cf(rule, ctx.target.label, cond, severity, status, evidence, recommendation), ...extra });
/** 応答がない（ヘッダを見るルールで、採取できなかったターゲット）の判定不能 */
export const noResponse = (rule: Rule, ctx: RuleContext): Finding => mk(rule, ctx, 'na', 'info', 'na', '応答がない', '');

export const header = (ctx: RuleContext, name: string): string[] => ctx.final?.headers.get(name) ?? [];
/** Cache-Control のディレクティブ（小文字）。カンマで区切る（引用符の中のカンマ（private="Set-Cookie, X-A"）では区切らない） */
export const cacheDirectives = (values: string[]): string[] =>
  (values.join(', ').toLowerCase().match(/(?:[^,"]|"[^"]*"?)+/g) ?? []).map(s => s.trim()).filter(Boolean);
/** ディレクティブの名前（private="Set-Cookie" は private） */
export const directiveNames = (parts: string[]): Set<string> => new Set(parts.map(s => s.split('=')[0].trim()));

/**
 * CSP のヘッダ値を、ポリシーごとに分ける。1つのヘッダ値の中のカンマは、ポリシーの区切り（CSP3 の serialized-policy-list）。
 * プロキシが2つのヘッダを「a, b」にまとめた場合も同じ。分けないと、カンマのあとのディレクティブ（, frame-ancestors 'none'）を
 * 前のディレクティブの値として読み、H-06① などを誤検知する
 */
export const splitPolicies = (values: string[]): string[] => values.flatMap(v => v.split(',')).map(s => s.trim()).filter(Boolean);
/**
 * 強制モードの CSP（ポリシーごと）。ディレクティブが1つもないかけら（report-uri の URL の中のカンマのあとの「2」、
 * 「img-src 'self', data:」の「data:」）は、ブラウザも何も制限しないポリシーとして扱うので除く（H-03③ は rules/headers.ts で見る）
 */
export const cspPolicies = (ctx: RuleContext): string[] => splitPolicies(header(ctx, 'content-security-policy')).filter(p => parseCsp(p).size > 0);
/**
 * X-Content-Type-Options が nosniff か。Fetch Standard の「determine nosniff」のとおり、すべての値をカンマで分けた最初の値で見る
 * （プロキシが付け足した「nosniff, nosniff」も nosniff。H-08 と A-09② で同じ読み方にする）
 */
export const isNosniff = (ctx: RuleContext): boolean =>
  header(ctx, 'x-content-type-options').join(',').split(',')[0].trim().toLowerCase() === 'nosniff';

// 静的リソース（JS・CSS・画像・フォント・動画・音声・WebAssembly）と、誰にでも同じ内容を返す公開ファイル（robots.txt、sitemap.xml、
// /.well-known/ の下など）。拡張子はパスの末尾だけで見る（クエリの ?avatar=me.png・?format=x.css で、利用者ごとの API を静的リソースにしない）
const STATIC_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|map|wasm|mp4|m4v|webm|ogv|mov|mp3|m4a|aac|oga|ogg|opus|wav|flac)$/i;
/** JS・CSS・フォントの Content-Type（古いフォントの型 application/font-woff・application/vnd.ms-fontobject を含む） */
export const ASSET_CT = /^\s*(?:text\/css|(?:text|application)\/(?:x-)?(?:java|ecma)script|font\/|application\/(?:x-)?font|application\/vnd\.ms-fontobject\b)/i;
const STATIC_CT = /^\s*(?:image\/|video\/|audio\/|application\/wasm\b)/i;
const PUBLIC_FILE = /\/(?:robots\.txt|sitemap[\w-]*\.xml(?:\.gz)?|favicon\.ico|(?:app-)?ads\.txt|humans\.txt|security\.txt|crossdomain\.xml|browserconfig\.xml|manifest\.json|[\w-]+\.webmanifest)$|\/\.well-known\//i;
const pathOf = (u: string) => { try { return new URL(u).pathname; } catch { return u.replace(/[?#].*$/s, ''); } };
// JSONP（?callback=）は、拡張子が .js（/api/user.js?callback=）でも Content-Type が JS でも、利用者ごとのデータを返す動的な応答なので、
// 静的リソースとしない
const JSONP_PARAM = /[?&](?:callback|jsonp)=/i;
export const isStaticResource = (ctx: RuleContext): boolean => {
  const u = ctx.target.url ?? '';
  const p = pathOf(u);
  return PUBLIC_FILE.test(p) || (!JSONP_PARAM.test(u) && (STATIC_RE.test(p) || [ASSET_CT, STATIC_CT].some(re => re.test(header(ctx, 'content-type')[0] ?? ''))));
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

/** HSTS の1つのディレクティブ：名前、または名前=値（値はトークンか引用符の文字列） */
const HSTS_DIRECTIVE = new RegExp(String.raw`^(${TCHAR}+)(?:\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(${TCHAR}+)))?$`);

/**
 * HSTS のヘッダを RFC 6797 6.1 のとおりに読む。「;」で分けた各ディレクティブが「名前」か「名前=値」（値はトークンか引用符の文字列）で、
 * 同じディレクティブが2回なく、max-age が数字であるときだけ有効（ブラウザは無効なヘッダを無視する（8.1））。
 * カンマ区切り（max-age=31536000, includeSubDomains）・「;」のないもの・max-age の重複は無効
 */
export function parseHsts(v: string | undefined): { valid: boolean; maxAge: number } {
  if (!v) return { valid: false, maxAge: 0 };
  const seen = new Set<string>(); let maxAge: number | undefined;
  for (const raw of hstsParts(v)) {
    const d = raw.trim(); if (!d) continue;
    const m = d.match(HSTS_DIRECTIVE);
    if (!m) return { valid: false, maxAge: 0 };
    const name = m[1].toLowerCase();
    if (seen.has(name)) return { valid: false, maxAge: 0 };
    seen.add(name);
    if (name === 'max-age') { const val = (m[2] ?? m[3] ?? '').replace(/\\(.)/g, '$1'); if (!/^\d+$/.test(val)) return { valid: false, maxAge: 0 }; maxAge = Number(val); }
  }
  return maxAge === undefined ? { valid: false, maxAge: 0 } : { valid: true, maxAge };
}
/**
 * HSTS のディレクティブを「;」で分ける。引用符の文字列（\ のエスケープを含む）の中の「;」では分けない（foo="a;b" は1つのディレクティブ）
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
/**
 * ブラウザが受け付ける（parseHsts で有効な）ヘッダにそのディレクティブ（includesubdomains・preload）があるか。無効なヘッダはブラウザが
 * 無視するので、ないのと同じ。H-01・H-02・横断ルール・画面の案内で同じ読み方にする（部分一致にしない）
 */
export const hstsDirective = (v: string | undefined, name: 'includesubdomains' | 'preload'): boolean =>
  !!v && parseHsts(v).valid && hstsParts(v).some(d => d.trim().toLowerCase() === name);

/** ログイン・ログアウトに失敗した採取での判定不能（na）の推奨対応（C-09・C-12・H-15） */
export const LOGOUT_FAILED_REC = 'ログアウトの方法（POST など）に合わせて logout を採取し直す';
export const LOGIN_FAILED_REC = 'テスト用アカウントでログインできることを確かめて、login を採取し直す';
/** 機密応答かどうか分からないときの推奨（第0章 0.3） */
export const SENSITIVE_REC = '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける';
/** 転送先を採取していないときの推奨 */
export const FOLLOW_REC = '-L を付けて、転送先まで採取し直す';
/** 一時的に使えない応答（5xx・429 のレート制限）。リクエストを処理したかが分からないので、合格にも指摘にもしない */
export const unavailable = (status: number): boolean => status >= 500 || status === 429;
export const RETRY_REC = '時間をおいて採取し直す';
/**
 * 本文を見て判定するルールで、本文を採取していないとき（-v、-D - -o /dev/null、HAR の本文なし）の推奨。
 * 本文がないのに「反映されない」「参照なし」と合格にすると、見逃しになり、カバレッジも水増しになる
 */
export const NO_BODY_REC = '本文も含めて採取し直す（curl は -v ではなく -i で、-o /dev/null を付けない）';
/**
 * 最後の応答の本文を採取していないか（本文のない応答（204・304、Content-Length: 0）は、採取していても本文がないので含めない）。
 * E-01・A-07 は、本文のない応答を適用外の [] にし、本文を見るべき応答（エラーの応答、API の 2xx）で採取していないものだけを na にする
 */
export const bodyNotCaptured = (ctx: RuleContext): boolean => {
  const f = ctx.final;
  return !!f && !f.body?.trim() && !noContent(ctx) && !zeroLength(ctx);
};
/**
 * 本文のない応答（204 No Content、304 Not Modified）。キャッシュに残す内容も、ほかのオリジンに読ませる内容も、スニッフィングする本文も
 * ないので、H-08・H-11・H-12・A-09 の対象外（ビーコンや XHR の 204 を指摘しない）
 */
export const noContent = (ctx: RuleContext): boolean => ctx.final?.status === 204 || ctx.final?.status === 304;
/** 本文のない応答（noContent。H-11・H-12）の na の推奨 */
export const NO_CONTENT_REC = '本文のある応答（200 など）で採取する（本文のない応答は対象外）';
/** 本文のない応答と転送の応答（nothingToSniff と Location のある 3xx。H-08・H-11・A-09）の na の推奨 */
export const NO_CONTENT_OR_REDIRECT_REC = '本文のある応答（200 など）で採取する（本文のない応答・転送の応答は対象外）';
/** Content-Length: 0 の応答 */
export const zeroLength = (ctx: RuleContext): boolean => header(ctx, 'content-length').some(x => /^\s*0\s*$/.test(x));
/** スニッフィングする本文がない応答（H-08・A-09②）：204・304、Location のある 3xx（ブラウザは 3xx の本文を表示しない）、Content-Length: 0 */
export const nothingToSniff = (ctx: RuleContext): boolean => noContent(ctx) || isRedirectWithLocation(ctx.final) || zeroLength(ctx);
/** プローブ（C13）のコードが 000（接続できなかった）のときの推奨。ファイルがあるかどうかは分からないので、合格にしない（E-03・E-04・E-13） */
export const PROBE_UNREACHED_REC = 'ネットワークの状態を確かめて C13 を実行し直す（HTTP 000 は接続できなかったことを示す）';
/** C13 のプローブは -L を付けない（転送先のファイルを取らない）。転送された（3xx）パスは、ファイルがないことが分からない */
export const PROBE_REDIRECT_REC = '転送先のホスト（www の有無など）・パスを URL にして C13 を実行し直す';
const AUTH_FLAG = /^(?:is_?)?(?:authenticated|authorized|logged_?in|signed_?in|auth|ok|success|valid)$/i;
// false を空とみなすのは、ログインの状態を表す名前（authenticated・loggedIn・isAuthenticated など）だけ（{"isAdmin":false,"mfaEnabled":false} は利用者のデータ）
const blank = (v: unknown, k?: string) => v === null || v === '' || (v === false && (k === undefined || AUTH_FLAG.test(k)))
  || (Array.isArray(v) && v.length === 0) || (typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 0);
const parseJson = (body: string | undefined): unknown => {
  const b = (body ?? '').trim();
  if (!/^[{[]|^null$/.test(b)) return undefined;
  try { return JSON.parse(b); } catch { return undefined; }
};
/**
 * データのない JSON の本文（{}・[]・null、値がすべて null・空のもの（false はログインの状態の名前のときだけ空とみなす）。NextAuth の未認証の /api/auth/session の {}、
 * {"authenticated":false,"user":null}）と、エラーだけを返した JSON。保護データを返していないので、A-01①・C-12①（高）にしない
 */
export const noDataJson = (body: string | undefined): boolean => {
  const j = parseJson(body);
  if (j === undefined) return false;
  return blank(j) || (typeof j === 'object' && j !== null && !Array.isArray(j) && (Object.entries(j as Record<string, unknown>).every(([k, v]) => blank(v, k)) || errorEnvelope(j as Record<string, unknown>)));
};
/**
 * エラーだけを返した JSON か（errorEnvelope。{"success":false,"error":"invalid_credentials"}）。空の {} や値がすべて空のものは含めない
 * （ログインの成功でも {} を返すアプリがある）。C-09 で、200 の JSON で返したログインの失敗を見分けるのに使う
 */
export const errorJson = (body: string | undefined): boolean => {
  const j = parseJson(body);
  return typeof j === 'object' && j !== null && !Array.isArray(j) && errorEnvelope(j as Record<string, unknown>);
};
/**
 * エラーだけを返した JSON（200 で {"success":false,"error":"Unauthorized","message":"Please log in"}）。エラーの項目（error・errors など）か
 * success:false・ok:false があり、ほかの項目がエラーの包みの決まった名前（message・code・status・timestamp など。値は文字・数値・真偽値）だけで、
 * data・result は空のもの。エラーの文言はデータではないので、空でない値があっても保護データとしない（A-01①（高）にしない）
 */
const ERROR_KEYS = /^(?:error|errors|err|fault|error_?(?:code|message|description|type)|errorcode|errormessage)$/i;
const ENVELOPE_KEYS = /^(?:message|msg|status|status_?code|statuscode|code|success|ok|timestamp|time|path|request_?id|trace_?id|correlation_?id|detail|title|type|instance)$/i;
const errorEnvelope = (j: Record<string, unknown>): boolean => {
  const entries = Object.entries(j);
  // 状態の番号だけのエラー（{"status":401,"message":"Unauthorized"}・{"code":401,"msg":"not logged in"}・{"status":"fail"}）も含める。
  // ログインの状態を表す名前（authenticated・loggedIn）が false のもの（{"authenticated":false,"message":"Not logged in"}）も失敗の印
  const failed = entries.some(([k, v]) => (ERROR_KEYS.test(k) && !blank(v)) || ((/^(?:success|ok)$/i.test(k) || AUTH_FLAG.test(k)) && v === false)
    || (/^(?:status|status_?code|statuscode|code)$/i.test(k) && ((typeof v === 'number' && v >= 400 && v < 600) || (typeof v === 'string' && /^(?:[45]\d\d|fail(?:ed|ure)?|error|unauthori[sz]ed|forbidden|denied)$/i.test(v)))));
  return failed && entries.every(([k, v]) => ERROR_KEYS.test(k) || (AUTH_FLAG.test(k) && v === false)
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
  const j = parseJson(b) as { errors?: unknown; data?: unknown } | undefined;
  if (!j || !Array.isArray(j.errors) || !j.errors.length) return undefined;
  const d = j.data;
  if (!(d === null || d === undefined || (typeof d === 'object' && Object.values(d as Record<string, unknown>).every(v => v === null)))) return undefined;
  return /UNAUTHENTICATED|UNAUTHORIZED|FORBIDDEN|not authenticated|unauthori[sz]ed|authentication required|access denied|not logged in|login required/i.test(JSON.stringify(j.errors)) ? 'denied' : 'error';
};
/** 本文の上限（パーサが残す先頭64K文字）に達しているか。末尾にある記述（sourceMappingURL など）は、なくても「ない」とは言えない */
export const bodyTruncated = (ctx: RuleContext) => (ctx.final?.body?.length ?? 0) >= BODY_LIMIT;

// 内部のホスト：プライベート・ループバックの IPv4 アドレスと localhost、最後のラベルが internal・local などのホスト名
// （edge01.local.example-cdn.net の .local. は公開のホスト名）
const INTERNAL_ADDR = String.raw`10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|localhost`;
const INTERNAL_SUFFIX = String.raw`\.(?:internal|local|lan|corp|intra)`;
/** URL のホスト名（new URL().hostname）が内部のホストか（T-05②・E-09②）。10.cdn.example.com のような、数字で始まる公開のホスト名は含めない */
export const INTERNAL_HOST = new RegExp(String.raw`^(?:${INTERNAL_ADDR})$|${INTERNAL_SUFFIX}$`, 'i');
/** ヘッダの値（Via・X-Backend-Server など）の中の内部のホスト（H-16④）。前後が名前の続き（10.0.0.1.example.com・localhost.example.com）のものは含めない */
export const INTERNAL_HOST_IN_TEXT = new RegExp(String.raw`(?<![\w.])(?:${INTERNAL_ADDR})(?!\w|\.\w)|[\w-]${INTERNAL_SUFFIX}(?![\w.-])`, 'i');

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
 * Stripe の公開キー（pk_live_・pk_test_）、Firebase の設定の Google API キー（AIza…。権限はセキュリティルールで絞る）。E-09①・A-07①（高）にしない
 */
export const isPublicClientValue = (v: string): boolean =>
  /^(?:pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$/.test(v) || /^pk_(?:live|test)_[A-Za-z0-9]+$/.test(v) || /^AIza[0-9A-Za-z_-]{35}$/.test(v)
  || /^phc_[A-Za-z0-9]{20,}$/.test(v);   // PostHog のプロジェクトのキー（ブラウザから送る公開のキー）
/**
 * 伏せ字の値（"********"、"***"、"•••"、"[REDACTED]"、Rails の "[FILTERED]"、"<hidden>"）。値を出していないので、秘密情報の露出（A-07①・E-09①）にしない
 */
export const isPlaceholderValue = (v: string): boolean =>
  /^(?:([*•●xX#.\-_])\1{2,}|[[(<{]?\s*(?:redacted|filtered|hidden|masked|protected|removed|omitted)\s*[\])>}]?)$/i.test(v.trim())
  // 文書・設定例の仮の値（YOUR_API_KEY_HERE・<your-client-secret>・your-secret-key・INSERT_TOKEN_HERE）。
  // example・sample・dummy は本物のパスワードにも使う（my_example_password）ので含めない
  || /^<[^<>]{1,64}>$/.test(v.trim()) || (/^[A-Za-z]+(?:[_-][A-Za-z]+)*$/.test(v) && /(?:^|[_-])(?:your|here|insert|replace|placeholder)(?=[_-]|$)/i.test(v));

/**
 * 入力の検証の規則（Laravel・VeeValidate の required|min:8|max:64）。| でつないだ、英字の規則名（引数は数字・英字）だけのもの。
 * ログイン・登録の画面の password:"required|min:8" を、秘密の値の代入（E-09①（高））にしない
 */
const VALIDATION_RULE = /^[a-z_]+(?::[\w,.-]{1,20})?(?:\|[a-z_]+(?::[\w,.-]{1,20})?)+$/i;
/** HTML の autocomplete の値（current-password・new-password・one-time-code など） */
const AUTOCOMPLETE = /^(?:current-password|new-password|one-time-code|username|email|off|on)$/i;
/** 秘密の値ではない形（入力の検証の規則・正規表現 ^…$・autocomplete の値）。E-09 と A-07 で共有する（同じ値を片方だけで指摘しない） */
export const notSecretFormat = (v: string): boolean => VALIDATION_RULE.test(v) || /^\^.*\$$/.test(v) || AUTOCOMPLETE.test(v);

/** 秘密の値の名前の語（項目の名前・セレクタに含まれていれば、その値は秘密ではなく画面の部品・項目を指す） */
const SECRET_WORD = /^(?:password|passwd|pass|pwd|secret|token|key|credentials?|passphrase)$/;
const wordsOf = (v: string) => v.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z\d]+/).filter(Boolean);
/** 項目の名前の部品の語（user_password・loginPassword・password_confirmation の、秘密の語以外の語） */
const FIELD_WORD = /^(?:user|users|login|new|current|old|confirm|confirmation|confirmed|input|field|repeat|retype|form|account|reset|verify|verification|enter|your|my|label|placeholder|hint|name|id)$/;
/** JSON でエスケープした ASCII 以外の文字（パ） */
const ESCAPED_NON_ASCII = /\\u(?!00[0-7])[0-9a-fA-F]{4}/g;
/**
 * 画面の部品・項目の名前などで、秘密の値ではない形（E-09 と A-07 で共有する）：
 * - パス（/settings/password・/Account/ForgotPassword）と翻訳キー（auth.password.label・user.newPassword）：かけらが語として読め、秘密の語を含むもの
 * - ユーザー情報のない URL と、テンプレート（{{…}}・${…}）
 * - 秘密の語を含む、小文字の CSS のセレクタ（#password-input・.js-password・input[name=password]。値の全体がセレクタの形のもの）
 * - 項目の名前（user_password・loginPassword・password_confirmation）：英字と _ - だけで、語が秘密の語と項目の部品の語（user・login・new・
 *   confirm など）だけのもの（super-secret-key・admin_pass・changeme_password は、ほかの語を含むので秘密の値として扱う）
 * - JSON でエスケープした ASCII 以外の文字（PHP の json_encode・Laravel の @json の "パス…"）が2つ以上で、値の半分以上を占めるもの
 * 語として読めないかけらのパス・ドットの形は除かない（base64 の秘密は / で始まることがあり、JWT はドットでつなぐ）
 */
export const notSecretText = (v: string): boolean => {
  const words = wordsOf(v);
  // base64 の /Ab3… や合言葉の correct.horse.battery を除かないため
  const wordy = (s: string) => s.split(/[/._-]+/).filter(Boolean).every(wordLike) && words.some(w => SECRET_WORD.test(w));
  if ((/^\/[\w\-./]*(?:\?[\w=&.-]*)?$/.test(v) && wordy(v.split('?')[0])) || (/^[a-z][\w-]*(?:\.[\w-]+)+$/.test(v) && wordy(v))) return true;
  if (/^https?:\/\/[^/@\s]+(?:[/?#]|$)/i.test(v) || /^(?:\{\{|\$\{)/.test(v)) return true;
  if ((/^[#.][a-z][a-z0-9_-]*$/.test(v) || /^[a-z]*(?:\[[a-z_-]+(?:[~|^$*]?=["']?[a-z0-9_-]*["']?)?\])+$/.test(v)) && words.some(w => SECRET_WORD.test(w))) return true;
  if (v.length <= 64 && /^[A-Za-z]+(?:[_-][A-Za-z]+)*$/.test(v) && words.length >= 2 && words.some(w => SECRET_WORD.test(w)) && words.every(w => SECRET_WORD.test(w) || FIELD_WORD.test(w))) return true;
  const esc = v.match(ESCAPED_NON_ASCII)?.length ?? 0;
  return esc >= 2 && esc * 6 * 2 >= v.length;
};
