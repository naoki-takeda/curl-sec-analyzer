import type { Finding, Rule, RuleContext, Severity, Status } from '../model';

export function mk(rule: Rule, ctx: RuleContext, cond: number | 'ok' | 'na', severity: Severity, status: Status,
                   evidence: string, recommendation: string, extra: Partial<Finding> = {}): Finding {
  return { ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined,
           title: rule.title, severity, status, target: ctx.target.label, evidence, recommendation,
           references: rule.basis, score: 0, ...extra };
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
export const hstsDirective = (v: string | undefined, name: 'includesubdomains' | 'preload'): boolean =>
  (v ?? '').split(';').some(d => d.trim().toLowerCase() === name);

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
