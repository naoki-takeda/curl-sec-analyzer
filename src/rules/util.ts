import type { Finding, Rule, RuleContext, Severity, Status } from '../model';

export function mk(rule: Rule, ctx: RuleContext, cond: number | 'ok' | 'na', severity: Severity, status: Status,
                   evidence: string, recommendation: string, extra: Partial<Finding> = {}): Finding {
  return { ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined,
           title: rule.title, severity, status, target: ctx.target.label, evidence, recommendation,
           references: rule.basis, score: 0, ...extra };
}

export const header = (ctx: RuleContext, name: string): string[] => ctx.final?.headers.get(name) ?? [];

// 静的リソース（JS・CSS・画像・フォント）と、誰にでも同じ内容を返す公開ファイル（robots.txt、sitemap.xml、/.well-known/ の下など）
const STATIC_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|map)(?:[?#]|$)/i;
const STATIC_CT = /^\s*(?:text\/css|(?:text|application)\/(?:x-)?(?:java|ecma)script|image\/|font\/)/i;
const PUBLIC_FILE = /\/(?:robots\.txt|sitemap[\w-]*\.xml(?:\.gz)?|favicon\.ico|(?:app-)?ads\.txt|humans\.txt|security\.txt|crossdomain\.xml|browserconfig\.xml|manifest\.json|[\w-]+\.webmanifest)$|\/\.well-known\//i;
const pathOf = (u: string) => { try { return new URL(u).pathname; } catch { return ''; } };
// JSONP（?callback=）は Content-Type が JS でも、利用者ごとのデータを返す動的な応答なので、静的リソースとしない
const JSONP_PARAM = /[?&](?:callback|jsonp)=/i;
export const isStaticResource = (ctx: RuleContext): boolean => {
  const u = ctx.target.url ?? '';
  return STATIC_RE.test(u) || PUBLIC_FILE.test(pathOf(u)) || (!JSONP_PARAM.test(u) && STATIC_CT.test(header(ctx, 'content-type')[0] ?? ''));
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
