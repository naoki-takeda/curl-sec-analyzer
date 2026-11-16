// rules/html.ts：HTML本文のルール（E-07〜E-10、E-12）。本文は先頭64KBまで。正規表現による簡易的な走査
import type { Rule, RuleContext } from '../model';
import { hostOf } from '../parser/target';
import { isTrustedOrigin } from '../engine/profile';
import { isLabelText, isPlaceholderValue, isPublicClientValue, mk } from './util';
import { clip } from '../mask';

/** evidence：証跡用のタグの表記（tagEvidence）。元のタグの文字列は、属性に秘密情報を含みうるので持たない */
export interface Tag { name: string; attrs: Map<string, string>; evidence: string; index: number; }

/**
 * 証跡に値を出す属性。判定に使う属性（読み込み先・送信先・種類）だけにする。
 * それ以外（data-api-key、data-auth-token、nonce、value など）は、名前の付け方によらず秘密情報を含みうるので、値を「…」にする。
 * URL のパラメータのトークンは、このあと engine/run.ts の maskText でマスクする
 */
const SHOWN_ATTRS = new Set(['src', 'href', 'action', 'data', 'rel', 'method', 'type', 'name', 'content', 'integrity', 'crossorigin', 'as']);
export function tagEvidence(name: string, attrs: Map<string, string>): string {
  const parts = [...attrs].map(([k, v]) => (SHOWN_ATTRS.has(k) ? `${k}="${v}"` : v === '' ? k : `${k}="…"`));
  return clip(`<${[name, ...parts].join(' ')}>`, 200);
}

/**
 * 属性の値の文字参照（&#61;・&#x3D;・&amp; など）を文字に戻す。ブラウザが解釈するのと同じ値で判定・マスクするため
 * （Handlebars は = を &#x3D; にするので、戻さないと ?token&#x3D;… のトークンがマスクされない）
 */
const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", equals: '=', quest: '?', num: '#', sol: '/', colon: ':', semi: ';' };
export const decodeEntities = (v: string) => v.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));/g, (all, d: string, h: string, n: string) => {
  const cp = d ? Number(d) : h ? parseInt(h, 16) : undefined;
  if (cp !== undefined) return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : all;
  return NAMED[n.toLowerCase()] ?? all;
});

/** 開始タグを列挙する（属性名は小文字、値は文字参照を戻したもの） */
/**
 * タグの終わり（引用符の外の >）を探す関数を作る。引用符で囲んだ属性の値の中の > では止めない（onsubmit="… && amt>0"、
 * data-config='{"min":">100"}'）。止めると、残りの値が属性名として証跡に出てしまう（値は伏せられるが、属性名は出る）。
 * 「位置と引用符の状態」ごとに結果を覚え、同じところを二度走査しない。> のない本文（<script の繰り返し）や閉じていない引用符でも、
 * 全体の時間が本文の長さに比例する（正規表現で書くと、タグの始まりごとに末尾まで走査し、本文の長さの2乗の時間がかかる）。長い属性にも上限を付けない
 */
function tagEndFinder(html: string): (from: number) => number {
  const memo = new Int32Array(html.length * 3);    // 0：未走査、-1：閉じない、k+1：位置 k の > で閉じる
  return (from: number) => {
    const path: number[] = []; let q = 0; let res = -1;
    for (let j = from; j < html.length; j++) {
      const key = j * 3 + q; const m = memo[key];
      if (m !== 0) { res = m < 0 ? -1 : m - 1; break; }
      path.push(key);
      const c = html.charCodeAt(j);
      if (q === 0) { if (c === 62) { res = j; break; } if (c === 34) q = 1; else if (c === 39) q = 2; }   // > " '
      else if ((q === 1 && c === 34) || (q === 2 && c === 39)) q = 0;
    }
    const v = res < 0 ? -1 : res + 1;
    for (const k of path) memo[k] = v;
    return res;
  };
}

export function tags(html: string, names: string[]): Tag[] {
  const start = new RegExp(`<(${names.join('|')})\\b`, 'iy');
  const endOf = tagEndFinder(html);
  const out: Tag[] = [];
  for (let i = html.indexOf('<'); i >= 0; i = html.indexOf('<', i + 1)) {
    start.lastIndex = i;
    const m = start.exec(html);
    if (!m) continue;
    const from = i + m[0].length; const end = endOf(from);
    if (end < 0) continue;                           // 閉じていないタグ（ブラウザはタグとして扱わない）
    const attrs = new Map<string, string>();
    for (const a of html.slice(from, end).matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) attrs.set(a[1].toLowerCase(), decodeEntities(a[2] ?? a[3] ?? a[4] ?? ''));
    const name = m[1].toLowerCase();
    out.push({ name, attrs, evidence: tagEvidence(name, attrs), index: i });
    i = end;                                         // 属性の中の < をタグの始まりとして読まない（正規表現の matchAll と同じ）
  }
  return out;
}

/** HTML本文があるか（-i・C2 で取得したもの） */
export const htmlBody = (ctx: RuleContext) => (ctx.responseKind === 'html' && ctx.final?.body?.trim() ? ctx.final.body : undefined);

/**
 * HTML の <meta http-equiv="Content-Security-Policy"> の CSP（ポリシーごと）。ヘッダを付けられない GitHub Pages・S3 などの配信では普通の形で、
 * ブラウザは強制する。ただし frame-ancestors・report-uri・sandbox は meta では効かないので除く（H-06 のクリックジャッキング対策には使わない）
 */
export function metaCspPolicies(ctx: RuleContext): string[] {
  const html = htmlBody(ctx);
  return html ? metaCspFromHtml(html) : [];
}
/**
 * <head> の中（<body> より前）の meta の CSP だけを読む。ブラウザは <body> の中の meta の CSP を無視するので、それで H-03 を合格にしない。
 * <body> のない断片は全体を見る
 */
/**
 * <body> の始まり。<head> の中のコメント（<!-- … -->）とスクリプト（<script>…</script>）の中の「<body」は飛ばす
 * （飛ばさないと、そこで <head> が終わったとみなし、あとの meta の CSP を読まなかった）。indexOf で前に進むだけなので、時間は本文の長さに比例する
 */
function bodyStart(html: string): number {
  const lower = html.toLowerCase();
  for (let i = 0; i < lower.length;) {
    const lt = lower.indexOf('<', i); if (lt < 0) return -1;
    if (lower.startsWith('<!--', lt)) { const e = lower.indexOf('-->', lt + 4); if (e < 0) return -1; i = e + 3; continue; }
    if (/^<script[\s>]/.test(lower.slice(lt, lt + 8))) { const e = lower.indexOf('</script', lt + 7); if (e < 0) return -1; i = e + 8; continue; }
    if (/^<body[\s>]/.test(lower.slice(lt, lt + 6))) return lt;
    i = lt + 1;
  }
  return -1;
}
export function metaCspFromHtml(html: string): string[] {
  const end = bodyStart(html);
  const head = end >= 0 ? html.slice(0, end) : html;
  return tags(head, ['meta']).filter(t => t.attrs.get('http-equiv')?.toLowerCase() === 'content-security-policy')
    .flatMap(t => (t.attrs.get('content') ?? '').split(','))
    .map(p => p.split(';').map(d => d.trim()).filter(d => d && !/^(?:frame-ancestors|report-uri|report-to|sandbox)(?![\w-])/i.test(d)).join('; '))
    .filter(Boolean);
}

/** 混在コンテンツ：①script・iframe・stylesheet、②img など */
export function mixedContent(html: string): { active: Tag[]; passive: Tag[] } {
  const ts = tags(html, ['script', 'iframe', 'link', 'img', 'audio', 'video', 'source', 'embed', 'object', 'form']);
  const isHttp = (v?: string) => !!v && /^http:\/\//i.test(v.trim());
  const active = ts.filter(t => (t.name === 'script' || t.name === 'iframe' || t.name === 'embed' || t.name === 'object') && isHttp(t.attrs.get('src') ?? t.attrs.get('data'))
    || (t.name === 'link' && /stylesheet|preload|modulepreload/i.test(t.attrs.get('rel') ?? '') && isHttp(t.attrs.get('href'))));
  const passive = ts.filter(t => ['img', 'audio', 'video', 'source'].includes(t.name) && isHttp(t.attrs.get('src')));
  return { active, passive };
}

export const mixedContentRule: Rule = { id: 'E-07', title: 'HTML本文：混在コンテンツ', appliesTo: 'html', scope: 'target',
  basis: ['MDN: Mixed content', 'W3C Mixed Content'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html || ctx.isHttps === false) return [];
    const { active, passive } = mixedContent(html);
    const out = [
      ...active.map(t => mk(mixedContentRule, ctx, 1, 'medium', 'fail', t.evidence, 'https:// で読み込む（CSPの upgrade-insecure-requests も検討）')),
      ...passive.map(t => mk(mixedContentRule, ctx, 2, 'low', 'fail', t.evidence, 'https:// で読み込む')),
    ];
    return out.length ? out : [mk(mixedContentRule, ctx, 'ok', 'info', 'pass', 'http:// の資源なし', '')];
  } };

export const sriRule: Rule = { id: 'E-08', title: 'HTML本文：第三者スクリプトのSRI', appliesTo: 'html', scope: 'target',
  basis: ['MDN: Subresource Integrity', 'OWASP Third Party JavaScript Management CS'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html) return [];
    const host = hostOf(ctx.target);
    const trusted = ctx.profile?.trustedScriptOrigins ?? [];
    // 外部オリジンの script を配信元（オリジン）ごとにまとめる。組織プロファイルで自社の配信元とした所は対象外
    const byOrigin = new Map<string, { total: number; missing: Tag[] }>();
    let skipped = 0;
    for (const t of tags(html, ['script'])) {
      const src = t.attrs.get('src');
      if (!src || !/^(https?:)?\/\//i.test(src)) continue;
      let u: URL; try { u = new URL(src, ctx.target.url ?? 'https://invalid.invalid/'); } catch { continue; }
      if (u.host === host) continue;
      if (isTrustedOrigin(u, trusted)) { skipped++; continue; }
      const g = byOrigin.get(u.origin) ?? { total: 0, missing: [] };
      g.total++; if (!t.attrs.has('integrity')) g.missing.push(t);
      byOrigin.set(u.origin, g);
    }
    const fails = [...byOrigin].filter(([, g]) => g.missing.length).map(([origin, g]) =>
      mk(sriRule, ctx, 1, 'low', 'fail', `${origin}（integrity なし ${g.missing.length}件／${g.total}件）。例：${g.missing[0].evidence}`,
         'integrity と crossorigin="anonymous" を付ける（自社の配信元なら、組織プロファイルの trustedScriptOrigins に登録して対象外にできる）'));
    if (fails.length) return fails;
    const total = [...byOrigin.values()].reduce((a, g) => a + g.total, 0);
    return [mk(sriRule, ctx, 'ok', 'info', 'pass', total ? `外部スクリプト${total}件にintegrityあり` : skipped ? `外部スクリプトはすべて自社の配信元（${skipped}件）` : '外部オリジンのscriptなし', '')];
  } };

// 秘密情報は証跡に値を出さず、種類の名前だけを出す
// キー・シークレットの代入。値は ASCII の記号・英数字だけ（日本語の文言「パスワードは8文字以上…」は空白がなくても秘密情報ではない）。
// 名前の前は語の境目（forgot_password: の password には一致させない）
const ASSIGNED = /(?<![\w-])["']?(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|password)["']?\s*[:=]\s*["']([!#-&(-~]{12,})["']/gi;
/**
 * 秘密ではない値：パス（password:"/users/password/new"）、URL、ドットでつないだ翻訳キー（"auth.password.label"）、テンプレート（{{…}}、${…}）、
 * 英語の画面の文言（A-07 と同じ isLabelText）
 */
const notSecretValue = (key: string, v: string): boolean =>
  v.startsWith('/') || /^https?:/i.test(v) || /^[a-z][\w-]*(?:\.[\w-]+)+$/.test(v) || /^(?:\{\{|\$\{)/.test(v) || isLabelText(key, v) || isPublicClientValue(v) || isPlaceholderValue(v);
// Google の API キー（AIza…）は、Maps・Firebase などブラウザから使う前提のキー（HTTP リファラーや API の制限で守る）なので、HTML にあっても①にしない。
// Stripe の公開キー（pk_live_…）、PaymentIntent の client_secret も同じ（A-07 と同じ isPublicClientValue）
/** 公開を前提にした JWT（ペイロードの role が anon。Supabase の anon key） */
const publicJwt = (payload: string): boolean => {
  try {
    const j = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '='))) as { role?: unknown };
    return j.role === 'anon';
  } catch { return false; }
};
const SECRETS: [string, { test(s: string): boolean }][] = [
  ['AWSアクセスキー', /\bAKIA[0-9A-Z]{16}\b/],
  ['秘密鍵', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['Slackトークン', /\bxox[baprs]-[0-9A-Za-z-]{10,}/],
  ['GitHubトークン', /\bgh[pousr]_[0-9A-Za-z]{36,}\b/],
  // ブラウザに渡す前提の JWT（Supabase の anon key。ペイロードの role が anon）は除く（行レベルのセキュリティで守る公開のキー）
  ['JWT', { test: (s: string) => [...s.matchAll(/\beyJ[\w-]{10,}\.(eyJ[\w-]{10,})\.[\w-]{10,}/g)].some(m => !publicJwt(m[1])) }],
  ['キー・シークレットの代入', { test: (s: string) => [...s.matchAll(ASSIGNED)].some(m => !notSecretValue(m[1], m[2])) }],
];
// ホスト名の最後で区切る（edge01.local.example-cdn.net の .local. には一致させない）。複数のラベルのホスト名（db.prod.internal）も含める
const INTERNAL_URL = /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|(?:[\w-]+\.)+(?:internal|local|lan|corp|intra))(?![\w.-])[^\s"'<>]*/gi;
/** 内部URL。診断した URL 自身のホスト（社内のポータル https://portal.corp/、http://localhost:3000/ の自サイトへのリンク）は除く */
function internalUrl(html: string, own?: string): string | undefined {
  for (const m of html.matchAll(INTERNAL_URL)) {
    let host: string | undefined; try { host = new URL(m[0]).host.toLowerCase(); } catch { /* 解釈できなければ内部URLとして出す */ }
    if (!own || host !== own) return m[0];
  }
  return undefined;
}
// 英字の境目で照合する（「_」は境目にする。debug_mode・staging_db も見る。\b は「_」を語の一部とみなした）。password・パスワードは、
// 画面の部品の説明（<!-- Password field -->、パスワード欄）を除く
// 開発用の語は大文字・小文字を区別して、後ろに小文字が続かないもの（debugMode・debug_mode は見る。/i で照合すると debugMode の M も
// 小文字の扱いになって見逃した）
const DEV_CODE_WORD = /(?<![A-Za-z])(?:TODO|FIXME|XXX|HACK|[Dd]ebug|DEBUG|[Ss]taging|STAGING)(?![a-z])/;
const DEV_WORD = /(?<![A-Za-z])pass(?:word)?(?![a-z])(?![\s_-]*(?:field|input|label|form|reset|box|placeholder|strength|hint|toggle|visibility|policy)\b)|パスワード(?!欄|入力|を忘れ|の再設定|の変更|変更|リセット)|本番/i;
/**
 * 閉じたコメント（<!-- … -->）を1つずつ切り出し、その中だけで開発用の語を探す。一致した語を返す。
 * 正規表現1つで「コメントの中の語」を探すと、閉じのない <!-- が続く本文でバックトラックが爆発する（64KBで数分）ため、indexOf で線形に走査する。
 * コメントの外（前後のコメントにはさまれた本文）には一致させない
 */
export function devCommentWord(html: string): string | undefined {
  for (let i = html.indexOf('<!--'); i >= 0;) {
    const end = html.indexOf('-->', i + 4);
    if (end < 0) return undefined;
    const c = html.slice(i + 4, end); const m = c.match(DEV_CODE_WORD) ?? c.match(DEV_WORD);
    if (m) return m[0];
    i = html.indexOf('<!--', end + 3);
  }
  return undefined;
}
export const htmlSecrets: Rule = { id: 'E-09', title: 'HTML本文：機密・内部情報', appliesTo: 'html', scope: 'target',
  basis: ['OWASP WSTG-INFO-05'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html) return [];
    const out = [];
    // OpenID Connect の response_mode=form_post：IdP は id_token・access_token を hidden の欄に入れて、アプリへ POST する画面を返す。
    // 利用者のブラウザに渡すのが仕事のトークンなので、その欄の値は秘密情報の露出として数えない（自社の Keycloak などを対象にしたとき）
    // 除くのはその input のタグだけ（値をページ全体から消すと、値が「A」のとき AWS のキーの A まで消えて見逃した）
    const posted = forms(html).filter(f => (f.form.attrs.get('method') ?? '').toLowerCase() === 'post')
      .flatMap(f => f.inputs).filter(i => i.attrs.get('type')?.toLowerCase() === 'hidden' && /^(?:id_token|access_token|code|state)$/i.test(i.attrs.get('name') ?? ''))
      .map(i => [i.index, html.indexOf('>', i.index) + 1] as const).filter(([, e]) => e > 0).sort((a, b) => b[0] - a[0]);
    const scan = posted.reduce((h, [s, e]) => h.slice(0, s) + h.slice(e), html);
    for (const [name, re] of SECRETS) if (re.test(scan)) out.push(mk(htmlSecrets, ctx, 1, 'high', 'fail', `本文に「${name}」らしき値（値は表示しない）`, '秘密情報をHTML・JavaScriptに含めない。漏れた値は失効させる'));
    const iu = internalUrl(html, hostOf(ctx.target)?.toLowerCase());
    if (iu) out.push(mk(htmlSecrets, ctx, 2, 'low', 'fail', `内部URL: ${clip(iu, 120)}`, '本番のHTMLに内部URLを残さない'));
    // コメントの中身はパスワードなどを含みうるので、証跡には一致した語だけを出す
    const dc = devCommentWord(html);
    if (dc) out.push(mk(htmlSecrets, ctx, 2, 'low', 'fail', `開発用コメント（「${dc}」を含む。中身は表示しない）`, 'ビルド時にコメントを削除する'));
    // 「Drupal 10 (https://www.drupal.org)」のように主な版だけのものも版とみなす（H-16 の X-Generator と同じ）
    const gen = tags(html, ['meta']).find(t => t.attrs.get('name')?.toLowerCase() === 'generator' && /\b\d+\b/.test(t.attrs.get('content') ?? ''));
    if (gen) out.push(mk(htmlSecrets, ctx, 3, 'info', 'fail', gen.evidence, 'generator のバージョンを出さない'));
    return out.length ? out : [mk(htmlSecrets, ctx, 'ok', 'info', 'pass', '秘密情報・内部情報らしき記述なし', '')];
  } };

/** form ごとに、その中の input を集める */
function forms(html: string): { form: Tag; inputs: Tag[] }[] {
  const fs = tags(html, ['form']);
  return fs.map((f, i) => {
    // 元の文字列で探す（toLowerCase で長さが変わる文字（İ など）があると、位置がずれる）
    const endRe = /<\/form\s*>/gi; endRe.lastIndex = f.index;
    const end = endRe.exec(html)?.index ?? -1;
    const stop = Math.min(end < 0 ? html.length : end, fs[i + 1]?.index ?? html.length);
    // input の位置（index）はページ全体での位置にする（フォームの中での位置のままだと、E-09 がページの別の場所を取り除いた）
    return { form: f, inputs: tags(html.slice(f.index, stop), ['input']).map(t => ({ ...t, index: t.index + f.index })) };
  });
}

export const passwordForm: Rule = { id: 'E-10', title: 'HTML本文：パスワードフォーム', appliesTo: 'html', scope: 'target',
  basis: ['IPA', 'OWASP Authentication CS'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html) return [];
    const pw = forms(html).filter(f => f.inputs.some(i => i.attrs.get('type')?.toLowerCase() === 'password'));
    if (!pw.length) return [];
    const out = [];
    for (const { form } of pw) {
      const action = form.attrs.get('action') ?? '';
      if (/^http:\/\//i.test(action)) out.push(mk(passwordForm, ctx, 1, 'high', 'fail', form.evidence, 'フォームの送信先を https:// にする'));
      if ((form.attrs.get('method') ?? 'get').toLowerCase() !== 'post') out.push(mk(passwordForm, ctx, 2, 'medium', 'fail', form.evidence, 'パスワードは method="post" で送る（URLに残さない）'));
    }
    return out.length ? out : [mk(passwordForm, ctx, 'ok', 'info', 'pass', `パスワードフォーム${pw.length}件は https・POST`, '')];
  } };

const TOKEN_NAME = /csrf|xsrf|token|authenticity|nonce|__RequestVerificationToken|_wpnonce/i;
export const csrfToken: Rule = { id: 'E-12', title: 'HTML本文：CSRFトークンの有無', appliesTo: 'html', scope: 'target',
  basis: ['OWASP CSRF Prevention CS'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html || ctx.sensitive === false) return [];
    const posts = forms(html).filter(f => (f.form.attrs.get('method') ?? '').toLowerCase() === 'post');
    if (!posts.length) return [];
    const missing = posts.filter(f => !f.inputs.some(i => i.attrs.get('type')?.toLowerCase() === 'hidden' && TOKEN_NAME.test(i.attrs.get('name') ?? '')));
    if (!missing.length) return [mk(csrfToken, ctx, 'ok', 'info', 'pass', `POSTフォーム${posts.length}件にトークンらしき項目あり`, '')];
    // ①は「トークンがなく、SameSite も Lax/Strict でない」。認証後ページ（機密応答）が前提なので、機密かどうか分からなければ na（第0章 0.3）
    if (ctx.sensitive === undefined)
      return [mk(csrfToken, ctx, 'na', 'info', 'na', `トークンのないPOSTフォーム${missing.length}件（機密応答かどうか分からない）`, '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける')];
    if (ctx.hostSessionSameSite === true)
      return [mk(csrfToken, ctx, 'ok', 'info', 'pass', `トークンのないPOSTフォーム${missing.length}件。同じホストのセッションCookieは SameSite=Lax/Strict`, '')];
    return missing.map(f => mk(csrfToken, ctx, 1, 'info', 'fail', f.form.evidence,
      ctx.hostSessionSameSite === false ? 'POSTフォームにCSRFトークンを入れる（セッションCookieも SameSite=Lax/Strict でない。実効性の確認は範囲外）'
                                        : 'POSTフォームにCSRFトークンを入れる（セッションCookieが見つからないため SameSite は確認できない。実効性の確認は範囲外）'));
  } };

/**
 * ログインのフォーム：フォームごとに見て、パスワード欄が1つで、次のどれでもないもの：
 * - パスワードを決める欄（name・id・autocomplete に new・confirm・確認用の retype・repeat があるもの。autocomplete="new-password"）
 * - name に current_password・old_password がある欄（Devise の user[current_password]、アカウントの削除・メールアドレスの変更の画面。
 *   旧セッションが使えるときに出る再認証の画面）。web.dev が勧めるログイン画面（name="current-password" と autocomplete="current-password"）と、
 *   id だけが currentPassword のログイン画面は除かない
 * そのうえで、ユーザー名の欄（パスワード・ボタン以外の input。2段階のログイン画面の hidden の username も）があるもの。パスワード欄だけの
 * フォームは、autocomplete="current-password" で、フォームの送り先（action）がログインらしいもの（/login・/signin・/session など。sudo・
 * reauth・confirm・verify を除く）だけ（ユーザー名を文字で表示した2段階目の画面。GitHub の sudo モードのような再認証の画面と分けるため）。
 * ページ全体で数えると、ログインと登録のフォームが並ぶ画面（WooCommerce）を外した。
 * input はタグごとに取り出して見る（閉じない「<input 」が並ぶ本文で、入力の長さの2乗の時間がかかった）
 */
const INPUT_TAG = /<input\b[^>]*(?:>|$)/gi;
const attr = (tag: string, name: string) => tag.match(new RegExp(String.raw`(?<![\w-])${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`, 'i'))?.slice(1).find(v => v !== undefined) ?? '';
const NON_TEXT_INPUT = /^(?:hidden|password|submit|button|checkbox|radio|image|reset|file|range|color)$/i;
const SETTING_FIELD = /(?:^|[\s_-])(?:new|confirm|confirmation|retype|repeat)(?:[\s_-]|$)|new[-_]?pass|(?:pass(?:word)?|pwd)[-_]?confirm/i;
/**
 * ログイン画面・認証の入り口のパス（C-09・C-12・T-06 で共有）：/login・/signin・Devise の /users/sign_in・WordPress の /wp-login.php・
 * OIDC の …/openid-connect/auth・/authorize・oauth2-proxy の /oauth2/start・SAML の /saml/login、拡張子の付いたログイン画面（ASP.NET の
 * /Account/Login.aspx、/login.php・.jsp・.do）、Spring Security の /oauth2/authorization/<登録名>、IdP の入り口（Google の /o/oauth2/v2/auth、
 * Shibboleth の /idp/profile/SAML2/Redirect/SSO、ADFS の /adfs/ls、SimpleSAMLphp の SSOService.php）
 */
export const LOGIN_PATH = /\/(?:log-?in|sign[-_]?in|signon|auth\/login|wp-login|authorize|oauth2\/(?:start|auth(?:orize)?)|oauth2\/authorization\/[\w.-]+|o\/oauth2(?:\/v\d)?\/auth|protocol\/openid-connect\/auth|saml2?\/(?:login|sso)|SAML2\/(?:Redirect|POST)\/SSO|adfs\/ls|SSOService)(?:\.(?:php|aspx?|jspx?|do|action|html?|cgi|pl))?\/?$/i;
export function loginForm(body: string): boolean {
  const chunks = /<form\b/i.test(body) ? body.split(/<form\b/i).slice(1).map(c => c.split(/<\/form\s*>/i)[0]) : [body];
  return chunks.some(f => {
    const inputs = f.match(INPUT_TAG) ?? [];
    const pw = inputs.filter(t => /^password$/i.test(attr(t, 'type')));
    if (pw.length !== 1) return false;
    const ac = attr(pw[0], 'autocomplete'), nameId = `${attr(pw[0], 'name')} ${attr(pw[0], 'id')}`;
    if (SETTING_FIELD.test(`${nameId} ${ac}`)) return false;
    const currentPassword = /\bcurrent-password\b/i.test(ac);
    // current・old の欄は、name か id がちょうど current-password のもの（web.dev が勧めるログイン画面）だけ認める。autocomplete が
    // current-password なら認めると、Devise の再認証のフォーム（name="user[current_password]" autocomplete="current-password"）をログイン画面とした
    // name に current_password・old_password があるもの（Devise の user[current_password]、メールアドレスの変更の old_password）だけを除く。
    // id だけで見ると、id="currentPassword" のログインのフォームまで外した
    const pwName = attr(pw[0], 'name');
    if (/(?:current|old)[-_]?pass/i.test(pwName) && !(currentPassword && /^current-password$/i.test(pwName))) return false;
    const user = inputs.some(t => !NON_TEXT_INPUT.test(attr(t, 'type')))
      || inputs.some(t => /^hidden$/i.test(attr(t, 'type')) && /^(?:user(?:name)?|email|login|identifier|j_username)$/i.test(attr(t, 'name')));
    if (user) return true;
    const action = attr(f.slice(0, Math.max(0, f.indexOf('>'))), 'action');
    return currentPassword && /\/(?:log-?in|sign[-_]?in|signon|sessions?|auth(?:enticate)?)(?:[/?.#]|$)/i.test(action) && !/sudo|re-?auth|confirm|verify/i.test(action);
  });
}
