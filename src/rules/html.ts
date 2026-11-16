// rules/html.ts：HTML本文のルール（E-07〜E-10、E-12）。本文は先頭64KBまで。正規表現による簡易的な走査
import type { Rule, RuleContext } from '../model';
import { hostOf } from '../parser/target';
import { isTrustedOrigin } from '../engine/profile';
import { isLabelText, isPublicClientValue, mk } from './util';
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
  v.startsWith('/') || /^https?:/i.test(v) || /^[a-z][\w-]*(?:\.[\w-]+)+$/.test(v) || /^(?:\{\{|\$\{)/.test(v) || isLabelText(key, v) || isPublicClientValue(v);
// Google の API キー（AIza…）は、Maps・Firebase などブラウザから使う前提のキー（HTTP リファラーや API の制限で守る）なので、HTML にあっても①にしない。
// Stripe の公開キー（pk_live_…）、PaymentIntent の client_secret も同じ（A-07 と同じ isPublicClientValue）
const SECRETS: [string, { test(s: string): boolean }][] = [
  ['AWSアクセスキー', /\bAKIA[0-9A-Z]{16}\b/],
  ['秘密鍵', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['Slackトークン', /\bxox[baprs]-[0-9A-Za-z-]{10,}/],
  ['GitHubトークン', /\bgh[pousr]_[0-9A-Za-z]{36,}\b/],
  ['JWT', /\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}/],
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
const DEV_WORD = /TODO|FIXME|XXX|HACK|debug|password|パスワード|本番|staging/i;
/**
 * 閉じたコメント（<!-- … -->）を1つずつ切り出し、その中だけで開発用の語を探す。一致した語を返す。
 * 正規表現1つで「コメントの中の語」を探すと、閉じのない <!-- が続く本文でバックトラックが爆発する（64KBで数分）ため、indexOf で線形に走査する。
 * コメントの外（前後のコメントにはさまれた本文）には一致させない
 */
export function devCommentWord(html: string): string | undefined {
  for (let i = html.indexOf('<!--'); i >= 0;) {
    const end = html.indexOf('-->', i + 4);
    if (end < 0) return undefined;
    const m = html.slice(i + 4, end).match(DEV_WORD);
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
    for (const [name, re] of SECRETS) if (re.test(html)) out.push(mk(htmlSecrets, ctx, 1, 'high', 'fail', `本文に「${name}」らしき値（値は表示しない）`, '秘密情報をHTML・JavaScriptに含めない。漏れた値は失効させる'));
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
    return { form: f, inputs: tags(html.slice(f.index, stop), ['input']) };
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
