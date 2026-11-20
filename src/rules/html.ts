// rules/html.ts：HTML本文のルール（E-07〜E-10、E-12）。本文は先頭64K文字まで。タグとコメントは HTML の字句解析をなぞった走査（scan）で読む
import type { Finding, Rule, RuleContext, Target } from '../model';
import { LOGOUT_WORD, finalResponse, firstStatus, hostOf, ownChain, sameDocumentHop } from '../parser/target';
import { looksLikeSessionName, parseSetCookie } from '../parser/setCookie';
import { isTrustedOrigin } from '../engine/profile';
import { FOLLOW_REC, INTERNAL_HOST, LOGOUT_FAILED_REC, NO_BODY_REC, SENSITIVE_REC, bodyNotCaptured, isLabelText, isPlaceholderValue, isPublicClientValue, mk, notSecretFormat, notSecretText } from './util';
import { excerpt } from '../mask';
import { b64urlJson } from './jwt';

interface Tag {
  name: string; attrs: Map<string, string>; index: number;
  /** タグを閉じる > の位置（引用符で囲んだ属性の値の中の > では閉じない。E-09 がタグを取り除く範囲） */
  end: number;
  /** 証跡用のタグの表記（tagEvidence）。元のタグの文字列は、属性に秘密情報を含みうるので持たない */
  evidence: string;
  /** <script> などテキストの要素の中身か <template> の中のタグ（ブラウザは文書の要素として使わない。H-03 の meta の CSP、H-09 の meta の referrer） */
  inert?: boolean;
  /**
   * inert のうち、あとから要素になることもないもの（<textarea>・<title>・<style>・<xmp>・<iframe>・<noembed>・<noframes> の中身）。
   * <script> の中（document.write・x-template）、<template> の中（複製して使う）、<noscript> の中（スクリプトが無効なら要素）は、
   * 読み込み・送信に使われうるので、E-07・E-08・E-10・E-12（と E-09 の hidden の欄、H-07③）はこれだけを除く
   */
  text?: boolean;
}

/**
 * 証跡に値を出す属性。判定に使う属性（読み込み先・送信先・種類）だけにする。
 * それ以外（data-api-key、data-auth-token、nonce、value など）は、名前の付け方によらず秘密情報を含みうるので、値を「…」にする。
 * URL のパラメータのトークンは、このあと engine/run.ts の showText（mask.ts の maskText と語の形の許可リスト）で伏せる
 */
const SHOWN_ATTRS = new Set(['src', 'href', 'action', 'data', 'rel', 'method', 'type', 'name', 'content', 'integrity', 'crossorigin', 'as']);
function tagEvidence(name: string, attrs: Map<string, string>): string {
  const parts = [...attrs].map(([k, v]) => (SHOWN_ATTRS.has(k) ? `${k}="${v}"` : v === '' ? k : `${k}="…"`));
  return excerpt(`<${[name, ...parts].join(' ')}>`, 200);
}

/**
 * 属性の値の文字参照（&#61;・&#x3D;・&amp; など）を文字に戻す。ブラウザが解釈するのと同じ値で判定・マスクするため
 * （Handlebars は = を &#x3D; にするので、戻さないと ?token&#x3D;… のトークンがマスクされない）
 */
const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", equals: '=', quest: '?', num: '#', sol: '/', colon: ':', semi: ';' };
const decodeEntities = (v: string) => v.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));/g, (all, d: string, h: string, n: string) => {
  const cp = d ? Number(d) : h ? parseInt(h, 16) : undefined;
  if (cp !== undefined) return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : all;
  return NAMED[n.toLowerCase()] ?? all;
});

/**
 * 開始タグの中の字句解析の状態（HTML の tokenizer の開始タグの部分と同じ）。引用符が値を囲むのは、属性名と = のあと（空白を挟んでよい）だけで、
 * 引用符のない値の中の = と引用符（<img src=/x?a="1>）、属性名の前の =（<p =" x>）、= のあとでない引用符（<p class=it's>）は普通の文字。
 * ずれると、ほかのタグを読み飛ばすときに本物の > を越え、後ろの <form>・<script> を見逃す
 */
const enum Q { TagName, BeforeAttr, AttrName, AfterAttr, BeforeValue, Unquoted, Double, Single, AfterQuoted }
const isSpace = (c: number) => c === 32 || c === 9 || c === 10 || c === 12 || c === 13;
function nextQ(q: Q, c: number): Q {
  switch (q) {
    case Q.TagName: return isSpace(c) || c === 47 ? Q.BeforeAttr : Q.TagName;                         // 空白 /
    case Q.BeforeAttr: return isSpace(c) || c === 47 ? Q.BeforeAttr : Q.AttrName;                     // 名前の最初の = も名前の文字
    case Q.AttrName: case Q.AfterAttr: return c === 61 ? Q.BeforeValue : c === 47 ? Q.BeforeAttr      // =
      : isSpace(c) ? Q.AfterAttr : Q.AttrName;
    case Q.BeforeValue: return isSpace(c) ? Q.BeforeValue : c === 34 ? Q.Double : c === 39 ? Q.Single : Q.Unquoted;
    case Q.Unquoted: return isSpace(c) ? Q.BeforeAttr : Q.Unquoted;
    case Q.Double: return c === 34 ? Q.AfterQuoted : Q.Double;
    case Q.Single: return c === 39 ? Q.AfterQuoted : Q.Single;
    default: return isSpace(c) || c === 47 ? Q.BeforeAttr : Q.AttrName;                               // 閉じた引用符のあと
  }
}
/**
 * 位置 lt の「<!--」で始まるコメントの終わり（閉じの > の位置。閉じがなければ -1）を探す関数を作る。「-->」（「<!-->」「<!--->」は空のコメント）と
 * 「--!>」で閉じる（ブラウザと同じ）。前に探した結果を覚えて線形時間にする（閉じのない「<!--」の繰り返しで2乗の時間にしない）。
 * lt が戻ったときは覚えた結果を捨てる
 */
function commentEndFinder(html: string): (lt: number) => number {
  const nextOf = (pat: string) => { let at = -2; let none = false; return (k: number) => { if (none) return -1; if (at < k) { at = html.indexOf(pat, k); none = at < 0; } return at; }; };
  let close = nextOf('-->'), bang = nextOf('--!>');
  let last = -1;
  return (lt: number) => {
    if (lt < last) { close = nextOf('-->'); bang = nextOf('--!>'); }
    last = lt;
    const a = close(lt + 2), b = bang(lt + 4);
    return a < 0 ? (b < 0 ? -1 : b + 3) : b < 0 ? a + 2 : Math.min(a + 2, b + 3);
  };
}
/**
 * タグの終わり（引用符の外の >）を探す関数を作る。引用符で囲んだ値の中の >（onsubmit="… && amt>0"）では止めない
 * （止めると、残りの値が属性名として証跡に出る）。「位置と状態」ごとに結果を覚え、> のない本文や閉じていない引用符でも
 * 全体を線形時間にする（正規表現で書くと2乗の時間になる）。長い属性にも上限を付けない
 */
function tagEndFinder(html: string): (from: number) => number {
  const memo = new Int32Array(html.length * 9);    // 0：未走査、-1：閉じない、k+1：位置 k の > で閉じる
  return (from: number) => {
    const path: number[] = []; let q: Q = Q.TagName; let res = -1;
    for (let j = from; j < html.length; j++) {
      const key = j * 9 + q; const m = memo[key];
      if (m !== 0) { res = m < 0 ? -1 : m - 1; break; }
      path.push(key);
      const c = html.charCodeAt(j);
      if (c === 62 && q !== Q.Double && q !== Q.Single) { res = j; break; }   // 引用符の外の >
      q = nextQ(q, c);
    }
    const v = res < 0 ? -1 : res + 1;
    for (const k of path) memo[k] = v;
    return res;
  };
}

/**
 * 開始タグ（属性名は小文字、値は文字参照を戻したもの）と、コメントの中身の範囲（[始まり, 終わり]）を列挙する。
 * タグの名前のあとは空白・/・> だけ（\b では、カスタム要素 <form-field>・<img-slider>・<iframe-wrapper> を <form>・<img>・<iframe> と読む）
 */
function scan(html: string, names: string[]): { tags: Tag[]; comments: [number, number][] } {
  const start = names.length ? new RegExp(`<(${names.join('|')})(?=[\\s/>])`, 'iy') : undefined;
  const endOf = tagEndFinder(html);
  const out: Tag[] = []; const comments: [number, number][] = [];
  // 中身をテキストとして読む要素（中の「<!--」はコメントではない）。<noscript> はスクリプトが有効なブラウザでテキスト
  const raw = /<(script|style|textarea|title|xmp|iframe|noembed|noframes|noscript)(?=[\s/>])/iy;
  let lower: string | undefined;                       // 閉じタグを探すため。初めて要るときに一度だけ小文字にする（タグごとでは2乗の時間になる）
  let rawEnd = -1;                                     // <script> などの中身（コメントにならない）の終わり
  let rawText = false;                                 // その中身があとから要素になることもないか（Tag.text）
  let templateEnd = -1;                                // <template> の中身の終わり（中のタグは inert）
  const template = /<template(?=[\s/>])/iy;
  const commentEnd = commentEndFinder(html);
  for (let i = html.indexOf('<'); i >= 0; i = html.indexOf('<', i + 1)) {
    // コメントの中のタグは、ブラウザが読まないので数えない。<script> などの中身の「<!--」（var s='<!--'）はコメントではない。
    // 閉じのない「<!--」は読み飛ばさない（後ろのタグをすべて見逃さないため）
    const outside = i > rawEnd;
    if (outside && html.startsWith('<!--', i)) {
      const e = commentEnd(i);
      // 中身は「-->」「--!>」の前まで（「<!-->」「<!--->」は空）
      if (e >= 0) { comments.push([i + 4, Math.max(i + 4, e - (html[e - 1] === '!' ? 3 : 2))]); i = e; continue; }
    }
    if (outside) {
      raw.lastIndex = i;
      const r = raw.exec(html);
      if (r) {
        lower ??= html.toLowerCase(); const name = r[1].toLowerCase(); const close = lower.indexOf(`</${name}`, i + r[0].length);
        rawEnd = close < 0 ? html.length : close; rawText = name !== 'script' && name !== 'noscript';
      }
      template.lastIndex = i;
      if (i > templateEnd && template.test(html)) { lower ??= html.toLowerCase(); const close = lower.indexOf('</template', i + 9); templateEnd = close < 0 ? html.length : close; }
    }
    let m: RegExpExecArray | null = null;
    if (start) { start.lastIndex = i; m = start.exec(html); }
    if (!m) {
      // ほかの開始タグも読み飛ばす（属性の値の中の「<!--」（<div title="<!--">）をコメントの始まりと読まないため）。
      // <script> などの中身では読み飛ばさない（スクリプトの「a<b」をタグとして読まない）
      if (outside && /[a-z]/i.test(html[i + 1] ?? '')) { const e = endOf(i + 1); if (e >= 0) i = e; }
      continue;
    }
    const from = i + m[0].length; const end = endOf(from);
    if (end < 0) continue;                           // 閉じていないタグ（ブラウザはタグとして扱わない）
    const attrs = new Map<string, string>();
    // 同じ名前の属性は最初の値を使う（HTML の字句解析と同じ）
    for (const a of html.slice(from, end).matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) { const k = a[1].toLowerCase(); if (!attrs.has(k)) attrs.set(k, decodeEntities(a[2] ?? a[3] ?? a[4] ?? '')); }
    const name = m[1].toLowerCase();
    out.push({ name, attrs, evidence: tagEvidence(name, attrs), index: i, end,
      ...(!outside ? { inert: true, ...(rawText ? { text: true } : {}) } : i < templateEnd ? { inert: true } : {}) });
    i = end;                                         // 属性の中の < をタグの始まりとして読まない
  }
  return { tags: out, comments };
}
/** 開始タグを列挙する */
export const tags = (html: string, names: string[]): Tag[] => scan(html, names).tags;

/** HTML本文があるか（-i・C2 で取得したもの） */
export const htmlBody = (ctx: RuleContext) => (ctx.responseKind === 'html' && ctx.final?.body?.trim() ? ctx.final.body : undefined);
/**
 * HTML本文がないときの結果：2xx の HTML 応答で本文を採取していない（-v・-D - -o /dev/null、HAR の本文なし）なら、本文の項目は判定できないので na。
 * それ以外（HTML でない応答、3xx・4xx など）は適用外の []（空配列は適用外だけに使う。na にしないと、本文を採取した HTML がほかにあるとき、
 * 本文のないページを調べていないことが見えない）
 */
export const noHtmlBody = (rule: Rule, ctx: RuleContext): Finding[] => {
  const s = ctx.final?.status ?? 0;
  return ctx.responseKind === 'html' && s >= 200 && s < 300 && bodyNotCaptured(ctx)
    ? [mk(rule, ctx, 'na', 'info', 'na', '本文を採取していない', NO_BODY_REC)] : [];
};
/**
 * HTML を返したページの URL とホスト。-L で別のホスト（apex から www など）に転送されたときは、ターゲットの URL ではなく転送先（最後のホップ）。
 * 自サイトのスクリプト（E-08）と相対の URL は、ブラウザと同じくこのページを基準にする
 */
const pageUrlOf = (ctx: RuleContext) => ctx.final?.url ?? ctx.target.url;
const pageHostOf = (ctx: RuleContext): string | undefined => {
  const u = pageUrlOf(ctx);
  try { if (u) return new URL(u).host; } catch { /* 読めなければターゲットのホスト */ }
  return hostOf(ctx.target);
};

/**
 * HTML の <meta http-equiv="Content-Security-Policy"> の CSP（ポリシーごと）。ヘッダを付けられない GitHub Pages・S3 などの配信では普通の形で、
 * ブラウザは強制する。ただし frame-ancestors・report-uri・report-to・sandbox は meta では効かないので除く（H-06 のクリックジャッキング対策には使わない）
 */
export function metaCspPolicies(ctx: RuleContext): string[] {
  const html = htmlBody(ctx);
  return html ? metaCspFromHtml(html) : [];
}
/**
 * <body> の始まり（なければ -1）。<head> の中のコメントとスクリプトの中の「<body」は飛ばす。indexOf で前に進むだけなので線形時間
 */
function bodyStart(html: string): number {
  const lower = html.toLowerCase();
  const commentEnd = commentEndFinder(lower);        // コメントの閉じ方は tags() と同じにする（「--!>」も）
  for (let i = 0; i < lower.length;) {
    const lt = lower.indexOf('<', i); if (lt < 0) return -1;
    if (lower.startsWith('<!--', lt)) { const e = commentEnd(lt); if (e < 0) return -1; i = e + 1; continue; }
    if (/^<script[\s>]/.test(lower.slice(lt, lt + 8))) { const e = lower.indexOf('</script', lt + 7); if (e < 0) return -1; i = e + 8; continue; }
    if (/^<body[\s>]/.test(lower.slice(lt, lt + 6))) return lt;
    i = lt + 1;
  }
  return -1;
}
/**
 * <head> の中（<body> より前）の meta の CSP だけを読む。ブラウザは <body> の中の meta の CSP を無視するので、それで H-03 を合格にしない。
 * <body> のない断片は全体を見る
 */
export function metaCspFromHtml(html: string): string[] {
  const end = bodyStart(html);
  const head = end >= 0 ? html.slice(0, end) : html;
  // <template>・<noscript>・スクリプトの文字列の中の meta（inert）は、ブラウザが要素として使わないので CSP にしない
  return tags(head, ['meta']).filter(t => !t.inert && t.attrs.get('http-equiv')?.toLowerCase() === 'content-security-policy')
    .flatMap(t => (t.attrs.get('content') ?? '').split(','))
    .map(p => p.split(';').map(d => d.trim()).filter(d => d && !/^(?:frame-ancestors|report-uri|report-to|sandbox)(?![\w-])/i.test(d)).join('; '))
    .filter(Boolean);
}

/** 混在コンテンツ：①script・iframe・embed・object・stylesheet・preload、②img・audio・video・source */
export function mixedContent(html: string): { active: Tag[]; passive: Tag[] } {
  const ts = tags(html, ['script', 'iframe', 'link', 'img', 'audio', 'video', 'source', 'embed', 'object']).filter(t => !t.text);
  const isHttp = (v?: string) => !!v && /^http:\/\//i.test(v.trim());
  const active = ts.filter(t => (t.name === 'script' || t.name === 'iframe' || t.name === 'embed' || t.name === 'object') && isHttp(t.attrs.get('src') ?? t.attrs.get('data'))
    || (t.name === 'link' && /stylesheet|preload/i.test(t.attrs.get('rel') ?? '') && isHttp(t.attrs.get('href'))));
  const passive = ts.filter(t => ['img', 'audio', 'video', 'source'].includes(t.name) && isHttp(t.attrs.get('src')));
  return { active, passive };
}

export const mixedContentRule: Rule = { id: 'E-07', title: 'HTML本文：混在コンテンツ', appliesTo: 'html', scope: 'target',
  basis: ['MDN: Mixed content', 'W3C Mixed Content'],
  run(ctx) {
    if (ctx.isHttps === false) return [];
    const html = htmlBody(ctx);
    if (!html) return noHtmlBody(mixedContentRule, ctx);
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
    if (!html) return noHtmlBody(sriRule, ctx);
    const host = pageHostOf(ctx);
    const trusted = ctx.profile?.trustedScriptOrigins ?? [];
    // 外部オリジンの script を配信元（オリジン）ごとにまとめる。組織プロファイルで自社の配信元とした所は対象外
    const byOrigin = new Map<string, { total: number; missing: Tag[] }>();
    let skipped = 0;
    for (const t of tags(html, ['script']).filter(t => !t.text)) {
      const src = t.attrs.get('src');
      if (!src || !/^(https?:)?\/\//i.test(src)) continue;
      let u: URL; try { u = new URL(src, pageUrlOf(ctx) ?? 'https://invalid.invalid/'); } catch { continue; }
      if (u.host === host) continue;
      if (isTrustedOrigin(u, trusted)) { skipped++; continue; }
      const g = byOrigin.get(u.origin) ?? { total: 0, missing: [] };
      // 空の integrity=""（空白だけを含む）は、ブラウザが検証しない（integrity なしと同じ）
      g.total++; if (!t.attrs.get('integrity')?.trim()) g.missing.push(t);
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
/** エスケープした引用符（HTML の文字参照、JS のエスケープ）。E-09 のキーの代入は、戻してからも見る */
const ESCAPED_QUOTE = /&(?:quot|apos|#0*3[49]|#x0*2[27]);|\\(?:u002[27]|x2[27]|["'])/i;
const unescapeQuotes = (s: string) => s
  .replace(/&(?:quot|#0*34|#x0*22);|\\u0022|\\x22|\\"/gi, '"')
  .replace(/&(?:apos|#0*39|#x0*27);|\\u0027|\\x27|\\'/gi, "'");
/**
 * 秘密ではない値（A-07 と同じ判定）：英語の画面の文言（isLabelText）、ブラウザから使う前提の公開のキー（isPublicClientValue。Google の AIza…、
 * Stripe の pk_live_…、PaymentIntent の client_secret）、伏せ字、入力の検証の規則・autocomplete の値（notSecretFormat）、
 * パス（password:"/users/password/new"）・URL・翻訳キー・テンプレート・セレクタ・項目の名前・エスケープした日本語の文言（notSecretText）
 */
const notSecretValue = (key: string, v: string): boolean =>
  isLabelText(key, v) || isPublicClientValue(v) || isPlaceholderValue(v)
  || notSecretFormat(v) || notSecretText(v);
/** 公開を前提にした JWT（ペイロードの role が anon。Supabase の anon key） */
const publicJwt = (payload: string): boolean => b64urlJson(payload)?.role === 'anon';
const PUBLIC_SDK = /\b(?:docsearch|algoliasearch|instantsearch|Bugsnag\.start|bugsnag|Sentry\.init|mixpanel\.init|amplitude\.(?:init|getInstance)|posthog\.init|LogRocket\.init|Rollbar\.init|datadogRum\.init)\s*\([^)]{0,300}$/;
/** AWS のアクセスキー。大文字だけで、語の境目で区切る（base64 の途中の …zakia… に一致させない。E-01① も使う） */
export const AWS_KEY = /\bAKIA[0-9A-Z]{16}\b/;
const SECRETS: [string, { test(s: string): boolean }][] = [
  ['AWSアクセスキー', AWS_KEY],
  ['秘密鍵', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['Slackトークン', /\bxox[baprs]-[0-9A-Za-z-]{10,}/],
  ['GitHubトークン', /\bgh[pousr]_[0-9A-Za-z]{36,}\b/],
  // ブラウザに渡す前提の JWT（Supabase の anon key。ペイロードの role が anon）は除く（行レベルのセキュリティで守る公開のキー）。
  // 始まりは直前が英数字・ハイフンでないところだけ（\b は「-eyJ」の繰り返しで2乗の時間になる）
  ['JWT', { test: (s: string) => [...s.matchAll(/(?<![\w-])eyJ[\w-]{10,}\.(eyJ[\w-]{10,})\.[\w-]{10,}/g)].some(m => !publicJwt(m[1])) }],
  // ブラウザで使う前提の SDK の呼び出しの中の apiKey（Algolia の docsearch・algoliasearch の検索専用のキー、Bugsnag・Sentry などの通知用のキー）は除く。
  // 属性の中の JSON（Inertia の data-page="{&quot;api_key&quot;:…}"）と、JS の文字列の中の JSON（JSON.parse("{\"api_key\":…}")）は、
  // 引用符を戻してからも見る
  ['キー・シークレットの代入', { test: (s: string) => [s, ...(ESCAPED_QUOTE.test(s) ? [unescapeQuotes(s)] : [])].some(x => [...x.matchAll(ASSIGNED)].some(m => !notSecretValue(m[1], m[2]) && !PUBLIC_SDK.test(x.slice(Math.max(0, (m.index ?? 0) - 300), m.index)))) }],
];
/**
 * URL の始まりとホスト（ポートを含む）。ホストまでだけを読む（?to=http://10.0.0.1/ のような URL の中の URL も見る）。
 * ユーザー情報（user:pass@host）のあるものは見ない（証跡にパスワードを出さない）
 */
const URL_AUTHORITY = /https?:\/\/([^\s"'<>/?#\\@]+)(?=[\s"'<>/?#\\]|$)/gi;
const URL_REST = /[^\s"'<>]*/y;
/**
 * 内部URL：ホスト名が内部のホスト（INTERNAL_HOST。ホスト名の最後で区切るので edge01.local.example-cdn.net は除く）のもの。
 * 診断した URL 自身のホスト（社内のポータル https://portal.corp/、http://localhost:3000/ の自サイトへのリンク）は除く
 */
function internalUrl(html: string, own?: string): string | undefined {
  for (const m of html.matchAll(URL_AUTHORITY)) {
    let u: URL; try { u = new URL(m[0]); } catch { continue; }
    if (!INTERNAL_HOST.test(u.hostname) || u.host.toLowerCase() === own) continue;
    URL_REST.lastIndex = m.index;
    return URL_REST.exec(html)![0];
  }
  return undefined;
}
// 開発用の語：英字の境目で照合する（「_」も境目にする。debug_mode・staging_db も見る。\b は「_」を語の一部とみなす）。
// 大文字・小文字を区別して、後ろに小文字が続かないもの（debugMode・debug_mode は見る。/i では debugMode の M も小文字と同じに扱う）。
// キャメルケースの途中（isDebug・useStaging）も見る
const DEV_CODE_WORD = /(?<![A-Za-z])(?:TODO|FIXME|XXX|HACK|[Dd]ebug|DEBUG|[Ss]taging|STAGING)(?![a-z])|(?<=[a-z])(?:Debug|Staging)(?![a-z])/;
// password（複数形を含む）・パスワード・本番。画面の部品の説明（<!-- Password field -->、パスワード欄）は除く。
// pass だけの語は、値の代入（pass: …、pass=…）か、数字・数字を含む語が続くもの（admin/pass123、pass admin123）だけ
// （「Tests pass」「tests pass 100%」「pass 2 of 3」は開発用のコメントではない）
const DEV_WORD = /(?<![A-Za-z])pass(?:\s*[:=]|\d|\s+[A-Za-z][^\s<]*\d)|(?<![A-Za-z])passwords?(?![a-z])(?![\s_-]*(?:field|input|label|form|reset|box|placeholder|strength|hint|toggle|visibility|policy)\b)|パスワード(?!欄|入力|を忘れ|の再設定|の変更|変更|リセット)|本番/i;
/**
 * コメントの中だけで開発用の語を探し、一致した語を返す。コメントは scan で切り出す（ブラウザと同じく「<!-->」は空のコメント、「--!>」でも閉じ、
 * <script> の文字列の中の「<!--」はコメントではない）。コメントの外（前後のコメントにはさまれた本文）には一致させない
 */
export function devCommentWord(html: string): string | undefined {
  for (const [from, to] of scan(html, []).comments) {
    // Knockout の制御のコメント（<!-- ko if: showDebug -->・<!-- /ko -->）は、開発用のコメントではない
    const c = html.slice(from, to); const m = /^\s*\/?ko\b/.test(c) ? null : c.match(DEV_CODE_WORD) ?? c.match(DEV_WORD);
    // 一致した語だけを返す（「pass Summer2024」の値の部分を証跡に出さない）
    if (m) return /^pass/i.test(m[0]) && !/^passwords?$/i.test(m[0]) ? 'pass' : m[0];
  }
  return undefined;
}
export const htmlSecrets: Rule = { id: 'E-09', title: 'HTML本文：機密・内部情報', appliesTo: 'html', scope: 'target',
  basis: ['OWASP WSTG-INFO-05'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html) return noHtmlBody(htmlSecrets, ctx);
    const out = [];
    // OpenID Connect の response_mode=form_post：IdP は id_token・access_token を hidden の欄に入れて、アプリへ POST する画面を返す。
    // 利用者のブラウザに渡すのが仕事のトークンなので、その欄の値は秘密情報の露出として数えない（自社の Keycloak などを対象にしたとき）。
    // 除くのはその input のタグだけ（値の文字列をページ全体から消すと、ほかの秘密の一部まで消える）。タグの終わりは字句解析の > で、
    // 引用符で囲んだ属性の値の中の >（data-x="a>b"）では切らない（切ると、後ろの value のトークンを本文の秘密として E-09① にする）
    const posted = forms(html).filter(f => (f.form.attrs.get('method') ?? '').toLowerCase() === 'post')
      .flatMap(f => f.inputs).filter(i => i.attrs.get('type')?.toLowerCase() === 'hidden' && /^(?:id_token|access_token|code|state)$/i.test(i.attrs.get('name') ?? ''))
      .map(i => [i.index, i.end + 1] as const).sort((a, b) => b[0] - a[0]);
    const text = posted.reduce((h, [s, e]) => h.slice(0, s) + h.slice(e), html);
    for (const [name, re] of SECRETS) if (re.test(text)) out.push(mk(htmlSecrets, ctx, 1, 'high', 'fail', `本文に「${name}」らしき値（値は表示しない）`, '秘密情報をHTML・JavaScriptに含めない。漏れた値は失効させる'));
    const iu = internalUrl(html, pageHostOf(ctx)?.toLowerCase());
    if (iu) out.push(mk(htmlSecrets, ctx, 2, 'low', 'fail', `内部URL: ${excerpt(iu, 120)}`, '本番のHTMLに内部URLを残さない'));
    // コメントの中身はパスワードなどを含みうるので、証跡には一致した語だけを出す
    const dc = devCommentWord(html);
    if (dc) out.push(mk(htmlSecrets, ctx, 2, 'low', 'fail', `開発用コメント（「${dc}」を含む。中身は表示しない）`, 'ビルド時にコメントを削除する'));
    // 「Drupal 10 (https://www.drupal.org)」のように主な版だけのものも版とみなす（H-16 の X-Generator と同じ）
    const gen = tags(html, ['meta']).find(t => t.attrs.get('name')?.toLowerCase() === 'generator' && /\b\d+\b/.test(t.attrs.get('content') ?? ''));
    if (gen) out.push(mk(htmlSecrets, ctx, 3, 'info', 'fail', gen.evidence, 'generator のバージョンを出さない'));
    return out.length ? out : [mk(htmlSecrets, ctx, 'ok', 'info', 'pass', '秘密情報・内部情報らしき記述なし', '')];
  } };

/** stop：その form の中の終わり（閉じタグか次の form の位置） */
type Form = { form: Tag; inputs: Tag[]; stop: number };
let formsMemo: { html: string; out: Form[] } | undefined;   // E-09・E-10・E-12 が同じ本文で呼ぶ
/**
 * form ごとに、その中（閉じタグか次の form まで）の input を集める。input の位置（index）はページ全体での位置（E-09 がその位置のタグを取り除く）。
 * 閉じタグは前に進むだけで探す（form ごとに本文の終わりまで探すと、閉じのない <form> の並びで2乗の時間になる）
 */
function forms(html: string): Form[] {
  if (formsMemo?.html === html) return formsMemo.out;
  const ts = tags(html, ['form', 'input']).filter(t => !t.text);
  const fs = ts.filter(t => t.name === 'form'), inputs = ts.filter(t => t.name === 'input');
  // 元の文字列で探す（toLowerCase で長さが変わる文字（İ など）があると、位置がずれる）
  const closeRe = /<\/form\s*>/gi; let close = -1; let j = 0;
  const out = fs.map((f, k) => {
    if (close < f.index) { closeRe.lastIndex = f.index; close = closeRe.exec(html)?.index ?? Infinity; }
    const stop = Math.min(close, fs[k + 1]?.index ?? html.length);
    while (j < inputs.length && inputs[j].index < f.index) j++;
    const own: Tag[] = [];
    while (j < inputs.length && inputs[j].index < stop) own.push(inputs[j++]);
    return { form: f, inputs: own, stop };
  });
  formsMemo = { html, out };
  return out;
}

/** フォームの送信先が http か（ページの URL が分からなければ、送信先そのものが http:// で始まるか） */
const sendsInClear = (action: string, page?: string): boolean => {
  try { return new URL(action.trim(), page).protocol === 'http:'; } catch { return /^\s*http:\/\//i.test(action); }
};

export const passwordForm: Rule = { id: 'E-10', title: 'HTML本文：パスワードフォーム', appliesTo: 'html', scope: 'target',
  basis: ['IPA', 'OWASP Authentication CS'],
  run(ctx) {
    const html = htmlBody(ctx);
    if (!html) return noHtmlBody(passwordForm, ctx);
    const pw = forms(html).filter(f => f.inputs.some(i => i.attrs.get('type')?.toLowerCase() === 'password'));
    if (!pw.length) return [];
    const out = [];
    for (const { form } of pw) {
      const action = form.attrs.get('action') ?? '';
      // 送信先はページの URL を基準に読む（ブラウザと同じ）。http のページの相対の送信先（/login・空・//host/login）も平文で送る
      if (sendsInClear(action, pageUrlOf(ctx))) out.push(mk(passwordForm, ctx, 1, 'high', 'fail', form.evidence, 'フォームの送信先を https:// にする'));
      if ((form.attrs.get('method') ?? 'get').toLowerCase() !== 'post') out.push(mk(passwordForm, ctx, 2, 'medium', 'fail', form.evidence, 'パスワードは method="post" で送る（URLに残さない）'));
    }
    return out.length ? out : [mk(passwordForm, ctx, 'ok', 'info', 'pass', `パスワードフォーム${pw.length}件は https・POST`, '')];
  } };

const TOKEN_NAME = /csrf|xsrf|token|authenticity|nonce|__RequestVerificationToken|_wpnonce/i;
export const csrfToken: Rule = { id: 'E-12', title: 'HTML本文：CSRFトークンの有無', appliesTo: 'html', scope: 'target',
  basis: ['OWASP CSRF Prevention CS'],
  run(ctx) {
    if (ctx.sensitive === false) return [];
    const html = htmlBody(ctx);
    if (!html) return noHtmlBody(csrfToken, ctx);
    const posts = forms(html).filter(f => (f.form.attrs.get('method') ?? '').toLowerCase() === 'post');
    if (!posts.length) return [];
    const missing = posts.filter(f => !f.inputs.some(i => i.attrs.get('type')?.toLowerCase() === 'hidden' && TOKEN_NAME.test(i.attrs.get('name') ?? '')));
    if (!missing.length) return [mk(csrfToken, ctx, 'ok', 'info', 'pass', `POSTフォーム${posts.length}件にトークンらしき項目あり`, '')];
    // ①は「トークンがなく、SameSite も Lax/Strict でない」。認証後ページ（機密応答）が前提なので、機密かどうか分からなければ na（第0章 0.3）
    if (ctx.sensitive === undefined)
      return [mk(csrfToken, ctx, 'na', 'info', 'na', `トークンのないPOSTフォーム${missing.length}件（機密応答かどうか分からない）`, SENSITIVE_REC)];
    if (ctx.hostSessionSameSite === true)
      return [mk(csrfToken, ctx, 'ok', 'info', 'pass', `トークンのないPOSTフォーム${missing.length}件。同じホストのセッションCookieは SameSite=Lax/Strict`, '')];
    return missing.map(f => mk(csrfToken, ctx, 1, 'info', 'fail', f.form.evidence,
      ctx.hostSessionSameSite === false ? 'POSTフォームにCSRFトークンを入れる（セッションCookieも SameSite=Lax/Strict でない。実効性の確認は範囲外）'
                                        : 'POSTフォームにCSRFトークンを入れる（セッションCookieが見つからないため SameSite は確認できない。実効性の確認は範囲外）'));
  } };

const NON_TEXT_INPUT = /^(?:hidden|password|submit|button|checkbox|radio|image|reset|file|range|color)$/i;
const attrOf = (t: Tag, name: string) => t.attrs.get(name) ?? '';
const isPassword = (t: Tag) => attrOf(t, 'type').toLowerCase() === 'password';
/** フォームごとの input。form のない本文（フォームを使わない画面）は、本文の input をまとめて1つとする */
const inputGroups = (html: string): { form?: Tag; inputs: Tag[] }[] => {
  const fs = forms(html);
  return fs.length ? fs : [{ inputs: tags(html, ['input']).filter(t => !t.text) }];
};
/** ログインのフォームの送信先らしいパス（C-12 の送信先の確認と、パスワード欄だけのフォーム） */
export const LOGIN_ACTION = /(?:^|\/)(?:log-?in|sign[-_]?in|signon|sessions?|auth(?:enticate)?|j_(?:spring_)?security_check)(?:[/?.#]|$)/i;
const SETTING_FIELD = /(?:^|[\s_-])(?:new|confirm|confirmation|retype|repeat)(?:[\s_-]|$)|new[-_]?pass|(?:pass(?:word)?|pwd)[-_]?confirm/i;
/**
 * ログイン画面・認証の入り口のパス（C-09・C-12・T-06 で共有。パスの最後で一致させる）：/login・/signin・Devise の /users/sign_in・
 * /wp-login.php・/authorize・oauth2-proxy の /oauth2/start・Spring Security の /oauth2/authorization/<登録名>、拡張子の付いたもの
 * （/Account/Login.aspx、/login.php・.jsp・.do）、OIDC・SAML の IdP の入り口（…/openid-connect/auth、Google の /o/oauth2/v2/auth・/o/saml2/idp、
 * Shibboleth の /idp/profile/SAML2/Redirect/SSO、ADFS の /adfs/ls、SimpleSAMLphp の SSOService.php、Entra ID の /<テナント>/saml2、
 * Okta の /sso/saml、Auth0 の /samlp/<クライアント>）
 */
export const LOGIN_PATH = /\/(?:log-?in|sign[-_]?in|signon|auth\/login|wp-login|authorize|oauth2\/(?:start|auth(?:orize)?)|oauth2\/authorization\/[\w.-]+|o\/oauth2(?:\/v\d)?\/auth|protocol\/openid-connect\/auth|saml2?\/(?:login|sso)|SAML2\/(?:Redirect|POST)\/SSO|adfs\/ls|SSOService|saml2?|sso\/saml|o\/saml2\/idp|samlp)(?:\.(?:php|aspx?|jspx?|do|action|html?|cgi|pl))?\/?$/i;
/**
 * ログインのフォームがあるか。フォームごとに見る（ログインと登録のフォームが並ぶ画面（WooCommerce）があるため）。パスワード欄が1つで、次のどれでもないもの：
 * - パスワードを決める欄（name・id・autocomplete に new・confirm・retype・repeat があるもの。autocomplete="new-password"）
 * - 再認証の欄（name に current_password・old_password、id に old_password があるもの。Devise の user[current_password]、メールアドレスの変更の画面）。
 *   ただし web.dev が勧めるログイン画面（name="current-password" と autocomplete="current-password"）と、id だけが currentPassword のものは除かない
 * そのうえで、ユーザー名の欄（文字を入力する input か、2段階のログイン画面の hidden の username など）があるもの。パスワード欄だけのフォームは、
 * autocomplete="current-password" で、送信先（action）がログインらしいもの（sudo・reauth・confirm・verify を除く）だけ
 * （ユーザー名を文字で表示した2段階目の画面を、GitHub の sudo モードのような再認証の画面と分けるため）。
 * フォームと input は forms()・tags() で読む（ブラウザと同じ字句解析。<form-field> のようなカスタム要素をフォームとしない）
 */
export function loginForm(body: string): boolean {
  return inputGroups(body).some(({ form, inputs }) => {
    const pw = inputs.filter(isPassword);
    if (pw.length !== 1) return false;
    const ac = attrOf(pw[0], 'autocomplete'), pwName = attrOf(pw[0], 'name');
    if (SETTING_FIELD.test(`${pwName} ${attrOf(pw[0], 'id')} ${ac}`)) return false;
    const currentPassword = /\bcurrent-password\b/i.test(ac);
    // 再認証の欄を除く。name の current_password は、name がちょうど current-password で autocomplete も current-password のときだけ認める
    // （Devise の再認証のフォームも autocomplete="current-password" を付ける）。id は old-password・old_password だけを見る
    if ((/(?:current|old)[-_]?pass/i.test(pwName) && !(currentPassword && /^current-password$/i.test(pwName))) || /old[-_]?pass/i.test(attrOf(pw[0], 'id'))) return false;
    const user = inputs.some(t => !NON_TEXT_INPUT.test(attrOf(t, 'type')))
      || inputs.some(t => /^hidden$/i.test(attrOf(t, 'type')) && /^(?:user(?:name)?|email|login|identifier|j_username)$/i.test(attrOf(t, 'name')));
    if (user) return true;
    const action = form ? attrOf(form, 'action') : '';
    return currentPassword && LOGIN_ACTION.test(action) && !/sudo|re-?auth|confirm|verify/i.test(action);
  });
}
/** パスワード欄（type=password の input）があるか。CSS・JavaScript の中の「type=password」の文字は数えない */
export const hasPasswordField = (html: string): boolean => tags(html, ['input']).some(t => !t.text && isPassword(t));
/** パスワード欄のあるフォームの送信先（action の属性がなければ undefined） */
export const passwordFormActions = (html: string): (string | undefined)[] =>
  forms(html).filter(f => f.inputs.some(isPassword)).map(f => f.form.attrs.get('action'));

/**
 * ログアウトできたと言えない理由（証跡と推奨）。応答が失敗（4xx・5xx）しているか、ログアウトの確認画面なら、ログアウトしていない（GET の /logout に
 * 405 を返すアプリなど）。同じページへの転送（apex → www、末尾の /）はたどった先で見て、転送先を採取していなければ分からない。
 * どちらでも C-12（ログアウト後の無効化・Cookie の削除）と H-15 を判定しない
 */
export function logoutProblem(t: Target): { ev: string; rec: string } | undefined {
  const { hop, unfollowed } = sameDocumentHop(t); const s = hop?.status ?? firstStatus(t);
  if (unfollowed) return { ev: `ログアウトの応答が HTTP ${s}（同じページへの転送。転送先を採取していない）`, rec: FOLLOW_REC };
  if (s >= 400 || (s >= 200 && s < 300 && logoutConfirmPage(t))) return { ev: `ログアウトの応答が HTTP ${s}（ログアウトできていない）`, rec: LOGOUT_FAILED_REC };
  return undefined;
}
/**
 * ログアウトの確認画面（GET では「ログアウトしますか」のフォームを返すだけで、POST でログアウトする作り。ASP.NET Core Identity の既定の画面、
 * Spring Security の既定のログアウトの確認画面）。次のすべてに当たるもの：
 * - セッションCookie らしい名前の Cookie を消しも発行し直しもせず、Clear-Site-Data もない（AWSALB のような毎回の Cookie は見ない）
 * - 本文に、送信先（action）に logout・signout・logoff の語がある POST のフォームがあり、その中にログアウトのボタンの文言がある
 *   （action のないフォームや購読のフォームを置くだけで本物のログアウトの C-12① を na に隠せないよう、送信先と文言の両方を見る）
 * - パスワード欄（ログアウトのあとのログインの画面）と、ASP.NET WebForms の __VIEWSTATE（ページ全体を囲むフォーム）がない。
 *   パスワード欄はタグで見る（CSS・JavaScript の「type=password」の文字で、確認画面を見逃さない）
 */
function logoutConfirmPage(t: Target): boolean {
  if (ownChain(t).some(r => r.headers.has('clear-site-data') || (r.headers.get('set-cookie') ?? []).some(c => looksLikeSessionName(parseSetCookie(c).name)))) return false;
  const body = finalResponse(t)?.body ?? '';
  if (/__VIEWSTATE/i.test(body) || hasPasswordField(body)) return false;
  return forms(body).some(({ form, stop }) => {
    if (form.attrs.get('method')?.trim().toLowerCase() !== 'post' || !LOGOUT_WORD.test(form.attrs.get('action') ?? '')) return false;
    const inner = body.slice(form.end + 1, Math.min(stop, form.end + 4000));
    return LOGOUT_WORD.test(inner.replace(/<[^>]{0,500}>/g, ' ')) || /value\s*=\s*["'][^"']{0,40}(?:log\s*out|sign\s*out|ログアウト)/i.test(inner);
  });
}
