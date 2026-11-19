// rules/cors.ts：第3章 CORS・WebSocket（R-01〜R-09）
import type { Rule, RuleContext, Target } from '../model';
import { baseLabel, hostOf, hostnameOf, siteOf, targetUrl } from '../parser/target';
import { looksLikeSessionName } from '../parser/setCookie';
import { SENSITIVE_REC, TEST_HOST, mk, noResponse, sensitiveUnlessStatic } from './util';

const TEST_ORIGINS = [`https://${TEST_HOST}`];        // 既知のテスト値（ツール設計1）
/** 送った Origin のホスト（ポートを含む）が、対象の URL のホストと同じか（ws・wss と http・https の違いは問わない） */
const sameHostOrigin = (ctx: RuleContext): boolean => {
  const o = ctx.target.sentOrigin; const host = hostOf(ctx.target);
  if (!o || !host) return false;
  try { return new URL(o).host.toLowerCase() === host.toLowerCase(); } catch { return false; }
};
// ACAO・ACAC が2回以上あれば、ブラウザは値を「, 」でつないだ1つの値として見る（Fetch Standard）。つないだ値は Origin とも * とも一致せず、
// CORS の検査は失敗する（アプリと nginx の add_header が両方付けた応答を、最初の値だけで反射（R-01①）としない）
const acaoOf = (ctx: RuleContext) => ctx.final?.headers.get('access-control-allow-origin')?.map(v => v.trim()).join(', ') || undefined;
// ACAC は値が「true」と完全に一致するときだけ資格情報を許可する（大文字・小文字を区別する。TRUE はブラウザが受け付けない）
const credOf = (ctx: RuleContext) => ctx.final?.headers.get('access-control-allow-credentials')?.map(v => v.trim()).join(', ') === 'true';

/**
 * 送信した Origin が、対象の URL 自身のオリジン（スキーム・ホスト・ポートが同じ）か。自分のオリジンへの ACAO は正しい動作で、
 * 許可外の Origin を反射するかは分からない。サブドメインや http のオリジン（http://a.example）は含めない：
 * http は経路上の誰でも偽れ、サブドメインは共用のホスティング（*.herokuapp.com、*.github.io）では他人のものでありうる
 */
function isOwnOrigin(ctx: RuleContext, origin?: string): boolean {
  try { return !!origin && !!ctx.target.url && new URL(origin).origin === new URL(ctx.target.url).origin; } catch { return false; }
}
/**
 * 送信したOriginが「対象ホストに似せた偽物」か（R-03 のテスト値：example.com.evil.net、evilexample.com など）。
 * 対象がサブドメイン（api.example.com）でも、そのサイト（example.com）に似せたもの（example.com.evil.net）を R-03 で判定する。
 * 同じサイトのサブドメイン（app.example.com）は、似せたものではない（R-01 で判定する）
 */
function isLookalike(ctx: RuleContext, origin?: string): boolean {
  const host = hostnameOf(targetUrl(ctx.target));
  const h = hostnameOf(origin);
  if (!host || !h) return false;
  const site = siteOf(host);
  if (h === site || h.endsWith(`.${site}`)) return false;
  return [...new Set([host.replace(/^www\./, ''), siteOf(host)])].some(c => h.includes(c));   // 例：example.com.evil.net、evilexample.com
}

/**
 * -v で採取したのに Origin を送っていない（送信ヘッダは全部見えている）。CORS のミドルウェアの多くは Origin があるときだけ ACAO を返すので、
 * ACAO がないことは「反射しない」「null を許可しない」の根拠にならない（合格にすると、カバレッジも水増しになる）。HAR もリクエストのヘッダが
 * 分かるので -v と同じに扱う。-i では送信ヘッダが見えないので対象外
 */
const sentHeadersVisible = (t: Target) => !!t.verbose || t.meta.source === 'har';
const noOriginSent = (ctx: RuleContext) => sentHeadersVisible(ctx.target) && !ctx.target.sentOrigin;
/** Origin: null を送った応答か（送った Origin が分からない -i では cors-null のラベル） */
const sentNull = (ctx: RuleContext) => ctx.target.sentOrigin === 'null' || (ctx.target.sentOrigin === undefined && baseLabel(ctx.target.label) === 'cors-null');
const NO_ORIGIN_REC = 'C6 のとおり Origin を付けて（-H "Origin: https://evil.example"、R-02 は "Origin: null"）採取し直す';
export const corsReflect: Rule = { id: 'R-01', title: 'Origin反射', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: CORS', 'OWASP WSTG'],
  run(ctx) {
    if (!ctx.final) return [noResponse(corsReflect, ctx)];
    const acao = acaoOf(ctx);
    if (isLookalike(ctx, ctx.target.sentOrigin)) return [];   // 似せたOriginのテストは R-03 で判定する
    // 対象の URL 自身のオリジンを送った応答では、許可外の Origin を反射するかは分からない（反射しても正しい動作）
    if (isOwnOrigin(ctx, ctx.target.sentOrigin))
      return [mk(corsReflect, ctx, 'na', 'info', 'na', `Origin: ${ctx.target.sentOrigin}（自サイトの Origin。許可外の Origin では試していない）`, 'C6 のとおり許可外の Origin（https://evil.example）で採取し直す')];
    if (noOriginSent(ctx)) return [mk(corsReflect, ctx, 'na', 'info', 'na', 'Origin を送っていない（-v の送信ヘッダに Origin がない）', NO_ORIGIN_REC)];
    // Origin: null を送った応答（cors-null）では、許可外の Origin を反射するかは試していない（null は R-02 で判定する）
    if (sentNull(ctx)) return [mk(corsReflect, ctx, 'na', 'info', 'na', 'Origin: null を送った応答（R-02 で判定する）', 'C6 のとおり許可外の Origin（https://evil.example）で採取する')];
    const ok = () => [mk(corsReflect, ctx, 'ok', 'info', 'pass', acao ? `ACAO: ${acao}` : '(ACAOなし)', '')];
    if (!acao || acao === '*' || acao === 'null') return ok();   // * は R-04、null は R-02 で判定する
    const sent = ctx.target.sentOrigin ?? (TEST_ORIGINS.includes(acao) ? acao : undefined);
    if (!sent) return [mk(corsReflect, ctx, 'na', 'info', 'na', `ACAO: ${acao}`, '送信したOriginが分からない。-v 付きで再取得する')];
    if (acao !== sent) return ok();
    const cred = credOf(ctx);
    return [mk(corsReflect, ctx, cred ? 1 : 2, cred ? 'high' : 'medium', 'fail',
               `Origin: ${sent} → ACAO: ${acao}${cred ? ' / ACAC: true' : ''}`, '許可リストとの完全一致で判定し、一致しないOriginにはACAOを返さない')];
  } };

export const corsNull: Rule = { id: 'R-02', title: 'null許可', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: CORS'],
  run(ctx) {
    if (!ctx.final) return [noResponse(corsNull, ctx)];
    const acao = acaoOf(ctx);
    if (acao !== 'null' && noOriginSent(ctx)) return [mk(corsNull, ctx, 'na', 'info', 'na', 'Origin を送っていない（-v の送信ヘッダに Origin がない）', NO_ORIGIN_REC)];
    // 合格にするのは、Origin: null を送った応答だけ。evil.example を送った応答の ACAO から、null を許可しないとは言えない
    // （どの Origin も反射するサーバは null も許可することが多い）
    if (acao !== 'null' && !sentNull(ctx)) return [mk(corsNull, ctx, 'na', 'info', 'na', `Origin: ${ctx.target.sentOrigin ?? '(不明)'}（null では試していない）`, 'C7 のとおり Origin: null を送って採取する')];
    if (acao !== 'null') return [mk(corsNull, ctx, 'ok', 'info', 'pass', acao ? `ACAO: ${acao}` : '(ACAOなし)', '')];
    const cred = credOf(ctx);
    return [mk(corsNull, ctx, cred ? 1 : 2, cred ? 'high' : 'medium', 'fail', `ACAO: null${cred ? ' / ACAC: true' : ''}`, 'Origin: null を許可しない（サンドボックス化したiframeやファイルから送られる）')];
  } };

export const corsPartial: Rule = { id: 'R-03', title: '部分一致の不備', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: CORS'],
  run(ctx) {
    // 送った Origin が見えない -i の cors-partial（C6 の似せた Origin）は、R-01 のテスト値と同じく、似せた Origin の ACAO を反射とみなす。
    // ACAO が似せた形でなければ、何を送ったか分からないので na（R-01 も na なので、[]（適用外）にすると何も判定しないことが見えない）
    const partialLabel = ctx.target.sentOrigin === undefined && baseLabel(ctx.target.label) === 'cors-partial';
    const acao = acaoOf(ctx);
    const sent = ctx.target.sentOrigin ?? (partialLabel && isLookalike(ctx, acao) ? acao : undefined);
    if (partialLabel && !ctx.final) return [noResponse(corsPartial, ctx)];
    if (partialLabel && !sent) return [mk(corsPartial, ctx, 'na', 'info', 'na', `送った Origin が分からない（${acao ? `ACAO: ${acao}` : 'ACAOなし'}）`, '-v を付けて、Origin を送って採取し直す')];
    if (!isLookalike(ctx, sent)) return [];                   // 似せたOriginを送ったターゲットだけ
    if (!ctx.final) return [noResponse(corsPartial, ctx)];
    if (acao !== sent) return [mk(corsPartial, ctx, 'ok', 'info', 'pass', `Origin: ${sent} → ${acao ? `ACAO: ${acao}` : '(ACAOなし)'}`, '')];
    const cred = credOf(ctx);
    return [mk(corsPartial, ctx, cred ? 1 : 2, cred ? 'high' : 'medium', 'fail', `Origin: ${sent} → ACAO: ${acao}${cred ? ' / ACAC: true' : ''}`, '前方一致・部分一致ではなく、許可リストとの完全一致で判定する')];
  } };

export const corsWildcard: Rule = { id: 'R-04', title: 'ワイルドカード', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'OWASP HTML5 Security CS'],
  run(ctx) {
    if (!ctx.final) return [noResponse(corsWildcard, ctx)];
    const acao = acaoOf(ctx);
    // Origin を送っていない応答の ACAO のなさは、* を返さないことの証拠にならない（Spring の allowedOrigins("*") など、ミドルウェアの多くは
    // Origin があるときだけ ACAO を返す）ので、R-01・R-02 と同じく na（合格にするとカバレッジも水増しになる）。-i（送ったヘッダが見えない）でも、
    // cors-* のラベル（C6 のとおり Origin を送る）でなければ、送ったとは分からないので同じく na（curl と HAR で結果をそろえる）
    if (!acao && !ctx.target.sentOrigin && (noOriginSent(ctx) || !/^cors-/.test(baseLabel(ctx.target.label))))
      return [mk(corsWildcard, ctx, 'na', 'info', 'na', 'ACAOなし（Origin を送っていない、または送ったかが分からない）', NO_ORIGIN_REC)];
    if (acao !== '*') return [mk(corsWildcard, ctx, 'ok', 'info', 'pass', acao ? `ACAO: ${acao}` : '(ACAOなし)', '')];
    if (credOf(ctx)) return [mk(corsWildcard, ctx, 2, 'low', 'fail', 'ACAO: * / ACAC: true', '仕様上ブラウザが拒否する組み合わせ。設定を見直す')];
    const sensitive = sensitiveUnlessStatic(ctx);    // JS・フォントは CDN から * で配ることが多い。sensitive=1 の明示がなければ機密としない
    if (sensitive) return [mk(corsWildcard, ctx, 1, 'medium', 'fail', 'ACAO: *（機密応答）', '機密応答には * を使わず、許可リストで返す')];
    // 機密かどうか分からないときは①を判定しない（第0章 0.3）。* が付いていることは確かなので、より弱い③として出す
    if (sensitive === undefined) return [mk(corsWildcard, ctx, 3, 'info', 'fail', 'ACAO: *（機密応答かどうか分からない）', '機密応答なら①（中）にあたる。#TARGET に sensitive=1 か sensitive=0 を付ける')];
    return [mk(corsWildcard, ctx, 3, 'info', 'fail', 'ACAO: *', '公開データであれば問題ない。意図どおりか確認する')];
  } };

export const corsPreflight: Rule = { id: 'R-05', title: 'プリフライト応答', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'Fetch Standard'],
  run(ctx) {
    const methods = ctx.final?.headers.get('access-control-allow-methods')?.join(',');
    const maxAge = ctx.final?.headers.get('access-control-max-age')?.[0];
    // プリフライト応答だけ。cors-preflight のラベル（C8 で許可外の Origin のプリフライトを送ったもの）で Allow-Methods も Max-Age もないなら、
    // プリフライトを許可しなかったので合格（適用外にせず、カバレッジで判定済みに数える）。Origin を送っていない OPTIONS はプリフライトではない
    // ので、許可しなかったとは言えない（R-01 と同じく na）
    if (!ctx.final || (!methods && !maxAge)) {
      if (!ctx.final || baseLabel(ctx.target.label) !== 'cors-preflight') return [];
      if (noOriginSent(ctx)) return [mk(corsPreflight, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（Origin を送っていない）`, NO_ORIGIN_REC)];
      return [mk(corsPreflight, ctx, 'ok', 'info', 'pass', `HTTP ${ctx.final.status}（プリフライトを許可していない）`, '')];
    }
    const out = [];
    const acao = acaoOf(ctx); const sent = ctx.target.sentOrigin;
    // 許可外の Origin を許可したか：R-01 と同じく、送った Origin（自サイト以外）を反射したか。送った Origin が分からない -i では、テスト値の ACAO
    const foreign = acao === '*' || (!!acao && !!sent && acao === sent && !isOwnOrigin(ctx, sent)) || (!sent && !!acao && TEST_ORIGINS.includes(acao));
    // Allow-Methods: * は、資格情報（Cookie）を伴わないリクエストではすべてのメソッドを許す（Fetch Standard）。ACAC: true のときは
    // 「*」という名前のメソッドの意味になるので、状態を変えるメソッドの許可にはしない
    const anyMethod = !!methods && /(?:^|,)\s*\*\s*(?:,|$)/.test(methods) && !credOf(ctx);
    if (methods && foreign && (/\b(PUT|DELETE|PATCH)\b/i.test(methods) || anyMethod))
      out.push(mk(corsPreflight, ctx, 1, 'medium', 'fail', `ACAO: ${acao} / Allow-Methods: ${methods}`, '許可外のOriginに状態を変えるメソッドを許可しない'));
    if (maxAge && Number(maxAge) > 7200) out.push(mk(corsPreflight, ctx, 2, 'info', 'fail', `Access-Control-Max-Age: ${maxAge}`, 'Chromeは7200秒、Safariは600秒で打ち切る。必要な長さにする'));
    return out.length ? out : [mk(corsPreflight, ctx, 'ok', 'info', 'pass', `Allow-Methods: ${methods ?? '-'} / Max-Age: ${maxAge ?? '-'}`, '')];
  } };

export const corsVary: Rule = { id: 'R-06', title: 'Vary: Origin', appliesTo: 'any', scope: 'target',
  basis: ['Fetch Standard', 'MDN'],
  run(ctx) {
    const acao = acaoOf(ctx);
    if (!ctx.final || !acao || acao === '*') return [];       // Origin によって ACAO を変える応答だけ
    // Origin を送っていない（-v の送信ヘッダに Origin がない）のに返した ACAO は、Origin によらない固定の値なので適用外（設計書：「ACAOを動的に返すなら」）
    if (noOriginSent(ctx)) return [];
    const vary = (ctx.final.headers.get('vary') ?? []).join(',').toLowerCase();
    // 名前の一部（X-Origin-Id）ではなく、カンマで区切った1つの値として Origin か * があるか
    if (vary.split(',').some(s => ['origin', '*'].includes(s.trim()))) return [mk(corsVary, ctx, 'ok', 'info', 'pass', `Vary: ${vary}`, '')];
    // プリフライト（OPTIONS）の応答は HTTP のキャッシュに保存されない（RFC 9110 9.3.7）ので、Vary: Origin は要らない
    if (baseLabel(ctx.target.label) === 'cors-preflight') return [];
    // 自サイトの Origin への ACAO は、Origin によって変わる値か、固定の値かが分からない（R-01 と同じく na）
    if (isOwnOrigin(ctx, ctx.target.sentOrigin)) return [mk(corsVary, ctx, 'na', 'info', 'na', `ACAO: ${acao}（自サイトの Origin を送った応答。Origin によって変わる値かが分からない）`, 'C6 のとおり許可外の Origin（https://evil.example）で採取し直す')];
    // 送った Origin と違う ACAO（https://evil.example を送って https://app.example.com が返った）は、Origin によって変わる値か、固定の値かが
    // 分からないので na（許可した Origin を送って ACAO が変わるかを見てもらう）
    if (ctx.target.sentOrigin && !acao.split(/\s*,\s*/).includes(ctx.target.sentOrigin)) return [mk(corsVary, ctx, 'na', 'info', 'na', `ACAO: ${acao}（送った Origin と違う。Origin によって変わる値かが分からない）`, 'ACAO に返った Origin を送って採取し、ACAO が Origin によって変わるかを確かめる')];
    // Vary がなく、送った Origin が分からない（-i。送信ヘッダの見えない採取）ときは、ACAO が Origin によって変わる値かが分からないので na。
    // ただし ACAO が既知のテスト値（https://evil.example）なら、R-01 と同じく送った Origin を反射した値とみなす（R-01 と結果をそろえる）
    if (!ctx.target.sentOrigin && !TEST_ORIGINS.includes(acao)) return [mk(corsVary, ctx, 'na', 'info', 'na', `ACAO: ${acao}（送った Origin が分からない）`, '-v を付けて、Origin を送って採取し直す')];
    return [mk(corsVary, ctx, 1, 'low', 'fail', `ACAO: ${acao} / Vary: ${vary || '(なし)'}`, 'Origin によって ACAO を変えるなら Vary: Origin を付ける（キャッシュ汚染の防止）')];
  } };

// Set-Cookie・Set-Cookie2 は禁止された応答ヘッダで、Access-Control-Expose-Headers に書いてもスクリプトには公開されない（数えない）
const SENSITIVE_EXPOSE = /\b(authorization|x-auth[\w-]*|[\w-]*token[\w-]*|x-internal[\w-]*|x-debug[\w-]*)\b/i;
// 名前に token を含んでも、認証のトークンではないヘッダ：CSRF 対策のトークン（SPA が読むために公開する）、ページ送りのトークン、
// レート制限・利用量の項目（x-ratelimit-remaining-tokens・X-Tokens-Used。LLM の API は消費したトークン数を返す）。
// token を含む名前だけに使う（X-Debug-Async-Trace、X-Internal-Pagecache-Node のような内部ヘッダまで除かないため）。
// used・count・limit は語として見る（X-Account-Token の account の count に一致させない）
const NOT_AUTH_TOKEN = /csrf|xsrf|page|next|continuation|cursor|sync|rate-?limit|remaining|usage|(?:^|[-_])(?:used|count|limit)(?:[-_]|$)/i;
export const corsExpose: Rule = { id: 'R-07', title: 'Access-Control-Expose-Headers', appliesTo: 'any', scope: 'target',
  basis: ['MDN'],
  run(ctx) {
    const v = ctx.final?.headers.get('access-control-expose-headers')?.join(',');
    if (!ctx.final || !v) return [];
    // * は、資格情報（Cookie）を伴わないリクエストでだけすべてのヘッダの意味になる。ACAC: true のときは「*」という名前のヘッダ（Fetch Standard。R-05 と同じ）
    if (v.split(',').some(s => s.trim() === '*') && !credOf(ctx)) return [mk(corsExpose, ctx, 2, 'low', 'fail', v, '公開するヘッダを明示する')];
    if (v.split(',').some(h => SENSITIVE_EXPOSE.test(h) && !(/token/i.test(h) && NOT_AUTH_TOKEN.test(h)))) return [mk(corsExpose, ctx, 1, 'medium', 'fail', v, '認証トークンや内部ヘッダを公開しない')];
    return [mk(corsExpose, ctx, 'ok', 'info', 'pass', v, '')];
  } };

export const timingAllowOrigin: Rule = { id: 'R-08', title: 'Timing-Allow-Origin', appliesTo: 'any', scope: 'target',
  basis: ['W3C Resource Timing', 'MDN'],
  run(ctx) {
    const v = ctx.final?.headers.get('timing-allow-origin')?.join(', ');
    if (!ctx.final || !v) return [];
    const star = /(^|,)\s*\*\s*(,|$)/.test(v); const sensitive = sensitiveUnlessStatic(ctx);
    if (sensitive && star) return [mk(timingAllowOrigin, ctx, 1, 'low', 'fail', `Timing-Allow-Origin: ${v}（機密応答）`, '機密応答には付けないか、Originを限定する（タイミング情報の漏えい）')];
    if (sensitive === undefined && star) return [mk(timingAllowOrigin, ctx, 'na', 'info', 'na', `Timing-Allow-Origin: ${v}（機密応答かどうか分からない）`, SENSITIVE_REC)];
    return [mk(timingAllowOrigin, ctx, 'ok', 'info', 'pass', `Timing-Allow-Origin: ${v}`, '')];
  } };

export const websocketOrigin: Rule = { id: 'R-09', title: 'WebSocketのOrigin検証', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger: Cross-site WebSocket hijacking', 'OWASP WebSocket Security CS'],
  run(ctx) {
    const s = ctx.target.responses.find(r => r.status === 101) ? 101 : ctx.final?.status;
    if (!s) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', '応答がない（--max-time で打ち切られた場合も、101 の行があれば判定できる）', '')];
    const got = s === 101 ? '101 Switching Protocols' : `HTTP ${s}`;
    // 送った Origin が自サイトか、Origin を送っていないなら、許可外の Origin を拒否するかは試していない（101 は正しい動作で、401・403 は
    // 認証が足りないための拒否かもしれない。Origin のないハンドシェイクを受け入れるサーバは多いが、ブラウザは必ず Origin を送る）
    if (sameHostOrigin(ctx)) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', `Origin: ${ctx.target.sentOrigin} で ${got}（自サイトの Origin。許可外の Origin では試していない）`, 'C16 のとおり許可外の Origin（https://evil.example）で採取し直す')];
    if (noOriginSent(ctx)) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', `${got}（Origin を送っていない）`, 'C16 のとおり許可外の Origin（https://evil.example）で採取し直す')];
    // 合格にするのは、拒否を示す応答（401・403）だけ。200・404・426 などは、WebSocket のエンドポイントではない可能性がある（パスの誤りなど）
    if (s === 401 || s === 403) return [mk(websocketOrigin, ctx, 'ok', 'info', 'pass', `許可外Originのハンドシェイクが HTTP ${s}（拒否）`, '')];
    if (s !== 101) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', `HTTP ${s}（WebSocket のエンドポイントではない可能性）`, 'C16 の URL が WebSocket のエンドポイントか確認して採取し直す（拒否なら 401 か 403、受け入れなら 101 が返る）')];
    // 機密かどうかは 0.3 の判定（sensitive=0 の明示を優先し、分からなければ na）に従う
    // -v・HAR で送信ヘッダが見えていて Cookie・Authorization を送っていないなら、認証なしの WebSocket（②）
    const sensitive = ctx.sensitive ?? (sentHeadersVisible(ctx.target) && !ctx.target.sentAuth ? false : undefined);
    // 送った認証が Bearer などのトークンだけ（-v・HAR で送信ヘッダが見え、セッションCookie もブラウザが自動で送る方式の Authorization もない）なら、
    // 攻撃者のページからのハンドシェイクにはトークンが付かないので、クロスサイトの乗っ取りにならない（①（高）にしない）。
    // sensitive=1 の明示があれば従う（セッションCookie の名前の推定から漏れた Cookie で認証する WebSocket を②にしない）
    const t = ctx.target;
    const tokenOnly = t.sensitive === undefined && sentHeadersVisible(t) && !!t.sentAuthorization && !t.sentAutoAuth && !(t.sentCookieNames ?? []).some(looksLikeSessionName);
    if (tokenOnly) return [mk(websocketOrigin, ctx, 2, 'info', 'fail', `Origin: ${t.sentOrigin ?? '(不明)'} で 101 Switching Protocols（Bearer などのトークンの認証。ブラウザはクロスサイトで送らない）`, 'Cookie で認証しないなら乗っ取りにはならない。Origin の許可リストでの照合も行う')];
    if (sensitive === undefined) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', `Origin: ${ctx.target.sentOrigin ?? '(不明)'} で 101 Switching Protocols（Cookie認証かどうか分からない）`, '認証後に使う WebSocket なら #TARGET に sensitive=1、公開用なら sensitive=0 を付ける')];
    return sensitive
      ? [mk(websocketOrigin, ctx, 1, 'high', 'fail', `Origin: ${ctx.target.sentOrigin ?? '(不明)'} で 101 Switching Protocols（Cookie認証）`, 'ハンドシェイクで Origin を許可リストと照合し、許可外は 403 で拒否する')]
      : [mk(websocketOrigin, ctx, 2, 'info', 'fail', `Origin: ${ctx.target.sentOrigin ?? '(不明)'} で 101 Switching Protocols（認証なし）`, '公開用のWebSocketなら問題ない。意図どおりか確認する')];
  } };
