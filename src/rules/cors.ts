// rules/cors.ts：第3章 CORS・WebSocket（R-01〜R-09）
import type { Rule, RuleContext } from '../model';
import { hostOf } from '../parser/target';
import { mk } from './util';

const TEST_ORIGINS = ['https://evil.example'];        // 既知のテスト値（ツール設計1）
const acaoOf = (ctx: RuleContext) => ctx.final?.headers.get('access-control-allow-origin')?.[0]?.trim();
const credOf = (ctx: RuleContext) => ctx.final?.headers.get('access-control-allow-credentials')?.[0]?.trim().toLowerCase() === 'true';

/** 送信したOriginが「対象ホストに似せた偽物」か（R-03 のテスト値：example.com.evil.net、evilexample.com など） */
export function isLookalike(ctx: RuleContext, origin?: string): boolean {
  const host = hostOf(ctx.target)?.replace(/:\d+$/, '').replace(/^www\./, '');
  if (!host || !origin) return false;
  let h: string;
  try { h = new URL(origin).hostname; } catch { return false; }
  return h.includes(host) && h !== host && !h.endsWith(`.${host}`);   // 例：example.com.evil.net、evilexample.com
}

export const corsReflect: Rule = { id: 'R-01', title: 'Origin反射', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: CORS', 'OWASP WSTG'],
  run(ctx) {
    if (!ctx.final) return [mk(corsReflect, ctx, 'na', 'info', 'na', '応答がない', '')];
    const acao = acaoOf(ctx);
    if (isLookalike(ctx, ctx.target.sentOrigin)) return [];   // 似せたOriginのテストは R-03 で判定する
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
    if (!ctx.final) return [mk(corsNull, ctx, 'na', 'info', 'na', '応答がない', '')];
    const acao = acaoOf(ctx);
    if (acao !== 'null') return [mk(corsNull, ctx, 'ok', 'info', 'pass', acao ? `ACAO: ${acao}` : '(ACAOなし)', '')];
    const cred = credOf(ctx);
    return [mk(corsNull, ctx, cred ? 1 : 2, cred ? 'high' : 'medium', 'fail', `ACAO: null${cred ? ' / ACAC: true' : ''}`, 'Origin: null を許可しない（サンドボックス化したiframeやファイルから送られる）')];
  } };

export const corsPartial: Rule = { id: 'R-03', title: '部分一致の不備', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: CORS'],
  run(ctx) {
    const sent = ctx.target.sentOrigin;
    if (!isLookalike(ctx, sent)) return [];                   // 似せたOriginを送ったターゲットだけ
    if (!ctx.final) return [mk(corsPartial, ctx, 'na', 'info', 'na', '応答がない', '')];
    const acao = acaoOf(ctx);
    if (acao !== sent) return [mk(corsPartial, ctx, 'ok', 'info', 'pass', `Origin: ${sent} → ${acao ? `ACAO: ${acao}` : '(ACAOなし)'}`, '')];
    const cred = credOf(ctx);
    return [mk(corsPartial, ctx, cred ? 1 : 2, cred ? 'high' : 'medium', 'fail', `Origin: ${sent} → ACAO: ${acao}${cred ? ' / ACAC: true' : ''}`, '前方一致・部分一致ではなく、許可リストとの完全一致で判定する')];
  } };

export const corsWildcard: Rule = { id: 'R-04', title: 'ワイルドカード', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'OWASP HTML5 Security CS'],
  run(ctx) {
    if (!ctx.final) return [mk(corsWildcard, ctx, 'na', 'info', 'na', '応答がない', '')];
    const acao = acaoOf(ctx);
    if (acao !== '*') return [mk(corsWildcard, ctx, 'ok', 'info', 'pass', acao ? `ACAO: ${acao}` : '(ACAOなし)', '')];
    if (credOf(ctx)) return [mk(corsWildcard, ctx, 2, 'low', 'fail', 'ACAO: * / ACAC: true', '仕様上ブラウザが拒否する組み合わせ。設定を見直す')];
    if (ctx.sensitive) return [mk(corsWildcard, ctx, 1, 'medium', 'fail', 'ACAO: *（機密応答）', '機密応答には * を使わず、許可リストで返す')];
    // 機密かどうか分からないときは①を判定しない（第0章 0.3）。* が付いていることは確かなので、より弱い③として出す
    if (ctx.sensitive === undefined) return [mk(corsWildcard, ctx, 3, 'info', 'fail', 'ACAO: *（機密応答かどうか分からない）', '機密応答なら①（中）にあたる。#TARGET に sensitive=1 か sensitive=0 を付ける')];
    return [mk(corsWildcard, ctx, 3, 'info', 'fail', 'ACAO: *', '公開データであれば問題ない。意図どおりか確認する')];
  } };

export const corsPreflight: Rule = { id: 'R-05', title: 'プリフライト応答', appliesTo: 'any', scope: 'target',
  basis: ['MDN', 'Fetch Standard'],
  run(ctx) {
    const methods = ctx.final?.headers.get('access-control-allow-methods')?.join(',');
    const maxAge = ctx.final?.headers.get('access-control-max-age')?.[0];
    if (!ctx.final || (!methods && !maxAge)) return [];      // プリフライト応答だけ
    const out = [];
    const acao = acaoOf(ctx); const sent = ctx.target.sentOrigin;
    const foreign = acao === '*' || (!!sent && acao === sent && (TEST_ORIGINS.includes(sent) || isLookalike(ctx, sent)));
    if (methods && foreign && /\b(PUT|DELETE|PATCH)\b/i.test(methods))
      out.push(mk(corsPreflight, ctx, 1, 'medium', 'fail', `ACAO: ${acao} / Allow-Methods: ${methods}`, '許可外のOriginに状態を変えるメソッドを許可しない'));
    if (maxAge && Number(maxAge) > 7200) out.push(mk(corsPreflight, ctx, 2, 'info', 'fail', `Access-Control-Max-Age: ${maxAge}`, 'Chromeは7200秒で打ち切る。必要な長さにする'));
    return out.length ? out : [mk(corsPreflight, ctx, 'ok', 'info', 'pass', `Allow-Methods: ${methods ?? '-'} / Max-Age: ${maxAge ?? '-'}`, '')];
  } };

export const corsVary: Rule = { id: 'R-06', title: 'Vary: Origin', appliesTo: 'any', scope: 'target',
  basis: ['Fetch Standard', 'MDN'],
  run(ctx) {
    const acao = acaoOf(ctx);
    if (!ctx.final || !acao || acao === '*') return [];       // Origin によって ACAO を変える応答だけ
    const vary = (ctx.final.headers.get('vary') ?? []).join(',').toLowerCase();
    return /\borigin\b|\*/.test(vary) ? [mk(corsVary, ctx, 'ok', 'info', 'pass', `Vary: ${vary}`, '')]
      : [mk(corsVary, ctx, 1, 'low', 'fail', `ACAO: ${acao} / Vary: ${vary || '(なし)'}`, 'Origin によって ACAO を変えるなら Vary: Origin を付ける（キャッシュ汚染の防止）')];
  } };

const SENSITIVE_EXPOSE = /\b(authorization|set-cookie|x-auth[\w-]*|[\w-]*token[\w-]*|x-internal[\w-]*|x-debug[\w-]*)\b/i;
export const corsExpose: Rule = { id: 'R-07', title: 'Access-Control-Expose-Headers', appliesTo: 'any', scope: 'target',
  basis: ['MDN'],
  run(ctx) {
    const v = ctx.final?.headers.get('access-control-expose-headers')?.join(',');
    if (!ctx.final || !v) return [];
    if (v.split(',').some(s => s.trim() === '*')) return [mk(corsExpose, ctx, 2, 'low', 'fail', v, '公開するヘッダを明示する')];
    if (SENSITIVE_EXPOSE.test(v)) return [mk(corsExpose, ctx, 1, 'medium', 'fail', v, '認証トークンや内部ヘッダを公開しない')];
    return [mk(corsExpose, ctx, 'ok', 'info', 'pass', v, '')];
  } };

// ---- 以下 v0.3 で追加（R-08、R-09） ----
export const timingAllowOrigin: Rule = { id: 'R-08', title: 'Timing-Allow-Origin', appliesTo: 'any', scope: 'target',
  basis: ['W3C Resource Timing', 'MDN'],
  run(ctx) {
    const v = ctx.final?.headers.get('timing-allow-origin')?.join(', ');
    if (!ctx.final || !v) return [];
    const star = /(^|,)\s*\*\s*(,|$)/.test(v);
    if (ctx.sensitive && star) return [mk(timingAllowOrigin, ctx, 1, 'low', 'fail', `Timing-Allow-Origin: ${v}（機密応答）`, '機密応答には付けないか、Originを限定する（タイミング情報の漏えい）')];
    if (ctx.sensitive === undefined && star) return [mk(timingAllowOrigin, ctx, 'na', 'info', 'na', `Timing-Allow-Origin: ${v}（機密応答かどうか分からない）`, '認証後ページや個人情報を含むAPIには #TARGET に sensitive=1 を付ける')];
    return [mk(timingAllowOrigin, ctx, 'ok', 'info', 'pass', `Timing-Allow-Origin: ${v}`, '')];
  } };

export const websocketOrigin: Rule = { id: 'R-09', title: 'WebSocketのOrigin検証', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger: Cross-site WebSocket hijacking', 'OWASP WebSocket Security CS'],
  run(ctx) {
    const s = ctx.target.responses.find(r => r.status === 101) ? 101 : ctx.final?.status;
    if (!s) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', '応答がない（--max-time で打ち切られた場合も、101 の行があれば判定できる）', '')];
    // 合格にするのは、拒否を示す応答（401・403）だけ。200・404・426 などは、WebSocket のエンドポイントではない可能性がある（パスの誤りなど）
    if (s === 401 || s === 403) return [mk(websocketOrigin, ctx, 'ok', 'info', 'pass', `許可外Originのハンドシェイクが HTTP ${s}（拒否）`, '')];
    if (s !== 101) return [mk(websocketOrigin, ctx, 'na', 'info', 'na', `HTTP ${s}（WebSocket のエンドポイントではない可能性）`, 'C16 の URL が WebSocket のエンドポイントか確認して採取し直す（拒否なら 401 か 403、受け入れなら 101 が返る）')];
    return ctx.target.sentAuth || ctx.sensitive
      ? [mk(websocketOrigin, ctx, 1, 'high', 'fail', `Origin: ${ctx.target.sentOrigin ?? '(不明)'} で 101 Switching Protocols（Cookie認証）`, 'ハンドシェイクで Origin を許可リストと照合し、許可外は 403 で拒否する')]
      : [mk(websocketOrigin, ctx, 2, 'info', 'fail', `Origin: ${ctx.target.sentOrigin ?? '(不明)'} で 101 Switching Protocols（認証なし）`, '公開用のWebSocketなら問題ない。意図どおりか確認する')];
  } };
