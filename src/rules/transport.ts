// rules/transport.ts：第4章 メソッド・転送・ヘッダインジェクション（T-01、T-04〜T-08、T-12。TLSは rules/hostRules.ts）
import type { Rule } from '../model';
import { NO_BODY_REC, mk } from './util';
import { baseLabel } from '../parser/target';

export const httpsRedirect: Rule = { id: 'T-04', title: 'HTTP→HTTPSリダイレクト', appliesTo: 'any', scope: 'target',
  basis: ['MDN HTTP Observatory'],
  run(ctx) {
    const url = ctx.target.url;
    if (!url || !/^http:\/\//i.test(url)) return [];   // URLが http:// のターゲットだけで判定する（スキームの大文字小文字は区別しない）
    const first = ctx.chain[0];
    if (!first) return [mk(httpsRedirect, ctx, 'na', 'info', 'na', '応答がない', '')];
    const rec = '同じホストの https:// へ 301 または 308 で転送する';
    const loc = first.headers.get('location')?.[0];
    // ステータスが分からない応答（%{header_json} だけで #META response_code= がない）は、転送したかどうかも分からない（A-01・C-12・E-05 と同じ）
    if (!first.status) return [mk(httpsRedirect, ctx, 'na', 'info', 'na', 'ステータスが分からない（HTTP 0）', 'ステータス行を含めて採取し直す（C10 なら #META response_code= も付ける）')];
    // HTTP を 4xx で断る（CloudFront の「HTTPS のみ」、HTTP を拒否する API）は、HTTP でコンテンツを返していないので①にしない。
    // 5xx はサーバの不調で、HTTP をどう扱う設定かが分からない
    if (first.status >= 400 && first.status < 500) return [mk(httpsRedirect, ctx, 'ok', 'info', 'pass', `HTTP ${first.status}（HTTP のリクエストを拒否）`, '')];
    if (first.status >= 500) return [mk(httpsRedirect, ctx, 'na', 'info', 'na', `HTTP ${first.status}（サーバエラー）`, '')];
    if (first.status < 300 || first.status >= 400 || !loc)
      return [mk(httpsRedirect, ctx, 1, 'high', 'fail', `HTTP ${first.status}（転送なし）`, rec, { obsId: 'redirection-missing', score: -20 })];
    let to: URL;
    try { to = new URL(loc, url); } catch { return [mk(httpsRedirect, ctx, 'na', 'info', 'na', `Location を解釈できない: ${loc}`, '')]; }
    const from = new URL(url);
    const ev = `HTTP ${first.status} → ${to.href}`;
    if (to.protocol !== 'https:') return [mk(httpsRedirect, ctx, 2, 'medium', 'fail', ev, rec, { obsId: 'redirection-not-to-https', score: -20 })];
    if (to.hostname !== from.hostname) return [mk(httpsRedirect, ctx, 3, 'low', 'fail', ev, rec, { obsId: 'redirection-off-host-from-http', score: -5 })];
    // 303 See Other も一時的な転送（ブラウザは覚えない）
    if (first.status === 302 || first.status === 303 || first.status === 307) return [mk(httpsRedirect, ctx, 4, 'info', 'fail', ev, '恒久的な転送（301 または 308）にする')];
    return [mk(httpsRedirect, ctx, 'ok', 'info', 'pass', ev, '')];
  } };

// ---- 以下 MVP で追加（T-05、T-07②、T-08） ----
const INTERNAL_HOST = /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|localhost$)|\.(?:internal|local|lan|corp|intra)$/i;
export const redirectChain: Rule = { id: 'T-05', title: 'リダイレクトチェーン', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG'],
  run(ctx) {
    const hops = ctx.chain.filter(r => r.kind === 'redirect');
    if (!hops.length || !ctx.target.url) return [];
    const out = [];
    let cur = ctx.target.url, sawHttps = /^https:\/\//i.test(cur);
    // 診断した URL 自身のポート（https://a.example:8443/）への転送は、内部のポートの露出ではない
    const own = (() => { try { return new URL(ctx.target.url!); } catch { return undefined; } })();
    for (const r of hops) {
      let to: URL;
      try { to = new URL(r.headers.get('location')![0], cur); } catch { continue; }
      if (sawHttps && to.protocol === 'http:') out.push(mk(redirectChain, ctx, 1, 'medium', 'fail', `${cur} → ${to.href}`, 'チェーンの途中で http に戻さない'));
      const ownPort = !!own && to.hostname === own.hostname && to.port === own.port;   // 同じホストの同じポートだけ（別のホストの同じポートは対象）
      if (INTERNAL_HOST.test(to.hostname) || (to.port && !['80', '443'].includes(to.port) && !ownPort))
        out.push(mk(redirectChain, ctx, 2, 'low', 'fail', `Location: ${to.href}`, 'Location に内部ホスト名やポートを出さない（リバースプロキシの設定を確認）'));
      sawHttps ||= to.protocol === 'https:'; cur = to.href;
    }
    return out.length ? out : [mk(redirectChain, ctx, 'ok', 'info', 'pass', `${hops.length}回の転送`, '')];
  } };

const HOST_INJ_VALUE = /evil\.example/i;
export const hostInjection: Rule = { id: 'T-07', title: 'Host・X-Forwarded-Hostヘッダインジェクション', appliesTo: 'any', scope: 'target',
  basis: ['PortSwigger Web Security Academy: Host header', 'OWASP WSTG-INPV-17'],
  run(ctx) {
    if (!ctx.final) return [mk(hostInjection, ctx, 'na', 'info', 'na', '応答がない', '')];
    const loc = ctx.target.responses.flatMap(r => r.headers.get('location') ?? []).find(l => HOST_INJ_VALUE.test(l));
    const ok2xx = ctx.final.status >= 200 && ctx.final.status < 300;
    if (!loc && ok2xx && !ctx.final.body?.trim()) return [mk(hostInjection, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（本文を採取していない）`, NO_BODY_REC)];
    const body = ctx.final.body?.match(/https?:\/\/[^\s"'<>]*evil\.example[^\s"'<>]*/i)?.[0];
    if (loc || body) return [mk(hostInjection, ctx, 2, 'medium', 'fail', loc ? `Location: ${loc}` : `本文の絶対URL: ${body}`, '絶対URLは設定値のホスト名から作り、Host・X-Forwarded-Host を信頼しない')];
    return [mk(hostInjection, ctx, 'ok', 'info', 'pass', 'テスト値（evil.example）は応答に現れない', '')];
  } };

export const crlfInjection: Rule = { id: 'T-08', title: 'CRLFインジェクション', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-INPV-15'],
  run(ctx) {
    if (!ctx.final) return [mk(crlfInjection, ctx, 'na', 'info', 'na', '応答がない', '')];
    const hit = ctx.target.responses.some(r => (r.headers.get('set-cookie') ?? []).some(v => /^crlf=1\b/i.test(v)) || r.headers.has('x-crlf-test'));
    return hit ? [mk(crlfInjection, ctx, 1, 'high', 'fail', '注入したヘッダ（Set-Cookie: crlf=1）が応答に現れた', 'ヘッダに出力する値から CR・LF を除去する（フレームワークのAPIでヘッダを設定する）')]
               : [mk(crlfInjection, ctx, 'ok', 'info', 'pass', '注入したヘッダは応答に現れない', '')];
  } };

// ---- 以下 v0.2 で追加（T-01、T-06、T-12） ----
const RISKY_METHODS = /\b(PUT|DELETE|PATCH|TRACE|TRACK|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\b/gi;
export const methods: Rule = { id: 'T-01', title: 'OPTIONS・TRACE', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-CONF-06'],
  run(ctx) {
    const f = ctx.final;
    if (!f) return [mk(methods, ctx, 'na', 'info', 'na', '応答がない', '')];
    if (baseLabel(ctx.target.label) === 'trace') {
      if (f.status === 200 && !f.body?.trim()) return [mk(methods, ctx, 'na', 'info', 'na', 'HTTP 200（本文を採取していない。反射したかが分からない）', NO_BODY_REC)];
      const reflected = f.status === 200 && /^TRACE \S+ HTTP\//m.test(f.body ?? '');
      return reflected ? [mk(methods, ctx, 1, 'medium', 'fail', `HTTP ${f.status}（リクエストを反射）`, 'TRACE を無効にする（405 か 501 を返す）')]
                       : [mk(methods, ctx, 'ok', 'info', 'pass', `HTTP ${f.status}`, '')];
    }
    const allow = [...(f.headers.get('allow') ?? []), ...(f.headers.get('access-control-allow-methods') ?? [])].join(', ');
    if (!allow) return [mk(methods, ctx, 'na', 'info', 'na', `HTTP ${f.status}（Allow ヘッダなし）`, '')];
    const risky = [...new Set(allow.match(RISKY_METHODS)?.map(m => m.toUpperCase()) ?? [])];
    return risky.length ? [mk(methods, ctx, 2, 'low', 'fail', `Allow: ${allow}`, `使っていなければ ${risky.join('・')} を無効にする`)]
                        : [mk(methods, ctx, 'ok', 'info', 'pass', `Allow: ${allow}`, '')];
  } };

const OPEN_REDIRECT_REC = 'next= などで実際に転送する URL（ログインに成功したあとの転送など）で採取し直す';
export const openRedirect: Rule = { id: 'T-06', title: 'オープンリダイレクト', appliesTo: 'any', scope: 'target',
  basis: ['OWASP Unvalidated Redirects CS', 'IPA'],
  run(ctx) {
    if (!ctx.final) return [mk(openRedirect, ctx, 'na', 'info', 'na', '応答がない', '')];
    const evil = (l: string) => /^(?:https?:)?\/\/(?:[^/]*@)?evil\.example\b/i.test(l.trim());
    const loc = ctx.target.responses.flatMap(r => r.headers.get('location') ?? []).find(evil);
    // Refresh ヘッダ（Refresh: 0; url=https://evil.example/）による転送も見る
    const refresh = ctx.target.responses.flatMap(r => r.headers.get('refresh') ?? []).map(v => v.match(/url\s*=\s*['"]?([^'"\s;]+)/i)?.[1] ?? '').find(evil);
    if (loc || refresh) return [mk(openRedirect, ctx, 1, 'medium', 'fail', loc ? `Location: ${loc}` : `Refresh: url=${refresh}`, '転送先は許可リスト（または相対パス）に限る')];
    // 転送しなかった応答（200・404 など）では、転送先を検証しているかは分からない（ログイン画面の next= はログインに成功したあとでだけ使う）
    const redirected = ctx.target.responses.some(r => (r.status >= 300 && r.status < 400 && r.headers.has('location')) || r.headers.has('refresh'));
    return redirected ? [mk(openRedirect, ctx, 'ok', 'info', 'pass', '外部ホスト（evil.example）へは転送しない', '')]
      : [mk(openRedirect, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（転送しなかった。転送先を検証しているかは分からない）`, OPEN_REDIRECT_REC)];
  } };

export const httpVersion: Rule = { id: 'T-12', title: 'HTTP/2・HTTP/3', appliesTo: 'any', scope: 'target',
  basis: ['MDN'],
  run(ctx) {
    const f = ctx.final;
    if (!f || ctx.isHttps === false) return [];
    const v = ctx.target.meta.http_version || f.httpVersion;
    if (!v) return [mk(httpVersion, ctx, 'na', 'info', 'na', 'HTTPのバージョンが分からない', '')];
    const altSvc = f.headers.get('alt-svc')?.join(', ') ?? '';
    if (/^1/.test(v) && !/\bh[23]\b/.test(altSvc)) return [mk(httpVersion, ctx, 1, 'info', 'fail', `HTTP/${v}`, 'HTTP/2（必要ならHTTP/3）を有効にする（任意）')];
    return [mk(httpVersion, ctx, 'ok', 'info', 'pass', `HTTP/${v}${altSvc ? ` / alt-svc: ${altSvc}` : ''}`, '')];
  } };
