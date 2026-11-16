// 同値性のテスト：同じ応答を別の形で入力しても、判定が同じになることを確かめる。
// - 改行の違い（CRLF、Windows の curl -v の CR CR LF、入力欄が CR CR LF を空行にしたもの）
// - curl の出力と HAR（ブラウザの記録）
// 形式ごとの読み方の違い（-v の CR CR LF、HAR の http のホップ、送った Cookie の推定など）は、これまで何度も片方だけの退行になったため。
// 意図して結果が違うもの（HAR は別のホストへの転送をつながない など）は、ここでは扱わない（KNOWN_DIFFERENCES に理由と一緒に書く）
import { readFileSync, readdirSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { analyze, findingLine, render } from './golden/analyze';

beforeAll(() => { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(new Date('2026-11-01T12:00:00Z')); });
afterAll(() => { vi.useRealTimers(); });

const casesDir = new URL('./golden/cases/', import.meta.url);
const curlCases = readdirSync(casesDir).filter(f => f.endsWith('.txt')).sort().map(f => ({ name: f, text: readFileSync(new URL(f, casesDir), 'utf8').replace(/\r\n/g, '\n') }));

describe('改行の違いで判定が変わらない', () => {
  for (const c of curlCases) {
    const base = render(analyze(c.text));
    it(`${c.name}：CRLF`, () => { expect(render(analyze(c.text.replace(/\n/g, '\r\n')))).toBe(base); });
    // Windows の curl -v（2>&1）は、受信ヘッダの行（< で始まる行）を CR CR LF で終える。入力欄に貼ると、それが空行になる
    it(`${c.name}：-v の受信ヘッダが CR CR LF`, () => { expect(render(analyze(c.text.replace(/^(< .*)\n/gm, '$1\r\r\n')))).toBe(base); });
    it(`${c.name}：-v の受信ヘッダのあとに空行（入力欄が CR CR LF を変えたもの）`, () => { expect(render(analyze(c.text.replace(/^(< .*)\n/gm, '$1\n\n')))).toBe(base); });
  }
});

/** 1つの応答（転送のホップを含む）。curl の出力と HAR のエントリの両方を、ここから作る */
interface Hop { url: string; status: number; headers: [string, string][]; body?: string; }
interface Scenario {
  name: string; label: string; method?: string;
  sent?: [string, string][];         // 送ったリクエストヘッダ（curl は -v で出す。-v では本文を読まないので、sent がある場面は本文を持たない）
  sentFrom?: number;                 // 送ったヘッダを付ける最初のホップ（Secure の Cookie は https のホップでしか送らない）。既定は0
  hops: Hop[];                        // 最後が最終の応答
}

const reason = (s: number) => ({ 200: 'OK', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 404: 'Not Found', 500: 'Internal Server Error' } as Record<number, string>)[s] ?? 'X';
/** curl の出力。送ったヘッダがあれば -v（-L で転送をたどったもの）、なければ -i -L */
function toCurl(s: Scenario): string {
  const head = [`#TARGET url=${s.hops[0].url} label=${s.label}`, '#META at=2026-11-01T10:00:00'];
  if (s.sent) {
    const lines = [...head];
    s.hops.forEach((h, i) => {
      const u = new URL(h.url);
      if (i > 0) lines.push(`* Issue another request to this URL: '${h.url}'`);
      // TLS の行（* SSL connection using）は出さない。HAR には TLS の情報がなく、T-09・T-10 が curl だけで判定されるのは形式の違いのため
      lines.push(`* Connected to ${u.hostname} (192.0.2.1) port ${u.protocol === 'https:' ? 443 : 80}`);
      lines.push(`> ${s.method ?? 'GET'} ${u.pathname}${u.search} HTTP/1.1`, `> Host: ${u.host}`, ...(i >= (s.sentFrom ?? 0) ? s.sent! : []).map(([k, v]) => `> ${k}: ${v}`), '>');
      lines.push(`< HTTP/1.1 ${h.status} ${reason(h.status)}`, ...h.headers.map(([k, v]) => `< ${k}: ${v}`), '<');
    });
    return `${lines.join('\n')}\n`;
  }
  const blocks = s.hops.map(h => [`HTTP/1.1 ${h.status} ${reason(h.status)}`, ...h.headers.map(([k, v]) => `${k}: ${v}`), '', h.body ?? ''].join('\n'));
  return `${[...head, blocks.join('\n')].join('\n')}\n`;
}
/** HAR。ホップごとに1つのエントリ（ブラウザは転送の先も別のエントリとして記録する） */
function toHar(s: Scenario): string {
  let t = Date.parse('2026-11-01T10:00:00Z');
  const entries = s.hops.map((h, i) => ({
    startedDateTime: new Date(t += 1000).toISOString(),
    request: { method: i === 0 ? s.method ?? 'GET' : 'GET', url: h.url, httpVersion: 'HTTP/1.1', headers: (i >= (s.sentFrom ?? 0) ? s.sent ?? [] : []).map(([name, value]) => ({ name, value })) },
    response: { status: h.status, statusText: reason(h.status), httpVersion: 'HTTP/1.1', headers: h.headers.map(([name, value]) => ({ name, value })), redirectURL: '',
                content: { mimeType: h.headers.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '', text: s.sent ? '' : h.body ?? '' } },
  }));
  return JSON.stringify({ log: { version: '1.2', entries } });
}

const SESSION = 'sessionid=Qm7Lp2Xc9Vb4Nr8Tz1Hd6Kf3Sw5Gy0Ja';
const STRICT: [string, string][] = [['Strict-Transport-Security', 'max-age=63072000; includeSubDomains'], ['X-Content-Type-Options', 'nosniff'],
  ['Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"], ['Referrer-Policy', 'no-referrer']];
const html = (url: string, headers: [string, string][], body = '<html><body>ok</body></html>', status = 200): Hop =>
  ({ url, status, headers: [['Content-Type', 'text/html; charset=utf-8'], ...headers], body });

const SCENARIOS: Scenario[] = [
  { name: '整ったHTMLのページ', label: 'top', hops: [html('https://www.example.com/', [...STRICT, ['Cache-Control', 'no-store']])] },
  { name: 'ヘッダの足りないページとセッションCookie', label: 'top', hops: [html('https://www.example.com/', [['Server', 'nginx/1.24.0'], ['Set-Cookie', `${SESSION}; Path=/`], ['X-Frame-Options', 'SAMEORIGIN']],
    '<html><body><img src="http://www.example.com/a.png"><form action="/s" method="post"><input name="q"></form><!-- TODO --></body></html>')] },
  { name: 'エラーページの本文', label: 'error-url', hops: [html('https://www.example.com/%25', [], '<title>Whitelabel Error Page</title>\nat com.example.Foo.bar(Foo.java:12)', 500)] },
  { name: 'JSON の API', label: 'api', hops: [{ url: 'https://api.example.com/v1/items', status: 200, headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-cache']], body: '{"items":[{"id":1,"is_admin":true}]}' }] },
  { name: 'http から https への転送（一般）', label: 'page', hops: [{ url: 'http://www.example.com/p', status: 301, headers: [['Location', 'https://www.example.com/p'], ['Set-Cookie', 'tmp=abc123; Path=/']] },
    html('https://www.example.com/p', STRICT)] },
  { name: 'http から https への転送（http ラベル）', label: 'http', hops: [{ url: 'http://www.example.com/', status: 302, headers: [['Location', 'https://www.example.com/']] }, html('https://www.example.com/', STRICT)] },
  { name: '同じホストの中の転送', label: 'top', hops: [{ url: 'https://www.example.com/a', status: 302, headers: [['Location', '/b']] }, html('https://www.example.com/b', [['X-Frame-Options', 'DENY']])] },
  { name: 'Cookie を送った認証後の API（機密と推定）', label: 'me', sent: [['Cookie', `${SESSION}; _ga=GA1.1.1`]],
    hops: [{ url: 'https://api.example.com/v1/me', status: 200, headers: [['Content-Type', 'application/json'], ['Cache-Control', 'private']] }] },
  { name: 'Authorization を送った API', label: 'me', sent: [['Authorization', 'Bearer abc.def.ghi']],
    hops: [{ url: 'https://api.example.com/v1/me', status: 200, headers: [['Content-Type', 'application/json']] }] },
  { name: 'Cookie を送った静的リソース（機密としない）', label: 'asset', sent: [['Cookie', SESSION]],
    hops: [{ url: 'https://www.example.com/static/app.js', status: 200, headers: [['Content-Type', 'application/javascript'], ['Access-Control-Allow-Origin', '*']] }] },
  { name: 'Cookie を送った robots.txt（公開ファイル）', label: 'robots', sent: [['Cookie', SESSION]],
    hops: [{ url: 'https://www.example.com/robots.txt', status: 200, headers: [['Content-Type', 'text/plain']] }] },
  { name: '解析用の Cookie だけを送ったページ（機密と推定しない）', label: 'top', sent: [['Cookie', '_ga=GA1.1.123; theme=dark']],
    hops: [html('https://www.example.com/', [['Cache-Control', 'public, max-age=60']])] },
  { name: 'Cookie を送って http から https に転送されたページ', label: 'page', sent: [['Cookie', SESSION]],
    hops: [{ url: 'http://www.example.com/acct', status: 301, headers: [['Location', 'https://www.example.com/acct']] }, html('https://www.example.com/acct', [['Cache-Control', 'no-cache']])] },
  { name: 'Secure の Cookie を https のホップでだけ送った転送（機密と推定）', label: 'acct', sent: [['Cookie', SESSION]], sentFrom: 1,
    hops: [{ url: 'http://api.example.com/v1/acct', status: 301, headers: [['Location', 'https://api.example.com/v1/acct']] },
      { url: 'https://api.example.com/v1/acct', status: 200, headers: [['Content-Type', 'application/json'], ['Cache-Control', 'private']] }] },
  { name: 'ログアウト', label: 'logout', sent: [['Cookie', SESSION]],
    hops: [{ url: 'https://www.example.com/logout', status: 302, headers: [['Location', '/login'], ['Set-Cookie', 'sessionid=; Max-Age=0; Path=/']] }, html('https://www.example.com/login', [])] },
];

/**
 * 意図して curl と HAR で結果が違うもの：「場面の名前 → 違ってよい行の始まり（ターゲット | ルールID）」と理由。
 * ここに書いたもの以外の違いは、テストの失敗にする。直したら消す
 */
const KNOWN_DIFFERENCES: Record<string, { lines: string[]; why: string }> = {};

describe('curl と HAR で判定が同じ', () => {
  for (const s of SCENARIOS) it(s.name, () => {
    const lines = (input: { curl?: string; har?: string }) => {
      const a = analyze(input.curl ?? '', input.har, input.har ? { [s.hops[0].url]: s.label } : {});
      // 突き合わせのキー（targetKey）は形式ごとに違う（curl はラベル、HAR はメソッドと URL）ので比べない
      return a.findings.map(findingLine).sort();
    };
    const curl = lines({ curl: toCurl(s) }), har = lines({ har: toHar(s) });
    const allowed = KNOWN_DIFFERENCES[s.name]?.lines ?? [];
    const ok = (l: string) => allowed.some(p => l.startsWith(p));
    expect({ onlyCurl: curl.filter(l => !har.includes(l) && !ok(l)), onlyHar: har.filter(l => !curl.includes(l) && !ok(l)) }).toEqual({ onlyCurl: [], onlyHar: [] });
  });
});
