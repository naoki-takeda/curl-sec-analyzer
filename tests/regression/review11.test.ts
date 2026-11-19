// 11回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前のコミットの退行を修正前後で比べたものを含む）で見つかった不具合の再現テスト
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { Rule } from '../../src/model';
import { maskText } from '../../src/mask';
import { urlKey } from '../../src/engine/targetKey';
import { parseInput } from '../../src/parser/input';
import { assignHopUrls, isHttps } from '../../src/parser/target';
import { harTargets, importHar } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const HSTS = 'strict-transport-security: max-age=31536000';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[], info: string[] = []) =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, ...info, `> GET ${new URL(url).pathname} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', ''].join('\n');

type H = { name: string; value: string };
const entry = (method: string, url: string, status: number, headers: H[], req: H[] = [], mimeType = 'text/html', text = '<p>x</p>') => ({
  startedDateTime: '2026-11-01T00:00:00Z', request: { method, url, headers: req },
  response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType, text } } });
const har = (...entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets } = harTargets(imp, new Set(imp.hosts));
  return { imp, targets, findings: runAll(targets) };
};

describe('1 退行：ホスト名を伏せない', () => {
  it('長いホスト名・ELB の名前は残し、パスのトークンは伏せる', () => {
    for (const u of ['https://staging-customer-portal-frontend-01.example.com/x', 'https://k8s-default-webingre-1a2b3c4d5e-1234567890.ap-northeast-1.elb.amazonaws.com/login',
      'https://idp.example/cb?r=https%3A%2F%2Fstaging-customer-portal-frontend-01.example.com%2Fx'])
      expect(maskText(u)).toBe(u);
    expect(maskText('https://staging-customer-portal-frontend-01.example.com/reset/AbCdEfGh1234567890XyZ')).not.toContain('AbCdEfGh1234567890XyZ');
  });
  it('URL のパターンで登録した例外が効く', () => {
    const { targets } = parseInput(t('top', 'https://staging-customer-portal-frontend-01.example.com/', HTML, '<p>x</p>'));
    const fs = runAll(targets, { suppressions: [{ ruleId: 'H-01', target: 'https://staging-customer-portal-frontend-01.example.com/*', reason: 'x', approver: 'y', until: '' }] });
    expect(fs.filter(f => f.item === 'H-01').map(f => f.status)).toEqual(['suppressed']);
  });
});

describe('2 退行：A-02① が本物のトークンを見逃す', () => {
  const a02 = (q: string) => ids(t('top', 'https://a.example/', `HTTP/2 302\nlocation: /cb?${q}`), 'A-02');
  it('英字だけのトークン・短い数字はトークン', () => {
    for (const q of ['access_token=QxZrTbWmPnLkHjGfDsAq', 'api_key=Wq-Er_Ty-Ui_OpAs', 'token=abcdefghijklmnopqrstuvwxyz', 'auth=1234567']) expect(a02(q), q).toContain('A-02.1');
  });
  it('状態を伝える短い語・真偽値はトークンにしない', () => {
    for (const q of ['session=expired', 'auth=required', 'token=invalid', 'auth=1', 'session=timeout']) expect(a02(q), q).not.toContain('A-02.1');
  });
});

describe('3 退行：URL 欄で補った URL', () => {
  it('ホップの URL を付け直せば、http から https に転送されたターゲットを HTTPS として判定する', () => {
    const { targets } = parseInput('HTTP/1.1 301 Moved\nLocation: https://www.example.com/\n\nHTTP/2 200\ncontent-type: text/html\n\n<html></html>\n');
    targets[0].url = 'http://www.example.com/';
    assignHopUrls(targets[0]);
    expect(isHttps(targets[0])).toBe(true);
  });
});

describe('4 突き合わせのキー', () => {
  it('伏せた値は「…」だけにし、記録し直しても変わらない', () => {
    expect(urlKey('https://a.example/cb?code=Splx0123abcdefgh&state=xyz')).toBe(urlKey('https://a.example/cb?code=Qx9v9876zyxwvuts1&state=xyz'));
    expect(urlKey('https://a.example/reset/AbCdEfGh1234567890XyZ')).toBe(urlKey('https://a.example/reset/ZyXwVuTs0987654321AbC'));
  });
  it('ダイジェスト付きのファイル名は、名前の語を残して区別する', () => {
    const d = 'a1'.repeat(32);
    expect(urlKey(`/assets/application-${d}.js`)).not.toBe(urlKey(`/assets/vendor-${d}.js`));
    const shown = maskText(`/assets/application-${d}.js`);
    expect(shown).toBe('/assets/application-…(64 chars).js');
    expect(maskText(shown)).toBe(shown);
  });
  it('HAR の targetKey は、同じページを記録し直しても同じ', () => {
    const key = (code: string) => har(entry('GET', `https://a.example/auth/callback?code=${code}&state=s`, 200, [{ name: 'content-type', value: 'text/html' }])).findings[0].targetKey;
    expect(key('Splx0123abcdefghij')).toBe(key('Qx9v9876zyxwvutsrq1'));
  });
});

describe('6 退行：CSV の BOM', () => {
  it('ソースに見えない BOM の文字をそのまま書かない', () => {
    expect(readFileSync(new URL('../../src/export/csv.ts', import.meta.url), 'utf8')).not.toContain(String.fromCharCode(0xfeff));
  });
});

describe('7 退行：R-07 の除外が広すぎる', () => {
  const expose = (h: string) => ids(t('api', 'https://a.example/api', `HTTP/2 200\ncontent-type: application/json\naccess-control-allow-origin: https://app.example\naccess-control-expose-headers: ${h}`, '{}'), 'R-07');
  it('token を含まない内部・デバッグのヘッダは①のまま', () => {
    expect(expose('X-Debug-Async-Trace')).toEqual(['R-07.1']);
    expect(expose('X-Internal-Pagecache-Node')).toEqual(['R-07.1']);
    expect(expose('X-CSRF-Token')).toEqual(['R-07.ok']);
  });
});

describe('8 漏えい：ASP.NET の Cookie を使わないセッション', () => {
  it('(S(…))・(F(…))・(A(…)) の値を伏せる', () => {
    const tok = 'lit3py55t21z5v55vlm25s55', tkt = '8A2C4E6F'.repeat(8);
    const m = maskText(`https://www.example.com/(S(${tok}))/default.aspx https://www.example.com/(A(anonid0123456789)F(${tkt}))/Login.aspx`);
    expect(m).not.toContain(tok);
    expect(m).not.toContain(tkt);
    expect(m).not.toContain('anonid0123456789');
    expect(maskText(m)).toBe(m);
  });
});

describe('9 プロキシの 407・認証し直した 401', () => {
  const proxied = (label: string, url: string, final: string) => `#TARGET url=${url} label=${label}\nHTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm="p"\n\nHTTP/1.1 200 Connection established\n\n${final}\n\n<p>x</p>\n`;
  it('407 をその URL の最初の応答にしない（T-04①・A-01① を見逃さない）', () => {
    expect(ids(proxied('http', 'http://www.example.com/', 'HTTP/1.1 200 OK\ncontent-type: text/html'), 'T-04')).toEqual(['T-04.1']);
    expect(ids(proxied('unauth-api', 'https://www.example.com/api/me', 'HTTP/1.1 200 OK\ncontent-type: application/json'), 'A-01')).toContain('A-01.1');
  });
  it('curl が認証し直した 401（--digest）のあとの応答で判定する', () => {
    const input = '#TARGET url=https://www.example.com/admin label=top\nHTTP/1.1 401 Unauthorized\nWWW-Authenticate: Digest realm="a", nonce="n"\n\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n<p>x</p>\n';
    expect(parseInput(input).targets[0].responses.map(r => r.kind)).toEqual(['challenge', 'final']);
  });
});

describe('10 C-09：ログイン前に送ったセッションID', () => {
  it('トップで発行し、ログイン画面では送るだけでも、login で再発行しなければ①（HAR）', () => {
    const ck = [{ name: 'Cookie', value: 'JSESSIONID=ABCDEF0123456789ABCDEF0123456789' }];
    const r = har(entry('GET', 'https://a.example/', 200, [{ name: 'content-type', value: 'text/html' }, { name: 'Set-Cookie', value: 'JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly' }]),
      entry('GET', 'https://a.example/login', 200, [{ name: 'content-type', value: 'text/html' }], ck, 'text/html', '<form method="post"><input type="password" name="p"></form>'),
      entry('POST', 'https://a.example/login', 302, [{ name: 'Location', value: '/home' }], ck));
    expect(r.findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.1']);
  });
  it('curl -v でも同じ。login で新しいセッションCookieを発行すれば合格', () => {
    const pre = v('pre-login', 'https://a.example/login', ['Cookie: JSESSIONID=ABCDEF0123456789'], ['HTTP/1.1 200 OK', 'Content-Type: text/html']);
    const login = (set: string[]) => v('login', 'https://a.example/login', ['Cookie: JSESSIONID=ABCDEF0123456789'], ['HTTP/1.1 302 Found', 'Location: /home', ...set]);
    const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
    expect(c09(pre + login([]))).toEqual(['C-09.1']);
    expect(c09(pre + login(['Set-Cookie: JSESSIONID=ZYXWVU9876543210; Path=/; Secure; HttpOnly']))).toEqual(['C-09.ok']);
  });
});

describe('11 本文を採取していない応答を合格にしない', () => {
  it('HAR の JSONP（JS の本文も残す）は E-06 を判定する', () => {
    const r = har(entry('GET', 'https://a.example/api/me?callback=cb1', 200, [{ name: 'content-type', value: 'application/javascript' }], [], 'application/javascript', 'cb1({"email":"a@b"})'));
    expect(r.findings.filter(f => f.item === 'E-06').map(f => f.ruleId)).not.toContain('E-06.ok');
  });
  it('-v の TRACE・host-inj・JS は na', () => {
    expect(ids(v('trace', 'https://a.example/', [], ['HTTP/1.1 200 OK', 'Content-Type: message/http']), 'T-01')).toEqual(['T-01.na']);
    expect(ids(v('host-inj', 'https://a.example/', ['Host: evil.example'], ['HTTP/1.1 200 OK', 'Content-Type: text/html']), 'T-07')).toEqual(['T-07.na']);
    expect(ids(v('top', 'https://a.example/app.js', [], ['HTTP/1.1 200 OK', 'Content-Type: application/javascript']), 'E-13')).toEqual(['E-13.na']);
    expect(ids(v('top', 'https://a.example/api/me?callback=cb1', [], ['HTTP/1.1 200 OK', 'Content-Type: application/javascript']), 'E-06')).toEqual(['E-06.na']);
  });
});

describe('12 curl -v の Cookie：解析用の Cookie だけでは機密としない', () => {
  it('_ga・theme だけなら H-12① にしない。セッションCookie なら①', () => {
    const page = (cookie: string) => ids(v('about', 'https://a.example/about', [`Cookie: ${cookie}`], ['HTTP/2 200', 'Content-Type: text/html']), 'H-12');
    expect(page('_ga=GA1.1.1.1; theme=dark')).not.toContain('H-12.1');
    expect(page('sessionid=abcdef0123456789')).toContain('H-12.1');
  });
});

describe('13 A-07：公開を前提にした値', () => {
  const api = (body: string) => ids(t('api', 'https://a.example/api/x', 'HTTP/2 200\ncontent-type: application/json', body), 'A-07');
  it('Stripe の client_secret・Firebase の apiKey は①にしない', () => {
    expect(api('{"clientSecret":"pi_3Abc123DEF_secret_XyZ987abcDEF"}')).not.toContain('A-07.1');
    expect(api(`{"apiKey":"AIza${'B'.repeat(35)}","authDomain":"x.firebaseapp.com"}`)).not.toContain('A-07.1');
    expect(api('{"clientSecret":"s3cr3t-Value-0123"}')).toContain('A-07.1');
  });
});

describe('14 E-09：ルート・翻訳キーの文字列', () => {
  const page = (js: string) => ids(t('top', 'https://a.example/', HTML, `<script>${js}</script>`), 'E-09');
  it('パス・翻訳キー・forgot_password は①にしない。秘密らしい値なら①', () => {
    expect(page('var routes={password:"/users/password/new"}')).not.toContain('E-09.1');
    expect(page('var t={"password":"auth.password.label"}')).not.toContain('E-09.1');
    expect(page('var r={forgot_password:"xY9-forgot-route-0"}')).not.toContain('E-09.1');
    expect(page('var c={api_key:"sk_live_abcdef1234567890"}')).toContain('E-09.1');
  });
});

describe('15 WAF・CDN の Cookie', () => {
  const page = (cookie: string) => evaluate(t('top', 'https://www.example.com/', `${HTML}\n${HSTS}\nset-cookie: ${cookie}`)).findings.filter(f => f.status === 'fail').map(f => f.ruleId);
  it('Imperva の incap_ses_* をセッションCookieとみなさない', () => {
    const fs = page(`incap_ses_123_456=${'A'.repeat(40)}; path=/; Domain=.example.com`);
    expect(fs).not.toContain('C-01.1');
    expect(fs).not.toContain('C-02.1');
  });
  it('Cloudflare の __cf_bm は C-03③・C-04① にしない', () => {
    const fs = page('__cf_bm=abcdefABCDEF0123456789abcdef-1700000000-0-AAAA; path=/; expires=Tue, 23 Nov 2027 00:00:00 GMT; domain=.example.com; HttpOnly; Secure; SameSite=None');
    expect(fs).not.toContain('C-03.3');
    expect(fs).not.toContain('C-04.1');
  });
});

describe('16・17 多数のターゲットと、ルールの例外', () => {
  it('同じラベルのターゲットが多くても、付け直しが件数の2乗の時間にならない', { tags: ['perf'] }, () => {
    const input = '#TARGET url=https://a.example/ label=x\nHTTP/2 200\n\n'.repeat(20_000);
    const s = performance.now(); parseInput(input);
    expect(performance.now() - s).toBeLessThan(2000);
  });
  it('細工した JWT（alg がオブジェクト）でも判定を止めない', () => {
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    expect(() => evaluate(t('top', 'https://a.example/', `${HTML}\nset-cookie: tok=${b64({ alg: { toString: 1, valueOf: 1 } })}.${b64({ sub: 'x' })}.sig; Path=/`))).not.toThrow();
  });
  it('ルールが例外を投げても、そのルールだけ na にしてほかの結果を残す', () => {
    const bad: Rule = { id: 'H-01', title: 'x', appliesTo: 'any', scope: 'target', basis: [], run: () => { throw new TypeError('boom'); } };
    const { targets } = parseInput(t('top', 'https://a.example/', HTML));
    expect(runAll(targets, { rules: [bad], hostRules: [], crossRules: [] }).map(f => f.ruleId)).toEqual(['H-01.na']);
  });
});

describe('18〜23 低の指摘', () => {
  it('18 E-11：ビルドした CSS・JS・フォントは②にしない', () => {
    expect(ids(t('top', 'https://a.example/sites/default/files/css/css_x.css', 'HTTP/2 200\ncontent-type: text/css', 'a{}'), 'E-11')).not.toContain('E-11.2');
    expect(ids(t('top', 'https://a.example/_next/static/media/f.woff2', 'HTTP/2 200\ncontent-type: font/woff2'), 'E-11')).not.toContain('E-11.2');
  });
  it('19 本文の末尾にくっついた #TARGET で、次のターゲットを失わない', () => {
    const input = '#TARGET url=https://a.example/api/x label=api\nHTTP/2 200\ncontent-type: application/json\n\n{"id":1}#TARGET url=https://a.example/api/me label=unauth-api\nHTTP/2 401\nwww-authenticate: Bearer\n\n';
    expect(parseInput(input).targets.map(x => x.label)).toEqual(['api', 'unauth-api']);
  });
  it('20 curl の進捗表示がステータス行と同じ行に出ても、応答を読む', () => {
    const input = ['#TARGET url=https://a.example/ label=top', '  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current',
      '                                 Dload  Upload   Total   Spent    Left  Speed', '* Connected to a.example (192.0.2.1) port 443', '> GET / HTTP/1.1', '>',
      '  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0< HTTP/2 200', '< content-type: text/html', '<', ''].join('\n');
    const r = parseInput(input);
    expect(r.targets[0].responses.map(x => x.status)).toEqual([200]);
    expect(r.warnings.map(w => w.kind)).not.toContain('unparsed-lines');
  });
  it('21 T-09②：TLS 1.3 のプローブで接続できたなら、合意が 1.2 でも②にしない', () => {
    const input = '#TARGET url=https://www.example.com/ label=tls\n#TLSPROBE v=tls1_3 ok=1\n#TLSPROBE v=tls1 ok=0\n'
      + '#TARGET url=https://www.example.com/ label=top\n* Connected to www.example.com (192.0.2.1) port 443\n* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256\n< HTTP/1.1 200 OK\n< content-type: text/html\n<\n';
    expect(ids(input, 'T-09')).not.toContain('T-09.2');
  });
  it('22 H-16：CDN の Server-Timing と、公開のホスト名の .local. は対象外', () => {
    const h16 = (h: string) => ids(t('top', 'https://a.example/', `${HTML}\n${h}`), 'H-16');
    expect(h16('server-timing: cfL4;desc="?proto=TCP&rtt=1", cfExtPri')).not.toContain('H-16.5');
    expect(h16('server-timing: cdn-upstream-layer;desc="EDGE", cdn-pop;desc="NRT57"')).not.toContain('H-16.5');
    expect(h16('server-timing: db;dur=53, app;dur=47.2')).toContain('H-16.5');
    expect(h16('via: 1.1 edge01.local.example-cdn.net')).not.toContain('H-16.4');
    expect(h16('via: 1.1 app01.internal')).toContain('H-16.4');
  });
  it('23 A-02②：トークンを発行するエンドポイントは対象外', () => {
    expect(ids(t('api', 'https://a.example/oauth/token', 'HTTP/2 200\ncontent-type: application/json', `{"access_token":"x","refresh_token":"${'r'.repeat(32)}"}`), 'A-02')).not.toContain('A-02.2');
  });
});
