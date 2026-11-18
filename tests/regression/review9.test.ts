// 9回目のレビュー（リポジトリ全体、独立した3人のレビュアー。実際の環境での通し試験を含む）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { parseInput } from '../../src/parser/input';
import { harTargets, importHar } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { coverage } from '../../src/engine/coverage';
import { IMPLEMENTED } from '../../src/rules/ruleset';
import { toCsv } from '../../src/export/csv';
import { toJson } from '../../src/export/json';
import { toMarkdown } from '../../src/export/markdown';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const exportsOf = (r: { targets: Parameters<typeof toCsv>[1]; findings: Parameters<typeof toCsv>[0] }) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [JSON.stringify(r.findings), toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};

describe('-v：入力欄が CR CR LF を変えた空行', () => {
  it('受信ヘッダの途中の空行で閉じない（反射した Origin を R-01① にする）', () => {
    const lines = ['#TARGET url=https://a.example/api label=cors-reflect sensitive=1', '* Connected to a.example (192.0.2.1) port 443', '> GET /api HTTP/1.1', '> Origin: https://evil.example', '>',
      '< HTTP/1.1 200 OK', '', '< Content-Type: application/json', '', '< Access-Control-Allow-Origin: https://evil.example', '', '< Access-Control-Allow-Credentials: true', '', '<', ''];
    expect(evaluate(lines.join('\n')).findings.filter(f => f.item === 'R-01').map(f => f.ruleId)).toEqual(['R-01.1']);
  });
});

describe('-v -L：2つ目のホップのリクエストと TLS', () => {
  it('「* Issue another request」のあとの TLS・送信した Origin・Cookie を読む', () => {
    const input = ['#TARGET url=http://example.com/ label=top', '*   Trying 192.0.2.1:80...', '* Connected to example.com (192.0.2.1) port 80', '> GET / HTTP/1.1', '>',
      '< HTTP/1.1 301 Moved Permanently', '< Location: https://example.com/', '<', '<html>moved</html>',
      "* Issue another request to this URL: 'https://example.com/'", '* Connected to example.com (192.0.2.1) port 443', '* SSL connection using TLSv1.0 / ECDHE-RSA-AES128-SHA',
      '> GET / HTTP/1.1', '> Origin: https://evil.example', '> Cookie: sid=x', '>', '< HTTP/1.1 200 OK', '< content-type: text/html', '<'].join('\n') + '\n';
    const tg = parseInput(input).targets[0];
    expect([tg.sentOrigin, tg.sentAuth]).toEqual(['https://evil.example', true]);
    expect(evaluate(input).findings.map(f => f.ruleId)).toContain('T-09.1');
  });
  it('本文の「* SSL connection …」だけの行では読み飛ばしをやめない（第15回の誤検知を戻さない）', () => {
    const input = ['#TARGET url=https://a.example/ label=top', '* Connected to a.example (192.0.2.1) port 443', '* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256', '>',
      '< HTTP/2 200', '< content-type: text/html', '<', '<pre>', '* SSL connection using TLSv1.0 / ECDHE-RSA-AES128-SHA', '</pre>'].join('\n') + '\n';
    expect(evaluate(input).findings.map(f => f.ruleId)).not.toContain('T-09.1');
  });
});

type H = { name: string; value: string };
const entry = (url: string, status: number, headers: H[], reqHeaders: H[] = [], redirectURL?: string) => ({
  startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: reqHeaders },
  response: { status, httpVersion: 'HTTP/2', headers, redirectURL, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
const har = (...entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets } = harTargets(imp, new Set(imp.hosts));
  return { imp, targets, findings: runAll(targets) };
};

describe('HAR：http から https に転送されたチェーン', () => {
  it('http のホップが発行した Cookie も判定する', () => {
    const r = har(entry('http://ex.example/', 302, [{ name: 'Location', value: 'https://ex.example/' }, { name: 'Set-Cookie', value: 'JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/' }], [], 'https://ex.example/'),
      entry('https://ex.example/', 200, [{ name: 'content-type', value: 'text/html' }]));
    expect(r.findings.map(f => f.ruleId)).toContain('C-01.1');
  });
  it('https のホップで送った Cookie で、機密応答と推定する', () => {
    const r = har(entry('http://ex.example/account', 301, [{ name: 'Location', value: 'https://ex.example/account' }], [], 'https://ex.example/account'),
      entry('https://ex.example/account', 200, [{ name: 'content-type', value: 'text/html' }, { name: 'cache-control', value: 'public, max-age=600' }], [{ name: 'Cookie', value: 'sid=abcdef' }]));
    expect(r.targets[0].sentAuth).toBe(true);
    expect(r.findings.map(f => f.ruleId)).toContain('H-12.1');
  });
});

describe('HAR：機密応答の推定', () => {
  const page = (cookie: H[]) => har(entry('https://ex.example/', 200, [{ name: 'content-type', value: 'text/html' }, { name: 'cache-control', value: 'public, max-age=600' }], cookie));
  it('解析用・同意用の Cookie だけでは機密とみなさない', () => {
    const r = page([{ name: 'Cookie', value: 'visitor_id=0d8f7c6b-5a4e-3d2c-1b0a-9f8e7d6c5b4a; _ga=GA1.1.123.456; CookieConsent=yes' }]);
    expect(r.targets[0].sentAuth).toBe(false);
    expect(r.findings.map(f => f.ruleId)).not.toContain('H-12.1');
  });
  it('セッションCookieらしい名前か Authorization なら機密とみなす', () => {
    expect(page([{ name: 'Cookie', value: '_ga=x; JSESSIONID=abc' }]).targets[0].sentAuth).toBe(true);
    expect(page([{ name: 'Authorization', value: 'Bearer x' }]).targets[0].sentAuth).toBe(true);
  });
});

describe('マスク：パスのトークン・属性の > ・長い値・エラーページのタイトル', () => {
  it('パスに置いたトークンを伏せ、普通の名前は残す', () => {
    for (const tok of ['Zq8xLr2Nw7Kp4Ty9Bv1Hm6Jd3Fs0Gc5', '7f3a9c2e1b4d5f6a8b9c0d1e2f3a4b5c', '550e8400-e29b-41d4-a716-446655440000']) {
      const m = maskText(`https://app.example/password/reset/${tok}?x=1`);
      expect(m).not.toContain(tok);
      expect(maskText(m)).toBe(m);
    }
    expect(maskText('https://app.example/news/2026-annual-report-v2/index.html')).toBe('https://app.example/news/2026-annual-report-v2/index.html');
  });
  it('HAR のパスのトークンを、エクスポートと例外の突き合わせのキーに出さない', () => {
    const r = har(entry('https://app.example/password/reset/Zq8xLr2Nw7Kp4Ty9Bv1Hm6Jd3Fs0Gc5', 200, [{ name: 'content-type', value: 'text/html' }]));
    expect(exportsOf(r)).not.toContain('Zq8xLr2Nw7Kp4Ty9Bv1Hm6Jd3Fs0Gc5');
  });
  it('属性の値の中の > で切れず、残りを属性名として出さない', () => {
    const r = evaluate(t('top', 'https://www.example.com/', HTML, `<form action="/pay" onsubmit="return Pay.init('pk_live_51HonsubmitKEY') && amt>0" method="post"><input type="text" name="q"></form>`, 'sensitive=1'));
    const fs = r.findings.filter(f => f.item === 'E-12');
    expect(fs.map(f => f.ruleId)).toEqual(['E-12.1']);                // method="post" も読めている
    expect(exportsOf(r).toLowerCase()).not.toContain('pk_live_51honsubmitkey');
  });
  it('4,096文字を超える値も、最後まで伏せる', () => {
    const jwt = `eyJhbGciOiJSUzI1NiJ9.${'A'.repeat(6000)}.SIGNATUREtail123`;
    expect(maskText(`https://app.example/cb#id_token=${jwt}`)).not.toContain('SIGNATUREtail123');
  });
  it('E-01③：エラーページのタイトルの文言を出さない', () => {
    const r = evaluate(t('t', 'https://a.example/x', 'HTTP/2 401\ncontent-type: text/html', '<title>Error 401 Invalid API key sk_live_51HtitleECHOkey</title>\n<h2>HTTP ERROR 401 Invalid API key sk_live_51HtitleECHOkey</h2>\n<hr><a href="https://eclipse.org/jetty">Powered by Jetty:// 9.4.53</a>'));   // Jetty の既定のエラーページ（第21回から、本文の HTTP ERROR・Powered by Jetty と合わせて見る）
    const fs = r.findings.filter(f => f.ruleId === 'E-01.3');
    expect(fs).toHaveLength(1);
    expect(exportsOf(r)).not.toContain('sk_live_51HtitleECHOkey');
  });
});

describe('C-09・C-12・H-15：ログイン・ログアウトの失敗', () => {
  const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sid=AAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly; SameSite=Lax`);
  const login = (status: number) => t('login', 'https://a.example/login', `HTTP/2 ${status}\ncontent-type: text/html`, '', 'sensitive=1');
  const logout = (status: number) => t('logout', 'https://a.example/logout', `HTTP/2 ${status}\ncontent-type: text/html`);
  const after = t('after-logout', 'https://a.example/mypage', HTML, '', 'sensitive=1');
  const mypage = (status: number) => t('mypage', 'https://a.example/mypage', `HTTP/2 ${status}\ncontent-type: text/html`, '', 'sensitive=1');
  const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
  it('ログインが 403 で失敗したら、C-09① にしない', () => {
    expect(evaluate(pre + login(403)).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.na']);
  });
  it('ログアウトが 405（GET を受け付けない）なら、C-12①②・H-15 にしない', () => {
    expect(ids(logout(405) + after, 'C-12')).toEqual(['C-12.na', 'C-12.na']);
    expect(ids(logout(405), 'H-15')).toEqual(['H-15.na']);
  });
  it('ログイン後のページが 2xx でない（ログインできていない）なら、C-12 を合格にしない', () => {
    const r = evaluate(mypage(302) + logout(200) + t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /login', '', 'sensitive=1'));
    expect(r.findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.na']);
  });
  it('ログインもログアウトもできていれば、旧Cookieで 200 は C-12①', () => {
    const r = evaluate(mypage(200) + logout(200) + after);
    expect(r.findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.1']);
  });
});
