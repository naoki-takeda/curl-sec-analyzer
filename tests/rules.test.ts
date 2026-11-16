import { describe, expect, it } from 'vitest';
import { evaluate, fixture, sampleText, target } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html\n';
const ids = (input: string) => evaluate(input).ids('t');
const withLabel = (label: string, url: string, head: string, extra = '') => evaluate(`#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n`).ids(label);

describe('H-01 HSTS', () => {
  it('なし→①、1年未満→②、構文不正→③、includeSubDomainsなし→④、十分→ok、http→適用外、URL不明→na', () => {
    expect(ids(target('https://a.example/', HTML))).toContain('H-01.1');
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: max-age=3600'))).toContain('H-01.2');
    // ASVS 5.0.0 3.4.1：1年未満は、6か月以上でも②
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: max-age=15768000; includeSubDomains'))).toContain('H-01.2');
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: includeSubDomains'))).toContain('H-01.3');
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: max-age=63072000'))).toContain('H-01.4');
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: max-age=31536000; includeSubDomains'))).toContain('H-01.ok');
    expect(ids(target('https://a.example/', HTML + 'strict-transport-security: max-age=63072000; includesubdomains; preload'))).toContain('H-01.ok');
    expect(ids(target('http://a.example/', HTML)).some(i => i.startsWith('H-01'))).toBe(false);
    expect(evaluate('#TARGET label=t\n' + HTML).ids('t')).toContain('H-01.na');
  });
});

describe('H-03 CSP・H-06 クリックジャッキング', () => {
  it('CSPなし→①（本文を採取していなければ na）、Report-Onlyのみ→②、強制あり→ok', () => {
    expect(ids(target('https://a.example/', `${HTML}\n\n<html><body>x</body></html>`))).toContain('H-03.1');
    expect(ids(target('https://a.example/', HTML))).toContain('H-03.na');   // <meta> の CSP があるかが分からない
    expect(ids(target('https://a.example/', HTML + "content-security-policy-report-only: default-src 'self'"))).toContain('H-03.2');
    expect(ids(target('https://a.example/', HTML + "content-security-policy: default-src 'self'"))).toContain('H-03.ok');
  });
  it('両方なし→①、ALLOW-FROM→②、XFOのみ→③、frame-ancestors→ok', () => {
    expect(ids(target('https://a.example/', HTML))).toContain('H-06.1');
    expect(ids(target('https://a.example/', HTML + 'x-frame-options: ALLOW-FROM https://b.example'))).toContain('H-06.2');
    expect(ids(target('https://a.example/', HTML + 'x-frame-options: DENY'))).toContain('H-06.3');
    expect(ids(target('https://a.example/', HTML + "content-security-policy: frame-ancestors 'none'"))).toContain('H-06.ok');
  });
  it('HTML向けの項目は画像などには適用せず、API応答では重要度を「情報」に下げる', () => {
    expect(ids(target('https://a.example/x.png', 'HTTP/2 200\ncontent-type: image/png')).some(i => i.startsWith('H-03'))).toBe(false);
    const api = evaluate(target('https://a.example/api', 'HTTP/2 200\ncontent-type: application/json')).findings;
    expect(api.find(f => f.ruleId === 'H-06.1')?.severity).toBe('info');
  });
});

describe('H-08 nosniff・H-12 Cache-Control', () => {
  it('nosniff なし・不正→①、あり→ok', () => {
    expect(ids(target('https://a.example/', HTML))).toContain('H-08.1');
    expect(ids(target('https://a.example/', HTML + 'x-content-type-options: sniff'))).toContain('H-08.1');
    expect(ids(target('https://a.example/', HTML + 'X-Content-Type-Options: NoSniff'))).toContain('H-08.ok');
  });
  it('機密応答：no-storeなし→①、privateのみ→②、no-store→ok。機密か不明→na', () => {
    expect(ids(target('https://a.example/', HTML + 'cache-control: no-cache', 'sensitive=1'))).toContain('H-12.1');
    expect(ids(target('https://a.example/', HTML + 'cache-control: private', 'sensitive=1'))).toContain('H-12.2');
    expect(ids(target('https://a.example/', HTML + 'cache-control: no-store', 'sensitive=1'))).toContain('H-12.ok');
    expect(ids(target('https://a.example/', HTML))).toContain('H-12.na');
    expect(ids(target('https://a.example/app.js', 'HTTP/2 200\ncontent-type: text/javascript'))).toContain('H-12.3');
  });
});

describe('C-01〜C-03 Cookie', () => {
  it('属性ごとに判定し、削除用のSet-Cookieは無視する', () => {
    const r = evaluate(fixture('multi_setcookie.txt'));
    const login = r.ids('login');
    expect(login).toContain('C-02.ok');                       // sid は HttpOnly あり
    expect(login).toContain('C-01.2');                        // tracker（セッション以外）に Secure なし、HSTS不明
    expect(login).toContain('C-03.4');                        // tracker の SameSite=None で Secure なし
    expect(login).toContain('C-03.2');                        // weird の不正な値
    expect(r.findings.some(f => f.evidence.startsWith('old='))).toBe(false);
  });
  it('セッションCookieの Secure なし→C-01①、SameSite なし→C-03①。証跡の値はマスクする', () => {
    const r = evaluate(sampleText());
    const login = r.findings.filter(f => f.target === 'login');
    const c01 = login.find(f => f.ruleId === 'C-01.1')!;
    expect(c01.severity).toBe('high');
    expect(c01.evidence).toContain('SESSIONID=8f3c…(32 chars); Path=/; HttpOnly');
    expect(c01.evidence).not.toContain('8f3c2a91d0b74e6fa1c55d3e9b2f7a40');
    expect(login.map(f => f.ruleId)).toContain('C-03.1');
  });
  it('ホストにHSTSがあれば、セッション以外のCookieの Secure なしは C-01③（低）', () => {
    expect(evaluate(sampleText()).ids('top')).toContain('C-01.3');   // ui_pref（設定用Cookie）
  });
});

describe('R-01 Origin反射・T-04 HTTP→HTTPS', () => {
  it('送信Originの反射＋ACAC→①、反射なし→ok、送信Origin不明→na', () => {
    expect(evaluate(sampleText()).ids('cors-reflect')).toContain('R-01.1');
    expect(withLabel('cors-x', 'https://a.example/', HTML)).toContain('R-01.ok');
    expect(withLabel('cors-x', 'https://a.example/', HTML + 'access-control-allow-origin: https://partner.example')).toContain('R-01.na');
  });
  it('302→④、転送なし→①、http へ→②、別ホスト→③、301→ok', () => {
    expect(evaluate(sampleText()).ids('http')).toContain('T-04.4');
    expect(withLabel('http', 'http://a.example/', HTML)).toContain('T-04.1');
    expect(withLabel('http', 'http://a.example/', 'HTTP/1.1 301 Moved\nLocation: http://a.example/x')).toContain('T-04.2');
    expect(withLabel('http', 'http://a.example/', 'HTTP/1.1 301 Moved\nLocation: https://b.example/')).toContain('T-04.3');
    expect(withLabel('http', 'http://a.example/', 'HTTP/1.1 301 Moved\nLocation: https://a.example/')).toContain('T-04.ok');
  });
});
