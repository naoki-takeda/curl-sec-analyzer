import { describe, expect, it } from 'vitest';
import { AT, evaluate, fixture, itemIds, sampleText, target } from './helpers';
import { ALL_CROSS_RULES, HOST_RULES, IMPLEMENTED, TARGET_RULES } from '../src/rules/ruleset';
import { coverage } from '../src/engine/coverage';

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
  it('CSPなし→①、Report-Onlyのみ→②、強制あり→ok（強制のヘッダが効かず本文を採取していなければ na）', () => {
    const body = '\n\n<html><body>x</body></html>';
    expect(ids(target('https://a.example/', `${HTML}${body}`))).toContain('H-03.1');
    expect(ids(target('https://a.example/', HTML))).toContain('H-03.na');   // <meta> の CSP があるかが分からない
    const ro = HTML + "content-security-policy-report-only: default-src 'self'";
    expect(ids(target('https://a.example/', ro + body))).toContain('H-03.2');
    expect(ids(target('https://a.example/', ro))).toContain('H-03.na');     // <meta> の CSP が強制しているかもしれない
    expect(ids(target('https://a.example/', `${HTML}content-security-policy: ,`))).toContain('H-03.na');
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

describe('ルールの誤検知', () => {
  const page = (body: string) => `#TARGET url=https://www.example.com/ label=page\n#META at=2026-11-01T10:00:00\n${HTML}\n${body}\n`;
  it('E-09①：入力の検証の規則・autocomplete の値・正規表現を秘密の値とみなさない（本物のキーは今までどおり）', () => {
    for (const s of ['<script>const schema={email:"required|email",password:"required|min:8|max:64"};</script>',
      '<script>window.cfg={"username":"username","password":"current-password"};</script>', '<script>var rules={password:"^(?=.*[A-Z])(?=.*\\d).{8,}$"};</script>']) {
      expect(evaluate(page(s)).ids('page'), s).not.toContain('E-09.1');
    }
    expect(evaluate(page('<script>var cfg={client_secret:"9f8e7d6c5b4a3f2e1d0c9b8a"};</script>')).ids('page')).toContain('E-09.1');
  });
  it('E-05①：本文のない /actuator/health の 200 は na（状態だけの応答かが分からない）', () => {
    const r = evaluate('#TARGET url=https://www.example.com/actuator/health label=page\n#META at=2026-11-01T10:00:00\nHTTP/2 200\ncontent-type: application/vnd.spring-boot.actuator.v3+json\n\n');
    expect(r.ids('page').filter(x => x.startsWith('E-05'))).toEqual(['E-05.na']);
  });
  it('H-03③：有効な CSP のヘッダがあれば、空の CSP のヘッダがあっても③にしない', () => {
    const r = withLabel('page', 'https://www.example.com/', `${HTML}content-security-policy: default-src 'self'; object-src 'none'; base-uri 'none'\ncontent-security-policy: \n`);
    expect(r).not.toContain('H-03.3');
    expect(r).toContain('H-03.ok');
  });
  it('R-05：cors-preflight で許可外の Origin のプリフライトを拒否したら合格（適用外にしない）', () => {
    const r = evaluate('#TARGET url=https://www.example.com/api label=cors-preflight\n* Connected to www.example.com (192.0.2.1) port 443\n> OPTIONS /api HTTP/2\n> Origin: https://evil.example\n> Access-Control-Request-Method: PUT\n>\n< HTTP/2 403\n<\n');
    expect(r.ids('cors-preflight')).toContain('R-05.ok');
  });
  it('T-05：一般ラベルで、許可していない条件（①）の指摘だけのときは、許可した条件（②）を判定済みとして残す', () => {
    const r = evaluate('#TARGET url=https://www.example.com/a label=page\n#META at=2026-11-01T10:00:00\nHTTP/2 302\nlocation: http://www.example.com/b\n\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n<p>b</p>\n');
    expect(r.ids('page').filter(x => x.startsWith('T-05'))).toEqual(['T-05.ok']);
  });
});

describe('ルールの誤検知・見逃し', () => {
  const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/x label=t\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('t');
  it('A-07①：API の検証の規則・autocomplete の値・エラーの項目の値を、パスワードの露出とみなさない（本物は今までどおり）', () => {
    for (const b of ['{"rules":{"email":"required|email","password":"required|min:8|max:64"}}', '{"autocomplete":{"password":"current-password"}}', '{"errors":{"password":"TOO_SHORT"}}']) {
      expect(api(b), b).not.toContain('A-07.1');
    }
    expect(api('{"user":{"id":1,"password":"Kirin2024secret"}}')).toContain('A-07.1');
  });
  it('H-03①：<template>・<noscript>・スクリプトの文字列の中の meta の CSP は効かない', () => {
    for (const head of ['<template><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; object-src \'none\'"></template>',
      '<script>var t=\'<meta http-equiv="Content-Security-Policy" content="default-src none">\';</script>']) {
      expect(evaluate(`#TARGET url=https://www.example.com/ label=page\n${AT}\n${HTML}\n<head>${head}</head><body><p>x</p></body>\n`).ids('page'), head).toContain('H-03.1');
    }
  });
  it('H-01・H-02：http で採取して www へ転送した apex は、www の HSTS で判定しない', () => {
    const r = evaluate(`#TARGET url=http://example.com/ label=apex\n${AT}\nHTTP/1.1 301 Moved\nlocation: https://www.example.com/\n\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\n\n<p>x</p>\n`).ids('apex');
    expect(r.filter(x => x.startsWith('H-01') || x.startsWith('H-02'))).toEqual(expect.arrayContaining(['H-01.na']));
    expect(r).not.toContain('H-01.ok');
    expect(r).not.toContain('H-02.ok');
  });
  it('E-10：同じ名前の属性が2つあれば、最初の値で判定する（ブラウザと同じ）', () => {
    const form = (a: string, b: string) => evaluate(`#TARGET url=https://www.example.com/login label=page\n${AT}\n${HTML}\n<form method="post" action="${a}" action="${b}"><input type="password" name="pw"></form>\n`).ids('page');
    expect(form('https://www.example.com/session', 'http://www.example.com/session')).not.toContain('E-10.1');
    expect(form('http://www.example.com/session', 'https://www.example.com/session')).toContain('E-10.1');
  });
});

describe('E-09・A-07 の画面の部品の値、R-04・R-06・E-05', () => {
  const page = (js: string) => `#TARGET url=https://www.example.com/login label=t\nHTTP/2 200\ncontent-type: text/html\n\n<html><script>${js}</script></html>\n`;
  const e09 = (js: string) => ids(page(js)).filter(i => i === 'E-09.1');
  it('E-09①：セレクタ・項目の名前・エスケープした日本語の文言は秘密の値ではない', () => {
    for (const js of ['var s={password:"#password-input"}', 'var s={password:".js-password"}', 'var s={password:"input[name=password]"}',
      'var s={"password":"user_password"}', 'var s={"password":"loginPassword"}', 'var s={"password":"password_confirmation"}',
      'window.i18n={"password":"\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5165\u529b"}'])
      expect(e09(js), js).toEqual([]);
  });
  it('E-09①：本物の秘密の値は、これまでどおり①', () => {
    expect(e09('var cfg={client_secret:"sk9Fq2LmZx81PwQr"}')).toEqual(['E-09.1']);
    expect(e09('var cfg={password:"Winter2024!Strong"}')).toEqual(['E-09.1']);
  });
  it('A-07①：パス・URL・項目の名前の値はパスワードの露出とみなさない', () => {
    const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('api');
    for (const b of ['{"menu":{"password":"/settings/password"}}', '{"links":{"password":"https://www.example.com/password/reset"}}', '{"form":{"password":"user_password"}}'])
      expect(api(b).filter(i => i === 'A-07.1'), b).toEqual([]);
    expect(api('{"user":{"password":"Winter2024!Strong"}}')).toContain('A-07.1');
  });
  it('R-04：Origin を送ったと分からず ACAO もない応答は合格にしない（na）。cors-* のラベルと ACAO: * はこれまでどおり判定', () => {
    expect(withLabel('page', 'https://www.example.com/', HTML)).toContain('R-04.na');
    expect(withLabel('cors-reflect', 'https://www.example.com/api', HTML)).toContain('R-04.ok');
    expect(withLabel('page', 'https://www.example.com/', `${HTML}access-control-allow-origin: *`)).not.toContain('R-04.na');
  });
  it('R-06①：送った Origin と違う固定の ACAO には出さない（na）。反射した ACAO はこれまでどおり①', () => {
    const v = (acao: string) => evaluate(['#TARGET url=https://www.example.com/api label=cors-reflect', '* Connected to www.example.com (192.0.2.1) port 443', '> GET /api HTTP/2',
      '> Origin: https://evil.example', '>', '< HTTP/2 200', '< content-type: application/json', `< access-control-allow-origin: ${acao}`, '<', ''].join('\n')).ids('cors-reflect');
    expect(v('https://app.example.com')).toContain('R-06.na');
    expect(v('https://evil.example')).toContain('R-06.1');
  });
  it('E-05：5xx は合格にしない（na）', () => {
    const r = evaluate('#TARGET url=https://www.example.com/actuator/env label=page\nHTTP/2 503\ncontent-type: application/json\n\n{"error":"x"}\n').ids('page').filter(x => x.startsWith('E-05'));
    expect(r).toEqual(['E-05.na']);
  });
  it('E-09①・A-07①：秘密の語のほかの語を含む値・セレクタの形でない値・エスケープが1つの値は、秘密の値として扱う', () => {
    for (const js of ['var cfg={secret_key:"my-super-secret-key"}', 'var cfg={password:"changeme_password"}', 'var cfg={password:"Pass[1]Secret!x"}', 'var cfg={password:"S3cr3t\\u00e9Value99"}', 'var cfg={password:"/Ab3xY9qLmZ81PwQr"}'])
      expect(e09(js), js).toEqual(['E-09.1']);
    const api = evaluate('#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n{"user":{"password":"admin_pass"}}\n').ids('api');
    expect(api).toContain('A-07.1');
  });
  it('E-09：語として読める翻訳キー・パスは除き、A-07：ユーザー情報のある URL・合言葉は除かない', () => {
    for (const js of ['var s={password:"auth.passwordLabel"}', 'var s={password:"user.newPassword"}', 'var s={password:"/Account/ForgotPassword"}', 'var s={password:"/users/password/new?locale=ja"}'])
      expect(e09(js), js).toEqual([]);
    const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('api');
    for (const b of ['{"user":{"password":"https://u:Winter2024@db.example.com/"}}', '{"user":{"password":"correct.horse.battery"}}', '{"user":{"password":"a1b2c3d4e5.f6a7b8c9d0e1f2"}}'])
      expect(api(b), b).toContain('A-07.1');
  });
});

describe('文書の仮の値・公開のクライアントのキー・H-02③ の主語・T-09 の重複', () => {
  const page = (js: string) => `#TARGET url=https://www.example.com/docs label=t\nHTTP/2 200\ncontent-type: text/html\n\n<html><script>${js}</script></html>\n`;
  it('E-09①：文書の仮の値は秘密の値ではない', () => {
    for (const js of ['var c={api_key:"YOUR_API_KEY_HERE"}', 'var c={client_secret:"<your-client-secret>"}', 'var c={access_token:"INSERT_TOKEN_HERE"}'])
      expect(ids(page(js)).filter(i => i === 'E-09.1'), js).toEqual([]);
    expect(ids(page('var c={api_key:"sk9Fq2LmZx81PwQr"}'))).toContain('E-09.1');
  });
  it('A-07①：検索専用のキー（searchOnlyApiKey・DocSearch）と PostHog の公開キーは除く', () => {
    const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/config label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('api');
    expect(api('{"algolia":{"appId":"ABCDEF1234","searchOnlyApiKey":"0123456789abcdef0123456789abcdef"}}')).not.toContain('A-07.1');
    expect(api('{"docsearch":{"appId":"ABCDEF1234","apiKey":"0123456789abcdef0123456789abcdef"}}')).not.toContain('A-07.1');
    // 管理用・マスターのキーも apiKey という名前なので、Algolia・Typesense の apiKey は除かない
    expect(api('{"algolia":{"appId":"ABCDEF1234","apiKey":"0123456789abcdef0123456789abcdef"}}')).toContain('A-07.1');
    expect(api('{"typesense":{"apiKey":"Xy7Qp2Lm9ZaB3cD4eF5gH6iJ7kL8mN9o"}}')).toContain('A-07.1');
    expect(api('{"posthog":{"api_key":"phc_AbCdEf0123456789AbCdEf0123456789AbCdEf01"}}')).not.toContain('A-07.1');
    expect(api('{"db":{"api_key":"0123456789abcdef0123456789abcdef"}}')).toContain('A-07.1');
  });
  it('H-02③：apex から www へ転送したとき、preload を付けたのは www と書く', () => {
    const r = evaluate(['#TARGET url=https://example.com/ label=apex', 'HTTP/2 301', 'location: https://www.example.com/', '', 'HTTP/2 200',
      'strict-transport-security: max-age=63072000; includeSubDomains; preload', '', ''].join('\n'));
    expect(r.findings.filter(f => f.ruleId === 'H-02.3').map(f => f.evidence)).toEqual(['www.example.com は preload を付けているが、apex がHSTSを返さない']);
  });
  it('T-09①：同じバージョンのプローブが重なっても、証跡に1回だけ書く', () => {
    const t = (i: number) => `#TARGET url=https://www.example.com/ label=tls${i}\n#TLSPROBE v=tls1 ok=0\n#TLSPROBE v=tls1_1 ok=1\n`;
    const ev = evaluate(t(1) + t(2)).findings.find(f => f.ruleId === 'T-09.1')?.evidence ?? '';
    expect(ev.match(/tls1_1/g)).toHaveLength(1);
  });
  it('example・sample を含む本物のパスワードは仮の値とみなさない', () => {
    expect(ids(page('var c={password:"my_example_password"}')).filter(i => i === 'E-09.1')).toEqual(['E-09.1']);
  });
});

describe('重要度「高」の条件の見逃し', () => {
  const SESSION = 'set-cookie: sessionid=Zx9k2LmQ8vT4pR7wN1yB6cH3; Path=/';
  it('C-01①・C-02①：数字だけの Expires（0・-1）はブラウザが無視するので、セッションCookieのまま判定する', () => {
    for (const exp of ['; Expires=0', '; Expires=-1', '; expires=2099']) {
      const r = ids(target('https://a.example/', `${HTML}${SESSION}${exp}`));
      expect(r, exp).toContain('C-01.1');
      expect(r, exp).toContain('C-02.1');
    }
  });
  it('C-12：logout の Expires=0 は削除ではない（Cookie は残る）', () => {
    const r = evaluate(['#TARGET url=https://a.example/logout label=logout', 'HTTP/2 302', 'location: /', `${SESSION}; Secure; HttpOnly; Expires=0`, '', ''].join('\n'));
    expect(r.ids('logout')).not.toContain('C-12.ok');
  });
  it('Cookie の日付：RFC 6265 5.1.1 の形は読み、2桁の年と範囲の外を扱う', async () => {
    const { cookieDate } = await import('../src/parser/setCookie');
    expect(cookieDate('Wed, 21 Oct 2026 07:28:00 GMT')).toBe(Date.UTC(2026, 9, 21, 7, 28, 0));
    expect(cookieDate('Wednesday, 21-Oct-26 07:28:00 GMT')).toBe(Date.UTC(2026, 9, 21, 7, 28, 0));
    expect(cookieDate('Wed, 01-Oct-69 00:00:00 GMT')).toBe(Date.UTC(2069, 9, 1));
    expect(cookieDate('Thu, 01 Jan 1970 00:00:00 GMT')).toBe(0);
    for (const bad of ['0', '-1', '2099', 'Wed, 30 Feb 2026 00:00:00 GMT', 'Wed, 21 Oct 2026', '2026-10-21T07:28:00Z', 'Wed, 21 Oct 2026 24:00:00 GMT'])
      expect(cookieDate(bad), bad).toBeNaN();
  });
  it('A-07①：先頭が大文字の略語のキー（DBPassword・SMTPPassword・AWSSecretKey）も分けて見る', () => {
    const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('api');
    for (const k of ['DBPassword', 'SMTPPassword', 'AWSSecretKey'])
      expect(api(`{"config":{"${k}":"hunter2xyz9Q"}}`), k).toContain('A-07.1');
    expect(api('{"config":{"DBHost":"db.internal"}}')).not.toContain('A-07.1');
  });
  it('E-01：静的ファイルの URL でも、エラーの応答と HTML の画面は見る（JS の本文は見ない）', () => {
    const err = (path: string, status: string, ct: string) => evaluate(`#TARGET url=https://www.example.com${path} label=error-img\nHTTP/1.1 ${status}\ncontent-type: ${ct}\n\n<html><pre>Traceback (most recent call last):\n  File "/srv/app/main.py", line 3\nmongodb://admin:S3cretPw9@db.internal:27017/app</pre></html>\n`).ids('error-img');
    expect(err('/img/missing.png', '500 Internal Server Error', 'text/html')).toEqual(expect.arrayContaining(['E-01.1', 'E-01.2']));
    expect(err('/img/missing.png', '404 Not Found', 'text/plain')).toContain('E-01.2');
    expect(err('/assets/app.js', '200 OK', 'application/javascript').filter(i => i.startsWith('E-01'))).toEqual([]);
  });
  it('E-09①：属性の中の文字参照の JSON と、JS の文字列の中のエスケープした JSON の秘密も見る', () => {
    const secrets = { config: { api_key: 'Zx9QwErT77LmNb3k', password: 'Hunter2-Secret!x' } };
    const json = JSON.stringify({ props: secrets });
    const attr = `<div id="app" data-page="${json.replace(/"/g, '&quot;')}"></div>`;
    const script = `<script>window.__S__ = JSON.parse(${JSON.stringify(json)})</script>`;
    for (const b of [attr, script]) expect(ids(`#TARGET url=https://www.example.com/ label=t\n${HTML}\n<html>${b}</html>\n`), b).toContain('E-09.1');
    // 文言・パスは、戻しても秘密としない
    const label = `<div data-page="${JSON.stringify({ password: '/users/password/new' }).replace(/"/g, '&quot;')}"></div>`;
    expect(ids(`#TARGET url=https://www.example.com/ label=t\n${HTML}\n<html>${label}</html>\n`)).not.toContain('E-09.1');
  });
  it('C-10①：csp-sample-* も一般のターゲットと同じ項目を判定する', () => {
    expect(withLabel('csp-sample-1', 'http://www.example.com/', `${HTML}${SESSION}; HttpOnly`)).toContain('C-10.1');
  });
  it('XHTML と Content-Type のない HTML の本文も HTML の画面として判定する', () => {
    const page = '<!doctype html><html><body>x</body></html>';
    for (const head of ['HTTP/2 200\ncontent-type: application/xhtml+xml; charset=utf-8\n', 'HTTP/2 200\n']) {
      const r = ids(target('https://a.example/', `${head}\n${page}`));
      expect(r, head).toContain('H-03.1');
      expect(r, head).toContain('H-06.1');
    }
    // 本文が HTML でない、Content-Type のない応答は、これまでどおり HTML の項目を判定しない
    expect(ids(target('https://a.example/', 'HTTP/2 200\n\n{"a":1}'))).not.toContain('H-03.1');
  });
});

describe('ヘッダ・Cookie・CORS・転送の判定の細部', () => {
  const only = (r: string[], item: string) => r.filter(x => x.startsWith(`${item}.`));
  it('H-09：meta だけの古い値（always・never）はヘッダでは読み替えない', () => {
    const page = (head: string, meta: string) => target('https://a.example/', `${HTML}${head}\n\n<html><head><meta name="referrer" content="${meta}"></head></html>`);
    // ヘッダの always はブラウザが無視する値なので、meta の no-referrer だけで判定する
    expect(only(ids(page('referrer-policy: always', 'no-referrer')), 'H-09')).toEqual(['H-09.ok']);
    // meta の always は unsafe-url と読む
    expect(only(ids(page('referrer-policy: no-referrer', 'always')), 'H-09')).toEqual(['H-09.1']);
  });
  it('H-02：スキームが分からないときは、H-01 と同じく na', () => {
    const r = evaluate(`#TARGET label=t\n${HTML}strict-transport-security: max-age=31536000\n`);
    expect(only(r.ids('t'), 'H-02')).toEqual(['H-02.na']);
    expect(r.findings.find(f => f.ruleId === 'H-02.na')?.evidence).toBe('HTTPSかどうか判定できない');
  });
  it('H-04：default-src だけのポリシーの合格の証跡は default-src と書く', () => {
    const f = evaluate(target('https://a.example/', `${HTML}content-security-policy: default-src 'self'; object-src 'none'; base-uri 'none'`)).findings.find(x => x.ruleId === 'H-04.ok');
    expect(f?.evidence).toBe("default-src 'self'");
  });
  it('T-05②・H-16④：内部のホストは、プライベート・ループバックのアドレス全体と localhost・内部の名前だけ', () => {
    const hop = (loc: string) => ids(target('https://a.example/', `HTTP/2 302\nlocation: ${loc}\n\nHTTP/2 200\ncontent-type: text/html`));
    expect(only(hop('https://10.cdn.example.com/x'), 'T-05')).toEqual(['T-05.ok']);   // 数字で始まる公開のホスト名
    expect(only(hop('https://127.example.net/x'), 'T-05')).toEqual(['T-05.ok']);
    for (const loc of ['http://10.0.0.5/', 'http://127.0.0.2/', 'http://localhost/', 'http://app.internal/']) expect(only(hop(loc), 'T-05'), loc).toContain('T-05.2');
    const h = (v: string) => only(ids(target('https://a.example/', `${HTML}${v}`)), 'H-16');
    for (const v of ['x-backend-server: 127.0.0.2:8080', 'x-served-by: 10.1.2.3', 'x-host: localhost', 'via: 1.1 app01.corp']) expect(h(v), v).toContain('H-16.4');
    for (const v of ['x-backend-server: 10.cdn.example.com', 'x-host: localhost.example.com', 'x-served-by: edge01.local.example-cdn.net', 'x-backend-server: 10.0.0.1.example.com']) expect(h(v), v).not.toContain('H-16.4');
  });
  it('C-04①：親ドメインへの拡大だけ。ホストのサブドメインの Domain は、ブラウザが拒否するので指摘しない', () => {
    const c = (url: string, dom: string) => only(ids(target(url, `${HTML}set-cookie: pref=1; Domain=${dom}; Secure`)), 'C-04');
    expect(c('https://www.example.com/', 'example.com')).toEqual(['C-04.1']);
    expect(c('https://example.com/', 'www.example.com')).toEqual(['C-04.ok']);
    expect(c('https://example.com/', 'other.example')).toEqual(['C-04.ok']);
  });
  it('R-07②：ACAC: true のときの Access-Control-Expose-Headers: * は「*」という名前のヘッダ', () => {
    const r = (extra: string) => only(ids(target('https://a.example/api', `HTTP/2 200\ncontent-type: application/json\naccess-control-expose-headers: *${extra}`)), 'R-07');
    expect(r('')).toEqual(['R-07.2']);
    expect(r('\naccess-control-allow-credentials: true')).toEqual(['R-07.ok']);
  });
});

describe('HTML本文のタグ・コメントの読み取り（E-07〜E-10・E-12）', () => {
  const page = (body: string) => ids(target('https://a.example/', `${HTML}\n\n${body}`));
  it('カスタム要素（<form-field>・<img-slider>・<script-loader>）を <form>・<img>・<script> と読まない', () => {
    const r = page('<form-field method="get" action="http://a.example/x"><input type="password"></form-field><img-slider src="http://cdn.example/a.jpg"></img-slider>'
      + '<script-loader src="https://cdn.other.example/x.js"></script-loader>');
    expect(r).not.toContain('E-10.1'); expect(r).not.toContain('E-10.2');
    expect(r).not.toContain('E-07.2');
    expect(r).not.toContain('E-08.1');
    expect(page('<form method="get"><input type="password"></form>')).toContain('E-10.2');
  });
  it('<textarea>・<title> の中のタグは要素にならないので数えない。<script> の中（document.write）は数える', () => {
    const r = page('<title><img src="http://x.example/a.png"></title><textarea><img src="http://x.example/a.png"><form method=get><input type=password></form><script src="https://cdn.other.example/x.js"></script></textarea>');
    expect(r).not.toContain('E-07.2'); expect(r).not.toContain('E-10.2'); expect(r).not.toContain('E-08.1');
    expect(page(`<script>document.write('<script src="http://x.example/a.js"></scr' + 'ipt>')</script>`)).toContain('E-07.1');
  });
  it('E-09②：コメントはブラウザと同じく切り出す（「<!-->」は空のコメント、「--!>」で閉じる、<script> の文字列の「<!--」はコメントではない）', () => {
    expect(page('<!--><p>Debug the staging server</p><!-- ok -->')).not.toContain('E-09.2');
    expect(page('<script>var s="<!--"</script><p>Debug panel</p><!-- hi -->')).not.toContain('E-09.2');
    expect(page('<!-- a --!><p>Debug panel</p><!-- b -->')).not.toContain('E-09.2');
    expect(page('<!-- FIXME later --!><p>x</p>')).toContain('E-09.2');
  });
  it('E-09②：内部URLは URL の中の URL も見る。ループバックは 127.0.0.0/8 全体。ユーザー情報のある URL は証跡に出さない', () => {
    expect(page('<a href="https://a.example/go?to=http://10.0.0.5/admin">x</a>')).toContain('E-09.2');
    expect(page('<a href="http://127.0.1.1:8080/">x</a>')).toContain('E-09.2');
    expect(page('<a href="https://cdn.example.com/a.js">x</a><a href="https://edge01.local.example-cdn.net/">y</a>')).not.toContain('E-09.2');
  });
});

describe('E-04・E-05・T-11 の細部', () => {
  const at = (url: string, head: string) => evaluate(`#TARGET url=${url} label=t\n${AT}\n${head}\n`).findings.filter(f => f.item === 'E-04');
  it('E-04：空の「Expires:」で次の行を値にしない。「Disallow:」の値は同じ行だけ', () => {
    const r = at('https://a.example/.well-known/security.txt', 'HTTP/2 200\ncontent-type: text/plain\n\nContact: mailto:sec@a.example\nExpires:\nPolicy: https://a.example/policy');
    expect(r.map(f => [f.ruleId, f.evidence])).toEqual([['E-04.2', 'Contact: あり / Expires: なし']]);
    expect(at('https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/plain\n\nUser-agent: *\nDisallow:\n/admin/ is not a rule').map(f => f.ruleId)).toEqual(['E-04.ok']);
    expect(at('https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/plain\n\nUser-agent: *\nDisallow: /admin/').map(f => f.ruleId)).toEqual(['E-04.1']);
  });
  it('T-11：#META at が読めないときは、応答の Date ではなく判定した時刻を基準にする', () => {
    // 応答の Date（2024-01-01）を基準にすると、notAfter（2025-06-01）まで1年以上あり合格になる
    const e = evaluate(['#TARGET url=https://www.example.com/ label=tls', '#META at=yesterday', 'HTTP/2 200', 'date: Mon, 01 Jan 2024 00:00:00 GMT', '', 'CONNECTED(00000003)',
      'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', 'Verify return code: 0 (ok)', 'notAfter=Jun  1 00:00:00 2025 GMT', ''].join('\n'));
    expect(e.targets[0].responses[0]?.headers.get('date')).toBeTruthy();
    expect(e.findings.filter(f => f.item === 'T-11').map(f => f.ruleId)).toContain('T-11.1');
  });
});

describe('ルールの登録', () => {
  it('scope は登録した一覧（ターゲット単位・ホスト単位・横断）と一致する', () => {
    for (const [list, scope] of [[TARGET_RULES, 'target'], [HOST_RULES, 'host'], [ALL_CROSS_RULES, 'cross']] as const)
      for (const r of list) expect(r.scope, r.id).toBe(scope);
  });
});

describe('H-04⑥ の \'unsafe-hashes\'', () => {
  const h04 = (csp: string) => evaluate(target('https://a.example/', `${HTML}content-security-policy: ${csp}; object-src 'none'; base-uri 'none'`)).findings.filter(f => f.item === 'H-04' && f.ruleId !== 'H-04.na');   // H-04.na は csp-sample のない横断の⑤
  const HASH = "'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='";
  it('ハッシュのあるディレクティブの \'unsafe-hashes\' は、情報として出す', () => {
    for (const csp of [`script-src 'self' 'unsafe-hashes' ${HASH}`, `script-src-attr 'unsafe-hashes' ${HASH}; script-src 'self'`, `default-src 'self' 'unsafe-hashes' ${HASH}`]) {
      const f = h04(csp);
      expect(f.map(x => x.ruleId), csp).toEqual(['H-04.6']);
      expect(f[0].severity).toBe('info');
      expect(f[0].evidence).toContain('SCRIPT_UNSAFE_HASHES');
    }
  });
  it('ハッシュのない \'unsafe-hashes\'（何も許さない）と、script-src があるときの default-src のものは出さない', () => {
    expect(h04("script-src 'self' 'unsafe-hashes'").map(x => x.ruleId)).toEqual(['H-04.ok']);
    expect(h04(`default-src 'self' 'unsafe-hashes' ${HASH}; script-src 'self'`).map(x => x.ruleId)).toEqual(['H-04.ok']);
  });
  it('style-src の \'unsafe-hashes\' は H-04 ではない', () => {
    expect(h04(`script-src 'self'; style-src 'self' 'unsafe-hashes' ${HASH}`).map(x => x.ruleId)).toEqual(['H-04.ok']);
  });
});

describe('E-09 の hidden の欄・A-09 の Content-Type の空白・E-04 の Expires', () => {
  const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDU2Nzg5MCIsImlzcyI6Imh0dHBzOi8vaWRwIn0.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU';
  const page = (input: string) => target('https://idp.example/', `${HTML}\n<html><body><form method="post" action="https://app.example/cb">${input}</form></body></html>`);
  it('E-09：form_post の id_token の欄は、属性の値に > があっても欄ごと除く', () => {
    expect(ids(page(`<input type="hidden" name="id_token" value="${JWT}">`)).filter(x => x.startsWith('E-09'))).toEqual(['E-09.ok']);
    expect(ids(page(`<input data-note="a>b" type="hidden" name="id_token" value="${JWT}">`)).filter(x => x.startsWith('E-09'))).toEqual(['E-09.ok']);
  });
  it('E-09：除いた欄の外の JWT は今までどおり①', () => {
    expect(ids(page(`<input data-note="a>b" type="hidden" name="id_token" value="x"><script>var t="${JWT}"</script>`)).filter(x => x.startsWith('E-09'))).toEqual(['E-09.1']);
  });
  it('A-09：HAR の Content-Type の値の前に空白があっても、JSON の本文の text/html を①にする', async () => {
    const { analyze } = await import('./golden/analyze');
    const har = JSON.stringify({ log: { entries: [{ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url: 'https://a.example/data', headers: [] },
      response: { status: 200, httpVersion: 'HTTP/2', headers: [{ name: 'Content-Type', value: ' text/html' }], content: { mimeType: 'text/html', text: '{"a":1}' } } }] } });
    expect(analyze('', har).findings.filter(f => f.item === 'A-09').map(f => f.ruleId)).toEqual(['A-09.1']);
  });
  it('E-04：CRLF の行の Expires も日時として読む', () => {
    const r = ids(target('https://a.example/.well-known/security.txt', 'HTTP/2 200\ncontent-type: text/plain\n\nContact: mailto:security@example.com\r\nExpires: 2099-01-01T00:00:00Z \r\n'));
    expect(r.filter(x => x.startsWith('E-04'))).toEqual(['E-04.ok']);
  });
});

describe('E-01・A-07 の本文を採取していない応答', () => {
  const only = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
  const t = (label: string, url: string, head: string) => `#TARGET url=${url} label=${label}\n${head.trim()}\n`;
  it('E-01：エラーの応答（4xx・5xx）と error-* で本文を採取していないなら na', () => {
    expect(only(t('page', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html'), 'E-01')).toEqual(['E-01.na']);
    expect(only(t('error-404', 'https://a.example/api/none', 'HTTP/2 404\ncontent-type: application/json'), 'E-01')).toEqual(['E-01.na']);
  });
  it('E-01：2xx の本文のない応答、204・Content-Length: 0 の応答は適用外のまま', () => {
    expect(only(t('page', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html'), 'E-01')).toEqual([]);
    expect(only(t('page', 'https://a.example/x', 'HTTP/2 500\ncontent-length: 0'), 'E-01')).toEqual([]);
  });
  it('A-07：API の 2xx で本文を採取していないなら na、204 は適用外', () => {
    expect(only(t('api', 'https://a.example/api/me', 'HTTP/2 200\ncontent-type: application/json'), 'A-07')).toEqual(['A-07.na']);
    expect(only(t('api', 'https://a.example/api/me', 'HTTP/2 204\ncontent-type: application/json'), 'A-07')).toEqual([]);
    expect(only(t('api', 'https://a.example/api/me', 'HTTP/2 200\ncontent-type: application/json\n\n{"id":1}'), 'A-07')).toEqual(['A-07.ok']);
  });
});

describe('\'unsafe-hashes\' の効くディレクティブと、ポリシーが複数のとき', () => {
  const HASH = "'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='";
  const h04f = (...csps: string[]) => evaluate(target('https://a.example/', `${HTML}${csps.map(c => `content-security-policy: ${c}; object-src 'none'; base-uri 'none'`).join('\n')}`))
    .findings.filter(f => f.item === 'H-04' && f.ruleId !== 'H-04.na');
  const h04 = (...csps: string[]) => h04f(...csps).map(f => f.ruleId);
  const hashes = (...csps: string[]) => h04f(...csps).filter(f => f.evidence.includes('SCRIPT_UNSAFE_HASHES')).length;
  it('script-src-attr があれば、script-src・default-src の \'unsafe-hashes\' は出さない', () => {
    expect(h04(`default-src 'self' 'unsafe-hashes' ${HASH}; script-src-attr 'none'`)).toEqual(['H-04.ok']);
    expect(h04(`script-src 'self' 'unsafe-hashes' ${HASH}; script-src-attr 'none'`)).toEqual(['H-04.ok']);
  });
  it('別のポリシーが \'unsafe-inline\' ならイベントハンドラを止めないので出し、短い nonce だけなら止めるので出さない', () => {
    expect(hashes(`script-src 'self' 'unsafe-hashes' ${HASH}`, "script-src 'self' 'unsafe-inline'")).toBe(1);
    expect(hashes(`script-src 'self' 'unsafe-hashes' ${HASH}`, "script-src 'self' 'nonce-a'")).toBe(0);
    expect(hashes(`script-src 'self' 'unsafe-hashes' ${HASH}`, `script-src 'self' 'unsafe-hashes' ${HASH}`)).toBe(1);
  });
});

describe('先頭が0の条件番号', () => {
  it('H-01.01 は H-01.1 と照合されず効かないのでエラーにする', async () => {
    const { parseProfile } = await import('../src/engine/profile');
    expect(parseProfile(JSON.stringify({ severity: { 'H-01.01': 'low' } })).errors).toEqual(['severity：「H-01.01」は条件番号がH-01にありません（1〜4）']);
  });
});

describe('C-13 の Cache-Control', () => {
  it('C-13：引用符の中の public（private="X-Public"）では共有キャッシュとみなさない', () => {
    const r = evaluate(target('https://a.example/login', `HTTP/2 200\ncontent-type: text/html\ncache-control: private="X-Public", max-age=60\nset-cookie: SESSIONID=${'a1B2'.repeat(8)}; Secure; HttpOnly; SameSite=Lax`));
    expect(r.findings.filter(f => f.item === 'C-13').map(f => f.ruleId)).not.toContain('C-13.1');
  });
});

describe('CORS：Origin を送っていない・自サイトの Origin の応答', () => {
  const v = (label: string, url: string, sent: string[], recv: string[]) => [`#TARGET url=${url} label=${label}`, '* Connected to a.example (192.0.2.1) port 443',
    ...sent.map(l => `> ${l}`), '>', ...recv.map(l => `< ${l}`), '<', ''].join('\n');
  const of = (input: string, item: string, label: string) => evaluate(input).findings.filter(f => f.item === item && f.target === label).map(f => f.ruleId);
  it('R-09：Origin を送っていない・自サイトの Origin の 401・403 は合格にしない（認証が足りないための拒否かもしれない）', () => {
    expect(of(v('websocket', 'https://a.example/ws', ['GET /ws HTTP/1.1', 'Host: a.example'], ['HTTP/1.1 403 Forbidden']), 'R-09', 'websocket')).toEqual(['R-09.na']);
    expect(of(v('websocket', 'https://a.example/ws', ['GET /ws HTTP/1.1', 'Host: a.example', 'Origin: https://a.example'], ['HTTP/1.1 403 Forbidden']), 'R-09', 'websocket')).toEqual(['R-09.na']);
    expect(of(v('websocket', 'https://a.example/ws', ['GET /ws HTTP/1.1', 'Host: a.example', 'Origin: https://evil.example'], ['HTTP/1.1 403 Forbidden']), 'R-09', 'websocket')).toEqual(['R-09.ok']);
  });
  it('R-05：Origin を送っていない cors-preflight の OPTIONS は、プリフライトを許可しなかったとは言えない', () => {
    expect(of(v('cors-preflight', 'https://a.example/api/me', ['OPTIONS /api/me HTTP/2', 'Host: a.example'], ['HTTP/2 204']), 'R-05', 'cors-preflight')).toEqual(['R-05.na']);
    expect(of(v('cors-preflight', 'https://a.example/api/me', ['OPTIONS /api/me HTTP/2', 'Host: a.example', 'Origin: https://evil.example'], ['HTTP/2 204']), 'R-05', 'cors-preflight')).toEqual(['R-05.ok']);
  });
  it('R-06：自サイトの Origin への ACAO は、Origin によって変わる値かが分からない', () => {
    expect(of(v('top', 'https://a.example/', ['GET / HTTP/2', 'Host: a.example', 'Origin: https://a.example'], ['HTTP/2 200', 'access-control-allow-origin: https://a.example']), 'R-06', 'top')).toEqual(['R-06.na']);
    expect(of(v('top', 'https://a.example/', ['GET / HTTP/2', 'Host: a.example', 'Origin: https://evil.example'], ['HTTP/2 200', 'access-control-allow-origin: https://evil.example']), 'R-06', 'top')).toEqual(['R-06.1']);
  });
});

describe('本文のない応答（304・Content-Length: 0）は「本文を採取していない」にしない', () => {
  const one = (label: string, url: string, head: string, item: string) =>
    evaluate(`#TARGET url=${url} label=${label}\n${head}\n\n`).findings.filter(f => f.item === item).map(f => f.ruleId);
  it('E-13：キャッシュした JS の 304 は適用外。本文を採っていない 200 は na', () => {
    expect(one('t', 'https://a.example/app.js', 'HTTP/2 304', 'E-13')).toEqual([]);
    expect(one('t', 'https://a.example/app.js', 'HTTP/2 200\ncontent-type: text/javascript', 'E-13')).toEqual(['E-13.na']);
  });
  it('E-06：?callback= の 204・Content-Length: 0 は JSONP ではない', () => {
    expect(one('t', 'https://a.example/api?callback=cb', 'HTTP/2 204', 'E-06')).toEqual([]);
    expect(one('t', 'https://a.example/api?callback=cb', 'HTTP/2 200\ncontent-type: application/javascript\ncontent-length: 0', 'E-06')).toEqual(['E-06.ok']);
  });
  it('E-04：空の robots.txt は合格、空の security.txt は②', () => {
    expect(one('t', 'https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/plain\ncontent-length: 0', 'E-04')).toEqual(['E-04.ok']);
    expect(one('t', 'https://a.example/.well-known/security.txt', 'HTTP/2 200\ncontent-type: text/plain\ncontent-length: 0', 'E-04')).toEqual(['E-04.2']);
  });
  it('T-07・T-01：Content-Length: 0 の応答は、反映していないので判定する', () => {
    expect(one('host-inj', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html\ncontent-length: 0', 'T-07')).toEqual(['T-07.ok']);
    expect(one('trace', 'https://a.example/', 'HTTP/1.1 200 OK\ncontent-type: message/http\ncontent-length: 0', 'T-01')).toEqual(['T-01.ok']);
  });
});

describe('拡張子・Content-Type・プロトコルの名前', () => {
  it('E-13：クエリの .js（?name=lib.js）の JSON の応答を JS とみなさない', () => {
    const r = evaluate(target('https://a.example/api/export?name=lib.js', 'HTTP/2 200\ncontent-type: application/json\n\n{"a":1}'));
    expect(r.findings.filter(f => f.item === 'E-13')).toEqual([]);
  });
  it('古いフォントの型（application/font-woff）も静的リソース（sensitive=1 がなければ H-12① にしない）', () => {
    const r = evaluate(target('https://a.example/fonts/f', `HTTP/2 200\ncontent-type: application/font-woff\nset-cookie: SESSIONID=${'a1B2'.repeat(8)}; Secure; HttpOnly`));
    expect(r.findings.filter(f => f.item === 'H-12').map(f => f.ruleId)).not.toContain('H-12.1');
  });
  it('H-16①：Via の S-HTTP は製品の版ではない', () => {
    expect(ids(target('https://a.example/', HTML + 'via: S-HTTP/1.3 proxy')).filter(i => i.startsWith('H-16'))).toEqual(['H-16.ok']);
  });
  it('T-09：旧バージョンのプローブがないときは、手元の OpenSSL のせいにしない', () => {
    const r = evaluate('#TARGET url=https://www.example.com/ label=tls\n#TLSPROBE v=tls1_2 ok=1\n#TLSPROBE v=tls1_3 ok=1\n');
    expect(r.findings.find(f => f.ruleId === 'T-09.na')?.evidence).toContain('#TLSPROBE がない');
  });
});

describe('転送・304・5xx の応答で合格にしない', () => {
  const one = (label: string, url: string, head: string, item: string) => itemIds(`#TARGET url=${url} label=${label}\n${head}\n\n`, item);
  it('E-03・E-13①：プローブが転送された（apex から www へ）なら、取得できなかったとして合格にしない', () => {
    const r = evaluate(['#TARGET url=https://example.com/ label=probes',
      ...['/.git/HEAD', '/.env', '/backup.zip', '/app.js.map'].map(p => `#PROBE path=${p} head= code=301 size=0 ct=text/html`), ''].join('\n'));
    const e03 = r.findings.filter(f => f.item === 'E-03'); const e13 = r.findings.filter(f => f.item === 'E-13');
    expect(e03.map(f => f.ruleId)).toEqual(['E-03.na']); expect(e03[0].evidence).toContain('転送された');
    expect(e13.map(f => f.ruleId)).toEqual(['E-13.na']);
  });
  it('A-01②：転送先のない 304 は、ログイン画面への転送ではない', () => {
    expect(one('unauth-me', 'https://a.example/api/me', 'HTTP/2 304\netag: "x"', 'A-01')).toEqual(['A-01.na']);
    expect(one('unauth-me', 'https://a.example/api/me', 'HTTP/2 302\nlocation: /login', 'A-01')).toEqual(['A-01.2']);
    expect(evaluate('#TARGET url=https://a.example/api/me label=unauth-me\nHTTP/2 302\nlocation: /login\n\n').findings.find(f => f.ruleId === 'A-01.2')?.evidence).toContain('/login');
  });
  it('E-05：304 は公開していないとは言えない', () => {
    expect(one('t', 'https://a.example/actuator/env', 'HTTP/2 304', 'E-05')).toEqual(['E-05.na']);
  });
  it('E-02：転送の応答の本文（nginx の 301 の画面）で「一覧表示なし」にしない', () => {
    expect(one('t', 'https://a.example/images', 'HTTP/1.1 301 Moved Permanently\ncontent-type: text/html\nlocation: https://a.example/images/\n\n<html><title>301 Moved Permanently</title></html>', 'E-02')).toEqual([]);
  });
  it('E-04：robots.txt の 5xx は na', () => {
    expect(one('t', 'https://a.example/robots.txt', 'HTTP/2 503\ncontent-type: text/html', 'E-04')).toEqual(['E-04.na']);
  });
  it('E-06・E-13②：2xx でない応答（404 の画面・ログインへの転送）は、反映・参照がないことを示さない', () => {
    expect(one('t', 'https://a.example/api?callback=cb', 'HTTP/2 404\ncontent-type: text/html\n\n<h1>Not found</h1>', 'E-06')).toEqual([]);
    expect(one('t', 'https://a.example/static/app.js', 'HTTP/2 404\ncontent-type: text/html\n\n<h1>Not found</h1>', 'E-13')).toEqual([]);
    expect(one('t', 'https://a.example/static/app.js', 'HTTP/2 302\nlocation: /login', 'E-13')).toEqual([]);
    expect(one('t', 'https://a.example/static/app.js', 'HTTP/2 200\ncontent-type: text/javascript\n\nconsole.log(1)', 'E-13')).toEqual(['E-13.ok']);
  });
  it('A-09③：空の Content-Security-Policy は CSP なし', () => {
    expect(one('t', 'https://a.example/api/me', 'HTTP/2 200\ncontent-type: application/json\nx-content-type-options: nosniff\ncontent-security-policy: \n\n{"a":1}', 'A-09')).toEqual(['A-09.3']);
  });
  it('A-01・R-05：ラベルが当てはまるターゲットに応答がなければ na（適用外にしない）', () => {
    expect(one('unauth-me', 'https://a.example/api/me', 'HTTP/1.1 200 Connection established', 'A-01')).toEqual(['A-01.na']);
    expect(one('cors-preflight', 'https://a.example/api', 'HTTP/1.1 200 Connection established', 'R-05')).toEqual(['R-05.na']);
  });
});

describe('CORS のカバレッジと Cookie の二重の指摘', () => {
  it('R-01・R-02：cors-evil と cors-null を採取していれば、互いのターゲットを入力不足に数えない', () => {
    const v = (label: string, origin: string) => [`#TARGET url=https://a.example/api label=${label}`, '* Connected to a.example (192.0.2.1) port 443', '> GET /api HTTP/2',
      `> Origin: ${origin}`, '>', '< HTTP/2 200', '< content-type: application/json', '<', ''];
    const input = [...v('cors-evil', 'https://evil.example'), ...v('cors-null', 'null')].join('\n');
    const { findings } = evaluate(input);
    const cov = coverage(findings, IMPLEMENTED);
    for (const id of ['R-01', 'R-02']) expect(cov.find(c => c.item === id)).toMatchObject({ status: 'evaluated', reasons: [] });
  });
  it('R-01：送った Origin の見えない -i の cors-partial は R-03 に任せる（ACAO がないことで合格にしない）', () => {
    expect(itemIds('#TARGET url=https://a.example/api label=cors-partial\nHTTP/2 200\ncontent-type: application/json\n\n', 'R-01')).toEqual([]);
  });
  it('C-01・C-10：http から -L で https に転送したとき、http のホップの同じ Cookie を両方で指摘しない', () => {
    const sid = `sessionid=${'0123456789abcdef'.repeat(2)}; path=/; httponly; samesite=lax`;
    const r = evaluate(['#TARGET url=http://a.example/ label=t', 'HTTP/1.1 301 Moved Permanently', 'location: https://a.example/', `set-cookie: ${sid}`, '',
      'HTTP/2 200', 'content-type: text/html', ''].join('\n'));
    const fails = r.findings.filter(f => f.status === 'fail' && /^C-(?:01|10)/.test(f.ruleId)).map(f => f.ruleId);
    expect(fails).toEqual(['C-01.1']);
    expect(r.findings.find(f => f.ruleId === 'C-10.1')?.dedupedBy).toBe('C-01.1');
  });
  it('C-10：分割した Cookie の印（chunks-2）は中身と別に数えない', () => {
    const r = evaluate(target('http://a.example/', `HTTP/1.1 200 OK\ncontent-type: text/html\nset-cookie: .AspNetCore.Cookies=chunks-2; path=/\nset-cookie: .AspNetCore.CookiesC1=${'a'.repeat(40)}; path=/\nset-cookie: .AspNetCore.CookiesC2=${'b'.repeat(40)}; path=/`));
    expect(r.findings.filter(f => f.item === 'C-10' && f.status === 'fail')).toHaveLength(2);
  });
});

describe('転送・304・5xx・ブラウザが拒否する Cookie', () => {
  const one = (label: string, url: string, head: string, item: string) => itemIds(`#TARGET url=${url} label=${label}\n${head}\n\n`, item);
  it('R-01〜R-04：ACAO のない転送の応答（ログインへの 302）は、許可外の Origin を拒否したとしない', () => {
    const v = (label: string, origin: string) => evaluate([`#TARGET url=https://a.example/api/me label=${label}`, '* Connected to a.example (192.0.2.1) port 443', '> GET /api/me HTTP/2',
      `> Origin: ${origin}`, '>', '< HTTP/2 302', '< location: https://a.example/login', '<', ''].join('\n')).findings;
    expect(v('cors-reflect', 'https://evil.example').filter(f => /^R-0[14]/.test(f.ruleId)).map(f => f.ruleId).sort()).toEqual(['R-01.na', 'R-04.na']);
    expect(v('cors-null', 'null').filter(f => f.item === 'R-02').map(f => f.ruleId)).toEqual(['R-02.na']);
    expect(v('cors-partial', 'https://a.example.evil.net').filter(f => f.item === 'R-03').map(f => f.ruleId)).toEqual(['R-03.na']);
  });
  it('E-04：304 は適用外（転送とみなさない）。security.txt の 5xx は na', () => {
    expect(one('t', 'https://a.example/robots.txt', 'HTTP/2 304', 'E-04')).toEqual([]);
    expect(one('t', 'https://a.example/.well-known/security.txt', 'HTTP/2 304', 'E-04')).toEqual([]);
    expect(one('t', 'https://a.example/.well-known/security.txt', 'HTTP/2 503\ncontent-type: text/html', 'E-04')).toEqual(['E-04.na']);
  });
  it('Secure のない __Host- の Cookie は C-06②（ブラウザが拒否する）、SameSite=None の Cookie は C-01 で数え、二重に指摘しない', () => {
    const fails = (cookie: string) => evaluate(target('https://a.example/', `HTTP/2 200\ncontent-type: text/html\nset-cookie: ${cookie}`)).findings
      .filter(f => f.status === 'fail' && /^C-0[136]/.test(f.ruleId)).map(f => f.ruleId).sort();
    expect(fails(`__Host-sid=${'0123456789abcdef'.repeat(2)}; Path=/; HttpOnly; SameSite=Lax`)).toEqual(['C-06.2']);
    expect(fails(`sid=${'0123456789abcdef'.repeat(2)}; Path=/; HttpOnly; SameSite=None`)).toEqual(['C-01.1', 'C-06.1']);
  });
  it('A-09③：API の応答の Report-Only だけの CSP は、H-03② と二重に指摘しない', () => {
    const r = evaluate(target('https://a.example/api/me', "HTTP/2 200\ncontent-type: application/json\nx-content-type-options: nosniff\ncontent-security-policy-report-only: default-src 'none'\n\n{\"a\":1}"));
    expect(r.findings.filter(f => f.status === 'fail' && /^(?:H-03|A-09)/.test(f.ruleId)).map(f => f.ruleId)).toEqual(['A-09.3']);
  });
  it('C-10：http のホップの分割の印は、https のホップの中身があれば数えない', () => {
    const r = evaluate(['#TARGET url=http://a.example/ label=t', 'HTTP/1.1 301 Moved Permanently', 'location: https://a.example/', 'set-cookie: .AspNetCore.Cookies=chunks-2; path=/', '',
      'HTTP/2 200', 'content-type: text/html', `set-cookie: .AspNetCore.CookiesC1=${'a'.repeat(40)}; path=/; secure; httponly`, ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'C-10' && f.status === 'fail')).toEqual([]);
  });
});

describe('二重の指摘の除去のたどりと、自サイトの Origin の R-04', () => {
  it('数えない指摘を keep にしない（C-10① → C-01① → C-06② と、数える指摘までたどる）', () => {
    const r = evaluate(['#TARGET url=http://a.example/ label=t', 'HTTP/1.1 301 Moved Permanently', 'location: https://a.example/',
      `set-cookie: __Host-sid=${'0123456789abcdef'.repeat(2)}; path=/; httponly; samesite=lax`, '', 'HTTP/2 200', 'content-type: text/html', ''].join('\n'));
    const by = (id: string) => r.findings.find(f => f.ruleId === id)?.dedupedBy;
    expect([by('C-10.1'), by('C-01.1')]).toEqual(['C-06.2', 'C-06.2']);
    expect(r.findings.find(f => f.ruleId === 'C-10.1')?.recommendation).toContain('C-06.2 として数える');
  });
  it('R-04：自サイトの Origin を送った応答の ACAO のなさは合格にしない', () => {
    const r = evaluate(['#TARGET url=https://a.example/api/me label=t', '* Connected to a.example (192.0.2.1) port 443', '> POST /api/me HTTP/2', '> Origin: https://a.example',
      '>', '< HTTP/2 200', '< content-type: application/json', '<', ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'R-04').map(f => f.ruleId)).toEqual(['R-04.na']);
  });
});

describe('第74回：同じサイトへの転送・プローブの 5xx・転送の応答・二重の指摘', () => {
  it('E-05：apex から www の同じパスへの転送は、転送先の応答で判定する（転送の 301 で合格にしない）', () => {
    const redirect = ['#TARGET url=https://example.com/actuator/env label=act', 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/actuator/env', ''];
    expect(evaluate([...redirect, 'HTTP/1.1 200 OK', 'content-type: application/json', '', '{"activeProfiles":["prod"]}', ''].join('\n')).ids('act').filter(i => i.startsWith('E-05'))).toEqual(['E-05.1']);
    expect(evaluate(redirect.join('\n')).ids('act').filter(i => i.startsWith('E-05'))).toEqual(['E-05.na']);
  });
  it('A-01：apex から www の同じパスへの転送のあとの 401・200 で判定する', () => {
    const api = (tail: string[]) => evaluate(['#TARGET url=https://example.com/api/me label=unauth-api', 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/api/me', '', ...tail, ''].join('\n'))
      .ids('unauth-api').filter(i => i.startsWith('A-01'));
    expect(api(['HTTP/1.1 401 Unauthorized', 'content-type: application/json', '', '{"error":"unauthorized"}'])).toEqual(['A-01.ok']);
    expect(api(['HTTP/1.1 200 OK', 'content-type: application/json', '', '{"id":1,"email":"alice@example.com"}'])).toEqual(['A-01.1']);
  });
  it('E-03・E-13①：プローブのサーバのエラー（5xx）は、取得できなかったと合格にしない', () => {
    const r = evaluate(['#TARGET url=https://www.example.com/ label=probes', ...['/.git/HEAD', '/.env', '/app.js.map'].map(p => `#PROBE path=${p} head= code=503 size=0 ct=text/html`), ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'E-03' || f.item === 'E-13').map(f => f.ruleId).sort()).toEqual(['E-03.na', 'E-13.na']);
  });
  it('H-11：Location のある 3xx は判定しない。H-12：ステータスが分からない応答は「キャッシュされない応答」としない', () => {
    expect(ids(target('https://a.example/mypage', 'HTTP/2 302\nlocation: https://a.example/mypage/\ncontent-type: text/html\ncontent-length: 0', 'sensitive=1')).filter(i => i.startsWith('H-11'))).toEqual(['H-11.na']);
    const r = evaluate(target('https://a.example/mypage', '{"content-type":["text/html; charset=utf-8"]}', 'sensitive=1'));
    expect(r.findings.find(f => f.item === 'H-12')?.evidence).toBe('ステータスが分からない（HTTP 0）');
  });
  it('Domain を付けた __Host- の Cookie は C-06② だけ、http の Secure のない SameSite=None の Cookie は C-10 だけで数える', () => {
    const fails = (url: string, cookie: string) => evaluate(target(url, `HTTP/2 200\ncontent-type: text/html\nset-cookie: ${cookie}`)).findings
      .filter(f => f.status === 'fail' && /^C-(?:0[346]|10)/.test(f.ruleId)).map(f => f.ruleId).sort();
    expect(fails('https://www.example.com/', `__Host-sid=${'0123456789abcdef'.repeat(2)}; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com`)).toEqual(['C-06.2']);
    expect(fails('http://intra.example.com/', `sid=${'0123456789abcdef'.repeat(2)}; Path=/; HttpOnly; SameSite=None`)).toEqual(['C-10.1']);
  });
});

describe('第75回：第74回の二重の指摘の組・転送のたどり方の退行', () => {
  const cors = (label: string, extra: string[]) => evaluate([`#TARGET url=https://api.example.com/v1/me label=${label}`, '* Connected to api.example.com (192.0.2.20) port 443',
    `> ${label === 'cors-preflight' ? 'OPTIONS' : 'GET'} /v1/me HTTP/2`, '> Origin: https://evil.example', '> Cookie: session=abc', '>', `< HTTP/2 ${label === 'cors-preflight' ? 204 : 200}`,
    '< access-control-allow-origin: https://evil.example', '< access-control-allow-credentials: true', ...extra.map(h => `< ${h}`), '<', ''].join('\n')).findings
    .filter(f => /^R-0[145]/.test(f.ruleId) && f.status === 'fail').map(f => f.ruleId).sort();
  it('R-05① と R-01・R-04 の組：プリフライトの応答は重要度の高いほう、普通の応答は R-01（Allow-Methods はブラウザが使わない）で数える', () => {
    expect(cors('cors-reflect', ['access-control-allow-methods: GET, POST, PUT, DELETE'])).toEqual(['R-01.1']);
    expect(cors('cors-preflight', ['access-control-allow-methods: GET, POST'])).toEqual(['R-01.1']);
    expect(cors('cors-preflight', ['access-control-allow-methods: GET, POST, PUT, DELETE'])).toEqual(['R-01.1']);
  });
  it('C-06② と C-04 の組は __Host- だけ（__Secure- は Domain を付けてよい）', () => {
    const r = evaluate(target('https://www.example.com/mypage', `HTTP/2 200\ncontent-type: text/html\nset-cookie: __Secure-sessionid=${'0123456789abcdef'.repeat(2)}; Path=/; HttpOnly; SameSite=Lax; Domain=example.com`));
    expect(r.findings.find(f => f.ruleId === 'C-04.1')?.status).toBe('fail');
  });
  it('A-08：POST を GET に変える転送（301）のあとの 200 は、送った本文を処理した応答としない', () => {
    const r = evaluate(['#TARGET url=https://example.com/api/items label=ctype', 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/api/items', '',
      'HTTP/1.1 200 OK', 'content-type: application/json', '', '{"ok":true}', ''].join('\n'));
    expect(r.ids('ctype').filter(i => i.startsWith('A-08'))).toEqual(['A-08.na']);
  });
  it('C-12①：mypage の同じページへの転送もたどる（転送の 301 を「ログインできていない」にしない）', () => {
    const page = (label: string) => [`#TARGET url=https://example.com/mypage label=${label}`, 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/mypage', '',
      'HTTP/1.1 200 OK', 'content-type: text/html', '', '<p>alice@example.com</p>', ''];
    const r = evaluate([...page('mypage'), '#TARGET url=https://www.example.com/logout label=logout', 'HTTP/1.1 302 Found', 'location: /login', 'set-cookie: sessionid=; Max-Age=0; Path=/', '',
      ...page('after-logout')].join('\n'));
    expect(r.findings.filter(f => f.item === 'C-12').map(f => f.ruleId)).toContain('C-12.1');
  });
  it('E-03・E-13①：プローブのレート制限（429）も、取得できなかったと合格にしない', () => {
    const r = evaluate(['#TARGET url=https://www.example.com/ label=probes', ...['/.git/HEAD', '/.env', '/app.js.map'].map(p => `#PROBE path=${p} head= code=429 size=0 ct=text/html`), ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'E-03' || f.item === 'E-13').map(f => f.ruleId).sort()).toEqual(['E-03.na', 'E-13.na']);
  });
});

describe('第76回：プリフライトの R-02・R-03、レート制限（429）、mypage の転送', () => {
  const pre = (origin: string, acac: boolean) => evaluate(['#TARGET url=https://www.example.com/v1/me label=cors-preflight', '* Connected to www.example.com (192.0.2.20) port 443',
    '> OPTIONS /v1/me HTTP/2', `> Origin: ${origin}`, '>', '< HTTP/2 204', `< access-control-allow-origin: ${origin}`, ...(acac ? ['< access-control-allow-credentials: true'] : []),
    '< access-control-allow-methods: GET, PUT, DELETE', '<', ''].join('\n')).findings.filter(f => /^R-0[1-5]/.test(f.ruleId) && f.status === 'fail').map(f => f.ruleId).sort();
  it('プリフライトの R-02・R-03 と R-05① も、重要度の高いほうで数える', () => {
    expect(pre('https://www.example.com.evil.net', true)).toEqual(['R-03.1']);
    expect(pre('https://www.example.com.evil.net', false)).toEqual(['R-05.1']);
    expect(pre('null', true)).toEqual(['R-02.1']);
  });
  it('レート制限（429）は、合格にも指摘にもしない（E-05・A-08・T-04・T-01・E-04）', () => {
    const one = (url: string, label: string, item: string) => evaluate(`#TARGET url=${url} label=${label}\nHTTP/1.1 429 Too Many Requests\ncontent-type: text/plain\n\nslow down\n`)
      .ids(label).filter(i => i.startsWith(item));
    expect([one('https://www.example.com/actuator/env', 't', 'E-05'), one('https://www.example.com/api/items', 'ctype', 'A-08'), one('http://www.example.com/', 'http', 'T-04'),
      one('https://www.example.com/', 'trace', 'T-01'), one('https://www.example.com/robots.txt', 't', 'E-04'), one('https://www.example.com/.well-known/security.txt', 't', 'E-04')])
      .toEqual([['E-05.na'], ['A-08.na'], ['T-04.na'], ['T-01.na'], ['E-04.na'], ['E-04.na']]);
  });
  it('C-12①：mypage の同じページへの転送を採取していなければ、ログインできていたかが分からないので na', () => {
    const r = evaluate(['#TARGET url=https://example.com/mypage label=mypage', 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/mypage', '',
      '#TARGET url=https://www.example.com/logout label=logout', 'HTTP/1.1 302 Found', 'location: /login', 'set-cookie: sessionid=; Max-Age=0; Path=/', '',
      '#TARGET url=https://www.example.com/mypage label=after-logout', 'HTTP/1.1 401 Unauthorized', 'content-type: text/html', '', '<p>login</p>', ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toContain('C-12.na');
  });
});

describe('第77回：ログアウトの同じページへの転送・CORS と T- の 5xx・429・TRACE の転送', () => {
  const page = (label: string, status = 'HTTP/1.1 200 OK') => [`#TARGET url=https://www.example.com/mypage label=${label}`, status, 'content-type: text/html', '', '<p>alice@example.com</p>', ''];
  it('ログアウトの同じページへの転送は、たどった先で「ログアウトできていない」かを見る（転送の 301 をログアウトの成功としない）', () => {
    const logout = (tail: string[]) => evaluate([...page('mypage'), '#TARGET url=https://example.com/logout label=logout', 'HTTP/1.1 301 Moved Permanently', 'location: https://www.example.com/logout', '',
      ...tail, ...page('after-logout')].join('\n')).findings.filter(f => ['C-12', 'H-15'].includes(f.item)).map(f => f.ruleId).sort();
    expect(logout(['HTTP/1.1 405 Method Not Allowed', 'content-type: text/html', '', '<p>no</p>', ''])).toEqual(['C-12.na', 'C-12.na', 'H-15.na']);
    expect(logout([])).toEqual(['C-12.na', 'C-12.na', 'H-15.na']);   // 転送先を採取していない
  });
  it('CORS の R-01〜R-04：ACAO のない 5xx・429 は、許可外の Origin を断ったとしない', () => {
    for (const st of ['HTTP/2 503', 'HTTP/2 429']) {
      const r = evaluate(['#TARGET url=https://api.example.com/v1/me label=cors-reflect', '* Connected to api.example.com (192.0.2.20) port 443', '> GET /v1/me HTTP/2', '> Origin: https://evil.example', '>', `< ${st}`, '<', ''].join('\n'));
      expect(r.findings.filter(f => /^R-0[14]/.test(f.ruleId)).map(f => f.ruleId).sort(), st).toEqual(['R-01.na', 'R-04.na']);
    }
  });
  it('T-01（TRACE）の転送、T-07・T-08 の 5xx・429 は合格にしない', () => {
    const one = (label: string, head: string, item: string) => evaluate(`#TARGET url=https://www.example.com/ label=${label}\n${head}\n\n`).ids(label).filter(i => i.startsWith(item));
    expect([one('trace', 'HTTP/1.1 301 Moved Permanently\nlocation: https://www.example.com/', 'T-01'), one('host-inj', 'HTTP/1.1 429 Too Many Requests', 'T-07'), one('crlf', 'HTTP/1.1 503 Service Unavailable', 'T-08')])
      .toEqual([['T-01.na'], ['T-07.na'], ['T-08.na']]);
  });
});
