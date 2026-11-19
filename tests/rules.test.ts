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

// 第48回のレビュー（判定ルール）で見つかった誤検知・取り決め違反
describe('第48回：ルールの誤検知', () => {
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

// 第49回のレビュー（判定ルール）
describe('第49回：ルールの誤検知・見逃し', () => {
  const AT49 = '#META at=2026-11-01T10:00:00';
  const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/x label=t\n${AT49}\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('t');
  it('A-07①：API の検証の規則・autocomplete の値・エラーの項目の値を、パスワードの露出とみなさない（本物は今までどおり）', () => {
    for (const b of ['{"rules":{"email":"required|email","password":"required|min:8|max:64"}}', '{"autocomplete":{"password":"current-password"}}', '{"errors":{"password":"TOO_SHORT"}}']) {
      expect(api(b), b).not.toContain('A-07.1');
    }
    expect(api('{"user":{"id":1,"password":"Kirin2024secret"}}')).toContain('A-07.1');
  });
  it('H-03①：<template>・<noscript>・スクリプトの文字列の中の meta の CSP は効かない', () => {
    for (const head of ['<template><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; object-src \'none\'"></template>',
      '<script>var t=\'<meta http-equiv="Content-Security-Policy" content="default-src none">\';</script>']) {
      expect(evaluate(`#TARGET url=https://www.example.com/ label=page\n${AT49}\n${HTML}\n<head>${head}</head><body><p>x</p></body>\n`).ids('page'), head).toContain('H-03.1');
    }
  });
  it('H-01・H-02：http で採取して www へ転送した apex は、www の HSTS で判定しない', () => {
    const r = evaluate(`#TARGET url=http://example.com/ label=apex\n${AT49}\nHTTP/1.1 301 Moved\nlocation: https://www.example.com/\n\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\n\n<p>x</p>\n`).ids('apex');
    expect(r.filter(x => x.startsWith('H-01') || x.startsWith('H-02'))).toEqual(expect.arrayContaining(['H-01.na']));
    expect(r).not.toContain('H-01.ok');
    expect(r).not.toContain('H-02.ok');
  });
  it('E-10：同じ名前の属性が2つあれば、最初の値で判定する（ブラウザと同じ）', () => {
    const form = (a: string, b: string) => evaluate(`#TARGET url=https://www.example.com/login label=page\n${AT49}\n${HTML}\n<form method="post" action="${a}" action="${b}"><input type="password" name="pw"></form>\n`).ids('page');
    expect(form('https://www.example.com/session', 'http://www.example.com/session')).not.toContain('E-10.1');
    expect(form('http://www.example.com/session', 'https://www.example.com/session')).toContain('E-10.1');
  });
});

describe('第50回：E-09・A-07 の画面の部品の値、R-04・R-06・E-05', () => {
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
  it('E-09①・A-07①（束のレビュー）：秘密の語のほかの語を含む値・セレクタの形でない値・エスケープが1つの値は、秘密の値として扱う', () => {
    for (const js of ['var cfg={secret_key:"my-super-secret-key"}', 'var cfg={password:"changeme_password"}', 'var cfg={password:"Pass[1]Secret!x"}', 'var cfg={password:"S3cr3t\\u00e9Value99"}', 'var cfg={password:"/Ab3xY9qLmZ81PwQr"}'])
      expect(e09(js), js).toEqual(['E-09.1']);
    const api = evaluate('#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n{"user":{"password":"admin_pass"}}\n').ids('api');
    expect(api).toContain('A-07.1');
  });
  it('（2回目の束のレビュー）E-09：語として読める翻訳キー・パスは除き、A-07：ユーザー情報のある URL・合言葉は除かない', () => {
    for (const js of ['var s={password:"auth.passwordLabel"}', 'var s={password:"user.newPassword"}', 'var s={password:"/Account/ForgotPassword"}', 'var s={password:"/users/password/new?locale=ja"}'])
      expect(e09(js), js).toEqual([]);
    const api = (body: string) => evaluate(`#TARGET url=https://www.example.com/api/me label=api sensitive=1\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`).ids('api');
    for (const b of ['{"user":{"password":"https://u:Winter2024@db.example.com/"}}', '{"user":{"password":"correct.horse.battery"}}', '{"user":{"password":"a1b2c3d4e5.f6a7b8c9d0e1f2"}}'])
      expect(api(b), b).toContain('A-07.1');
  });
});

describe('第51回：文書の仮の値・公開のクライアントのキー・H-02③ の主語・T-09 の重複', () => {
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
    // 管理用・マスターのキーも apiKey という名前なので、Algolia・Typesense の apiKey は除かない（束のレビュー）
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
  it('（束のレビュー）example・sample を含む本物のパスワードは仮の値とみなさない', () => {
    expect(ids(page('var c={password:"my_example_password"}')).filter(i => i === 'E-09.1')).toEqual(['E-09.1']);
  });
});
