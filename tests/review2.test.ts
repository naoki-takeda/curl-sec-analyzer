// 2回目のレビュー（新鮮な目でのレビュー）で見つかった不具合の再現テスト
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { finalResponse } from '../src/parser/target';
import { devCommentWord } from '../src/rules/html';
import { evaluate } from './helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n`;
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';

describe('高', () => {
  it('E-09②：閉じのない <!-- が続く本文でも線形時間で終わる（以前は64KBで数分）', () => {
    const hostile = '<!--TODO '.repeat(Math.ceil(65536 / 9)).slice(0, 65536);
    const start = Date.now();
    expect(devCommentWord(hostile)).toBeUndefined();          // 閉じたコメントがない
    expect(Date.now() - start).toBeLessThan(500);
    expect(devCommentWord('<p>a</p><!-- x --><b>debug</b><!-- FIXME later -->')).toBe('FIXME');
  });
  it('同じラベルを付け直した http#2 も、http と同じ項目（T-04・C-10）で判定する', () => {
    const r = evaluate(t('http', 'http://www.example.com/', 'HTTP/1.1 301 Moved Permanently\nlocation: https://www.example.com/')
      + t('http', 'http://example.com/', `HTTP/1.1 200 OK\ncontent-type: text/html\nset-cookie: sid=${'a1'.repeat(16)}; HttpOnly`));
    expect(r.ids('http#2')).toEqual(expect.arrayContaining(['T-04.1', 'C-10.1']));
    expect(r.ids('http#2').some(id => /^H-0[368]\./.test(id))).toBe(false);   // 一般ページ用のヘッダの項目は判定しない
  });
  it('本文は1行が長くても64KBで切る', () => {
    const body = 'x'.repeat(2 * 1024 * 1024);
    const r = finalResponse(parseInput(t('top', 'https://a.example/', `${HTML}\n\n${body}`)).targets[0])!;
    expect(r.body!.length).toBeLessThanOrEqual(64 * 1024);
  });
});

describe('中：TLS（T-10・T-11）', () => {
  const tls = (lines: string) => evaluate(`#TARGET url=https://www.example.com/ label=tls\n${lines.trim()}\n`).findings
    .filter(f => f.target === 'www.example.com').map(f => f.ruleId);
  it('ハンドシェイクに失敗した出力は合格にせず na', () => {
    const ids = tls(`CONNECTED(00000003)
4047D3B5E87F0000:error:0A000126:SSL routines::unexpected eof while reading
no peer certificate available
New, (NONE), Cipher is (NONE)
Verify return code: 0 (ok)`);
    expect(ids).toEqual(expect.arrayContaining(['T-10.na', 'T-11.na']));
    expect(ids).not.toContain('T-10.ok');
    expect(ids).not.toContain('T-11.ok');
  });
  it('OpenSSL 1.1・LibreSSL の「Server public key is 1024 bit」も T-10②', () => {
    expect(tls(`CONNECTED(00000003)
Certificate chain
 0 s:/CN=www.example.com
   i:/CN=Example Intermediate
Server public key is 1024 bit
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Verify return code: 0 (ok)`)).toContain('T-10.2');
  });
  it('SHA-1 の署名は、最後の証明書でも自己署名でなければ T-10②。自己署名（ルート）は対象外', () => {
    const chain = (rootSig: string, interSig: string, withRoot: boolean) => `Certificate chain
 0 s:CN = www.example.com
   i:CN = Example Intermediate
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
 1 s:CN = Example Intermediate
   i:CN = Example Root
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: ${interSig}
${withRoot ? ` 2 s:CN = Example Root\n   i:CN = Example Root\n   a:PKEY: rsaEncryption, 4096 (bit); sigalg: ${rootSig}` : ''}`;
    expect(tls(chain('', 'RSA-SHA1', false))).toContain('T-10.2');
    expect(tls(chain('RSA-SHA1', 'RSA-SHA256', true))).not.toContain('T-10.2');
  });
});

describe('中：判定の誤り', () => {
  it('C-07②：同じアカウントの JWT（クレームが共通）は、署名の部分で比べる', () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const jwt = (i: number) => {
      const hp = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '42', email: 'a@example.com', name: 'Taro', roles: ['user'], iat: 1700000000 + i, exp: 1700003600 + i })}`;
      return `${hp}.${createHmac('sha256', `k${i}`).update(hp).digest('base64url')}`;
    };
    const input = [1, 2, 3].map(i => t(`session-sample-${i}`, 'https://a.example/login', `${HTML}\nset-cookie: token=${jwt(i)}; Secure; HttpOnly; SameSite=Lax`)).join('');
    const c07 = evaluate(input).findings.filter(f => f.item === 'C-07' && f.target === 'session-sample-*').map(f => f.ruleId);
    expect(c07).toEqual(['C-07.ok']);
  });
  it('JSON を text/html で返す件は A-09① だけで数え（H-13② は数えない）、kind=api でも A-09①', () => {
    const r = evaluate(t('t', 'https://a.example/api', 'HTTP/2 200\ncontent-type: text/html\n\n{"id":1}'));
    expect(r.ids('t')).toContain('A-09.1');
    expect(r.findings.find(f => f.ruleId === 'H-13.2' && f.target === 't')?.status).toBe('na');
    expect(evaluate(t('t', 'https://a.example/api', 'HTTP/2 200\ncontent-type: text/html; charset=utf-8\n\n{"id":1}', 'kind=api')).ids('t')).toContain('A-09.1');
  });
  it('H-12：Cookie を送って取得した静的リソースは機密応答とみなさない（sensitive=1 の明示は別）', () => {
    const js = (extra = '') => evaluate(`#TARGET url=https://a.example/static/app.3f9a.js label=t ${extra}\n* Connected to a.example port 443\n> GET /static/app.3f9a.js HTTP/2\n> Cookie: sid=abc\n>\n< HTTP/2 200\n< content-type: application/javascript\n< cache-control: public, max-age=31536000, immutable\n<\n`).ids('t');
    expect(js()).toContain('H-12.ok');
    expect(js('sensitive=1')).toContain('H-12.1');
  });
  it('E-01：普通の JS や Laravel の既定レイアウトでは指摘せず、接続文字列やエラーページは指摘する', () => {
    const e01 = (body: string) => evaluate(t('t', 'https://a.example/', `${HTML}\n\n${body}`)).ids('t').filter(id => id.startsWith('E-01'));
    expect(e01('<script>var password = document.getElementById("pw").value;</script>')).toEqual(['E-01.ok']);
    expect(e01('<script>window.Laravel = {"csrfToken":"x"};</script>')).toEqual(['E-01.ok']);
    expect(e01('Server=db01;Database=app;User ID=sa;Password=P@ssw0rd;')).toContain('E-01.1');
    expect(e01('<h1>Whoops, looks like something went wrong.</h1>')).toContain('E-01.3');
  });
  it('E-09①・A-07①：日本語の文言は秘密情報とみなさない。英数字の値は指摘する', () => {
    const e09 = (body: string) => evaluate(t('t', 'https://a.example/', `${HTML}\n\n${body}`)).ids('t');
    expect(e09('<script>var m = {"password":"パスワードは8文字以上で入力してください"};</script>')).not.toContain('E-09.1');
    expect(e09('<script>var c = {"api_key":"sk_live_abcdefghijkl1234"};</script>')).toContain('E-09.1');
    const a07 = (json: string) => evaluate(t('t', 'https://a.example/api', `HTTP/2 200\ncontent-type: application/json\n\n${json}`)).ids('t');
    expect(a07('{"login":{"password":"パスワード","hint":"Enter your password"}}')).not.toContain('A-07.1');
    expect(a07('{"user":{"id":1,"password_hash":"$2b$12$abcdefghijklmnopqrstuv"}}')).toContain('A-07.1');
    expect(a07('{"user":{"id":1,"password":null}}')).not.toContain('A-07.1');
  });
});
