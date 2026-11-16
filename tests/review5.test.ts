// 5回目のレビュー（リポジトリ全体）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { evaluateCsp } from '../src/rules/csp';
import { evaluate } from './helpers';

const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const items = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item);

describe('証跡：HTMLのタグの属性の値を出さない', () => {
  const SECRETS = ['sk_live_abcdefghijklmnop1234', 'QWERTYUIOPASDFGHJKL0987', 'r4nd0mN0nceValue123', 'csrfValue000000000000000'];
  it('E-08：外部スクリプトの例は、判定に使う属性（src など）の値だけを出す', () => {
    const fs = items(t('top', 'https://www.example.com/', HTML,
      `<script src="https://cdn.other.example/a.js" data-api-key="${SECRETS[0]}" data-auth-token="${SECRETS[1]}" nonce="${SECRETS[2]}" async></script>`), 'E-08');
    expect(fs.map(f => f.ruleId)).toEqual(['E-08.1']);
    expect(fs[0].evidence).toContain('src="https://cdn.other.example/a.js"');
    expect(fs[0].evidence).toContain('data-api-key="…"');
    expect(fs[0].evidence).toContain(' async');
    for (const s of SECRETS) expect(fs[0].evidence).not.toContain(s);
  });
  it('E-07・E-10・E-12 の証跡にも出さない', () => {
    const body = `<img src="http://img.example/a.png" data-token="${SECRETS[1]}">`
      + `<form action="http://www.example.com/login" data-key="${SECRETS[0]}"><input type="password" name="pw"></form>`
      + `<form method="post" action="/x" data-x="${SECRETS[3]}"><input type="text" name="q"></form>`;
    const all = evaluate(t('top', 'https://www.example.com/', HTML, body, 'sensitive=1')).findings;
    const ev = JSON.stringify(all.filter(f => ['E-07', 'E-10', 'E-12'].includes(f.item) && f.status === 'fail').map(f => f.evidence));
    expect(all.map(f => f.ruleId)).toEqual(expect.arrayContaining(['E-07.2', 'E-10.1', 'E-10.2', 'E-12.1']));
    for (const s of SECRETS) expect(ev).not.toContain(s);
  });
});

describe('マスク：URL のユーザー情報', () => {
  it('ユーザー名だけに置いたトークンをマスクする', () => {
    const m = maskText('https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@git.example.com/repo');
    expect(m).not.toContain('abcdefghijklmnopqrstuvwxyz0123456789');
    expect(m).toMatch(/^https:\/\/ghp_…\(40 chars\)@git\.example\.com\/repo$/);
  });
  it('パスワードに @ を含んでも残さない', () => {
    expect(maskText('https://user:p@ss-word-secret@host.example.com/')).toBe('https://user:****@host.example.com/');
  });
  it('パス・クエリの @ には一致させない', () => {
    expect(maskText('https://www.example.com/u/@alice?mail=a@b.example')).toBe('https://www.example.com/u/@alice?mail=a@b.example');
  });
});

describe('E-01①：接続文字列・AWSのアクセスキーだけを高とする', () => {
  const e01 = (body: string) => items(t('t', 'https://www.example.com/', HTML, body), 'E-01').map(f => f.ruleId);
  it('小文字の JS の host・password の代入は①にしない', () => {
    expect(e01('<script>var host = location.host; var password = form.value;</script>')).not.toContain('E-01.1');
    expect(e01('<script>Host = x; var Password = y;</script>')).not.toContain('E-01.1');
  });
  it('base64 の途中の akia は①にしない', () => {
    expect(e01('<img src="data:image/png;base64,Q29zakiaQb3J0Zm9saW8xMjM0NTY3OA">')).not.toContain('E-01.1');
  });
  it('接続文字列とアクセスキーは①', () => {
    expect(e01('Server=db01;Database=app;User ID=sa;Password=P@ssw0rd;')).toContain('E-01.1');
    expect(e01('Host=db;Port=5432;Username=app;Password=secret;')).toContain('E-01.1');
    expect(e01('key: AKIAABCDEFGHIJKLMNOP')).toContain('E-01.1');
  });
});

describe('CSP：default-src の指摘はフォールバック先の項目に振り分ける', () => {
  const route = (p: string) => evaluateCsp(p).map(i => `${i.item}.${i.condition}`);
  it("script-src があれば default-src * は H-04② にせず、object-src がなければ H-05①", () => {
    expect(route("default-src *; script-src 'self'; base-uri 'none'")).toEqual(['H-05.1']);
    const ids = evaluate(t('top', 'https://www.example.com/', `${HTML}\ncontent-security-policy: default-src *; script-src 'self'; base-uri 'none'`)).ids('top');
    expect(ids).toContain('H-04.ok');
    expect(ids).toContain('H-05.1');
  });
  it('default-src だけなら H-04② と H-05① の両方', () => {
    expect(route('default-src *').sort()).toEqual(['H-04.2', 'H-05.1']);
  });
  it("object-src 'none' があれば default-src https: は H-04② だけ", () => {
    expect(route("default-src https:; object-src 'none'")).toEqual(['H-04.2']);
  });
});

describe('T-09・T-10：-v で合意した旧バージョン・暗号', () => {
  const v = (line: string) => `#TARGET url=https://www.example.com/ label=top\n* Connected to www.example.com (192.0.2.1) port 443\n* SSL connection using ${line}\n< HTTP/1.1 200 OK\n< content-type: text/html\n<\n`;
  const ids = (line: string) => evaluate(v(line)).findings.filter(f => f.item === 'T-09' || f.item === 'T-10').map(f => `${f.ruleId} ${f.severity}`).sort();
  it('TLS 1.1・1.0（OpenSSL の表記は TLSv1）で合意したら T-09①（高）', () => {
    expect(ids('TLSv1.1 / ECDHE-RSA-AES128-SHA')).toEqual(['T-09.1 high', 'T-09.2 info', 'T-10.3 medium']);
    expect(ids('TLSv1 / ECDHE-RSA-AES128-SHA')).toContain('T-09.1 high');
  });
  it('合意した弱い暗号は T-10①', () => {
    expect(ids('TLSv1.2 / RC4-SHA')).toContain('T-10.1 high');
  });
  it('TLS 1.2 の AEAD なら①③にしない', () => {
    expect(ids('TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256')).toEqual(['T-09.2 info', 'T-10.ok info']);
  });
});
