import { describe, expect, it } from 'vitest';
import { harTargets, importHar, normalizeVersion } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { decodeJwt, jsonKeys } from '../../src/rules/api';
import { evaluate, fixture } from '../helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n`;
const jwt = (header: object, payload: object) => [header, payload].map(o => Buffer.from(JSON.stringify(o)).toString('base64url')).join('.') + '.sig';

describe('HAR の取り込み', () => {
  const imp = importHar(fixture('har_chrome.har'));
  it('リダイレクトをチェーンにまとめ、ラベルの候補を付ける', () => {
    expect(imp.chains.map(c => [c.method, new URL(c.url).pathname, c.hops, c.suggested])).toEqual([
      ['GET', '/login', 1, 'pre-login'], ['POST', '/login', 2, 'login'], ['GET', '/g/collect', 1, 'har-3'], ['GET', '/api/me', 1, 'har-4'], ['GET', '/logout', 1, 'logout']]);
    expect(imp.hosts).toEqual(['www.example.com', 'www.google-analytics.com']);
    expect(imp.sanitized).toBe(false);
  });
  it('パスワード（postData）を残さず、疑似ヘッダを除き、バージョンをそろえる', () => {
    const { targets, warnings } = harTargets(imp, new Set(['www.example.com']));
    const all = JSON.stringify(targets, (_, v) => (v instanceof Map ? [...v] : v));
    expect(all).not.toContain('SuperSecretPassw0rd');
    expect(all).not.toContain(':status');
    expect(targets[0].responses[0].httpVersion).toBe('2');
    expect(targets[0].responses[0].body).toContain('type="password"');      // base64 の本文をデコード
    expect(targets.map(t => t.meta.source)).toEqual(['har', 'har', 'har', 'har']);
    expect(warnings.map(w => w.kind)).toEqual(['har-excluded']);
    expect([normalizeVersion('HTTP/2.0'), normalizeVersion('h3'), normalizeVersion('http/1.1')]).toEqual(['2', '3', '1.1']);
  });
  it('横断ルールまで判定でき、確認用ラベルは付けられない', () => {
    const { targets } = harTargets(imp, new Set(['www.example.com']));
    const fs = runAll(targets);
    expect(fs.find(f => f.item === 'C-09' && f.target === 'pre-login/login')?.ruleId).toBe('C-09.1');
    expect(fs.some(f => f.ruleId === 'A-07.1')).toBe(true);
    imp.chains[3].label = 'cors-x';
    expect(harTargets(imp, new Set(['www.example.com'])).targets.find(x => x.url?.endsWith('/api/me'))!.label).toBe('har-4');
  });
  it('機密情報を除いたHARを検出する', () => {
    const s = importHar(fixture('har_sanitized.har'));
    expect(s.sanitized).toBe(true);
    expect(harTargets(s, new Set(['www.example.com'])).warnings.map(w => w.kind)).toContain('har-sanitized');
  });
});

describe('API（A-01〜A-03、A-07、A-08、A-10、A-11）', () => {
  it('未認証アクセス', () => {
    expect(evaluate(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 200\ncontent-type: application/json\n\n{"id":1}')).ids('unauth-me')).toContain('A-01.1');
    expect(evaluate(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 302\nlocation: /login')).ids('unauth-me')).toContain('A-01.2');
    expect(evaluate(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 401\nwww-authenticate: Bearer realm="api"')).ids('unauth-me')).toContain('A-01.ok');
    expect(evaluate(t('top', 'http://a.example/admin', 'HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm="x"')).ids('top')).toContain('A-01.3');
  });
  it('トークンの露出と JWT の中身（値は出さない）', () => {
    expect(evaluate(t('top', 'https://a.example/cb?access_token=abcdef0123456789', 'HTTP/2 200\ncontent-type: text/html')).ids('top')).toContain('A-02.1');
    const token = jwt({ alg: 'none' }, { sub: '1', email: 'a@example.com' });
    const r = evaluate(`#TARGET url=https://a.example/api/me label=top\n* Connected to a.example (192.0.2.1) port 443\n> GET /api/me HTTP/2\n> Authorization: Bearer ${token}\n>\n< HTTP/2 200\n< content-type: application/json\n<\n`);
    expect(r.ids('top')).toEqual(expect.arrayContaining(['A-03.1', 'A-03.2', 'A-03.3']));
    expect(JSON.stringify(r.findings)).not.toContain('a@example.com');
    expect(decodeJwt(token)?.header.alg).toBe('none');
  });
  it('過剰なデータ露出（キー名だけを出す）', () => {
    const ids = evaluate(t('top', 'https://a.example/api/u', 'HTTP/2 200\ncontent-type: application/json\n\n{"users":[{"id":1,"password_hash":"$2b$x","internal_note":"x"}]}')).ids('top');
    expect(ids).toEqual(expect.arrayContaining(['A-07.1', 'A-07.2']));
    expect(jsonKeys({ a: { b: [{ c: 1 }] } })).toEqual(['a', 'a.b', 'a.b[0].c']);
  });
  it('Content-Type、メソッド、旧版、エラー形式', () => {
    expect(evaluate(t('ctype', 'https://a.example/api/x', 'HTTP/2 200\ncontent-type: application/json')).ids('ctype')).toContain('A-08.1');
    expect(evaluate(t('ctype', 'https://a.example/api/x', 'HTTP/2 415')).ids('ctype')).toContain('A-08.ok');
    expect(evaluate(t('method-delete', 'https://a.example/api/x', 'HTTP/2 204')).ids('method-delete')).toContain('A-11.1');
    expect(evaluate(t('old-v1', 'https://a.example/api/v1/x', 'HTTP/2 200\ncontent-type: application/json')).ids('old-v1')).toContain('A-11.2');
    const errs = t('error-a', 'https://a.example/api/x', 'HTTP/2 404\ncontent-type: application/problem+json') + t('error-b', 'https://a.example/api/y', 'HTTP/2 500\ncontent-type: application/json');
    expect(evaluate(errs).findings.find(f => f.item === 'A-10')?.ruleId).toBe('A-10.1');
    // HTMLのエラーページと、error-* 以外（unauth-* の 401）は比べない
    const other = t('error-a', 'https://a.example/api/x', 'HTTP/2 404\ncontent-type: application/problem+json') + t('error-page', 'https://a.example/%25', 'HTTP/2 400\ncontent-type: text/html') + t('unauth-me', 'https://a.example/api/me', 'HTTP/2 401\ncontent-type: application/json');
    expect(evaluate(other).findings.find(f => f.item === 'A-10')?.ruleId).toBe('A-10.na');
  });
});

describe('C-11、R-08、R-09', () => {
  it('Partitioned、Timing-Allow-Origin、WebSocket', () => {
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html\nset-cookie: emb=1; Secure; SameSite=None')).ids('top')).toContain('C-11.1');
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html\ntiming-allow-origin: *', 'sensitive=1')).ids('top')).toContain('R-08.1');
    expect(evaluate(t('websocket', 'https://a.example/ws', 'HTTP/1.1 101 Switching Protocols\nUpgrade: websocket', 'sensitive=1')).ids('websocket')).toContain('R-09.1');
    expect(evaluate(t('websocket', 'https://a.example/ws', 'HTTP/1.1 403 Forbidden')).ids('websocket')).toContain('R-09.ok');
  });
});
