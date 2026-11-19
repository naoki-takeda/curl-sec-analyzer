import { describe, expect, it } from 'vitest';
import { allowedItems } from '../../src/engine/labels';
import { applySuppressions, parseSuppressions } from '../../src/engine/suppress';
import { predictable } from '../../src/rules/cross';
import { estimateBits } from '../../src/rules/cookies';
import { evaluate } from '../helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n`;
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8\n';

describe('ラベル対応表', () => {
  it('前方一致・完全一致・既定（一般）を引き分け、条件単位の指定を扱う', () => {
    expect(allowedItems('cors-null').allowsItem('R-02')).toBe(true);
    expect(allowedItems('cors-null').allowsItem('H-01')).toBe(false);
    expect(allowedItems('top').allowsItem('H-01')).toBe(true);
    expect(allowedItems('top').allowsItem('H-15')).toBe(false);
    const general = allowedItems('top');
    expect(general.allowsItem('T-05')).toBe(true);                // T-05.2 だけ
    expect(general.allowsFinding({ item: 'T-05', condition: 1 } as never)).toBe(false);
    expect(general.allowsFinding({ item: 'T-05', condition: 2 } as never)).toBe(true);
    expect(general.allowsFinding({ item: 'T-05' } as never)).toBe(true);   // ok・na
  });
});

describe('CSP（H-04、H-05、H-07）', () => {
  const run = (csp: string) => evaluate(t('top', 'https://a.example/', HTML + `content-security-policy: ${csp}`)).ids('top');
  it("unsafe-inline・広い指定・unsafe-eval を指摘し、nonce＋strict-dynamic は合格", () => {
    expect(run("script-src 'self' 'unsafe-inline'")).toContain('H-04.1');
    expect(run('script-src https:')).toContain('H-04.2');
    expect(run("script-src 'self' 'unsafe-eval'")).toContain('H-04.3');
    expect(run("script-src 'nonce-R4nd0mN0nceValue' 'strict-dynamic' https: 'unsafe-inline'")).toContain('H-04.ok');
    expect(run("script-src 'nonce-abc' 'strict-dynamic'")).toContain('H-04.6');   // csp_evaluator：nonce が短い
    expect(run("script-src https://www.google.com")).toContain('H-04.4');          // csp_evaluator：JSONP を置くホスト
    expect(run("default-src 'self'; object-src *; base-uri 'none'")).toContain('H-05.1');   // csp_evaluator：object-src のワイルドカード
    expect(run("default-src 'self'; base-uri 'none'; scirpt-src 'self'")).toContain('H-07.4');   // csp_evaluator：不明なディレクティブ
  });
  it('object-src・base-uri と非推奨ディレクティブ', () => {
    expect(run("script-src 'self'")).toEqual(expect.arrayContaining(['H-05.1', 'H-05.2']));
    expect(run("default-src 'self'; base-uri 'none'")).toContain('H-05.ok');
    expect(run("default-src 'self'; block-all-mixed-content; report-uri /r")).toEqual(expect.arrayContaining(['H-07.1', 'H-07.2']));
  });
});

describe('ヘッダ（H-09、H-13、H-16、H-17）', () => {
  const run = (h: string) => evaluate(t('top', 'https://a.example/', HTML + h)).ids('top');
  it('Referrer-Policy の値ごとの判定', () => {
    expect(run('referrer-policy: unsafe-url')).toContain('H-09.1');
    expect(run('referrer-policy: origin')).toContain('H-09.2');
    expect(run('')).toContain('H-09.3');
    expect(run('referrer-policy: no-referrer, bogus')).toContain('H-09.ok');
  });
  it('製品・バージョン情報、デバッグ、内部ホスト、廃止ヘッダ', () => {
    expect(run('server: Apache/2.4.58')).toContain('H-16.1');
    expect(run('server: nginx')).toContain('H-16.2');
    expect(run('x-debug-token: abc')).toContain('H-16.3');
    expect(run('via: 1.1 app01.internal')).toContain('H-16.4');
    expect(run('x-xss-protection: 1; mode=block')).toContain('H-17.1');
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/2 200\n')).ids('top')).toContain('H-13.1');
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html')).ids('top')).toContain('H-13.2');
  });
});

describe('Cookie（C-04〜C-08、C-10、C-13）', () => {
  const run = (cookie: string, label = 'login', url = 'https://www.example.com/') => evaluate(t(label, url, HTML + `set-cookie: ${cookie}`)).ids(label);
  it('Domain の拡大、長い期限、プレフィックス、推測しやすいID、既定の名前', () => {
    expect(run('sid=abcdefghijklmnopqrstuvwxyz012345; Domain=.example.com; Secure; HttpOnly; SameSite=Lax')).toContain('C-04.1');
    expect(run('sid=abcdefghijklmnopqrstuvwxyz012345; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax')).toContain('C-05.1');
    expect(run('__Host-sid=abcdefghijklmnopqrstuvwxyz012345; Path=/app; Secure; HttpOnly; SameSite=Lax')).toContain('C-06.2');
    expect(run('sid=12345678; Secure; HttpOnly; SameSite=Lax')).toContain('C-07.1');
    expect(run('JSESSIONID=abcdefghijklmnopqrstuvwxyz012345; Secure; HttpOnly; SameSite=Lax')).toContain('C-08.1');
    expect(estimateBits('0123456789abcdef0123456789abcdef')).toBe(128);
  });
  it('HTTP応答でのCookie発行（C-10）と共有キャッシュ（C-13）', () => {
    expect(evaluate(t('http', 'http://www.example.com/', 'HTTP/1.1 302 Found\nLocation: https://www.example.com/\nSet-Cookie: sid=abcdefghijklmnopqrstuvwxyz012345')).ids('http')).toContain('C-10.1');
    expect(evaluate(t('top', 'https://a.example/', HTML + 'cache-control: public, max-age=60\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz012345; Secure; HttpOnly; SameSite=Lax')).ids('top')).toContain('C-13.1');
  });
});

describe('CORS（R-02〜R-07）', () => {
  const run = (label: string, h: string, extra = '') => evaluate(t(label, 'https://www.example.com/api', 'HTTP/2 200\ncontent-type: application/json\n' + h, extra)).ids(label);
  const verbose = (origin: string, h: string) => evaluate(`#TARGET url=https://www.example.com/api label=cors-x\n* Connected to www.example.com (192.0.2.1) port 443\n> GET /api HTTP/2\n> Origin: ${origin}\n>\n< HTTP/2 200\n< content-type: application/json\n${h.split('\n').map(l => `< ${l}`).join('\n')}\n<\n`).ids('cors-x');
  it('null、部分一致、ワイルドカード、Vary、Expose-Headers、プリフライト', () => {
    expect(run('cors-null', 'access-control-allow-origin: null\naccess-control-allow-credentials: true')).toContain('R-02.1');
    expect(verbose('https://www.example.com.evil.net', 'access-control-allow-origin: https://www.example.com.evil.net')).toContain('R-03.2');
    expect(verbose('https://www.example.com.evil.net', 'access-control-allow-origin: https://www.example.com.evil.net')).not.toContain('R-01.2');
    expect(run('cors-star', 'access-control-allow-origin: *', 'sensitive=1')).toContain('R-04.1');
    expect(run('cors-star', 'access-control-allow-origin: *')).toContain('R-04.3');
    // 第31回から、送った Origin の分からない -i の固定の ACAO は na（Origin によって変わる値かが分からない）。-v で Origin を送ったものは①
    expect(run('cors-x', 'access-control-allow-origin: https://partner.example')).toContain('R-06.na');
    expect(run('cors-x', 'access-control-allow-origin: https://partner.example\nvary: Origin\naccess-control-expose-headers: Authorization')).toEqual(expect.arrayContaining(['R-06.ok', 'R-07.1']));
    expect(run('cors-pre', 'access-control-allow-origin: *\naccess-control-allow-methods: GET, DELETE\naccess-control-max-age: 86400')).toEqual(expect.arrayContaining(['R-05.1', 'R-05.2']));
  });
});

describe('T-05、T-07②、T-08、A-09', () => {
  it('リダイレクトチェーンと注入テスト', () => {
    const chain = '#TARGET url=http://a.example/ label=http\nHTTP/1.1 301 Moved\nLocation: https://a.example/x\n\nHTTP/1.1 302 Found\nLocation: http://a.example:8080/y\n\nHTTP/1.1 200 OK\ncontent-type: text/html\n';
    expect(evaluate(chain).ids('http')).toEqual(expect.arrayContaining(['T-05.1', 'T-05.2']));
    expect(evaluate(t('host-inj', 'https://a.example/', 'HTTP/1.1 302 Found\nLocation: https://evil.example/reset')).ids('host-inj')).toContain('T-07.2');
    expect(evaluate(t('crlf', 'https://a.example/', 'HTTP/1.1 302 Found\nLocation: /\nSet-Cookie: crlf=1')).ids('crlf')).toContain('T-08.1');
    expect(evaluate(t('crlf', 'https://a.example/', 'HTTP/1.1 302 Found\nLocation: /')).ids('crlf')).toContain('T-08.ok');
  });
  it('JSONを text/html で返す、APIに nosniff がない', () => {
    expect(evaluate(t('api', 'https://a.example/api', 'HTTP/2 200\ncontent-type: text/html\n\n{"a":1}')).ids('api')).toContain('A-09.1');
    expect(evaluate(t('api', 'https://a.example/api', 'HTTP/2 200\ncontent-type: application/json')).ids('api')).toEqual(expect.arrayContaining(['A-09.2', 'A-09.3']));
  });
});

describe('横断ルール', () => {
  it('セッションIDの比較（C-07②）', () => {
    expect(predictable(['abc123def456ghi1', 'abc123def456ghi2'])).toContain('共通');
    expect(predictable(['1000', '1001'])).toBeDefined();
    expect(predictable(['8f3c2a91d0b74e6f', '1c55d3e9b2f7a40b'])).toBeUndefined();
    const s = (n: number, v: string) => t(`session-sample-${n}`, 'https://a.example/login', HTML + `set-cookie: sid=${v}; Secure; HttpOnly; SameSite=Lax`);
    const r = evaluate(s(1, 'AAAABBBBCCCCDDDD0001') + s(2, 'AAAABBBBCCCCDDDD0002'));
    expect(r.findings.find(f => f.item === 'C-07' && f.target === 'session-sample-*')?.ruleId).toBe('C-07.2');
  });
  it('予約ラベルが欠けたら na にする', () => {
    const r = evaluate(t('login', 'https://a.example/login', HTML));
    expect(r.findings.find(f => f.target === 'pre-login/login')?.ruleId).toBe('C-09.na');
  });
  it('固定 nonce（H-04⑤）', () => {
    const s = (n: number, nonce: string) => t(`csp-sample-${n}`, 'https://a.example/', HTML + `content-security-policy: script-src 'nonce-${nonce}' 'strict-dynamic'`);
    expect(evaluate(s(1, 'same') + s(2, 'same')).findings.find(f => f.target === 'csp-sample-*')?.ruleId).toBe('H-04.5');
    expect(evaluate(s(1, 'aaa') + s(2, 'bbb')).findings.find(f => f.target === 'csp-sample-*')?.ruleId).toBe('H-04.ok');
  });
});

describe('例外登録', () => {
  it('期限内の例外だけを適用し、期限切れは fail に戻す', () => {
    const { list, errors } = parseSuppressions(JSON.stringify({ suppressions: [
      { ruleId: 'H-10', target: 'top', reason: 'Permissions-Policy は次期リリースで対応', approver: '情報セキュリティ委員会', until: '2099-12-31' },
      { ruleId: 'H-14.1', target: 'https://a.example/*', reason: '旧Flash不使用', approver: 'x', until: '2000-01-01' },
      { ruleId: 'bad', target: 'x', reason: 'y' },
    ] }));
    expect(errors).toHaveLength(1);
    const fs = evaluate(t('top', 'https://a.example/', HTML)).findings;
    const out = applySuppressions(fs, list, '2026-11-11');
    expect(out.find(f => f.item === 'H-10')?.status).toBe('suppressed');
    expect(out.find(f => f.item === 'H-14')?.status).toBe('fail');
  });
});
