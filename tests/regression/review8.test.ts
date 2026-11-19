// 8回目のレビュー（リポジトリ全体、独立した3人のレビュアー）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { parseInput } from '../../src/parser/input';
import { splitSetCookie } from '../../src/parser/setCookie';
import { harTargets, importHar } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { coverage } from '../../src/engine/coverage';
import { IMPLEMENTED } from '../../src/rules/ruleset';
import { generateScript } from '../../src/commands';
import { toCsv } from '../../src/export/csv';
import { toJson } from '../../src/export/json';
import { toMarkdown } from '../../src/export/markdown';
import type { Profile } from '../../src/model';
import { evaluate } from '../helpers';

const CR = String.fromCharCode(13);
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const t = (label: string, url: string, head: string, body = '') => `#TARGET url=${url} label=${label}\n${head.trim()}\n\n${body}\n`;
const exportsOf = (r: ReturnType<typeof evaluate>) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [JSON.stringify(r.findings), toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};

describe('CSP：csp_evaluator が例外を出す値でも、判定を止めない', () => {
  it('img-src data:image/svg+xml で判定全体が止まらず、H-07④ にし、H-04 は合格にしない', () => {
    const input = t('top', 'https://www.example.com/', `${HTML}\ncontent-security-policy: img-src 'self' data:image/svg+xml`);
    expect(() => evaluate(input)).not.toThrow();
    const ids = evaluate(input).ids('top');
    expect(ids).toContain('H-07.4');
    expect(ids).toContain('H-04.na');
  });
});

describe('-v：プロキシ経由（CONNECT）の出力', () => {
  const lines = ['#TARGET url=https://a.example/api label=cors-partial sensitive=1', '* Connected to proxy (10.0.0.1) port 8080', '> CONNECT a.example:443 HTTP/1.1', '>',
    '< HTTP/1.1 200 Connection established', '<', '* SSL connection using TLSv1.0 / ECDHE-RSA-AES128-SHA', '> GET /api HTTP/2', '> Origin: https://a.example.evil.net', '> Cookie: sid=x', '>',
    '< HTTP/2 200', '< content-type: application/json', '< access-control-allow-origin: https://a.example.evil.net', '< access-control-allow-credentials: true', '<'].join('\n') + '\n';
  it('トンネルの応答のあとの、本当のリクエスト（Origin・Cookie・TLS）を読む', () => {
    const tg = parseInput(lines).targets[0];
    expect([tg.sentOrigin, tg.sentAuth]).toEqual(['https://a.example.evil.net', true]);
    const ids = evaluate(lines).findings.map(f => f.ruleId);
    expect(ids).toContain('R-03.1');
    expect(ids).toContain('T-09.1');
  });
  it('理由句が違うプロキシでも、> CONNECT への応答ならトンネルとみなす', () => {
    const tg = parseInput(lines.replace('200 Connection established', '200 OK')).targets[0];
    expect(tg.sentOrigin).toBe('https://a.example.evil.net');
  });
});

describe('CSP：同じ緩いポリシーが2つあっても H-04①② を出す', () => {
  it('1つのときと同じ指摘になる', () => {
    const p = "default-src 'self' 'unsafe-inline' *; object-src 'none'; base-uri 'none'";
    const ids = (n: number) => evaluate(t('top', 'https://www.example.com/', `${HTML}\n${Array(n).fill(`content-security-policy: ${p}`).join('\n')}`)).ids('top').filter(i => i.startsWith('H-04'));
    expect(ids(2)).toEqual(ids(1));
    expect(ids(2)).toEqual(['H-04.1', 'H-04.2']);
  });
});

describe('HAR：http から入る apex', () => {
  type H = { name: string; value: string };
  const entry = (url: string, status: number, headers: H[], redirectURL?: string) => ({
    startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: [] as H[] },
    response: { status, httpVersion: 'HTTP/2', headers, redirectURL, content: { mimeType: 'text/html', text: '' } } });
  it('https の apex 自身が HSTS を返せば H-01 は合格（http の転送を apex 自身の応答にしない）', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [
      entry('http://example.com/', 301, [{ name: 'location', value: 'https://example.com/' }], 'https://example.com/'),
      entry('https://example.com/', 301, [{ name: 'location', value: 'https://www.example.com/' }, { name: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains; preload' }], 'https://www.example.com/'),
    ] } }));
    imp.chains[0].label = 'apex';
    const fs = runAll(harTargets(imp, new Set(imp.hosts)).targets);
    expect(fs.filter(f => f.item === 'H-01').map(f => f.ruleId)).toEqual(['H-01.ok']);
  });
});

describe('Set-Cookie：値の中のカンマでは分けない', () => {
  it('前のかけらに属性がなければ、同じ Cookie の値の続き', () => {
    expect(splitSetCookie('prefs=lang=ja,tz=JST; Path=/; Secure; HttpOnly')).toEqual(['prefs=lang=ja,tz=JST; Path=/; Secure; HttpOnly']);
    expect(splitSetCookie('pref=1; Path=/, session_id=abc; Path=/')).toEqual(['pref=1; Path=/', 'session_id=abc; Path=/']);
  });
  it('値の一部を Cookie 名として出さない', () => {
    const r = evaluate(t('top', 'https://www.example.com/', `${HTML}\nset-cookie: sessionid=abc,S3CR3Tvalue=1; Path=/`));
    expect(exportsOf(r)).not.toContain('S3CR3T');
  });
});

describe('マスク：漏れていた形', () => {
  const BS = String.fromCharCode(92);
  it.each([
    ['「…」に続く日本語の文', 'http://stg.internal/login?token=S3CR3TVALUE1234567…詳しくは担当まで'],
    ['1語の名前（authtoken）', 'https://a/?authtoken=S3CR3Tval123'],
    ['1語の名前（apitoken）', 'https://a/?apitoken=S3CR3Tval123'],
    ['1語の名前（secretkey）', 'https://a/?secretkey=S3CR3Tval123'],
    ['1語の名前（sessiontoken）', 'https://a/?sessiontoken=S3CR3Tval123'],
    ['1語の名前（CFTOKEN）', 'https://a/?CFTOKEN=S3CR3Tval123'],
    ['1語の名前（sesskey）', 'https://a/?sesskey=S3CR3Tval123'],
    ['1語の名前（passphrase）', 'https://a/?passphrase=S3CR3Tval123'],
    ['二重エンコード', 'https://a/sso?return=%252Fcb%253Faccess_token%253DS3CR3Tdbl123'],
    ['文字参照の =（&#61;）', 'https://cdn.example/a.js?api_key&#61;S3CR3Tentity123'],
    ['文字参照の =（&#x3D;）', 'https://cdn.example/a.js?token&#x3D;S3CR3Tentity123'],
    ['スキームのないユーザー情報', 'src="//admin:S3CR3Tpw@cdn.other.example/x.js"'],
    ['JS のエスケープ（前回の修正）', `http://localhost:3000/v1?client=web${BS}u0026api_key=S3CR3Tkey12345`],
  ])('%s', (_, input) => {
    const m = maskText(input);
    expect(m).not.toContain('S3CR3T');
    expect(maskText(m)).toBe(m);
  });
  it('タグの属性の文字参照も、証跡で伏せる（E-08）', () => {
    const r = evaluate(t('top', 'https://www.example.com/', HTML, '<script src="https://cdn.other.example/a.js?api_key&#61;S3CR3Tentity123"></script>'));
    expect(r.findings.some(f => f.ruleId === 'E-08.1')).toBe(true);
    expect(exportsOf(r)).not.toContain('S3CR3T');
  });
  it('秘密でない名前は伏せない', () => {
    expect(maskText('https://a/?q=hello&page=2&lang=ja')).toBe('https://a/?q=hello&page=2&lang=ja');
  });
});

describe('Markdown：CR だけの改行でも行を増やさない', () => {
  it('プロファイル名の CR で見出しを差し込めない', () => {
    const profile: Profile = { name: `Org${CR}# INJECTED${CR}- list`, severity: {}, exclude: [], sessionCookieNames: [], sessionMaxAgeHours: 24, trustedScriptOrigins: [] };
    const md = toMarkdown([], [], [], new Date('2026-11-01T00:00:00Z'), { profile });
    expect(md).not.toContain(CR);
    expect(md).not.toMatch(/^# INJECTED/m);
  });
});

describe('Windows の curl の -v：受信ヘッダの行が CR CR LF で終わる', () => {
  it('受信ヘッダを失わない（反射した Origin を R-01① にする）', () => {
    const lines = ['#TARGET url=https://a.example/api label=cors-reflect sensitive=1', '* Connected to a.example (192.0.2.1) port 443', '> GET /api HTTP/1.1', '> Origin: https://evil.example', '>',
      '< HTTP/1.1 200 OK', '< Content-Type: application/json', '< Access-Control-Allow-Origin: https://evil.example', '< Access-Control-Allow-Credentials: true', '<'];
    const win = lines.map(l => (l.startsWith('<') ? `${l}${CR}${CR}` : l)).join('\n') + '\n';
    expect(evaluate(win).findings.filter(f => f.item === 'R-01').map(f => f.ruleId)).toEqual(['R-01.1']);
  });
  it('今の curl の表示（*   Trying、* Established connection to）でも -v の出力と分かる', () => {
    const input = ['#TARGET label=top', '*   Trying 192.0.2.1:80...', '* Established connection to 192.0.2.1 (192.0.2.1 port 80) from 192.0.2.9 port 51234', '> GET / HTTP/1.1', '>',
      '< HTTP/1.1 200 OK', '< Content-Type: text/html', '<'].join('\n') + '\n';
    const tg = parseInput(input).targets[0];
    expect(tg.verbose).toBe(true);
    expect(tg.responses.map(r => r.status)).toEqual([200]);
  });
});

describe('生成スクリプト：-i の出力のあとに改行を出す', () => {
  const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/a.js', dangerous: true });
  it('本文を取るコマンドはすべて、ヘッダと本文を分けて取り、本文のあとに改行を出す（第40回で -i -w から変えた）', () => {
    expect(s).not.toMatch(/curl -sS -i /);
    const lines = s.split('\n').filter(l => /-D "\$hdr" -o "\$body"/.test(l));
    expect(lines.length).toBeGreaterThan(10);
    for (const l of lines) expect(l).toMatch(/cat "\$hdr"; echo "#BODY run=\$RUN"; head -c 196608 "\$body"; echo/);
  });
  it('改行で終わらない本文でも、次の #TARGET が別のターゲットになる', () => {
    // 生成スクリプトが出す形：本文（改行なし）のあとに -w の改行、次の #TARGET
    const out = '#TARGET url=https://a.example/api label=api\nHTTP/2 401\ncontent-type: application/json\n\n{"error":"x"}\n#TARGET url=https://a.example/api label=unauth-api\nHTTP/2 200\ncontent-type: application/json\n\n{}\n';
    expect(parseInput(out).targets.map(x => x.label)).toEqual(['api', 'unauth-api']);
  });
});

describe('E-11①・E-05①：そのURL自身の応答で判定する', () => {
  const ids = (url: string, head: string, item: string) => evaluate(t('t', url, head, '<p>x</p>')).findings.filter(f => f.item === item).map(f => f.ruleId);
  it('アップロード先の 404 のエラーページや、ログイン画面への転送先を E-11① にしない', () => {
    expect(ids('https://a.example/uploads/missing.png', 'HTTP/2 404\ncontent-type: text/html', 'E-11')).toEqual([]);
    expect(ids('https://a.example/uploads/report.pdf', 'HTTP/2 302\nlocation: /login\n\nHTTP/2 200\ncontent-type: text/html', 'E-11')).toEqual([]);
    expect(ids('https://a.example/uploads/a.html', 'HTTP/2 200\ncontent-type: text/html', 'E-11')).toEqual(['E-11.1']);
  });
  it('/actuator からログイン画面への転送先の 200 を E-05① にしない', () => {
    expect(ids('https://a.example/actuator', 'HTTP/2 302\nlocation: /login\n\nHTTP/2 200\ncontent-type: text/html', 'E-05')).toEqual(['E-05.ok']);
    expect(ids('https://a.example/actuator/health', 'HTTP/2 200\ncontent-type: application/json', 'E-05')).toEqual(['E-05.1']);
  });
});
