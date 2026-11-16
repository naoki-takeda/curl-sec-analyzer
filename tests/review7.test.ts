// 7回目のレビュー（リポジトリ全体、独立した3人のレビュアー）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { clip, maskText } from '../src/mask';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { runAll } from '../src/engine/run';
import { coverage } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toCsv } from '../src/export/csv';
import { toJson } from '../src/export/json';
import { toMarkdown } from '../src/export/markdown';
import { evaluate } from './helpers';

const BS = String.fromCharCode(92);   // バックスラッシュ（JS のエスケープ & を入力に入れるため）
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const t = (label: string, url: string, head: string, body = '') => `#TARGET url=${url} label=${label}\n${head.trim()}\n\n${body}\n`;
const exportsOf = (r: ReturnType<typeof evaluate>) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [JSON.stringify(r.findings), toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTRUtSRVR1c2VyIiwiZW1haWwiOiJhQGIuZXhhbXBsZSJ9.c2lnbmF0dXJlc2lnbmF0dXJl';

describe('カンマでつないだ Set-Cookie', () => {
  const r = () => evaluate(t('top', 'https://www.example.com/', `${HTML}\nset-cookie: pref=1; Path=/, session_id=SEKRETcookie0123456789abcd; Path=/; HttpOnly`));
  it('2つ目の Cookie の値を、画面とエクスポートに出さない', () => {
    expect(exportsOf(r())).not.toContain('SEKRETcookie');
  });
  it('2つ目の Cookie も判定する（セッションCookieの Secure なし）', () => {
    expect(r().findings.filter(f => f.ruleId === 'C-01.1').map(f => f.evidence).join()).toContain('session_id=');
  });
  it('Expires の日付のカンマでは分けない', () => {
    const { targets } = parseInput(t('top', 'https://www.example.com/', `${HTML}\nset-cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure`));
    expect(targets[0].responses[0].headers.get('set-cookie')).toEqual(['a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure']);
  });
});

describe('マスク：秘密のパラメータ名と、エンコードした区切り', () => {
  it.each([
    ['https://a.example/login?user=alice&pass=SEKRETpass1', 'SEKRETpass1'],
    ['https://a.example/login?pw=SEKRETpw12345', 'SEKRETpw12345'],
    ['https://a.example/cas?ticket=ST-SEKRETticket', 'SEKRETticket'],
    ['https://a.example/cb?oauth_verifier=SEKRETverifier', 'SEKRETverifier'],
    ['https://a.example/acs?SAMLResponse=PHNhbWxwOlNFS1JFVA', 'PHNhbWxwOlNFS1JFVA'],
    ['https://a.example/?api%5Fkey=SEKRETenc123', 'SEKRETenc123'],
    ['https://a.example/?next=%2Fcb%3Ftoken%3DSEKRETtok12345', 'SEKRETtok12345'],
    [`x=%3D${JWT}`, 'eyJzdWIi'],
    [`https://a.example/x?a=Bearer%20${JWT}`, 'eyJzdWIi'],
    [`http://localhost:3000/v1?client=web${BS}u0026api_key=SEKRETkey12345`, 'SEKRETkey12345'],
  ])('%s', (input, secret) => {
    const m = maskText(input);
    expect(m).not.toContain(secret);
    expect(maskText(m)).toBe(m);           // もう一度マスクしても変わらない（ルールで切り詰める前と engine/run.ts の2回マスクする）
  });
  it('秘密でない名前は伏せない', () => {
    expect(maskText('https://a.example/?q=hello&state=xyz&page=2')).toBe('https://a.example/?q=hello&state=xyz&page=2');
  });
});

describe('証跡の抜粋：マスクしてから切り詰める', () => {
  it('途中で切れる位置にある JWT も、payload を出さない', () => {
    const s = `http://localhost:3000/${'p/'.repeat(40)}${JWT}`;
    expect(clip(s, 120)).not.toContain('eyJzdWIi');
    const fs = evaluate(t('top', 'https://www.example.com/', HTML, `<a href="${s}">x</a>`)).findings.filter(f => f.ruleId === 'E-09.2');
    expect(fs.length).toBeGreaterThan(0);
    expect(JSON.stringify(fs)).not.toContain('eyJzdWIi');
  });
});

describe('-v：本文も出力した場合、本文の行を応答・情報行・送信ヘッダとして読まない', () => {
  const head = ['* Connected to a.example (192.0.2.1) port 443', '* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256', '> GET / HTTP/2', '> Host: a.example', '>',
    '< HTTP/2 200', '< content-type: text/html; charset=utf-8', '< strict-transport-security: max-age=63072000; includeSubDomains', '<'];
  const body = ['<pre>', 'HTTP/1.1 200 OK', 'Content-Type: text/html', '', '* SSL connection using TLSv1.0 / ECDHE-RSA-AES128-SHA', '> Authorization: Bearer x', '> Origin: https://evil.example', '</pre>'];
  it('本文のステータス行・「* 」「> 」の行を読まない', () => {
    const input = `#TARGET url=https://a.example/ label=top\n${[...head, ...body].join('\n')}\n`;
    const { targets } = parseInput(input);
    expect(targets[0].responses).toHaveLength(1);
    expect([targets[0].sentAuth, targets[0].sentOrigin]).toEqual([false, undefined]);
    const ids = evaluate(input).findings.map(f => f.ruleId);
    expect(ids).not.toContain('H-01.1');
    expect(ids).not.toContain('T-09.1');
  });
  it('-L の次の応答（< HTTP/）は読む', () => {
    const input = ['#TARGET url=http://a.example/ label=http', '* Connected to a.example (192.0.2.1) port 80', '> GET / HTTP/1.1', '>', '< HTTP/1.1 301 Moved Permanently', '< location: https://a.example/', '<',
      '<html>moved</html>', '* Issue another request to this URL', '> GET / HTTP/2', '>', '< HTTP/2 200', '< content-type: text/html', '<', '<p>ok</p>'].join('\n');
    expect(parseInput(input).targets[0].responses.map(r => r.status)).toEqual([301, 200]);
  });
});

describe('%{header_json}', () => {
  it('JSON の本文だけ（curl -s）は応答にせず、警告する', () => {
    const r = parseInput('#TARGET url=https://a.example/api/items label=api\n{"items":[{"id":1}],"total":1}\n');
    expect(r.targets).toHaveLength(0);
    expect(r.warnings.map(w => w.kind)).toContain('unparsed-lines');
    expect(parseInput('#TARGET url=https://a.example/ label=t\n{"tags":["a","b"]}\n').targets).toHaveLength(0);
  });
  it('ヘッダの JSON は応答にする', () => {
    expect(parseInput('#TARGET url=https://a.example/ label=t\n#META response_code=200\n{"content-type":["text/html"],"date":["Mon, 16 Nov 2026 00:00:00 GMT"]}\n').targets[0].responses[0].status).toBe(200);
  });
  const logout = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0');
  const after = (meta: string) => `#TARGET url=https://a.example/mypage label=after-logout\n{"content-type":["text/html"],"date":["Mon, 16 Nov 2026 00:00:00 GMT"]}\n${meta}`;
  it('あとの #META response_code をステータスにする（C-12① を見逃さない）', () => {
    expect(evaluate(logout + after('#META response_code=200\n')).findings.map(f => f.ruleId)).toContain('C-12.1');
  });
  it('ステータスが分からなければ C-12・A-01 は判定しない（合格にしない）', () => {
    expect(evaluate(logout + after('')).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.na']);
    expect(evaluate('#TARGET url=https://a.example/api/users label=unauth-users\n{"content-type":["application/json"],"date":["Mon, 16 Nov 2026 00:00:00 GMT"]}\n').ids('unauth-users')).toContain('A-01.na');
  });
});

describe('CONNECT（プロキシ）の応答', () => {
  it('理由句が「Connection established」でなくても、本文のない 2xx のあとに応答が続けばプロキシの応答', () => {
    const input = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0')
      + '#TARGET url=https://a.example/mypage label=after-logout\nHTTP/1.1 200 OK\n\nHTTP/2 302\nlocation: https://a.example/login\n\n';
    expect(evaluate(input).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.ok']);
  });
});

describe('HAR：別のホストへの転送先をつながない', () => {
  type H = { name: string; value: string };
  const entry = (url: string, status: number, headers: H[], extra: Record<string, unknown> = {}) => ({
    startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: [] as H[] },
    response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' }, ...extra } });
  it('IdP の応答（Cookie・ヘッダ）を、選んだホストの結果にしない', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [
      entry('https://app.example/', 302, [{ name: 'location', value: 'https://idp.other.example/login' }, { name: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains' }], { redirectURL: 'https://idp.other.example/login' }),
      entry('https://idp.other.example/login', 200, [{ name: 'content-type', value: 'text/html' }, { name: 'set-cookie', value: 'idp_sid=abcdefabcdefabcdefabcdefabcdefab; Path=/' }]),
    ] } }));
    const { targets } = harTargets(imp, new Set(['app.example']));
    expect(targets.map(x => x.responses.map(r => r.status))).toEqual([[302]]);
    const fs = runAll(targets);
    expect(JSON.stringify(fs)).not.toContain('idp_sid');
    expect(fs.map(f => f.ruleId)).not.toContain('H-01.1');
  });
});

describe('負荷分散の Cookie をセッションCookieとみなさない', () => {
  it('BIGipServer・ARRAffinity で C-01①・C-02①・C-07 を出さない', () => {
    const ids = evaluate(t('top', 'https://www.example.com/', `${HTML}\nset-cookie: BIGipServerpool_web=1677787402.20480.0000; path=/\nset-cookie: ARRAffinity=${'a'.repeat(64)}; Path=/`)).ids('top');
    expect(ids).not.toContain('C-01.1');
    expect(ids).not.toContain('C-02.1');
    const s = (n: number) => t(`session-sample-${n}`, 'https://www.example.com/login', `HTTP/2 200\nset-cookie: ARRAffinity=${'a'.repeat(64)}; Path=/; Secure; HttpOnly`);
    expect(evaluate(s(1) + s(2)).findings.filter(f => f.item === 'C-07').map(f => f.ruleId)).not.toContain('C-07.2');
  });
});

describe('CSP：複数の強制モードのポリシー', () => {
  const ids = (...ps: string[]) => evaluate(t('top', 'https://www.example.com/', `${HTML}\n${ps.map(p => `content-security-policy: ${p}`).join('\n')}`)).ids('top');
  const STRICT = "script-src 'nonce-r4nd0mN0nceValue123' 'strict-dynamic'; object-src 'none'; base-uri 'none'";
  it('別のポリシーにないディレクティブで H-04②・H-05① にしない', () => {
    for (const other of ["frame-ancestors 'self'", 'upgrade-insecure-requests']) {
      const x = ids(STRICT, other);
      expect(x).toContain('H-04.ok');
      expect(x).toContain('H-05.ok');
    }
  });
  it('どのポリシーもスクリプトを制限していなければ H-04②', () => {
    expect(ids('default-src *', "frame-ancestors 'none'")).toContain('H-04.2');
  });
});

describe('E-05：パスの区切りごとに照合する', () => {
  const e05 = (url: string) => evaluate(t('t', url, 'HTTP/2 200\ncontent-type: text/html', '<p>x</p>')).findings.filter(f => f.item === 'E-05').map(f => f.ruleId);
  it('普通のページの語には一致させない', () => {
    expect(e05('https://shop.example/category/actuator-kits')).toEqual([]);
    expect(e05('https://a.example/blog/swagger-tips')).toEqual([]);
    expect(e05('https://a.example/docs/api-docs-guide')).toEqual([]);
  });
  it('actuator・swagger-ui・api-docs は指摘する', () => {
    // 第24回から、HTML の 200 はその機能の画面と分かるときだけ①②にする（SPA の誤検知を防ぐ）。本物の actuator と API 仕様は JSON、Swagger UI の画面は swagger-ui を含む
    const json = (url: string) => evaluate(t('t', url, 'HTTP/2 200\ncontent-type: application/json', '{"status":"UP"}')).findings.filter(f => f.item === 'E-05').map(f => f.ruleId);
    expect(json('https://a.example/actuator/health')).toEqual(['E-05.1']);
    expect(evaluate(t('t', 'https://a.example/swagger-ui/index.html', 'HTTP/2 200\ncontent-type: text/html', '<div id="swagger-ui"></div>')).findings.filter(f => f.item === 'E-05').map(f => f.ruleId)).toEqual(['E-05.2']);
    expect(json('https://a.example/v3/api-docs')).toEqual(['E-05.2']);
    expect(e05('https://a.example/actuator/health')).toEqual(['E-05.na']);   // HTML の 200（SPA の可能性）
  });
});

describe('C-07②：1つのサンプルの同じ Cookie を2回数えない', () => {
  it('同じ応答に同じ Set-Cookie が2つあっても「同じ値が繰り返し発行された」にしない', () => {
    const s = (n: number, v: string) => t(`session-sample-${n}`, 'https://www.example.com/login', `HTTP/2 200\nset-cookie: PHPSESSID=${v}; Path=/; Secure; HttpOnly\nset-cookie: PHPSESSID=${v}; Path=/; Secure; HttpOnly`);
    const ids = evaluate(s(1, 'q8w7e6r5t4y3u2i1o0p9a8s7d6') + s(2, 'z1x2c3v4b5n6m7l8k9j0h1g2f3')).findings.filter(f => f.item === 'C-07').map(f => f.ruleId);
    expect(ids).not.toContain('C-07.2');
  });
});

describe('apex：apex 自身の応答（転送の最初のホップ）で HSTS を見る', () => {
  const www = 'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains; preload';
  it('apex が HSTS なしで www に転送するなら H-01①', () => {
    const r = evaluate(t('top', 'https://www.example.com/', www) + t('apex', 'https://example.com/', `HTTP/1.1 301 Moved Permanently\nlocation: https://www.example.com/\n\n${www}`));
    expect(r.ids('apex')).toContain('H-01.1');
  });
  it('apex が HSTS を返し、転送先の www が返さなくても、apex は合格', () => {
    const r = evaluate(t('apex', 'https://example.com/', 'HTTP/1.1 301 Moved Permanently\nlocation: https://www.example.com/\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\n\nHTTP/2 200\ncontent-type: text/html'));
    expect(r.ids('apex')).toContain('H-01.ok');
  });
});

describe('横断ルール：付け直したラベル（#2）は比べない', () => {
  it('同じ csp-sample-1 が2つあっても H-04⑤ にしない', () => {
    const c = (label: string, nonce: string) => t(label, 'https://www.example.com/', `${HTML}\ncontent-security-policy: script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`);
    const r = evaluate(c('csp-sample-1', 'AAAAAAAAAAAAAAAAAAAA') + c('csp-sample-1', 'AAAAAAAAAAAAAAAAAAAA') + c('csp-sample-2', 'BBBBBBBBBBBBBBBBBBBB'));
    expect(r.findings.filter(f => f.target === 'csp-sample-*').map(f => f.ruleId)).toEqual(['H-04.ok']);
  });
});
