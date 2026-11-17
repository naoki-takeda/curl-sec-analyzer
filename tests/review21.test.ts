// 21回目のレビュー（リポジトリ全体を新しい目で見直したもの。直近4コミットの退行を含む）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { importHar, harTargets } from '../src/parser/har';
import { generateScript } from '../src/commands';
import { runAll } from '../src/engine/run';
import { toCsv } from '../src/export/csv';
import { toMarkdown } from '../src/export/markdown';
import { evaluate } from './helpers';

const AT = '#META at=2026-11-01T10:00:00';
const RUN = '0123456789abcdef';

describe('1 応答の本文に書いたマーカーで、ターゲットを作ったり分けたりできない', () => {
  // 生成スクリプトの形（全部のマーカー行に run= の印）。page の本文に、偽の login と、本文の1行の中の #TARGET を入れる
  const input = [
    `#TARGET url=https://a.example/login label=pre-login run=${RUN}`, `#META at=2026-11-01T10:00:00 run=${RUN}`,
    'HTTP/2 200', 'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '',
    `#TARGET url=https://a.example/ label=page run=${RUN}`, 'HTTP/2 200', 'content-type: text/html', '',
    '<p>comment</p>', '#TARGET url=https://a.example/login label=login', 'HTTP/1.1 302 Found',
    'set-cookie: JSESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '',
    '{"bio":"hi#TARGET url=x label=z","password":"hunter2hunter2"}',
    `#TARGET url=https://a.example/login label=login run=${RUN}`, `#META at=2026-11-01T10:00:00 run=${RUN}`,
    'HTTP/2 302', 'location: /home', 'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', ''].join('\n');
  it('印のないマーカーは本文として読む', () => {
    const r = parseInput(input);
    expect(r.targets.map(t => t.label)).toEqual(['pre-login', 'page', 'login']);
    expect(r.warnings.map(w => w.kind)).not.toContain('duplicate-label');
  });
  it('偽の login で C-09①（高）を合格にできない', () => {
    expect(evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.1']);
  });
  it('印のない手書きの入力では、ラベルの形を確かめ、本文の残りを画面・警告に出さない', () => {
    const r = parseInput('#TARGET url=https://a.example/api label=api\nHTTP/2 200\ncontent-type: application/json\n\n{"bio":"hi#TARGET url=x label=z","password":"hunter2hunter2"}\n');
    expect(JSON.stringify(r.targets.map(t => t.label))).not.toContain('hunter2');
    expect(JSON.stringify(r.warnings)).not.toContain('hunter2');
  });
  it('コマンド生成器のスクリプトは、全部のマーカー行に同じ印を付ける', () => {
    const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/a.js', wsPath: '/ws', dangerous: true });
    expect(s).toMatch(/^RUN=\$\(od -An -N8 -tx1 \/dev\/urandom/m);
    const markers = s.split('\n').filter(l => /#(?:TARGET|META|PROBE|TLSPROBE|CIPHERPROBE)\b/.test(l) && !/^\s*#/.test(l));
    expect(markers.length).toBeGreaterThan(30);
    for (const l of markers) expect(l, l).toMatch(/run=(?:\$RUN|%s|'"\$RUN"')/);
  });
});

describe('4 プロキシの 407 だけの応答は、サイトの応答として判定しない', () => {
  it('-i で 407 だけ', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=top\n${AT}\nHTTP/1.1 407 Proxy Authentication Required\nproxy-authenticate: Basic realm="proxy"\n\n`);
    expect(r.targets[0].responses[0].kind).toBe('connect');
    expect(r.ids('top')).not.toContain('H-01.1');
  });
});

describe('5 C-09 は、-L でたどった外部の IdP の Cookie を再発行とみなさない', () => {
  it('JSESSIONID を再発行せず、IdP だけが Cookie を発行した', () => {
    const r = evaluate([
      '#TARGET url=https://app.example.com/login label=pre-login', AT, 'HTTP/2 200', 'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '',
      '#TARGET url=https://app.example.com/login label=login', AT, 'HTTP/2 302', 'location: https://idp.other.net/session/start', '',
      'HTTP/2 302', 'location: https://app.example.com/home', 'set-cookie: idp_session=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ; Path=/; Secure; HttpOnly', '',
      'HTTP/2 200', 'content-type: text/html', '', '<p>home</p>', ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.1']);
  });
});

describe('6 T-09・T-10 は、-L で移った別のホストの TLS を対象のホストのものにしない', () => {
  const tls = (proxy: boolean) => evaluate(['#TARGET url=https://app.example.com/ label=top', AT,
    ...(proxy ? ['* Connected to proxy.corp (10.0.0.1) port 8080', '> CONNECT app.example.com:443 HTTP/1.1', '>', '< HTTP/1.1 200 Connection established', '<'] : ['* Connected to app.example.com (192.0.2.1) port 443']),
    '* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256', '> GET / HTTP/2', '>', '< HTTP/2 302', '< location: https://sso.partner.net/login', '<',
    "* Issue another request to this URL: 'https://sso.partner.net/login'", '* Connected to sso.partner.net (198.51.100.1) port 443',
    '* SSL connection using TLSv1.1 / ECDHE-RSA-AES128-SHA', '> GET /login HTTP/1.1', '>', '< HTTP/1.1 200 OK', '<', ''].join('\n'))
    .findings.filter(f => f.item === 'T-09' || f.item === 'T-10').map(f => `${f.target} ${f.ruleId}`);
  it('外部の SSO の TLS 1.1 を、対象のホストの①にしない', () => {
    expect(tls(false)).not.toContain('app.example.com T-09.1');
    expect(tls(false).some(x => /^app\.example\.com T-10\.[13]$/.test(x))).toBe(false);
  });
  it('プロキシ経由でも、対象のホストの TLS は読む（確認用）', () => {
    expect(tls(true).some(x => x.startsWith('app.example.com T-09'))).toBe(true);
  });
});

describe('8 HAR の壊れたエントリが1件あっても、ほかのエントリは読む', () => {
  it('"response": 1', () => {
    const e = (url: string) => ({ startedDateTime: '2026-11-01T01:00:00Z', request: { method: 'GET', url, headers: [] }, response: { status: 200, headers: [], content: { mimeType: 'text/html', text: '' } } });
    const imp = importHar(JSON.stringify({ log: { entries: [{ request: { url: 'https://a.example/x' }, response: 1 }, e('https://a.example/')] } }));
    expect(imp.chains).toHaveLength(1);
  });
});

describe('9 C-09：ログイン前のセッションIDを再発行せず、別の Cookie だけを発行したら合格にしない', () => {
  it('na（どちらで認証しているか分からない）', () => {
    const r = evaluate([
      '#TARGET url=https://a.example/login label=pre-login', AT, 'HTTP/2 200', 'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '',
      '#TARGET url=https://a.example/login label=login', AT, 'HTTP/2 302', 'location: /home', 'set-cookie: auth_token=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n'));
    expect(r.findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.na']);
  });
});

describe('10 H-11：機密か分からないときの CORP の cross-origin と、大文字の値', () => {
  const h11 = (corp: string, extra = '') => evaluate(`#TARGET url=https://a.example/ label=page ${extra}\n${AT}\nHTTP/2 200\ncontent-type: text/html\ncross-origin-resource-policy: ${corp}\ncross-origin-opener-policy: same-origin\n\n<p>x</p>\n`)
    .ids('page').filter(x => x.startsWith('H-11'));
  it('cross-origin・読めない値は na', () => {
    expect(h11('cross-origin')).toEqual(['H-11.na']);
    expect(h11('bogus')).toEqual(['H-11.na']);
    expect(h11('same-origin')).toEqual(['H-11.ok']);
  });
  it('Same-Origin（大文字）はブラウザが読めないので、機密応答では①', () => {
    expect(h11('Same-Origin', 'sensitive=1')).toContain('H-11.1');
  });
});

describe('12 R-06：HAR で Origin を送っていない応答の固定の ACAO は、判定しない', () => {
  const har = (origin?: string) => {
    const imp = importHar(JSON.stringify({ log: { entries: [{ startedDateTime: '2026-11-01T01:00:00Z',
      request: { method: 'GET', url: 'https://a.example/api', headers: origin ? [{ name: 'Origin', value: origin }] : [] },
      response: { status: 200, headers: [{ name: 'content-type', value: 'application/json' }, { name: 'access-control-allow-origin', value: 'https://partner.example' }], content: { mimeType: 'application/json', text: '{}' } } }] } }));
    return runAll(harTargets(imp, new Set(imp.hosts)).targets).filter(f => f.item === 'R-06').map(f => f.ruleId);
  };
  it('Origin なしは適用外、Origin ありで Vary がなければ①', () => {
    expect(har()).toEqual([]);
    expect(har('https://partner.example')).toContain('R-06.1');
  });
});

describe('13 C-07：同じ署名付きトークン（JWT）は、推測できる（②（高））としない', () => {
  it('na', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaWF0IjoxNzAwMDAwMDAwfQ.c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJl';
    const s = [1, 2, 3].map(i => `#TARGET url=https://a.example/login label=session-sample-${i}\n${AT}\nHTTP/2 302\nset-cookie: session=${jwt}; Path=/; Secure; HttpOnly\n`).join('\n');
    expect(evaluate(s).findings.filter(f => f.item === 'C-07' && f.target === 'session-sample-*').map(f => f.ruleId)).toEqual(['C-07.na']);
  });
});

describe('2 URL のユーザー名に置いたトークンを、画面・エクスポートに出さない', () => {
  it('https://<トークン>:x-oauth-basic@…', () => {
    const tok = '0123456789abcdef0123456789abcdef01234567';
    const r = evaluate(`#TARGET url=https://${tok}:x-oauth-basic@api.example/user label=api\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n{}\n`);
    const all = [JSON.stringify(r.findings), toCsv(r.findings, r.targets), toMarkdown(r.findings, [], [])].join('\n');
    expect(all).not.toContain(tok.slice(0, 12));
    expect(all).toContain('api.example');
  });
});
