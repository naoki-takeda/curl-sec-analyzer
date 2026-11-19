import { describe, expect, it } from 'vitest';
import { attrs, parseInput } from '../src/parser/input';
import { finalResponse, isHttps, siteOf } from '../src/parser/target';
import { logoutFailed } from '../src/rules/html';
import { importHar } from '../src/parser/har';
import { fixture, sampleText } from './helpers';
import { analyze } from './golden/analyze';

describe('parseInput', () => {
  it('#TARGET ごとにターゲットを分け、url・label・sensitive を読む', () => {
    const { targets } = parseInput(sampleText());
    expect(targets.map(t => t.label)).toEqual(['top', 'http', 'apex', 'pre-login', 'login', 'mypage', 'cors-reflect', 'logout', 'after-logout', 'probes', 'tls']);
    expect(targets.find(t => t.label === 'mypage')!.sensitive).toBe(true);
    expect(targets[0].sensitive).toBeUndefined();
    expect(targets.find(t => t.label === 'probes')!.probes[0]).toMatchObject({ path: '/.git/HEAD', code: 200, contentType: 'text/plain' });
    expect(targets.find(t => t.label === 'tls')!.tlsProbes.map(p => p.result)).toEqual(['rejected', 'accepted', 'accepted', 'accepted']);
  });

  it('-v の出力から送信ヘッダ（Origin・Authorization）と接続情報を読む', () => {
    const { targets } = parseInput(sampleText());
    const top = targets[0], api = targets.find(t => t.label === 'cors-reflect')!;
    expect(top.verbose).toBe(true);
    expect(top.sentAuth).toBe(false);
    expect(top.info.some(l => l.startsWith('ALPN'))).toBe(true);
    expect(api.sentOrigin).toBe('https://evil.example');
    expect(api.sentAuth).toBe(true);
    expect(finalResponse(top)?.headers.get('strict-transport-security')).toEqual(['max-age=31536000; includeSubDomains; preload']);
  });

  it('-L の複数ホップを1つのターゲットの応答チェーンにする', () => {
    const http = parseInput(sampleText()).targets[1];
    expect(http.responses.map(r => [r.status, r.kind])).toEqual([[302, 'redirect'], [200, 'final']]);
    expect(isHttps(http)).toBe(false);
  });

  it('既知のマーカー以外の # 行は本文として扱い、obs-fold をつなぐ', () => {
    const { targets, warnings } = parseInput(fixture('body_hash_comments.txt'));
    expect(targets).toHaveLength(1);
    const r = finalResponse(targets[0])!;
    expect(r.headers.get('x-long')).toEqual(['continued value']);
    expect(r.body).toContain('# これは本文の行');
    expect(r.body).toContain('#TARGETS も本文');
    expect(warnings).toEqual([]);
  });

  it('ct= は行末まで1つの値として読む', () => {
    expect(attrs(' path=/x code=200 ct=text/html; charset=utf-8')).toEqual({ path: '/x', code: '200', ct: 'text/html; charset=utf-8' });
  });

  it('解析警告：属さない行、データのない #TARGET、URL不明', () => {
    const { warnings } = parseInput('garbage line\n#TARGET label=empty\n#TARGET label=nourl\nHTTP/1.1 200 OK\nA: b\n');
    expect(warnings.map(w => w.kind)).toEqual(['unparsed-lines', 'orphan-block', 'unknown-url']);
  });

  it('CRLF の改行も読める', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/\r\nHTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n');
    expect(finalResponse(targets[0])?.headers.get('x-content-type-options')).toEqual(['nosniff']);
  });
});

describe('ターゲットの共通の処理', () => {
  it('ログアウトの確認画面は、小文字にすると長さの変わる文字（İ）が前にあっても見つける', () => {
    const body = `<p>${'İ'.repeat(5000)}</p><form method="post" action="/logout"><button>Log out</button></form>`;
    const { targets } = parseInput(`#TARGET url=https://a.example/logout label=logout
HTTP/1.1 200 OK
content-type: text/html

${body}
`);
    expect(logoutFailed(targets[0])).toBe(true);
  });
  it('siteOf はポート・角かっこを外し、国別の第2レベルは3つのラベルにする', () => {
    expect(siteOf('www.Example.com:8443')).toBe('example.com');
    expect(siteOf('a.b.example.co.jp')).toBe('example.co.jp');
    expect(siteOf('[::1]')).toBe('::1');
    expect(siteOf('192.0.2.1')).toBe('192.0.2.1');
  });
  it('HAR の小文字のメソッド（post）も、ログインの候補にする', () => {
    const har = JSON.stringify({ log: { entries: [{ request: { method: 'post', url: 'https://a.example/login', headers: [] }, response: { status: 200, headers: [] } }] } });
    const c = importHar(har).chains[0];
    expect(c.method).toBe('POST');
    expect(c.suggested).toBe('login');
  });
});

describe('HAR のラベルの候補', () => {
  const entry = (method: string, url: string, reqHeaders: { name: string; value: string }[] = []) =>
    ({ request: { method, url, headers: reqHeaders }, response: { status: 200, headers: [] } });
  const har = (...entries: unknown[]) => JSON.stringify({ log: { entries } });
  it('ASP.NET の /Account/LogOff と /log_out も logout の候補にする', async () => {
    expect(importHar(har(entry('POST', 'https://a.example/Account/LogOff'))).chains[0].suggested).toBe('logout');
    expect(importHar(har(entry('GET', 'https://a.example/log_out'))).chains[0].suggested).toBe('logout');
  });
  it('一覧の「自動（はい）」は、組織プロファイルのセッションCookieの名前で作り直す', async () => {
    const { suggestLabels } = await import('../src/parser/har');
    const { withProfile, parseProfile } = await import('../src/engine/profile');
    const imp = importHar(har(entry('GET', 'https://a.example/me', [{ name: 'Cookie', value: 'corpauth=abc' }])));
    expect(imp.chains[0].sentAuth).toBe(false);
    withProfile(parseProfile('{"sessionCookieNames":["corpauth"]}').profile, () => suggestLabels(imp.chains, true));
    expect(imp.chains[0].sentAuth).toBe(true);
  });
});

describe('最初の #TARGET と HAR の redirectURL', () => {
  it('属性のない #TARGET が最初なら、後ろの行の run= を印にしない（本文が作ったマーカーで利用者のターゲットを消さない）', () => {
    const { targets } = parseInput(['#TARGET', 'HTTP/1.1 200 OK', 'content-type: text/html', '', '<p>hi</p>', '#TARGET run=0123456789abcdef label=login',
      '#TARGET url=https://a.example/ label=top', 'HTTP/1.1 200 OK', 'content-type: text/html', '', '<p>top</p>', ''].join('\n'));
    expect(targets.map(t => t.label)).toContain('top');
  });
  it('HAR の redirectURL が文字列でなくても、ルールを例外で止めない', () => {
    const har = { log: { entries: [{ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url: 'https://a.example/r', headers: [] },
      response: { status: 302, headers: [], redirectURL: { a: 1 }, content: { mimeType: 'text/html', text: '' } } }] } };
    const r = analyze('', JSON.stringify(har));
    expect(r.findings.filter(f => f.evidence.includes('エラーが発生した'))).toEqual([]);
  });
});
