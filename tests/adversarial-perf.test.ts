// 入力の長さの2乗の時間にならないことの見張り（第40回）。第37回〜第39回の修正は、毎回どこかに2乗の時間の正規表現・繰り返しを入れた
// （許可リストのホスト名、印のある入力の行分け、閉じのない <!-- のタグの読み取り、差分のキー）。診断対象のサーバは本文・ヘッダを
// 自由に書けるので、よくある繰り返しの形を本文・ヘッダ・設定ファイルの値に置き、全体の時間が上限に収まることを確かめる。
// 上限は、普通の入力の数倍（2乗の時間なら、64KB で数秒〜数十秒になる）
import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { diff } from '../src/engine/diff';
import { maskText } from '../src/mask';
import { showText } from '../src/shownText';
import { summarizeCommand } from '../src/export/cmdSummary';
import { urlKey } from '../src/engine/targetKey';
import type { Finding } from '../src/model';

const N = 64 * 1024;
const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const fill = (p: string) => p.repeat(Math.ceil(N / p.length)).slice(0, N);

/** 繰り返しの形（正規表現の位置ごとの読み直し・閉じのない区切り・入れ子を起こしやすいもの） */
const PATTERNS = ['<!--', '<!-- x', '<script ', '<a href="', '<form ', '<input type=password ', '"', "'", '\\', '[', '{"a":', '-', '_', 'a.', 'ab.', 'a@', '//a@',
  '%2B', '%25', '&', ';', '=', ':', 'eyJ', 'eyJa.', 'nonce-', "'nonce-a", 'https://', 'http://evil.example/', '#META ', '#TARGET ', 'password=', '"password":"',
  'aaaa', 'A1b2', ' ', '\t', '…(1 chars)', 'a-', 'a_b', 'x:y@', '?a=', '/a', 'a/', '(S(', 'sha256-', 'pass ', 'CONNECTED(1)\n', 'HTTP/1.1 200 OK\n',
  // 第40回の束6：全角・ゼロ幅の名前、番号の形、パスワードの名前の値
  '?ａ', '&ｐａｓｓ\u200b', '\u200b', '1234 ', '1234-', '1234.', '123-45-', '4111 1111 1111 1111 ', 'password: secure ', '"cvv":1',
  // 第48回：エンコードした URL のユーザー情報・エンコードした区切りの番号・ユーザー名と組の p=・区切りのある番号
  '%2F%2Fa%3A', '%3A//a:', '%253A%252F%252F', '1234%20', '123%2D45%2D', '?u=a&p=', 'QWER-', 'a1b2-',
  '.%2F%2F%40', '=%2F%2F%40', 'a.%2F%2F%2540', 'https:%2F%2Fa:', '?u=a&p=…(1 chars) '];

describe('2乗の時間にならない', { tags: ['perf'] }, () => {
  it.each(PATTERNS)('本文・ヘッダに「%s」の繰り返し', p => {
    const v = fill(p).replace(/[\r\n]/g, ' ');
    const input = [
      '#TARGET url=https://a.example/ label=page run=0123456789abcdef', '#META at=2026-11-01T10:00:00 run=0123456789abcdef', 'HTTP/2 200', 'content-type: text/html',
      `content-security-policy: script-src ${v}`, `server: ${v}`, `set-cookie: sid=${v}; Path=/`, '', fill(p), '',
      '#TARGET url=https://a.example/api label=api run=0123456789abcdef', 'HTTP/2 302', `location: https://a.example/${v}`, 'content-type: application/json', '', `{"a":"${v.replace(/"/g, '')}"}`, ''].join('\n');
    let findings: Finding[] = [];
    const t = ms(() => { findings = runAll(parseInput(input).targets); });
    expect(t, `${p}: ${Math.round(t)}ms`).toBeLessThan(4000);
    // 差分（前回の結果の証跡に同じ値）
    const before = findings.map(f => ({ ...f, evidence: `${f.evidence} ${v}` }));
    expect(ms(() => diff(before, findings)), `diff ${p}`).toBeLessThan(1500);
  });

  it.each(PATTERNS)('マスク・要約・キーに「%s」の繰り返し', p => {
    const v = fill(p);
    for (const [name, f] of [['maskText', maskText], ['showText', showText], ['summarizeCommand', summarizeCommand], ['urlKey', (s: string) => urlKey(`https://a.example/${s}`)]] as const)
      expect(ms(() => f(v)), `${name} ${p}`).toBeLessThan(1500);
  });
});

describe('第49回：HAR の転送のつなぎ方が2乗の時間にならない', { tags: ['perf'] }, () => {
  it('同じ URL へ転送する 302 と、メソッドの違う同じ URL のエントリが多い HAR', async () => {
    const { importHar } = await import('../src/parser/har');
    const e = (method: string, url: string, status: number, loc?: string) => ({ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method, url, headers: [] }, response: { status, httpVersion: 'HTTP/2', headers: loc ? [{ name: 'location', value: loc }] : [], content: { mimeType: 'text/html', text: '' } } });
    const N = 20000;
    const entries = [
      ...Array.from({ length: N }, (_, i) => e('GET', `https://a.example/p${i}`, 302, '/login')),
      ...Array.from({ length: N }, () => e('POST', 'https://a.example/login', 200)),
    ];
    const har = JSON.stringify({ log: { entries } });
    expect(ms(() => importHar(har)), 'importHar').toBeLessThan(4000);
  });
  it('転送先の URL の使っていないエントリが、転送元より前に多くある HAR', async () => {
    const { importHar } = await import('../src/parser/har');
    const e = (url: string, status: number, loc?: string) => ({ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method: 'GET', url, headers: [] }, response: { status, httpVersion: 'HTTP/2', headers: loc ? [{ name: 'location', value: loc }] : [], content: { mimeType: 'text/html', text: '' } } });
    const N = 15000;
    const entries = [
      ...Array.from({ length: N }, (_, i) => e(`https://a.example/a${i}`, 302, `/b${i}`)),
      ...Array.from({ length: N }, () => e('https://a.example/x', 200)),
      ...Array.from({ length: N }, (_, i) => e(`https://a.example/b${i}`, 302, '/x')),
    ];
    const har = JSON.stringify({ log: { entries } });
    expect(ms(() => importHar(har)), 'importHar').toBeLessThan(4000);
  });
});
