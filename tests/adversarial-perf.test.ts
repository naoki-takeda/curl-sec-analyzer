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
import { ms } from './helpers';

const N = 64 * 1024;
const fill = (p: string) => p.repeat(Math.ceil(N / p.length)).slice(0, N);

/** 繰り返しの形（正規表現の位置ごとの読み直し・閉じのない区切り・入れ子を起こしやすいもの） */
const PATTERNS = ['<!--', '<!-- x', '<script ', '<a href="', '<form ', '<input type=password ', '"', "'", '\\', '[', '{"a":', '-', '_', 'a.', 'ab.', 'a@', '//a@',
  '%2B', '%25', '&', ';', '=', ':', 'eyJ', 'eyJa.', 'nonce-', "'nonce-a", 'https://', 'http://evil.example/', '#META ', '#TARGET ', 'password=', '"password":"',
  'aaaa', 'A1b2', ' ', '\t', '…(1 chars)', 'a-', 'a_b', 'x:y@', '?a=', '/a', 'a/', '(S(', 'sha256-', 'pass ', 'CONNECTED(1)\n', 'HTTP/1.1 200 OK\n',
  // 第40回の束6：全角・ゼロ幅の名前、番号の形、パスワードの名前の値
  '?ａ', '&ｐａｓｓ\u200b', '\u200b', '1234 ', '1234-', '1234.', '123-45-', '4111 1111 1111 1111 ', 'password: secure ', '"cvv":1',
  // 第48回：エンコードした URL のユーザー情報・エンコードした区切りの番号・ユーザー名と組の p=・区切りのある番号
  '%2F%2Fa%3A', '%3A//a:', '%253A%252F%252F', '1234%20', '123%2D45%2D', '?u=a&p=', 'QWER-', 'a1b2-',
  '.%2F%2F%40', '=%2F%2F%40', 'a.%2F%2F%2540', 'https:%2F%2Fa:', '?u=a&p=…(1 chars) ',
  // 第49回：// の数が標準でない URL、引用符と @、フラグメントの p=、日本語の名前
  'https:\\a:', 'http:/a:', "a'@", '#u=a&p=', '?パ=',
  // 第50回：値の中の生の ;、長いパラメータの名前、pass で終わる名前、配列の値
  '?password=a;', ';a', '&aaaaaaaaaa', 'xpass=', 'password":["',
  '"password":[[', 'password: [a, ', ';a a ', '%22password%22%3A%5B', 'password":[{"v":"',
  // 第51回：配列の空の要素、オブジェクトの値、CSP の ;、エスケープした //
  '"password":["",', '"password":{"v":"', ';script-src ', 'a:\\/\\/b:',
  // 第54回：ハイフンのあとの eyJ（\b は - と e の間でも一致するので、位置ごとに並びの終わりまで読み直す）、値の中の ; の並び、同じ深さの %40、生の区切りでつないだエンコードの並び
  '-eyJ', '-eyJa.', '-eyJaaaaaaaaaa.eyJ', '?password=a;;', ';;;;;;;;Secure', 'a;;',
  'https%3A%2F%2Fa%3Ab%40', '%40a', '%3A%40', '%31-', '%31%31-', '%E3%81%8A.', '1%31 ', '%3D1-', '%2F%2Fa%3Ab@', '%2540'];

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

describe('第54回：送ったヘッダの JWT の読み取りが2乗の時間にならない', { tags: ['perf'] }, () => {
  it.each(['-eyJ', '-eyJa.', '-eyJaaaaaaaaaa.eyJ'])('-v の Authorization・Cookie に「%s」の繰り返し', p => {
    const v = fill(p);
    const input = ['#TARGET url=https://a.example/ label=page', '* Connected to a.example (192.0.2.1) port 443', '> GET / HTTP/2', '> Host: a.example',
      `> Authorization: Bearer ${v}`, `> Cookie: a=${v}`, '>', '< HTTP/2 200', '< content-type: text/html', '<', ''].join('\n');
    const { targets } = parseInput(input);
    expect(targets[0].responses.length, '-v として読む').toBe(1);
    expect(ms(() => runAll(parseInput(input).targets)), `parse+runAll ${p}`).toBeLessThan(1500);
  });
  it.each(['-eyJ', '-eyJa.'])('HAR の Authorization・Cookie に「%s」の繰り返し', async p => {
    const { importHar } = await import('../src/parser/har');
    const v = fill(p);
    const har = JSON.stringify({ log: { entries: [{ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method: 'GET', url: 'https://a.example/', headers: [{ name: 'Authorization', value: `Bearer ${v}` }, { name: 'Cookie', value: `a=${v}` }] },
      response: { status: 200, httpVersion: 'HTTP/2', headers: [], content: { mimeType: 'text/html', text: '' } } }] } });
    expect(ms(() => importHar(har)), `importHar ${p}`).toBeLessThan(1500);
  });
});

describe('第54回（2回目の束のレビュー）：%25 を重ねた数字の並びが2乗の時間・スタックのあふれにならない', { tags: ['perf'] }, () => {
  it('ターゲットの URL と証跡に、%25 を数万段重ねた数字', () => {
    const v = '1-%' + '25'.repeat(32000) + '31';
    expect(ms(() => showText(v)), 'showText').toBeLessThan(1500);
    const input = [`#TARGET url=https://a.example/?x=${v} label=page`, 'HTTP/2 200', 'content-type: text/html', '', '<html></html>', ''].join('\n');
    expect(ms(() => runAll(parseInput(input).targets)), 'parse+runAll').toBeLessThan(4000);
  });
  it('エンコードしたユーザー情報のあとの @ の繰り返し', () => {
    expect(ms(() => showText('?r=https%3A%2F%2Fa%3A' + 'b@'.repeat(32000))), 'showText').toBeLessThan(1500);
  });
});

describe('第50回：Set-Cookie の多い応答の判定が長くならない', { tags: ['perf'] }, () => {
  it('5MB の Set-Cookie の行', () => {
    const lines = ['#TARGET url=https://a.example/ label=page', 'HTTP/2 200', 'content-type: text/html'];
    for (let n = 0, len = 0; len < 5_000_000; n++) { const l = `set-cookie: sess${n}=v${n}abcdefghijklmnop; Path=/; Secure; HttpOnly; SameSite=Lax`; lines.push(l); len += l.length + 1; }
    lines.push('', '<html></html>', '');
    const input = lines.join('\n');
    expect(ms(() => runAll(parseInput(input).targets)), 'parse+runAll').toBeLessThan(4000);
  });
});

describe('ルールの本文の走査が2乗の時間にならない', { tags: ['perf'] }, () => {
  const page = (label: string, url: string, body: string) => [`#TARGET url=${url} label=${label}`, '#META at=2026-11-01T10:00:00', 'HTTP/2 200', 'content-type: text/html', '', body, ''].join('\n');
  it.each(['<form>', '<form></form>', '<form><input type=password>', '<form method=post><input type=hidden name=a></form>'])('E-09・E-10・E-12：本文に「%s」の繰り返し', p => {
    const input = page('page', 'https://a.example/', fill(p));
    expect(ms(() => runAll(parseInput(input).targets)), p).toBeLessThan(1500);
  });
  it('E-01①：本文に「jdbc:oracle:thin:u/」の繰り返し', () => {
    const input = page('error-500', 'https://a.example/x', fill('jdbc:oracle:thin:u/'));
    expect(ms(() => runAll(parseInput(input).targets)), 'E-01').toBeLessThan(1500);
  });
  it('C-12①：after-logout の本文のスクリプトに長い語の代入', () => {
    const shell = (s: string) => `<div id="root"></div><script>${s}</script>`;
    // 代入（a = {}）があるとスクリプトの中身を STATE_DATA で読む。長い語の各位置から名前を読み直すと2乗の時間になる
    const input = [page('logout', 'https://a.example/logout', ''), page('after-logout', 'https://a.example/mypage', shell(`var a = {}; ${'user'.repeat(16000)}`))].join('');
    expect(ms(() => runAll(parseInput(input).targets)), 'C-12').toBeLessThan(1500);
  });
});
