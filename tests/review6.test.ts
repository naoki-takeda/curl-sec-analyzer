// 6回目のレビュー（リポジトリ全体、独立した3人のレビュアー）で見つかった不具合の再現テスト
import { afterEach, describe, expect, it, vi } from 'vitest';
import { harTargets, importHar } from '../src/parser/har';
import { parseOpenssl } from '../src/parser/openssl';
import { runAll } from '../src/engine/run';
import { coverage } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toCsv } from '../src/export/csv';
import { toJson } from '../src/export/json';
import { toMarkdown } from '../src/export/markdown';
import type { Profile } from '../src/model';
import { evaluate } from './helpers';

type H = { name: string; value: string };
const entry = (url: string, status: number, headers: H[], extra: Record<string, unknown> = {}) => ({
  startedDateTime: '2026-11-01T00:00:00Z',
  request: { method: 'GET', url, headers: [] as H[] },
  response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' }, ...extra },
});
const harRun = (entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets } = harTargets(imp, new Set(imp.hosts));
  return { targets, findings: runAll(targets) };
};
const exportsOf = (r: ReturnType<typeof harRun> | ReturnType<typeof evaluate>) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};

describe('HAR：1つのヘッダに改行でつないだ Set-Cookie', () => {
  const SECRET = 'SEKRETsessionValue0123456789abcd';
  const r = () => harRun([entry('https://www.example.com/', 200, [
    { name: 'content-type', value: 'text/html; charset=utf-8' },
    // 1つ目の Cookie に Secure がないと、その証跡（Set-Cookie の行）に2つ目の Cookie がつながって出ていた
    { name: 'set-cookie', value: `theme=dark; Path=/\nsessionid=${SECRET}; Path=/` },
  ])]);
  it('2つ目以降の Cookie の値を、画面とエクスポートに出さない', () => {
    const x = r();
    expect(JSON.stringify(x.findings)).not.toContain(SECRET);
    expect(exportsOf(x)).not.toContain(SECRET);
  });
  it('2つ目以降の Cookie も判定する（セッションCookieの Secure・HttpOnly なし）', () => {
    expect(r().findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['C-01.1', 'C-02.1']));
  });
});

describe('Markdown：外から来た文字列で見出し・画像・リンクを差し込めない', () => {
  it('応答のヘッダに書かれた画像・リンクの記法をエスケープする', () => {
    const r = evaluate('#TARGET url=https://x.example/ label=top\nHTTP/2 200\ncontent-type: text/html\nserver: nginx/1.0 ![pixel](https://attacker.example/p.png) [Click](https://attacker.example/)\n\n');
    const md = toMarkdown(r.findings, coverage(r.findings, IMPLEMENTED), []);
    expect(md).toContain('server: nginx/1.0');
    expect(md).not.toMatch(/(^|[^\\])!\[pixel\]/);
    expect(md).not.toMatch(/(^|[^\\])\[Click\]/);
  });
  it('プロファイル名・前回の日時・ルールセットの警告に改行や HTML を入れても、行が増えない', () => {
    const profile: Profile = { name: 'org\n\n# 偽の見出し', severity: {}, exclude: [], sessionCookieNames: [], sessionMaxAgeHours: 24, trustedScriptOrigins: [] };
    const md = toMarkdown([], [], [], new Date('2026-11-01T00:00:00Z'), { profile,
      diff: { rows: [], baselineAt: '2026\n\n## 指摘なし（全項目合格）\n<img src=https://attacker.example/x>', rulesetWarning: 'x\n## 見出し' } });
    expect(md).not.toMatch(/^# 偽の見出し/m);
    expect(md).not.toMatch(/^## 指摘なし/m);
    expect(md).not.toMatch(/^## 見出し/m);
    expect(md).not.toContain('<img');
  });
});

describe('HAR の Worker：JSON の誤りの文言（入力の断片を含む）を返さない', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });
  it('壊れた HAR では、種類（JSON）だけを返す', async () => {
    const posted: unknown[] = [];
    const self: { onmessage?: (e: MessageEvent<string>) => void; postMessage: (m: unknown) => void } = { postMessage: m => posted.push(m) };
    vi.stubGlobal('self', self);
    await import('../src/worker');
    self.onmessage!({ data: '{"log":{"entries":[{"request":{"headers":[{"name":"Authorization","value":Bearer SEKRETbearer9}]}}]}}' } as MessageEvent<string>);
    expect(posted).toEqual([{ ok: false, error: 'JSON' }]);
  });
});

describe('H-16③：デバッグ用のヘッダの値をマスクする', () => {
  it('x-debug-token・x-debug-token-link の値を出さない', () => {
    const r = evaluate('#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\nx-debug-token: SEKRETdebug12345\nx-debug-token-link: https://www.example.com/_profiler/SEKRETdebug12345\n\n');
    const fs = r.findings.filter(f => f.ruleId === 'H-16.3');
    expect(fs).toHaveLength(2);
    expect(JSON.stringify(fs)).not.toContain('SEKRETdebug12345');
    expect(exportsOf(r)).not.toContain('SEKRETdebug12345');
  });
});

describe('HAR：http から https に転送されたチェーン', () => {
  const chain = () => harRun([
    entry('http://www.example.com/', 301, [{ name: 'location', value: 'https://www.example.com/' }], { redirectURL: 'https://www.example.com/' }),
    entry('https://www.example.com/', 200, [{ name: 'content-type', value: 'text/html; charset=utf-8' }, { name: 'set-cookie', value: 'sessionid=abcdefabcdefabcdefabcdefabcdefab; Path=/' }]),
  ]);
  it('最後の https の応答で H-01 と Cookie の項目を判定する', () => {
    const ids = chain().findings.map(f => f.ruleId);
    expect(ids).toEqual(expect.arrayContaining(['H-01.1', 'C-01.1', 'C-02.1']));
  });
  it('http ラベルにしたチェーンは、転送元の http の URL のまま（T-04 で判定する）', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [
      entry('http://www.example.com/', 301, [{ name: 'location', value: 'https://www.example.com/' }], { redirectURL: 'https://www.example.com/' }),
      entry('https://www.example.com/', 200, [{ name: 'content-type', value: 'text/html' }]),
    ] } }));
    imp.chains[0].label = 'http';
    expect(harTargets(imp, new Set(imp.hosts)).targets[0].url).toBe('http://www.example.com/');
  });
});

describe('採取時刻：#META at がなければ応答の Date ヘッダで期限を比べる', () => {
  it('前に採取した出力でも、採取時に有効だったセッションCookieを削除用とみなさない', () => {
    const r = evaluate('#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\ndate: Mon, 03 Nov 2025 00:00:00 GMT\nset-cookie: sessionid=abcdefabcdefabcdefabcdefabcdefab; Path=/; Expires=Tue, 04 Nov 2025 00:00:00 GMT\n\n');
    expect(r.ids('top')).toEqual(expect.arrayContaining(['C-01.1', 'C-02.1']));
  });
});

describe('A-01③：HTTP の応答の Basic 認証だけを指摘する', () => {
  const a01 = (head: string) => evaluate(`#TARGET url=http://staging.example.com/ label=http\n${head}\n`).findings.filter(f => f.item === 'A-01').map(f => f.ruleId);
  it('-L で https に転送した先の Basic は指摘しない', () => {
    expect(a01('HTTP/1.1 301 Moved Permanently\nlocation: https://staging.example.com/\n\nHTTP/2 401\nwww-authenticate: Basic realm="staging"\n')).not.toContain('A-01.3');
  });
  it('HTTP の応答なら、2つ目のチャレンジの Basic も指摘する', () => {
    expect(a01('HTTP/1.1 401 Unauthorized\nwww-authenticate: Bearer realm="a"\nwww-authenticate: Basic realm="b"\n')).toContain('A-01.3');
  });
});

describe('T-10②：OpenSSL 3 の EC 鍵のチェーンで、ルート証明書の SHA-1 を指摘しない', () => {
  const lines = [
    'CONNECTED(00000003)', '---', 'Certificate chain',
    ' 0 s:CN = example.com', '   i:C = US, O = Let\'s Encrypt, CN = E5', '   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA384',
    ' 1 s:C = US, O = Let\'s Encrypt, CN = E5', '   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1', '   a:PKEY: id-ecPublicKey, 384 (bit); sigalg: RSA-SHA256',
    ' 2 s:C = US, O = Internet Security Research Group, CN = ISRG Root X1', '   i:O = Digital Signature Trust Co., CN = DST Root CA X3', '   a:PKEY: rsaEncryption, 4096 (bit); sigalg: RSA-SHA256',
    ' 3 s:O = Digital Signature Trust Co., CN = DST Root CA X3', '   i:O = Digital Signature Trust Co., CN = DST Root CA X3', '   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA1',
    '---',
  ];
  it('鍵の種類はリーフ（EC 256bit）、署名は証明書の番号ごと', () => {
    const info = parseOpenssl(lines)!;
    expect([info.keyType, info.keyBits]).toEqual(['id-ecPublicKey', 256]);
    expect(info.sigalgs).toEqual(['ecdsa-with-SHA384', 'RSA-SHA256', 'RSA-SHA256', 'RSA-SHA1']);
  });
  it('自己署名のルート（DST Root CA X3）の SHA-1 は T-10② にしない', () => {
    const r = evaluate(`#TARGET url=https://example.com/ label=tls\n#META at=2026-11-01T00:00:00\n${lines.join('\n')}\n`);
    expect(r.findings.filter(f => f.item === 'T-10').map(f => f.ruleId)).not.toContain('T-10.2');
  });
});

describe('E-11①：アップロードしたファイルらしいURLだけを対象にする', () => {
  const e11 = (url: string, ct = 'text/html; charset=utf-8') => evaluate(`#TARGET url=${url} label=t\nHTTP/2 200\ncontent-type: ${ct}\n\n<p>x</p>\n`).findings.filter(f => f.item === 'E-11').map(f => f.ruleId);
  it('/media/・/download/ の下の普通の HTML ページは対象外', () => {
    expect(e11('https://www.example.com/media/press-releases/')).toEqual([]);
    expect(e11('https://www.example.com/download/')).toEqual([]);
  });
  it('アップロード先のファイルを inline の text/html・SVG で配信すれば①', () => {
    expect(e11('https://www.example.com/uploads/2026/report.html')).toContain('E-11.1');
    expect(e11('https://www.example.com/media/avatar.svg', 'image/svg+xml')).toContain('E-11.1');
  });
});
