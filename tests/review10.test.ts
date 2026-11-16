// 10回目のレビュー（リポジトリ全体、独立した4人のレビュアー）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { runAll } from '../src/engine/run';
import { coverage } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { tags } from '../src/rules/html';
import { toCsv } from '../src/export/csv';
import { toJson } from '../src/export/json';
import { toMarkdown } from '../src/export/markdown';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const HSTS = 'strict-transport-security: max-age=31536000';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const exportsOf = (r: { targets: Parameters<typeof toCsv>[1]; findings: Parameters<typeof toCsv>[0] }) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [JSON.stringify(r.findings), toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);

type H = { name: string; value: string };
const entry = (url: string, status: number, headers: H[], reqHeaders: H[] = [], mimeType = 'text/html') => ({
  startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: reqHeaders },
  response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType, text: '<p>x</p>' } } });
const har = (...entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets, warnings } = harTargets(imp, new Set(imp.hosts));
  return { imp, targets, warnings, findings: runAll(targets) };
};
const failIds = (fs: { ruleId: string; status: string }[]) => fs.filter(f => f.status === 'fail').map(f => f.ruleId);

const TOK = 'AbCdEfGh1234567890XyZ';

describe('1 マスク：完全な URL 以外の場所にあるパスのトークン', () => {
  it('相対パス・パラメータの値・エンコードしたパス・フラグメントのルートのトークンを伏せる', () => {
    for (const s of [`/password/reset/${TOK}`, `https://www.example.com/login?next=/invite/accept/${TOK}`, `?returnTo=%2Finvite%2Faccept%2F${TOK}`,
      `redirect_uri=https%3A%2F%2Fwww.example.com%2Freset%2F${TOK}`, `https://app.example.com/#/reset/${TOK}`, `<script src="//cdn.example/1/${TOK}/w.js">`,
      `/files/${TOK}.pdf`, `/bot123456789:${TOK}/send`]) {
      const m = maskText(s);
      expect(m, s).not.toContain(TOK);
      expect(maskText(m)).toBe(m);
    }
    expect(maskText('/reset/MTIzNDU2Nzg5MDEyMzQ1Ng==')).not.toContain('MTIzNDU2Nzg5MDEyMzQ1Ng');
  });
  it('普通のパス（日付やハッシュ付きのファイル名）は残す', () => {
    for (const s of ['https://www.example.com/news/2026-annual-report-v2/index.html', '/static/js/main.3f8a9c2e1b4d5f6a.js', '/api/v1/users/12345/orders'])
      expect(maskText(s)).toBe(s);
  });
  it('E-12・A-01② の証跡とエクスポートに、相対パスのトークンを出さない', () => {
    const form = evaluate(t('top', 'https://a.example/', HTML, `<form method="post" action="/password/reset/${TOK}"><input name="q"></form>`, 'sensitive=1'));
    expect(form.findings.map(f => f.ruleId)).toContain('E-12.1');
    expect(exportsOf(form)).not.toContain(TOK);
    const loc = evaluate(t('unauth-api', 'https://a.example/api/me', `HTTP/2 302\nlocation: /login/continue/${TOK}`));
    expect(loc.findings.map(f => f.ruleId)).toContain('A-01.2');
    expect(exportsOf(loc)).not.toContain(TOK);
  });
});

describe('2 CSV：#META の実施コマンド', () => {
  it('コマンドに含まれるトークンを伏せる', () => {
    const r = evaluate(`#TARGET url=https://www.example.com/ label=page\n#META cmd=curl_https://www.example.com/?access_token=SECRETsecret0123456789 at=2026-11-01T00:00:00Z\n${HTML}\n\n<html></html>\n`);
    const csv = toCsv(r.findings, r.targets);
    expect(csv).toContain('curl https://www.example.com/?access_token,');   // 第31回から、URL は突き合わせのキーの形（クエリは名前だけ）
    expect(csv).not.toContain('SECRETsecret0123456789');
  });
});

describe('3 ASP.NET の CSRF 対策用 Cookie', () => {
  it('セッションCookie とみなさない（C-01①・C-03① にしない）', () => {
    const head = (c: string) => t('top', 'https://a.example/', `${HTML}\n${HSTS}\nset-cookie: ${c}`);
    expect(ids(head('.AspNetCore.Antiforgery.Xy=CfDJ8AAAAAAAAAAAAAAAAAAAAAAA; path=/; samesite=strict; httponly'), 'C-01')).not.toContain('C-01.1');
    const rvt = evaluate(head('__RequestVerificationToken=CfDJ8AAAAAAAAAAAAAAAAAAAAAAA; path=/; HttpOnly')).findings.map(f => f.ruleId);
    expect(rvt).not.toContain('C-01.1');
    expect(rvt).not.toContain('C-03.1');
  });
});

describe('4 A-07：英語の翻訳用 JSON', () => {
  const api = (body: string) => t('api', 'https://a.example/api/x', 'HTTP/2 200\ncontent-type: application/json', body);
  it('画面の文言（"password":"Password"）は A-07① にしない', () => {
    expect(ids(api('{"login":{"username":"Username","password":"Password","newPassword":"New Password"}}'), 'A-07')).not.toContain('A-07.1');
  });
  it('秘密らしい値なら A-07① のまま', () => {
    expect(ids(api('{"user":{"name":"a","password":"hunter2x9"}}'), 'A-07')).toContain('A-07.1');
  });
});

describe('5 T-04：HTTP を 4xx で断る', () => {
  it('403 は ①にしない。HTTP で 200 を返せば ①のまま', () => {
    expect(ids(t('http', 'http://a.example/', 'HTTP/1.1 403 Forbidden\ncontent-type: text/html', '<p>forbidden</p>'), 'T-04')).toEqual(['T-04.ok']);
    expect(ids(t('http', 'http://a.example/', HTML, '<p>x</p>'), 'T-04')).toEqual(['T-04.1']);
  });
});

describe('6 A-02：値がトークンでないパラメータ', () => {
  it('?session=expired・?auth=required は ①にしない。トークンらしい値なら ①', () => {
    expect(ids(t('top', 'https://a.example/', 'HTTP/2 302\nlocation: /login?session=expired'), 'A-02')).not.toContain('A-02.1');
    expect(ids(t('top', 'https://a.example/', 'HTTP/2 302\nlocation: /login?auth=required'), 'A-02')).not.toContain('A-02.1');
    expect(ids(t('top', 'https://a.example/', 'HTTP/2 302\nlocation: /cb?access_token=AbCdEf1234567890'), 'A-02')).toContain('A-02.1');
  });
});

describe('7・8 HAR：304 とフラグメント付きの転送', () => {
  it('304（キャッシュの再検証）は既定で除外し、H-01① にしない', () => {
    const r = har(entry('https://www.example.com/', 304, [{ name: 'etag', value: '"x"' }, { name: 'cache-control', value: 'no-cache' }]));
    expect(failIds(r.findings)).not.toContain('H-01.1');
    expect(r.warnings.map(w => w.detail).join()).toContain('304');
  });
  it('Location のフラグメントを除いて次のエントリにつなぐ', () => {
    const r = har(entry('https://www.example.com/', 302, [{ name: 'Location', value: '/app/#/home' }]),
      entry('https://www.example.com/app/', 200, [{ name: 'content-type', value: 'text/html' }, { name: 'strict-transport-security', value: 'max-age=31536000' }]));
    expect(r.imp.chains).toHaveLength(1);
    expect(failIds(r.findings)).not.toContain('H-01.1');
  });
});

describe('9 E-11：サーバ側のページ', () => {
  it('/download/index.php は ①にしない。アップロード先の .html は ①のまま', () => {
    expect(ids(t('top', 'https://a.example/download/index.php', HTML, '<p>x</p>'), 'E-11')).not.toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/uploads/evil.html', HTML, '<p>x</p>'), 'E-11')).toContain('E-11.1');
  });
});

describe('10 C-13：no-store と s-maxage', () => {
  it('no-store があれば共有キャッシュに残らない', () => {
    const login = (cc: string) => t('login', 'https://a.example/login', `${HTML}\ncache-control: ${cc}\nset-cookie: sid=AAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly; SameSite=Lax`, '', 'sensitive=1');
    expect(ids(login('no-store, s-maxage=0'), 'C-13')).toEqual(['C-13.ok']);
    expect(ids(login('public, s-maxage=600'), 'C-13')).toEqual(['C-13.1']);
  });
});

describe('11 curl：http の URL から -L で https に転送されたターゲット', () => {
  const input = (label: string) => `#TARGET url=http://www.example.com/ label=${label}\nHTTP/1.1 301 Moved\nLocation: https://www.example.com/\n\nHTTP/2 200\ncontent-type: text/html\nset-cookie: sessionid=${'B'.repeat(26)}; Path=/\n\n<html></html>\n`;
  it('一般のラベルは HTTPS の応答として H-・C- を判定する', () => {
    const fs = failIds(evaluate(input('page')).findings);
    expect(fs).toEqual(expect.arrayContaining(['H-01.1', 'C-01.1']));
  });
  it('http ラベルは T-04 だけ（HTTPS の項目は判定しない）', () => {
    const fs = evaluate(input('http')).findings.map(f => f.ruleId);
    expect(fs).toContain('T-04.ok');
    expect(fs.some(id => id.startsWith('H-01'))).toBe(false);
  });
});

describe('12・13 HAR：外部サービスの Cookie・公開ファイル・静的リソース', () => {
  const robots = (cookie: string) => har(entry('https://ex.example/robots.txt', 200, [{ name: 'content-type', value: 'text/plain' }, { name: 'cache-control', value: 'public, max-age=600' }],
    [{ name: 'Cookie', value: cookie }], 'text/plain'));
  it('解析・チャット・決済の Cookie だけでは機密とみなさない', () => {
    const r = robots('_hjSessionUser_123=abc; _hjSession_123=def; intercom-session-abcd=ghi; __stripe_sid=jkl');
    expect(r.targets[0].sentAuth).toBe(false);
    expect(failIds(r.findings)).not.toContain('H-12.1');
  });
  it('セッションCookie を送っても、robots.txt は機密応答にしない（H-12①・H-11①）', () => {
    const fs = failIds(robots('laravel_session=abcdef0123456789').findings);
    expect(fs).not.toContain('H-12.1');
    expect(fs).not.toContain('H-11.1');
  });
  it('セッションCookie を送った JS の ACAO: * は R-04①・H-11① にしない', () => {
    const r = har(entry('https://ex.example/app.js', 200, [{ name: 'content-type', value: 'application/javascript' }, { name: 'access-control-allow-origin', value: '*' }],
      [{ name: 'Cookie', value: 'JSESSIONID=abcdef' }], 'application/javascript'));
    const fs = failIds(r.findings);
    expect(fs).not.toContain('R-04.1');
    expect(fs).not.toContain('H-11.1');
  });
});

describe('14 C-03③：負荷分散の Cookie', () => {
  it('AWSALBCORS の SameSite=None は ③にしない。ほかの Cookie なら ③のまま', () => {
    const head = (c: string) => t('top', 'https://a.example/', `${HTML}\n${HSTS}\nset-cookie: ${c}; Expires=Tue, 23 Nov 2027 00:00:00 GMT; Path=/; SameSite=None; Secure`);
    expect(ids(head('AWSALBCORS=abcdefABCDEF0123456789abcdef'), 'C-03')).not.toContain('C-03.3');
    expect(ids(head('prefs=abcdef'), 'C-03')).toContain('C-03.3');
  });
});

describe('15 R-07：認証ではないトークンのヘッダ', () => {
  const expose = (v: string) => t('api', 'https://a.example/api', `HTTP/2 200\ncontent-type: application/json\naccess-control-allow-origin: https://app.example\naccess-control-expose-headers: ${v}`, '{}');
  it('X-CSRF-Token・X-Next-Page-Token は ①にしない。X-Auth-Token は ①', () => {
    expect(ids(expose('X-CSRF-Token, X-Next-Page-Token'), 'R-07')).toEqual(['R-07.ok']);
    expect(ids(expose('X-Auth-Token'), 'R-07')).toEqual(['R-07.1']);
  });
});

describe('16 E-05：GraphQL', () => {
  const gql = (head: string, body: string) => t('top', 'https://a.example/graphql', head, body);
  it('introspection を試していない応答は合格にしない', () => {
    expect(ids(gql('HTTP/2 400\ncontent-type: application/json', '{"errors":[{"message":"Must provide query string."}]}'), 'E-05')).toEqual(['E-05.na']);
    expect(ids(gql('HTTP/2 400\ncontent-type: application/json', '{"errors":[{"message":"GraphQL introspection is not allowed"}]}'), 'E-05')).toEqual(['E-05.ok']);
    expect(ids(gql('HTTP/2 200\ncontent-type: application/json', '{"data":{"__schema":{"types":[]}}}'), 'E-05')).toEqual(['E-05.3']);
  });
});

describe('17 性能', () => {
  const ms = (f: () => void) => { const s = performance.now(); f(); return performance.now() - s; };
  it('-i の本文の中にステータス行らしい行が多くても、入力の長さに比例する時間で読む', () => {
    const body = 'abc\n'.repeat(20_000) + 'HTTP/1.1 200 OK\n'.repeat(50_000);
    expect(ms(() => parseInput(`#TARGET url=https://a.example/ label=t\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n${body}`))).toBeLessThan(1500);
  });
  it('%{header_json} らしい行が続いても、行ごとに全体を解析し直さない', () => {
    expect(ms(() => parseInput('{"date":["x",\n'.repeat(150_000)))).toBeLessThan(1500);
  });
  it('> のない <script の繰り返しでも、タグの読み取りが本文の長さに比例する', () => {
    const block = `"${'<script '.repeat(249)}"`;                   // 引用符で囲んだ <script の並び（> がない。64KB）
    const body = block.repeat(Math.floor(64 * 1024 / block.length));
    expect(ms(() => { for (let i = 0; i < 10; i++) tags(body, ['script', 'iframe', 'link', 'img', 'form']); })).toBeLessThan(300);
  });
  it('ターゲットが多くても、CSV は指摘の数 × ターゲットの数の時間にならない', () => {
    const input = Array.from({ length: 3000 }, (_, i) => t(`t${i}`, `https://a.example/p${i}`, HTML, '<p>x</p>')).join('');
    const { targets } = parseInput(input);
    // 判定は1つのターゲットだけで行い、その指摘をほかのターゲットに写す（準備の時間を測らないため）
    const base = runAll(targets.slice(0, 1)).filter(f => f.status === 'fail');
    const findings = targets.flatMap(tg => base.map(f => ({ ...f, target: tg.label })));
    expect(ms(() => toCsv(findings, targets))).toBeLessThan(1000);
  });
});

describe('tags()：書き換えた走査の振る舞い', () => {
  it('引用符の中の > で止まらず、長い属性も読む。閉じていないタグは飛ばして続きを読む', () => {
    const ts = tags(`<form onsubmit="a>0" action="/x" data-c="${'y'.repeat(5000)}"><script src="/a.js"></script><img src="/i.png`, ['form', 'script', 'img']);
    expect(ts.map(x => [x.name, x.attrs.get('action') ?? x.attrs.get('src')])).toEqual([['form', '/x'], ['script', '/a.js']]);
  });
});
