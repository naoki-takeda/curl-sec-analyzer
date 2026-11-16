// 12回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前のコミットの前後を比べたもの、実物の curl 8.22・OpenSSL 3.5 の出力を含む）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { urlKey } from '../src/engine/targetKey';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { runAll } from '../src/engine/run';
import { coverage } from '../src/engine/coverage';
import { legacyHarKey } from '../src/engine/targetKey';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toCsv } from '../src/export/csv';
import { toJson } from '../src/export/json';
import { toMarkdown } from '../src/export/markdown';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const HSTS = 'strict-transport-security: max-age=31536000';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[]) =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', ''].join('\n');
const exportsOf = (r: { targets: Parameters<typeof toCsv>[1]; findings: Parameters<typeof toCsv>[0] }) => {
  const cov = coverage(r.findings, IMPLEMENTED);
  return [JSON.stringify(r.findings), toMarkdown(r.findings, cov, []), toCsv(r.findings, r.targets), toJson(r.findings, cov, [])].join('\n');
};
type H = { name: string; value: string };
const entry = (url: string, status: number, headers: H[], req: H[] = [], mimeType = 'text/html', text = '<p>x</p>') => ({
  startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: req }, response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType, text } } });
const har = (...entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets } = harTargets(imp, new Set(imp.hosts));
  return { imp, targets, findings: runAll(targets) };
};

describe('1 突き合わせのキーをマスクから切り離す', () => {
  it('キーはスキーム・ホスト・パス（トークンは *）とパラメータの名前だけ。値もマスクの一覧も入らない', () => {
    expect(urlKey('https://a.example/reset?hash=9f86d081884c7d65&pin=4821')).toBe('https://a.example/reset?hash&pin');
    expect(urlKey('https://a.example/list?postal_code=1000001&state=af0ifjsldkj7Xyz#frag')).toBe('https://a.example/list?postal_code&state');
    expect(urlKey('https://user:pw@a.example/reset/AbCdEfGh1234567890XyZ/x?code=1')).toBe('https://a.example/reset/*/x?code');
    expect(urlKey('https://a.example/(S(lit3py55t21z5v55vlm25s55))/default.aspx')).toBe('https://a.example/(*)/default.aspx');
  });
  it('HAR の targetKey は新しい形で、以前の形（値を伏せた「…」や「=」を含む）は見分けられる', () => {
    const r = har(entry('https://a.example/cb?code=Splx0123abcdefghij&state=s', 200, [{ name: 'content-type', value: 'text/html' }]));
    expect(r.findings[0].targetKey).toBe('HAR GET https://a.example/cb?code&state');
    expect(legacyHarKey('HAR GET https://a.example/cb?code=…&state=s')).toBe(true);
    expect(legacyHarKey(r.findings[0].targetKey)).toBe(false);
  });
});

describe('2 curl 8.22 の進捗表示', () => {
  it('時刻の欄が 00:02 や空欄でも、ステータス行の前の進捗表示を取り除き、進捗表示の行は読み飛ばす', () => {
    const input = ['#TARGET url=https://a.example/ label=t', '  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current',
      '                                 Dload  Upload  Total   Spent   Left   Speed', '* Connected to a.example (192.0.2.1) port 443', '> GET / HTTP/1.1', '>',
      '  0      0   0      0   0      0      0      0           00:02              0< HTTP/1.1 200 OK', '< Content-Type: text/html', '<',
      '100   1256 100   1256   0      0   5432      0           00:01              5437', ''].join('\n');
    const r = parseInput(input);
    expect(r.targets[0].responses.map(x => x.status)).toEqual([200]);
    expect(r.warnings.map(w => w.kind)).not.toContain('unparsed-lines');
  });
  it('本文の日時の行や数字の行は消さない', () => {
    const r = parseInput(t('t', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/plain', '2026-11-01 12:00:00\n1 2 3 4 5 6 7 8 9'));
    expect(r.targets[0].responses[0].body).toContain('2026-11-01 12:00:00');
    expect(r.targets[0].responses[0].body).toContain('1 2 3 4 5 6 7 8 9');
  });
});

describe('3 H-16⑤：Server-Timing の desc', () => {
  const h16 = (st: string) => evaluate(t('top', 'https://a.example/', `${HTML}\nserver-timing: ${st}`)).findings.filter(f => f.item === 'H-16');
  it('引用符の中のカンマで分けず、desc の中身を証跡に出さない', () => {
    const cdn = h16('cdn-cache;desc="HIT, sk_live_abcdefghijklmnop123"');
    expect(cdn.map(f => f.ruleId)).not.toContain('H-16.5');
    expect(JSON.stringify(cdn)).not.toContain('sk_live_abcdefghijklmnop123');
    const db = h16('db;desc="user lookup, bob@example.com";dur=3');
    expect(db.map(f => f.ruleId)).toContain('H-16.5');
    expect(JSON.stringify(db)).not.toContain('bob@example.com');
  });
});

describe('4 A-07：- や _ を含む、秘密らしいキーの名前', () => {
  it('証跡にキーの名前を出さない', () => {
    for (const k of ['sk-proj-Ab3dEf6hIj9kLm2nOp5q', 'glpat-xYz12AbC34dEf56GhI', 'npm_AbCdEf1234567890AbCdEf1234567890AbCd', 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY', 'a1B2c3D4e5F6g7H8_i9J0kL']) {
      const r = evaluate(t('api', 'https://a.example/api', 'HTTP/2 200\ncontent-type: application/json', JSON.stringify({ apiKeys: { [k]: { secret: 'Zx9Qw8Er7Ty6' } } })));
      expect(r.findings.map(f => f.ruleId), k).toContain('A-07.1');
      expect(exportsOf(r), k).not.toContain(k);
    }
  });
});

describe('5 E-01：資格情報を含む jdbc:', () => {
  it('①だけにする。資格情報のないものは②', () => {
    expect(ids(t('top', 'https://a.example/', 'HTTP/2 500\ncontent-type: text/html', 'jdbc:mysql://app:S3cret@db.internal:3306/app'), 'E-01')).toEqual(['E-01.1']);
    expect(ids(t('top', 'https://a.example/', 'HTTP/2 500\ncontent-type: text/html', 'jdbc:mysql://db.internal:3306/app'), 'E-01')).toEqual(['E-01.2']);
  });
});

describe('6 マスクは冪等', () => {
  it('前の手順で伏せた結果が後の手順の手がかりを変えても、2回目で結果が変わらない', () => {
    for (const s of ["https://a.example/?code=xyz'nonce-abcdef", "nonce-XYZ9nonce-'nonce-nonce-", '?token=abc&x=1 nonce-ABCDEF12', '"password":"p4ss" ?code=1\'nonce-Zz9']) {
      const m = maskText(s);
      expect(maskText(m), s).toBe(m);
    }
  });
});

describe('7 ビルドしたファイルの名前', () => {
  it('Vite・webpack のハッシュ付きの名前は伏せず、別のファイルは別のキーになる。トークンは伏せる', () => {
    for (const n of ['/assets/AdminDashboard-Dk3x9Lq2.js', '/assets/vendor-react-BxYz12Ab.js', '/static/js/main-3f8a9c2e1b4d5f6a7b8c.js']) expect(maskText(n)).toBe(n);
    expect(urlKey('https://a.example/assets/AdminDashboard-Dk3x9Lq2.js')).not.toBe(urlKey('https://a.example/assets/UserProfile-CkL3x9aB.js'));
    expect(maskText('/reset/AbCdEfGh1234567890XyZ')).not.toContain('AbCdEfGh1234567890XyZ');
  });
});

describe('8 深い入れ子の URL のトークン', () => {
  it('4段以上の入れ子でも、秘密の名前のパラメータは伏せる', () => {
    const r = evaluate(t('top', 'https://www.example.com/sso?next=/a?r=/b?r=/c?r=/d?access_token=SuperSecretTokenValue123', HTML, '<p>x</p>'));
    expect(exportsOf(r)).not.toContain('SuperSecretTokenValue123');
    expect(maskText('/x?a=%2Fb%3Fc%3D%2Fd%3Fe%3D%2Ff%3Fg%3D%2Fh%3Faccess_token%3DSuperSecretTokenValue123')).not.toContain('SuperSecretTokenValue123');
  });
});

describe('9・11 C-07② と負荷分散の Cookie', () => {
  const samples = (cookie: (i: number) => string) => [1, 2, 3].map(i => t(`session-sample-${i}`, 'https://a.example/login', `HTTP/2 302\nlocation: /\nset-cookie: ${cookie(i)}`)).join('');
  it('Flask の圧縮したセッションは署名の部分だけで比べる', () => {
    expect(ids(samples(i => `session=.eJwlzjEOwjAMAMC_ZKaQ4zhxuVVIFQMLA8vFTqU3x6Z.ZxYz${i}A.Sig${i}abcXYZ${i}q9w8e7r6t5; HttpOnly; Path=/; Secure`), 'C-07')).not.toContain('C-07.2');
  });
  it('Azure Front Door の ASLBSA・Citrix の NSC_ はセッションCookieとみなさない', () => {
    expect(ids(samples(() => 'ASLBSA=0003abcdefabcdefabcdef0123456789; path=/; secure; httponly'), 'C-07')).not.toContain('C-07.2');
    const fs = evaluate(t('top', 'https://a.example/', `${HTML}\n${HSTS}\nset-cookie: NSC_vsl_xxx=ffffffff09b5a3c545525d5f4f58455e445a4a423660; path=/`)).findings.map(f => f.ruleId);
    expect(fs).not.toContain('C-01.1');
    expect(fs).not.toContain('C-02.1');
  });
});

describe('10 C-09：2xx・3xx でもログインに失敗した応答', () => {
  const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input type="password" name="p"></form>');
  const c09 = (login: string) => evaluate(pre + login).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('ログイン画面への転送・?error・パスワード欄のある画面は na', () => {
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /login?error'))).toEqual(['C-09.na']);
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: https://a.example/login'))).toEqual(['C-09.na']);
    expect(c09(t('login', 'https://a.example/login', HTML, '<form method="post"><input type="password" name="p"></form>'))).toEqual(['C-09.na']);
  });
  it('ログインできて再発行しなければ①のまま', () => {
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /home'))).toEqual(['C-09.1']);
  });
});

describe('12 H-03：<meta http-equiv> の CSP', () => {
  const page = (csp: string) => t('top', 'https://a.example/', HTML, `<html><head><meta http-equiv="Content-Security-Policy" content="${csp}"></head><body></body></html>`);
  it('meta の CSP があれば H-03① にせず、H-04 は meta の CSP で判定する。frame-ancestors は meta では効かない', () => {
    expect(ids(page("default-src 'self'; script-src 'self'"), 'H-03')).toEqual(['H-03.ok']);
    expect(ids(page("default-src 'self'; script-src 'self' 'unsafe-inline'"), 'H-04')).toContain('H-04.1');
    expect(ids(page("default-src 'self'; frame-ancestors 'none'"), 'H-06')).not.toContain('H-06.ok');
  });
});

describe('14・15 送った認証情報', () => {
  it('ALB の認証の Cookie（AWSELBAuthSessionCookie）を送れば機密と推定する', () => {
    expect(ids(v('page', 'https://a.example/app', ['Cookie: AWSELBAuthSessionCookie-0=abcdefghijklmnop'], ['HTTP/2 200', 'Content-Type: text/html', 'Cache-Control: max-age=600']), 'H-12')).toContain('H-12.1');
  });
  it('HAR の Authorization で送った JWT も A-03 で見る（curl の -v と同じ）', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcDEF123';
    const r = har(entry('https://a.example/api/me', 200, [{ name: 'content-type', value: 'application/json' }], [{ name: 'Authorization', value: `Bearer ${jwt}` }], 'application/json', '{}'));
    expect(r.findings.filter(f => f.item === 'A-03').map(f => f.ruleId)).toContain('A-03.2');
    expect(exportsOf(r)).not.toContain('abcDEF123');
  });
});

describe('16 R-01・R-02：Origin を送っていない -v', () => {
  it('合格にせず na', () => {
    const input = v('cors-reflect', 'https://a.example/api', [], ['HTTP/2 200', 'Content-Type: application/json']);
    expect(ids(input, 'R-01')).toEqual(['R-01.na']);
    expect(ids(v('cors-null', 'https://a.example/api', [], ['HTTP/2 200', 'Content-Type: application/json']), 'R-02')).toEqual(['R-02.na']);
  });
});

describe('17 カバレッジ：ほかのラベルと比べる条件が入力不足', () => {
  it('login だけの C-09 は、判定済みのまま理由にそれを示す', () => {
    const r = evaluate(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /home\nset-cookie: sid=AAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly; SameSite=Lax', '', 'sensitive=1'));
    const c = coverage(r.findings, IMPLEMENTED).find(x => x.item === 'C-09')!;
    expect(c.status).toBe('evaluated');
    expect(c.reasons.join()).toContain('一部の条件');
  });
});

describe('18・19 E-09・R-07', () => {
  it('E-09：OIDC の form_post の hidden の id_token は①にしない。スクリプトの JWT は①', () => {
    const tok = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4eHgifQ.c2lnbmF0dXJlc2lnbmF0dXJl';
    expect(ids(t('top', 'https://idp.example/auth', HTML, `<form method="post" action="https://app.example/cb"><input type="hidden" name="id_token" value="${tok}"></form><script>document.forms[0].submit()</script>`), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/', HTML, `<script>var t="${tok}"</script>`), 'E-09')).toContain('E-09.1');
  });
  it('R-07：レート制限のヘッダは①にしない', () => {
    expect(ids(t('api', 'https://a.example/api', 'HTTP/2 200\ncontent-type: application/json\naccess-control-allow-origin: https://app.example\naccess-control-expose-headers: x-ratelimit-limit-tokens, x-ratelimit-remaining-tokens', '{}'), 'R-07')).toEqual(['R-07.ok']);
  });
});

describe('20・21 長い行', () => {
  it('非常に長い Set-Cookie の行でもスタックがあふれない', () => {
    const line = Array.from({ length: 200_000 }, (_, i) => `c${i}=v; Path=/`).join(', ');
    expect(() => parseInput(`#TARGET url=https://a.example/ label=t\nHTTP/2 200\nset-cookie: ${line}\n\n`)).not.toThrow();
  });
  it('} で終わる %{header_json} らしい行が続いても、上限を超えたら解析し直さない', () => {
    const big = 'x'.repeat(10_000);
    const input = `{"date":[{"b":"${big}"}\n` + `,{"b":"${big}"}\n`.repeat(499);
    const s = performance.now(); parseInput(input);
    expect(performance.now() - s).toBeLessThan(500);
  });
});
