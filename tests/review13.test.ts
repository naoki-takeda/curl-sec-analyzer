// 13回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前の修正の前後の比較、回帰テストのコミットの確認を含む）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { urlKey } from '../src/engine/targetKey';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { runAll } from '../src/engine/run';
import { diff } from '../src/engine/diff';
import { legacyHarKey } from '../src/engine/targetKey';
import { coverage } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toJson } from '../src/export/json';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const HSTS = 'strict-transport-security: max-age=31536000';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
type H = { name: string; value: string };
const entry = (url: string, status: number, headers: H[], req: H[] = [], mimeType = 'text/html', text = '<p>x</p>', method = 'GET') => ({
  startedDateTime: '2026-11-01T00:00:00Z', request: { method, url, headers: req }, response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType, text } } });
const har = (...entries: unknown[]) => {
  const imp = importHar(JSON.stringify({ log: { entries } }));
  const { targets } = harTargets(imp, new Set(imp.hosts));
  return { imp, targets, findings: runAll(targets) };
};

describe('1・9 突き合わせのキーに秘密を入れない', () => {
  it('パス引数の値・%2B を含むトークン・記号の付いたトークン・JWT の名前を * にし、パラメータの名前を並べ替える', () => {
    expect(urlKey('https://www.example.com/app/index.jsp;jsessionid=CANARY0SESSION1A2B3C4D5E6F7A8B9')).toBe('https://www.example.com/app/index.jsp;jsessionid');
    for (const u of ['https://a.example/reset/Zx8Kq2Lm9Np4Rt7W%2B%2Fabc%3D%3D', 'https://a.example/a/Zq8xLr2Nw7Kp4Ty9Bv1H,v2', 'https://a.example/auth?eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln'])
      expect(urlKey(u), u).not.toMatch(/Zx8K|Zq8x|eyJ/);
    expect(urlKey('https://a.example/x?token=x&page=1')).toBe(urlKey('https://a.example/x?page=1&token=y'));
  });
  it('普通の名前は残し、別のファイル・別のページは別のキーにする', () => {
    expect(urlKey('https://a.example/news/2026-annual-report-v2/index.html')).toBe('https://a.example/news/2026-annual-report-v2/index.html');
    expect(urlKey('https://a.example/assets/AdminDashboard-Dk3x9Lq2.js')).not.toBe(urlKey('https://a.example/assets/UserProfile-CkL3x9aB.js'));
    expect(urlKey('https://a.example/x?page=1')).not.toBe(urlKey('https://a.example/x?page=2'));
  });
  it('HAR の JSON のエクスポートにセッションIDを出さない', () => {
    const r = har(entry('https://www.example.com/shop/cart.do;jsessionid=A1b2C3d4CANARYxyz0123456789', 200, [{ name: 'content-type', value: 'text/html' }]));
    expect(toJson(r.findings, coverage(r.findings, IMPLEMENTED), [])).not.toContain('CANARY');
  });
});

describe('2 C-09：ログインに成功してトップに転送される流れ', () => {
  const pre = (url: string) => t('pre-login', url, `${HTML}\nset-cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input type="password" name="p"></form>');
  const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('pre-login がトップ（/）でも、/ への転送は失敗ではない', () => {
    expect(c09(pre('https://app.example/') + t('login', 'https://app.example/login', 'HTTP/2 302\nlocation: /'))).toEqual(['C-09.1']);
  });
  it('クエリで画面を切り替えるアプリ：?_task=login への転送は失敗、?_task=mail は成功', () => {
    const u = 'https://mail.example/?_task=login';
    expect(c09(pre(u) + t('login', u, 'HTTP/2 302\nlocation: ./?_task=mail'))).toEqual(['C-09.1']);
    expect(c09(pre(u) + t('login', u, 'HTTP/2 302\nlocation: ./?_task=login'))).toEqual(['C-09.na']);
  });
});

describe('3 同じキーの番号', () => {
  it('HAR で同じ URL を何度も取得しても番号を付けない', () => {
    const e = () => entry('https://a.example/api/poll', 200, [{ name: 'content-type', value: 'application/json' }], [], 'application/json', '{}');
    const keys = new Set(har(e(), e(), e()).findings.filter(f => f.targetKey).map(f => f.targetKey));
    expect([...keys]).toEqual(['HAR GET https://a.example/api/poll']);
  });
  it('curl で ?page=1 と ?page=2 を同じラベルにしても、貼り付けの順番で差分が出ない', () => {
    const a = t('top', 'https://a.example/list?page=1', HTML, '<p>1</p>'), b = t('top', 'https://a.example/list?page=2', `${HTML}\n${HSTS}`, '<p>2</p>');
    const f1 = evaluate(a + b).findings, f2 = evaluate(b + a).findings;
    expect(diff(f1, f2).filter(r => r.kind !== 'continuing')).toEqual([]);
  });
});

describe('4 A-03：HAR で同じ JWT を送ったエントリ', () => {
  it('指摘は1回だけ', () => {
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const jwt = `${b64({ alg: 'HS256' })}.${b64({ sub: 'x', email: 'a@example.com' })}.c2lnbmF0dXJl`;
    const e = (i: number) => entry(`https://a.example/api/x${i}`, 200, [{ name: 'content-type', value: 'application/json' }], [{ name: 'Authorization', value: `Bearer ${jwt}` }], 'application/json', '{}');
    const fs = har(e(1), e(2), e(3), e(4), e(5)).findings.filter(f => f.item === 'A-03' && f.status === 'fail');
    expect(fs.map(f => f.ruleId).sort()).toEqual(['A-03.2', 'A-03.3']);
  });
});

describe('5・13 H-03：meta の CSP と本文のない採取', () => {
  it('<body> の中の meta の CSP では合格にしない', () => {
    expect(ids(t('top', 'https://a.example/', HTML, '<html><head></head><body><meta http-equiv="Content-Security-Policy" content="default-src *"></body></html>'), 'H-03')).toEqual(['H-03.1']);
  });
  it('ヘッダがなく本文も採取していなければ na（meta の CSP があるかが分からない）', () => {
    expect(ids(t('top', 'https://a.example/', HTML), 'H-03')).toEqual(['H-03.na']);
    expect(ids(t('top', 'https://a.example/', HTML, '<html><body>x</body></html>'), 'H-03')).toEqual(['H-03.1']);
  });
});

describe('6・7 E-09 と、ビルドしたファイルの名前の除外', () => {
  it('E-09：送信する欄の値（"A"）をページ全体から消さない', () => {
    expect(ids(t('top', 'https://idp.example/', HTML, '<form method="post" action="https://app.example/cb"><input type="hidden" name="state" value="A"></form><script>var k="AKIAIOSFODNN7EXAMPLE"</script>'), 'E-09')).toContain('E-09.1');
  });
  it('拡張子のない、語で始まるトークンは伏せる。ビルドしたファイルは伏せない', () => {
    for (const s of ['/magic/login-Xy7Kp2Lm9QaBc12', '/s/share_AbC123xyz9QwE45']) expect(maskText(s), s).toMatch(/…/);
    expect(maskText('/assets/AdminDashboard-Dk3x9Lq2.js')).toBe('/assets/AdminDashboard-Dk3x9Lq2.js');
  });
});

describe('8 以前の形式のキー', () => {
  it('v0.4.29 の形（パス引数の値、並べ替えていない名前）も以前の形式と見分ける', () => {
    expect(legacyHarKey('HAR GET https://a.example/app;jsessionid=ABC')).toBe(true);
    expect(legacyHarKey('HAR GET https://a.example/x?token&page')).toBe(true);
    expect(legacyHarKey('HAR GET https://a.example/cb?code=…&state=s')).toBe(true);
    expect(legacyHarKey(`HAR GET ${urlKey('https://a.example/x?token=1&page=2')}`)).toBe(false);
  });
});

describe('10 テストのタイムゾーン', () => {
  it('ゴールデンテストの期待結果と同じ JST で動く（CI の UTC でも同じ結果にする）', () => {
    expect(new Date('2026-01-01T00:00:00').getTimezoneOffset()).toBe(-540);
  });
});

describe('12・14 T-10 と本文のない応答', () => {
  it('T-10：合意した暗号だけでは合格にしない', () => {
    expect(ids('#TARGET url=https://a.example/ label=top\n* Connected to a.example (192.0.2.1) port 443\n* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384\n> GET / HTTP/1.1\n>\n< HTTP/2 200\n< content-type: text/html\n<\n', 'T-10')).toEqual(['T-10.na']);
  });
  it('H-12・H-11：HAR の 204 は対象外', () => {
    const r = har(entry('https://a.example/api/events', 204, [], [{ name: 'Cookie', value: 'sessionid=abcdef0123456789' }], '', '', 'POST'));
    const fs = r.findings.filter(f => f.item === 'H-12' || f.item === 'H-11').map(f => f.ruleId);
    expect(fs).not.toContain('H-12.1');
    expect(fs).not.toContain('H-11.1');
  });
});

describe('15・16 性能とパスのトークン', () => {
  const ms = (f: () => void) => { const s = performance.now(); f(); return performance.now() - s; };
  it('継続行（obs-fold）と -v の Cookie の行が多くても、2乗の時間にならない', () => {
    expect(ms(() => parseInput(`#TARGET url=https://a.example/ label=t\nHTTP/1.1 200 OK\nX-A: b\n${' a\n'.repeat(200_000)}\n`))).toBeLessThan(1000);
    const cookies = Array.from({ length: 4000 }, (_, i) => `> Cookie: c${i}=1`).join('\n');
    expect(ms(() => parseInput(`#TARGET url=https://a.example/ label=t\n* Connected to a.example (192.0.2.1) port 443\n> GET / HTTP/1.1\n${cookies}\n>\n< HTTP/1.1 200 OK\n<\n`))).toBeLessThan(1000);
  });
  it('%2B・%3D を含むパスのトークンを最後まで伏せる', () => {
    expect(maskText('/reset/aB3dE5fG7hJ9kL1m%2BnP3qR5sT7v')).not.toContain('nP3qR5sT7v');
  });
});

describe('17・18 E-01・E-02 の見逃し', () => {
  const err = (body: string) => ids(t('top', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', body), 'E-01');
  it('Node.js・Go・Symfony のスタックトレースを②にする', () => {
    expect(err('Error: boom<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)')).toContain('E-01.2');
    expect(err('{"stack":"Error: x\\n    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)"}')).toContain('E-01.2');
    expect(err('panic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()')).toContain('E-01.2');
    expect(err('Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException')).toContain('E-01.2');
  });
  it('IIS・Tomcat・Jetty・serve-index のディレクトリ一覧を①にする', () => {
    for (const b of ['<pre><A HREF="/">[To Parent Directory]</A>', '<h1>Directory Listing For [/files/]</h1>', '<title>Directory: /files/</title>', '<title>listing directory /files/</title>'])
      expect(ids(t('top', 'https://a.example/files/', HTML, b), 'E-02'), b).toEqual(['E-02.1']);
  });
});

describe('19〜22 Cookie と H-04⑤', () => {
  it('19 Cloudflare の __cfruid は C-03③・C-04① にしない', () => {
    const fs = evaluate(t('top', 'https://www.example.com/', `${HTML}\n${HSTS}\nset-cookie: __cfruid=${'a1'.repeat(20)}-1700000000; path=/; domain=.example.com; HttpOnly; Secure; SameSite=None`)).findings.map(f => f.ruleId);
    expect(fs).not.toContain('C-03.3');
    expect(fs).not.toContain('C-04.1');
  });
  it('20 Django の署名付きのセッションは、署名の部分だけで比べる', () => {
    const input = [1, 2, 3].map(i => t(`session-sample-${i}`, 'https://a.example/login', `HTTP/2 302\nlocation: /\nset-cookie: sessionid=.eJxVjDsOwjAQBe-ypqnI2Y7jdIgOQUGBRIsEFYqXv4n_Ow:1rUa${i}b:Sig${i}abcXYZ${i}q9w8e7r6t5u; HttpOnly; Path=/; Secure`)).join('');
    expect(ids(input, 'C-07')).not.toContain('C-07.2');
  });
  it('21 ASP.NET Core Identity の期限付きの Cookie もセッションCookie', () => {
    expect(ids(t('login', 'https://a.example/login', `HTTP/2 302\nlocation: /\nset-cookie: .AspNetCore.Identity.Application=CfDJ8${'A'.repeat(40)}; expires=Tue, 23 Nov 2027 00:00:00 GMT; path=/; samesite=lax`), 'C-01')).toContain('C-01.1');
  });
  it('22 H-04⑤：meta の CSP の nonce が固定', () => {
    const page = (i: number) => t(`csp-sample-${i}`, 'https://a.example/', HTML, `<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'nonce-FiXeD123abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'"></head><body>${i}</body></html>`);
    expect(ids(page(1) + page(2), 'H-04')).toContain('H-04.5');
  });
});
