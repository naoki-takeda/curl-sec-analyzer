// 14回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前の修正の前後の比較を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/09-review14.txt・10-har-keys.har にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { summarizeCommand } from '../../src/export/cmdSummary';
import { urlKey } from '../../src/engine/targetKey';
import { parseInput } from '../../src/parser/input';
import { harTargets, importHar } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { legacyHarKey } from '../../src/engine/targetKey';
import { coverage } from '../../src/engine/coverage';
import { IMPLEMENTED } from '../../src/rules/ruleset';
import { toJson } from '../../src/export/json';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[]) =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', ''].join('\n');

describe('1 突き合わせのキー：残してよい形だけを残す', () => {
  it('小文字と数字だけのトークン・大文字の base32・接頭辞付きのトークンをキーに入れない', () => {
    for (const tok of ['t2ybctp03i2b8ehtsq04ttsmgdmq4qdl', 'ap0b254fyhcvu5wnat476dkfetk7a1kz', 'MFRGGZDFMZTWQ2LKNNWG23TPOBYXE4DS', 'sk_live_51HxYzabc123def456ghi789jkl', 'ghp_abcdef0123456789abcdef0123456789abcd'])
      expect(urlKey(`https://a.example/reset/${tok}`), tok).not.toContain(tok.slice(-12));
  });
  it('普通の名前は残し、別のファイルは別のキーにする', () => {
    expect(urlKey('https://a.example/news/2026-annual-report-v2/index.html')).toBe('https://a.example/news/2026-annual-report-v2/index.html');
    expect(urlKey('https://a.example/assets/AdminDashboard-Dk3x9Lq2.js')).not.toBe(urlKey('https://a.example/assets/UserProfile-CkL3x9aB.js'));
  });
  it('HAR の JSON のエクスポートに、画面で伏せたトークンを出さない', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [{ request: { method: 'GET', url: 'https://www.example.com/password/reset/t2ybctp03i2b8ehtsq04ttsmgdmq4qdl', headers: [] },
      response: { status: 200, headers: [{ name: 'content-type', value: 'text/html' }], content: { mimeType: 'text/html', text: '<p>x</p>' } } }] } }));
    const fs = runAll(harTargets(imp, new Set(imp.hosts)).targets);
    expect(toJson(fs, coverage(fs, IMPLEMENTED), [])).not.toContain('t2ybctp03i2b8ehtsq04ttsmgdmq4qdl');
  });
});

describe('5・8・9 以前の形式のキーとパラメータの値', () => {
  it('作り方が変わったキーは、どの部分が変わっても以前の形式と見分ける', () => {
    expect(legacyHarKey('HAR GET https://a.example/docs/GettingStartedV2Guide')).toBe(true);
    expect(legacyHarKey('HAR GET https://a.example/assets/index-*.js')).toBe(false);
    expect(legacyHarKey(`HAR GET ${urlKey('https://a.example/x/t2ybctp03i2b8ehtsq04ttsmgdmq4qdl?page=2&token=1')}`)).toBe(false);
  });
  it('配布ごとに変わる ?v= と ?p= の値はキーに残さない', () => {
    expect(urlKey('https://a.example/app.js?v=20261116')).toBe(urlKey('https://a.example/app.js?v=20261201'));
    expect(urlKey('https://a.example/x?p=hunter2password')).not.toContain('hunter2');
  });
});

describe('2 E-09：フォームがページの先頭にないとき', () => {
  const tok = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4eHgifQ.c2lnbmF0dXJlc2lnbmF0dXJl';
  it('form_post の hidden の欄を正しく除き、ほかの秘密は見逃さない', () => {
    expect(ids(t('top', 'https://idp.example/', HTML, `<html><head><title>x</title></head><body><noscript>JS required</noscript><form method="post" action="https://app.example/cb"><input type="hidden" name="id_token" value="${tok}"></form></body></html>`), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://idp.example/', HTML, '<script>var k="AKIAIOSFODNN7EXAMPLE"</script><p>padding padding</p><form method="post" action="/cb"><input type="hidden" name="code" value="abc"></form>'), 'E-09')).toContain('E-09.1');
  });
});

describe('3 C-09：失敗したログイン', () => {
  const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input type="password" name="p"></form>');
  const c09 = (login: string) => evaluate(pre + login).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('/login?next= から /login、/login/ から /login、POST /session から pre-login の /login、/signin への転送は na', () => {
    expect(c09(t('login', 'https://a.example/login?next=%2Fhome', 'HTTP/2 302\nlocation: /login'))).toEqual(['C-09.na']);
    expect(c09(t('login', 'https://a.example/login/', 'HTTP/2 302\nlocation: /login'))).toEqual(['C-09.na']);
    expect(c09(t('login', 'https://a.example/session', 'HTTP/2 302\nlocation: /login'))).toEqual(['C-09.na']);
    expect(c09(t('login', 'https://a.example/session', 'HTTP/2 302\nlocation: /signin\n\nHTTP/2 200\ncontent-type: text/html', '<form><input type="password"></form>'))).toEqual(['C-09.na']);
  });
  it('成功してトップやアカウント画面に転送されたら①のまま', () => {
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /'))).toEqual(['C-09.1']);
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /account\n\nHTTP/2 200\ncontent-type: text/html', '<form><input type="password" name="new"></form>'))).toEqual(['C-09.1']);
  });
});

describe('4・6・7・8 H-03・E-01・C-07', () => {
  it('JSON の API は H-03① を情報に下げて A-09③ として数える（本文がないという na にしない）', () => {
    const fs = evaluate(t('api', 'https://a.example/api', 'HTTP/2 200\ncontent-type: application/json', '{"id":1}')).findings.filter(f => f.item === 'H-03');
    expect(fs.map(f => [f.ruleId, f.dedupedBy])).toEqual([['H-03.1', 'A-09.3']]);
  });
  it('E-01・E-02：/app/ のスクリプト、文章の「at …(/x:3:12)」、本文の「listing directory」で誤検知しない', () => {
    expect(ids(t('top', 'https://a.example/', HTML, '<script type="module">import "/app/assets/main.js"</script>'), 'E-01')).not.toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<p>Meet at Building A (/floor:3:12)</p>'), 'E-01')).not.toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<p>The tool prints listing directory /public when run.</p>'), 'E-02')).not.toContain('E-02.1');
  });
  it('C-07：ASP.NET Core の Cookie の分割の印（chunks-2）をセッションIDとして数えない', () => {
    const s = (i: number) => t(`session-sample-${i}`, 'https://a.example/signin-oidc', `HTTP/2 302\nlocation: /\nset-cookie: .AspNetCore.Cookies=chunks-2; path=/; secure; samesite=lax; httponly\nset-cookie: .AspNetCore.CookiesC1=CfDJ8${['Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5Lz0Xc', 'Mn3Bv8Cx1Za6Sd9Fg4Hj7Kl2Po5Iu0Yt'][i - 1]}; path=/; secure; samesite=lax; httponly`);
    const fs = evaluate(s(1) + s(2)).findings.filter(f => f.item === 'C-07').map(f => f.ruleId);
    expect(fs).not.toContain('C-07.1');
    expect(fs).not.toContain('C-07.2');
  });
  it('H-03：<head> のコメント・スクリプトの中の <body> で、あとの meta の CSP を読み落とさない', () => {
    expect(ids(t('top', 'https://a.example/', HTML, `<html><head><!-- <body> --><script>var s="<body>"</script><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body>x</body></html>`), 'H-03')).toEqual(['H-03.ok']);
  });
});

describe('11〜18 判定', () => {
  it('11 E-05：SPA の 200 の HTML は①②にしない。JSON の actuator は①', () => {
    expect(ids(t('top', 'https://a.example/actuator', HTML, '<html><body><div id="root"></div></body></html>'), 'E-05')).toEqual(['E-05.na']);
    expect(ids(t('top', 'https://a.example/swagger-ui/', HTML, '<html><body><div id="root"></div></body></html>'), 'E-05')).toEqual(['E-05.na']);
    expect(ids(t('top', 'https://a.example/actuator', 'HTTP/2 200\ncontent-type: application/vnd.spring-boot.actuator.v3+json', '{"_links":{}}'), 'E-05')).toEqual(['E-05.1']);
  });
  it('12・18 C-12：ログイン画面を返したら①にしない。セッションCookieでないものを消しただけなら②', () => {
    const mp = t('mypage', 'https://a.example/mypage', HTML, '<p>me</p>', 'sensitive=1');
    const lo = (set: string) => t('logout', 'https://a.example/logout', `HTTP/2 302\nlocation: /\nset-cookie: ${set}`);
    // ログインのフォームは、ユーザー名の欄とパスワード欄が1つずつあるもの（第25回で、パスワード変更の画面と区別するために求めた）
    const al = t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input name="username"><input type="password" name="p"></form>', 'sensitive=1');
    expect(evaluate(mp + lo('sid=; Max-Age=0; Path=/') + al).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.ok']);
    const c12 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-12' && f.target === 'logout').map(f => f.ruleId);
    expect(c12(lo('remember-me=; Max-Age=0; Path=/'))).toEqual(['C-12.2']);
    expect(c12(lo('JSESSIONID=; Max-Age=0; Path=/'))).toEqual(['C-12.ok']);
  });
  it('13 C-10：2つ目の HTTP のホップで発行した Cookie も見る', () => {
    expect(ids(t('http', 'http://a.example/app', 'HTTP/1.1 301 Moved\nlocation: http://a.example/app/\n\nHTTP/1.1 302 Found\nlocation: https://a.example/app/\nset-cookie: ASP.NET_SessionId=abcdefabcdefabcdefabcdef; path=/; HttpOnly\n\nHTTP/2 200\ncontent-type: text/html'), 'C-10')).toContain('C-10.1');
  });
  it('14 T-04：ステータスが分からない応答は na', () => {
    expect(ids('#TARGET url=http://a.example/ label=http\n{"location":["https://a.example/"],"content-length":["0"]}\n', 'T-04')).toEqual(['T-04.na']);
  });
  it('15 T-06：転送しなかった応答は na。Refresh で evil.example に転送したら①', () => {
    expect(ids(t('open-redirect', 'https://a.example/login?next=https://evil.example/', HTML, '<p>login</p>'), 'T-06')).toEqual(['T-06.na']);
    expect(ids(t('open-redirect', 'https://a.example/go?u=x', `${HTML}\nrefresh: 0; url=https://evil.example/`, '<p>x</p>'), 'T-06')).toEqual(['T-06.1']);
  });
  it('16 R-01・R-02：送った Origin で判定する', () => {
    const reflect = v('cors-reflect', 'https://a.example/api', ['Origin: https://evil.example'], ['HTTP/2 200', 'Content-Type: application/json', 'Access-Control-Allow-Origin: https://evil.example', 'Access-Control-Allow-Credentials: true']);
    expect(ids(reflect, 'R-02')).toEqual(['R-02.na']);
    const nul = v('cors-null', 'https://a.example/api', ['Origin: null'], ['HTTP/2 200', 'Content-Type: application/json']);
    expect(ids(nul, 'R-01')).toEqual(['R-01.na']);
    expect(ids(nul, 'R-02')).toEqual(['R-02.ok']);
  });
  it('17 A-08：401・403・404 は na', () => {
    expect(ids(t('ctype', 'https://a.example/api/items', 'HTTP/2 401\ncontent-type: application/json\nwww-authenticate: Bearer', '{}'), 'A-08')).toEqual(['A-08.na']);
  });
});

describe('19・20 解析の速さとマスクの漏れ', () => {
  it('#META response_code の行が多くても、入力の長さに比例する時間で読む', { tags: ['perf'] }, () => {
    const s = performance.now(); parseInput(`#TARGET url=https://a.example/ label=t\n${'HTTP/1.1 200 OK\n#META response_code=200\n'.repeat(40_000)}`);
    expect(performance.now() - s).toBeLessThan(1000);
  });
  it('= のないクエリ・フラグメント・\\/ を含む値・引用符で始まる値・_csrf のトークンを伏せる', () => {
    expect(maskText('https://www.example.com/activate?Xy7Kp2Lm9QaBc4De5Fg6Hj')).not.toContain('Xy7Kp2Lm9QaBc4De5Fg6Hj');
    expect(maskText('https://www.example.com/share#Xy7Kp2Lm9QaBc4De5Fg6Hj')).not.toContain('Xy7Kp2Lm9QaBc4De5Fg6Hj');
    expect(maskText(String.raw`{"u":"https:\/\/a\/cb?token=abc\/defSECRETtail"}`)).not.toContain('SECRETtail');
    expect(maskText("?token='Xy7Kp2Lm9QaBc4De5Fg6'")).not.toContain('Xy7Kp2Lm9QaBc4De5Fg6');
    expect(maskText('?_csrf=abc123def456ghi789')).not.toContain('abc123def456ghi789');
  });
  it('手で書いた #META cmd= の認証情報を CSV に出さない', () => {
    for (const c of ['curl_-u_admin:S3cretPass_https://a.example/', 'curl_-H_Authorization:_Bearer_opaqueT0kenValue_https://a.example/', 'curl_-b_SESSIONID=abc123def_https://a.example/'])
      expect(summarizeCommand(c), c).not.toMatch(/S3cretPass|opaqueT0kenValue|abc123def/);
  });
});
