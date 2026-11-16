// 15回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前の修正の前後の比較を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/11-review15.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { maskCommand, maskKey, maskText } from '../src/mask';
import { parseInput } from '../src/parser/input';
import { legacyHarKey } from '../src/engine/diff';
import { coverage } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const fails = (input: string, re: RegExp) => evaluate(input).findings.filter(f => re.test(f.ruleId) && f.status === 'fail').map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[], info: string[] = []) =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, ...info, `> GET ${new URL(url).pathname}${new URL(url).search} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', ''].join('\n');
const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
const c09 = (p: string, login: string) => evaluate(p + login).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);

describe('1・4・21 セッションCookie の名前', () => {
  it('分割した ASP.NET の認証の Cookie（期限付き）もセッションCookie として C-01①・C-02① にする', () => {
    const input = t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /\nset-cookie: .AspNetCore.Identity.Application=chunks-2; expires=Tue, 23 Nov 2027 00:00:00 GMT; path=/\nset-cookie: .AspNetCore.Identity.ApplicationC1=CfDJ8Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5Lz0Xc; expires=Tue, 23 Nov 2027 00:00:00 GMT; path=/');
    expect(fails(input, /^C-0[12]/)).toEqual(expect.arrayContaining(['C-01.1', 'C-02.1']));
  });
  it('WordPress・Shibboleth のログアウトは C-12② にしない。Clear-Site-Data: "cookies" でも合格', () => {
    const lo = (h: string) => evaluate(t('logout', 'https://a.example/logout', `HTTP/2 302\nlocation: /\n${h}`)).findings.filter(f => f.item === 'C-12' && f.target === 'logout').map(f => f.ruleId);
    expect(lo('set-cookie: wordpress_logged_in_0123456789abcdef0123456789abcdef=+; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/')).toEqual(['C-12.ok']);
    expect(lo('set-cookie: _shibsession_64656661756c74=; Max-Age=0; path=/')).toEqual(['C-12.ok']);
    expect(lo('clear-site-data: "cookies", "storage"')).toEqual(['C-12.ok']);
  });
});

describe('2 C-09：元のページへ戻るログイン、SSO のコールバック', () => {
  it('pre-login が /mypage → /login のチェーンでも、ログイン後の /mypage への転送は成功（①）', () => {
    const p = t('pre-login', 'https://a.example/mypage', `HTTP/2 302\nlocation: /login\nset-cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789; Path=/; Secure; HttpOnly\n\n${HTML}`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    expect(c09(p, t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage'))).toEqual(['C-09.1']);
  });
  it('SSO のコールバック（/sso/login?code=）は失敗ではない（その先を採取していなければ na、-L で再発行していなければ①）。/login への転送は失敗', () => {
    expect(c09(pre, t('login', 'https://a.example/session', 'HTTP/2 302\nlocation: https://a.example/sso/login?code=abc&state=xyz'))).toEqual(['C-09.na']);
    expect(c09(pre, t('login', 'https://a.example/session', 'HTTP/2 302\nlocation: https://a.example/sso/login?code=abc&state=xyz\n\nHTTP/2 302\nlocation: /home'))).toEqual(['C-09.1']);
    expect(c09(pre, t('login', 'https://a.example/session', 'HTTP/2 302\nlocation: /login'))).toEqual(['C-09.na']);
  });
});

describe('3 E-01：/app/ のスタックトレース', () => {
  it('Rails・Node.js（無名のフレーム・node:）・Python を②にする。スクリプトの import は誤検知しない', () => {
    const err = (b: string) => ids(t('top', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/plain', b), 'E-01');
    expect(err("/app/app/controllers/users_controller.rb:12:in 'show'")).toContain('E-01.2');
    expect(err('Error: x\n    at /app/index.js:7:9\n    at node:internal/main/run_main_module:28:49')).toContain('E-01.2');
    expect(err('File "/app/main.py", line 41, in handler')).toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<script type="module">import "/app/assets/main.js"</script>'), 'E-01')).not.toContain('E-01.2');
  });
});

describe('5・12 C-12①', () => {
  const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
  const c12 = (after: string, mp = '') => evaluate(mp + lo + after).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId);
  it('パスワード変更の画面はログイン画面とみなさない（①）', () => {
    expect(c12(t('after-logout', 'https://a.example/account/security', HTML, '<form><input type="password" name="current_password"><input type="password" name="new_password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
  });
  it('末尾の / への転送のあとに 200 なら①。401・ログイン画面への転送は合格。404 は na', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 301\nlocation: https://a.example/mypage/\n\n${HTML}`, '<p>me</p>', 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 401'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /login?next=%2Fmypage'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 404\ncontent-type: text/html', '<p>nf</p>'))).toEqual(['C-12.na']);
  });
});

describe('6・7 キーとコマンドのマスク', () => {
  it('maskKey は冪等で、この版のキーを以前の形式と知らせない', () => {
    for (const u of ['https://a.example/(S(lit3py55t21z5v55vlm25s55))/default.aspx', 'https://a.example/x?=x&q=1', 'https://a.example/reset/t2ybctp03i2b8ehtsq04ttsmgdmq4qdl?page=2']) {
      const k = maskKey(u);
      expect(maskKey(k), u).toBe(k);
      expect(legacyHarKey(`HAR GET ${k}`), u).toBe(false);
    }
  });
  it('#META cmd= の -U・-uuser:pass・-d password=・-E・-H X-Api-Key を伏せ、URL は残す', () => {
    const m = maskCommand('curl_-sS_-i_-U_alice:Hunter2pw_-uBob:S3cretpw_-d_password=Hunter3pw_-E_client.pem:certpw_-H_X-Api-Key:_abc123secret_https://a.example/x');
    expect(m).not.toMatch(/Hunter2pw|S3cretpw|Hunter3pw|certpw|abc123secret/);
    expect(m).toContain('https://a.example/x');
    expect(maskCommand('curl_-u_alice:pw_https://example.com/')).toBe('curl_-u_****_https://example.com/');
  });
});

describe('9・10・18 T-06・E-05', () => {
  it('T-06：ログイン画面への転送（next= を持ち越し）は na', () => {
    expect(ids(t('open-redirect', 'https://a.example/go?next=https://evil.example/', 'HTTP/2 302\nlocation: /login?next=https://evil.example/'), 'T-06')).toEqual(['T-06.na']);
  });
  it('E-05：<title>Swagger UI</title> は Swagger UI の画面', () => {
    expect(ids(t('top', 'https://a.example/swagger-ui/', HTML, '<html><head><title>Swagger UI</title></head><body><div id="root"></div></body></html>'), 'E-05')).toEqual(['E-05.2']);
  });
});

describe('13〜17・19・20 判定', () => {
  it('13 R-09：Origin を送っていない -v、sensitive=0 の明示', () => {
    const ws = (sent: string[], extra = '') => ids(v('websocket', 'https://a.example/ws', sent, ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket']).replace('label=websocket', `label=websocket ${extra}`), 'R-09');
    expect(ws(['Cookie: sessionid=abcdef0123456789', 'Upgrade: websocket'])).toEqual(['R-09.na']);
    expect(ws(['Origin: https://evil.example', 'Cookie: sessionid=abcdef0123456789'], 'sensitive=0')).toEqual(['R-09.2']);
    expect(ws(['Origin: https://evil.example', 'Cookie: sessionid=abcdef0123456789'])).toEqual(['R-09.1']);
  });
  it('14 A-01・A-11：末尾の / への転送のあとのステータスで見る', () => {
    expect(ids(t('unauth-me', 'https://a.example/api/me', `HTTP/2 307\nlocation: /api/me/\n\nHTTP/2 200\ncontent-type: application/json`, '{"id":1}'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 307\nlocation: /api/me/'), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('old-v1', 'https://a.example/api/v1/items', `HTTP/2 308\nlocation: /api/v1/items/\n\nHTTP/2 200\ncontent-type: application/json`, '[]'), 'A-11')).toEqual(['A-11.2']);
  });
  it('15 R-05：-i で ACAO がテスト値のプリフライトは①', () => {
    expect(ids(t('cors-preflight', 'https://a.example/api', 'HTTP/2 204\naccess-control-allow-origin: https://evil.example\naccess-control-allow-methods: GET, PUT, DELETE'), 'R-05')).toContain('R-05.1');
  });
  it('16・19 T-10③ の静的 RSA と、T-09① の SSLv3', () => {
    const tls = (line: string) => evaluate(v('top', 'https://a.example/', [], ['HTTP/1.1 200 OK', 'content-type: text/html'], [`* SSL connection using ${line}`])).findings.map(f => f.ruleId);
    expect(tls('TLSv1.2 / AES256-GCM-SHA384')).toContain('T-10.3');
    expect(tls('SSLv3 / DES-CBC3-SHA')).toContain('T-09.1');
  });
  it('17 JSONP の .js の URL は静的リソースにしない（H-12①）', () => {
    expect(ids(v('jsonp', 'https://a.example/api/user.js?callback=test123', ['Cookie: sessionid=abcdef0123456789'], ['HTTP/2 200', 'content-type: application/javascript']), 'H-12')).toContain('H-12.1');
  });
  it('20 E-11：/download/ の下の .html は①にしない', () => {
    expect(ids(t('top', 'https://a.example/download/windows.html', HTML, '<p>x</p>'), 'E-11')).not.toContain('E-11.1');
  });
});

describe('22 T-09：②だけで判定済みとしない', () => {
  it('プローブがなければ①は na として出し、カバレッジに「一部の条件は入力不足」を示す', () => {
    const r = evaluate(v('top', 'https://a.example/', [], ['HTTP/1.1 200 OK', 'content-type: text/html'], ['* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256']));
    expect(r.findings.filter(f => f.item === 'T-09').map(f => f.ruleId).sort()).toEqual(['T-09.2', 'T-09.na']);
    expect(coverage(r.findings, IMPLEMENTED).find(c => c.item === 'T-09')!.reasons.join()).toContain('一部の条件');
  });
});

describe('23〜26 入力とマスク', () => {
  it('23 数字のないパスのトークンを伏せ、トークンの先頭を語として残さない', () => {
    expect(maskText('https://example.com/reset/AbCdEfGhIjKlMnOpQrStUv')).not.toContain('AbCdEfGhIjKlMnOpQrStUv');
    expect(maskText('/invite/QwErTyUiOpAsDfGhJk_9xZ4bN7mQ2wE5rT8y')).not.toContain('QwErTyUiOpAsDfGhJk');
    expect(maskText('/docs/GettingStartedWithTheAdminGuide')).toBe('/docs/GettingStartedWithTheAdminGuide');
  });
  it('24 前のターゲットの CONNECT の状態を持ち越さない', () => {
    const r = parseInput(['#TARGET url=https://a.example/ label=a', '* Connected to proxy (192.0.2.9) port 8080', '> CONNECT a.example:443 HTTP/1.1', '>', '< HTTP/1.1 407 Proxy Authentication Required', '<',
      '#TARGET url=https://b.example/ label=b', '* Connected to b.example (192.0.2.1) port 443', '> GET / HTTP/1.1', '>', '< HTTP/1.1 200 OK', '< content-type: text/plain', '<', 'HTTP/1.1 404 Not Found', ''].join('\n'));
    expect(r.targets[1].responses.map(x => [x.status, x.kind])).toEqual([[200, 'final']]);
  });
  it('25 -v の本文の中の「< HTTP/」を次の応答にしない', () => {
    const r = parseInput(['#TARGET url=https://a.example/doc label=t', '* Connected to a.example (192.0.2.1) port 443', '> GET /doc HTTP/2', '>', '< HTTP/2 200', '< content-type: text/plain', '< set-cookie: sid=abc; Secure', '<', 'Example output:', '< HTTP/1.1 200 OK', ''].join('\n'));
    expect(r.targets[0].responses.map(x => [x.status, x.kind])).toEqual([[200, 'final']]);
  });
  it('26 webpack の [name].[contenthash].js を伏せない', () => {
    expect(maskText('/static/js/main.3f8a9c2e1b4d5f6a7b8c.js')).toBe('/static/js/main.3f8a9c2e1b4d5f6a7b8c.js');
  });
});

// コミットの前の差分のレビュー（修正の前後を比べたもの）で見つかった退行
describe('コミット前のレビュー', () => {
  const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
  const c12 = (after: string) => evaluate(lo + after).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId);
  it('P1 C-12：autocomplete="current-password"、2段階のログイン、ログインと登録が並ぶ画面はログイン画面', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input name="username" autocomplete="username"><input type="password" name="password" autocomplete="current-password"></form>', 'sensitive=1'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input type="hidden" name="username" value="a"><input type="password" name="password"></form>', 'sensitive=1'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form class="login"><input name="username"><input type="password" name="password"></form><form class="register"><input name="email"><input type="password" name="password"></form>', 'sensitive=1'))).toEqual(['C-12.ok']);
  });
  it('P4 C-12：Devise・WordPress・OIDC の入り口への転送、-L でたどったログイン画面は合格', () => {
    for (const loc of ['/users/sign_in', '/wp-login.php?redirect_to=x', 'https://idp.example/realms/r/protocol/openid-connect/auth?client_id=x', '/oauth2/start?rd=/mypage'])
      expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 302\nlocation: ${loc}`)), loc).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 302\nlocation: /account/entry\n\n${HTML}`, '<form><input name="u"><input type="password" name="p"></form>'))).toEqual(['C-12.ok']);
  });
  it('P2 #META cmd=：_- を含むトークンの残り・空白で区切った Authorization・「・」でつないだコマンド', () => {
    const tok = 'abcDEF_-ghiJKLmnoPQRstuVWXyz0123456789';
    expect(maskCommand(`curl_-H_Authorization:_Bearer_${tok}_https://a.example/`)).not.toContain('ghiJKL');
    expect(maskCommand(`curl_-u_alice:Pa55_-word123Secret_https://a.example/`)).not.toContain('word123Secret');
    expect(maskCommand('curl -H "Authorization: Bearer Zz9Yy8Xx7Ww6Vv5Uu4" https://a.example/')).not.toContain('Zz9Yy8Xx7Ww6Vv5Uu4');
    expect(maskCommand('curl_-u_a:b・curl_-sS_https://a.example/')).toContain('・curl_-sS_https://a.example/');
  });
  it('P3 E-01：/app のスクリプトの読み込み・JSON・文章は②にしない', () => {
    for (const b of ['<script>navigator.serviceWorker.register("/app/sw.js")</script>', '{"entry":"/app/main.js"}', "<script>new Worker('/app/worker.js')</script>", '<p>Put your code in /app/index.js</p>'])
      expect(ids(t('top', 'https://a.example/', HTML, b), 'E-01'), b).not.toContain('E-01.2');
  });
  it('P6 分割した Cookie の印と中身を2回指摘しない', () => {
    const r = fails(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /\nset-cookie: .AspNetCore.Identity.Application=chunks-2; expires=Tue, 23 Nov 2027 00:00:00 GMT; path=/\nset-cookie: .AspNetCore.Identity.ApplicationC1=CfDJ8Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5Lz0Xc; expires=Tue, 23 Nov 2027 00:00:00 GMT; path=/'), /^C-01/);
    expect(r).toEqual(['C-01.1']);
  });
  it('P7 R-09：-v で Origin を送り、Cookie を送っていなければ②（認証なし）', () => {
    expect(ids(v('websocket', 'https://a.example/ws', ['Origin: https://evil.example', 'Upgrade: websocket'], ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket']), 'R-09')).toEqual(['R-09.2']);
  });
  it('P8 T-06：クエリだけが違う転送、ログイン画面以外への転送は試した転送', () => {
    expect(ids(t('open-redirect', 'https://a.example/redirect?url=https://evil.example/', 'HTTP/2 302\nlocation: /redirect?error=invalid'), 'T-06')).toEqual(['T-06.ok']);
    expect(ids(t('open-redirect', 'https://a.example/go?url=https://evil.example/', 'HTTP/2 302\nlocation: /home?blocked=https%3A%2F%2Fevil.example'), 'T-06')).toEqual(['T-06.ok']);
  });
  it('P9 マスク：キャメルケースの API のパスを伏せず、名前全体が16進数のファイルは伏せる', () => {
    expect(maskText('/api/getUserByIdAndName')).toBe('/api/getUserByIdAndName');
    expect(maskText('/media/3F8A9C2E1B4D5F6A7B8C.png')).not.toContain('3F8A9C2E1B4D5F6A7B8C');
  });
});
