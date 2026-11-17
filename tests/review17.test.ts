// 17回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直近2コミットの副作用を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/14-review17.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { summarizeCommand } from '../src/export/cmdSummary';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { targetKeys, urlKey } from '../src/engine/targetKey';
import { matches } from '../src/engine/suppress';
import { coverage, LIMITED } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import type { Finding } from '../src/model';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_HEAD = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string, target?: string) => evaluate(input).findings.filter(f => f.item === item && (!target || f.target === target)).map(f => f.ruleId);
const ms = (f: () => void) => { const s = performance.now(); f(); return performance.now() - s; };
const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
const c12 = (after: string) => ids(lo + after, 'C-12', 'after-logout');

describe('1・6・7・10・28・29 #META cmd=', () => {
  it('1 コマンドの名前を認識できなくても、認証の値を伏せる', () => {
    for (const c of ['C3:curl_-u_alice:Hunter2pw_https://a.example/', '[C3]curl_-b_sid=abc_https://a.example/', '-u_alice:Hunter2pw_https://a.example/',
      'curlie_-u_alice:pw_https://a.example/', 'curl-impersonate-chrome -u alice:pw https://a.example/', 'timeout 10 curl -u alice:pw https://a.example/'])
      expect(summarizeCommand(c)).not.toMatch(/alice:(?:Hunter2)?pw|sid=abc/);
  });
  it('7 パイプでつないだ grep・openssl と、/var/log/http_access の grep のオプションは伏せない', () => {
    // 第31回から、実施コマンドは残してよい形だけを残す（オプションの名前は残し、値は ****）
    expect(summarizeCommand('curl_-sS_https://a.example/_|_grep_-iE_set-cookie')).toBe('curl -sS https://a.example/ | grep -iE ****');
    expect(summarizeCommand('curl_-sS_https://a.example/_|_openssl_x509_-subject_-noout')).toBe('curl -sS https://a.example/ | openssl x509 -subject -noout');
    expect(summarizeCommand('grep_-E_x_/var/log/http_access')).toBe('grep -E ****');
  });
  it('28・29 -x のユーザー:パスワード@、wget・httpie・xh の認証、Authentication・X-Bearer、先頭の TOKEN= を伏せる', () => {
    expect(summarizeCommand('curl_-x_alice:hunter2pw@proxy.example:3128_https://a.example/')).toBe('curl -x **** https://a.example/');
    expect(summarizeCommand('curl_--proxy_http://alice:pw@proxy.example:3128_https://a.example/')).toBe('curl --proxy http://proxy.example:3128/ https://a.example/');
    for (const c of ['wget_--password=hunter2pw_https://a.example/', 'wget_--http-password=hunter2pw_https://a.example/', 'http_-a_alice:hunter2pw_https://a.example/',
      'http_--auth=alice:hunter2pw_https://a.example/', 'xh_--bearer_hunter2pw_https://a.example/', 'http_POST_https://example.com/login_username=alice_password=hunter2pw',
      'curl_-H_Authentication:_hunter2pw_https://a.example/', 'curl_-H_X-Bearer:_hunter2pw_https://a.example/', 'TOKEN=hunter2pw_curl_-sS_https://a.example/'])
      expect(summarizeCommand(c)).not.toContain('hunter2pw');
    expect(summarizeCommand('LANG=C_curl_-sS_https://a.example/')).toBe('LANG=**** curl -sS https://a.example/');
  });
  it('6・10 「_-daaaaa」「Cookie:-H」の繰り返しでも線形の時間。結果はもう一度かけても変わらない', () => {
    expect(ms(() => summarizeCommand(`curl${'_-daaaaa'.repeat(20000)}`))).toBeLessThan(1500);
    expect(ms(() => summarizeCommand(`curl_${'Cookie:-H'.repeat(8000)}`))).toBeLessThan(1500);
    for (const c of ['C3:curl_-u_alice:Hunter2pw_https://a.example/', 'curl_-x_alice:hunter2pw@proxy.example:3128_https://a.example/', 'http_POST_https://example.com/login_password=hunter2pw']) {
      const once = summarizeCommand(c); expect(summarizeCommand(once)).toBe(once);
    }
  });
});

describe('27・33 マスク', () => {
  it('27 名前が一覧にないパラメータのトークン（?t=・&invite=）を伏せる。普通の値は残す', () => {
    expect(maskText('https://www.example.com/magic?t=kyFBQuRU5fxaThYvjaxZry')).not.toContain('kyFBQuRU5fxaThYvjaxZry');
    expect(maskText('https://a.example/x?invite=kyFBQuRU5fxaThYvjaxZry&page=2')).toContain('&page=2');
    expect(maskText('https://a.example/?q=hello_world&sort=asc')).toBe('https://a.example/?q=hello_world&sort=asc');
    expect(ms(() => maskText(`x?${'a=b'.repeat(100000)}`))).toBeLessThan(1500);
  });
  it('33 パラメータの値に入れたエンコードした URL のパスワードを伏せる', () => {
    const o = maskText('https://example.com/?redirect=https%3A%2F%2Falice%3Ahunter2pw%40evil.example%2F');
    expect(o).toBe('https://example.com/?redirect=https%3A%2F%2Falice%3A****%40evil.example%2F');
    expect(maskText(o)).toBe(o);
  });
});

describe('8・9・30 突き合わせのキーと例外', () => {
  it('30 日本語のパスはキーに残す。数字は6桁まで（7桁以上はワンタイムの番号のことがある）', () => {
    expect(urlKey('https://www.example.jp/お知らせ')).not.toBe(urlKey('https://www.example.jp/採用情報'));
    expect(urlKey('https://a.example/orders/123456')).toBe('https://a.example/orders/123456');
    expect(urlKey('https://a.example/login/code/48213907')).toBe('https://a.example/login/code/*');
    const keys = targetKeys([{ label: 'har-1', url: 'https://www.example.jp/お知らせ', meta: { source: 'har' } }, { label: 'har-2', url: 'https://www.example.jp/採用情報', meta: { source: 'har' } }] as never);
    expect(keys.some(k => k.includes('#2'))).toBe(false);
  });
  it('9 URL のパターンの例外は、突き合わせのキーの URL とも照合する（マスクの一覧が変わっても外れない）', () => {
    // マスクした URL（?t=ky…(22 chars)&page=2）には一致しないが、キーの URL（?page=2&t）には一致するパターン
    const f = { item: 'H-01', ruleId: 'H-01.1', target: 'har-1', targetKey: 'HAR GET https://a.example/x?page=2&t', url: 'https://a.example/x?t=ky…(22 chars)&page=2' } as Finding;
    expect(matches({ ruleId: 'H-01', target: 'https://a.example/x?page=2&t', reason: 'x' } as never, f)).toBe(true);
    expect(matches({ ruleId: 'H-01', target: 'https://b.example/*', reason: 'x' } as never, f)).toBe(false);
  });
});

describe('2・22・26 C-12・C-09', () => {
  it('2 Devise の再認証のフォーム（current_password・autocomplete="current-password"）はログイン画面としない', () => {
    expect(c12(t('after-logout', 'https://a.example/account/email', HTML, '<form method="post"><input type=email name=email><input type=password name="current_password" autocomplete="current-password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input type="email" name="email" autocomplete="username"><input id="current-password" name="current-password" type="password" autocomplete="current-password"></form>'))).toEqual(['C-12.ok']);
  });
  it('26 Google・Shibboleth・ADFS・SimpleSAMLphp の認証の入り口への転送は合格', () => {
    for (const loc of ['https://accounts.google.com/o/oauth2/v2/auth?client_id=x', 'https://idp.example/idp/profile/SAML2/Redirect/SSO?SAMLRequest=x', 'https://adfs.example/adfs/ls/?wa=x', 'https://idp.example/simplesaml/saml2/idp/SSOService.php?x=1'])
      expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 302\nlocation: ${loc}`))).toEqual(['C-12.ok']);
  });
  it('22 C-09：多要素認証の途中（/two_factor/verify への転送）は na', () => {
    const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    expect(ids(pre + t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /account/two_factor/verify'), 'C-09', 'pre-login/login')).toEqual(['C-09.na']);
    expect(ids(pre + t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage'), 'C-09', 'pre-login/login')).toEqual(['C-09.1']);
  });
});

describe('3・15・16 A-01・A-11', () => {
  it('3 text/html で返した CSV・平文・空の本文は HTML の画面としない', () => {
    expect(ids(t('unauth-x', 'https://a.example/api/export', HTML, 'id,email\n1,a@example.com'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('unauth-x', 'https://a.example/api/x', HTML, ''), 'A-01')).toEqual(['A-01.na']);   // 本文を採取していない text/html は分からない
    expect(ids(t('unauth-x', 'https://a.example/api/x', 'HTTP/2 200\ncontent-type: text/plain', 'id,email'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('unauth-x', 'https://a.example/api/x', HTML, '<!doctype html><div id="root"></div>'), 'A-01')).toEqual(['A-01.na']);
  });
  it('15 GraphQL の認証エラー（200・errors・data: null）は合格。ほかのエラーは na', () => {
    expect(ids(t('unauth-gql', 'https://a.example/graphql', JSON_HEAD, '{"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}],"data":{"me":null}}'), 'A-01')).toEqual(['A-01.ok']);
    expect(ids(t('unauth-gql', 'https://a.example/graphql', JSON_HEAD, '{"errors":[{"message":"Syntax Error"}],"data":null}'), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-gql', 'https://a.example/graphql', JSON_HEAD, '{"data":{"me":{"id":1}}}'), 'A-01')).toEqual(['A-01.1']);
  });
  it('16 A-11：401・403・404・3xx は na。405・501（メソッド）、404・410（旧版）は合格', () => {
    for (const s of ['401', '403', '404', '302\nlocation: /login']) expect(ids(t('method-delete', 'https://a.example/api/x', `HTTP/2 ${s}`), 'A-11')).toEqual(['A-11.na']);
    expect(ids(t('method-delete', 'https://a.example/api/x', 'HTTP/2 405\nallow: GET'), 'A-11')).toEqual(['A-11.ok']);
    for (const s of ['401', '302\nlocation: /login']) expect(ids(t('old-v1', 'https://a.example/api/v1/', `HTTP/2 ${s}`), 'A-11')).toEqual(['A-11.na']);
    expect(ids(t('old-v1', 'https://a.example/api/v1/', 'HTTP/2 410'), 'A-11')).toEqual(['A-11.ok']);
  });
});

describe('4・12・13・14・26 転送・キャッシュ', () => {
  it('4・12 T-06：絶対 URL でないターゲットでも①。ログイン画面への転送は、テスト値を持ち越したかによらず na', () => {
    expect(ids(t('open-redirect', 'a.example/r?to=https://evil.example/', 'HTTP/2 302\nlocation: https://evil.example/'), 'T-06')).toEqual(['T-06.1']);
    for (const loc of ['/login', '/login.php?redirect_to=https%3A%2F%2Fevil.example', '/Account/Login.aspx?ReturnUrl=https%3A%2F%2Fevil.example', '/oauth2/authorization/keycloak'])
      expect(ids(t('open-redirect', 'https://a.example/redirect?url=https://evil.example', `HTTP/2 302\nlocation: ${loc}`), 'T-06')).toEqual(['T-06.na']);
  });
  it('13 -L で別のホストへ転送したときは、対象と同じホストの最後のホップで判定する', () => {
    expect(ids(t('top', 'https://app.example.com/', `HTTP/2 302\nlocation: https://legacy.example.net/\nstrict-transport-security: max-age=31536000\n\n${HTML}`, '<p>x</p>'), 'H-01')).not.toContain('H-01.1');
    expect(ids(t('top', 'https://app.example.com/', `HTTP/2 302\nlocation: https://idp.example.net/\n\n${HTML}\nstrict-transport-security: max-age=31536000`, '<p>x</p>'), 'H-01')).toEqual(['H-01.1']);
  });
  it('14 H-12：鮮度の指定のない 302・303・307 は na。max-age のある 302 は判定する', () => {
    expect(ids(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /home\nset-cookie: sid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly', '', 'sensitive=1'), 'H-12')).toEqual(['H-12.na']);
    expect(ids(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /home\ncache-control: max-age=600', '', 'sensitive=1'), 'H-12')).toEqual(['H-12.1']);
  });
  it('26 カバレッジ：静的リソースだけで判定した H-12 は「機密応答では判定していない」と示す。H-13 は HTTP/2 の本文の空の 401 で①にしない', () => {
    const r = evaluate(t('top', 'https://a.example/app.js', 'HTTP/2 200\ncontent-type: application/javascript\ncache-control: max-age=3600', 'x()'));
    expect(coverage(r.findings, IMPLEMENTED).find(c => c.item === 'H-12')!.reasons).toContain(LIMITED);
    expect(ids(t('top', 'https://a.example/api/me', 'HTTP/2 401\nwww-authenticate: Bearer'), 'H-13')).toEqual([]);
  });
});

describe('5・9・17・18・19・24・25 E-01・E-09・E-11', () => {
  const e01 = (head: string, body: string, label = 'error-x') => ids(t(label, 'https://a.example/api/x', head, body), 'E-01');
  it('5 行の途中・タグの中・JSON の stack の無名のフレームも②。スクリプトの文字列は②にしない', () => {
    expect(e01('HTTP/2 500\ncontent-type: text/plain', 'Error: boom at /app/index.js:7:9')).toContain('E-01.2');
    expect(e01('HTTP/2 500\ncontent-type: application/json', '{"stack":"at /app/x.js:1:2"}')).toContain('E-01.2');
    expect(e01('HTTP/2 500\ncontent-type: text/html', '<ul><li>at /app/x.js:1:2</li></ul>')).toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<script>var s="at /static/js/chunk.js:1:20345"</script>'), 'E-01')).toEqual(['E-01.ok']);
  });
  it('17 Spring の JSON の trace、PHP の html_errors・Stack trace、エスケープした Python、.NET のフレームは②', () => {
    const json = 'HTTP/2 500\ncontent-type: application/json';
    expect(e01(json, '{"trace":"java.lang.NullPointerException\\n\\tat com.example.Ctl.get(Ctl.java:21)"}')).toContain('E-01.2');
    expect(e01('HTTP/2 500\ncontent-type: text/html', '<b>Fatal error</b>: x in <b>/app/public/index.php</b> on line <b>3</b>')).toContain('E-01.2');
    expect(e01('HTTP/2 500\ncontent-type: text/plain', 'PHP Fatal error: Uncaught Exception\nStack trace:\n#0 /app/src/a.php(3): f()')).toContain('E-01.2');
    expect(e01(json, '{"detail":"Traceback\\n  File \\"/app/main.py\\", line 41, in f"}')).toContain('E-01.2');
    expect(e01('HTTP/2 500\ncontent-type: text/plain', 'Npgsql.PostgresException: 42P01\n   at Npgsql.Internal.NpgsqlConnector.ReadMessage()')).toContain('E-01.2');
  });
  it('18・24 資格情報のない mongodb:// と、普通のページの「Express」のタイトルは誤検知しない', () => {
    expect(e01(JSON_HEAD, '{"db":"mongodb://db.example.com:27017/app","contact":"ops@example.com"}')).not.toContain('E-01.1');
    expect(e01(JSON_HEAD, '{"db":"mongodb://app:Hunter2pw@db.example.com:27017/app"}')).toContain('E-01.1');
    expect(ids(t('top', 'https://a.example/', HTML, '<title>Example Express</title>'), 'E-01')).not.toContain('E-01.3');
    expect(e01('HTTP/2 500\ncontent-type: text/html', '<html><title>Express</title></html>')).toContain('E-01.3');
  });
  it('19・25 E-09：Supabase の anon key は①にせず、「<!-- Password field -->」は②にしない', () => {
    const p = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'anon', exp: 2000000000 })).toString('base64url');
    const s = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'service_role', exp: 2000000000 })).toString('base64url');
    expect(ids(t('top', 'https://a.example/', HTML, `<script>window.ENV={k:"eyJhbGciOiJIUzI1NiJ9.${p}.AbCdEfGhIjKlMnOp"}</script>`), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/', HTML, `<script>window.ENV={k:"eyJhbGciOiJIUzI1NiJ9.${s}.AbCdEfGhIjKlMnOp"}</script>`), 'E-09')).toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- Password field --><input type="password">'), 'E-09')).not.toContain('E-09.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- password: admin123 -->'), 'E-09')).toContain('E-09.2');
  });
  it('9 E-11：/media/download/press.html は①にせず、/static/media/uploads/evil.html は①', () => {
    expect(ids(t('top', 'https://a.example/media/download/press.html', HTML, '<p>x</p>'), 'E-11')).not.toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/static/media/uploads/evil.html', HTML, '<p>x</p>'), 'E-11')).toContain('E-11.1');
  });
});

describe('20・21・23・25 CSP・Cookie・A-07', () => {
  it('20 H-04：1つ目のポリシーが制限していれば、2つ目の unsafe-inline・https: で①②にしない', () => {
    const r = ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: default-src 'self'; object-src 'none'; base-uri 'none'\ncontent-security-policy: script-src 'self' 'unsafe-inline' https:`, '<p>x</p>'), 'H-04');
    expect(r).not.toContain('H-04.1');
    expect(r).not.toContain('H-04.2');
    expect(ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: script-src 'self' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'`, '<p>x</p>'), 'H-04')).toContain('H-04.1');
  });
  it('25 H-07④：fenced-frame-src は未知のディレクティブにしない', () => {
    expect(ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: default-src 'self'; fenced-frame-src 'none'; object-src 'none'; base-uri 'none'`, '<p>x</p>'), 'H-07')).not.toContain('H-07.4');
  });
  it('21 C-02①：idsrv.session・KEYCLOAK_SESSION はセッションCookie としない', () => {
    for (const c of ['idsrv.session=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; SameSite=None', 'KEYCLOAK_SESSION=realm/AbCdEf0123456789/AbCdEf; Path=/; Secure; SameSite=None'])
      expect(ids(t('login', 'https://a.example/login', `HTTP/2 302\nlocation: /\nset-cookie: ${c}`), 'C-02')).not.toContain('C-02.1');
  });
  it('23 A-07①：状態の語（set・configured・true）は秘密としない。salt は②。英小文字のパスワードは①', () => {
    expect(ids(t('top', 'https://a.example/api/me', JSON_HEAD, '{"credentials":{"password":"set","otp_secret":"configured"},"flag":{"password":"true"}}', 'sensitive=1'), 'A-07')).toEqual(['A-07.ok']);
    expect(ids(t('top', 'https://a.example/api/pre', JSON_HEAD, '{"salt":"AbCdEf0123456789"}', 'sensitive=1'), 'A-07')).toEqual(['A-07.2']);
    expect(ids(t('top', 'https://a.example/api/me', JSON_HEAD, '{"password":"hunter"}', 'sensitive=1'), 'A-07')).toContain('A-07.1');
  });
});

describe('11・31・32・34 入力', () => {
  type H = { name: string; value: string };
  const entry = (url: string, status: number, headers: H[]) => ({ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: [] },
    response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
  it('11 同じ URL へ転送する 3xx が多い HAR でも線形の時間', () => {
    const entries = [...Array.from({ length: 20000 }, (_, i) => entry(`https://a.example/r${i}`, 302, [{ name: 'location', value: '/same' }])),
      ...Array.from({ length: 20000 }, () => entry('https://a.example/same', 200, []))];
    let imp: ReturnType<typeof importHar> | undefined;
    expect(ms(() => { imp = importHar(JSON.stringify({ log: { entries } })); })).toBeLessThan(3000);
    expect(imp!.chains.filter(c => c.hops === 2).length).toBe(20000);
    expect(() => harTargets(imp!, new Set(imp!.hosts))).not.toThrow();
  });
  it('31 HTTP の応答に続けた openssl の出力は、本文ではなく openssl の出力として読む', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/ label=tls\nHTTP/1.1 200 OK\nX: 1\n\nCONNECTED(00000003)\ndepth=0 CN = a.example\n---\nVerify return code: 0 (ok)\n');
    expect(targets[0].openssl.length).toBeGreaterThan(0);
    expect(targets[0].responses[0].body ?? '').not.toContain('CONNECTED');
  });
  it('32 #TARGET の引用符で囲んだ値を読む。URL として読めない url= は警告する', () => {
    const r = parseInput('#TARGET label="top page" url="https://a.example/"\nHTTP/2 200\n\n');
    expect(r.targets[0].url).toBe('https://a.example/');
    expect(r.targets[0].label).toBe('top page');
    expect(parseInput('#TARGET label=x url=a.example/r\nHTTP/2 200\n\n').warnings.map(w => w.kind)).toContain('unknown-url');
  });
  it('34 %{header_json} の閉じない括弧が続く入力でも、行ごとに解析し直さない', () => {
    const block = `{"a":[ }\n${'}\n'.repeat(499)}`;
    expect(ms(() => parseInput(`#TARGET url=https://a.example/ label=x\n${block.repeat(2000)}`))).toBeLessThan(2000);
    const ok = parseInput('#TARGET url=https://a.example/ label=x\n{"content-type":["text/html"],\n"x-a":["}"]}\n#META response_code=200\n');
    expect(ok.targets[0].responses[0]?.headers.get('x-a')).toEqual(['}']);
  });
});

describe('コミット前のレビュー', () => {
  it('P1 -L で apex から www（同じサイト）へ転送したときは www の応答で判定する。別のサイトへの転送はたどらない', () => {
    const www = `${HTML}\nstrict-transport-security: max-age=31536000; includeSubDomains\ncontent-security-policy: default-src 'self'; frame-ancestors 'none'\nx-content-type-options: nosniff`;
    const r = evaluate(t('top', 'https://example.com/', `HTTP/2 301\nlocation: https://www.example.com/\n\n${www}`, '<p>x</p>')).findings.filter(f => f.status === 'fail').map(f => f.ruleId);
    expect(r).not.toContain('H-01.1');
    expect(r).not.toContain('H-08.1');
    expect(ids(t('top', 'https://www.example.co.jp/', `HTTP/2 301\nlocation: https://shop.example.co.jp/\n\n${www}`, '<p>x</p>'), 'H-01')).not.toContain('H-01.1');
  });
  it('P2・P9 前の語に付けた「;」で区切る。引用符の中の「;」では区切らない', () => {
    for (const c of ['sleep 2; curl -u alice:hunter2pw https://a.example/', 'echo start; curl -b sid=hunter2pw https://a.example/', 'date +%s; curl --user alice:hunter2pw https://a.example/'])
      expect(summarizeCommand(c)).not.toContain('hunter2pw');
    expect(summarizeCommand('curl -H "Cookie: lang=ja ; sid=s3cr3t" https://a.example/path')).toBe('curl -H Cookie:**** https://a.example/path');
  });
  it('P3 伏せなかった -d の値の中の、まとめ書きの -sSLfu と閉じない引用符のあとの -u も伏せる', () => {
    expect(summarizeCommand('curl_-d_x=1_-sSLfu_alice:hunter2pw_https://a.example/')).not.toContain('hunter2pw');
    expect(summarizeCommand("curl -d 'a=1 -u alice:hunter2pw https://a.example/")).not.toContain('hunter2pw');
  });
  it('P4 今の形式と同じ形の以前の版のキー（* を含む）の例外は、別のページに効かない。非 ASCII の大文字・小文字が入れ替わるトークンはキーに入れない', () => {
    // 第34回の見直し：画面で登録した今のキーと見分けられないので、完全一致だけにする（* を任意の文字列とすると、ほかのページの指摘を黙って抑止した）
    const f = { item: 'H-01', ruleId: 'H-01.1', target: 'har-1', targetKey: 'HAR GET https://www.example.jp/お知らせ', url: 'https://www.example.jp/お知らせ' } as Finding;
    expect(matches({ ruleId: 'H-01', target: 'HAR GET https://www.example.jp/*', reason: 'x' } as never, f)).toBe(false);
    expect(urlKey('https://a.example/x/ÀbcDéfGhîJkLmNöPqRsTüVw')).toBe('https://a.example/x/*');
  });
  it('P5 本文を採取していない text/html の 200 は na。PHP の Notice のあとに続く HTML は HTML の画面', () => {
    expect(ids(t('unauth-me', 'https://a.example/api/me', HTML), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', HTML, 'Notice: Undefined index x in /app/a.php on line 3\n<!doctype html><html><div id="root"></div></html>'), 'A-01')).toEqual(['A-01.na']);
  });
  it('P6 開発用コメントの password・debug_mode・staging_db・パスワードは は②。部品の説明は②にしない', () => {
    for (const c of ['admin password is hunter2', 'パスワードは hunter2', 'debug_mode=true', 'debugMode on', 'staging_db 10.0.0.1'])
      expect(ids(t('top', 'https://a.example/', HTML, `<!-- ${c} -->`), 'E-09')).toContain('E-09.2');
    for (const c of ['Password field', 'パスワード欄', 'password reset link'])
      expect(ids(t('top', 'https://a.example/', HTML, `<!-- ${c} -->`), 'E-09')).not.toContain('E-09.2');
  });
  it('P7 C-09：メールの確認の案内（/verify-email・/email/verify）は多要素認証とみなさない', () => {
    const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    for (const loc of ['/verify-email', '/email/verify', '/account/verification/pending'])
      expect(ids(pre + t('login', 'https://a.example/login', `HTTP/2 302\nlocation: ${loc}`), 'C-09', 'pre-login/login')).toEqual(['C-09.1']);
  });
  it('P8 id="currentPassword"・name=password のログインのフォームはログイン画面', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input name=email><input type=password name=password id=currentPassword autocomplete=current-password></form>'))).toEqual(['C-12.ok']);
  });
  it('P10 utm_*・list・id・title などの公開の値は伏せない', () => {
    for (const u of ['https://a.example/?utm_campaign=SpringSale2026Banner01', 'https://a.example/?utm_content=Header_CTA_Button_v2', 'https://a.example/watch?list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG',
      'https://a.example/?id=0f8fad5b-d9cb-469f-a165-70867728950e', 'https://a.example/?title=HelloWorldFromExampleCom2026'])
      expect(maskText(u)).toBe(u);
  });
  it('P11 httpie のクエリの項目（api_key==…）は印の == を残して伏せる', () => {
    expect(summarizeCommand('http_GET_https://a.example/_api_key==hunter2pw')).toBe('http GET https://a.example/ api_key==****');
  });
});
