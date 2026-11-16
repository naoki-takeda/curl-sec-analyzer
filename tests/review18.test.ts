// 18回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前のコミットの副作用を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/15-review18.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { maskCommand, maskText } from '../src/mask';
import { parseInput } from '../src/parser/input';
import { harTargets, importHar } from '../src/parser/har';
import { urlKey } from '../src/engine/targetKey';
import { matches } from '../src/engine/suppress';
import { recommendationEn } from '../src/recommendationsEn';
import { LIMITED } from '../src/engine/coverage';
import type { Finding } from '../src/model';
import { evaluate } from './helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_HEAD = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string, target?: string) => evaluate(input).findings.filter(f => f.item === item && (!target || f.target === target)).map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[], body = '') =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', body, ''].join('\n');
const idem = (s: string) => { const once = maskCommand(s); expect(maskCommand(once)).toBe(once); return once; };

describe('1〜3・10・16〜20 #META cmd=', () => {
  it('1 引数の中の「;」（Cookie・;jsessionid=・パスワード）ではコマンドを区切らない。伏せ方は冪等', () => {
    expect(idem('curl_-b_lang=ja;_remember=k3Jx9QpL2mZ7Wv_https://a.example/')).toBe('curl_-b_****_https://a.example/');
    expect(idem('curl -sS https://a.example/app;jsessionid=ABC -o /dev/null')).toBe('curl -sS https://a.example/app;jsessionid=…(3 chars) -o /dev/null');
    expect(idem('curl_-u_alice:p;ss_https://a.example/')).not.toContain('ss_');
    expect(idem("curl -sS 'https://a.example/x?a=1;sid=Hunter2pw' -o /dev/null")).toContain('-o /dev/null');
    // コマンドが続く「;」「&&」「|」では区切る
    expect(maskCommand('sleep 2; curl -u alice:hunter2pw https://a.example/')).not.toContain('hunter2pw');
    expect(maskCommand('curl_-sS_https://a.example/_|_grep_-iE_set-cookie')).toBe('curl_-sS_https://a.example/_|_grep_-iE_set-cookie');
  });
  it('2 パスを付けた curl（./curl、C:\\tools\\curl.exe）もクライアントとみなす', () => {
    expect(maskCommand('find . -exec ./curl -u alice:hunter2pw https://a.example/ \\;')).not.toContain('hunter2pw');
    expect(maskCommand('find . -exec C:\\tools\\curl.exe -u alice:hunter2pw https://a.example/')).not.toContain('hunter2pw');
  });
  it('3 -d の値のあとに続けて書いた -dpassword=・-Fpassword= も伏せる', () => {
    expect(idem('curl_-d_user=alice_-dpassword=hunter2pw_https://a.example/')).not.toContain('hunter2pw');
    expect(idem('curl_-F_user=alice_-Fpassword=hunter2pw_https://a.example/')).not.toContain('hunter2pw');
  });
  it('16・17・18 export・env・set・$env: の代入、wget の --post-data、空白のある引用符の値を伏せる', () => {
    for (const c of ['export TOKEN=hunter2pw && curl https://a.example/', 'env API_KEY=hunter2pw curl https://a.example/', 'set TOKEN=hunter2pw && curl https://a.example/',
      '$env:TOKEN="hunter2pw"; curl https://a.example/', 'wget --post-data "password=hunter2pw" https://a.example/', 'wget --body-data=password=hunter2pw https://a.example/'])
      expect(maskCommand(c)).not.toContain('hunter2pw');
    for (const c of ['curl -d "password=Hunter 2pw" https://a.example/', "curl -F 'password=Hunter 2pw' https://a.example/", 'curl -d password="Hunter 2pw" https://a.example/'])
      expect(idem(c)).not.toMatch(/Hunter| 2pw/);
  });
  it('19・20 httpie の Authorization:"Bearer …"、echo・printf・<<< で渡した本文を伏せる', () => {
    expect(idem('http https://a.example/ Authorization:"Bearer hunter2pwTOKEN"')).not.toContain('hunter2pw');
    for (const c of ['echo password=hunter2pw | curl -d @- https://a.example/', 'printf "password=hunter2pw" | curl -d @- https://a.example/',
      'curl --data-binary @- https://a.example/ <<< "password=hunter2pw"'])
      expect(maskCommand(c)).not.toContain('hunter2pw');
  });
});

describe('10・15・21・23 maskText', () => {
  it('10 エンコードした URL のユーザー情報は、ポート・パスまで伏せない', () => {
    const u = 'https://a.example/?next=https%3A%2F%2Fa.example%3A8443%2Fx%3Femail%3Dbob%40example.com';
    expect(maskText(u)).toBe(u);
    expect(maskText('https://example.com/?redirect=https%3A%2F%2Falice%3Ahunter2pw%40evil.example%2F')).not.toContain('hunter2pw');
  });
  it('15・23 pass1・pw1・otp1・userpw・_wpnonce を伏せる（key1 は例にも使うので伏せない）', () => {
    for (const q of ['?pass1=hunter2pw', '?pw1=hunter2pw', '?otp1=hunter2pw', '?userpw=hunter2pw', '?_wpnonce=hunter2pw'])
      expect(maskText(`https://a.example/x${q}`)).not.toContain('hunter2pw');
    expect(maskCommand('curl -d "pass1=Hunter2pw&pass2=Hunter2pw" https://a.example/')).not.toContain('Hunter2pw');
  });
  it('21 英小文字だけで母音の少ないトークンを、画面でもキーでも伏せる。英語の語は残す', () => {
    expect(maskText('https://example.com/reset/kqzvwxmplrtbnhjdq')).not.toContain('kqzvwxmplrtbnhjdq');
    expect(urlKey('https://example.com/reset/kqzvwxmplrtbnhjd')).toBe('https://example.com/reset/*');
    expect(maskText('https://example.com/docs/internationalization')).toBe('https://example.com/docs/internationalization');
    expect(urlKey('https://example.com/docs/internationalization')).toBe('https://example.com/docs/internationalization');
  });
});

describe('5・11・22 キーと例外', () => {
  const f = (key: string, url: string, target = 'har-2') => ({ item: 'H-01', ruleId: 'H-01.1', target, targetKey: key, url } as Finding);
  it('5 キーの * は1つのパスの部分だけに一致する。ラベルだけのキーとは * で照合しない', () => {
    const s = { ruleId: 'H-01', target: 'HAR GET https://a.example/*', reason: 'x' } as never;
    expect(matches(s, f('HAR GET https://a.example/admin/settings', 'https://a.example/admin/settings'))).toBe(false);
    expect(matches(s, f('HAR GET https://a.example/お知らせ', 'https://a.example/お知らせ'))).toBe(true);
    expect(matches({ ruleId: 'H-01', target: '*login*', reason: 'x' } as never, f('login', 'https://a.example/x', 'login'))).toBe(false);
  });
  it('11 長音（ー）を含む語もキーに残す', () => {
    expect(urlKey('https://a.example/ユーザーデータベース')).toBe('https://a.example/ユーザーデータベース');
  });
  it('22 同じラベルが1つに減っても、「ラベル URL」で登録した例外は効く', () => {
    expect(matches({ ruleId: 'H-01', target: 'page https://a.example/b', reason: 'x' } as never, f('page', 'https://a.example/b', 'page'))).toBe(true);
  });
});

describe('14・29 入力', () => {
  it('14 改行のない本文（Unauthorized）の直後の #TARGET も分ける', () => {
    const r = parseInput('#TARGET url=https://a.example/api/me label=unauth-api\nHTTP/2 401\r\ncontent-type: text/plain\r\n\r\nUnauthorized#TARGET url=https://a.example/api/me label=cors-reflect\nHTTP/2 200\n\n');
    expect(r.targets.map(x => x.label)).toEqual(['unauth-api', 'cors-reflect']);
  });
  it('29 HAR のブラウザ内部の転送（307 Internal Redirect）はサーバの応答として判定しない', () => {
    const entry = (url: string, status: number, statusText: string, headers: { name: string; value: string }[]) => ({ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method: 'GET', url, headers: [] }, response: { status, statusText, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
    const imp = importHar(JSON.stringify({ log: { entries: [entry('http://a.example/', 307, 'Internal Redirect', [{ name: 'Location', value: 'https://a.example/' }, { name: 'Non-Authoritative-Reason', value: 'HSTS' }]),
      entry('https://a.example/', 200, 'OK', [{ name: 'content-type', value: 'text/html' }])] } }));
    expect(imp.chains.map(c => c.url)).toEqual(['https://a.example/']);
    expect(() => harTargets(imp, new Set(imp.hosts))).not.toThrow();
  });
});

describe('4・6〜9・12・13・24〜36 判定', () => {
  it('4・27 A-01：JSON の本文は HTML の文字列を含んでも①。データのない {}・{"user":null} は na', () => {
    expect(ids(t('unauth-api', 'https://a.example/api/x', HTML, '{"id":1,"html":"<!DOCTYPE html><p>x</p>","owner":"alice@example.com"}'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('unauth-me', 'https://a.example/api/auth/session', JSON_HEAD, '{}'), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', JSON_HEAD, '{"user":null}'), 'A-01')).toEqual(['A-01.na']);
  });
  it('6 C-09：ログインのあとの設定の画面（/mfa/setup-reminder・/users/otp_settings）は多要素認証の途中としない', () => {
    const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    for (const loc of ['/mfa/setup-reminder', '/account/2fa/backup-codes', '/users/otp_settings'])
      expect(ids(pre + t('login', 'https://a.example/login', `HTTP/2 302\nlocation: ${loc}`), 'C-09', 'pre-login/login')).toEqual(['C-09.1']);
    for (const loc of ['/mfa', '/account/two_factor/verify', '/users/two_factor_authentication'])
      expect(ids(pre + t('login', 'https://a.example/login', `HTTP/2 302\nlocation: ${loc}`), 'C-09', 'pre-login/login')).toEqual(['C-09.na']);
  });
  it('7 E-01②：文章の「Look at /src/app.js:10:5」は②にしない。Error のあとの無名のフレームは②', () => {
    expect(ids(t('top', 'https://a.example/', HTML, '<p>Look at /src/app.js:10:5 for the example.</p>'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(t('top', 'https://a.example/api/x', JSON_HEAD, '{"message":"compiled at /app/main.js:1:1"}'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(t('error-x', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/plain', 'Error: boom at /app/index.js:7:9'), 'E-01')).toContain('E-01.2');
  });
  it('8 E-09②：「Tests pass」は②にせず、passwords:・isDebug は②', () => {
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- Tests pass -->'), 'E-09')).not.toContain('E-09.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- passwords: admin/admin -->'), 'E-09')).toContain('E-09.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- isDebug = true -->'), 'E-09')).toContain('E-09.2');
  });
  it('9 カバレッジの「機密応答では判定していない」に英訳がある', () => {
    expect(recommendationEn(LIMITED)).not.toBe(LIMITED);
  });
  it('12 id="old-password" の再認証の画面はログイン画面としない', () => {
    const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
    expect(ids(lo + t('after-logout', 'https://a.example/users/email', HTML, '<form action="/users/email"><input type="email" name="email"><input type="password" name="pass" id="old-password"></form>', 'sensitive=1'), 'C-12', 'after-logout')).toEqual(['C-12.1']);
  });
  it('13 別のサイトへの転送で終わるターゲットは、H-13 を na にして示す', () => {
    expect(ids(t('top', 'https://old.example.com/', `HTTP/2 301\nlocation: https://new.example.net/\n\n${HTML}`, '<p>x</p>'), 'H-13')).toEqual(['H-13.na']);
  });
  it('24 解析用の Cookie（ai_session・s_sess・ab.storage.*）を送っただけの公開ページは、機密応答と推定しない', () => {
    for (const c of ['ai_session=Ab12C|1700|1700; ai_user=x', 's_sess=abc', 'ab.storage.sessionId.1a2b=xyz'])
      expect(ids(v('top', 'https://a.example/about', [`Cookie: ${c}`], ['HTTP/2 200', 'content-type: text/html', 'cache-control: public, max-age=600']), 'H-12')).toEqual(['H-12.na']);
  });
  it('25 H-12：鮮度の指定のない 401・500 は na', () => {
    expect(ids(t('top', 'https://a.example/api/me', 'HTTP/2 401\ncontent-type: application/json', '{}', 'sensitive=1'), 'H-12')).toEqual(['H-12.na']);
    expect(ids(t('top', 'https://a.example/api/me', JSON_HEAD, '{"id":1}', 'sensitive=1'), 'H-12')).toEqual(['H-12.1']);
  });
  it('26 H-01③：カンマ区切り・「;」のない・max-age の重複した HSTS は無効', () => {
    for (const h of ['max-age=31536000, includeSubDomains', 'max-age=31536000 includeSubDomains', 'max-age=31536000; includeSubDomains; max-age=0'])
      expect(ids(t('top', 'https://a.example/', `${HTML}\nstrict-transport-security: ${h}`, '<p>x</p>'), 'H-01')).toEqual(['H-01.3']);
    expect(ids(t('top', 'https://a.example/', `${HTML}\nstrict-transport-security: max-age="31536000"; includeSubDomains; preload`, '<p>x</p>'), 'H-01')).toEqual(['H-01.ok']);
  });
  it('28 C-12①：ログアウトのあとの SPA の画面は na', () => {
    const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
    expect(ids(lo + t('after-logout', 'https://a.example/mypage', HTML, '<!doctype html><html><head><script src="/assets/index-abc.js"></script></head><body><div id="root"></div></body></html>', 'sensitive=1'), 'C-12', 'after-logout')).toEqual(['C-12.na']);
    expect(ids(lo + t('after-logout', 'https://a.example/mypage', HTML, '<p>Welcome back, alice. Your orders: #1001, #1002, #1003 are shipped.</p>', 'sensitive=1'), 'C-12', 'after-logout')).toEqual(['C-12.1']);
  });
  it('30 E-05：/actuator/health の状態だけの応答は合格。詳細のあるものは①', () => {
    expect(ids(t('t', 'https://a.example/actuator/health', 'HTTP/2 200\ncontent-type: application/vnd.spring-boot.actuator.v3+json', '{"status":"UP"}'), 'E-05')).toEqual(['E-05.ok']);
    expect(ids(t('t', 'https://a.example/actuator/health', JSON_HEAD, '{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL"}}}}'), 'E-05')).toEqual(['E-05.1']);
  });
  it('31・32 フラグの Cookie（has_session=1）はセッションCookie としない。小文字と数字だけの24文字は約124bit（①）', () => {
    expect(ids(t('top', 'https://a.example/', `${HTML}\nset-cookie: has_session=1; Path=/; Secure; SameSite=Lax`, '<p>x</p>'), 'C-02')).not.toContain('C-02.1');
    expect(ids(t('login', 'https://a.example/login', `HTTP/2 302\nlocation: /\nset-cookie: ASP.NET_SessionId=ab3cdefgh0ij1klmn2opqrs4; path=/; secure; HttpOnly; SameSite=Lax`), 'C-07', 'login')).toEqual(['C-07.1']);
  });
  it('33・34 H-08 は本文のない 3xx で na。E-11 はフォント（.eot）と HLS のプレイリストで②にしない', () => {
    expect(ids(t('top', 'https://a.example/old', 'HTTP/2 302\nlocation: /new\ncontent-length: 0'), 'H-08')).toEqual(['H-08.na']);
    expect(ids(t('top', 'https://a.example/fonts/icons.eot', 'HTTP/2 200\ncontent-type: application/vnd.ms-fontobject', 'x'), 'E-11')).not.toContain('E-11.2');
    expect(ids(t('top', 'https://a.example/video/master.m3u8', 'HTTP/2 200\ncontent-type: application/vnd.apple.mpegurl', '#EXTM3U'), 'E-11')).not.toContain('E-11.2');
  });
  it('35・36 A-02 は ?session=12 を①にしない。R-07 は X-Tokens-Used を①にしない', () => {
    expect(ids(t('top', 'https://a.example/program?session=12', HTML, '<p>x</p>'), 'A-02')).toEqual(['A-02.ok']);
    expect(ids(t('top', 'https://a.example/program?token=482913', HTML, '<p>x</p>'), 'A-02')).toEqual(['A-02.1']);
    expect(ids(t('top', 'https://a.example/api', `${JSON_HEAD}\naccess-control-allow-origin: https://app.example.com\naccess-control-expose-headers: X-Total-Count, X-Tokens-Used`, '{}'), 'R-07')).toEqual(['R-07.ok']);
  });
});

describe('コミット前のレビュー', () => {
  const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
  it('P1 区切りのあとが一覧にない名前・引数だけでも伏せる', () => {
    for (const c of ['sleep_2;curl8_-u_alice:Hunter2pw_https://a.example.com', 'echo_x|curl-impersonate_-u_alice:Hunter2pw_https://a.example.com',
      'sleep_1;C3:curl_-u_alice:Hunter2pw_https://a.example.com', 'cat_a|./bin/apiclient_-u_alice:Hunter2pw_https://a.example.com', 'sleep_1;_-u_alice:Hunter2pw',
      'sleep 2; curl8 -u alice:Hunter2pw https://a.example.com', 'sleep_2;LANG=C_wget2_--password=Hunter2pw_https://a.example.com', 'sleep 1; export TOKEN=Hunter2pw; curl https://a.example.com'])
      expect(idem(c)).not.toContain('Hunter2pw');
  });
  it('P2 秘密の値の中の _-d…= ・ _-F…= で値を切らない', () => {
    for (const c of ['curl -b sid=AbCd_-dEfGh1jKlMn0123= https://a.example.com', 'curl_-u_alice:Pa_-dW0rdSecret9=_https://a.example.com',
      'curl_--oauth2-bearer_eyJabc_-dQ9xZz8Yy7Xx=_https://a.example.com', 'curl_-x_alice:Pa_-dW0rdSecret9=@proxy.example:3128_https://a.example.com'])
      expect(idem(c)).not.toMatch(/EfGh1jKlMn0123|W0rdSecret9|Q9xZz8Yy7Xx/);
  });
  it('P3 C-09：Fortify・GitHub・Auth0・allauth の2段階目の画面は多要素認証の途中（na）', () => {
    const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    for (const loc of ['/two-factor-challenge', '/sessions/two-factor/app', '/u/mfa-otp-challenge', '/accounts/2fa/authenticate/'])
      expect(ids(pre + t('login', 'https://a.example/login', `HTTP/2 302\nlocation: ${loc}`), 'C-09', 'pre-login/login')).toEqual(['C-09.na']);
  });
  it('P4 C-12：Inertia の data-page と、文字のあるサーバ描画の画面は SPA の殻としない', () => {
    expect(ids(lo + t('after-logout', 'https://a.example/mypage', HTML, '<div id="app" data-page="{&quot;props&quot;:{&quot;user&quot;:{&quot;email&quot;:&quot;alice@example.com&quot;}}}"></div><script src="/build/app.js"></script>', 'sensitive=1'), 'C-12', 'after-logout')).toEqual(['C-12.1']);
    expect(ids(lo + t('after-logout', 'https://a.example/mypage', HTML, '<div id="app"><h1>マイページ</h1><p>山田太郎様のご注文</p></div><script src="/a.js"></script>', 'sensitive=1'), 'C-12', 'after-logout')).toEqual(['C-12.1']);
  });
  it('P5 値のないヘッダ（-H "Authorization:"）のあとの -H・URL を伏せない', () => {
    expect(idem('curl -H "Authorization:" -H "X-Trace: 1" https://a.example.com/')).toBe('curl -H "Authorization:" -H "X-Trace: 1" https://a.example.com/');
    expect(idem("curl -H 'Cookie:' -u alice:pw https://a.example.com/")).toBe("curl -H 'Cookie:' -u **** https://a.example.com/");
  });
  it('P6 引数のパスの中の /curl_ をクライアントとみなさない', () => {
    for (const c of ["grep -E '^HTTP/' /tmp/curl_out.txt", "grep_-E_'^(HTTP|Location)'_./curl_out.txt"]) expect(maskCommand(c)).toBe(c);
  });
  it('P7 数字の値のセッションCookie（SESSIONID=1234）は C-07①', () => {
    expect(ids(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /\nset-cookie: SESSIONID=1234; Path=/; Secure; HttpOnly'), 'C-07', 'login')).toEqual(['C-07.1']);
  });
  it('P8 開発用コメントの pass: ・pass= は②', () => {
    for (const c of ['test login: admin / pass: Adm1n!23', 'admin pass=hunter2'])
      expect(ids(t('top', 'https://a.example/', HTML, `<!-- ${c} -->`), 'E-09')).toContain('E-09.2');
  });
  it('P9 R-07：X-Account-Token は①', () => {
    expect(ids(t('top', 'https://a.example/api', `${JSON_HEAD}\naccess-control-allow-origin: https://app.example.com\naccess-control-expose-headers: X-Account-Token`, '{}'), 'R-07')).toEqual(['R-07.1']);
  });
  it('P10 H-12：private の付いた 403 は判定する（②）', () => {
    expect(ids(t('top', 'https://a.example/api/me', 'HTTP/2 403\ncontent-type: application/json\ncache-control: private', '{}', 'sensitive=1'), 'H-12')).toEqual(['H-12.2']);
  });
  it('P11 mac1・pin2・code128・key1・hash1 は伏せない。cryptography・strengthening はキーに残す', () => {
    for (const q of ['?mac1=abc123def', '?pin2=7', '?code128=ABC123', '?key1=value1&key2=value2', '?hash1=abc'])
      expect(maskText(`https://a.example/x${q}`)).toBe(`https://a.example/x${q}`);
    expect(urlKey('https://a.example/docs/cryptography/strengthening')).toBe('https://a.example/docs/cryptography/strengthening');
  });
  it('P12 本文の文中の「#TARGET url=」と set -x の「+ echo \'#TARGET …\'」では分けない', () => {
    const r = parseInput("#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/plain\n\nUse a line like #TARGET url=https://x.example label=foo to start.\n");
    expect(r.targets.map(x => x.label)).toEqual(['top']);
    expect(r.warnings.filter(w => w.kind === 'orphan-block')).toEqual([]);
  });
});
