// 16回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直前のコミットの副作用を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/13-review16.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { summarizeCommand } from '../../src/export/cmdSummary';
import { parseInput } from '../../src/parser/input';
import { splitSetCookie } from '../../src/parser/setCookie';
import { harTargets, importHar } from '../../src/parser/har';
import { runAll } from '../../src/engine/run';
import { PARTIAL } from '../../src/engine/coverage';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_HEAD = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const v = (label: string, url: string, sent: string[], recv: string[], body = '') =>
  [`#TARGET url=${url} label=${label}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname}${new URL(url).search} HTTP/1.1`, ...sent.map(s => `> ${s}`), '>',
    ...recv.map(s => `< ${s}`), '<', body, ''].join('\n');
const ms = (f: () => void) => { const s = performance.now(); f(); return performance.now() - s; };

describe('1・26 #META cmd= の認証情報', () => {
  it('「_」で区切った長いオプションの値を伏せる（--user_…、--header_X-Api-Key:_…、--cookie_…、--oauth2-bearer_…）', () => {
    expect(summarizeCommand('curl_-sS_-i_--user_alice:Hunter2Secret_--header_X-Api-Key:_ApiKeyZz9Yy8Xx7_https://example.com/'))
      .toBe('curl -sS -i --user **** --header X-Api-Key: **** https://example.com/');
    expect(summarizeCommand('curl_--cookie_sid=abc_--oauth2-bearer_tok123_https://a.example/')).toBe('curl --cookie **** --oauth2-bearer **** https://a.example/');
  });
  it('値のない長いオプションのあとの -H Cookie と、オプションの外の Authorization（httpie）も伏せる', () => {
    expect(summarizeCommand('curl_-sS_--compressed_-H_Cookie:_sid=s3cretVal_https://a.example/')).toBe('curl -sS --compressed -H Cookie: **** https://a.example/');
    expect(summarizeCommand('http_GET_https://a.example/_Authorization:Bearer_tok123abc')).toBe('http GET https://a.example/ Authorization:****');
  });
  it('まとめ書きの -sSu、値を取るオプションのあとの -uadmin:pw、--url-query・--tlspassword・--variable を伏せる', () => {
    expect(summarizeCommand('curl_-sSu_alice:pw_https://a.example/')).toBe('curl -sSu **** https://a.example/');
    expect(summarizeCommand('curl_-X_POST_-uadmin:pw_https://a.example/')).toBe('curl -X POST -u**** https://a.example/');
    expect(summarizeCommand('curl_-H_Accept:*/*_-ualice:pw_https://a.example/')).toBe('curl -H Accept:**** -u**** https://a.example/');
    expect(summarizeCommand('curl_--url-query_access_token=Sk9xAbCdEf_https://a.example/')).not.toContain('Sk9xAbCdEf');
    expect(summarizeCommand('curl_--tlspassword_hunter2_https://a.example/')).toBe('curl --tlspassword **** https://a.example/');
    expect(summarizeCommand('curl_--variable_TOKEN=abcdefgh_https://a.example/')).toBe('curl --variable **** https://a.example/');
  });
  it('伏せた結果はもう一度伏せても変わらず、秘密でないオプションと URL は残す', () => {
    for (const c of ['curl_-sS_-i_-U_proxyuser:pw_-d_password=Hunter2_https://a.example/', 'curl_-XPOST_-H_"Authorization:_Bearer_abc"_https://a.example/',
      'curl_-v_--compressed_https://a.example/path_-H_X-Trace:_abc']) {
      const once = summarizeCommand(c);
      expect(summarizeCommand(once)).toBe(once);
      expect(once).toContain('https://a.example/');
    }
    expect(summarizeCommand('curl_-v_--compressed_https://a.example/path_-H_X-Trace:_abc')).toBe('curl -v --compressed https://a.example/path -H X-Trace: ****');
  });
});

describe('2・6・9 C-12①', () => {
  const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
  const c12 = (after: string) => evaluate(lo + after).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId);
  it('id="current-password" のログインのフォームと、パスワード欄だけの2段階目の画面はログイン画面（合格）', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input type="email" name="email" autocomplete="username"><input id="current-password" name="current-password" type="password" autocomplete="current-password"></form>'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post" action="/login/password"><p>alice@example.com</p><input type="password" name="password" autocomplete="current-password"></form>'))).toEqual(['C-12.ok']);
    // パスワードを決める欄（new-password）は、ログイン画面ではない
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form><input type="password" name="password" autocomplete="new-password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
  });
  it('/Account/Login.aspx・/login.php・Spring の /oauth2/authorization/x への転送は合格（トップは na）。-L でたどった IdP の入り口も合格', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /Account/Login.aspx?ReturnUrl=%2Fmypage'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /login.php'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /'))).toEqual(['C-12.na']);   // トップへの転送は、トップが利用者の画面を返すアプリもあるので分からない
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /oauth2/authorization/keycloak'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /sso/start\n\nHTTP/2 302\nlocation: https://idp.example/realms/x/protocol/openid-connect/auth?client_id=a'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 302\nlocation: /home'))).toEqual(['C-12.na']);
  });
  it('閉じない <input が並ぶ本文でも、ログインのフォームの判定は線形の時間', { tags: ['perf'] }, () => {
    const body = `<form><input type="password" name="p">${'<input '.repeat(12000)}`;
    expect(ms(() => c12(t('after-logout', 'https://a.example/mypage', HTML, body)))).toBeLessThan(500);
  });
});

describe('3・11 E-11①', () => {
  it('Redmine の /attachments/download/42/evil.html は①、/en/download/windows.html は①にしない', () => {
    expect(ids(t('top', 'https://a.example/attachments/download/42/evil.html', HTML, '<p>x</p>'), 'E-11')).toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/files/download/evil.html', HTML, '<p>x</p>'), 'E-11')).toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/en/download/windows.html', HTML, '<p>x</p>'), 'E-11')).not.toContain('E-11.1');
  });
  it('ビルドした SVG（/static/media/logo.<ハッシュ>.svg、/_next/static/media/…）はアップロードしたファイルとしない', () => {
    expect(ids(t('top', 'https://a.example/static/media/logo.6ce24c58.svg', 'HTTP/2 200\ncontent-type: image/svg+xml', '<svg/>'), 'E-11')).not.toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/_next/static/media/hero.4a5b6c7d.svg', 'HTTP/2 200\ncontent-type: image/svg+xml', '<svg/>'), 'E-11')).not.toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/uploads/avatar.svg', 'HTTP/2 200\ncontent-type: image/svg+xml', '<svg/>'), 'E-11')).toContain('E-11.1');
  });
});

describe('4・22 分割した Cookie と oauth2-proxy', () => {
  it('C-07①：分割した Cookie の2つ目以降のかけら（…C2）は単独で判定しない', () => {
    // C-07① はログイン・セッションの採取（login・pre-login・session-sample-*）で判定する
    const input = t('login', 'https://a.example/login', `${HTML}\nset-cookie: .AspNetCore.Identity.Application=chunks-2; path=/; secure; httponly; samesite=lax\nset-cookie: .AspNetCore.Identity.ApplicationC1=CfDJ8Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5Lz0XcVb7Nm2Qw4Er6Ty8Ui0Op; path=/; secure; httponly; samesite=lax\nset-cookie: .AspNetCore.Identity.ApplicationC2=Xy7Kp2Lm9Q; path=/; secure; httponly; samesite=lax`);
    expect(evaluate(input).findings.filter(f => f.item === 'C-07' && f.target === 'login').map(f => f.ruleId)).toEqual(['C-07.ok']);
    // 2つ目以降のかけらだけの応答も、単独では判定しない
    expect(ids(t('login', 'https://a.example/login', `${HTML}\nset-cookie: .AspNetCore.Identity.ApplicationC2=Xy7Kp2Lm9Q; path=/; secure; httponly; samesite=lax`), 'C-07')).not.toContain('C-07.1');
  });
  it('_oauth2_proxy をセッションCookie とみなす（ログアウトの削除は C-12② にせず、属性がなければ C-01①）', () => {
    expect(evaluate(t('logout', 'https://a.example/oauth2/sign_out', 'HTTP/2 302\nlocation: /\nset-cookie: _oauth2_proxy=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/')).findings
      .filter(f => f.item === 'C-12' && f.target === 'logout').map(f => f.ruleId)).toEqual(['C-12.ok']);
    expect(ids(t('top', 'https://a.example/', `${HTML}\nset-cookie: _oauth2_proxy=Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=|1763251200|AbCdEf; Expires=Tue, 23 Nov 2027 00:00:00 GMT; Path=/`), 'C-01')).toContain('C-01.1');
  });
});

describe('5・20 E-01', () => {
  it('JSON・スクリプトの文字列の中の「at /…:1:2」は②にしない。行の始めの無名のフレームは②', () => {
    expect(ids(t('top', 'https://a.example/api/x', JSON_HEAD, '{"tip":"look at /docs","entry":"main.js:1:2"}'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(t('top', 'https://a.example/', HTML, '<script>var s="at /static/js/chunk.js:1:20345"</script>'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(t('top', 'https://a.example/api/x', 'HTTP/2 500\ncontent-type: text/plain', 'Error: boom\n    at /app/index.js:7:9\n    at node:internal/main/run_main_module:28:49'), 'E-01')).toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/api/x', 'HTTP/2 500\ncontent-type: application/json', '{"stack":"Error: boom\\n    at /app/index.js:7:9"}'), 'E-01')).toContain('E-01.2');
  });
  it('HTML の AWS のキーは E-09① だけで数える（E-01① と2回、高として数えない）', () => {
    const fs = evaluate(t('top', 'https://a.example/', HTML, '<p>AKIAQWERTYUIOPASDFGH</p>')).findings.filter(f => f.status === 'fail' && f.severity === 'high').map(f => f.ruleId);
    expect(fs).toContain('E-09.1');
    expect(fs).not.toContain('E-01.1');
  });
});

describe('7・25 E-05・E-13', () => {
  it('E-05：本文に「Swagger UI」の語があるだけの SPA の画面は na。<div id="swagger-ui">・<title>Swagger UI</title> は②', () => {
    expect(ids(t('swagger', 'https://a.example/swagger-ui/', HTML, '<html><title>MyApp</title><p>We document our API with Swagger UI.</p></html>'), 'E-05')).toEqual(['E-05.na']);
    expect(ids(t('swagger', 'https://a.example/swagger-ui/', HTML, '<div id="swagger-ui"></div>'), 'E-05')).toEqual(['E-05.2']);
    expect(ids(t('swagger', 'https://a.example/swagger-ui/', HTML, '<html><title>Swagger UI</title></html>'), 'E-05')).toEqual(['E-05.2']);
  });
  it('E-13：本文に埋め込んだソースマップ（data:）は、.map の取得を勧めない②', () => {
    const js = 'HTTP/2 200\ncontent-type: application/javascript';
    const inline = evaluate(t('top', 'https://a.example/app.js', js, 'console.log(1)\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==')).findings.filter(f => f.item === 'E-13');
    expect(inline.map(f => f.ruleId)).toEqual(['E-13.2']);
    expect(inline[0].evidence).toContain('埋め込んだ');
    expect(inline[0].recommendation).not.toContain('C13');
    expect(ids(t('top', 'https://a.example/app.js', js, 'console.log(1)\n//# sourceMappingURL=app.js.map'), 'E-13')).toEqual(['E-13.2']);
  });
});

describe('8・27・28 マスク', () => {
  it('画像の「語.ハッシュ」は伏せ、ビルドした JS・CSS のハッシュは伏せない', () => {
    expect(maskText('https://a.example/img/avatar.0123456789abcdef0123.png')).not.toContain('0123456789abcdef0123');
    expect(maskText('https://a.example/js/main.0123456789abcdef0123.js')).toBe('https://a.example/js/main.0123456789abcdef0123.js');
    expect(maskText('https://a.example/static/js/main.0123456789abcdef0123.chunk.js')).toBe('https://a.example/static/js/main.0123456789abcdef0123.chunk.js');
  });
  it('Akamai の署名トークン（hdnts・hdnea）と ?hmac=・?mac= を伏せる', () => {
    const hmac = '0123456789abcdef'.repeat(4);
    expect(maskText(`https://cdn.example.com/v/a.m3u8?hdnts=st=1763251200~exp=1763254800~acl=/*~hmac=${hmac}`)).not.toContain(hmac);
    expect(maskText(`https://cdn.example.com/v/a.m3u8?hdnea=exp=1763254800~acl=/*~hmac=${hmac}`)).not.toContain(hmac);
    expect(maskText(`https://a.example/cb?hmac=${hmac}&shop=x`)).not.toContain(hmac);
    expect(maskText('https://a.example/cb?mac=AbCdEf1234567890')).not.toContain('AbCdEf1234567890');
  });
  it('code_challenge_method・key_size・max_password_length などの公開の設定値は残す', () => {
    const q = '?code_challenge_method=S256&oauth_signature_method=HMAC-SHA1&token_endpoint_auth_method=client_secret_basic&key_size=2048&max_password_length=64';
    expect(maskText(q)).toBe(q);
    expect(maskText('?code=abcdef&password=Hunter2xx')).not.toContain('Hunter2xx');
  });
});

describe('12〜24 判定', () => {
  it('12 A-07①・E-09①：伏せ字の値（********・***・[FILTERED]）は秘密情報としない', () => {
    expect(ids(t('top', 'https://a.example/api/me', JSON_HEAD, '{"password":"********","apiKey":"***","secret":"[FILTERED]"}', 'sensitive=1'), 'A-07')).toEqual(['A-07.ok']);
    expect(ids(t('top', 'https://a.example/', HTML, '<script>var c={"smtp":{"password":"************"}}</script>'), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/api/me', JSON_HEAD, '{"password":"Hunter2Secret!"}', 'sensitive=1'), 'A-07')).toContain('A-07.1');
  });
  it('13 T-09・T-10：openssl が一度も接続できなかったら合格にしない（na）', () => {
    const base = '#TARGET url=https://a.example/ label=tls\n';
    const none = `${base}#TLSPROBE v=tls1 ok=0\n#TLSPROBE v=tls1_1 ok=0\n#TLSPROBE v=tls1_2 ok=0\n#TLSPROBE v=tls1_3 ok=0\n#CIPHERPROBE c=RC4-SHA ok=0\n#CIPHERPROBE c=DES-CBC3-SHA ok=0\n#CIPHERPROBE c=AES128-SHA ok=0\n`;
    expect(ids(none, 'T-09')).toEqual(['T-09.na']);
    expect(ids(none, 'T-10')).toEqual(['T-10.na']);
    const reached = `${base}#TLSPROBE v=tls1 ok=0\n#TLSPROBE v=tls1_1 ok=0\n#TLSPROBE v=tls1_2 ok=1\n#TLSPROBE v=tls1_3 ok=1\n#CIPHERPROBE c=RC4-SHA ok=0\n#CIPHERPROBE c=DES-CBC3-SHA ok=0\n`;
    expect(ids(reached, 'T-09')).toEqual(['T-09.ok']);
    expect(ids(reached, 'T-10')).toEqual(['T-10.ok']);
  });
  it('14・21 A-01・A-11：SPA の HTML は na、ログインのフォームも na、404・5xx は na', () => {
    const spa = '<!doctype html><html><div id="root"></div></html>';
    expect(ids(t('unauth-me', 'https://a.example/api/me', HTML, spa), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-me', 'https://a.example/account', HTML, '<form method="post"><input name="username"><input type="password" name="password"></form>'), 'A-01')).toEqual(['A-01.na']);   // ログインのフォームがあっても、データを返したかは分からない
    expect(ids(t('unauth-me', 'https://a.example/api/me', JSON_HEAD, '{"id":1}'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 404\ncontent-type: application/json', '{}'), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 500\ncontent-type: application/json', '{}'), 'A-01')).toEqual(['A-01.na']);
    expect(ids(t('unauth-me', 'https://a.example/api/me', 'HTTP/2 403\ncontent-type: application/json', '{}'), 'A-01')).toEqual(['A-01.ok']);
    expect(ids(t('old-v1', 'https://a.example/api/v1/', HTML, spa), 'A-11')).toEqual(['A-11.na']);
  });
  it('15 T-06：バックスラッシュで書いた外部ホストへの転送は①', () => {
    for (const loc of ['/\\evil.example', 'https:\\\\evil.example/', '///evil.example/'])
      expect(ids(t('open-redirect', 'https://a.example/r?next=https://evil.example', `HTTP/2 302\nlocation: ${loc}`), 'T-06')).toEqual(['T-06.1']);
    expect(ids(t('open-redirect', 'https://a.example/r?next=https://evil.example', 'HTTP/2 302\nlocation: https://evil.example.a.example/'), 'T-06')).toEqual(['T-06.ok']);
  });
  it('16 H-12①・H-11①：Cookie を送った mp4・wasm は静的リソース', () => {
    const media = (path: string, ct: string) => evaluate(v('top', `https://a.example/assets/${path}`, ['Cookie: sessionid=abcdef0123456789abcdef'], ['HTTP/2 200', `content-type: ${ct}`, 'cache-control: public, max-age=86400'])).findings.filter(f => f.status === 'fail' && /^H-1[12]\./.test(f.ruleId)).map(f => f.ruleId);
    expect(media('intro.mp4', 'video/mp4')).toEqual([]);
    expect(media('app.wasm', 'application/wasm')).toEqual([]);
  });
  it('17・18 H-08 は 204 で na、H-13 は本文が空の 401・201 で①にしない', () => {
    expect(ids(t('top', 'https://a.example/beacon', 'HTTP/2 204'), 'H-08')).toEqual(['H-08.na']);
    expect(ids(t('top', 'https://a.example/api/me', 'HTTP/1.1 401 Unauthorized\nwww-authenticate: Bearer\ncontent-length: 0'), 'H-13')).toEqual([]);
    expect(ids(t('top', 'https://a.example/api/items', 'HTTP/1.1 201 Created\ncontent-length: 0'), 'H-13')).toEqual([]);
    expect(ids(t('top', 'https://a.example/api/items', 'HTTP/1.1 200 OK\ncontent-length: 12'), 'H-13')).toEqual(['H-13.1']);
  });
  it('19 T-11：SAN が IP アドレスの証明書は、IP アドレスで比べる', () => {
    const tls = (url: string, san: string) => evaluate(`#TARGET url=${url} label=tls\nCertificate chain\n 0 s:CN = internal-gw\n---\nVerify return code: 0 (ok)\nsubject=CN = internal-gw\nnotAfter=Jan  1 00:00:00 2036 GMT\nX509v3 Subject Alternative Name:\n    ${san}\n`).findings.filter(f => f.item === 'T-11').map(f => f.ruleId);
    expect(tls('https://192.0.2.10/', 'IP Address:192.0.2.10')).toEqual(['T-11.ok']);
    expect(tls('https://192.0.2.11/', 'IP Address:192.0.2.10')).toEqual(['T-11.1']);
    expect(tls('https://[2001:db8::1]/', 'IP Address:2001:DB8:0:0:0:0:0:1')).toEqual(['T-11.ok']);
  });
  it('23 R-06：Origin を送っていない -v の固定の ACAO は適用外', () => {
    expect(ids(v('top', 'https://a.example/api', [], ['HTTP/2 200', 'content-type: application/json', 'access-control-allow-origin: https://app.example.com']), 'R-06')).toEqual([]);
    expect(ids(v('top', 'https://a.example/api', ['Origin: https://app.example.com'], ['HTTP/2 200', 'content-type: application/json', 'access-control-allow-origin: https://app.example.com']), 'R-06')).toEqual(['R-06.1']);
  });
  it('24 H-06④：frame-ancestors https://*・*:443 は広い指定', () => {
    for (const fa of ['https://*', '*:443', 'https://*:*'])
      expect(ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: frame-ancestors ${fa}`, '<p>x</p>'), 'H-06')).toEqual(['H-06.4']);
    expect(ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: frame-ancestors https://*.example.com https://partner.example`, '<p>x</p>'), 'H-06')).toEqual(['H-06.4']);
    expect(ids(t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: frame-ancestors https://partner.example`, '<p>x</p>'), 'H-06')).toEqual(['H-06.ok']);
  });
});

describe('29〜32 入力', () => {
  it('29 splitSetCookie は「a=b,」の繰り返しでも線形の時間', { tags: ['perf'] }, () => {
    const big = 'a=b,'.repeat(100000);
    expect(ms(() => splitSetCookie(big))).toBeLessThan(500);
    expect(splitSetCookie('a=1; Path=/, b=2; Path=/')).toEqual(['a=1; Path=/', 'b=2; Path=/']);
    expect(splitSetCookie('prefs=lang=ja,tz=JST; Path=/')).toEqual(['prefs=lang=ja,tz=JST; Path=/']);
  });
  type H = { name: string; value: string } | null | Record<string, string>;
  const entry = (url: string, status: number, headers: H[], reqHeaders: H[] = []) => ({
    startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: reqHeaders },
    response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
  it('30 転送先のない 302 が多い HAR でも線形の時間', { tags: ['perf'] }, () => {
    const entries = Array.from({ length: 8000 }, (_, i) => entry(`https://a.example/r${i}`, 302, [{ name: 'location', value: `/missing${i}` }]));
    expect(ms(() => importHar(JSON.stringify({ log: { entries } })))).toBeLessThan(1000);
  });
  it('31 名前のないヘッダや null を含む HAR でも取り込める（そのヘッダだけを無視する）', () => {
    const entries = [entry('https://a.example/', 302, [{ value: 'x' }, null, { name: 'location', value: '/next' }], [{ value: 'x' }, null, { name: 'cookie', value: 'sid=abc' }]),
      entry('https://a.example/next', 200, [{ name: 'content-type', value: 'text/html' }])];
    const imp = importHar(JSON.stringify({ log: { entries } }));
    expect(imp.chains.map(c => c.hops)).toEqual([2]);
    expect(() => runAll(harTargets(imp, new Set(imp.hosts)).targets)).not.toThrow();
  });
  it('32 curl 8.22 の時刻の欄のない進捗の行で警告を出さない', () => {
    const input = '#TARGET url=https://a.example/ label=top\n  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current\n                                 Dload  Upload  Total   Spent   Left   Speed\n  0      0   0      0   0      0      0      0                              0\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n';
    const { warnings, targets } = parseInput(input);
    expect(warnings.join()).toBe('');
    expect(targets[0].responses[0].status).toBe(200);
    // 本文の数字の行（短い空白）は進捗の行とみなさない
    expect(parseInput('#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/plain\n\n0 1 2 3 4 5 6 7 8\n').targets[0].responses[0].body).toContain('0 1 2 3 4 5 6 7 8');
  });
});

describe('10 設計書', () => {
  it('カバレッジの「一部の条件」の文言が、コードと同じ', () => {
    const design = readFileSync(new URL('../../docs/design.md', import.meta.url), 'utf8');
    expect(design).toContain(PARTIAL);
  });
});

describe('コミット前のレビュー', () => {
  const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
  const c12 = (after: string) => evaluate(lo + after).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId);
  it('P1 E-01①：E-09 を判定しないラベル（error-*）の HTML の AWS のキーは E-01① で数える', () => {
    expect(ids(t('error-500', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html; charset=utf-8', '<pre>AWS_KEY=AKIAIOSFODNN7EXAMPLE</pre>'), 'E-01')).toContain('E-01.1');
  });
  it('P2 C-12①：-L でたどった最後の 200（トップが利用者の画面）を合格にしない。トップへの転送だけなら na', () => {
    expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 302\nlocation: /dashboard\n\nHTTP/2 302\nlocation: /\n\n${HTML}`, '<p>Welcome back, alice</p>', 'sensitive=1'))).not.toContain('C-12.ok');
    expect(c12(t('after-logout', 'https://a.example/mypage', 'HTTP/2 301\nlocation: /'))).toEqual(['C-12.na']);
  });
  it('P3・P4 A-01・A-11：text/html で返した JSON は HTML の画面としない。ログイン欄のある画面は合格にしない', () => {
    const phpJson = 'HTTP/2 200\ncontent-type: text/html; charset=UTF-8';
    expect(ids(t('unauth-users', 'https://a.example/api/users.php', phpJson, '[{"id":1,"email":"a@example.com"}]'), 'A-01')).toEqual(['A-01.1']);
    expect(ids(t('old-v1', 'https://a.example/api/v1/users.php', phpJson, '{"users":[]}'), 'A-11')).toEqual(['A-11.2']);
    expect(ids(t('method-delete', 'https://a.example/api/users.php', phpJson, '{"deleted":true}'), 'A-11')).toEqual(['A-11.1']);
    expect(ids(t('unauth-admin', 'https://a.example/orders', HTML, '<form method="post" action="/login"><input type="email" name="email"><input type="password" name="password"></form><p>Your orders: alice@example.com</p>'), 'A-01')).not.toContain('A-01.ok');
  });
  it('P5 loginForm：再認証の画面（current_password・old_password、sudo モード）はログイン画面としない。password2・login-again のログイン画面は除かない', () => {
    expect(c12(t('after-logout', 'https://a.example/account/delete', HTML, '<form method="post"><input name="confirm_text"><input type="password" name="current_password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/account/email', HTML, '<form method="post"><input type="email" name="email"><input type="password" name="old_password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/settings', HTML, '<form method="post" action="/sessions/sudo"><input type="password" name="sudo_password" autocomplete="current-password"></form>', 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post"><input name="user"><input type="password" name="password2"></form>'))).toEqual(['C-12.ok']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<form method="post" id="login-again"><input name="user"><input type="password" name="pw"></form>'))).toEqual(['C-12.ok']);
  });
  it('P6 E-11①：アップロード先の名前にハッシュ・日付の付いたファイルは除かない', () => {
    expect(ids(t('top', 'https://a.example/uploads/minutes.20241231.html', HTML, '<p>x</p>'), 'E-11')).toContain('E-11.1');
    expect(ids(t('top', 'https://a.example/uploads/avatar.5f3a9c2e.svg', 'HTTP/2 200\ncontent-type: image/svg+xml', '<svg/>'), 'E-11')).toContain('E-11.1');
  });
  it('P7 summarizeCommand は「_-Habcde」の繰り返しでも線形の時間', { tags: ['perf'] }, () => {
    expect(ms(() => summarizeCommand(`curl${'_-Habcde'.repeat(25000)}`))).toBeLessThan(1000);
  });
  it('P8 summarizeCommand：curl 以外のコマンド（openssl・grep）のオプションは伏せない', () => {
    const c = 'openssl_x509_-noout_-subject_-issuer_-dates・grep_-qiE_unknown_option';
    expect(summarizeCommand(c)).toBe('openssl x509 -noout -subject -issuer -dates・grep ****');   // grep などのオプションは2文字まで（第31回）
    expect(summarizeCommand('openssl x509 -noout -subject -issuer -dates')).toBe('openssl x509 -noout -subject -issuer -dates');
    expect(summarizeCommand('openssl_s_client_-connect_a.example:443・curl_-u_alice:pw_https://a.example/')).toBe('openssl s_client -connect ****・curl -u **** https://a.example/');
  });
  it('P9 E-01②：<br>・&nbsp; のあとと JSON の配列の要素の無名のフレームも②', () => {
    expect(ids(t('top', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', '<pre>Error: boom<br> &nbsp; &nbsp;at /app/index.js:7:9<br></pre>'), 'E-01')).toContain('E-01.2');
    expect(ids(t('top', 'https://a.example/api/x', 'HTTP/2 500\ncontent-type: application/json', '{"stack":["Error","    at /app/index.js:7:9"]}'), 'E-01')).toContain('E-01.2');
  });
  it('P10 T-06：末尾のドットの付いた外部ホスト（evil.example.）への転送も①', () => {
    expect(ids(t('open-redirect', 'https://a.example/r?next=https://evil.example', 'HTTP/2 302\nlocation: https://evil.example./'), 'T-06')).toEqual(['T-06.1']);
  });
  it('P11 本文の桁をそろえた数値の表は、進捗の行として消さない', () => {
    const row = '100  1024  100  1024    0     0   5120      0          0';
    expect(parseInput(`#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/plain\n\n${row}\n`).targets[0].responses[0].body).toContain(row);
  });
  it('P12 mac_address・isMac は伏せない。フォントの「語.ハッシュ」も伏せない', () => {
    expect(maskText('https://a.example/x?mac_address=00:11:22:33:44:55&isMac=true')).toBe('https://a.example/x?mac_address=00:11:22:33:44:55&isMac=true');
    expect(maskText('https://a.example/fonts/roboto.0123456789abcdef0123.woff2')).toBe('https://a.example/fonts/roboto.0123456789abcdef0123.woff2');
  });
});
