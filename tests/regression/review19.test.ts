// 19回目のレビュー（リポジトリ全体、独立した3人のレビュアー。直近2コミットの副作用を含む）で見つかった不具合の再現テスト。
// 入力の多くは tests/golden/cases/16-review19.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { summarizeCommand } from '../../src/export/cmdSummary';
import { toCsv } from '../../src/export/csv';
import { importHar, harTargets } from '../../src/parser/har';
import { urlKey } from '../../src/engine/targetKey';
import { applySuppressions, matches } from '../../src/engine/suppress';
import type { Finding } from '../../src/model';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_HEAD = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n#META at=2026-11-01T10:00:00\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string, target?: string) => evaluate(input).findings.filter(f => f.item === item && (!target || f.target === target)).map(f => f.ruleId);
const ms = (f: () => void) => { const s = performance.now(); f(); return performance.now() - s; };
const lo = t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: sid=; Max-Age=0; Path=/');
const c12 = (after: string) => ids(lo + after, 'C-12', 'after-logout');
const pre = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
const c09 = (login: string, p = pre) => ids(p + login, 'C-09', 'pre-login/login');

describe('1・2・9 例外の照合', () => {
  const f = (key: string, url: string, target = 'har-2') => ({ item: 'H-01', ruleId: 'H-01.1', status: 'fail', target, targetKey: key, url, keyUrl: urlKey(url) } as Finding);
  it('1 指摘5000件 × 例外300件でも速い', () => {
    const fs = Array.from({ length: 5000 }, (_, i) => f(`HAR GET https://a.example/p${i}`, `https://a.example/p${i}`));
    const list = Array.from({ length: 300 }, (_, i) => ({ ruleId: 'H-02', target: `HAR GET https://b.example/x${i}`, reason: 'x' })) as never[];
    expect(ms(() => applySuppressions(fs, list))).toBeLessThan(2000);
  });
  it('2 画面で登録した今回のキーの例外は、そのターゲットだけに効く。以前の版の HAR GET * は広く効く', () => {
    const fs = [f('HAR GET https://a.example/*', 'https://a.example/Xy7Kp2Lm9QaBcDeF'), f('HAR GET https://a.example/login', 'https://a.example/login'), f('HAR GET https://a.example/', 'https://a.example/')];
    const out = applySuppressions(fs, [{ ruleId: 'H-01', target: 'HAR GET https://a.example/*', reason: 'x' } as never]);
    expect(out.map(x => x.status)).toEqual(['suppressed', 'fail', 'fail']);
    expect(applySuppressions(fs.slice(1), [{ ruleId: 'H-01', target: 'HAR GET *', reason: 'x' } as never]).map(x => x.status)).toEqual(['suppressed', 'suppressed']);
  });
  it('9 「ラベル URL」の例外は、生の URL のキーで照合する（ASP.NET の (S(…)) も外れない）', () => {
    // 指摘の url は画面に出すマスクした URL（(S(ab…(12 chars)))）。キーの URL は生の URL から作る
    const raw = 'https://a.example/(S(abcdefghij12))/page';
    const x = { ...f('top', maskText(raw), 'top'), keyUrl: urlKey(raw) };
    expect(urlKey(raw)).toBe('https://a.example/(*)/page');
    expect(matches({ ruleId: 'H-01', target: 'top https://a.example/(*)/page', reason: 'x' } as never, x)).toBe(true);
  });
});

describe('4・5・11・13・16〜18 C-12・C-09・A-01・Cookie の範囲', () => {
  it('4 C-12①：データを持つ SPA の画面（window.Laravel・__NUXT_DATA__・ng-state・data-user・:user）は①', () => {
    for (const b of ['<div id="app"></div><script>window.Laravel={"user":{"email":"alice@example.com"}}</script>',
      '<div id="__nuxt"></div><script type="application/json" id="__NUXT_DATA__">[{"user":1}]</script>',
      '<div id="root"></div><script id="ng-state" type="application/json">{"u":1}</script>', '<div id="app" data-user=\'{"email":"a@example.com"}\'></div><script src="/a.js"></script>',
      '<div id="app" :user="{&quot;email&quot;:&quot;a@example.com&quot;}"></div><script src="/a.js"></script>'])
      expect(c12(t('after-logout', 'https://a.example/mypage', HTML, b, 'sensitive=1'))).toEqual(['C-12.1']);
    expect(c12(t('after-logout', 'https://a.example/mypage', HTML, '<div id="root"></div><script src="/assets/index.js"></script><script>gtag("js", new Date())</script>', 'sensitive=1'))).toEqual(['C-12.na']);
  });
  it('11 C-12：データのない JSON は na、GraphQL の認証の拒否は合格', () => {
    for (const b of ['{}', '{"user":null}']) expect(c12(t('after-logout', 'https://a.example/api/auth/session', JSON_HEAD, b, 'sensitive=1'))).toEqual(['C-12.na']);
    expect(c12(t('after-logout', 'https://a.example/graphql', JSON_HEAD, '{"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}],"data":{"me":null}}', 'sensitive=1'))).toEqual(['C-12.ok']);
  });
  it('5 C-09：拡張子の付いた2段階目の画面は多要素認証の途中（na）', () => {
    for (const loc of ['/2fa.php', '/login/otp.php', '/mfa.aspx', '/two_factor.html', '/Account/TwoFactor.aspx']) expect(c09(t('login', 'https://a.example/login', `HTTP/2 302\nlocation: ${loc}`))).toEqual(['C-09.na']);
  });
  it('16 C-09：新しいセッションIDを発行し、期限付きの device_token を同じ値で送り直しただけなら合格', () => {
    const p = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly\nset-cookie: device_token=Zx81Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5L; Max-Age=31536000; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage\nset-cookie: sessionid=ZyXw9876543210ZyXw9876543210ZyXw; Path=/; Secure; HttpOnly\nset-cookie: device_token=Zx81Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5L; Max-Age=31536000; Path=/; Secure; HttpOnly'), p)).toEqual(['C-09.ok']);
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly'), p)).toEqual(['C-09.1']);
  });
  it('17 T-06・C-12：SAML の入り口（Entra の /saml2、Okta の /sso/saml、Google の /o/saml2/idp）はログイン画面', () => {
    for (const loc of ['https://login.microsoftonline.com/tid/saml2?SAMLRequest=x', 'https://x.okta.com/app/y/sso/saml', 'https://accounts.google.com/o/saml2/idp?idpid=x']) {
      expect(ids(t('open-redirect', 'https://a.example/r?url=https://evil.example', `HTTP/2 302\nlocation: ${loc}`), 'T-06')).toEqual(['T-06.na']);
      expect(c12(t('after-logout', 'https://a.example/mypage', `HTTP/2 302\nlocation: ${loc}`))).toEqual(['C-12.ok']);
    }
  });
  it('18 A-01：{"authenticated":false,"user":null} は na', () => {
    expect(ids(t('unauth-me', 'https://a.example/api/me', JSON_HEAD, '{"authenticated":false,"user":null}'), 'A-01')).toEqual(['A-01.na']);
  });
  it('13 -L で別のサイトへ転送した先の Set-Cookie・Clear-Site-Data は、対象の Cookie として判定しない', () => {
    const idp = t('top', 'https://app.example.com/', `HTTP/2 302\nlocation: https://login.microsoftonline.com/x\n\n${HTML}\nset-cookie: buid=AbCdEf0123456789AbCdEf0123456789; Domain=.login.microsoftonline.com; Path=/; SameSite=None`, '<p>x</p>');
    expect(evaluate(idp).findings.filter(f => /^C-(?:03|04|06|11)\./.test(f.ruleId) && f.status === 'fail')).toEqual([]);
    const lo2 = t('logout', 'https://app.example.com/logout', 'HTTP/2 302\nlocation: https://idp.example.net/logout\n\nHTTP/2 200\nclear-site-data: "cookies"\nset-cookie: AUTH_SESSION_ID=; Max-Age=0; Path=/');
    expect(ids(lo2, 'C-12', 'logout')).not.toContain('C-12.ok');
    expect(ids(lo2, 'H-15', 'logout')).not.toContain('H-15.ok');
  });
});

describe('3・6・7・10・12・14・15・19〜22 判定', () => {
  it('10 Location のある 3xx の本文で HTML の項目を判定しない', () => {
    const r = ids(t('top', 'https://example.com/', 'HTTP/1.1 301 Moved Permanently\ncontent-type: text/html\nlocation: https://www.example.com/', '<html><head><title>301 Moved Permanently</title></head><body><center><h1>301 Moved Permanently</h1></center><hr><center>nginx</center></body></html>'), 'H-03');
    expect(r).not.toContain('H-03.1');
  });
  it('3 H-12：private だけの 302・303 は na のまま', () => {
    expect(ids(t('top', 'https://a.example/x', 'HTTP/2 302\nlocation: /y\ncache-control: private', 'Object moved', 'sensitive=1'), 'H-12')).toEqual(['H-12.na']);
    expect(ids(t('top', 'https://a.example/x', 'HTTP/2 403\ncontent-type: application/json\ncache-control: private', '{}', 'sensitive=1'), 'H-12')).toEqual(['H-12.2']);
  });
  it('6 E-09②：admin/pass123・pass admin123 は②、Knockout の <!-- ko if: showDebug --> は②にしない', () => {
    for (const c of ['admin/pass123', 'test user admin pass admin123']) expect(ids(t('top', 'https://a.example/', HTML, `<!-- ${c} -->`), 'E-09')).toContain('E-09.2');
    expect(ids(t('top', 'https://a.example/', HTML, '<!-- ko if: showDebug --><p>x</p><!-- /ko -->'), 'E-09')).not.toContain('E-09.2');
  });
  it('7・21 E-01：小文字の error at /… は②、nginx・Apache の既定のエラーページは③', () => {
    expect(ids(t('error-x', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/plain', 'Internal server error at /app/src/handler.js:10:5'), 'E-01')).toContain('E-01.2');
    expect(ids(t('error-url', 'https://a.example/x', 'HTTP/1.1 400 Bad Request\ncontent-type: text/html\nserver: cloudflare', '<html><head><title>400 Bad Request</title></head><body><center><h1>400 Bad Request</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>'), 'E-01')).toContain('E-01.3');
    expect(ids(t('error-url', 'https://a.example/x', 'HTTP/1.1 404 Not Found\ncontent-type: text/html', '<html><body><h1>Not Found</h1><hr><address>Apache/2.4.41 (Ubuntu) Server at a.example Port 443</address></body></html>'), 'E-01')).toContain('E-01.3');
  });
  it('12 E-05：Kubernetes の health（groups）と、既定の /actuator の一覧は合格', () => {
    expect(ids(t('t', 'https://a.example/actuator/health', JSON_HEAD, '{"status":"UP","groups":["liveness","readiness"]}'), 'E-05')).toEqual(['E-05.ok']);
    expect(ids(t('t', 'https://a.example/actuator', JSON_HEAD, '{"_links":{"self":{"href":"x"},"health":{"href":"y"},"health-path":{"href":"z"}}}'), 'E-05')).toEqual(['E-05.ok']);
    expect(ids(t('t', 'https://a.example/actuator', JSON_HEAD, '{"_links":{"self":{"href":"x"},"env":{"href":"y"}}}'), 'E-05')).toEqual(['E-05.1']);
  });
  it('14 E-09①：docsearch・Bugsnag の apiKey は①にしない', () => {
    expect(ids(t('top', 'https://a.example/', HTML, "<script>docsearch({ appId:'BH4D9OD16A', apiKey:'599cec31baffa4868cae4e79f180729b', indexName:'docs' })</script>"), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/', HTML, "<script>Bugsnag.start({ apiKey: 'c9d60ae4c7e70c4b6c4ebd3e8056d2b8' })</script>"), 'E-09')).not.toContain('E-09.1');
    expect(ids(t('top', 'https://a.example/', HTML, "<script>var cfg = { apiKey: 'c9d60ae4c7e70c4b6c4ebd3e8056d2b8' }</script>"), 'E-09')).toContain('E-09.1');
  });
  it('15 E-02：S3・Azure の一覧（XML）は①', () => {
    expect(ids(t('top', 'https://bucket.s3.amazonaws.com/', 'HTTP/2 200\ncontent-type: application/xml', '<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>backup/db.sql</Key></Contents></ListBucketResult>'), 'E-02')).toEqual(['E-02.1']);
    expect(ids(t('top', 'https://x.blob.core.windows.net/c?restype=container&comp=list', 'HTTP/2 200\ncontent-type: application/xml', '<?xml version="1.0"?><EnumerationResults ContainerName="c"><Blobs/></EnumerationResults>'), 'E-02')).toEqual(['E-02.1']);
  });
  it('19 A-03③：OIDC の id_token の email・name は③にしない', () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const idt = `${b64({ alg: 'RS256' })}.${b64({ iss: 'https://idp.example', aud: 'app', nonce: 'n', exp: 2000000000, email: 'a@example.com', name: 'A' })}.sig`;
    expect(ids(t('login', 'https://a.example/token', JSON_HEAD, `{"id_token":"${idt}"}`), 'A-03')).not.toContain('A-03.3');
  });
  it('20 E-04：/robots.txt に SPA の HTML が返るときは robots.txt なし', () => {
    const f = evaluate(t('top', 'https://a.example/robots.txt', HTML, '<!doctype html><html><div id="root"></div></html>')).findings.find(x => x.item === 'E-04');
    expect(f?.evidence).toContain('robots.txt なし');
  });
  it('22 R-06：-i で送った Origin の分からない固定の ACAO は na', () => {
    expect(ids(t('top', 'https://a.example/font.woff2', 'HTTP/2 200\ncontent-type: font/woff2\naccess-control-allow-origin: https://www.example.com', 'x'), 'R-06')).toEqual(['R-06.na']);
  });
});

describe('23〜28 マスク・要約・エクスポート・HAR', () => {
  it('23 英小文字だけのトークンの多くを伏せる（乱数の16〜24文字で9割以上）', () => {
    let seed = 7; const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
    let hit = 0; const n = 500;
    for (let i = 0; i < n; i++) { const len = 16 + Math.floor(rnd() * 9); const tok = Array.from({ length: len }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(rnd() * 26)]).join(''); if (!maskText(`https://a.example/invite/${tok}`).includes(tok)) hit++; }
    expect(hit / n).toBeGreaterThan(0.9);
    expect(maskText('https://a.example/docs/internationalization')).toBe('https://a.example/docs/internationalization');
  });
  it('24 authcode・otpcode・smscode・totp の値を伏せる。zipcode・errorcode は残す', () => {
    for (const q of ['authcode=482913', 'otpcode=889911', 'smscode=123456', 'totp=654321', 'vcode=111222']) expect(maskText(`https://a.example/cb?${q}`)).not.toContain(q.split('=')[1]);
    expect(maskText('https://a.example/x?zipcode=1000001&errorcode=E42')).toBe('https://a.example/x?zipcode=1000001&errorcode=E42');
  });
  it('25 #META cmd= に constructor があっても CSV を出せる', () => {
    const input = '#TARGET url=https://a.example/ label=top\n#META at=2026-11-01T10:00:00 cmd=curl_-sS_https://a.example/_|_constructor_-v\nHTTP/2 200\n\n';
    const r = evaluate(input);
    expect(() => toCsv(r.findings, r.targets)).not.toThrow();
  });
  it('26 要約：パス・クエリの @ のある URL と、sudo・timeout のあとの curl を読む', () => {
    // 第33回（T9）：URL のあとに @ がある URL は、ユーザー情報の途中で切れた URL と見分けないので **** にする（伏せすぎを選ぶ）。秘密は出ない
    expect(summarizeCommand('curl "https://a.example/s?email=alice@example.com&page=2"')).toBe('curl ****');
    expect(summarizeCommand('curl https://mastodon.example/@alice/1')).toBe('curl ****');
    expect(summarizeCommand('sudo curl -u a:b https://a.example/')).toBe('sudo curl -u **** https://a.example/');
    expect(summarizeCommand('timeout 10 curl -sS https://a.example/')).toBe('timeout 10 curl -sS https://a.example/');
    // パスワードに / のあるユーザー情報は、今までどおり ****
    expect(summarizeCommand('curl https://alice:pa/ss@a.example/')).not.toMatch(/alice|pa\/ss/);
  });
  it('27 応答のヘッダが {} や本文が数値の壊れたエントリがあっても、HAR を取り込める', () => {
    const e = (url: string, headers: unknown, text: unknown) => ({ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url, headers: [] }, response: { status: 200, httpVersion: 'HTTP/2', headers, content: { mimeType: 'application/json', text } } });
    const imp = importHar(JSON.stringify({ log: { entries: [e('https://a.example/a', {}, 12345), e('https://a.example/b', [{ name: 'content-type', value: 'text/html' }], '<p>x</p>')] } }));
    expect(imp.chains.length).toBe(2);
    expect(() => harTargets(imp, new Set(imp.hosts))).not.toThrow();
  });
  it('28 CSV：cmd=- はそのまま、実施日時は時刻で最も新しいもの（T 区切りと空白区切りが混ざっても）', () => {
    const input = pre.replace('#META at=2026-11-01T10:00:00', '#META at="2026-11-01 23:00:00" cmd=-') + t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly');
    const r = evaluate(input);
    const row = toCsv(r.findings, r.targets).split('\n').find(l => l.startsWith('C-09'));
    expect(row).toContain('2026-11-01 23:00:00');
    expect(row).not.toContain("'-");
  });
});

// コミット前のレビュー（差分だけを見る独立したレビュアー）で見つかった、上の修正の退行
describe('コミット前のレビュー', () => {
  it('P1 要約：ホストのあとまで続いたユーザー情報（パスに / が2つ以上、//、バックスラッシュ、?、#）を出さない', () => {
    for (const c of ['curl https://alice.smith:2024/p/w@host.example/', 'curl "https://bob.example:1234/x/y/z@host.example"', String.raw`curl https://alice.smith:1\2\3@host.example/`,
      'curl https://alice.smith:12//pw@host.example/', 'curl https://alice.smith:1?x=y@host.example/', 'curl https://alice.smith:1#a/b@host.example/', 'curl HTTPS://alice.smith:77/a/b@host.example',
      'wget https://alice.smith:2024/p/w@host.example/']) expect(summarizeCommand(c)).not.toMatch(/alice|bob|2024|1234|p\/w|pw/);
  });
  it('P7 要約：前置きのプログラム（time・nohup・exec・stdbuf・command）のあとも、もう一度かけて変わらない。sudo のあとの数字は出さない', () => {
    for (const c of ['time curl -u alice:secret https://a.example/', 'nohup curl -u alice:secret https://a.example/', 'exec curl https://a.example/', 'sudo nohup curl -u a:b https://a.example/',
      'stdbuf -oL curl https://a.example/', 'command alicepassword123 curl https://a.example/']) {
      const once = summarizeCommand(c);
      expect(summarizeCommand(once)).toBe(once);
      expect(once).not.toMatch(/alice|secret/);
    }
    expect(summarizeCommand('time curl -sS https://a.example/')).toBe('time curl -sS https://a.example/');
    expect(summarizeCommand('sudo 12345 curl https://a.example/')).not.toContain('12345');
  });
  it('P2 例外：URL のパターンをラベルだけのキーに当てない（*login* が login・pre-login ラベルの指摘を抑止しない）', () => {
    const g = (target: string, url: string) => ({ item: 'C-01', ruleId: 'C-01.1', status: 'fail', target, targetKey: target, url, keyUrl: urlKey(url) } as Finding);
    const fs = [g('pre-login', 'https://a.example/'), g('login', 'https://a.example/'), g('top', 'https://a.example/account/login')];
    expect(applySuppressions(fs, [{ ruleId: 'C-01', target: '*login*', reason: 'x' } as never]).map(x => x.status)).toEqual(['fail', 'fail', 'suppressed']);
    expect(applySuppressions(fs, [{ ruleId: 'C-01', target: 'log*', reason: 'x' } as never]).map(x => x.status)).toEqual(['fail', 'fail', 'fail']);
  });
  it('P3 C-09：期限付きの sessionid を再発行せず、auth_token を足しただけなら①', () => {
    const p = t('pre-login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Expires=Wed, 01 Dec 2027 00:00:00 GMT; Path=/; Secure; HttpOnly`, '<form method="post"><input name="u"><input type="password" name="p"></form>');
    expect(c09(t('login', 'https://a.example/login', 'HTTP/2 302\nlocation: /mypage\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Expires=Wed, 01 Dec 2027 00:00:00 GMT; Path=/; Secure; HttpOnly\nset-cookie: auth_token=Qq99Ww88Ee77Rr66Tt55Yy44Uu33Ii22; Path=/; Secure; HttpOnly'), p)).toEqual(['C-09.1']);
  });
  it('P4 A-03③：azp のあるアクセストークン（Keycloak）の email は③。id_token の欄の JWT は③にしない', () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const at = `${b64({ alg: 'RS256' })}.${b64({ iss: 'https://idp.example', aud: 'account', azp: 'web', exp: 2000000000, email: 'a@example.com', name: 'A', preferred_username: 'a' })}.sig`;
    expect(ids(t('login', 'https://a.example/token', JSON_HEAD, `{"access_token":"${at}"}`), 'A-03')).toContain('A-03.3');
    const idt = `${b64({ alg: 'RS256' })}.${b64({ iss: 'https://idp.example', aud: 'app', exp: 2000000000, email: 'a@example.com' })}.sig`;
    expect(ids(t('login', 'https://a.example/token', JSON_HEAD, `{"id_token":"${idt}"}`), 'A-03')).not.toContain('A-03.3');
  });
  it('P5 C-12：設定・構造化データ・ルート以外の data- 属性だけの SPA の画面は na のまま', () => {
    const shell = '<div id="root"></div><script src="/assets/index.js"></script>';
    for (const x of ['<script>window.__ENV__ = {"API_URL":"https://api.example"}</script>', '<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Example"}</script>',
      '<div class="spinner" data-testid="loading"></div>', '<script>window.dataLayer = window.dataLayer || []; window.dataLayer = [];</script>'])
      expect(c12(t('after-logout', 'https://a.example/mypage', HTML, shell + x, 'sensitive=1'))).toEqual(['C-12.na']);
  });
  it('P12 C-12：false の値を持つ利用者のデータ（isAdmin・mfaEnabled）は①', () => {
    expect(c12(t('after-logout', 'https://a.example/api/me', JSON_HEAD, '{"isAdmin":false,"mfaEnabled":false,"user":{}}', 'sensitive=1'))).toEqual(['C-12.1']);
  });
  it('P6 英語の語をつないだパスは、画面にもキーにもそのまま', () => {
    for (const w of ['healthcheckstatus', 'nightschoolprograms', 'searchstringhelper', 'strengthsandweaknesses', 'lightweightwrapper']) {
      expect(urlKey(`https://a.example/api/${w}`)).toBe(`https://a.example/api/${w}`);
      expect(maskText(`https://a.example/api/${w}`)).toBe(`https://a.example/api/${w}`);
    }
  });
  it('P8 E-01③：nginx・Apache の既定の 301 の本文は③にしない', () => {
    expect(ids(t('top', 'http://a.example/', 'HTTP/1.1 301 Moved Permanently\ncontent-type: text/html\nlocation: https://a.example/', '<html><head><title>301 Moved Permanently</title></head><body><center><h1>301 Moved Permanently</h1></center><hr><center>nginx</center></body></html>'), 'E-01')).not.toContain('E-01.3');
    expect(ids(t('top', 'http://a.example/', 'HTTP/1.1 302 Found\ncontent-type: text/html\nlocation: https://a.example/', '<html><body><h1>Found</h1><hr><address>Apache/2.4.41 (Ubuntu) Server at a.example Port 80</address></body></html>'), 'E-01')).not.toContain('E-01.3');
  });
  it('P9 E-09：転送の本文の秘密は見る（H-03 は見ない）', () => {
    const x = t('top', 'https://a.example/', 'HTTP/2 302\ncontent-type: text/html\nlocation: /home', '<script>var apiKey = "sk_live_51HxQwErTyUiOpAsDfGhJkL0123";</script>');
    expect(ids(x, 'E-09')).toContain('E-09.1');
    expect(ids(x, 'H-03')).toEqual([]);
  });
  it('P10 E-04：text/html で返した robots.txt の中身も見る', () => {
    expect(ids(t('top', 'https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/html', 'User-agent: *\nDisallow: /admin/'), 'E-04')).toContain('E-04.1');
  });
  it('P11 E-09②：「tests pass 100%」「pass 2 of 3」は開発用コメントにしない', () => {
    for (const c of ['all tests pass 100%', 'step: pass 2 of 3']) expect(ids(t('top', 'https://a.example/', HTML, `<!-- ${c} -->`), 'E-09')).not.toContain('E-09.2');
  });
});
