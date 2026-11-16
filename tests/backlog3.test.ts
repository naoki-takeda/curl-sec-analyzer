// 積み残しへの対応（第26回、3回目：第22〜24回の「未対応」のうち低の指摘）の再現テスト。
// 入力の多くは tests/golden/cases/12-backlog3.txt にも入れてある（結果の全体をゴールデンテストで比べる）
import { describe, expect, it } from 'vitest';
import { clip, maskText } from '../src/mask';
import { parseInput } from '../src/parser/input';
import { parseOpenssl } from '../src/parser/openssl';
import { coverage, PARTIAL } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { evaluate } from './helpers';

const t = (label: string, url: string, head: string, body = '', at = '2026-11-01T10:00:00') => `#TARGET url=${url} label=${label}\n#META at=${at}\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string, target?: string) =>
  evaluate(input).findings.filter(f => f.item === item && (!target || f.target === target)).map(f => f.ruleId).sort();

/** OpenSSL 3.5 の s_client -showcerts（EC 鍵の行は長さの代わりに曲線の名前を出す。CONNECTED の前に Connecting to を出す） */
const ossl35 = (leafSig: string) => [
  'Connecting to 192.0.2.10', 'CONNECTED(00000003)', '---', 'Certificate chain',
  ' 0 s:CN=www.example.com', '   i:C=US, O=Example CA, CN=Example Issuing CA',
  `   a:PKEY: EC, (prime256v1); sigalg: ${leafSig}`, '   v:NotBefore: Oct  1 00:00:00 2026 GMT; NotAfter: Oct  1 00:00:00 2027 GMT',
  ' 1 s:C=US, O=Example CA, CN=Example Issuing CA', '   i:C=US, O=Example CA, CN=Example Root CA',
  '   a:PKEY: rsaEncryption, 2048 (bit); sigalg: sha256WithRSAEncryption',
  ' 2 s:C=US, O=Example CA, CN=Example Root CA', '   i:C=US, O=Example CA, CN=Example Root CA',
  '   a:PKEY: rsaEncryption, 4096 (bit); sigalg: sha1WithRSAEncryption',
  '---', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', 'Verify return code: 0 (ok)'].join('\n');

describe('OpenSSL 3.5 の出力', () => {
  it('EC 鍵の行（a:PKEY: EC, (prime256v1)）を読み、リーフの SHA-1 の署名を T-10② にする', () => {
    const info = parseOpenssl(ossl35('ecdsa-with-SHA256').split('\n'))!;
    expect([info.keyType, info.keyBits, info.sigalgs[0]]).toEqual(['EC', 256, 'ecdsa-with-SHA256']);
    expect(ids(`#TARGET url=https://www.example.com/ label=tls\n${ossl35('ecdsa-with-SHA1')}\n`, 'T-10')).toEqual(['T-10.2']);
  });
  it('ルート証明書の SHA-1 の署名は T-10② にしない', () => {
    expect(ids(`#TARGET url=https://www.example.com/ label=tls\n${ossl35('ecdsa-with-SHA256')}\n`, 'T-10')).toEqual(['T-10.ok']);
  });
  it('次の行が CONNECTED( でない「Connecting to」は、openssl の出力とみなさない（コミット前のレビュー）', () => {
    const r = evaluate('#TARGET url=https://www.example.com/ label=top\nConnecting to www.example.com\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n');
    expect(r.targets[0].openssl).toEqual([]);
    expect(r.findings.filter(f => /^T-1[01]/.test(f.ruleId))).toEqual([]);
  });
  it('「Connecting to」の行で、解析できない行の警告を出さない', () => {
    const { warnings } = parseInput(`#TARGET url=https://www.example.com/ label=tls\n${ossl35('ecdsa-with-SHA256')}\n`);
    expect(warnings.map(w => w.kind)).not.toContain('unparsed-lines');
  });
});

describe('プロキシを使った -v', () => {
  it('最初の行の「* Uses proxy env variable」で、解析できない行の警告を出さない', () => {
    const input = ['#TARGET url=https://www.example.com/ label=top', "* Uses proxy env variable https_proxy == 'http://proxy.example:3128'",
      '* Connected to proxy.example (192.0.2.1) port 3128', '> GET / HTTP/1.1', '> Host: www.example.com', '>', '< HTTP/1.1 200 OK', '< content-type: text/html', '<', ''].join('\n');
    const { targets, warnings } = parseInput(input);
    expect(warnings.map(w => w.kind)).not.toContain('unparsed-lines');
    expect(targets[0].responses.map(r => r.status)).toEqual([200]);
  });
});

describe('CR が長く続く入力', () => {
  it('LF のない CR の並びを、入力の長さに比例した時間で読む', () => {
    const input = `#TARGET url=https://www.example.com/ label=top\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n${'\r'.repeat(200_000)}x\n`;
    const start = performance.now();
    parseInput(input);
    expect(performance.now() - start).toBeLessThan(1000);
  });
  it('改行の扱いは変えない（CR CR LF は1つの改行、LF のない CR CR は空行）', () => {
    const a = parseInput('#TARGET url=https://a.example/ label=a\r\r\nHTTP/1.1 200 OK\r\r\ncontent-type: text/html\r\r\nx-a: 1\r\r\n\r\r\nbody\r\r\n').targets[0].responses[0];
    expect([...a.headers.keys()]).toEqual(['content-type', 'x-a']);
    const b = parseInput('#TARGET url=https://a.example/ label=a\rHTTP/1.1 200 OK\rcontent-type: text/html\r\rx-b: 1\r').targets[0].responses[0];
    expect([...b.headers.keys()]).toEqual(['content-type']);
    expect(b.body).toContain('x-b: 1');
  });
});

describe('T-10・T-11 の結果が入力の順番で変わらない', () => {
  const cert = (label: string, notAfter: string, at: string) => [`#TARGET url=https://www.example.com/ label=${label}`, `#META at=${at}`,
    'CONNECTED(00000003)', 'Verify return code: 0 (ok)', 'subject=CN = www.example.com', 'notBefore=Oct  1 00:00:00 2025 GMT', `notAfter=${notAfter}`,
    'X509v3 Subject Alternative Name:', '    DNS:www.example.com', ''].join('\n');
  const failed = ['#TARGET url=https://www.example.com/ label=tls-x', '#META at=2026-11-01T10:00:00', 'CONNECTED(00000003)',
    '40F7B1E7D27F0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure', '---', 'no peer certificate available', ''].join('\n');
  const old = cert('tls-old', 'Oct  1 00:00:00 2026 GMT', '2026-09-01T10:00:00');
  const fresh = cert('tls-new', 'Oct  1 00:00:00 2027 GMT', '2026-11-01T10:00:00');
  it('採取した時刻が新しいものを使う（どちらの順番でも同じ）', () => {
    expect(ids(old + fresh, 'T-11')).toEqual(['T-11.ok']);
    expect(ids(fresh + old, 'T-11')).toEqual(['T-11.ok']);
  });
  it('採取した時刻のない出力は、時刻のある出力より後にする（コミット前のレビュー）', () => {
    const undated = cert('tls-undated', 'Oct  1 00:00:00 2021 GMT', '').replace('#META at=\n', '');
    expect(ids(undated + fresh, 'T-11')).toEqual(['T-11.ok']);
    expect(ids(fresh + undated, 'T-11')).toEqual(['T-11.ok']);
  });
  it('ハンドシェイクに失敗した出力より、証明書の分かる出力を使う', () => {
    expect(ids(failed + fresh, 'T-11')).toEqual(['T-11.ok']);
    expect(ids(fresh + failed, 'T-11')).toEqual(['T-11.ok']);
  });
  it('T-10 は鍵・署名の分かる出力を使う（x509 -noout だけの出力が先にあっても）', () => {
    const tls = `#TARGET url=https://www.example.com/ label=tls\n${ossl35('ecdsa-with-SHA1')}\n`;
    expect(ids(fresh + tls, 'T-10')).toEqual(['T-10.2']);
    expect(ids(tls + fresh, 'T-10')).toEqual(['T-10.2']);
  });
});

describe('C-12②：セッションを作り直すログアウト', () => {
  const lo = (h: string) => ids(t('logout', 'https://a.example/logout', `HTTP/2 302\nlocation: /\n${h}`), 'C-12', 'logout');
  it('Laravel・Rails の、セッションCookie を新しい値で発行し直すログアウトは②にしない（新しい値かは分からないので na）', () => {
    expect(lo('set-cookie: laravel_session=eyJpdiI6IkNBTkFSWW5ldyJ9; path=/; secure; httponly; samesite=lax')).toEqual(['C-12.na']);
    expect(lo('set-cookie: _myapp_session=NewSessionValue0123456789; path=/; secure; httponly')).toEqual(['C-12.na']);
    expect(lo('set-cookie: remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/\nset-cookie: laravel_session=eyJpdiI6IkNBTkFSWW5ldyJ9; path=/; secure; httponly')).toEqual(['C-12.na']);
  });
  it('セッションCookie でない Cookie を発行しただけなら、今までどおり②', () => {
    expect(lo('set-cookie: theme=dark; path=/')).toEqual(['C-12.2']);
  });
  it('セッションCookie を消していれば、今までどおり合格', () => {
    expect(lo('set-cookie: laravel_session=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/')).toEqual(['C-12.ok']);
  });
});

describe('E-04：一般のターゲットの security.txt', () => {
  const sec = (body: string) => ids(t('sec', 'https://www.example.com/.well-known/security.txt', 'HTTP/2 200\ncontent-type: text/plain', body), 'E-04');
  it('期限切れなら②を出す（合格だけを出し、②を消していた）', () => {
    expect(sec('Contact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00.000Z')).toEqual(['E-04.2']);
    expect(sec('Contact: mailto:security@example.com')).toEqual(['E-04.2']);
  });
  it('404 と、SPA が返した HTML の画面は「security.txt がない」（②）。証跡にステータスを出す（コミット前のレビュー）', () => {
    const get = (head: string, body: string) => evaluate(t('sec', 'https://www.example.com/.well-known/security.txt', head, body)).findings.filter(f => f.item === 'E-04').map(f => `${f.ruleId} ${f.evidence}`);
    expect(get('HTTP/2 404\ncontent-type: text/html', '<html>Not Found</html>')).toEqual(['E-04.2 security.txt を取得できない（HTTP 404）']);
    expect(get('HTTP/2 200\ncontent-type: text/html', '<!doctype html><html><div id="app"></div></html>')).toEqual(['E-04.2 HTML の画面が返った（security.txt ではない。HTTP 200）']);
  });
  it('robots.txt の 404 は「機密パスらしき記述なし」ではなく「robots.txt なし」（コミット前のレビュー）', () => {
    expect(evaluate(t('robots', 'https://www.example.com/robots.txt', 'HTTP/2 404\ncontent-type: text/html', '<html>Not Found</html>')).findings.filter(f => f.item === 'E-04').map(f => f.evidence)).toEqual(['robots.txt なし（HTTP 404）']);
  });
  it('有効なら合格', () => {
    expect(sec('Contact: mailto:security@example.com\nExpires: 2027-12-31T00:00:00.000Z')).toEqual(['E-04.ok']);
  });
});

describe('カバレッジの「一部の条件は入力不足」（第25回で直っていたことの確認）', () => {
  const partial = (input: string, item: string) => coverage(evaluate(input).findings, IMPLEMENTED).find(c => c.item === item)!.reasons[0];
  it('logout だけ（after-logout がない）なら C-12 に示す', () => {
    expect(partial(t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /\nset-cookie: JSESSIONID=; Max-Age=0; path=/'), 'C-12')).toBe(PARTIAL);
  });
  it('preload を付けたターゲットがあり apex がないなら H-02 に示す', () => {
    expect(partial(t('top', 'https://www.example.com/', 'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains; preload'), 'H-02')).toBe(PARTIAL);
  });
});

describe('H-16①：Via の製品の版', () => {
  const via = (v: string) => ids(t('top', 'https://www.example.com/', `HTTP/2 200\ncontent-type: text/html\nvia: ${v}`), 'H-16');
  it('「名前/版」の形があれば①', () => {
    expect(via('1.1 varnish (Varnish/7.4)')).toEqual(['H-16.1']);
    expect(via('1.1 proxy.example (squid/4.10)')).toEqual(['H-16.1']);
  });
  it('プロトコルの版（1.1、HTTP/1.1）と製品名だけは指摘しない', () => {
    expect(via('1.1 vegur')).toEqual(['H-16.ok']);
    expect(via('HTTP/1.1 abc.cloudfront.net (CloudFront)')).toEqual(['H-16.ok']);
    for (const v of ['HTTPS/1.1 proxy', 'SPDY/3.1 x', '1.1 SHTTP/1.3']) expect(via(v)).toEqual(['H-16.ok']);
  });
});

describe('マスク', () => {
  it('パスの途中の「//」の直後のトークンも伏せる', () => {
    expect(maskText('https://a.example/reset//Ab3dEf7GhJ2kLm9NpQ4rSt')).not.toContain('Ab3dEf7GhJ2kLm9NpQ4rSt');
    expect(maskText('/reset//Ab3dEf7GhJ2kLm9NpQ4rSt')).not.toContain('Ab3dEf7GhJ2kLm9NpQ4rSt');
  });
  it('ホスト名（スキームのあと・スキームのない「//」のあと・パラメータの値の「//」のあと）は今までどおり伏せない', () => {
    for (const s of ['https://staging-customer-portal-frontend-01.example.com/', '<script src="//cdn0123456789abcdefABC.example.net/a.js">', '?next=//portal2026Frontend01Staging.example.com/'])
      expect(maskText(s)).toBe(s);
  });
  it('語と短い数字をつないだ名前は伏せない', () => {
    for (const s of ['/img/MyCompanyLogo2026Final.png', '/docs/GettingStartedV2Guide', '/api/v1/UserProfileSettings2024', '/files/AnnualReportFY2025Summary.pdf'])
      expect(maskText(s)).toBe(s);
  });
  it('乱数のトークンは今までどおり伏せる', () => {
    for (const tok of ['Dk3x9Lq2AbZ7Qw8EmNp4', 'Ab3dEf7GhJ2kLm9NpQ4rSt', 'x9Kp2Lm7Qa4Zb8Wc3Ve6Rt1Yu5Io0Pa', 'CfDJ8Qw7Er2Ty9Ui4Op1As6Df3Gh8Jk5Lz0Xc'])
      expect(maskText(`/reset/${tok}`)).not.toContain(tok);
  });
  it('SRI と CSP のハッシュは途中で伏せない', () => {
    const sri = '<script src="/a.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous">';
    const csp = "script-src 'self' 'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=' 'sha512-pKvURIxJVi2CgRXROh/M6pJ/UrTVRZKX+LQ+QtqJI4vBNibkPcs43bCCSIkn7JBPtCBXRDmD6IWFF51QVRr+Yg=='";
    expect(maskText(sri)).toBe(sri);
    expect(maskText(csp)).toBe(csp);
  });
  it('ハッシュの長さと違う sha256-… のあとのパスのトークンは伏せる（コミット前のレビュー）', () => {
    for (const s of ['https://a.example/sha256-abcdefghijklmnopqrstu/reset/Ab3dEf7GhJ2kLm9NpQ4rSt', '/x/sha512-Ab3dEf7GhJ2kLm9NpQ4rSt',
      'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC/Ab3dEf7GhJ2kLm9NpQ4rSt"'])
      expect(maskText(s)).not.toContain('Ab3dEf7GhJ2kLm9NpQ4rSt');
  });
  it('「///」の直後のトークンも伏せる。エンコードしたスキーム（https%3A//）の直後のホスト名は伏せない（コミット前のレビュー）', () => {
    expect(maskText('/reset///Ab3dEf7GhJ2kLm9NpQ4rSt')).not.toContain('Ab3dEf7GhJ2kLm9NpQ4rSt');
    for (const s of ['?redirect_uri=https%3A//cdn0123456789abcdefABC.example.net/cb', '?r=https%253A//cdn0123456789abcdefABC.example.net/cb'])
      expect(maskText(s)).toBe(s);
  });
  it('秘密らしい語を含む名前と、語の少ない名前は、語だけでできていても伏せる（コミット前のレビュー）', () => {
    for (const tok of ['SessionToken2024Value', 'ProdApiKey2025Secret', 'HelloWorldSecretKey2026', 'MyAuthCode2026Value', 'fvbkkluzuqyYZH9J', 'xogBinidv3IOMELU', 'PoqyPNXN3Cjkochh', 'kh8uerlepa7qxrulidue1qxauypawhiq'])
      expect(maskText(`/x/${tok}`)).not.toContain(tok);
    expect(maskText('/api/v2/OrderHistory2024Export_csv')).toBe('/api/v2/OrderHistory2024Export_csv');
  });
  it('証跡の切り詰めで、伏せた値の印の途中で切らない', () => {
    const s = 'xxxxxxxxxx?token=abcdefghijklmnopqrstuvwxyz and more text';
    const full = maskText(s);
    const at = full.indexOf('…(') + 3;
    expect(clip(s, at)).toMatch(/…\(26 chars\)$/);
    expect(clip(s, 5)).toBe('xxxxx');
    expect(clip(s, full.length + 10)).toBe(full);
  });
});
