// 積み残しの対応（2回目：第10〜19回の「未対応」のうち、中・低の判定の誤り）の再現テスト
import { describe, expect, it } from 'vitest';
import { diff } from '../../src/engine/diff';
import { runAll } from '../../src/engine/run';
import { parseInput } from '../../src/parser/input';
import { evaluate, fixture } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_CT = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
/** -v の出力（送ったヘッダと受け取ったヘッダ） */
const v = (label: string, url: string, sent: string[], recv: string[], extra = '') =>
  [`#TARGET url=${url} label=${label} ${extra}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname} HTTP/1.1`,
    ...sent.map(s => `> ${s}`), '>', ...recv.map(s => `< ${s}`), '<', ''].join('\n');
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const page = (head: string, body = '') => t('top', 'https://a.example/', `${HTML}\n${head}`, body);

describe('第1章 ヘッダ', () => {
  it('H-01：max-age=0（HSTS を解除する指定）は①（高）。短い max-age は今までどおり②', () => {
    expect(ids(page('strict-transport-security: max-age=0'), 'H-01')).toEqual(['H-01.1']);
    expect(ids(page('strict-transport-security: max-age=86400'), 'H-01')).toEqual(['H-01.2']);
  });

  it('H-06：X-Frame-Options の不正な値（ALLOWALL・綴りの誤り）は、ブラウザが無視するので①', () => {
    expect(ids(page('x-frame-options: ALLOWALL'), 'H-06')).toEqual(['H-06.1']);
    expect(ids(page('x-frame-options: SAMEORGIN'), 'H-06')).toEqual(['H-06.1']);
    // HTML Standard：2つ以上の値に deny・sameorigin があれば拒否。同じ値の繰り返しは1つ
    expect(ids(page('x-frame-options: ALLOW-FROM https://b.example, DENY'), 'H-06')).toEqual(['H-06.3']);
    expect(ids(page('x-frame-options: SAMEORIGIN\nx-frame-options: SAMEORIGIN'), 'H-06')).toEqual(['H-06.3']);
    expect(ids(page('x-frame-options: DENY'), 'H-06')).toEqual(['H-06.3']);
    expect(ids(page('x-frame-options: ALLOW-FROM https://b.example'), 'H-06')).toEqual(['H-06.2']);
  });

  it('H-06④：frame-ancestors * のポリシーと \'none\' のポリシーが両方あれば、制限は \'none\'（合格）', () => {
    expect(ids(page("content-security-policy: frame-ancestors *\ncontent-security-policy: frame-ancestors 'none'"), 'H-06')).toEqual(['H-06.ok']);
    expect(ids(page("content-security-policy: frame-ancestors *\ncontent-security-policy: frame-ancestors https:"), 'H-06')).toEqual(['H-06.4']);
  });

  it('H-08・A-09②：プロキシが付け足した「nosniff, nosniff」は nosniff（Fetch Standard は最初の値で見る）', () => {
    expect(ids(page('x-content-type-options: nosniff, nosniff'), 'H-08')).toEqual(['H-08.ok']);
    expect(ids(page('x-content-type-options: nosniff\nx-content-type-options: nosniff'), 'H-08')).toEqual(['H-08.ok']);
    expect(ids(t('api', 'https://a.example/api', `${JSON_CT}\nx-content-type-options: nosniff, nosniff`, '{"a":1}'), 'A-09')).not.toContain('A-09.2');
    expect(ids(page('x-content-type-options: sniff, nosniff'), 'H-08')).toEqual(['H-08.1']);   // 最初の値が nosniff でなければ効かない
  });

  it('CSP：1つのヘッダ値の中のカンマはポリシーの区切り（, frame-ancestors \'none\' を前のディレクティブの値にしない）', () => {
    const csp = "content-security-policy: script-src 'nonce-AbCdEf0123456789xyz' 'strict-dynamic'; object-src 'none'; base-uri 'none', frame-ancestors 'none'";
    expect(ids(page(csp), 'H-06')).toEqual(['H-06.ok']);
    expect(ids(page(csp), 'H-07')).toEqual(['H-07.ok']);
    expect(ids(page(csp), 'H-04')).toContain('H-04.ok');
    // 緩いポリシーと厳しいポリシーをカンマでつないでも、緩いほうだけで①②にしない（ブラウザはすべてのポリシーを満たすものだけを許すので、
    // 'self' のポリシーがインラインと * を止める）。第29回から、別のポリシーが同じ条件の指摘なしにスクリプトを制限していれば H-04 の指摘も出さない
    const both = ids(page("content-security-policy: script-src * 'unsafe-inline', script-src 'self'"), 'H-04');
    expect(both).not.toContain('H-04.1');
    expect(both).not.toContain('H-04.2');
  });

  it('H-02③：別のサイトの preload で、apex を③にしない', () => {
    const www = (host: string) => t('www', `https://${host}/`, `${HTML}\nstrict-transport-security: max-age=63072000; includeSubDomains; preload`);
    const apex = t('apex', 'https://a.example/', HTML);
    expect(evaluate(www('www.b.example') + apex).findings.filter(f => f.ruleId === 'H-02.3')).toHaveLength(0);
    expect(evaluate(www('www.a.example') + apex).findings.filter(f => f.ruleId === 'H-02.3')).toHaveLength(1);   // 同じサイトなら今までどおり
  });

  it('H-07③：http のページは混在コンテンツの対象外（E-07 と同じ）', () => {
    const http = t('top', 'http://a.example/', "HTTP/1.1 200 OK\ncontent-type: text/html; charset=utf-8\ncontent-security-policy: default-src 'self'", '<img src="http://a.example/x.png">');
    expect(ids(http, 'H-07')).not.toContain('H-07.3');
    expect(ids(page("content-security-policy: default-src 'self'", '<img src="http://a.example/x.png">'), 'H-07')).toContain('H-07.3');
  });

  it('H-11：機密応答かどうか分からず CORP もなければ、COOP があっても合格にしない', () => {
    expect(ids(page('cross-origin-opener-policy: same-origin'), 'H-11')).toEqual(['H-11.na']);
    expect(ids(page('cross-origin-opener-policy: same-origin\ncross-origin-resource-policy: same-origin'), 'H-11')).toEqual(['H-11.ok']);
    expect(ids(t('top', 'https://a.example/', `${HTML}\ncross-origin-opener-policy: same-origin`, '', 'sensitive=0'), 'H-11')).toEqual(['H-11.ok']);
    expect(ids(page(''), 'H-11')).toEqual(['H-11.2']);
  });

  it('H-16・E-09③：主な版だけの X-Generator・generator（Drupal 10）を見逃さない。版のない X-Generator は②', () => {
    expect(ids(page('x-generator: Drupal 10 (https://www.drupal.org)'), 'H-16')).toEqual(['H-16.1']);
    expect(ids(page('x-generator: Drupal'), 'H-16')).toEqual(['H-16.2']);
    expect(ids(page('server: AmazonS3'), 'H-16')).toEqual(['H-16.2']);   // Server の製品名の数字は版にしない
    expect(ids(page('', '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">'), 'E-09')).toContain('E-09.3');
  });
});

describe('第2章 Cookie', () => {
  it('C-04：-L で転送した先のホストが発行した Cookie は、そのホストと比べる', () => {
    const r = ids(t('top', 'https://a.example/', 'HTTP/2 301\nlocation: https://www.a.example/\n\nHTTP/2 200\ncontent-type: text/html\nset-cookie: pref=1; Domain=.a.example; Secure'), 'C-04');
    expect(r).toEqual(['C-04.1']);                                   // www が親ドメインに広げた
    const same = evaluate(t('top', 'https://a.example/', 'HTTP/2 301\nlocation: https://www.a.example/\n\nHTTP/2 200\ncontent-type: text/html\nset-cookie: pref=1; Domain=www.a.example; Secure')).findings.filter(f => f.item === 'C-04');
    expect(same.map(f => f.ruleId)).toEqual(['C-04.3']);             // 親ドメインではない（①にしない）
    expect(same[0].evidence).toContain('ホスト www.a.example');
  });

  it('C-04③：Domain がホストと同じでも、サブドメインに送られる（低）。Domain なしは合格', () => {
    expect(ids(page('set-cookie: pref=1; Domain=a.example; Secure'), 'C-04')).toEqual(['C-04.3']);
    expect(ids(page('set-cookie: pref=1; Secure'), 'C-04')).toEqual(['C-04.ok']);
    expect(ids(page('set-cookie: pref=1; Domain=; Secure'), 'C-04')).toEqual(['C-04.ok']);   // 空の Domain はブラウザが無視する
  });

  it('C-05：空の Max-Age は無視され、Expires の長い期限を見逃さない', () => {
    const sid = 'sessionid=Zx8f9aQ2LmN4pR7sT1vW3yB5cD6eF0gH';
    expect(ids(page(`set-cookie: ${sid}; Max-Age=; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Secure; HttpOnly`), 'C-05')).toEqual(['C-05.1']);
    expect(ids(page(`set-cookie: ${sid}; Max-Age=abc; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Secure; HttpOnly`), 'C-05')).toEqual(['C-05.1']);
    expect(ids(page(`set-cookie: ${sid}; Max-Age=3600; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Secure; HttpOnly`), 'C-05')).toEqual(['C-05.ok']);   // Max-Age が優先
  });

  it('C-06：小文字の __host-・__secure- にも条件を求める（今のブラウザは大文字小文字を区別しない）', () => {
    const v = 'Zx8f9aQ2LmN4pR7sT1vW3yB5cD6eF0gH';
    expect(ids(page(`set-cookie: __host-sid=${v}; Secure; HttpOnly; Path=/app`), 'C-06')).toEqual(['C-06.2']);
    expect(ids(page(`set-cookie: __host-sid=${v}; Secure; HttpOnly; Path=/`), 'C-06')).toEqual(['C-06.ok']);
    expect(ids(page(`set-cookie: __SECURE-sid=${v}; HttpOnly`), 'C-06')).toContain('C-06.2');
  });

  it('C-07①：時刻から作る UUID（v1・v7）のセッションIDを、文字種の推定で合格にしない', () => {
    // C-07② は横断ルール（session-sample-*）なので、login のターゲットの①だけを見る
    const login = (val: string) => evaluate(t('login', 'https://a.example/login', `${HTML}\nset-cookie: sessionid=${val}; Secure; HttpOnly; SameSite=Lax`)).ids('login').filter(id => id.startsWith('C-07'));
    expect(login('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).toEqual(['C-07.1']);   // v1
    expect(login('01890a5d-ac96-774b-bcce-b302099a8057')).toEqual(['C-07.1']);   // v7
    expect(login('f47ac10b-58cc-4372-a567-0e02b2c3d479')).toEqual(['C-07.ok']);  // v4 は今までどおり（ASVS の128bitとの差は別に決める）
  });
});

describe('第3章 CORS', () => {
  it('R-01：自サイトの Origin（同じホスト・サブドメイン）を送った応答では、反射を指摘しない（na）', () => {
    const self = (origin: string) => ids(v('cors-reflect', 'https://a.example/api/me', [`Origin: ${origin}`], ['HTTP/1.1 200 OK', `access-control-allow-origin: ${origin}`, 'vary: Origin']), 'R-01');
    expect(self('https://a.example')).toEqual(['R-01.na']);
    expect(self('https://evil.example')).toEqual(['R-01.2']);       // 許可外の Origin は今までどおり
  });
  it('R-01（レビュー）：http のオリジン、サブドメイン、共用のホスティングの隣のホストは自サイトにしない（反射は今までどおり指摘する）', () => {
    const refl = (url: string, origin: string) => ids(v('cors-reflect', url, [`Origin: ${origin}`], ['HTTP/1.1 200 OK', `access-control-allow-origin: ${origin}`, 'access-control-allow-credentials: true', 'vary: Origin']), 'R-01');
    expect(refl('https://a.example/api', 'http://a.example')).toEqual(['R-01.1']);
    expect(refl('https://a.example/api', 'https://evil.a.example')).toEqual(['R-01.1']);
    expect(refl('https://myapp.herokuapp.com/api', 'https://evil.herokuapp.com')).toEqual(['R-01.1']);
    expect(refl('https://me.github.io/api', 'https://attacker.github.io')).toEqual(['R-01.1']);
  });

  it('R-03：サブドメインの対象（api.a.example）でも、サイトに似せた Origin（a.example.evil.net）は R-03 で判定する', () => {
    const r = evaluate(v('cors-partial', 'https://api.a.example/me', ['Origin: https://a.example.evil.net'], ['HTTP/1.1 200 OK', 'access-control-allow-origin: https://a.example.evil.net']));
    expect(r.findings.filter(f => f.item === 'R-03').map(f => f.ruleId)).toEqual(['R-03.2']);
    expect(r.findings.filter(f => f.item === 'R-01')).toHaveLength(0);
    // co.jp のような国別の第2レベルでは、co.jp をサイトとみなさない（evil.co.jp を自サイトにしない）
    expect(ids(v('cors-reflect', 'https://www.example.co.jp/api', ['Origin: https://evil.co.jp'], ['HTTP/1.1 200 OK', 'access-control-allow-origin: https://evil.co.jp']), 'R-01')).toEqual(['R-01.2']);
  });

  it('R-05①：Allow-Methods: *（資格情報なし）を、許可外の Origin への状態を変えるメソッドの許可とする', () => {
    const pre = (extra: string[]) => ids(v('cors-preflight', 'https://a.example/api/x', ['Origin: https://evil.example'], ['HTTP/1.1 204 No Content', 'access-control-allow-origin: https://evil.example', ...extra]), 'R-05');
    expect(pre(['access-control-allow-methods: *'])).toEqual(['R-05.1']);
    expect(pre(['access-control-allow-methods: *', 'access-control-allow-credentials: true'])).toEqual(['R-05.ok']);   // 資格情報ありの * は「*」という名前
    expect(pre(['access-control-allow-methods: GET, POST'])).toEqual(['R-05.ok']);
  });

  it('R-06：Vary の名前の一部（X-Origin-Id）を Vary: Origin とみなさない', () => {
    const r = (vary: string) => ids(v('cors-reflect', 'https://a.example/api/x', ['Origin: https://evil.example'], ['HTTP/1.1 200 OK', 'access-control-allow-origin: https://evil.example', `vary: ${vary}`]), 'R-06');
    expect(r('X-Origin-Id')).toEqual(['R-06.1']);
    expect(r('Accept-Encoding, Origin')).toEqual(['R-06.ok']);
    expect(r('*')).toEqual(['R-06.ok']);
  });
});

describe('第4章 通信・TLS', () => {
  it('T-04④：303 も一時的な転送', () => {
    expect(ids(t('http', 'http://a.example/', 'HTTP/1.1 303 See Other\nlocation: https://a.example/'), 'T-04')).toEqual(['T-04.4']);
    expect(ids(t('http', 'http://a.example/', 'HTTP/1.1 301 Moved Permanently\nlocation: https://a.example/'), 'T-04')).toEqual(['T-04.ok']);
  });

  it('T-05②：診断した URL 自身のポートへの転送は、ポートの露出にしない', () => {
    expect(ids(t('top', 'https://a.example:8443/', 'HTTP/1.1 302 Found\nlocation: https://a.example:8443/login\n\nHTTP/1.1 200 OK\ncontent-type: text/html'), 'T-05')).toEqual(['T-05.ok']);
    expect(ids(t('top', 'https://a.example/', 'HTTP/1.1 302 Found\nlocation: https://a.example:8080/login\n\nHTTP/1.1 200 OK\ncontent-type: text/html'), 'T-05')).toEqual(['T-05.2']);
  });

  it('T-11①：SAN のない証明書（CN だけ）は、CN が一致してもブラウザが拒否する', () => {
    const tls = (pem: string, extra = '') => evaluate(`#TARGET url=https://a.example/ label=tls\n${extra}CONNECTED(00000003)\n---\nCertificate chain\n 0 s:CN = a.example\n   i:CN = a.example\n${pem.trim()}\n---\nVerify return code: 0 (ok)\nsubject=CN = a.example\nnotAfter=Jan  1 00:00:00 2036 GMT\n`).findings.filter(f => f.item === 'T-11');
    const noSan = tls(fixture('cert_cn_only.pem'));
    expect(noSan.map(f => f.ruleId)).toEqual(['T-11.1']);
    expect(noSan[0].evidence).toContain('SAN がない');
    expect(tls(fixture('cert_san.pem')).map(f => f.ruleId)).toEqual(['T-11.ok']);
    // PEM がない出力（x509 を -ext subjectAltName なしで実行）では、SAN があるかが分からないので、今までどおり CN で比べる
    expect(tls('').map(f => f.ruleId)).toEqual(['T-11.ok']);
  });
});

describe('第5章 情報露出', () => {
  const body = (b: string, label = 'top', status = '200') => t(label, 'https://a.example/x', `HTTP/2 ${status}\ncontent-type: text/html; charset=utf-8`, b);
  it('E-01：品番（FLORA-12345）、URL のパス、独自の404のタイトル、「Ruby on Rails」の語を誤検知しない', () => {
    expect(ids(body('<p>Item FLORA-12345</p>'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(body('<script src="/srv/main.js"></script><a href="https://cdn.example/opt/app.js">x</a><div style="background:url(/opt/bg.js)"></div>'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(body('<title>Error 404 - Page not found | MyShop</title>', 'error-url', '404'), 'E-01')).toEqual(['E-01.ok']);
    expect(ids(body('<p>This site is built with Ruby on Rails.</p>'), 'E-01')).toEqual(['E-01.ok']);
  });
  it('E-01：本物のエラーの詳細は今までどおり指摘する（守り）', () => {
    expect(ids(body('ORA-00942: table or view does not exist'), 'E-01')).toContain('E-01.2');
    expect(ids(body('Warning: include(): Failed in /var/www/html/index.php on line 3'), 'E-01')).toContain('E-01.2');
    expect(ids(body('File "/srv/app/main.py", line 3, in handler'), 'E-01')).toContain('E-01.2');
    expect(ids(body('<title>Error 404 Not Found</title><h2>HTTP ERROR 404 Not Found</h2>', 'error-url', '404'), 'E-01')).toContain('E-01.3');
    expect(ids(body("<h1>We're sorry, but something went wrong.</h1>", 'error-url', '500'), 'E-01')).toContain('E-01.3');
    expect(ids(body('<h1>Routing Error</h1><p>No route matches [GET] "/x"</p>', 'error-url', '404'), 'E-01')).toContain('E-01.3');
  });

  it('E-04①：robots.txt の語の一部（/devices/、/latest/、/contest/）に一致させない', () => {
    const robots = (b: string) => ids(t('robots', 'https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/plain', `User-agent: *\n${b}`), 'E-04');
    expect(robots('Disallow: /devices/\nDisallow: /latest/\nDisallow: /contest/\nDisallow: /privacy')).toEqual(['E-04.ok']);
    expect(robots('Disallow: /wp-admin/')).toEqual(['E-04.1']);
    expect(robots('Disallow: /administrator/')).toEqual(['E-04.1']);
    expect(robots('Disallow: /staging-api/')).toEqual(['E-04.1']);
    expect(robots('Disallow: /test/')).toEqual(['E-04.1']);
  });

  it('E-05：GraphiQL などの IDE の画面の 200 を「introspection を拒否」と合格にしない', () => {
    const gql = (b: string, head = HTML) => ids(t('top', 'https://a.example/graphql', head, b), 'E-05');
    expect(gql('<!doctype html><div id="graphiql"></div><script>getIntrospectionQuery(); introspection</script>')).toEqual(['E-05.2']);
    expect(gql('<!doctype html><p>introspection</p>')).toEqual(['E-05.na']);
    expect(gql('{"errors":[{"message":"GraphQL introspection is not allowed"}]}', 'HTTP/2 400\ncontent-type: application/json')).toEqual(['E-05.ok']);
  });

  it('E-06：Express の res.jsonp の形（/**/ typeof cb === \'function\' && cb(…)）を JSONP とみなす', () => {
    const jp = (b: string) => ids(t('top', 'https://a.example/api/x?callback=cb', 'HTTP/2 200\ncontent-type: text/javascript', b), 'E-06');
    expect(jp("/**/ typeof cb === 'function' && cb({\"a\":1});")).toEqual(['E-06.2']);
    expect(jp('cb({"a":1});')).toEqual(['E-06.2']);
    expect(jp('{"a":1}')).toEqual(['E-06.ok']);
  });

  it('E-09②：複数のラベルの内部ホスト名（db.prod.internal）を見逃さない。診断した URL 自身のホストは内部URLにしない', () => {
    expect(ids(body('<a href="http://db.prod.internal/x">x</a>'), 'E-09')).toContain('E-09.2');
    expect(ids(t('top', 'https://portal.corp/', HTML, '<a href="https://portal.corp/home">x</a>'), 'E-09')).toEqual(['E-09.ok']);
    expect(ids(t('top', 'https://portal.corp/', HTML, '<a href="https://portal.corp/home">x</a><a href="https://db.corp/">y</a>'), 'E-09')).toContain('E-09.2');
  });

  it('E-11②：アップロード先らしいパスの JSON の API の応答を、ダウンロードとして指摘しない', () => {
    expect(ids(t('top', 'https://a.example/api/files/123.json', JSON_CT, '{"a":1}'), 'E-11')).toEqual([]);
    expect(ids(t('top', 'https://a.example/files/report.pdf', 'HTTP/2 200\ncontent-type: application/pdf'), 'E-11')).toEqual(['E-11.2']);   // 守り
  });
});

describe('第6章 API', () => {
  it('A-07②：GraphQL の __typename と Mongoose の __v を内部属性にしない（ほかの __ は今までどおり）', () => {
    const api = (b: string) => ids(t('api', 'https://a.example/api/me', JSON_CT, b), 'A-07');
    expect(api('{"__typename":"User","__v":0,"id":1}')).toEqual(['A-07.ok']);
    expect(api('{"__internalRole":"x","id":1}')).toEqual(['A-07.2']);
  });

  it('A-10：付け直したラベル（error-a#2）は比べない（横断の判定には最初のものだけを使う）', () => {
    const err = (label: string, path: string, ct: string) => t(label, `https://a.example/api/${path}`, `HTTP/2 404\ncontent-type: ${ct}`, '{}');
    const r = evaluate(err('error-a', 'x', 'application/json') + err('error-a', 'y', 'application/problem+json') + err('error-b', 'z', 'application/json'));
    expect(r.findings.filter(f => f.item === 'A-10').map(f => f.ruleId)).toEqual(['A-10.ok']);
  });
});

describe('差分と例外の突き合わせ', () => {
  it('同じラベルが複数あっても、貼り付けの順番を変えたら差分がずれない（突き合わせは元のラベル＋URL）', () => {
    const a = t('top', 'https://a.example/', `${HTML}\nstrict-transport-security: max-age=63072000; includeSubDomains`);
    const b = t('top', 'https://a.example/x', HTML);
    const run = (input: string) => runAll(parseInput(input).targets);
    const rows = diff(run(a + b), run(b + a));
    expect(rows.filter(r => r.kind === 'new' || r.kind === 'resolved' || r.kind === 'not-rechecked')).toEqual([]);
    // ラベルが1つだけのターゲットは、今までどおりラベルで突き合わせる
    expect(run(a).find(f => f.item === 'H-08')?.targetKey).toBe('top');
  });
});

describe('独立したレビューの指摘（第21回）', () => {
  it('R-1 H-03③：カンマのあとのかけら（report-uri の URL の中、ソースの区切りの誤り）だけが読めなくても③にしない', () => {
    expect(ids(page("content-security-policy: script-src 'nonce-AbCdEf0123456789xyz' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-uri https://r.example/csp?a=1,2"), 'H-03')).toEqual(['H-03.ok']);
    expect(ids(page("content-security-policy: default-src 'self'; img-src 'self', data:"), 'H-03')).toEqual(['H-03.ok']);
    expect(ids(page('content-security-policy: ,', '<html><body>x</body></html>'), 'H-03')).toEqual(['H-03.3']);   // ディレクティブが1つもなければ③（本文がなければ na）
  });

  it('R-2 T-11：切れた PEM・空行の入った PEM で「SAN がない」にしない。x509 の SAN の行があれば SAN はある', () => {
    const san = fixture('cert_san.pem').trim().split(/\r?\n/);
    const truncated = [...san.slice(0, 5), '-----END CERTIFICATE-----'].join('\n');
    const tls = (body: string) => evaluate(`#TARGET url=https://a.example/ label=tls\nCertificate chain\n 0 s:CN = a.example\n${body}\n---\nVerify return code: 0 (ok)\nsubject=CN = a.example\nnotAfter=Jan  1 00:00:00 2036 GMT\n`).findings.filter(f => f.item === 'T-11').map(f => f.ruleId);
    expect(tls(`${truncated}\nX509v3 Subject Alternative Name:\n    DNS:a.example`)).toEqual(['T-11.ok']);
    expect(tls(truncated)).toEqual(['T-11.ok']);                                     // 切れた PEM は「分からない」
    const broken = [...san.slice(0, 4), '', ...san.slice(4)].join('\n');               // 入力欄が CR CR LF を空行にした PEM
    expect(tls(`${broken}\n 1 s:CN = ca\n${fixture('cert_cn_only.pem').trim()}`)).toEqual(['T-11.ok']);   // 次の（中間 CA の）PEM をリーフにしない
  });

  it('R-3 E-11：kind=api を明示したターゲットでも、SVG の①・PDF の②を見逃さない', () => {
    expect(ids(t('top', 'https://a.example/uploads/x.svg', 'HTTP/2 200\ncontent-type: image/svg+xml', '<svg/>', 'kind=api'), 'E-11')).toEqual(['E-11.1']);
    expect(ids(t('top', 'https://a.example/api/files/1.pdf', 'HTTP/2 200\ncontent-type: application/pdf', '', 'kind=api'), 'E-11')).toEqual(['E-11.2']);
  });

  it('R-4 差分：同じラベルの2つ目を足しても、1つ目の指摘は「継続」のまま。同じラベル・同じ URL の2つはキーを分ける', () => {
    const a = t('top', 'https://a.example/', HTML), b = t('top', 'https://a.example/x', HTML);
    const run = (input: string) => runAll(parseInput(input).targets);
    const rows = diff(run(a), run(a + b));
    expect(rows.filter(r => r.kind === 'not-rechecked' || r.kind === 'resolved')).toEqual([]);
    expect(rows.filter(r => r.kind === 'new').every(r => r.target === 'top#2')).toBe(true);
    const keys = new Set(run(a + a).filter(f => f.item === 'H-08').map(f => f.targetKey));
    expect(keys.size).toBe(2);
  });

  it('R-5 E-04①：複数形と接頭辞（/tests/、/internals/、/sysadmin/、/devel/）を見逃さない。/badminton/ は対象外', () => {
    const robots = (b: string) => ids(t('robots', 'https://a.example/robots.txt', 'HTTP/2 200\ncontent-type: text/plain', `User-agent: *\n${b}`), 'E-04');
    for (const p of ['/tests/', '/internals/', '/privates/', '/devel/', '/testsite/', '/myadmin/', '/sysadmin/']) expect(robots(`Disallow: ${p}`), p).toEqual(['E-04.1']);
    expect(robots('Disallow: /badminton/')).toEqual(['E-04.ok']);
  });

  it('R-6 H-02③：apex の max-age=0 は HSTS を返していないのと同じ', () => {
    const www = t('www', 'https://www.a.example/', `${HTML}\nstrict-transport-security: max-age=63072000; includeSubDomains; preload`);
    expect(evaluate(www + t('apex', 'https://a.example/', `${HTML}\nstrict-transport-security: max-age=0`)).findings.filter(f => f.ruleId === 'H-02.3')).toHaveLength(1);
  });

  it('R-7 T-05②：別のホストへの転送は、同じポートでも対象', () => {
    expect(ids(t('top', 'https://a.example:8443/', 'HTTP/1.1 302 Found\nlocation: https://other.example:8443/\n\nHTTP/1.1 200 OK\ncontent-type: text/html'), 'T-05')).toEqual(['T-05.2']);
  });
});
