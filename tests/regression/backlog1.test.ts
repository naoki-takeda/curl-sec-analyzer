// 積み残しの対応（1回目：第11〜19回の「未対応」のうち、秘密情報が出る経路と重要度「高」の誤判定・見逃し）の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { evaluate } from '../helpers';

const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const JSON_CT = 'HTTP/2 200\ncontent-type: application/json';
const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const v = (label: string, url: string, sent: string[], recv: string[], extra = '') =>
  [`#TARGET url=${url} label=${label} ${extra}`, `* Connected to ${new URL(url).hostname} (192.0.2.1) port 443`, `> GET ${new URL(url).pathname}${new URL(url).search} HTTP/1.1`,
    ...sent.map(s => `> ${s}`), '>', ...recv.map(s => `< ${s}`), '<', ''].join('\n');
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
/** 画面・エクスポートに出るすべての文字列（証跡・URL） */
const shown = (input: string) => evaluate(input).findings.map(f => `${f.evidence} ${f.url ?? ''} ${f.targetKey ?? ''}`).join('\n');
const b64 = (s: string) => btoa(s);

describe('P1 秘密情報が出る経路', () => {
  const NAMELESS = 'S3cr3tT0kenAbCdEf0123456789';
  it('名前のない Set-Cookie（値だけ）の値を、証跡に出さない', () => {
    const logout = t('logout', 'https://a.example/logout', `HTTP/2 200\ncontent-type: text/html\nset-cookie: ${NAMELESS}; Path=/`);
    expect(shown(logout)).not.toContain(NAMELESS);
    // 名前のない Cookie は値だけを持つ（RFC 6265bis）。削除用ではないので、ログアウトで Cookie を削除していない（C-12②）
    expect(ids(logout, 'C-12')).toContain('C-12.2');
    expect(ids(logout, 'C-12')).not.toContain('C-12.ok');
  });
  it('名前のない Set-Cookie もセッションCookieとして判定する（C-01①・C-02① を見逃さない）', () => {
    const top = t('top', 'https://a.example/', `${HTML}\nset-cookie: ${NAMELESS}; Path=/`);
    expect(ids(top, 'C-01')).toContain('C-01.1');
    expect(ids(top, 'C-02')).toContain('C-02.1');
    expect(shown(top)).not.toContain(NAMELESS);
  });

  it('引用符のない nonce、閉じ引用符のない nonce を伏せる', () => {
    expect(maskText('script-src nonce-R4ndomNonceValue123')).not.toContain('R4ndomNonceValue123');
    expect(maskText("script-src 'nonce-R4ndomNonceValue123")).not.toContain('R4ndomNonceValue123');
    expect(maskText("script-src 'nonce-R4ndomNonceValue123' 'self'")).not.toContain('R4ndomNonceValue123');
    const page = t('page', 'https://a.example/', `${HTML}\ncontent-security-policy: script-src nonce-R4ndomNonceValue123; object-src 'none'; base-uri 'none'`);
    expect(shown(page)).not.toContain('R4ndomNonceValue123');
    // もう一度マスクしても変わらない
    const once = maskText('script-src nonce-R4ndomNonceValue123');
    expect(maskText(once)).toBe(once);
  });

  it('passcode・pin・hash・assertion のパラメータを伏せる', () => {
    for (const [name, val] of [['passcode', '839201'], ['pin', '4821'], ['hash', '9f86d081884c7d659a2feaa0'], ['client_assertion', 'Zm9vYmFyYmF6cXV4'], ['SAMLAssertion', 'PHNhbWw6QXNz']])
      expect(maskText(`https://a.example/cb?${name}=${val}`), name).not.toContain(val);
  });

  it('Bearer_eyJ… の JWT を伏せる', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl';
    expect(maskText(`token=Bearer_${jwt}`)).not.toContain('c2lnbmF0dXJlLXZhbHVl');
    expect(maskText(`Bearer_${jwt}`)).not.toContain('c2lnbmF0dXJlLXZhbHVl');
  });

  it('JWE（5つの部分）の暗号文とタグを残さない。鍵の部分が空の dir 形式も伏せる', () => {
    const jwe = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZ.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TAL.XFBoMYUZodetZdvTiFvSkQ';
    const out = maskText(`https://a.example/cb?x=1#${jwe}`);
    expect(out).not.toContain('5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TAL');
    expect(out).not.toContain('XFBoMYUZodetZdvTiFvSkQ');
    const dir = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TAL.XFBoMYUZodetZdvTiFvSkQ';
    const out2 = maskText(`value: ${dir}`);
    expect(out2).not.toContain('5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TAL');
    expect(out2).not.toContain('48V1_ALb6US04U3b');
  });

  it('パラメータの値の中の JSON（そのまま・エンコード・エスケープ）の秘密の値を伏せる', () => {
    expect(maskText('https://a.example/?data={"password":"Hunter2xyz"}')).not.toContain('Hunter2xyz');
    expect(maskText('https://a.example/?data=%7B%22password%22%3A%22Hunter2xyz%22%7D')).not.toContain('Hunter2xyz');
    expect(maskText('{\\"client_secret\\":\\"Hunter2xyz\\"}')).not.toContain('Hunter2xyz');
    expect(maskText('{"name":"Alice","api_key": "Hunter2xyz"}')).not.toContain('Hunter2xyz');
    // 秘密でない名前の値は残す
    expect(maskText('{"name":"Alice"}')).toContain('Alice');
  });

  it('OAuth の state・nonce を伏せる（短い状態の値 state=open は残す）', () => {
    const out = maskText('https://a.example/cb?state=af0ifjsldkj7Xyz&nonce=n-0S6_WzA2Mj');
    expect(out).not.toContain('af0ifjsldkj7Xyz');
    expect(out).not.toContain('n-0S6_WzA2Mj');
    expect(maskText('https://a.example/issues?state=open')).toContain('state=open');
  });

  it('country_code・zip_code・error_code などは伏せない。認可コード・確認コードは伏せる', () => {
    for (const p of ['country_code=JP', 'zip_code=1000001', 'promo_code=SPRING', 'error_code=E1001', 'status_code=404', 'currency_code=JPY'])
      expect(maskText(`https://a.example/?${p}`), p).toContain(p);
    for (const [name, val] of [['code', 'SplxlOBeZQQYbYS6WxSbIA'], ['auth_code', 'abcd1234efgh'], ['verification_code', '483920'], ['otp_code', '112233'], ['device_code', 'GmRhmhcxhwAz']])
      expect(maskText(`https://a.example/?${name}=${val}`), name).not.toContain(val);
  });

  it('A-07 の証跡のキーに、動的なキー（メールアドレス・秘密の値）を出さない', () => {
    const body = JSON.stringify({ users: { 'alice@example.com': { password: 'x9$kQ2!zP' } }, keys: { sk_live_51HabcDEF123456789: { secret: 'zz9!k2Lq#' } } });
    const input = t('api', 'https://a.example/api/admin', JSON_CT, body);
    expect(ids(input, 'A-07')).toContain('A-07.1');
    const s = shown(input);
    expect(s).not.toContain('alice@example.com');
    expect(s).not.toContain('sk_live_51HabcDEF123456789');
    expect(s).toContain('password');
  });

  it('Server-Timing の説明（desc）の値を証跡に出さない', () => {
    const input = t('page', 'https://a.example/', `${HTML}\nserver-timing: db;desc="SELECT * FROM users WHERE email='alice@example.com' AND api_key='sk_live_123'";dur=53, app;dur=12`);
    const ev = evaluate(input).findings.filter(f => f.ruleId === 'H-16.5').map(f => f.evidence).join(' ');
    expect(ev).toContain('db');
    expect(ev).toContain('app');
    expect(ev).not.toContain('alice@example.com');
    expect(ev).not.toContain('sk_live_123');
  });
});

describe('P2 重要度「高」の誤判定と見逃し', () => {
  it('クエリに画像・JS の名前があるだけで静的リソースとしない（H-12① を見逃さない）', () => {
    const api = v('t', 'https://a.example/api/me?avatar=me.png', ['Authorization: Bearer x'], ['HTTP/2 200', 'content-type: application/json']);
    expect(ids(api, 'H-12')).toContain('H-12.1');
    const css = v('t', 'https://a.example/api/user?format=x.css', ['Cookie: JSESSIONID=abc'], ['HTTP/2 200', 'content-type: application/json']);
    expect(ids(css, 'H-12')).toContain('H-12.1');
    // パスが静的リソースなら今までどおり
    const js = v('t', 'https://a.example/app.js?v=3', ['Cookie: JSESSIONID=abc'], ['HTTP/2 200', 'content-type: text/javascript']);
    expect(ids(js, 'H-12')).not.toContain('H-12.1');
  });

  it('コードが 000（接続できなかった）のプローブを、E-03・E-13・E-04 で合格にしない', () => {
    const probes = (lines: string) => evaluate(`#TARGET url=https://a.example/ label=probes\n${lines}`).findings.map(f => f.ruleId);
    const p = (path: string, code: string) => `#PROBE path=${path} code=${code} size=0 head= ct=\n`;
    const r = probes(p('/.git/HEAD', '000') + p('/.env', '000'));
    expect(r).toContain('E-03.na');
    expect(r).not.toContain('E-03.ok');
    expect(probes(p('/static/app.js.map', '000'))).toContain('E-13.na');
    const s = probes(p('/.well-known/security.txt', '000'));
    expect(s).toContain('E-04.na');
    expect(s).not.toContain('E-04.2');
    // 404 は今までどおり合格（E-03）・②（E-04）
    expect(probes(p('/.git/HEAD', '404'))).toContain('E-03.ok');
    expect(probes(p('/.well-known/security.txt', '404'))).toContain('E-04.2');
  });

  it('資格情報のない jdbc: は E-01①（高）にしない（②）。資格情報があれば①', () => {
    const bare = t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', '<pre>Cannot connect to jdbc:mysql://db.internal:3306/app</pre>');
    expect(ids(bare, 'E-01')).not.toContain('E-01.1');
    expect(ids(bare, 'E-01')).toContain('E-01.2');
    expect(shown(bare)).not.toContain('db.internal');
    const withUser = t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', '<pre>jdbc:mysql://db/app?user=root&password=Secr3tPw</pre>');
    expect(ids(withUser, 'E-01')).toContain('E-01.1');
    const inUrl = t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', '<pre>jdbc:postgresql://admin:Secr3tPw@db/app</pre>');
    expect(ids(inUrl, 'E-01')).toContain('E-01.1');
    const oracle = t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/html', '<pre>jdbc:oracle:thin:scott/Secr3tPw@db:1521:orcl</pre>');
    expect(ids(oracle, 'E-01')).toContain('E-01.1');
  });

  it('公開を前提にした API キー（Google の AIza…、Stripe の pk_live_…）を E-09①（高）にしない', () => {
    const page = (js: string) => t('page', 'https://a.example/', HTML, `<html><script>${js}</script></html>`);
    expect(ids(page('var firebaseConfig = { apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv" };'), 'E-09')).not.toContain('E-09.1');
    expect(ids(page('<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyA1234567890abcdefghijklmnopqrstuv"></script>'), 'E-09')).not.toContain('E-09.1');
    expect(ids(page('Stripe({ api_key: "pk_live_abcdefghijklmnop123" })'), 'E-09')).not.toContain('E-09.1');
    // 秘密のキーは今までどおり①
    expect(ids(page('var cfg = { api_key: "sk_live_abcdefghijklmnop123" };'), 'E-09')).toContain('E-09.1');
  });

  it('自サイトの Origin で 101 になっても R-09①（高）にしない（許可外の Origin で試していない）', () => {
    const ws = (origin: string) => v('websocket', 'https://a.example/ws', [`Origin: ${origin}`, 'Upgrade: websocket'], ['HTTP/1.1 101 Switching Protocols', 'upgrade: websocket'], 'sensitive=1');
    expect(ids(ws('https://a.example'), 'R-09')).toEqual(['R-09.na']);
    expect(ids(ws('https://evil.example'), 'R-09')).toEqual(['R-09.1']);
  });

  it('Kubernetes の ingress-nginx の INGRESSCOOKIE をセッションCookieとみなさない（C-01①・C-02①）', () => {
    const top = t('top', 'https://a.example/', `${HTML}\nset-cookie: INGRESSCOOKIE=1700000000.123.45.678901|abcdef0123456789abcdef0123456789; Path=/; HttpOnly`);
    expect(ids(top, 'C-01')).not.toContain('C-01.1');
    expect(ids(top, 'C-03')).not.toContain('C-03.1');
  });

  it('OpenSSL 1.1 の Ed25519（253bit）・Ed448（456bit）の鍵を「RSA 2048bit 未満」（T-10②、高）にしない', () => {
    for (const bits of [253, 456]) {
      const input = ['#TARGET url=https://a.example/ label=tls', 'CONNECTED(00000003)', '---', `Server public key is ${bits} bit`, 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', ''].join('\n');
      expect(ids(input, 'T-10'), String(bits)).not.toContain('T-10.2');
    }
    const rsa = ['#TARGET url=https://a.example/ label=tls', 'CONNECTED(00000003)', '---', 'Server public key is 1024 bit', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', ''].join('\n');
    expect(ids(rsa, 'T-10')).toContain('T-10.2');
  });

  describe('E-05', () => {
    it('Cookie・Authorization を送った応答では「未認証で使える」（①、高）としない', () => {
      const input = v('t', 'https://a.example/actuator', ['Cookie: JSESSIONID=abc'], ['HTTP/1.1 200 OK', 'content-type: application/json']);
      expect(ids(input, 'E-05')).toEqual(['E-05.na']);
      const bearer = v('t', 'https://a.example/v3/api-docs/swagger.json', ['Authorization: Bearer x'], ['HTTP/1.1 200 OK', 'content-type: application/json']);
      expect(ids(bearer, 'E-05')).toEqual(['E-05.na']);
      // 何も送らなければ今までどおり①（本文のない /actuator の一覧は、既定のリンクだけかが分からないので na（第48回）。/actuator/env は取得できれば①）
      expect(ids(v('t', 'https://a.example/actuator/env', [], ['HTTP/1.1 200 OK', 'content-type: application/json']), 'E-05')).toEqual(['E-05.1']);
      expect(ids(v('t', 'https://a.example/actuator', [], ['HTTP/1.1 200 OK', 'content-type: application/json']), 'E-05')).toEqual(['E-05.na']);
    });
    it('ステータスが分からない応答（%{header_json} だけ）を合格にしない', () => {
      const input = '#TARGET url=https://a.example/swagger.json label=t\n{"content-type":["application/json"],"date":["Mon, 16 Nov 2026 00:00:00 GMT"]}\n';
      expect(ids(input, 'E-05')).toEqual(['E-05.na']);
    });
    it('同じホストの Swagger UI のページへの転送（/swagger-ui → /swagger-ui/index.html）は、転送先で判定する', () => {
      // 第24回から、HTML の 200 はその機能の画面（swagger-ui を含む）と分かるときだけ②にする
      const followed = t('t', 'https://a.example/swagger-ui', 'HTTP/2 302\nlocation: /swagger-ui/index.html\n\nHTTP/2 200\ncontent-type: text/html', '<div id="swagger-ui"></div>');
      expect(ids(followed, 'E-05')).toEqual(['E-05.2']);
      // -L を付けずに転送だけを採取したら、判定しない
      const notFollowed = t('t', 'https://a.example/swagger-ui', 'HTTP/2 302\nlocation: /swagger-ui/index.html');
      expect(ids(notFollowed, 'E-05')).toEqual(['E-05.na']);
      // ログイン画面への転送は今までどおり合格（転送先の 200 で①・②にしない）
      const login = t('t', 'https://a.example/actuator', 'HTTP/2 302\nlocation: /login\n\nHTTP/2 200\ncontent-type: text/html');
      expect(ids(login, 'E-05')).toEqual(['E-05.ok']);
    });
  });
});

describe('レビューの指摘（同じ PR の中で見つかったもの）', () => {
  it('jdbc: を繰り返した本文で2乗の時間にならない', { tags: ['perf'] }, () => {
    const body = 'jdbc:x:'.repeat(64 * 1024 / 7);
    const t0 = performance.now();
    evaluate(t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/plain', body));
    expect(performance.now() - t0).toBeLessThan(500);
  });
  it('jdbc: の資格情報：パスワードのない user=…@ は①にしない。パスワードに / を含むものは①', () => {
    const at = (s: string) => ids(t('err', 'https://a.example/x', 'HTTP/2 500\ncontent-type: text/plain', s), 'E-01');
    expect(at('jdbc:sqlserver://db:1433;databaseName=app;user=svc@corp.example')).not.toContain('E-01.1');
    expect(at('jdbc:mysql://app:p4ss/w0rd@db/app')).toContain('E-01.1');
  });
  it('A-07：AWS のアクセスキーや英小文字・数字のIDをキーにしたものも証跡に出さない', () => {
    const input = t('api', 'https://a.example/api/x', JSON_CT, JSON.stringify({ keys: { AKIAIOSFODNN7EXAMPLE: { secret: 'zz9!k2Lq#' } }, sessions: { k3j4h5g6f7d8s9a0q1w2e3r4t5: { password: 'x9$kQ2!zP' } } }));
    const s = shown(input);
    expect(ids(input, 'A-07')).toContain('A-07.1');
    expect(s).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(s).not.toContain('k3j4h5g6f7d8s9a0q1w2e3r4t5');
  });
  it('A-07：数字で始まるキー（2fa_secret）も①にする（判定は元のキーで行う）', () => {
    const input = t('api', 'https://a.example/api/me', JSON_CT, JSON.stringify({ user: { '2fa_secret': 'JBSWY3DPEHPK3PXP' } }));
    expect(ids(input, 'A-07')).toContain('A-07.1');
  });
  it('1行にまとめた Set-Cookie の、名前のない2つ目の Cookie の値を証跡に出さない', () => {
    const top = t('top', 'https://a.example/', `${HTML}\nset-cookie: a=1; Path=/, ${'S3cr3tT0kenAbCdEf0123456789'}; Path=/`);
    expect(shown(top)).not.toContain('S3cr3tT0kenAbCdEf0123456789');
  });
  it('閉じ引用符のない短い nonce も伏せ、マスクは冪等', () => {
    expect(maskText("script-src 'nonce-Ab1d 'strict-dynamic'")).not.toContain('Ab1d');
    for (const s of ["%3A'nonce-eyJ_('nonce-A(x)\\\"%2F&state{}token'", "script-src 'nonce-Ab1d 'strict-dynamic'", "'nonce-abcdefghijk' 'nonce-xyz123456789'"]) {
      const once = maskText(s);
      expect(maskText(once), s).toBe(once);
    }
  });
  it('「nonce-」で始まる普通の語（パス、クラス名）は伏せない', () => {
    expect(maskText('https://a.example/posts/nonce-reuse-attacks-explained')).toContain('nonce-reuse-attacks-explained');
    expect(maskText('<div class="nonce-container">')).toContain('nonce-container');
  });
  it('前の語が _ を含む JWT（x_Bearer_eyJ…、access_token_eyJ…）も伏せる', { tags: ['perf'] }, () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl';
    expect(maskText(`x_Bearer_${jwt}`)).not.toContain('c2lnbmF0dXJlLXZhbHVl');
    expect(maskText(`access_token_${jwt}`)).not.toContain('c2lnbmF0dXJlLXZhbHVl');
    const t0 = performance.now(); maskText('a_eyJ'.repeat(200000)); expect(performance.now() - t0).toBeLessThan(1000);
  });
  it('JSON の state・oauth_state・数値の pin、二重エンコード・エンコードしていないコロンの JSON も伏せる', () => {
    expect(maskText('{"state":"af0ifjsldkj7Xyz"}')).not.toContain('af0ifjsldkj7Xyz');
    expect(maskText('https://a.example/cb?oauth_state=af0ifjsldkj7Xyz')).not.toContain('af0ifjsldkj7Xyz');
    expect(maskText('{"pin":483920}')).not.toContain('483920');
    expect(maskText('?d=%2522password%2522%253A%2522Hunter2xyz%2522')).not.toContain('Hunter2xyz');
    expect(maskText('?d=%22password%22:%22Hunter2xyz%22')).not.toContain('Hunter2xyz');
  });
  it('伏せすぎない：client_assertion_type、token_type、pin_lat、state=California。長い英小文字の state は伏せる', () => {
    for (const p of ['client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'token_type=Bearer', 'pin_lat=35.6', 'state=California'])
      expect(maskText(`https://a.example/?${p}`), p).toContain(p);
    expect(maskText('https://a.example/cb?state=abcdefghijklmnopqrstuvwx')).not.toContain('abcdefghijklmnopqrstuvwx');
  });
  it('OpenSSL 1.1 の P-224（224bit）を「RSA 224bit」（T-10②）にしない', () => {
    const input = ['#TARGET url=https://a.example/ label=tls', 'CONNECTED(00000003)', '---', 'Server public key is 224 bit', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', ''].join('\n');
    expect(ids(input, 'T-10')).not.toContain('T-10.2');
  });
  it('E-05：/actuator から /actuator/login（ログイン画面）への転送は、転送先の 200 で①にしない', () => {
    const input = t('t', 'https://a.example/actuator', 'HTTP/2 302\nlocation: /actuator/login\n\nHTTP/2 200\ncontent-type: text/html');
    expect(ids(input, 'E-05')).toEqual(['E-05.ok']);
    // springdoc の /swagger-ui.html → /swagger-ui/index.html は転送先で見る
    const springdoc = t('t', 'https://a.example/swagger-ui.html', 'HTTP/2 302\nlocation: /swagger-ui/index.html\n\nHTTP/2 200\ncontent-type: text/html', '<div id="swagger-ui"></div>');
    expect(ids(springdoc, 'E-05')).toEqual(['E-05.2']);
  });
});

describe('守り（直したあとも変わらないこと）', () => {
  it('普通の Set-Cookie の名前と値の扱いは変わらない', () => {
    const top = t('top', 'https://a.example/', `${HTML}\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz0123; Path=/; Secure; HttpOnly; SameSite=Lax`);
    expect(ids(top, 'C-01')).toEqual(['C-01.ok']);
    expect(evaluate(top).findings.find(f => f.ruleId === 'C-01.ok')?.evidence).toBe('sid');
  });
  it('普通の文の nonce という語は伏せない', () => {
    expect(maskText('nonce-based CSP を使う')).toBe('nonce-based CSP を使う');
  });
  it('プローブの 200 は今までどおり', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=probes\n#PROBE path=/.git/HEAD code=200 size=23 head=${b64('ref: refs/heads/main\n')} ct=text/plain\n`).findings.map(f => f.ruleId);
    expect(r).toContain('E-03.1');
  });
});
