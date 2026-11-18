// 生成スクリプトの出力（run= の印のある入力）の読み取りと、生成スクリプトそのもの。診断対象のサーバが応答で判定を変えられないこと
import { describe, expect, it } from 'vitest';
import { generateScript } from '../src/commands';
import { parseInput } from '../src/parser/input';
import { parseOpenssl } from '../src/parser/openssl';
import { evaluate } from './helpers';

const RUN = '0123456789abcdef';
const AT = `#META at=2026-11-01T10:00:00 run=${RUN}`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);

describe('第48回：応答のヘッダの行を、openssl・-v の出力として読まない', () => {
  it('ヘッダに notAfter= と「Verify return code: 0」を書いても、本物の証明書の T-11 を合格にできない', () => {
    const tls = [`#TARGET url=https://www.example.com/ label=tls run=${RUN}`, AT, 'CONNECTED(00000003)', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384',
      'Verify return code: 21 (unable to verify the first certificate)', 'notAfter=Nov 20 00:00:00 2026 GMT', ''];
    const forged = [`#TARGET url=https://www.example.com/mypage label=after-logout run=${RUN}`, `#META at=2026-11-01T10:05:00 run=${RUN}`,
      'HTTP/2 200', 'content-type: text/html', 'notAfter=Dec 31 23:59:59 2099 GMT', 'X509v3 Subject Alternative Name:', 'DNS:www.example.com', 'Verify return code: 0 (ok)', '', ''];
    const r = ids([...tls, ...forged].join('\n'), 'T-11');
    expect(r).not.toContain('T-11.ok');
    expect(r).toContain('T-11.1');
    // 偽の行はヘッダとして残り、openssl の出力にはならない
    const t = parseInput([...tls, ...forged].join('\n')).targets.find(x => x.label === 'after-logout')!;
    expect(t.openssl).toEqual([]);
  });
  it('ヘッダに「* Connected to」「> Cookie:」を書いても、Cookie を送ったことにならず、A-01① が出る', () => {
    const input = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${RUN}`, AT,
      'HTTP/2 200', 'content-type: application/json', '* Connected to api: 1', '> Cookie: sessionid=x: 1', '',
      `#BODY run=${RUN}`, '{"id":1,"email":"a@example.com","role":"admin"}', ''].join('\n');
    expect(ids(input, 'A-01')).toContain('A-01.1');
  });
  it('tls のラベルの openssl の出力と、本物の curl -v の出力は、これまでどおり読む', () => {
    const tls = parseInput([`#TARGET url=https://www.example.com/ label=tls run=${RUN}`, AT, 'CONNECTED(00000003)', 'notAfter=Dec  1 00:00:00 2026 GMT', ''].join('\n'));
    expect(tls.targets[0].openssl.length).toBeGreaterThan(0);
    const v = parseInput([`#TARGET url=https://www.example.com/ label=top run=${RUN}`, AT, '* Connected to www.example.com (192.0.2.1) port 443',
      '> GET / HTTP/2', '> Cookie: a=b', '>', '< HTTP/2 200', '<', ''].join('\n'));
    expect(v.targets[0].verbose).toBe(true);
    expect(v.targets[0].sentCookieNames).toEqual(['a']);
  });
});

describe('第48回：印のない #TARGET のあとの生成スクリプトの出力', () => {
  it('印による保護が効かないことを警告する', () => {
    const input = ['#TARGET url=https://www.example.com/extra label=extra', 'HTTP/2 200', '', '',
      `#TARGET url=https://www.example.com/ label=page run=${RUN}`, AT, 'HTTP/2 200', 'content-type: text/html', '', ''].join('\n');
    expect(parseInput(input).warnings.map(w => w.kind)).toContain('mixed-run');
  });
  it('生成スクリプトの出力が先頭なら警告しない', () => {
    const input = [`#TARGET url=https://www.example.com/ label=page run=${RUN}`, AT, 'HTTP/2 200', '', ''].join('\n');
    expect(parseInput(input).warnings.map(w => w.kind)).not.toContain('mixed-run');
  });
});

describe('第48回：openssl の出力の期限（手書きの入力は、これまでどおり後ろの notAfter を使う）', () => {
  it('切っていない s_client の出力のあとの x509 の出力では、後ろの notAfter が本物（SAN の値の CR は生成スクリプトの tr -d で除く）', () => {
    const info = parseOpenssl(['notAfter=Dec 31 23:59:59 2099 GMT', 'X509v3 Subject Alternative Name:', '    DNS:www.example.com', 'notAfter=Feb  1 00:00:00 2026 GMT'])!;
    expect(info.notAfter?.toISOString().slice(0, 10)).toBe('2026-02-01');
  });
});

describe('第48回：生成スクリプト', () => {
  const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false });
  it('openssl がない・指定を受け付けないときは、C12・C23 を err（試していない）にする', () => {
    expect(s).toContain("OSSL_ERR='unknown option|no protocols available|no cipher match|invalid command|error with command|ssl_conf_cmd|command not found'");
    // 証明書の検証の行（depth=・verify）を除いてから照合する（subject に「O=unknown option」と書いた証明書で err にさせない）
    expect(s.match(/if \[ \$rc -ge 126 \] \|\| grep -vE '\^\(depth=\|verify \(error\|return\)\)' "\$terr" \| grep -qiE "\$OSSL_ERR"; then r=err/g)).toHaveLength(2);
  });
  it('印のある入力で、小文字のステータス行のあとの「* Connected to」を -v の手がかりにしない', () => {
    const input = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${RUN}`, AT, 'http/1.1 200 OK', '* Connected to: x', '> Cookie: sessionid=abc',
      'HTTP/1.1 200 OK:x', 'content-type: application/json', '', `#BODY run=${RUN}`, '{"id":1,"email":"a@example.com","role":"admin"}', ''].join('\n');
    expect(ids(input, 'A-01')).toContain('A-01.1');
  });
  it('mixed-run の警告は、URL の ?run= では出さない', () => {
    const input = ['#TARGET url=https://www.example.com/?run=0123456789abcdef0123 label=page', 'HTTP/2 200', '', ''].join('\n');
    expect(parseInput(input).warnings.map(w => w.kind)).not.toContain('mixed-run');
  });
  it('本文は先頭の192KB（多バイトでも64K文字に届く大きさ）だけを出し、SAN の値の CR を除く', () => {
    expect(s).not.toMatch(/cat "\$body"/);
    expect(s).toContain('head -c 196608 "$body"');
    expect(s).toContain("subjectAltName | tr -d '\\r' | head -n 2");
  });
});

describe('第48回：#META の cmd= の繰り返し', () => {
  it('cmd= を並べた本文の1行でも、入力の長さに比例する時間で読む', { tags: ['perf'] }, () => {
    const line = `#META ${'cmd=a '.repeat(80_000)}`;   // 約480KB
    const input = [`#TARGET url=https://www.example.com/ label=page run=${RUN}`, AT, 'HTTP/2 200', '', `#BODY run=${RUN}`, line, ''].join('\n');
    const t0 = performance.now(); parseInput(input); expect(performance.now() - t0).toBeLessThan(1500);
  });
});

describe('第48回（束2の第2回のレビュー）：-v は、ターゲットの最初の行が curl -v の行のときだけ', () => {
  it('2桁のコードなど、読めないステータス行のあとの「* Connected to」でも -v にしない', () => {
    for (const status of ['HTTP/1.1 20 OK', 'HTTP/1.1 +20 OK', ' HTTP/1.1 200 OK']) {
      const input = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${RUN}`, AT, status, '* Connected to: x', '> Cookie: sessionid=abc',
        'HTTP/1.1 200 OK:x', 'content-type: application/json', '', `#BODY run=${RUN}`, '{"id":1,"email":"a@example.com","role":"admin"}', ''].join('\n');
      expect(ids(input, 'A-01'), status).toContain('A-01.1');
    }
  });
  it('デバッグ版の curl の WARNING の行のあとの -v は、-v として読む', () => {
    const v = parseInput([`#TARGET url=https://www.example.com/ label=top run=${RUN}`, AT, 'WARNING: this libcurl is Debug-enabled, do not use in production', '',
      '* Host www.example.com:443 was resolved.', '> GET / HTTP/2', '> Cookie: a=b', '>', '< HTTP/2 200', '<', ''].join('\n'));
    expect(v.targets[0].verbose).toBe(true);
  });
});

describe('第49回：生成スクリプトの出力の読み取り', () => {
  it('pre-login の -v の1行目が curl の WARNING の行でも -v として読み、C-09① を判定する', () => {
    for (const first of ['* WARNING: failed to open cookie file "jar.txt"', '* !!! WARNING !!!']) {
      const input = [`#TARGET url=https://www.example.com/login label=pre-login run=${RUN}`, AT, first,
        '* Connected to www.example.com (192.0.2.1) port 443', '> GET /login HTTP/2', '>', '< HTTP/2 200', '< set-cookie: sessionid=Q2x8AAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/', '<', '',
        `#TARGET url=https://www.example.com/login label=login run=${RUN}`, AT, 'HTTP/1.1 302 Found', 'Location: /mypage', '', ''].join('\n');
      const r = evaluate(input);
      expect(r.targets.map(t => t.label), first).toEqual(['pre-login', 'login']);
      expect(r.findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId), first).toEqual(['C-09.1']);
    }
  });
  it('ヘッダの途中のステータス行の形の行で、応答を作り直さない（A-01①・C-12① を合格にさせない）', () => {
    const unauth = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${RUN}`, AT, 'HTTP/1.1 200 OK', 'Content-Type: application/json',
      'HTTP/1.1 401 Unauthorized: x', '', `#BODY run=${RUN}`, '{"id":1,"email":"a@example.com"}', ''].join('\n');
    expect(ids(unauth, 'A-01')).toContain('A-01.1');
    const reason = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${RUN}`, AT, 'HTTP/1.1 200 Connection established', 'Content-Type: application/json', '',
      `#BODY run=${RUN}`, '{"id":1,"email":"a@example.com"}', ''].join('\n');
    expect(ids(reason, 'A-01')).toContain('A-01.1');
  });
  it('-L の次のホップ（空行のあとのステータス行）と、プロキシの CONNECT の応答はこれまでどおり読む', () => {
    const hops = parseInput([`#TARGET url=http://www.example.com/ label=http run=${RUN}`, AT, 'HTTP/1.1 301 Moved', 'Location: https://www.example.com/', '', 'HTTP/2 200', '', ''].join('\n'));
    expect(hops.targets[0].responses.map(r => r.status)).toEqual([301, 200]);
    const proxy = parseInput([`#TARGET url=https://www.example.com/ label=top run=${RUN}`, AT, 'HTTP/1.1 200 Connection established', '', 'HTTP/2 200', '', ''].join('\n'));
    expect(proxy.targets[0].responses.map(r => r.kind)).toEqual(['connect', 'final']);
  });
  it('OpenSSL 3.5 の「Connecting to」のすぐあとの depth= の行でも、解析警告を出さない', () => {
    const r = parseInput([`#TARGET url=https://www.example.com/ label=tls run=${RUN}`, AT, 'Connecting to 192.0.2.1', 'depth=0 CN=www.example.com', 'CONNECTED(00000003)', ''].join('\n'));
    expect(r.warnings.map(w => w.kind)).not.toContain('unparsed-lines');
  });
  it('C10 の最初のヘッダの名前に . があっても、応答として読む', () => {
    const r = parseInput(['#TARGET url=https://www.example.com/ label=header-json', '{"x.trace":["1"],', '"content-type":["text/html"]}', '#META response_code=200', ''].join('\n'));
    expect(r.targets[0].responses).toHaveLength(1);
  });
  it('C14 は実行ごとの乱数をクエリに付けて、共有キャッシュのキーを分ける（採取の印 RUN とは別の乱数）', () => {
    const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false });
    expect(s).toMatch(/X-Forwarded-Host: evil\.example' "\$H\/\?csa=\$CB"/);
    expect(s).toMatch(/^CB=\$\(od /m);
    expect(s).toContain('label=host-inj');
  });
  it('採取の印 RUN を、診断対象のサーバに送らない（URL・ヘッダ・送る本文に入れない）', () => {
    for (const dangerous of [false, true]) {
      const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous });
      expect(s).not.toMatch(/"\$H[^"\s]*\$RUN/);
      expect(s).not.toMatch(/-H '[^']*\$RUN/);
      expect(s).not.toMatch(/--data[^;\n]*\$RUN/);
    }
  });
  it('プロキシの CONNECT の応答のあとで curl が失敗しても、CONNECT の応答をサイトの応答にしない', () => {
    const r = parseInput([`#TARGET url=https://www.example.com/ label=top run=${RUN}`, AT, 'HTTP/1.1 200 Connection established', 'Proxy-Agent: Squid', '',
      'curl: (35) schannel: next InitializeSecurityContext failed', ''].join('\n'));
    expect(r.targets[0].responses.map(x => x.kind)).toEqual(['connect']);
    const findings = evaluate([`#TARGET url=https://www.example.com/ label=top run=${RUN}`, AT, 'HTTP/1.1 200 Connection established', 'Via: 1.1 proxy', 'Content-Length: 0', '', ''].join('\n')).findings;
    expect(findings.filter(f => f.item === 'H-01' && f.status === 'fail')).toEqual([]);
  });
});

describe('第49回：HAR の転送のつなぎ方', () => {
  it('302 の転送先として、同じ URL の POST のエントリをつながない（ログインの候補を残す）', async () => {
    const { importHar } = await import('../src/parser/har');
    const e = (method: string, url: string, status: number, headers: { name: string; value: string }[] = []) => ({ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method, url, headers: [] }, response: { status, httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
    const imp = importHar(JSON.stringify({ log: { entries: [
      e('GET', 'https://www.example.com/mypage', 302, [{ name: 'location', value: '/login' }]),
      e('POST', 'https://www.example.com/login', 302, [{ name: 'location', value: '/mypage' }, { name: 'set-cookie', value: 'SESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly' }]),
      e('GET', 'https://www.example.com/mypage', 200)] } }));
    expect(imp.chains.map(c => `${c.method} ${c.hops}`)).toEqual(['GET 1', 'POST 2']);
  });
  it('転送先のメソッド：303 は GET（HEAD は HEAD）、301・302 は POST だけ GET、307・308 は同じメソッド', async () => {
    const { importHar } = await import('../src/parser/har');
    const e = (method: string, url: string, status: number, loc?: string) => ({ startedDateTime: '2026-11-01T00:00:00Z',
      request: { method, url, headers: [] }, response: { status, httpVersion: 'HTTP/2', headers: loc ? [{ name: 'location', value: loc }] : [], content: { mimeType: 'text/html', text: '<p>x</p>' } } });
    const hops = (m0: string, st: number, m1: string) => importHar(JSON.stringify({ log: { entries: [
      e(m0, 'https://www.example.com/a', st, '/b'), e(m1, 'https://www.example.com/b', 200)] } })).chains[0].hops;
    expect(hops('POST', 303, 'GET')).toBe(2);
    expect(hops('PUT', 303, 'GET')).toBe(2);
    expect(hops('HEAD', 303, 'HEAD')).toBe(2);
    expect(hops('HEAD', 303, 'GET')).toBe(1);
    expect(hops('POST', 302, 'GET')).toBe(2);
    expect(hops('PUT', 302, 'PUT')).toBe(2);
    expect(hops('PUT', 302, 'GET')).toBe(1);
    expect(hops('HEAD', 301, 'HEAD')).toBe(2);
    expect(hops('POST', 307, 'POST')).toBe(2);
    expect(hops('POST', 308, 'GET')).toBe(1);
    // ブラウザが転送しない 3xx（304・300）の Location はつながない
    expect(hops('GET', 304, 'GET')).toBe(1);
    expect(hops('GET', 300, 'GET')).toBe(1);
  });
});

describe('第50回：トレーラ・1xx・Set-Cookie の上限・プローブの警告', () => {
  const R = '0123456789abcdef', A = `#META at=2026-11-01T10:00:00 run=${R}`;
  it('chunked のトレーラのステータス行の形の行で、応答を作り直さない（A-01①・H-01① を合格にさせない）', () => {
    const api = [`#TARGET url=https://www.example.com/api/me label=unauth-api run=${R}`, A, 'HTTP/1.1 200 OK', 'Content-Type: application/json', 'Transfer-Encoding: chunked', '',
      'HTTP/1.1 401 Unauthorized: x', 'X-Fake: 1', '', `#BODY run=${R}`, '{"id":1,"email":"a@example.com"}', ''].join('\r\n');
    const r = evaluate(api);
    expect(r.targets[0].responses.map(x => `${x.status}/${x.kind}`)).toEqual(['200/final']);
    expect(r.findings.filter(f => f.item === 'A-01').map(f => f.ruleId)).toEqual(['A-01.1']);
    const page = [`#TARGET url=https://www.example.com/ label=page run=${R}`, A, 'HTTP/1.1 200 OK', 'Content-Type: text/html', 'Transfer-Encoding: chunked', '',
      'HTTP/1.1 200 OK: x', 'Strict-Transport-Security: max-age=31536000', '', `#BODY run=${R}`, '<p>x</p>', ''].join('\n');
    expect(evaluate(page).findings.filter(f => f.item === 'H-01' && f.status === 'fail').map(f => f.ruleId)).toContain('H-01.1');
  });
  it('#BODY の前の行（トレーラ）を本文にしない', () => {
    const r = parseInput([`#TARGET url=https://www.example.com/mypage label=after-logout sensitive=1 run=${R}`, A, 'HTTP/1.1 200 OK', 'Transfer-Encoding: chunked', '',
      'X-T: <form><input type="password"></form>', '', `#BODY run=${R}`, '{"id":1}', ''].join('\n'));
    expect(r.targets[0].responses[0].body).toBe('{"id":1}\n\n');
  });
  it('-L の次のホップ（コロンのないステータス行）はこれまでどおり読む', () => {
    const r = parseInput([`#TARGET url=http://www.example.com/ label=http run=${R}`, A, 'HTTP/1.1 301 Moved', 'Location: https://www.example.com/', '', 'HTTP/2 200', 'content-type: text/html', '', `#BODY run=${R}`, '<p>x</p>', ''].join('\n'));
    expect(r.targets[0].responses.map(x => x.status)).toEqual([301, 200]);
  });
  it('1xx（103 Early Hints）の Set-Cookie で C-09 を合格にしない', () => {
    const input = [`#TARGET url=https://www.example.com/login label=pre-login run=${R}`, A, 'HTTP/2 200', 'set-cookie: sid=Q2x8AAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', '',
      `#TARGET url=https://www.example.com/login label=login run=${R}`, A, 'HTTP/1.1 103 Early Hints', 'Set-Cookie: sid=NEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNE; Path=/; Secure; HttpOnly', '',
      'HTTP/1.1 302 Found', 'Location: /mypage', '', ''].join('\n');
    expect(evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.1']);
  });
  it('1つの応答の Set-Cookie は上限まで読み（後のものを残す）、超えた分を知らせる', () => {
    const cs = Array.from({ length: 400 }, (_, i) => `Set-Cookie: c${i}=v; Path=/`);
    const r = parseInput(['#TARGET url=https://www.example.com/ label=page', 'HTTP/2 200', ...cs, '', ''].join('\n'));
    expect(r.targets[0].responses[0].headers.get('set-cookie')).toHaveLength(300);
    expect(r.targets[0].responses[0].headers.get('set-cookie')!.at(-1)).toBe('c399=v; Path=/');
    expect(r.warnings.filter(w => w.kind === 'too-many-cookies').map(w => w.detail)).toEqual([expect.stringContaining('100個')]);
  });
  it('対応していないプローブの警告は、ターゲットごとに1つ', () => {
    const r = parseInput([`#TARGET url=https://www.example.com/ label=tls run=${R}`, A, `#CIPHERPROBE run=${R} c=RC4-SHA ok=err`, `#CIPHERPROBE run=${R} c=DES-CBC3-SHA ok=err`, ''].join('\n'));
    expect(r.warnings.filter(w => w.kind === 'tls-probe-error').map(w => w.detail)).toEqual([expect.stringContaining('RC4-SHA・DES-CBC3-SHA')]);
  });
});

describe('第50回（束のレビュー）：古い curl のトレーラ・転送のホップのトレーラ・header_json の上限', () => {
  const R = '0123456789abcdef', A = `#META at=2026-11-01T10:00:00 run=${R}`;
  it('chunked の 200 のあとのコロンのないトレーラ（curl 7.82 以前）で応答を作り直さない', () => {
    const r = evaluate([`#TARGET url=https://www.example.com/api/me label=unauth-api run=${R}`, A, 'HTTP/1.1 200 OK', 'Content-Type: application/json', 'Transfer-Encoding: chunked', '',
      'HTTP/1.1 401 Unauthorized', 'X-Fake: 1', '', `#BODY run=${R}`, '{"id":1,"email":"a@example.com"}', ''].join('\n'));
    expect(r.targets[0].responses.map(x => x.status)).toEqual([200]);
    expect(r.findings.filter(f => f.item === 'A-01').map(f => f.ruleId)).toEqual(['A-01.1']);
  });
  it('転送のホップのトレーラのあと、空行なしで続く次のホップを読む', () => {
    const r = parseInput([`#TARGET url=http://www.example.com/ label=http run=${R}`, A, 'HTTP/1.1 301 Moved', 'Location: http://www.example.com/a', 'Transfer-Encoding: chunked', '',
      'X-T: 1', 'HTTP/1.1 302 Found', 'Location: https://www.example.com/', 'Set-Cookie: sessionid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; HttpOnly', '', 'HTTP/2 200', '',
      `#META response_code=200 num_redirects=2 run=${R}`, ''].join('\n'));
    expect(r.targets[0].responses.map(x => x.status)).toEqual([301, 302, 200]);
  });
  it('%{header_json} の Set-Cookie も上限まで', () => {
    const cs = JSON.stringify(Array.from({ length: 400 }, (_, i) => `c${i}=v`));
    const r = parseInput(['#TARGET url=https://www.example.com/ label=header-json', `{"content-type":["text/html"],"set-cookie":${cs}}`, '#META response_code=200', ''].join('\n'));
    expect(r.targets[0].responses[0].headers.get('set-cookie')).toHaveLength(300);
    expect(r.warnings.map(w => w.kind)).toContain('too-many-cookies');
  });
  it('-L でない採取の chunked の 3xx のあとのコロンのないトレーラ（curl 7.82 以前）を、次のホップにしない', () => {
    const input = [`#TARGET url=https://www.example.com/login label=pre-login run=${R}`, A, 'HTTP/2 200', 'set-cookie: sid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', '',
      `#TARGET url=https://www.example.com/login label=login run=${R}`, A, 'HTTP/1.1 302 Found', 'Location: /mypage', 'Transfer-Encoding: chunked', '',
      'HTTP/1.1 200 OK', 'Set-Cookie: sid=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', `#BODY run=${R}`, 'x', ''].join('\n');
    const r = evaluate(input);
    expect(r.targets.find(t => t.label === 'login')!.responses.map(x => x.status)).toEqual([302]);
    expect(r.findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.1']);
  });
});
