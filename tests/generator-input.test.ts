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
