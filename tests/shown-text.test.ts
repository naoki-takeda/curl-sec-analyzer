// 画面・エクスポートに出す証跡と URL の許可リスト（src/shownText.ts）。名前の付いていないトークン（本文の ghp_…・AKIA…・sk_live_…）も、
// どこに置いても出さない。読める語（ヘッダの名前・値、版、暗号の名前、日時）は残す
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { allowText, showTarget, showText } from '../src/shownText';
import { excerpt, maskText } from '../src/mask';
import { AT, evaluate, FC_MULT, leaks } from './helpers';


describe('名前の付いていないトークンを出さない', () => {
  it.each([
    ['GitHub', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'abcdefghijklmnopqrstuvwxyz0123456789'],
    ['Slack', 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx', 'AbCdEfGhIjKlMnOpQrStUvWx'],
    ['Stripe', 'sk_live_51HxYzABCDEFGHIJ', '51HxYzABCDEFGHIJ'],
    ['AWS のアクセスキー', 'AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
    ['AWS のシークレット', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'bPxRfiCYEXAMPLEKEY'],
    ['Slack の Webhook', 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX', 'XXXXXXXXXXXXXXXXXXXXXXXX'],
    ['Basic 認証', 'Authorization: Basic dXNlcjpwYXNz', 'dXNlcjpwYXNz'],
    ['秘密鍵', '-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA', 'MIIEowIBAAKCAQEA'],
    // - _ で区切ったかけらを1つずつ見ると、短いかけらが語に見えて残る
    ['GitLab', 'glpat-rbdO66tkD_ZWNg4NoDgY', 'rbdO66tkD'],
    ['GitLab（後半）', 'glpat-rbdO66tkD_ZWNg4NoDgY', 'NoDgY'],
    ['URL のユーザー名のトークン', 'https://0123456789abcdef0123456789abcdef01234567:x-oauth-basic@api.example/user', '0123456789abcdef'],
    ['クエリの @ のあと', 'https://a.example?ref=bob@XHuZ1Wd8E71o0abQ', 'XHuZ1Wd8E71o0abQ'],
    ['短い英数字', 'id NDBjn4jbean / lPbj3kupRYBa', 'NDBjn4jbean'],
  ])('%s', (_, text, secret) => {
    expect(showText(`本文：${text} 。`)).not.toContain(secret);
  });

  it('名前を付けた短い合言葉（URL・JSON の外）は、名前で伏せる', () => {
    for (const s of ['<!-- admin password=hunter2 -->', 'password="hunter2"', "{'password': 'hunter2'}", 'pass: hunter2', 'X-Auth-Token: hunter2', 'db_password = hunter2',
      "'password' => 'hunter2'", "define('DB_PASSWORD', 'hunter2');", '<password>hunter2</password>', '<add key="Password" value="hunter2"/>',
      'SPRING_DATASOURCE_PRIMARY_CONNECTIONPOOL_PASSWORD=hunter2', 'secret="hunter2&3"', 'https://a.example/x?magic=abcd-efgh-ijkl-hunter2', 'https://a.example/x?verification=hunter2'])
      expect(showText(s), s).not.toContain('hunter2');
  });

  it('一様な乱数のトークン（実際のトークンの作り方）のかけらが残る割合は小さい', () => {
    // 決まった種の擬似乱数（mulberry32）。fast-check の文字列は区切りの文字に偏るので、実際のトークンの形を一様な乱数で作る
    let seed = 20261117;
    const rand = () => { seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    const A62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const gen = (alpha: string, min: number, max: number) => { const n = min + Math.floor(rand() * (max - min + 1)); let s = ''; for (let i = 0; i < n; i++) s += alpha[Math.floor(rand() * alpha.length)]; return s; };
    const shapes: [string, () => string, number][] = [
      ['base62', () => gen(A62, 16, 40), 0.002], ['URL-safe', () => gen(`${A62}-_`, 20, 43), 0.01], ['GitLab', () => `glpat-${gen(`${A62}-_`, 20, 20)}`, 0.02],
      ['16進数', () => gen('0123456789abcdef', 16, 40), 0.002], ['英数字10〜15文字', () => gen(A62, 10, 15), 0.02],
      // 標準の Base64（+ / を含む）、パーセントエンコードした Base64、英大文字だけ・英小文字だけの短いもの。残る割合は大きめで、
      // 形では語と見分けられない部分（設計書に書いた残り）。悪くならないことを確かめる
      ['Base64', () => gen(`${A62}+/`, 40, 40), 0.07], ['エンコードした Base64', () => encodeURIComponent(gen(`${A62}+/`, 40, 40)), 0.09],
      ['英大文字10文字', () => gen(A62.slice(0, 26), 10, 10), 0.18], ['英小文字6〜9文字', () => gen(A62.slice(26, 52), 6, 9), 0.14],
    ];
    for (const [name, make, limit] of shapes) {
      let n = 0;
      for (let i = 0; i < 2000; i++) { const t = make(); if (leaks(showText(` ${t} `), t.replace(/^glpat-/, ''))) n++; }
      expect(n / 2000, name).toBeLessThan(limit);
    }
  });

  it('秘密でない名前は伏せない', () => {
    for (const s of ['Access-Control-Allow-Credentials: true', 'token_type: Bearer', 'password_policy: strong', 'type="password"'])
      expect(showText(s)).toBe(s);
  });

  it('乱数のトークンは、前後に何があっても出さない', () => {
    const token = fc.noBias(fc.stringMatching(/^[A-Za-z0-9]{16,40}$/).filter(t => /\d/.test(t) && /[a-z]/.test(t) && /[A-Z]/.test(t)));
    const around = fc.constantFrom('', ' ', '本文：', 'x-debug: ', 'via: 1.1 ', '<!-- ', '"', "'", '/', '_', '-', '.', 'key ', '(', 'id=');
    fc.assert(fc.property(around, token, around, (pre, t, post) => {
      const out = showText(`${pre}${t}${post}`);
      expect(leaks(out, t), out).toBeUndefined();
    }), { numRuns: 500 * FC_MULT, seed: 20261117 });
  });

  it('判定の証跡にも出さない（ヘッダ・本文に置いた名前のないトークン）', () => {
    const r = evaluate(['#TARGET url=https://a.example/ label=top', '#META at=2026-11-01T10:00:00', 'HTTP/2 200', 'content-type: text/html',
      'via: 1.1 proxy-AKIAJ3KQ7XZ2PLM4N5RT (squid/5.7)', 'x-debug-token: ghp_abcdefghijklmnopqrstuvwxyz0123456789', '',
      '<html><!-- TODO remove ghp_abcdefghijklmnopqrstuvwxyz0123456789 --><a href="http://10.0.0.5/api/sk_live_51HxYzABCDEFGHIJ">x</a></html>', ''].join('\n'));
    const all = r.findings.map(f => `${f.evidence} ${f.url ?? ''}`).join('\n');
    for (const s of ['abcdefghijklmnopqrstuvwxyz0123456789', 'AKIAJ3KQ7XZ2PLM4N5RT', '51HxYzABCDEFGHIJ']) expect(all).not.toContain(s);
  });
});

describe('読める語は残す', () => {
  it.each([
    'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    "script-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' https://cdn.jsdelivr.net",
    'nginx/1.25.3 PHP/8.1.2-1ubuntu2.14 Microsoft-IIS/10.0',
    'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 X25519 secp256r1 sha1WithRSAEncryption RSA 1024bit',
    'notAfter=Nov 17 00:00:00 2026 GMT / 2026-11-01T10:00:00Z',
    'at com.example.UserController.getUserById(UserController.java:42)',
    '.AspNetCore.Identity.ApplicationC1=CfDJ…(45 chars); path=/; samesite=lax; httponly',
    'X-Frame-Options: SAMEORIGIN / XMLHttpRequest / oauth2 / app01.prod.internal / font/woff2',
    'https://d111111abcdef8.cloudfront.net/app.js',
    'HTTP 302 → /login?next=%2Fv1%2Fadmin',
    'sessionid=AbCd…(29 chars); Secure; HttpOnly',
    // 許可リストで伏せすぎやすい製品名・例外名・パス
    'server: AkamaiGHost / x-powered-by: lighttpd/1.4.59 / X-AspNetMvc-Version: 5.2 / NextJS',
    'System.InvalidOperationException HttpMessageNotReadableException IndexOutOfRangeException',
    'Disallow: /phpMyAdmin/ /xmlrpc.php brainpoolP256r1',
    "script-src 'self' ajax.aspnetcdn.com *.example.com",
    'https://user:****@api.example/x',
  ])('%s', s => {
    expect(showText(s)).toBe(s);
  });
});

describe('冪等', () => {
  it('もう一度かけても変わらない', () => {
    const piece = fc.oneof(fc.stringMatching(/^[A-Za-z0-9]{1,30}$/), fc.constantFrom(' ', '/', '-', '_', '.', ':', '=', '…(12 chars)', 'https://', '%2F', '日本語', "'sha256-", '"', '@', '>', '?', "'nonce-", ':****@'));
    fc.assert(fc.property(fc.array(piece, { maxLength: 10 }), ps => {
      const once = showText(ps.join(''));
      expect(showText(once)).toBe(once);
      expect(allowText(once)).toBe(once);
    }), { numRuns: 500 * FC_MULT, seed: 20261117 });
  });

  it('maskText だけを通した値に許可リストを通しても、伏せた印は変えない', () => {
    const m = maskText('https://a.example/cb?token=Xk3Lm9QaBcDeFgHiJkLm');
    expect(allowText(m)).toBe(m);
  });
});

describe('URL・番号・決まった文言の伏せ方', () => {
  it('URL のユーザー情報に引用符があっても、パスワードを伏せる', () => {
    for (const u of ["https://alice:Summer'2024@www.example.com/", 'https://al\'ice:Summer2024@www.example.com/', 'http://admin:Tr0ub4dor"3@10.0.0.5/']) {
      expect(showText(u), u).not.toMatch(/Summer|Tr0ub4dor|2024@/);
      expect(showText(u), u).toContain(':****@');
    }
    const r = evaluate(`#TARGET url=https://alice:Summer'2024@www.example.com/ label=top\n${AT}\nHTTP/2 302\nlocation: https://www.example.com/x\n\n`);
    expect(JSON.stringify(r.findings.map(f => f.url))).not.toContain('Summer');
  });
  it('区切りをパーセントエンコードしたカード番号・社会保障番号・12桁の番号を伏せる', () => {
    for (const s of ['?card=4111%201111%201111%201111', '?card=4111%2D1111%2D1111%2D1111', '?id=123%2D45%2D6789', '?mn=1234%205678%209012',
      '?card=%34%31%31%31%20%31%31%31%31%20%31%31%31%31%20%31%31%31%31']) {
      expect(showText(`https://www.example.com/pay${s}`), s).not.toMatch(/4111|6789|9012|%31%31%31%31%20/);
    }
    // 番号でないもの（エンコードした空白でつないだ語、Luhn に通らない番号）は残す
    expect(showText('https://www.example.com/search?q=hello%20world')).toContain('hello%20world');
  });
  it('パラメータの値に入れた、エンコードした URL のユーザー情報を伏せる', () => {
    for (const s of ['?r=https%3A//alice:Summer2024@idp.example.com/', '?r=%2F%2Falice%3ASummer2024%40idp.example.com',
      '?r=https%253A%252F%252Falice%253ASummer2024%2540idp.example.com', '?r=https%3A%2F%2Falice%3ASummer%2F2024%40idp.example.com']) {
      expect(showText(`https://www.example.com/sso${s}`), s).not.toContain('Summer');
    }
  });
  it('パスに置いた、区切りのある招待・再設定の番号を伏せる（読める語の並びは残す）', () => {
    for (const p of ['/invite/QWER-TYUI-ZXCV-ASDF', '/magic/K7QX-9MZP-A2B4-C6D8', '/reset/a1b2-c3d4-e5f6-g7h8']) {
      expect(showText(`https://www.example.com${p}`), p).not.toMatch(/ZXCV|K7QX|a1b2/);
    }
    for (const keep of ['DES-CBC3-SHA', 'max-age=31536000', 'GET-POST-PUT', '2026-11-18']) expect(showText(keep), keep).toBe(keep);
  });
  it('ユーザー名と組の p= の値を伏せる（ページ番号の p= は残す）', () => {
    expect(showText('https://www.example.com/rest/ping?u=alice&p=Summer2024&v=1.16')).not.toContain('Summer2024');
    expect(showText('https://www.example.com/list?p=2&sort=asc')).toContain('p=2');
  });
  it('推奨対応の決まった文言の nonce を化けさせない', () => {
    expect(showText("script-src 'nonce-…' 'strict-dynamic'")).toBe("script-src 'nonce-…' 'strict-dynamic'");
  });
  it('T-11 の証跡に、手で書いた #META at= の値をそのまま出さない', () => {
    const tls = [`#TARGET url=https://www.example.com/ label=tls`, '#META at="2026-11-20 10:00 alice:Summer2024"', 'CONNECTED(00000003)',
      'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', 'Verify return code: 0 (ok)', 'notAfter=Dec  1 00:00:00 2026 GMT', ''].join('\n');
    expect(JSON.stringify(evaluate(tls).findings.filter(f => f.item === 'T-11'))).not.toContain('Summer');
  });
});

describe('冪等性・伏せすぎ・残った形', () => {
  const twice = (s: string) => showText(showText(s));
  it('ユーザー名と組の p= を伏せた結果は、何度かけても変わらない', () => {
    for (const s of ['https://www.example.com/rest/ping?u=alice&p=Summer2024&v=1.16', '?login=alice&p=enc:abc', '?user=bob&P=3', '?u=alice&amp;p=Summer2024', '?r=%3Fu%3Dalice%26p%3DSummer2024']) {
      expect(twice(s), s).toBe(showText(s));
      expect(showText(s), s).not.toContain('Summer2024');
      expect(showText(s), s).not.toContain('chars) chars)');
    }
  });
  it('URL の後ろの JSON・属性に置いたトークンを、ホスト名として残さない', () => {
    for (const s of ['{"site":"https://a.example","id":"x@xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"}', '{"site":"https://a.example","ref":"bob@AKIAIOSFODNN7EXAMPLE"}',
      "?r=https://a.example'@AKIAIOSFODNN7EXAMPLE"]) {
      expect(showText(s), s).not.toMatch(/AbCdEfGhIjKl|AKIAIOSFODNN7/);
    }
  });
  it('JSON・HTML のメールアドレスと URL を伏せすぎない', () => {
    expect(showText('{"site":"https://a.example","email":"bob@example.com"}')).toContain('"email":"bob@example.com"');
    expect(showText('<a href="https://x.example" title="mailto:me@x.example">')).toContain('mailto:me@x.example');
  });
  it('暗号の名前・型番を、区切りのある番号として伏せない', () => {
    for (const c of ['ECDHE-RSA-RC4-SHA', 'EXP-RC4-MD5', 'ADH-RC4-MD5', 'DHE-DSS-RC4-SHA', 'IDEA-CBC-MD5', 'ECDH-RSA-RC4-SHA', 'ECDHE-ECDSA-RC4-SHA', 'EXP-RC2-CBC-MD5',
      'ADH-DES-CBC3-SHA', 'SRP-3DES-EDE-CBC-SHA', 'AES-128-GCM', 'AES-256-CBC', 'node-v18-x64', 'win-x64-msvc', '?q=XSS%20CSRF%20SQLI', '?q=AES%20GCM%20CBC', '?s=MD5%20SHA1%20RC4']) {
      expect(showText(c), c).toBe(c);
    }
    const r = evaluate(`#TARGET url=https://www.example.com/ label=tls\n#CIPHERPROBE c=ECDHE-RSA-RC4-SHA ok=1\n#CIPHERPROBE c=DES-CBC3-SHA ok=1\n`);
    expect(r.findings.filter(f => f.item === 'T-10').map(f => f.evidence).join(' ')).toContain('ECDHE-RSA-RC4-SHA');
  });
  it('語のあとの、エンコードした区切り・+ の番号を伏せる', () => {
    for (const s of ['?q=card%204111%201111%201111%201111', '?q=card%3D4111%201111%201111%201111', '?q=ssn%20123-45-6789', '?q=SSN%20123%2D45%2D6789',
      '?q=card+4111+1111+1111+1111', '?mn=1234%2E5678%2E9012']) {
      expect(showText(s), s).not.toMatch(/4111|6789|9012/);
    }
  });
  it('エンコードした URL のユーザー情報の近い形を伏せ、ポートのあとのパスは伏せない', () => {
    for (const s of ['?r=%22https%3A%2F%2Falice%3ASummer2024%40idp.example.com%22', '?next=%2Flogin%3Fr%3Dhttps%3A%2F%2Falice%3ASummer2024%40idp.example.com',
      '?r=https:%2F%2Falice:Summer2024@idp.example.com', '?r=https%3A%2F%2Fbob%40corp.example%3ASummer2024%40idp.example.com', '?r=https%3A//alice%3ASummer2024%40idp.example.com',
      '?r=https%3A%2F%2Falice%3ASum%3Fmer2024%40idp.example.com', '?r=https%25253A%25252F%25252Falice%25253ASummer2024%252540idp.example.com']) {
      expect(showText(s), s).not.toMatch(/Summer2024|mer2024/);
    }
    expect(showText('?r=https%3A%2F%2Fapi.example.com%3A8443%2Fusers%2Fbob%40example.com')).toContain('8443%2Fusers%2Fbob%40example.com');
  });
  it('T-11 の時点は、書いてある日時の形のまま出す（タイムゾーンでずらさない）', () => {
    const tls = (at: string) => evaluate([`#TARGET url=https://www.example.com/ label=tls`, `#META at=${at}`, 'CONNECTED(00000003)', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384',
      'Verify return code: 0 (ok)', 'notAfter=Dec  1 00:00:00 2026 GMT', ''].join('\n')).findings.filter(f => f.item === 'T-11').map(f => f.evidence).join(' ');
    expect(tls('2026-11-20')).toContain('2026-11-20 時点');
    expect(tls('2026-11-20T10:00:00+09:00')).toContain('2026-11-20T10:00:00+09:00 時点');
  });
});

describe('二重エンコードした @・ユーザー名と組の p=・番号としない並び', () => {
  it('パスワードの中の二重エンコードした @（%2540）のあとも伏せる', () => {
    for (const s of ['?r=https%3A%2F%2Falice%3AP%2540summer2024%40idp.example', '?r=https%3A%2F%2Falice%3AWinter%2540Tokyo%40idp.example']) {
      expect(showText(s), s).not.toMatch(/summer2024|Tokyo/);
      expect(showText(s), s).toContain('idp.example');
    }
  });
  it('ユーザー名と p= の組は同じクエリの中だけで見る（別の URL・ユーザー名のないクエリの p= は残す）', () => {
    expect(showText('https://a.example/list?p=3 and https://b.example/?user=x')).toContain('p=3');
    expect(showText('https://a.example/?u=alice&p=Summer2024')).not.toContain('Summer2024');
  });
  it('日付を含むファイル名・3文字の略語の並び・暗号の名前を、番号として伏せない', () => {
    for (const s of ['db-backup-20261118-0300-01.sql', 'cdn-img-001', 'pdf-doc-xls', 'MIT-BSD-GPL', '?q=MIT%20BSD%20GPL', 'SM4-GCM-SM3']) expect(showText(s), s).toBe(s);
  });
});

describe('URL のユーザー情報・p=・名前・伏せすぎ', () => {
  it('パスワードの末尾・前後の引用符でも、パスワードを伏せる', () => {
    for (const s of ["https://alice:Summer2024'@stg.example/", 'https://alice:"Summer2024"@host.example/', 'https://alice:Summer2024"@host.example/']) {
      expect(showText(s), s).not.toContain('Summer2024');
      expect(showText(s), s).toContain(s.includes('stg') ? 'stg.example' : 'host.example');
    }
  });
  it('// の数が標準でない特別なスキームの URL のユーザー情報も伏せる', () => {
    for (const s of ['<script src="https:///dave:Kirin2024@cdn3.other.example/b.js">', 'https:\\dave:Kirin2024@h.example/', 'http:/dave:Kirin2024@h.example/', 'https:dave:Kirin2024@h.example/']) {
      expect(showText(s), s).not.toContain('Kirin2024');
    }
  });
  it('mail・user_name・login_id と組の p=、フラグメントの p= を伏せる', () => {
    for (const s of ['https://a.example/rest/ping?mail=alice@example.com&p=Kirin2024', '?user_name=alice&p=Kirin2024', '?login_id=alice&p=Kirin2024', 'https://a.example/app#u=alice&p=Kirin2024']) {
      expect(showText(s), s).not.toContain('Kirin2024');
    }
  });
  it('日本語・外国語のパスワードの名前の値を伏せる', () => {
    for (const s of ['https://a.example/?パスワード=Kirin2024', `https://a.example/?${encodeURIComponent('パスワード')}=Kirin2024`, '{"暗証番号":"4821"}', '{"暗証番号":4821}', '?senha=Kirin2024', '?wachtwoord=Kirin2024']) {
      expect(showText(s), s).not.toMatch(/Kirin2024|4821/);
    }
  });
  it('製品名・ヘッダ名・暗号の名前を伏せすぎない', () => {
    for (const s of ['CherryPy/18.9.0', 'WebSEAL/10.0.6.0', 'Proxy-Authorization', 'Proxy-Authenticate', 'X-Proxy-Cache', 'Zyxel', 'DHE-RSA-CAMELLIA256-SHA', 'CAMELLIA256-SHA', 'X25519MLKEM768']) {
      expect(showText(s), s).toBe(s);
    }
  });
});

describe('Markdown の自動リンク', () => {
  it('_ の直後の URL・www. もリンクにしない', async () => {
    const { toMarkdown } = await import('../src/export/markdown');
    const { coverage } = await import('../src/engine/coverage');
    const { IMPLEMENTED } = await import('../src/rules/ruleset');
    const fs = evaluate('#TARGET url=https://www.example.com/ label=page\n#META at=2026-11-01T10:00:00\nHTTP/2 200\ncontent-type: text/html\n\n<script src="https://cdn.other.example/lib_https://evil.example/x.js"></script>\n').findings;
    const md = toMarkdown(fs, coverage(fs, IMPLEMENTED), []);
    expect(md).not.toMatch(/_https:\/\//);
  });
});

describe('pass で終わる名前・長い名前・値の中の ;・配列の値・Cookie の名前', () => {
  it('pass で終わる名前の値を伏せる（bypass・compass は伏せない）', () => {
    expect(showText('https://a.example/login?username=bob&userpass=Winter2024')).not.toContain('Winter2024');
    expect(showText('{"newpass":"Winter2024","oldpass":"Autumn2023"}')).not.toMatch(/Winter2024|Autumn2023/);
    expect(showText('dbpass=Winter2024')).not.toContain('Winter2024');
    expect(showText('?pword=Winter2024&pswrd=Spring2025')).not.toMatch(/Winter2024|Spring2025/);
    expect(showText('?bypass=1&compass=north')).toBe('?bypass=1&compass=north');
  });
  it('100文字を超える名前（Rails の入れ子のフォームをエンコードしたもの）の値も伏せる', () => {
    expect(showText('?registration%5Buser_attributes%5D%5Baccount_attributes%5D%5Bsecurity_settings%5D%5Bcredentials%5D%5Bpassword%5D=Winter2024')).not.toContain('Winter2024');
  });
  it('値の中の生の ; も値として伏せる（; のあとが名前= のときは区切り）', () => {
    expect(showText('?username=bob&password=Summer;2024')).not.toContain('2024');
    expect(showText('a=1;jsessionid=ABCDEF0123456789ABCD;b=2')).toMatch(/;b=2$/);
    expect(showText('token=abc; Path=/')).toMatch(/; Path=\/$/);
  });
  it('配列の値（"password":["…"]）の中身を伏せる', () => {
    expect(showText('?q={"password":["Winter2024"]}')).not.toContain('Winter2024');
  });
  it('よくあるセッション Cookie の名前は伏せない', () => {
    for (const n of ['AWSELBAuthSessionCookie-0', 'ObSSOCookie', 'JSESSIONIDSSO', '.ASPXFORMSAUTH', 'AUTHSESSIONID', 'CFAUTHORIZATION'])
      expect(showText(`${n}=x; Secure`), n).toContain(n);
  });
});

describe('括弧で始まる値・pass で終わる語・配列・; の続き', () => {
  it('括弧で始まる引用符のない値も伏せる', () => {
    for (const x of ['password: [Winter2024]', 'password={Winter2024}', 'api_key=[Spring2025]', 'secret: {Spring2025}'])
      expect(showText(x), x).not.toMatch(/Winter2024|Spring2025/);
  });
  it('pass で終わる語は、数字・区切り・入れ子の名前でも伏せる', () => {
    for (const x of ['?newpass1=Winter2024', '?newpass_confirm=Winter2024', '?user[newpass]=Winter2024', '?user%5Bnewpass%5D=Winter2024', '?dbpass.value=Winter2024', '{"newpass1":"Winter2024"}'])
      expect(showText(x), x).not.toContain('Winter2024');
  });
  it('配列のすべての要素・入れ子・JSON の名前・エスケープ・URL エンコードの形を伏せ、ほかのキーの配列は残す', () => {
    for (const x of ['{"password":["Winter2024","Spring2025"]}', '{"password":[["Winter2024"]]}', '{"userPassword":["Winter2024"]}', '{\\"password\\":[\\"Winter2024\\"]}',
      '?q=%7B%22password%22%3A%5B%22Winter2024%22%5D%7D', "password: ['Winter2024', 'Spring2025']"])
      expect(showText(x), x).not.toMatch(/Winter2024|Spring2025/);
    expect(showText('{"password":["Winter2024"],"x":["keepme"]}')).toContain('keepme');
  });
  it('自由文の ; の続きも伏せ、Cookie の属性・接続文字列の設定の前では切る', () => {
    expect(showText('password=Summer;2024')).not.toContain('2024');
    expect(showText('x=1;session=abc;Secure;HttpOnly')).toMatch(/;Secure;HttpOnly$/);
    expect(showText('Server=db;Password=Winter2024;Max Pool Size=100')).toMatch(/;Max Pool Size=100$/);
  });
  it('改行を含む配列・括弧のあとの空白・引用符のない要素・=>・数字の付く名前・配列の中のキー', () => {
    for (const x of ['{"password":[\n  "Winter2024",\n  "Summer2025"\n]}', 'password: [ Winter2024 ]', 'password = { Winter2024 }', 'password: [[Winter2024]]',
      'password: [Winter2024, Summer2025]', "'password' => ['Winter2024','Summer2025']", 'newpass1=Winter2024', 'password1: Winter2024', 'db_pass1: Winter2024'])
      expect(showText(x), x).not.toMatch(/Winter2024|Summer2025/);
    expect(showText('{"password":[{"v":"Winter2024"}]}')).toBe('{"password":[{"v":"Wi…(10 chars)"}]}');
    expect(showText('a;jsessionid=ABCDEF0123456789;foo/bar.jsp')).toMatch(/;foo\/bar\.jsp$/);
  });
});

describe('配列の空の要素・CSP の ;・エスケープした // のユーザー情報・オブジェクトの値', () => {
  it('配列に空の文字列の要素があっても、後ろの要素を伏せる', () => {
    for (const x of ['"password":["","Hunter2Spring"]', '{"password":["a","","Hunter2Spring"]}', '{\\"password\\":[\\"\\",\\"Hunter2Spring\\"]}',
      'https://a.example/graphql?variables=%7B%22password%22%3A%5B%22%22%2C%22Hunter2Spring%22%5D%7D', "password: ['', 'Hunter2Spring']", 'password => ["", "Hunter2Spring"]'])
      expect(showText(x), x).not.toContain('Hunter2Spring');
  });
  it('値の中の ; の続きは、CSP のディレクティブの前で切る', () => {
    expect(showText("default-src 'self';report-uri https://o1.ingest.sentry.io/api/4/security/?sentry_key=abc123;script-src 'self' 'unsafe-inline'")).toContain(";script-src 'self' 'unsafe-inline'");
  });
  it('JSON でエスケープした // の、特別でないスキームのユーザー情報を伏せる', () => {
    for (const x of ['postgres:\\/\\/alice:Hunter2Spring@db.example\\/x', 'redis:\\/\\/:Hunter2Spring@cache'])
      expect(showText(x), x).not.toContain('Hunter2Spring');
  });
  it('値がオブジェクトのときも、中の値を伏せる（キーは残す）', () => {
    expect(showText('"password":{"value":"Hunter2Spring"}')).toMatch(/"value":"Hu…\(13 chars\)"/);
    expect(showText('password: {value: Hunter2Spring}')).toMatch(/\{value: Hu…\(13 chars\)\}/);
  });
  it('入れ子のオブジェクト・配列の中の秘密の名前、バックスラッシュを含むユーザー情報、CSP の名前の一覧、引用符のあるオブジェクトのキー', () => {
    for (const x of ['{"user":{"password":{"value":"Hunter2Spring"}}}', '{"user":{"name":"bob","password":{"value":"Hunter2Spring"}}}', '{"items":[{"password":["Hunter2Spring"]}]}',
      'smb://CORP\\alice:Hunter2Spring@fileserver/share', '"dsn":"postgres://alice:Hunter2\\\\Spring@db"', '?password=Hunter2Spring;correct-horse-battery',
      "password: {value: 'Hunter2Spring'}", 'password: {"value": Hunter2Spring}', 'password = {"value": "Hunter2Spring"}', 'password => {"value" => "Hunter2Spring"}',
      "{'password': {'value': 'Hunter2Spring'}}", '%22password%22%3A%7B%22value%22%3A%22Hunter2Spring%22%7D'])
      expect(showText(x), x).not.toContain('Spring');
    expect(showText("password: {value: 'Hunter2Spring'}")).toContain('{value: ');
  });
});

describe('値の中の ; の並び', () => {
  it('; の並び（;;）のあとも値として伏せる', () => {
    for (const x of ['https://a.example/?password=hunter2;;Winter2024', '?password=a;;Winter2024', 'password=hunter2;;;Winter2024', '?password=hunter2;;Winter2024&x=1'])
      expect(showText(x), x).not.toContain('Winter2024');
    expect(showText('?password=hunter2;;Winter2024&x=1')).toMatch(/&x=1$/);
  });
  it('; の並びのあとが名前=・Cookie の属性・空白・パス・CSP のディレクティブ・終わりなら、値はそこまで', () => {
    expect(showText('?password=hunter2;;x=1')).toMatch(/;;x=1$/);
    expect(showText('password=hunter2;;Secure')).toMatch(/;;Secure$/);
    expect(showText('password=hunter2;; Path=/')).toMatch(/;; Path=\/$/);
    expect(showText('?password=hunter2;;/path')).toMatch(/;;\/path$/);
    expect(showText('?password=hunter2;;script-src')).toMatch(/;;script-src$/);
    expect(showText('?password=hunter2;;')).toMatch(/;;$/);
  });
});

describe('エンコードした URL のユーザー情報の同じ深さの %40、区切りの違うエンコードした番号', () => {
  it('パスワードの中の同じ深さの %40 も、ホストの前の最後の %40 まで伏せる', () => {
    for (const x of ['?redirect=https%3A%2F%2Falice%3AWinter%40Tokyo%40evil.example%2Fcb', '?redirect=https%3A%2F%2Falice%3AWinter%40Tokyo%40Osaka%40evil.example',
      '?redirect=https%253A%252F%252Falice%253AWinter%2540Tokyo%2540evil.example', '?redirect=https%3A%2F%2Fbob%40corp%3AWinter%40Tokyo%40idp.example'])
      expect(showText(x), x).not.toMatch(/Tokyo|Osaka|Winter/);
    expect(showText('?redirect=https%3A%2F%2Falice%3AWinter%40Tokyo%40evil.example%2Fcb')).toMatch(/%40evil\.example%2Fcb$/);
  });
  it('パス・クエリの %40 はユーザー情報に含めない', () => {
    expect(showText('?redirect=https%3A%2F%2Falice%3Apw%40host.example%2Fusers%2Fbob%40x.example')).toMatch(/%40host\.example%2Fusers%2Fbob%40x\.example$/);
    expect(showText('?redirect=https%3A%2F%2Falice%3Apw%40evil.example%3Fx%3D%40y')).toMatch(/%40evil\.example%3Fx%3D%40y$/);
    expect(showText('?redirect=https%3A%2F%2Fhost.example%3A8443%2Fusers%2Fbob%40x.example')).toBe('?redirect=https%3A%2F%2Fhost.example%3A8443%2Fusers%2Fbob%40x.example');
  });
  it('全体をエンコードした番号は、生の - _ + . の区切りでも伏せる', () => {
    for (const sep of ['-', '_', '+', '.']) {
      const x = `?card=${['%34%31%31%31', '%31%31%31%31', '%31%31%31%31', '%31%31%31%31'].join(sep)}`;
      expect(showText(x), x).not.toContain('%31%31%31%31');
    }
    expect(showText('?ssn=%31%32%33-%34%35-%36%37%38%39')).not.toContain('%36%37%38%39');
  });
  it('区切りでつないだエンコードした日本語・記号は残す', () => {
    for (const x of ['/%E3%81%8A%E7%9F%A5-%E3%82%89%E3%81%9B', '/a%2Fb.%2Fc', 'x%20-%20y', '?q=%E3%81%8A.%E3%81%8B+%E3%81%8C'])
      expect(showText(x), x).toBe(x);
  });
});

describe('空白・続く区切り・生とエンコードの混在の番号、生の @ で終わるエンコードしたユーザー情報', () => {
  it('生の空白・2文字以上の区切りでつないだ、全体をエンコードした番号を伏せる', () => {
    for (const x of ['?q=%34%31%31%31 %31%31%31%31 %31%31%31%31 %31%31%31%31', '?x=%34%31%31%31--%31%31%31%31--%31%31%31%31--%31%31%31%31',
      '?x=%34%31%31%31-_%31%31%31%31-_%31%31%31%31-_%31%31%31%31'])
      expect(showText(x), x).not.toMatch(/%31%31%31%31|%34%31%31%31/);
  });
  it('生の数字とエンコードした数字の混ざった番号を伏せる', () => {
    for (const x of ['?x=4111-%31%31%31%31-%31%31%31%31-1111', '?x=4%31%31%31-1%31%31%31-1%31%31%31-1%31%31%31', '?card%3D4111%2D%31%31%31%31%2D1111%2D1111'])
      expect(showText(x), x).not.toMatch(/1111|%31%31/);
  });
  it('番号の形でない数字の並び（日付・IP アドレス・版・電話番号）は残す', () => {
    for (const x of ['/d/%32%30%32%36-%31%31-%31%38', 'Mozilla%2F5.0 (Windows NT 10.0)', '192.168.100.200', 'v1.2%2E3', '?ip=%31%39%32.%31%36%38.%31.%31', 'tel: %30%33-%31%32%33%34-%35%36%37%38'])
      expect(showText(x), x).toBe(x);
  });
  it('エンコードしたスキームのユーザー情報は、生の @ や深さの違う %40 で終わっても伏せる', () => {
    for (const x of ['?redirect=https%3A%2F%2Falice%3AWinter2024@evil.example', '?redirect=https%253A%252F%252Falice%253AWinter%2540Tokyo%40evil.example',
      '?redirect=https%3A%2F%2Falice%3AWinter%2540Tokyo%40evil.example'])
      expect(showText(x), x).not.toMatch(/Winter|Tokyo/);
    expect(showText('?redirect=https%3A%2F%2Falice%3Apw@host.example%2Fx%40y')).toMatch(/@host\.example%2Fx%40y$/);
    expect(showText('?redirect=https%3A%2F%2Fhost.example%2Fusers@x')).toBe('?redirect=https%3A%2F%2Fhost.example%2Fusers@x');
  });
});

describe('パスワードの中の生の @', () => {
  it('エンコードしたスキームのユーザー情報のパスワードに生の @ が2つ以上あっても、最後の @ まで伏せる', () => {
    for (const x of ['?r=https%3A%2F%2Falice%3AWin@ter%40Tokyo%40evil.example', '?r=https%3A%2F%2Falice%3AWin@ter@evil.example',
      '?r=https%3A%2F%2Falice%3ASummer2024@Winter2024%40evil.example', '?r=%2F%2Falice%3AWin@ter%40evil.example'])
      expect(showText(x), x).not.toMatch(/Win|ter|Tokyo|Summer/);
  });
  it('%25 を重ねて3回戻しても % が残る数字の並びは伏せる', () => {
    expect(showText('1-%' + '25'.repeat(10) + '31-%31%31')).not.toContain('2525');
  });
});

describe('スキームのない URL（//ホスト）', () => {
  it.each([
    '<script src="//d111111abcdef8.cloudfront.net/app.js"></script>',
    "src='//d111111abcdef8.cloudfront.net/app.js'",
    'background: url(//d111111abcdef8.cloudfront.net/bg.png)',
    '<img srcset="//d111111abcdef8.cloudfront.net/a.png 1x, //d222222abcdef9.cloudfront.net/b.png 2x">',
    "script-src 'self' //d111111abcdef8.cloudfront.net",
    '//d111111abcdef8.cloudfront.net:8443/app.js',
    '//user:****@d111111abcdef8.cloudfront.net/x',
  ])('https:// の URL と同じく、ホスト名を残す：%s', s => {
    expect(showText(s)).toBe(s);
  });
  it('ホスト名の形でないもの・ユーザー名・コメントに置いたトークンは残さない', () => {
    for (const s of ['"//AKIAIOSFODNN7EXAMPLE"', '"//AKIAIOSFODNN7EXAMPLE.abcd1234"', '<script>//AKIAIOSFODNN7EXAMPLE.cloudfront.net</script>',
      '// AKIAIOSFODNN7EXAMPLE', 'x=//AKIAIOSFODNN7EXAMPLE.cloud:x-oauth-basic@api.example/', 'a.example//AKIAIOSFODNN7EXAMPLE.cloudfront.net',
      ' //AKIAIOSFODNN7EXAMPLE.wJalrXUtnFEMIK']) {
      expect(showText(s), s).not.toMatch(/AKIAIOSFODNN7/);
    }
  });
  it('URL でない場所（Authorization・Cookie の値・JS のコメント・JSON）の「//」のあとのドットで区切ったトークンは残さない', () => {
    for (const s of ['Authorization: Bearer //QwErTyUiOp.AsDfGhJkLz', 'Cookie: a=1, sid=//QwErTyUiOp.AsDfGhJkLz', 'x = 1  //QwErTyUiOpAsDfGhJkLz.ZxCvBnMqWeRtYu',
      '{"k":"//MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjmXVWvRzebCqseKWs"}', '(//ya29.a0AfH6SMBxQwErTy.AbCdEfGh', 'Bearer //qwrtzxkpmnbvcdfgh.zxcvbnmqwrt']) {
      expect(showText(s), s).not.toMatch(/QwErTyUiOp|MTk4NjIy|a0AfH6SMBx|qwrtzxkpmnbvcdfgh/);
    }
  });
});

describe('パーセントエンコードした URL のユーザー情報', () => {
  const T = 'QwErTyUiOpAsDfGhJkLz';
  it('エンコードした @（%40・%2540）の前のユーザー名を、ホスト名として残さない', () => {
    for (const s of [`https://${T}%40cdn.example.com/`, `https://${T}%3Ax%40cdn.example.com/`, `https://${T}%2540cdn.example.com/`,
      `https://${T}%3Ax%252540cdn.example.com/`, `?next=https://${T}%40evil.example/`, ` //qwrtzxkpmnbvcdfgh.example.com%3Ax%40cdn.example.com/`]) {
      expect(showText(s), s).not.toMatch(/QwErTyUiOp|qwrtzxkpmnbvcdfgh/);
    }
  });
  it('パス・クエリのエンコードした @ では、ホスト名を伏せない', () => {
    for (const s of ['https://d111111abcdef8.cloudfront.net/a%40b.png', 'https://d111111abcdef8.cloudfront.net?e=a%40b.example', ' //d111111abcdef8.cloudfront.net/a%40b'])
      expect(showText(s), s).toContain('d111111abcdef8.cloudfront.net');
  });
});

describe('HTML・JS で書いた @、引用符、ユーザー情報のあとのホスト名', () => {
  const T = 'QwErTyUiOpAsDfGhJkLz';
  it('文字参照・JS のエスケープで書いた @ の前のユーザー名を、ホスト名として残さない', () => {
    for (const s of [`https://${T}:x&#64;cdn.example.com/`, `https://${T}:x&#x40;cdn.example.com/`, `https://${T}:x&commat;cdn.example.com/`,
      `"https://${T}:x\u0040cdn.example.com/"`, `"https://${T}:x\x40cdn.example.com/"`, `https://${T}'x%40cdn.example.com/`, `https://${T}"x%40cdn.example.com/`,
      `https://a@${T}.x%40cdn.example.com/`]) {
      expect(showText(s), s).not.toMatch(/QwErTyUiOp/);
    }
  });
  it('クエリの & のあとのエンコードした @（OAuth の login_hint）では、ホスト名を伏せない', () => {
    expect(showText('?redirect_uri=https://d111111abcdef8.cloudfront.net&login_hint=alice%40example.com')).toContain('https://d111111abcdef8.cloudfront.net&');
  });
});

describe('2つのかけらのコードと、切り詰めた証跡', () => {
  it('同じ長さの乱数のかけら2つのコード（K7QX-9MZP）は伏せ、暗号の名前・略語は残す', () => {
    expect(showText('backup code K7QX-9MZP')).not.toContain('9MZP');
    for (const w of ['SHA-256', 'x264-h265', 'TLS-AES', 'pdf-img']) expect(showText(w)).toBe(w);
  });
  it('excerpt：語の途中で切ったトークンのかけらを残さない（clip はそのまま）', () => {
    const s = `Found key in body: ${'x'.repeat(30)} ghp_R8kQ2mZxW4pL9vT1yN6bC3dF7hJ0sA5eU`;
    expect(showText(excerpt(s, 58))).not.toContain('R8kQ');
    expect(excerpt('abc def', 5)).toBe('abc ');
  });
});

describe('~ でつないだ番号とコード', () => {
  it('~ で区切ったカード番号・コードも伏せる', () => {
    expect(showText('4111~1111~1111~1111')).not.toContain('1111');
    expect(showText('QWER~TYUI~ZXCV~ASDF')).not.toContain('ZXCV');
  });
});

describe('. : で区切ったコード・長さのそろわないコード', () => {
  it('電話番号・日付に番号を付けたもの・略語の並びは、画面では残す（電話番号を伏せるのは突き合わせのキーだけ）', () => {
    for (const s of ['tel 090-1234-5678', '0120-123-456', '2026-11-19-01', 'Date: 2026-11-20', '1920-1080', '?q=XSS%20CSRF%20SQLI']) expect(showText(s), s).toBe(s);
  });
  it('. や : で区切ったコードと、長さのそろわない乱数のかけらのコードは伏せる', () => {
    for (const s of ['code K7QX.9MZP.A2B4.C6D8', 'K7QX:9MZP:A2B4:C6D8', '/magic/K7QX.9MZP', '/invite/7Gk-p2Q-xZ81-m', '7Gk.p2Q.xZ81.m'])
      expect(showText(s), s).not.toMatch(/K7QX|9MZP|xZ81/);
  });
  it('版・ファイル名・ホスト名・IPv6 と MAC アドレス・時刻・暗号の名前は残す', () => {
    for (const s of ['nginx/1.25.3', 'TLSv1.3', 'ASP.NET', 'Apache/2.4.41 (Ubuntu)', 'ECDHE-RSA-AES128-GCM-SHA256', 's3-ap-northeast-1', 'win10-x64-v2',
      'k8s-1-28', 'i18n.js', 'jquery-3.6.0.min.js', '10:30:00', 'https://a1b2.c3d4.example/', 'x86.x64', 'md5:sha1', '1.0.0a1', 'fe80::1',
      '2001:db8:85a3:8d3:1319:8a2e:370:7348', '00:1A:2B:3C:4D:5E', 'cdn.k7qx.example'])
      expect(showText(s), s).toBe(s);
  });
});

describe('. : で区切ったコードの前後と、英字と数字の語の並び', () => {
  it('- _ が前後に付いた . : のコードも伏せる', () => {
    for (const s of ['code-K7QX.9MZP.A2B4.C6D8', 'invite_K7QX.9MZP.A2B4.C6D8', 'K7QX.9MZP.A2B4.C6D8-x', 'K7QX.9MZP%2Dfoo', 'K7QX.9MZP-Q2Z4.C6D8', '%2FK7QX.9MZP'])
      expect(showText(s), s).not.toMatch(/K7QX|9MZP|C6D8/);
  });
  it('小文字だけ・大文字だけの英字と数字の語の並び（ファイル名・略語・ビルドの名前・時刻・曲線）は伏せない', () => {
    for (const s of ['icon-16x16-2x.png', '/docs/i18n-l10n-guide', '/blog/p2p-e2e-tips', 'ec2-s3-iam', 'e2e-k8s-1-28',
      '4xx-5xx-errors', 'W3C.WAI.a11y', '4k.8k.hdr', '(Linux; Android 13; Build/TQ3A.230901.001.C2; wv)', 'T10:30:00Z', '1.0.0a1.dev2',
      'X25519:P256:P384', 'db1.k8s.lan'])
      expect(showText(s), s).toBe(s);
  });
});

describe('ホスト単位の指摘の対象（URL.host）', () => {
  it('URL のホスト名と同じく、伏せずに出す（知らない最上位ドメイン・IDN・ポート・IPv6）', () => {
    for (const h of ['xk9qz2mpl7rtv.shop.tokyo', 'xn--eckwd4c7c.xn--zckzah', 'www.example.co.jp:8443', '[2001:db8::1]:8443', '192.168.0.1'])
      expect(showTarget(h, h), h).toBe(h);
  });
  it('ホスト名の形でないもの・ホスト単位でない対象（ラベルの組）は、許可リストを通す', () => {
    expect(showTarget('ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789')).not.toContain('abcdefghijklmnop');
    expect(showTarget('a.example/ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'a.example/ghp_abcdefghijklmnopqrstuvwxyz0123456789')).not.toContain('abcdefghijklmnop');
    expect(showTarget('xk9qz2mpl7rtv.shop.tokyo')).toBe(showText('xk9qz2mpl7rtv.shop.tokyo'));
    expect(showTarget('pre-login/login')).toBe('pre-login/login');
  });
  it('URL の列でも伏せるホスト名（カード番号のラベル）は伏せ、末尾の . のホスト名はそのまま出す', () => {
    expect(showTarget('4111111111111111.shop.tokyo', '4111111111111111.shop.tokyo')).not.toContain('4111111111111111');
    expect(showTarget('xk9qz2mpl7rtv.shop.tokyo.', 'xk9qz2mpl7rtv.shop.tokyo.')).toBe('xk9qz2mpl7rtv.shop.tokyo.');
  });
  it('ユーザー情報のあとでは URL の列が伏せる点のない乱数のホスト名は伏せ、今のターゲットのラベルはそのまま出す', () => {
    const h = 'a8f3k2m9x7q1w5e6r4t0y2u8i3o5p7a9';
    expect(showTarget(h, h)).not.toContain(h);
    expect(showTarget('web01', undefined, new Set(['web01']))).toBe('web01');
    expect(showTarget('web01')).toBe(showText('web01'));
  });
  it('ホスト単位の指摘は、対象と host が同じ URL.host になる', () => {
    const r = evaluate('#TARGET url=https://xk9qz2mpl7rtv.shop.tokyo:8443/ label=tls\n#TLSPROBE v=tls1 ok=1\n');
    const f = r.findings.find(x => x.item === 'T-09');
    expect(f?.target).toBe('xk9qz2mpl7rtv.shop.tokyo:8443'); expect(f?.host).toBe(f?.target);
  });
});
