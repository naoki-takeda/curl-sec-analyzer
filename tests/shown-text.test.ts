// 画面・エクスポートに出す証跡と URL の許可リスト（src/shownText.ts）。名前の付いていないトークン（本文の ghp_…・AKIA…・sk_live_…）も、
// どこに置いても出さない。読める語（ヘッダの名前・値、版、暗号の名前、日時）は残す
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { allowText, showText } from '../src/shownText';
import { maskText } from '../src/mask';
import { evaluate } from './helpers';

const MULT = Number(process.env.FC_RUNS) || 1;
const leaks = (out: string, t: string) => { for (let i = 0; i + 8 <= t.length; i++) if (out.includes(t.slice(i, i + 8))) return t.slice(i, i + 8); return undefined; };

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
    // 第38回：- _ で区切ったかけらを1つずつ見ると、短いかけらが語に見えて残った
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
      // 第39回：標準の Base64（+ / を含む）、パーセントエンコードした Base64、英大文字だけ・英小文字だけの短いもの。残る割合は大きめで、
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
    }), { numRuns: 500 * MULT, seed: 20261117 });
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
    // 第38回：許可リストで伏せすぎた製品名・例外名・パス
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
    }), { numRuns: 500 * MULT, seed: 20261117 });
  });

  it('maskText だけを通した値に許可リストを通しても、伏せた印は変えない', () => {
    const m = maskText('https://a.example/cb?token=Xk3Lm9QaBcDeFgHiJkLm');
    expect(allowText(m)).toBe(m);
  });
});

// 第48回のレビュー（マスキング・エクスポート）で見つかった漏れ
describe('第48回：URL・番号・決まった文言の伏せ方', () => {
  const AT48 = '#META at=2026-11-01T10:00:00';
  it('URL のユーザー情報に引用符があっても、パスワードを伏せる', () => {
    for (const u of ["https://alice:Summer'2024@www.example.com/", 'https://al\'ice:Summer2024@www.example.com/', 'http://admin:Tr0ub4dor"3@10.0.0.5/']) {
      expect(showText(u), u).not.toMatch(/Summer|Tr0ub4dor|2024@/);
      expect(showText(u), u).toContain(':****@');
    }
    const r = evaluate(`#TARGET url=https://alice:Summer'2024@www.example.com/ label=top\n${AT48}\nHTTP/2 302\nlocation: https://www.example.com/x\n\n`);
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

// 第48回の束1の修正のレビューで見つかったもの（修正で新しく出た問題と、修正の足りなかった形）
describe('第48回（束1のレビュー）：冪等性・伏せすぎ・残った形', () => {
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

// 第48回の束1の修正の、第2回のレビューで見つかったもの
describe('第48回（束1の第2回のレビュー）', () => {
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
    expect(showText('/invite/QWER-TYUI-ZXCV-ASDF')).not.toContain('ZXCV');
  });
});
