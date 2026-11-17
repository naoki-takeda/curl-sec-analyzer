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
  ])('%s', (_, text, secret) => {
    expect(showText(`本文：${text} 。`)).not.toContain(secret);
  });

  it('名前を付けた短い合言葉（URL・JSON の外）は、名前で伏せる', () => {
    for (const s of ['<!-- admin password=hunter2 -->', 'password="hunter2"', "{'password': 'hunter2'}", 'pass: hunter2', 'X-Auth-Token: hunter2', 'db_password = hunter2'])
      expect(showText(s), s).not.toContain('hunter2');
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
  ])('%s', s => {
    expect(showText(s)).toBe(s);
  });
});

describe('冪等', () => {
  it('もう一度かけても変わらない', () => {
    const piece = fc.oneof(fc.stringMatching(/^[A-Za-z0-9]{1,30}$/), fc.constantFrom(' ', '/', '-', '_', '.', ':', '=', '…(12 chars)', 'https://', '%2F', '日本語', "'sha256-", '"'));
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
