// 第40回の束5（第1〜3章のルールの誤判定）と束6（マスクの残り・プローブ・差分）の再現テスト
import { describe, expect, it } from 'vitest';
import { hostSameSiteMap } from '../src/engine/run';
import { parseInput } from '../src/parser/input';
import { diff } from '../src/engine/diff';
import type { Finding } from '../src/model';
import { maskText } from '../src/mask';
import { showText } from '../src/shownText';
import { evaluate } from './helpers';

const ids = (input: string, item: string, target?: string) =>
  evaluate(input).findings.filter(f => f.item === item && (!target || f.target === target)).map(f => f.ruleId);

describe('束5 H-04⑤ はスクリプトのディレクティブの nonce を比べる', () => {
  const two = (csp1: string, csp2: string) => [csp1, csp2].map((c, i) =>
    `#TARGET url=https://a.example/ label=csp-sample-${i + 1}\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy: ${c}\n\n`).join('');
  it('style-src の固定の nonce では⑤にしない', () => {
    expect(ids(two("style-src 'nonce-STATICstyle'; script-src 'nonce-rotA1'", "style-src 'nonce-STATICstyle'; script-src 'nonce-rotB2'"), 'H-04')).not.toContain('H-04.5');
  });
  it('script-src の固定の nonce は、前に style-src の nonce があっても⑤', () => {
    expect(ids(two("style-src 'nonce-rotA1'; script-src 'nonce-FIXEDscript'", "style-src 'nonce-rotB2'; script-src 'nonce-FIXEDscript'"), 'H-04')).toContain('H-04.5');
    expect(ids(two("default-src 'self' 'nonce-FIXEDdef'", "default-src 'self' 'nonce-FIXEDdef'"), 'H-04')).toContain('H-04.5');
    expect(ids(two("script-src 'NONCE-FIXEDup' 'nonce-r1'", "script-src 'NONCE-FIXEDup' 'nonce-r2'"), 'H-04')).toContain('H-04.5');
  });
  it('script-src があるときの default-src の固定の nonce と、同じ応答の中で繰り返す nonce では⑤にしない', () => {
    expect(ids(two("default-src 'self' 'nonce-STATICdef'; script-src 'nonce-rotA1' 'strict-dynamic'", "default-src 'self' 'nonce-STATICdef'; script-src 'nonce-rotB2' 'strict-dynamic'"), 'H-04')).not.toContain('H-04.5');
    expect(ids(two("script-src 'nonce-rotA1'; script-src-elem 'nonce-rotA1'", "script-src 'nonce-rotB2'; script-src-elem 'nonce-rotB2'"), 'H-04')).not.toContain('H-04.5');
  });
});

describe('束5 R-09 は Bearer だけの WebSocket を①にしない', () => {
  const ws = (auth: string) => `#TARGET url=https://a.example/ws label=websocket\n* Connected to a.example (127.0.0.1) port 443\n> GET /ws HTTP/1.1\n> Host: a.example\n> Origin: https://evil.example\n${auth}\n>\n< HTTP/1.1 101 Switching Protocols\n< Upgrade: websocket\n<\n`;
  it('Bearer のトークンだけなら②', () => {
    expect(ids(ws('> Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'), 'R-09')).toEqual(['R-09.2']);
  });
  it('Basic 認証とセッションCookie は①のまま', () => {
    expect(ids(ws('> Authorization: Basic dXNlcjpwYXNz'), 'R-09')).toEqual(['R-09.1']);
    expect(ids(ws('> Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln\n> Cookie: sessionid=abcdefghijklmnopqrstuvwxyz012345'), 'R-09')).toEqual(['R-09.1']);
  });
  it('sensitive=1 の明示には従う', () => {
    expect(ids(ws('> Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln').replace('label=websocket', 'label=websocket sensitive=1'), 'R-09')).toEqual(['R-09.1']);
  });
});

describe('束5 C-07① は引用符とパーセントエンコードを乱数に数えない', () => {
  it('引用符で囲んだ20桁の16進数（80bit）は①', () => {
    const r = ids(`#TARGET url=https://a.example/login label=login\nHTTP/2 302\nlocation: /home\nset-cookie: sid="abcdefabcdefabcdefab"; Path=/; Secure; HttpOnly; SameSite=Lax\n\n`, 'C-07');
    expect(r).toContain('C-07.1');
  });
});

describe('束5 H-03③ は空の CSP ヘッダのとき meta の CSP を見る', () => {
  it('空のヘッダと有効な meta の CSP は合格', () => {
    const r = ids(`#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy: \n\n<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; object-src 'none'; base-uri 'none'"></head><body>x</body></html>\n`, 'H-03');
    expect(r).toEqual(['H-03.ok']);
  });
});

describe('束5 H-05 は csp_evaluator が解析できないときに合格にしない', () => {
  it('data:image/png のある CSP は na', () => {
    const r = ids(`#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy: default-src * 'unsafe-inline'; img-src data:image/png; base-uri 'self'\n\n`, 'H-05');
    expect(r).toEqual(['H-05.na']);
  });
  it('ほかのポリシーに object-src \'none\' と base-uri があれば合格', () => {
    const r = ids(`#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy: default-src * 'unsafe-inline'; img-src data:image/png\ncontent-security-policy: object-src 'none'; base-uri 'self'\n\n`, 'H-05');
    expect(r).toEqual(['H-05.ok']);
  });
});

describe('束5 H-12 の値のある private', () => {
  it('private="Set-Cookie" は②で、仕様では共有キャッシュに保存してよいことを証跡に書く（引用符の中のカンマで区切らない）', () => {
    const r = evaluate(`#TARGET url=https://a.example/mypage label=mypage sensitive=1\nHTTP/2 200\ncontent-type: text/html\ncache-control: max-age=600, private="Set-Cookie, X-A"\n\n`).findings.filter(f => f.item === 'H-12');
    expect(r.map(f => f.ruleId)).toEqual(['H-12.2']);
    expect(r[0].evidence).toContain('値のある private');
  });
  it('値のない private は②のまま', () => {
    expect(ids(`#TARGET url=https://a.example/mypage label=mypage sensitive=1\nHTTP/2 200\ncontent-type: text/html\ncache-control: private, max-age=600\n\n`, 'H-12')).toEqual(['H-12.2']);
  });
});

describe('束5 H-09 は <meta name="referrer"> を見る', () => {
  const page = (hdr: string, meta: string) => `#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\n${hdr}\n<html><head>${meta}</head><body>x</body></html>\n`;
  it('ヘッダが no-referrer でも meta の unsafe-url は①', () => {
    expect(ids(page('referrer-policy: no-referrer\n', '<meta name="referrer" content="unsafe-url">'), 'H-09')).toEqual(['H-09.1']);
    expect(ids(page('referrer-policy: no-referrer\n', '<meta name="referrer" content="always">'), 'H-09')).toEqual(['H-09.1']);
  });
  it('ヘッダと meta のうち最も弱いもので判定する（最後の strict な meta で合格にしない）', () => {
    expect(ids(page('referrer-policy: unsafe-url\n', '<meta name="referrer" content="no-referrer">'), 'H-09')).toEqual(['H-09.1']);
    expect(ids(page('', '<meta name="referrer" content="unsafe-url"><meta name="referrer" content="strict-origin">'), 'H-09')).toEqual(['H-09.1']);
  });
  it('<script>・<textarea>・<template>・<noscript> の中の meta は使わない', () => {
    for (const m of [`<script>var t='<meta name="referrer" content="unsafe-url">'</script>`, '<textarea><meta name="referrer" content="unsafe-url"></textarea>', '<template><meta name="referrer" content="unsafe-url"></template>', '<noscript><meta name="referrer" content="unsafe-url"></noscript>'])
      expect(ids(page('referrer-policy: no-referrer\n', m), 'H-09'), m).toEqual(['H-09.ok']);
  });
  it('ヘッダがなくても meta の strict-origin-when-cross-origin は合格', () => {
    expect(ids(page('', '<meta name="referrer" content="strict-origin-when-cross-origin">'), 'H-09')).toEqual(['H-09.ok']);
  });
});

describe('束5 CORS', () => {
  it('R-07：Set-Cookie の公開は数えない（禁止された応答ヘッダ）', () => {
    expect(ids(`#TARGET url=https://a.example/api label=api\nHTTP/2 200\ncontent-type: application/json\naccess-control-expose-headers: Set-Cookie\n\n{}\n`, 'R-07')).toEqual(['R-07.ok']);
  });
  it('R-06：-i で ACAO がテスト値（R-01 の反射）なら、Vary がないのを指摘する', () => {
    const input = `#TARGET url=https://a.example/api label=cors-reflect\nHTTP/2 200\ncontent-type: application/json\naccess-control-allow-origin: https://evil.example\naccess-control-allow-credentials: true\n\n{}\n`;
    expect(ids(input, 'R-01')).toEqual(['R-01.1']);
    expect(ids(input, 'R-06')).toEqual(['R-06.1']);
  });
  it('R-06：プリフライト（OPTIONS）の応答は対象外（HTTP のキャッシュに保存されない）', () => {
    expect(ids(`#TARGET url=https://a.example/api label=cors-preflight\nHTTP/2 204\naccess-control-allow-origin: https://evil.example\naccess-control-allow-methods: GET\n\n`, 'R-06')).toEqual([]);
  });
});

describe('束5 sensitive の値', () => {
  it('true・yes は機密、false・no は機密でない', () => {
    const r = parseInput('#TARGET url=https://a.example/ label=a sensitive=true\nHTTP/2 200\n\n#TARGET url=https://a.example/b label=b sensitive=No\nHTTP/2 200\n\n');
    expect(r.targets.map(t => t.sensitive)).toEqual([true, false]);
    expect(r.warnings.map(w => w.kind)).not.toContain('invalid-attr');
  });
  it('読めない値は警告する', () => {
    const r = parseInput('#TARGET url=https://a.example/ label=a sensitive=maybe\nHTTP/2 200\n\n');
    expect(r.targets[0].sensitive).toBeUndefined();
    expect(r.warnings.map(w => w.kind)).toContain('invalid-attr');
  });
});

describe('束5 H-02③ の apex を http で採取したとき', () => {
  it('「HSTSを返さない」とは言わず na', () => {
    const r = ids(`#TARGET url=https://www.a.example/ label=top\nHTTP/2 200\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\n\n#TARGET url=http://a.example/ label=apex\nHTTP/1.1 200 OK\ncontent-type: text/html\n\n`, 'H-02', 'apex');
    expect(r).toEqual(['H-02.na']);
  });
  it('http で採取して https の apex に転送したものは、その https のホップで見る', () => {
    const r = ids(`#TARGET url=https://www.a.example/ label=top\nHTTP/2 200\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\n\n#TARGET url=http://a.example/ label=apex\nHTTP/1.1 301 Moved Permanently\nlocation: https://a.example/\n\nHTTP/2 301\nlocation: https://www.a.example/\n\nHTTP/2 200\ncontent-type: text/html\n\n`, 'H-02', 'apex');
    expect(r).toEqual(['H-02.3']);
  });
});

describe('束5 hostSameSiteMap は同じサイトの応答だけを見る', () => {
  it('-L で転送した先の IdP の SameSite=None の Cookie で、対象のホストを決めない', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/ label=top\nHTTP/2 302\nlocation: https://login.idp.example/auth\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz012345; Path=/; Secure; HttpOnly; SameSite=Lax\n\nHTTP/2 200\nset-cookie: idpsession=abcdefghijklmnopqrstuvwxyz012345; Path=/; Secure; HttpOnly; SameSite=None\n\n');
    expect(hostSameSiteMap(targets).get('a.example')).toBe(true);
  });
});

describe('束5 A-07 の見逃していた秘密のキー', () => {
  const a07 = (k: string) => evaluate(`#TARGET url=https://a.example/api/me label=api\nHTTP/2 200\ncontent-type: application/json\n\n{"${k}":"abc123def456"}\n`)
    .findings.filter(f => f.item === 'A-07').map(f => f.ruleId);
  it('①にするもの', () => {
    for (const k of ['password1', 'new_password2', 'user_pass', 'secret_key_base', 'secret_token', 'master_key', 'serviceRoleKey', 'service_role_key', 'db_pwd', 'remember_token'])
      expect(a07(k), k).toContain('A-07.1');
  });
  it('password_salt は②、app_key（Pusher の公開キー）は①にしない', () => {
    expect(a07('password_salt')).toEqual(['A-07.2']);
    for (const k of ['app_key', 'pwd', 'PWD', 'service_role']) expect(a07(k), k).not.toContain('A-07.1');
  });
});

describe('束6 マスクの残り', () => {
  it('全角・ゼロ幅の文字を含むパラメータ名の値を伏せる', () => {
    for (const u of ['https://x.example/?ｐａｓｓｗｏｒｄ=hunter22', `https://x.example/?pass${'​'}word=hunter22`, `https://x.example/?pass${'­'}word=hunter22`])
      expect(showText(u), u).not.toContain('hunter22');
  });
  it('パスワードの名前では、Cookie の属性の語も伏せる（ほかの名前の secret: none、XSRF-TOKEN: Secure は残す）', () => {
    expect(showText('password: secure')).not.toMatch(/password: secure/);
    expect(showText('pwd=strict')).not.toMatch(/pwd=strict/);
    expect(showText('password: true')).toBe('password: true');
    expect(showText('secret: none')).toBe('secret: none');
  });
  it('社会保障番号とカード番号の形は、名前によらず伏せる', () => {
    for (const s of ['https://x.example/?q=123-45-6789', 'https://x.example/?q=4111 1111 1111 1111', 'card 0738-9781-0828-3555 x', 'id=4111111111111111'])
      expect(showText(s), s).not.toMatch(/6789|1111 1111|3555|4111111111111111/);
    expect(showText('https://x.example/?ssn=12345')).not.toContain('12345');
  });
  it('Luhn に通らない番号・ミリ秒の時刻・日付は残す', () => {
    expect(maskText('t=1700000000000')).toBe('t=1700000000000');   // 値の形で伏せる段（showText の許可リストは長い数字を別に短くする）
    expect(maskText('n=4111 1111 1111 1112')).toBe('n=4111 1111 1111 1112');
    expect(showText('2026-11-17')).toBe('2026-11-17');
  });
  it('showText は、もう一度かけても変わらない', () => {
    for (const s of ['zxqvbnmt//%2B@', 'https://u:p@x.example/?code=abc&state=xyzxyzxyzxyzxyzxyz', 'a 123-45-6789 b'])
      expect(showText(showText(s)), s).toBe(showText(s));
  });
});

describe('束6 security.txt のプローブ', () => {
  const probe = (head: string) => evaluate(`#TARGET url=https://a.example/ label=probes\n#PROBE path=/.well-known/security.txt head=${Buffer.from(head).toString('base64')} code=200 size=100 ct=text/plain\n`)
    .findings.filter(f => f.item === 'E-04').map(f => f.ruleId);
  it('先頭がコメントだけなら na（Contact・Expires があるかは分からない）', () => {
    expect(probe('# This file is served for every path\n# nothing here\n')).toEqual(['E-04.na']);
  });
  it('Contact・Expires があれば合格', () => {
    expect(probe('Contact: mailto:security@a.example\nExpires: 2027-01-01T00:00:00Z\n')).toEqual(['E-04.ok']);
  });
});

describe('束6 差分の突き合わせ', () => {
  const f = (evidence: string): Finding => ({ ruleId: 'A-01.2', item: 'A-01', title: '', severity: 'low', status: 'fail', target: 'unauth-api', evidence, recommendation: '', references: [], score: 0 });
  it('同じサイトの別のサーバに変わっただけなら「継続」', () => {
    const rows = diff([f('HTTP 302 → https://web-03.example.com/login')], [f('HTTP 302 → https://web-07.example.com/login')]);
    expect(rows.map(r => r.kind)).not.toContain('new');
    expect(rows.map(r => r.kind)).not.toContain('resolved');
  });
  it('別のサイトの配信元は別の指摘（cdn-a を直して cdn-b が増えた）', () => {
    const rows = diff([f('https://cdn-a.example/x.js')], [f('https://cdn-b.example/x.js')]);
    expect(rows.map(r => r.kind).sort()).toEqual(['new', 'resolved']);
  });
});
