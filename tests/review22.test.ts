// 22回目のレビュー（リポジトリ全体を新しい目で見直したもの。直近2コミットの退行を含む）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { generateScript } from '../src/commands';
import { allowText, showText } from '../src/shownText';
import { diff } from '../src/engine/diff';
import { parseProfile } from '../src/engine/profile';
import { runAll } from '../src/engine/run';
import type { Finding } from '../src/model';
import { evaluate } from './helpers';

const AT = '#META at=2026-11-01T10:00:00';
const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const script = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/a.js', dangerous: false });

describe('1・2 TLS の採取は、診断対象のサーバがハンドシェイクのあとに送るデータで結果を変えられない', () => {
  it('プローブのエラーは標準エラーだけで見て、結果はハンドシェイクの要約（最初の Verify return code: まで）だけで見る', () => {
    expect(script).toMatch(/>"\$tout" 2>"\$terr"; rc=\$\?/);
    expect(script).toMatch(/grep -qiE 'unknown option\|no protocols available' "\$terr"/);
    expect(script).not.toMatch(/printf '%s' "\$out" \| grep/);
    // 版は問わない（OpenSSL 1.1 以降は、AES128-SHA の TLS 1.0 の接続も「New, SSLv3, Cipher is AES128-SHA」と出す）。失敗の (NONE) だけを除く
    expect(script).toContain(`sed '/^ *Verify return code:/q' "$tout" | grep -qE '^New, [^(,][^,]*, Cipher is [^(]'`);
    expect(script).not.toContain('New, TLS[');
  });
  it('証明書の採取（C11）も、要約の終わりで切る', () => {
    expect(script).toMatch(/-showcerts <\/dev\/null 2>&1 \| sed '\/\^ \*Verify return code:\/q'/);
  });
  it('T-10：ok=err の暗号は「拒否」に数えず、試していないと書く（OpenSSL 1.1 以降は RC4・3DES を試せないので、na にはしない）', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=tls\n${AT}\n#CIPHERPROBE c=DES-CBC3-SHA ok=err\n#CIPHERPROBE c=RC4-SHA ok=0\n#TLSPROBE v=tls1_2 ok=1\n`);
    const t10 = r.findings.filter(f => f.item === 'T-10');
    expect(t10.map(f => f.ruleId)).toEqual(['T-10.ok']);
    expect(t10[0].evidence).toContain('弱い暗号1種は拒否');
    expect(t10[0].evidence).toContain('DES-CBC3-SHA は手元のOpenSSLが非対応で試していない');
  });
});

describe('3・4 入力の長さの2乗の時間にならない', () => {
  it('ホスト名らしい長い並びのあとの @（Location・CSP の値）', () => {
    expect(ms(() => allowText(`https://${'a'.repeat(64000)}@x`))).toBeLessThan(500);
    expect(ms(() => showText(`Location: https://${'a.'.repeat(32000)}:@evil/`))).toBeLessThan(1000);
    expect(ms(() => allowText(`https://${'a@'.repeat(32000)}`))).toBeLessThan(500);
  });
  it('印のある入力の本文の1行に「#META 」が続く', () => {
    const s = `#TARGET url=https://a.example/ label=p run=0123456789abcdef\nHTTP/2 200\n\n${'#META '.repeat(40000)}\n`;
    expect(ms(() => parseInput(s))).toBeLessThan(1000);
  });
});

describe('5 印は入力の最初の #TARGET からだけ取る', () => {
  it('手書きの入力で、本文の「#TARGET … run=…」が利用者のターゲットを消さない', () => {
    const r = parseInput(`#TARGET url=https://a.example/ label=page\nHTTP/2 200\n\n#TARGET url=https://a.example/login label=fake run=0123456789abcdef\nHTTP/2 200\n\n#TARGET url=https://a.example/x label=other\nHTTP/2 200\n\n`);
    expect(r.targets.map(t => t.label)).toContain('page');
    expect(r.targets.map(t => t.label)).toContain('other');
  });
  it('生成スクリプトの出力に付け足した印のないターゲットは、本文として読み、警告する', () => {
    const r = parseInput('#TARGET url=https://a.example/ label=page run=0123456789abcdef\nHTTP/2 200\n\n<p>x</p>{"a":1}#TARGET url=https://a.example/b label=b run=0123456789abcdef\nHTTP/2 200\n\n#TARGET url=https://a.example/c label=handwritten\nHTTP/2 200\n\n');
    expect(r.targets.map(t => t.label)).toEqual(['page', 'b']);
    expect(r.warnings.map(w => w.kind)).toContain('ignored-marker');
  });
  it('プロキシの応答（407）だけのターゲットは警告する。WebSocket の 101 だけでは警告しない', () => {
    expect(parseInput(`#TARGET url=https://a.example/ label=unauth-api\nHTTP/1.1 407 Proxy Authentication Required\n\n`).warnings.map(w => w.kind)).toContain('proxy-only');
    expect(parseInput(`#TARGET url=https://a.example/ws label=websocket\nHTTP/1.1 101 Switching Protocols\nupgrade: websocket\n\n`).warnings.map(w => w.kind)).not.toContain('proxy-only');
  });
});

describe('6〜8 本文の判定', () => {
  const page = (body: string, extra = '') => evaluate(`#TARGET url=https://a.example/ label=page ${extra}\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n${body}\n`);
  it('6 E-09 の開発用コメントの証跡に、パスワードを出さない', () => {
    const ev = page('<html><!-- admin login: pass Summer2024 --></html>').findings.filter(f => f.item === 'E-09').map(f => f.evidence).join(' ');
    expect(ev).toContain('「pass」');
    expect(ev).not.toContain('Summer2024');
  });
  it('7 組織プロファイルで E-09 を対象外にしても、HTML の AWS のキーは E-01① で指摘する', () => {
    const { profile } = parseProfile('{"exclude":["E-09"]}');
    const t = parseInput(`#TARGET url=https://a.example/ label=page\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<script>var k="AKIAIOSFODNN7EXAMPLE";</script>\n`).targets;
    expect(runAll(t, { profile }).filter(f => f.item === 'E-01').map(f => f.ruleId)).toContain('E-01.1');
  });
  it('8 <script> の中の「<!--」・閉じのない「<!--」・空のコメント「<!-->」で、後ろのタグを見逃さない', () => {
    for (const pre of ["<script>var s='<!--';</script>", '<title>a <!-- b</title>', '<!-->', '<textarea><!--</textarea>'])
      expect(page(`<html>${pre}<script src="https://cdn.other.example/x.js"></script></html>`).ids('page'), pre).toContain('E-08.1');
  });
  it('8 コメントの中のタグは判定しない', () => {
    const ids = page('<html><!--<form action="http://old/login"><input name=u><input type=password name=p></form><script src="http://cdn.old/a.js"></script>--><p>x</p></html>').ids('page');
    expect(ids).not.toContain('E-10.1');
    expect(ids).not.toContain('E-07.1');
  });
});

describe('9〜12 API・転送', () => {
  const api = (label: string, head: string, body = '') => evaluate(`#TARGET url=https://a.example/api/me label=${label}\n${AT}\n${head}\n\n${body}\n`).ids(label);
  it('9 A-07①：Rails の password_digest、キャメルケースの名前', () => {
    for (const k of ['password_digest', 'hashedPassword', 'dbPassword', 'stripeSecretKey', 'awsSecretAccessKey'])
      expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', `{"user":{"id":1,"${k}":"$2b$10$abcdefghijklmnop"}}`), k).toContain('A-07.1');
    expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', '{"user":{"id":1,"password_updated_at":"2026-01-01T00:00:00Z"}}')).not.toContain('A-07.1');
    // 設定・パス・画面の部品の名前（値は秘密ではない）
    for (const kv of ['"passwordPattern":"^[A-Za-z0-9]{8,}$"', '"changePasswordUri":"/account/password"', '"passwordEncoder":"bcrypt"', '"passwordComplexity":"high"', '"forgotPasswordPath":"/forgot"', '"password_regex":"[a-z]+"'])
      expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', `{"config":{"id":1,${kv}}}`), kv).not.toContain('A-07.1');
  });
  it('10 E-05：Spring Boot のヘルスのグループは既定の応答', () => {
    const ids = evaluate(`#TARGET url=https://a.example/actuator/health/liveness label=t\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n{"status":"UP"}\n`).ids('t');
    expect(ids).not.toContain('E-05.1');
  });
  it('11 A-01：本文のない 2xx と、状態の番号だけのエラーは①（高）にしない', () => {
    expect(api('unauth-api', 'HTTP/2 204')).not.toContain('A-01.1');
    expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json')).not.toContain('A-01.1');
    expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', '{"status":401,"message":"Unauthorized"}')).not.toContain('A-01.1');
    expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', '{"status":"fail","msg":"not logged in"}')).not.toContain('A-01.1');
    expect(api('unauth-api', 'HTTP/2 200\ncontent-type: application/json', '{"id":1,"email":"a@example.com"}')).toContain('A-01.1');
  });
  it('12 T-06：テスト値を持ったまま同じ入口へ転送したものは、試した転送としない', () => {
    const t06 = (loc: string) => evaluate(`#TARGET url=https://example.com/redirect?url=https://evil.example label=open-redirect\n${AT}\nHTTP/2 302\nlocation: ${loc}\n\n`).ids('open-redirect').filter(x => x.startsWith('T-06'));
    expect(t06('https://www.example.com/redirect?url=https://evil.example')).toEqual(['T-06.na']);
    expect(t06('/en/redirect?url=https%3A%2F%2Fevil.example')).toEqual(['T-06.na']);
    expect(t06('/home?blocked=https%3A%2F%2Fevil.example')).toEqual(['T-06.ok']);
  });
});

describe('13 差分は、同じルール・ターゲットの別のものの指摘を別に突き合わせる', () => {
  const f = (evidence: string) => ({ ruleId: 'E-08.1', item: 'E-08', condition: 1, title: 'SRI', severity: 'low', status: 'fail', target: 'page', targetKey: 'page', evidence, recommendation: '', references: [], score: 0 } as Finding);
  it('cdn-a を直して cdn-b が増えた', () => {
    const rows = diff([f('https://cdn-a.example（integrity なし 1件／1件）')], [f('https://cdn-b.example（integrity なし 1件／1件）')]);
    expect(rows.map(r => r.kind).sort()).toEqual(['new', 'resolved']);
  });
  it('ホスト名の数字だけが違うもの（cdn1・cdn2）も別の指摘', () => {
    expect(diff([f('https://cdn1.example（integrity なし 1件／1件）')], [f('https://cdn2.example（integrity なし 1件／1件）')]).map(r => r.kind).sort()).toEqual(['new', 'resolved']);
  });
  it('マスクの形が変わっても、同じ指摘は継続（突き合わせのキーはマスクに依存しない）', () => {
    expect(diff([f('https://cdn-a.example（integrity なし）。例：<script src="https://cdn-a.example/CSRFTOKEN.js">')],
      [f('https://cdn-a.example（integrity なし）。例：<script src="https://cdn-a.example/…(9 chars).js">')]).map(r => r.kind)).toEqual(['continuing']);
  });
  it('件数・伏せた値だけが違うものは継続', () => {
    expect(diff([f('https://cdn-a.example（integrity なし 1件／2件）')], [f('https://cdn-a.example（integrity なし 2件／3件）')]).map(r => r.kind)).toEqual(['continuing']);
  });
});

describe('14 C-07②：同じ署名付きトークンを na にするのは、同じ秒の採取だけ', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJl';
  const c07 = (ats: string[], v = jwt) => evaluate(ats.map((at, i) => `#TARGET url=https://a.example/login label=session-sample-${i + 1}\n#META at=${at}\nHTTP/2 302\nset-cookie: session=${v}; Path=/; Secure; HttpOnly\n`).join('\n'))
    .findings.filter(f => f.item === 'C-07' && f.target === 'session-sample-*').map(f => f.ruleId);
  it('採取の時刻が60秒より離れていれば②', () => { expect(c07(['2026-11-01T10:10:00', '2026-11-01T10:25:00', '2026-11-01T10:40:00'])).toEqual(['C-07.2']); });
  it('近い時刻（秒をまたいだものを含む）なら na。Django の署名付きの形も同じ', () => {
    expect(c07(['2026-11-01T10:10:00', '2026-11-01T10:10:00'])).toEqual(['C-07.na']);
    expect(c07(['2026-11-01T10:00:00', '2026-11-01T10:00:01', '2026-11-01T10:00:01'])).toEqual(['C-07.na']);
    expect(c07(['2026-11-01T10:00:00', '2026-11-01T10:00:01'], 'eyJhbGciOiJIUzI1NiJ9:1tAbCd:AbCdEfGhIjKlMnOpQrStUvWxYz012')).toEqual(['C-07.na']);
  });
  it('a:b:c の固定の値は②', () => { expect(c07(['2026-11-01T10:10:00', '2026-11-01T10:10:00'], 'guest:1:admin')).toEqual(['C-07.2']); });
});

describe('15 許可リストと名前の伏せ方の抜け', () => {
  it('カード番号の形、パーセントエンコードした Base64、略したパスワードの名前', () => {
    expect(showText('card 0738-9781-0828-3555')).not.toContain('3555');
    expect(showText('2026-11-01')).toBe('2026-11-01');
    const b64 = 'Xk3Lm9Qa+Bc/De7Fg=';
    expect(showText(`?x=${encodeURIComponent(b64)}abcdEFGH12`)).not.toContain('abcdEFGH12');
    for (const q of ['?pswd=Summer2024', '?mdp=Summer2024', '?password+=Summer2024', '?pin_number=Summer2024'])
      expect(showText(`https://a.example/x${q}`), q).not.toContain('Summer2024');
  });
  it('状態の語は名前で伏せない', () => {
    for (const s of ['secret: none', 'XSRF-TOKEN: Secure', 'token: required']) expect(showText(s)).toBe(s);
  });
});

describe('16〜20 低の指摘', () => {
  it('16 T-07②：スキームのない //evil.example の反映', () => {
    const ids = evaluate(`#TARGET url=https://a.example/ label=host-inj\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<script src="//evil.example/app.js"></script>\n`).ids('host-inj');
    expect(ids).toContain('T-07.2');
  });
  it('17 A-08：ログイン画面への転送・5xx は合格にしない', () => {
    const a08 = (head: string) => evaluate(`#TARGET url=https://a.example/api/me label=ctype\n${AT}\n${head}\n\n`).ids('ctype').filter(x => x.startsWith('A-08'));
    expect(a08('HTTP/2 302\nlocation: /login')).toEqual(['A-08.na']);
    expect(a08('HTTP/2 500')).toEqual(['A-08.na']);
    expect(a08('HTTP/2 415')).toEqual(['A-08.ok']);
  });
  it('18 A-09②：本文のない API の応答は判定しない', () => {
    const ids = evaluate(`#TARGET url=https://a.example/api/me label=api kind=api\n${AT}\nHTTP/2 204\ncontent-type: application/json\n\n`).ids('api');
    expect(ids).not.toContain('A-09.2');
  });
  it('19 E-04：-L なしの robots.txt の転送は na', () => {
    const ids = evaluate(`#TARGET url=https://a.example/robots.txt label=robots\n${AT}\nHTTP/2 301\nlocation: https://www.a.example/robots.txt\n\n`).ids('robots');
    expect(ids.filter(x => x.startsWith('E-04'))).toEqual(['E-04.na']);
  });
  it('20 E-08：空の integrity は integrity なし', () => {
    const ids = evaluate(`#TARGET url=https://a.example/ label=page\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<script src="https://cdn.other.example/a.js" integrity=""></script>\n`).ids('page');
    expect(ids).toContain('E-08.1');
  });
});
