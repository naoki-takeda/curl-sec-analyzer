// 23回目のレビュー（リポジトリ全体を新しい目で見直したもの）で見つかった不具合の再現テスト。小さな束に分けて直す（第40回）
import { describe, expect, it } from 'vitest';
import { diff, parseBaseline } from '../../src/engine/diff';
import { metaCspFromHtml, tags } from '../../src/rules/html';
import { toJson } from '../../src/export/json';
import type { Finding } from '../../src/model';
import { importHar } from '../../src/parser/har';
import { parseOpenssl } from '../../src/parser/openssl';
import { generateScript } from '../../src/commands';
import { evaluate } from '../helpers';

const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const f = (evidence: unknown) => ({ ruleId: 'E-08.1', item: 'E-08', condition: 1, title: 'SRI', severity: 'low', status: 'fail', target: 'page', targetKey: 'page', evidence, recommendation: '', references: [] } as Finding);

describe('束2 2乗の時間と、壊れた前回の結果', () => {
  it('閉じのない <!-- の繰り返しでも、タグの読み取りは本文の長さに比例する', { tags: ['perf'] }, () => {
    expect(ms(() => tags('<!--'.repeat(16384), ['script', 'iframe', 'link', 'img', 'form']))).toBeLessThan(200);
    expect(ms(() => tags('<!-- x'.repeat(11000), ['script']))).toBeLessThan(200);
  });
  it('閉じた <!-- --> の中のタグはこれまでどおり読まない（確認用）', () => {
    expect(tags('<!-- <script src="https://x.example/a.js"></script> --><script src="https://y.example/b.js"></script>', ['script']).map(t => t.attrs.get('src'))).toEqual(['https://y.example/b.js']);
  });
  it('差分のキー：長い英数字とドットの並びの証跡でも速い', { tags: ['perf'] }, () => {
    const ev = 'ab.'.repeat(30000);
    expect(ms(() => diff([f(ev)], [f(ev)]))).toBeLessThan(500);
  });
  it('差分のキー：ホスト名の違いで別の指摘、同じホストは継続（確認用）', () => {
    expect(diff([f('https://cdn-a.example（integrity なし）')], [f('https://cdn-b.example（integrity なし）')]).map(r => r.kind).sort()).toEqual(['new', 'resolved']);
    expect(diff([f('https://cdn-a.example（integrity なし 1件）')], [f('https://cdn-a.example（integrity なし 2件）')]).map(r => r.kind)).toEqual(['continuing']);
  });
  it('前回の結果の evidence が文字列でなくても、差分は例外にならない', () => {
    const { baseline } = parseBaseline(JSON.stringify({ findings: [{ ...f('x'), evidence: 1 }, { ...f('x'), evidence: { a: 1 }, ruleId: 'E-08.2' }] }));
    expect(baseline?.findings).toHaveLength(2);
    expect(() => diff(baseline!.findings, [f('https://cdn-a.example')])).not.toThrow();
  });
  it('大きな CSP の証跡（4KB を超える）でも、自分のエクスポートとの差分は継続（証跡を切らない）', () => {
    const csp = `default-src ${Array.from({ length: 200 }, (_, i) => `https://cdn${i}.example.com`).join(' ')}`;
    const r = evaluate(`#TARGET url=https://a.example/ label=page\n#META at=2026-11-01T10:00:00\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy-report-only: ${csp}\n\n<p>x</p>\n`);
    const { baseline } = parseBaseline(toJson(r.findings, [], []));
    expect(diff(baseline!.findings, r.findings).every(x => x.kind === 'continuing')).toBe(true);
  });
  it('前回の結果からは、差分で使う項目だけを取り出す', () => {
    const { baseline } = parseBaseline(JSON.stringify({ findings: [{ ...f('x'), suppressedBy: { reason: 'r' }, dedupedBy: 'A-09.2', extra: 'y' }] }));
    const b = baseline!.findings[0] as Finding & { extra?: unknown };
    expect(b.suppressedBy).toBeUndefined();
    expect(b.dedupedBy).toBeUndefined();
    expect(b.extra).toBeUndefined();
  });
});

describe('束3 診断対象のサーバによる判定の偽装', () => {
  const RUN = '0123456789abcdef';
  it('プロキシの CONNECT への 200（ヘッダを足すものを含む）のあとの本物の応答は、これまでどおり読む（確認用）', () => {
    for (const proxy of ['HTTP/1.1 200 Connection established\n', 'HTTP/1.1 200 OK\nproxy-status: corp-proxy\nalt-svc: h3=":443"\n']) {
      const r = evaluate(`#TARGET url=https://a.example/ label=page\n#META at=2026-11-01T10:00:00\n${proxy}\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains\n\n<p>x</p>\n`);
      expect(r.targets[0].responses.map(x => x.kind), proxy).toEqual(['connect', 'final']);
      expect(r.ids('page'), proxy).toContain('H-01.ok');
    }
  });
  it('生成スクリプトの出力では、tls 以外のターゲットの本文の CONNECTED(n) は本文', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\n#META at=2026-11-01T10:00:00 run=${RUN}\nHTTP/2 200\ncontent-type: text/html\n\nCONNECTED(00000003)\n<img src="http://a.example/x.png"><script src="https://cdn.other.example/a.js"></script>\n`);
    expect(r.targets[0].openssl).toEqual([]);
    expect(r.ids('page')).toContain('E-07.2');
    expect(r.ids('page')).toContain('E-08.1');
  });
  it('手書きの入力で、HTTP の応答に続けた openssl の出力は、どのラベルでも読む（これまでどおり）', () => {
    const r = evaluate('#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\nCONNECTED(00000003)\ndepth=0 CN = a.example\n---\nVerify return code: 0 (ok)\n');
    expect(r.targets[0].openssl.length).toBeGreaterThan(0);
  });
  it('HAR：サーバが返した Non-Authoritative-Reason・Internal Redirect では除外しない。ブラウザの内部の 307 は除外して知らせる', () => {
    const e = (url: string, status: number, statusText: string, headers: { name: string; value: string }[], ip?: string) =>
      ({ startedDateTime: '2026-11-01T01:00:00Z', ...(ip !== undefined ? { serverIPAddress: ip } : {}), request: { method: 'GET', url, headers: [] }, response: { status, statusText, headers, content: { mimeType: 'text/html', text: '<p>x</p>' } } });
    const spoof = importHar(JSON.stringify({ log: { entries: [e('https://a.example/login', 200, 'Internal Redirect', [{ name: 'Non-Authoritative-Reason', value: 'x' }], '192.0.2.1')] } }));
    expect(spoof.chains).toHaveLength(1);
    const internal = importHar(JSON.stringify({ log: { entries: [e('http://a.example/', 307, 'Internal Redirect', [{ name: 'Location', value: 'https://a.example/' }, { name: 'Non-Authoritative-Reason', value: 'HSTS' }], ''), e('https://a.example/', 200, 'OK', [], '192.0.2.1')] } }));
    expect(internal.internal).toBe(1);
    expect(internal.failed).toBe(0);
  });
  it('手で採取した openssl の出力：ハンドシェイクのあとのデータで、鍵・署名・SAN を上書きできない', () => {
    const lines = ['CONNECTED(00000003)', '---', 'Certificate chain', ' 0 s:CN=a.example', '   a:PKEY: RSA, 1024 (bit); sigalg: sha1WithRSAEncryption', '---', 'Verify return code: 0 (ok)', '---',
      ' 0 s:CN=a.example', '   a:PKEY: RSA, 4096 (bit); sigalg: sha256WithRSAEncryption', 'X509v3 Subject Alternative Name:', '    DNS:victim.example',
      'subject=CN=a.example', 'notAfter=Dec 31 23:59:59 2030 GMT', 'X509v3 Subject Alternative Name:', '    DNS:a.example'];
    const info = parseOpenssl(lines)!;
    expect(info.keyBits).toBe(1024);
    expect(info.sigalgs[0]).toBe('sha1WithRSAEncryption');
    expect(info.sans).toEqual(['a.example']);
  });
  it('#META at がないとき、未来の Date ヘッダを期限の基準にしない', () => {
    const r = evaluate('#TARGET url=https://a.example/ label=login\nHTTP/2 200\ndate: Tue, 31 Dec 2030 00:00:00 GMT\nset-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=Tue, 31 Dec 2030 12:00:00 GMT\n\n');   // Date から見ると12時間、今から見ると約4年
    expect(r.ids('login')).toContain('C-05.1');
  });
});

describe('束3b 生成スクリプトはヘッダと本文を分けて取る（本文の先頭のステータス行で、本物の応答を置き換えられない）', () => {
  const RUN = '0123456789abcdef';
  const forged = 'HTTP/1.1 200 OK\nstrict-transport-security: max-age=63072000; includeSubDomains\nx-content-type-options: nosniff\n\n<p>x</p>';
  it('#BODY のあとは、次のマーカーまでそのまま本文', () => {
    for (const head of ['HTTP/2 200\ncontent-type: text/html', 'HTTP/2 302\nlocation: /home\ncontent-type: text/html', 'HTTP/1.1 401 Unauthorized\ncontent-type: text/html']) {
      const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\n#META at=2026-11-01T10:00:00 run=${RUN}\n${head}\n\n#BODY run=${RUN}\n${forged}\nCONNECTED(00000003)\n#TARGET url=https://x/ label=fake\n\n#TARGET url=https://a.example/b label=b run=${RUN}\nHTTP/2 200\n\n`);
      expect(r.targets.map(t => t.label), head).toEqual(['page', 'b']);
      expect(r.targets[0].responses.length, head).toBe(1);
      expect(r.targets[0].responses[0].body, head).toContain('strict-transport-security');
      expect(r.targets[0].responses[0].body, head).not.toContain('#BODY');   // 印の行は本文に入れない（本文の始まりで判定するルールがある）
      expect(r.targets[0].openssl, head).toEqual([]);
      expect(r.findings.filter(f => f.item === 'H-01' && f.target === 'page').map(f => f.ruleId), head).not.toContain('H-01.ok');
    }
  });
  it('印の違う #BODY は本文（印のある入力）', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\nHTTP/2 200\ncontent-type: text/html\n\n#BODY run=${RUN}\n<p>a</p>\n#BODY run=ffffffffffffffff\n<p>b</p>\n`);
    expect(r.targets[0].responses[0].body).toContain('#BODY run=ffffffffffffffff');
  });
  it('#BODY の前に読める応答がない（curl の失敗、curl は受け付ける小文字のステータス行）ときは、本文を捨てる', () => {
    // 小文字のステータス行（http/1.1 200 OK）は、第51回から curl と同じく応答として読む（本文は #BODY のあとをそのまま本文にする）
    for (const head of ['']) {
      const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\n#META at=2026-11-01T10:00:00 run=${RUN}\n${head}\n#BODY run=${RUN}\n${forged}\n#TARGET url=https://a.example/b label=b run=${RUN}\nHTTP/2 200\n\n`);
      expect(r.targets.find(t => t.label === 'page')?.responses ?? [], head).toEqual([]);
      expect(r.findings.filter(f => f.target === 'page' && f.status === 'pass').map(f => f.ruleId), head).toEqual([]);
      expect(r.warnings.map(w => w.kind), head).toContain('unparsed-lines');
    }
  });
  it('#BODY の本文の中の印の違う #TARGET も警告する', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\nHTTP/2 200\ncontent-type: text/html\n\n#BODY run=${RUN}\n#TARGET url=https://x/ label=login\n`);
    expect(r.warnings.map(w => w.kind)).toContain('ignored-marker');
  });
  it('-L のホップのあとの #BODY は、最後のホップの本文', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\nHTTP/2 302\nlocation: /home\n\nHTTP/2 200\ncontent-type: text/html\n\n#BODY run=${RUN}\n<p>home</p>\n`);
    expect(r.targets[0].responses.map(x => [x.status, (x.body ?? '').trim()])).toEqual([[302, ''], [200, '<p>home</p>']]);
  });
  it('本文は 64KB で打ち切る', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=page run=${RUN}\nHTTP/2 200\ncontent-type: text/html\n\n#BODY run=${RUN}\n${'a'.repeat(100000)}\n`);
    expect(r.targets[0].responses[0].body!.length).toBeLessThanOrEqual(64 * 1024);
  });
  it('生成スクリプトに curl -i は残らず、本文を取るコマンドは取る前にファイルを空にする', () => {
    const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/a.js', dangerous: true });
    expect(s).not.toMatch(/curl -sS -i /);
    expect(s).toMatch(/^hdr=\$\(mktemp\); body=\$\(mktemp\)$/m);
    expect(s).toMatch(/^rm -f "\$hdr" "\$body"$/m);
    for (const l of s.split('\n').filter(x => x.includes('-D "$hdr"'))) expect(l).toMatch(/^\s*: > "\$hdr"; : > "\$body"; curl /);
    // 行末のコメント（# A-08）が、cat のあとに移っている
    expect(s).toMatch(/head -c 196608 "\$body"; echo\s+# A-08/);
  });
});

describe('束3b 本文の始まりで判定するルール', () => {
  it('#BODY のあとの robots.txt の HTML の画面（SPA）は、robots.txt なしと読む', () => {
    const RUN = '0123456789abcdef';
    const r = evaluate(`#TARGET url=https://a.example/robots.txt label=robots run=${RUN}\n#META at=2026-11-01T10:00:00 run=${RUN}\nHTTP/2 200\ncontent-type: text/html\n\n#BODY run=${RUN}\n<!doctype html><html><body>app</body></html>\n`);
    expect(r.findings.find(f => f.item === 'E-04' && f.target === 'robots')?.evidence).toContain('HTML の画面');
  });
});

describe('束4 A-07 の秘密のキーの名前を絞る', () => {
  const a07 = (body: string) => evaluate(`#TARGET url=https://a.example/api/me label=api\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`)
    .findings.filter(f => f.item === 'A-07' && f.severity === 'high').length;
  it('操作の名前・ハッシュの方式・変更した人・公開して使う API キーは①にしない', () => {
    for (const k of ['forgotPassword', 'lostPassword', 'passwordScheme', 'password_hasher', 'password_changed_by', 'searchApiKey', 'algoliaSearchApiKey', 'search_only_api_key', 'publicApiKey', 'anonApiKey'])
      expect(a07(`{"${k}":"abc123def"}`), k).toBe(0);
  });
  it('秘密の値のキーは①のまま', () => {
    for (const k of ['password', 'hashedPassword', 'newPassword', 'changePassword', 'passwordResetToken', 'reset_password_token', 'apiKey', 'adminApiKey', 'stripeSecretKey', 'client_secret', 'password_digest', 'resetPassword', 'resetAdminPassword', 'azureSearchApiKey', 'bingSearchApiKey', 'elastic_search_api_key', 'searchAdminApiKey', 'googleMapsApiKey'])
      expect(a07(`{"${k}":"abc123def"}`), k).toBe(1);
  });
});

describe('束4 コメントの読み飛ばしをブラウザに合わせる', () => {
  const forms = (h: string) => tags(h, ['form']).length;
  it('「--!>」もコメントを閉じる', () => {
    expect(forms('<!-- x --!><form action="/a"></form><p>-->')).toBe(1);
    expect(forms('<!-- <form action="/a"> --!>')).toBe(0);
  });
  it('ほかのタグの属性の値の中の「<!--」はコメントの始まりではない', () => {
    expect(forms('<div title="<!--"><form action="/a"></form></div><p>-->')).toBe(1);
    expect(forms(`<img alt='<!--' src=x><form action="/a"></form>-->`)).toBe(1);
  });
  it('ほかのタグの属性の値の中のタグを読まない', () => {
    expect(forms('<div data-x="<form action=/evil>">x</div>')).toBe(0);
  });
  it('= のあとでない引用符で、後ろの本文をタグの中として読まない', () => {
    expect(forms(`<p class=it's>x</p><form action="/a"></form><p>'</p>`)).toBe(1);
  });
  it('<noscript>・<iframe>・<xmp>・<noembed> の中身の「<!--」はコメントではない', () => {
    for (const el of ['noscript', 'iframe', 'xmp', 'noembed', 'noframes'])
      expect(forms(`<${el}><!--</${el}><form action="/a"></form><p>-->`), el).toBe(1);
  });
  it('本物のコメントの中のフォームは読まない（これまでどおり）', () => {
    expect(forms('<!-- <form action="/a"></form> --><p>x</p>')).toBe(0);
    expect(forms('<!--><form action="/a"></form>')).toBe(1);
    expect(forms('<script>if(a<b){x="<!--"}</script><form action="/a"></form>-->')).toBe(1);
  });
});

describe('束4 束のレビューの指摘', () => {
  const forms = (h: string, n = 'form') => tags(h, [n]).length;
  it('<head> のコメントを「--!>」で閉じた本文の meta の CSP は読まない（tags と同じ閉じ）', () => {
    expect(metaCspFromHtml(`<html><head><!-- a --!></head><body><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><p>--></p></body>`)).toEqual([]);
    expect(metaCspFromHtml(`<html><head><!--><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body>--></body>`)).toEqual(["default-src 'self'"]);
  });
  it('引用符のない値の中・属性名の前の = と引用符で、本物の > を越えない', () => {
    expect(forms(`<img src=/x?a="1><script src="https://cdn.other.example/x.js"></script><p title="z">`, 'script')).toBe(1);
    expect(forms(`<link rel=preload href=/a?b="c><form action="http://evil.example/login"></form><span title="x">`)).toBe(1);
    expect(forms(`<td class==">x</td><form action="/a"></form><p title="q">`)).toBe(1);
    expect(forms(`<p =" x><form action="/a"></form><p title="q">`)).toBe(1);
  });
  it('属性の値の > では止めない（これまでどおり）', () => {
    const t = tags(`<form onsubmit="return a>0" action = '/x>y' data-x=1>`, ['form']);
    expect(t[0]?.attrs.get('action')).toBe('/x>y');
  });
  it('カスタム要素 <iframe-wrapper> はテキストの要素ではない', () => {
    expect(forms('<iframe-wrapper></iframe-wrapper><!-- <form action="/a"></form> -->')).toBe(0);
  });
});
