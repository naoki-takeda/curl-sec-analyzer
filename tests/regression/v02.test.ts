import { describe, expect, it } from 'vitest';
import { parseInput } from '../../src/parser/input';
import { finalResponse } from '../../src/parser/target';
import { nameMatches, parseOpenssl } from '../../src/parser/openssl';
import { generateScript, validate } from '../../src/commands';
import { toCsv } from '../../src/export/csv';
import { evaluate, fixture } from '../helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n`;
const page = (body: string, label = 'top', extra = '') => evaluate(t(label, 'https://www.example.com/', `HTTP/2 200\ncontent-type: text/html; charset=utf-8\n\n${body}`, extra)).ids(label);

describe('openssl の出力（T-10②・T-11）', () => {
  const info = parseOpenssl(parseInput(fixture('openssl_tls13.txt')).targets[0].openssl)!;
  it('プロトコル・暗号・検証結果・期限・SAN・鍵を読む', () => {
    expect(info.protocol).toBe('TLSv1.3');
    expect(info.cipher).toBe('TLS_AES_256_GCM_SHA384');
    expect(info.verifyCode).toBe(18);
    expect(info.sans).toEqual(['www.example.com', 'example.com']);
    expect(info.keyType).toBe('rsaEncryption');
    expect(info.keyBits).toBe(2048);
    expect(info.sigalgs).toEqual(['RSA-SHA256']);
    expect(info.notAfter?.toISOString()).toBe('2026-12-01T06:11:57.000Z');
  });
  it('自己署名の証明書は T-11①', () => {
    expect(evaluate(fixture('openssl_tls13.txt')).findings.some(f => f.ruleId === 'T-11.1' && /Verify return code: 18/.test(f.evidence))).toBe(true);
  });
  it('ワイルドカードの一致は1階層だけ', () => {
    expect(nameMatches('*.example.com', 'www.example.com')).toBe(true);
    expect(nameMatches('*.example.com', 'a.b.example.com')).toBe(false);
    expect(nameMatches('*.example.com', 'example.com')).toBe(false);
  });
  it('期限切れ・期限間近・ホスト名不一致・弱い暗号・短い鍵', () => {
    const tls = (lines: string, cipher = '') => evaluate(`#TARGET url=https://www.example.com/ label=tls\nsubject=CN = www.example.com\n${lines}\n${cipher}`).findings.filter(f => f.target === 'www.example.com').map(f => f.ruleId);
    expect(tls('notAfter=Jan  1 00:00:00 2020 GMT')).toContain('T-11.1');
    const soon = new Date(Date.now() + 10 * 86400e3).toUTCString().replace(/^\w+, (\d+) (\w+) (\d+) ([\d:]+) GMT$/, '$2 $1 $4 $3 GMT');
    expect(tls(`notAfter=${soon}`)).toContain('T-11.2');
    expect(tls('notAfter=Jan  1 00:00:00 2099 GMT\nX509v3 Subject Alternative Name: \n    DNS:other.example')).toContain('T-11.1');
    expect(tls('notAfter=Jan  1 00:00:00 2099 GMT', '#CIPHERPROBE c=DES-CBC3-SHA ok=1\n#CIPHERPROBE c=AES128-SHA ok=1')).toEqual(expect.arrayContaining(['T-10.1', 'T-10.3']));
    expect(tls('Certificate chain\n 0 s:CN = www.example.com\n   a:PKEY: rsaEncryption, 1024 (bit); sigalg: RSA-SHA1\nnotAfter=Jan  1 00:00:00 2099 GMT')).toContain('T-10.2');
  });
});

describe('C10（%{header_json}）', () => {
  it('ステータス行のないJSONを応答として読む', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/ label=top\n#META response_code=200\n{"content-type":["text/html"],\n"x-content-type-options":["nosniff"]}\n');
    const r = finalResponse(targets[0])!;
    expect(r.status).toBe(200);
    expect(r.headers.get('x-content-type-options')).toEqual(['nosniff']);
  });
});

describe('HTML本文（E-07〜E-10、E-12、H-07③）', () => {
  it('混在コンテンツ', () => {
    expect(page('<script src="http://cdn.example/a.js"></script>')).toEqual(expect.arrayContaining(['E-07.1']));
    expect(page('<img src="http://cdn.example/a.png">')).toContain('E-07.2');
    expect(page('<img src="https://cdn.example/a.png">')).toContain('E-07.ok');
  });
  it('SRI、秘密情報、generator', () => {
    expect(page('<script src="https://cdn.other.example/x.js"></script>')).toContain('E-08.1');
    expect(page('<script src="https://cdn.other.example/x.js" integrity="sha384-x" crossorigin="anonymous"></script>')).toContain('E-08.ok');
    expect(page('<script>var k="AKIAABCDEFGHIJKLMNOP"</script>')).toContain('E-09.1');
    expect(page('<a href="http://app01.internal/admin">x</a>')).toContain('E-09.2');
    expect(page('<!-- TODO: remove debug -->')).toContain('E-09.2');
    expect(page('<meta name="generator" content="WordPress 6.4.2">')).toContain('E-09.3');
  });
  it('秘密情報の値そのものは証跡に出さない', () => {
    const fs = evaluate(t('top', 'https://www.example.com/', 'HTTP/2 200\ncontent-type: text/html\n\n<script>var k="AKIAABCDEFGHIJKLMNOP"</script>')).findings;
    expect(JSON.stringify(fs)).not.toContain('AKIAABCDEFGHIJKLMNOP');
  });
  it('開発用コメント（E-09②）：中身は証跡に出さず、コメントの外の本文には一致しない', () => {
    const fs = evaluate(t('top', 'https://www.example.com/', 'HTTP/2 200\ncontent-type: text/html\n\n<!-- admin password: Hunter2-Prod! -->')).findings;
    expect(fs.find(f => f.ruleId === 'E-09.2')?.evidence).toContain('password');
    expect(JSON.stringify(fs)).not.toContain('Hunter2');
    // 前後のコメントの間にあるパスワード欄は、開発用コメントではない
    expect(page('<!-- header --><form method="post"><input type="hidden" name="csrf" value="x"><input type="password" name="password"></form><!-- footer -->')).not.toContain('E-09.2');
  });
  it('パスワードフォームとCSRFトークン', () => {
    expect(page('<form action="http://www.example.com/login" method="post"><input type="password" name="p"></form>')).toContain('E-10.1');
    expect(page('<form action="/login"><input type="password" name="p"></form>')).toContain('E-10.2');
    expect(page('<form method="post" action="/x"><input name="a"></form>', 'mypage', 'sensitive=1')).toContain('E-12.1');
    expect(page('<form method="post" action="/x"><input type="hidden" name="csrf_token" value="x"></form>', 'mypage', 'sensitive=1')).toContain('E-12.ok');
  });
  it('混在コンテンツがあるのに upgrade-insecure-requests がない（H-07③）', () => {
    const ids = evaluate(t('top', 'https://www.example.com/', `HTTP/2 200\ncontent-type: text/html\ncontent-security-policy: default-src 'self'\n\n<img src="http://x.example/a.png">`)).ids('top');
    expect(ids).toContain('H-07.3');
  });
});

describe('情報露出（E-01、E-02、E-04〜E-06、E-11、E-13）', () => {
  const at = (url: string, head: string, label = 'top', extra = '') => evaluate(t(label, url, head, extra)).ids(label);
  it('エラーの詳細', () => {
    expect(at('https://a.example/x', 'HTTP/1.1 500 Error\ncontent-type: text/html\n\njava.lang.NullPointerException\n\tat com.example.Foo.bar(Foo.java:42)', 'error-x')).toContain('E-01.2');
    expect(at('https://a.example/x', 'HTTP/1.1 500 Error\ncontent-type: text/html\n\n<h1>Whitelabel Error Page</h1>', 'error-x')).toContain('E-01.3');
    // 資格情報のない jdbc: は②、資格情報を含むものは①（積み残しの対応1、tests/regression/backlog1.test.ts）
    expect(at('https://a.example/x', 'HTTP/1.1 500 Error\ncontent-type: text/plain\n\njdbc:mysql://db:3306/app', 'error-x')).toContain('E-01.2');
    expect(at('https://a.example/x', 'HTTP/1.1 500 Error\ncontent-type: text/plain\n\njdbc:mysql://db:3306/app?user=app&password=Secr3t', 'error-x')).toContain('E-01.1');
  });
  it('ディレクトリの一覧、robots.txt、security.txt のプローブ', () => {
    expect(at('https://a.example/images/', 'HTTP/1.1 200 OK\ncontent-type: text/html\n\n<html><head><title>Index of /images</title>')).toContain('E-02.1');
    expect(at('https://a.example/robots.txt', 'HTTP/1.1 200 OK\ncontent-type: text/plain\n\nUser-agent: *\nDisallow: /admin-secret/')).toContain('E-04.1');
    expect(evaluate('#TARGET url=https://a.example/ label=probes\n#PROBE path=/.well-known/security.txt code=404 size=0 head= ct=text/html\n').ids('probes')).toContain('E-04.2');
  });
  it('actuator・API仕様・GraphQL・JSONP', () => {
    expect(at('https://a.example/actuator/env', 'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{}')).toContain('E-05.1');
    expect(at('https://a.example/v3/api-docs', 'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{}')).toContain('E-05.2');
    expect(at('https://a.example/graphql', 'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"data":{"__schema":{}}}')).toContain('E-05.3');
    expect(at('https://a.example/api/x?callback=test123', 'HTTP/1.1 200 OK\ncontent-type: application/javascript\n\ntest123({"a":1})', 'top', 'sensitive=1')).toContain('E-06.1');
  });
  it('ダウンロード応答とソースマップ', () => {
    expect(at('https://a.example/files/a.pdf', 'HTTP/1.1 200 OK\ncontent-type: application/pdf')).toContain('E-11.2');
    expect(at('https://a.example/uploads/x.html', 'HTTP/1.1 200 OK\ncontent-type: text/html')).toContain('E-11.1');
    expect(at('https://a.example/app.js', 'HTTP/1.1 200 OK\ncontent-type: text/javascript\n\nconsole.log(1)\n//# sourceMappingURL=app.js.map')).toContain('E-13.2');
    expect(evaluate('#TARGET url=https://a.example/ label=probes\n#PROBE path=/app.js.map code=200 size=10 head=eyJ2ZXJzaW9uIjozfQ== ct=application/json\n').ids('probes')).toContain('E-13.1');
  });
});

describe('T-01、T-06、T-12', () => {
  it('TRACE の反射、Allow の危険なメソッド、オープンリダイレクト、HTTP/1.1 のみ', () => {
    expect(evaluate(t('trace', 'https://a.example/', 'HTTP/1.1 200 OK\ncontent-type: message/http\n\nTRACE / HTTP/1.1\nHost: a.example')).ids('trace')).toContain('T-01.1');
    expect(evaluate(t('options', 'https://a.example/', 'HTTP/1.1 200 OK\nAllow: GET, HEAD, OPTIONS, PUT, DELETE')).ids('options')).toContain('T-01.2');
    expect(evaluate(t('open-redirect', 'https://a.example/login', 'HTTP/1.1 302 Found\nLocation: https://evil.example/')).ids('open-redirect')).toContain('T-06.1');
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/1.1 200 OK\ncontent-type: text/html')).ids('top')).toContain('T-12.1');
    expect(evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html')).ids('top')).toContain('T-12.ok');
  });
});

describe('コマンド生成器', () => {
  const base = { host: 'www.example.com', apex: 'example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false };
  it('シェルに展開される文字を含む入力を拒否する', () => {
    expect(validate(base)).toEqual([]);
    expect(validate({ ...base, host: 'a.example;rm -rf /' }).length).toBe(1);
    expect(validate({ ...base, apiPath: '/api/$(id)' }).length).toBe(1);
  });
  it('予約ラベルと確認用ラベルの #TARGET を出し、検証環境の試験は指定したときだけ含める', () => {
    const s = generateScript(base);
    for (const l of ['top', 'http', 'apex', 'pre-login', 'login', 'logout', 'after-logout', 'cors-reflect', 'probes', 'tls', 'open-redirect'])
      expect(s).toContain(`label=${l}`);
    expect(s).not.toContain('label=crlf');
    expect(generateScript({ ...base, dangerous: true })).toContain('label=crlf');
    expect(s).toContain('umask 077');
    expect(s).toContain('rm -f out.txt login.txt');   // パスワードを含む login.txt の削除を案内する
    expect(s).toContain('テスト用アカウント');
    expect(generateScript({ ...base, dangerous: true })).not.toMatch(/-X DELETE/);   // データを消しうる試験は生成しない
  });
  it('生成したスクリプトをローカルで実行した出力を、警告付きで最後まで解析できる', () => {
    const { targets } = parseInput(fixture('generated_local.txt'));
    expect(targets.length).toBeGreaterThan(20);
    expect(targets.find(t => t.label === 'probes')!.probes.length).toBe(13);
    expect(targets.find(t => t.label === 'tls')!.cipherProbes.length).toBe(5);
  });
});

describe('CSV（第8章の様式）', () => {
  it('BOM付きで、数式として解釈される値を無害化する', () => {
    const r = evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html'));
    const f = { ...r.findings.find(x => x.status === 'fail')!, evidence: '=HYPERLINK("https://x.example")' };
    const csv = toCsv([f], r.targets);
    expect(csv.startsWith('\ufeff項目ID,')).toBe(true);
    expect(csv).toContain(`"'=HYPERLINK(""https://x.example"")"`);
  });
});

describe('コマンド生成器（#META と WebSocket）', () => {
  const base = { host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false };
  it('各ターゲットの直後に #META at・cmd を出し、CSVの実施日時・実施コマンドが埋まる', async () => {
    const s = generateScript(base);
    const lines = s.split('\n');
    const targets = lines.filter(l => l.includes('#TARGET'));
    for (const l of targets) expect(lines[lines.indexOf(l) + (l.includes('for i') ? 0 : 1)] + l).toMatch(/#META at=\$\(date [^)]*\) cmd=\S+/);
    expect(s).toContain('cmd=C18');
    const out = '#TARGET url=https://www.example.com/ label=top\n#META at=2026-11-11T10:00:00 cmd=C4\nHTTP/2 200\ncontent-type: text/html\n';
    const r = evaluate(out);
    expect(toCsv(r.findings, r.targets)).toContain(',2026-11-11T10:00:00,C4,');
  });
  it('WebSocket のパスを入れたときだけ C16 を出し、パスの不正な文字は拒否する', () => {
    expect(generateScript(base)).not.toContain('label=websocket');
    const s = generateScript({ ...base, wsPath: '/ws' });
    expect(s).toContain('label=websocket');
    expect(s).toContain("-H 'Origin: https://evil.example'");
    expect(s).toContain('cmd=C16');
    expect(validate({ ...base, wsPath: '/ws;id' }).length).toBe(1);
  });
});
