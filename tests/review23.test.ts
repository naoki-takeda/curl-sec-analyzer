// 23回目のレビュー（リポジトリ全体を新しい目で見直したもの）で見つかった不具合の再現テスト。小さな束に分けて直す（第40回）
import { describe, expect, it } from 'vitest';
import { diff, parseBaseline } from '../src/engine/diff';
import { tags } from '../src/rules/html';
import { toJson } from '../src/export/json';
import type { Finding } from '../src/model';
import { importHar } from '../src/parser/har';
import { parseOpenssl } from '../src/parser/openssl';
import { evaluate } from './helpers';

const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const f = (evidence: unknown) => ({ ruleId: 'E-08.1', item: 'E-08', condition: 1, title: 'SRI', severity: 'low', status: 'fail', target: 'page', targetKey: 'page', evidence, recommendation: '', references: [], score: 0 } as Finding);

describe('束2 2乗の時間と、壊れた前回の結果', () => {
  it('閉じのない <!-- の繰り返しでも、タグの読み取りは本文の長さに比例する', () => {
    expect(ms(() => tags('<!--'.repeat(16384), ['script', 'iframe', 'link', 'img', 'form']))).toBeLessThan(200);
    expect(ms(() => tags('<!-- x'.repeat(11000), ['script']))).toBeLessThan(200);
  });
  it('閉じた <!-- --> の中のタグはこれまでどおり読まない（確認用）', () => {
    expect(tags('<!-- <script src="https://x.example/a.js"></script> --><script src="https://y.example/b.js"></script>', ['script']).map(t => t.attrs.get('src'))).toEqual(['https://y.example/b.js']);
  });
  it('差分のキー：長い英数字とドットの並びの証跡でも速い', () => {
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
