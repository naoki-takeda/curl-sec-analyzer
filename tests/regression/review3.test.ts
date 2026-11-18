// 3回目のレビュー（ソースコード・ドキュメント）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { parseInput } from '../../src/parser/input';
import { importHar } from '../../src/parser/har';
import { parseSuppressions } from '../../src/engine/suppress';
import { parseProfile } from '../../src/engine/profile';
import { evaluate } from '../helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n`;
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';
const b64 = (s: string) => Buffer.from(s).toString('base64');
const probe = (path: string, code: number, head: string) => `#PROBE path=${path} code=${code} size=${head.length} head=${b64(head)} ct=application/json\n`;

describe('E-03・E-13：取得できた（2xx）プローブだけを一致とする', () => {
  const run = (probes: string) => evaluate(`#TARGET url=https://a.example/ label=probes\n${probes}`).findings.map(f => f.ruleId);
  it('404・403 のエラーページ（JSON・XML）は既知ファイルにしない', () => {
    expect(run(probe('/package.json', 404, '{"error":"Not Found"}'))).not.toContain('E-03.1');
    expect(run(probe('/WEB-INF/web.xml', 404, '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey'))).not.toContain('E-03.1');
    expect(run(probe('/.svn/entries', 403, '<?xml version="1.0"?><Error>AccessDenied'))).not.toContain('E-03.1');
    expect(run(probe('/assets/app.js.map', 404, '{"message":"not found"}'))).not.toContain('E-13.1');
  });
  it('2xx で中身がそのファイルの形なら指摘する', () => {
    expect(run(probe('/package.json', 200, '{\n  "name": "my-app",\n  "version": "1.0.0",\n  "private": true'))).toContain('E-03.1');
    // name・version だけでは、どのパスにも同じ JSON を返す API と見分けられないので②（判定保留）（要確認事項の確認、2026-11-18）
    const nameOnly = run(probe('/package.json', 200, '{\n  "name": "my-app",\n  "version": "1.0.0"'));
    expect(nameOnly).toContain('E-03.2');
    expect(nameOnly).not.toContain('E-03.1');
    expect(run(probe('/WEB-INF/web.xml', 200, '<?xml version="1.0" encoding="UTF-8"?>\n<web-app xmlns'))).toContain('E-03.1');
    expect(run(probe('/assets/app.js.map', 200, '{"version":3,"file":"app.js","sources":["src/a.ts"]'))).toContain('E-13.1');
  });
});

describe('マスク：署名付きURLなどのパラメータ', () => {
  it('名前を区切った語に token・signature・credential・key などがあれば伏せる', () => {
    const u = 'https://s3.example/f?X-Amz-Credential=AKIDEXAMPLE%2F2026&X-Amz-Security-Token=FQoGZXIvYXdzEJr1234567890&X-Amz-Signature=abcdef0123456789&page=2';
    const m = maskText(u);
    for (const secret of ['AKIDEXAMPLE', 'FQoGZXIvYXdzEJr1234567890', 'abcdef0123456789']) expect(m).not.toContain(secret);
    expect(m).toContain('page=2');
    expect(maskText('https://g.example/?private_token=glpat-abcdefghij1234&x-api-key=k1234567890abc&q=hello')).toMatch(/private_token=gl…\(\d+ chars\)&x-api-key=k1…\(\d+ chars\)&q=hello/);
  });
});

describe('H-06・H-14：広すぎる許可', () => {
  it('frame-ancestors の *・スキームだけ・ワイルドカードは④（XFO が DENY でも）', () => {
    const h06 = (csp: string) => evaluate(t('t', 'https://a.example/', `${HTML}\ncontent-security-policy: ${csp}\nx-frame-options: DENY`)).ids('t').filter(i => i.startsWith('H-06'));
    expect(h06('frame-ancestors *')).toEqual(['H-06.4']);
    expect(h06('frame-ancestors https:')).toEqual(['H-06.4']);
    expect(h06('frame-ancestors https://*.example.com')).toEqual(['H-06.4']);
    expect(h06("frame-ancestors 'self' https://partner.example")).toEqual(['H-06.ok']);
  });
  it('X-Permitted-Cross-Domain-Policies: all は②', () => {
    expect(evaluate(t('t', 'https://a.example/', `${HTML}\nx-permitted-cross-domain-policies: all`)).ids('t')).toContain('H-14.2');
    expect(evaluate(t('t', 'https://a.example/', `${HTML}\nx-permitted-cross-domain-policies: none`)).ids('t')).toContain('H-14.ok');
  });
});

describe('HAR・E-11', () => {
  it('応答のない（status 0）HAR のエントリは判定に使わない', () => {
    const entry = (url: string, status: number) => ({ request: { method: 'GET', url, headers: [] }, response: { status, headers: status ? [{ name: 'content-type', value: 'text/html' }] : [], content: {} } });
    const imp = importHar(JSON.stringify({ log: { entries: [entry('https://a.example/', 200), entry('https://a.example/blocked.js', 0)] } }));
    expect(imp.chains.map(c => c.url)).toEqual(['https://a.example/']);
    expect(imp.failed).toBe(1);
  });
  it('E-11：JSON:API・アップロード先の画像は②にしない。アップロード先の SVG は①', () => {
    const e11 = (url: string, ct: string) => evaluate(t('t', url, `HTTP/2 200\ncontent-type: ${ct}\n\n<svg></svg>`)).ids('t').filter(i => i.startsWith('E-11'));
    expect(e11('https://a.example/api/items', 'application/vnd.api+json')).toEqual([]);
    expect(e11('https://a.example/uploads/2026/a.png', 'image/png')).toEqual(['E-11.ok']);
    expect(e11('https://a.example/uploads/2026/a.svg', 'image/svg+xml')).toEqual(['E-11.1']);
  });
});

describe('小さな不具合', () => {
  it('URL のスキームが大文字（HTTPS://）でも HTTPS として判定する', () => {
    expect(evaluate(t('t', 'HTTPS://a.example/', HTML)).ids('t')).toContain('H-01.1');
  });
  it('空の Max-Age= は削除用とみなさない（セッションCookieとして判定する）', () => {
    const ids = evaluate(t('t', 'https://a.example/', `${HTML}\nset-cookie: sid=${'ab12'.repeat(10)}; HttpOnly; SameSite=Lax; Max-Age=; Path=/`)).ids('t');
    expect(ids).toContain('C-01.1');
  });
  it('H-01 と H-02 で includeSubDomains の読み方をそろえる', () => {
    const ids = evaluate(t('t', 'https://a.example/', `${HTML}\nstrict-transport-security: max-age=63072000; includeSubDomainsX; preload`)).ids('t');
    expect(ids).toEqual(expect.arrayContaining(['H-01.4', 'H-02.1']));
  });
  it('例外ファイルの approver が文字列でなければエラーにする', () => {
    const r = parseSuppressions(JSON.stringify([{ ruleId: 'H-01', target: '*', reason: 'r', approver: 123 }]));
    expect(r.list).toEqual([]);
    expect(r.errors[0]).toMatch(/approver/);
  });
  it('組織プロファイルでエラーにした値は使わない', () => {
    const r = parseProfile(JSON.stringify({ name: 'x', sessionMaxAgeHours: 1e9, sessionCookieNames: ['ok', 'bad name'] }));
    expect(r.profile?.sessionMaxAgeHours).toBe(24);
    expect(r.errors.some(e => e.startsWith('sessionCookieNames'))).toBe(true);
  });
  it('フォームの切り出しは、長さが変わる文字（İ）があってもずれない', () => {
    const form = '<form action="/login"><input type="password" name="pw"></form>';
    expect(evaluate(t('t', 'https://a.example/', `${HTML}\n\n${'İ'.repeat(20)}<form method="post"><input name="q"></form>${form}`)).ids('t')).toContain('E-10.2');
  });
  it('URL が分からないターゲットの警告は、ラベルを持つ', () => {
    expect(parseInput(t('api', '', 'HTTP/2 200').replace(' url= ', ' ')).warnings.find(w => w.kind === 'unknown-url')?.label).toBe('api');
  });
});
