// 20回目のレビュー（リポジトリ全体を新しい目で見直したもの）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { applySuppressions } from '../src/engine/suppress';
import { isCurrentKey, urlKey } from '../src/engine/targetKey';
import { isDeletion, parseSetCookie } from '../src/parser/setCookie';
import { parseProfile } from '../src/engine/profile';
import { importHar } from '../src/parser/har';
import { parseInput } from '../src/parser/input';
import { messageEn } from '../src/messagesEn';
import type { Finding } from '../src/model';
import { readFileSync } from 'node:fs';
import { evaluate } from './helpers';

const AT = '#META at=2026-11-01T10:00:00';

describe('1 画面で登録した例外は、そのページがない回にもほかのページに効かない', () => {
  const f = (path: string) => ({ item: 'H-01', ruleId: 'H-01.1', status: 'fail', target: 'har-1', targetKey: `HAR GET ${urlKey(`https://a.example${path}`)}`,
    url: `https://a.example${path}`, keyUrl: urlKey(`https://a.example${path}`) } as Finding);
  // 1回目：/AdminDashboardV2 の指摘に例外を登録した（キーは HAR GET https://a.example/*）
  const s = { ruleId: 'H-01', target: f('/AdminDashboardV2').targetKey!, reason: 'x', approver: '', until: '' };
  it('登録したキーは今の形式で、* を含む', () => {
    expect(s.target).toBe('HAR GET https://a.example/*');
    expect(isCurrentKey(s.target)).toBe(true);
    expect(isCurrentKey('HAR GET *')).toBe(false);
    expect(isCurrentKey('HAR GET https://a.example/admin*')).toBe(false);
  });
  it('2回目の入力に /AdminDashboardV2 がなくても、/login・/account の H-01①（高）を抑止しない', () => {
    expect(applySuppressions([f('/login'), f('/account')], [s]).map(x => x.status)).toEqual(['fail', 'fail']);
  });
  it('同じページ（同じキー）にはこれまでどおり効く。手で書いた HAR GET * は広く効く', () => {
    expect(applySuppressions([f('/AdminDashboardV2'), f('/login')], [s]).map(x => x.status)).toEqual(['suppressed', 'fail']);
    expect(applySuppressions([f('/login'), f('/account')], [{ ...s, target: 'HAR GET *' }]).map(x => x.status)).toEqual(['suppressed', 'suppressed']);
  });
});

describe('2 CORS：ACAO が2つある応答と、ACAC: TRUE', () => {
  const cors = (acao: string[], acac?: string) => evaluate([
    '#TARGET url=https://a.example/api/me label=cors-reflect sensitive=1', AT,
    '* Connected to a.example (192.0.2.1) port 443', '> GET /api/me HTTP/2', '> Host: a.example', '> Origin: https://evil.example', '>',
    '< HTTP/2 200', '< content-type: application/json', ...acao.map(v => `< access-control-allow-origin: ${v}`),
    ...(acac ? [`< access-control-allow-credentials: ${acac}`] : []), '<', '{}', ''].join('\n')).ids('cors-reflect').filter(x => x.startsWith('R-0'));
  it('1つの ACAO の反射と ACAC: true は R-01①（確認用）', () => {
    expect(cors(['https://evil.example'], 'true')).toContain('R-01.1');
  });
  it('ACAO が2つあれば、ブラウザの CORS の検査は失敗するので反射としない', () => {
    const r = cors(['https://evil.example', 'https://evil.example'], 'true');
    expect(r).not.toContain('R-01.1');
    expect(r).toContain('R-01.ok');
    expect(cors(['*', 'https://evil.example'])).not.toContain('R-04.1');
  });
  it('ACAC: TRUE（大文字）は資格情報を許可しないので、R-01② にする', () => {
    const r = cors(['https://evil.example'], 'TRUE');
    expect(r).toContain('R-01.2');
    expect(r).not.toContain('R-01.1');
  });
});

describe('3 Set-Cookie：正しい Max-Age は過去の Expires より優先する', () => {
  const cookie = 'sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  it('生きている Cookie を削除とみなさない', () => {
    const now = Date.parse('2026-11-01T10:00:00Z');
    expect(isDeletion(parseSetCookie(cookie), now)).toBe(false);
    expect(isDeletion(parseSetCookie('sessionid=x; Max-Age=0; Expires=Thu, 01 Jan 2099 00:00:00 GMT'), now)).toBe(true);
    expect(isDeletion(parseSetCookie('sessionid=x; Max-Age=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT'), now)).toBe(true);   // 数字でない Max-Age は無視
  });
  it('Secure のない Cookie を C-01 で判定する', () => {
    const r = evaluate(`#TARGET url=https://a.example/ label=top\n${AT}\nHTTP/2 200\ncontent-type: text/html\nset-cookie: ${cookie}\n\n<p>x</p>\n`);
    expect(r.ids('top').some(x => x.startsWith('C-01.') && x !== 'C-01.ok' && x !== 'C-01.na')).toBe(true);
  });
});

describe('4 T-09：旧バージョンの一部が ok=err なら合格にしない', () => {
  const tls = (tls1: string, tls11: string) => evaluate(['#TARGET url=https://a.example/ label=tls', AT,
    `#TLSPROBE v=tls1 ok=${tls1}`, `#TLSPROBE v=tls1_1 ok=${tls11}`, '#TLSPROBE v=tls1_2 ok=1', '#TLSPROBE v=tls1_3 ok=1', ''].join('\n'))
    .findings.filter(f => f.item === 'T-09').map(f => f.ruleId);
  it('tls1=err・tls1_1=0 と、その逆は na', () => {
    expect(tls('err', '0')).toContain('T-09.na');
    expect(tls('0', 'err')).toContain('T-09.na');
    expect(tls('err', '0')).not.toContain('T-09.ok');
  });
  it('どちらも拒否されたら合格、どちらかで接続できたら①（確認用）', () => {
    expect(tls('0', '0')).toContain('T-09.ok');
    expect(tls('err', '1')).toContain('T-09.1');
  });
});

// ---- 中程度の指摘 ----

describe('5 端末で採取した curl -iv（-v の「< 」の行と -i の行が交互に並ぶ）', () => {
  const lines = ['#TARGET url=https://a.example/ label=top', AT, '* Connected to a.example (192.0.2.1) port 443', '> GET / HTTP/2', '> Host: a.example', '>',
    '< HTTP/2 200', 'HTTP/2 200', '< content-type: text/html', 'content-type: text/html', '< set-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/',
    'set-cookie: sessionid=AbCdEf0123456789AbCdEf0123456789; Path=/', '<', '', '<p>x</p>', ''];
  it('応答は1つで、ヘッダは二重にならない', () => {
    const t = parseInput(lines.join('\n')).targets[0];
    expect(t.responses.map(r => [r.status, r.kind])).toEqual([[200, 'final']]);
    expect(t.responses[0].headers.get('set-cookie')).toHaveLength(1);
  });
  it('C-06 を2回出さない', () => {
    expect(evaluate(lines.join('\n')).ids('top').filter(x => x === 'C-06.1')).toHaveLength(1);
  });
});

describe('6 E-08・E-09 は、-L の転送先（HTML を返したページ）のホストと比べる', () => {
  const page = (script: string) => evaluate(['#TARGET url=https://a.example/ label=page', AT,
    'HTTP/1.1 301 Moved Permanently', 'location: https://www.a.example/', '', 'HTTP/2 200', 'content-type: text/html', '',
    `<html><script src="${script}"></script></html>`, ''].join('\n')).ids('page').filter(x => x.startsWith('E-08'));
  it('転送先と同じホストのスクリプトは第三者のものとしない', () => {
    expect(page('https://www.a.example/wp-includes/js/jquery.min.js')).toEqual(['E-08.ok']);
  });
  it('ほかのホストのスクリプトは①（確認用）', () => {
    expect(page('https://cdn.other.example/x.js')).toContain('E-08.1');
  });
});

describe('7 A-01：200 で返したエラーだけの JSON は保護データとしない', () => {
  const unauth = (body: string) => evaluate(`#TARGET url=https://a.example/api/me label=unauth-api\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n${body}\n`)
    .ids('unauth-api').filter(x => x.startsWith('A-01'));
  it('success:false とエラーの文言だけなら na', () => {
    expect(unauth('{"success":false,"error":"Unauthorized","message":"Please log in"}')).toEqual(['A-01.na']);
    expect(unauth('{"error":{"code":401,"message":"Login required"},"data":null}')).toEqual(['A-01.na']);
  });
  it('エラーの項目のほかにデータがあれば①（確認用）', () => {
    expect(unauth('{"success":false,"error":"x","user":{"email":"a@example.com"}}')).toContain('A-01.1');
    expect(unauth('{"success":true,"name":"alice"}')).toContain('A-01.1');
  });
});

describe('8 組織プロファイル：配列でない値と知らない項目はエラーにする', () => {
  it('文字列で書いた exclude・sessionCookieNames・trustedScriptOrigins と、配列の severity', () => {
    const { errors } = parseProfile('{"exclude":"T-12","sessionCookieNames":"APPSESSION","trustedScriptOrigins":"https://cdn.example.com","severity":["H-10"]}');
    expect(errors).toHaveLength(4);
    for (const e of errors) expect(messageEn(e)).not.toMatch(/[ぁ-んァ-ヶ一-龠]/);
  });
  it('綴りを誤った項目を知らせる。ひな形と正しい項目はエラーにしない', () => {
    const { errors } = parseProfile('{"excludes":["T-12"],"sessionCookieName":["APPSESSION"]}');
    expect(errors.map(e => messageEn(e))).toEqual(['"excludes" is not a profile setting', '"sessionCookieName" is not a profile setting']);
    expect(parseProfile('{"name":"x","severity":{"H-10":"low"},"exclude":["T-12"],"sessionCookieNames":["A"],"sessionMaxAgeHours":12,"trustedScriptOrigins":["cdn.example.com"]}').errors).toEqual([]);
  });
});

describe('9 T-10：単一 DES・EXP1024・匿名の鍵交換は①', () => {
  const t10 = (c: string) => evaluate(`#TARGET url=https://a.example/ label=tls\n${AT}\n#CIPHERPROBE c=${c} ok=1\n`).findings.filter(f => f.item === 'T-10').map(f => f.ruleId);
  it.each(['DES-CBC-SHA', 'EXP1024-DES-CBC-SHA', 'EDH-RSA-DES-CBC-SHA', 'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_DES_CBC_SHA'])('%s', c => {
    expect(t10(c)).toContain('T-10.1');
  });
  it('前方秘匿性のない AES は③のまま（確認用）', () => {
    expect(t10('AES128-SHA')).toContain('T-10.3');
    expect(t10('AES128-SHA')).not.toContain('T-10.1');
  });
});

describe('10 H-11：守りにならない CORP・COOP の値は、ないのと同じ', () => {
  const h11 = (head: string, label = 'api', extra = 'sensitive=1') => evaluate(`#TARGET url=https://a.example/x label=${label} ${extra}\n${AT}\nHTTP/2 200\n${head}\n\n<p>x</p>\n`)
    .ids(label).filter(x => x.startsWith('H-11'));
  it('機密応答の CORP: cross-origin は①', () => {
    expect(h11('content-type: application/json\ncross-origin-resource-policy: cross-origin')).toContain('H-11.1');
    expect(h11('content-type: application/json\ncross-origin-resource-policy: same-site')).toEqual(['H-11.ok']);
  });
  it('COOP: unsafe-none は②。report-to の付いた same-origin は合格', () => {
    expect(h11('content-type: text/html\ncross-origin-resource-policy: same-origin\ncross-origin-opener-policy: unsafe-none', 'page')).toContain('H-11.2');
    expect(h11('content-type: text/html\ncross-origin-resource-policy: same-origin\ncross-origin-opener-policy: same-origin; report-to="coop"', 'page')).toEqual(['H-11.ok']);
  });
});

describe('11 HAR：URL の書き方の違いと、文字列の状態コード', () => {
  const entry = (url: string, status: number | string, headers: { name: string; value: string }[] = []) =>
    ({ startedDateTime: '2026-11-01T01:00:00Z', request: { method: 'GET', url, headers: [] }, response: { status, statusText: '', httpVersion: 'HTTP/2', headers, content: { mimeType: 'text/html', text: '' } } });
  it('http から https への転送は、転送先が :443 付きで記録されていてもつなぐ', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [entry('http://a.example/', 301, [{ name: 'location', value: 'https://a.example/' }]), entry('https://a.example:443/', 200)] } }));
    expect(imp.chains.map(c => c.hops)).toEqual([2]);
  });
  it('文字列の "304" も 304 として除外し、数値にそろえる', () => {
    const imp = importHar(JSON.stringify({ log: { entries: [entry('https://a.example/', '304')] } }));
    expect(imp.chains[0].excluded).toBe(true);
    expect(imp.chains[0].status).toBe(304);
  });
});

// ---- 低の指摘 ----

describe('12 E-04：読めない security.txt の Expires は合格にしない', () => {
  const sec = (ex: string) => evaluate(`#TARGET url=https://a.example/.well-known/security.txt label=sec\n${AT}\nHTTP/2 200\ncontent-type: text/plain\n\nContact: mailto:security@example.com\nExpires: ${ex}\n`)
    .ids('sec').filter(x => x.startsWith('E-04'));
  it('Expires: never は②', () => { expect(sec('never')).toEqual(['E-04.2']); });
  it('正しい日時は合格（確認用）', () => { expect(sec('2027-06-01T00:00:00Z')).toEqual(['E-04.ok']); });
});

describe('13 HSTS：カンマ区切りのヘッダと、引用符の中の「;」', () => {
  const hsts = (v: string) => evaluate(`#TARGET url=https://a.example/ label=top\n${AT}\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: ${v}\n\n<p>x</p>\n`)
    .ids('top').filter(x => /^H-0[12]\./.test(x));
  it('カンマ区切りは H-01③ だけで、H-02 は「preload なし」にしない', () => {
    const r = hsts('max-age=63072000, includeSubDomains, preload');
    expect(r).toContain('H-01.3');
    expect(r).toContain('H-02.na');
    expect(r).not.toContain('H-02.2');
  });
  it('引用符の文字列の中の「;」で分けない', () => {
    expect(hsts('max-age=63072000; includeSubDomains; preload; foo="a;b"')).toEqual(['H-01.ok', 'H-02.ok']);
    expect(hsts('max-age="63072000"; includeSubDomains')).toContain('H-01.ok');
  });
});

describe('14 R-03：送った Origin の見えない -i の cors-partial', () => {
  const partial = (acao?: string) => evaluate(`#TARGET url=https://www.example.com/api/me label=cors-partial sensitive=1\n${AT}\nHTTP/2 200\ncontent-type: application/json\n${acao ? `access-control-allow-origin: ${acao}\naccess-control-allow-credentials: true\n` : ''}\n{}\n`)
    .ids('cors-partial').filter(x => x.startsWith('R-03'));
  it('似せた Origin の ACAO は反射とみなして①', () => { expect(partial('https://www.example.com.evil.net')).toEqual(['R-03.1']); });
  it('ACAO がなければ na（[] にしない）', () => { expect(partial()).toEqual(['R-03.na']); });
});

describe('15 Cookie の Expires の2桁の年（RFC 6265 5.1.1）', () => {
  const now = Date.parse('2026-11-01T10:00:00Z');
  it('69 は 2069 年、70 は 1970 年', () => {
    expect(isDeletion(parseSetCookie('sessionid=x; Expires=Mon, 01-Oct-69 00:00:00 GMT'), now)).toBe(false);
    expect(isDeletion(parseSetCookie('sessionid=x; Expires=Thu, 01-Jan-70 00:00:00 GMT'), now)).toBe(true);
    expect(isDeletion(parseSetCookie('sessionid=x; Expires=Thu, 01 Jan 2099 00:00:00 GMT'), now)).toBe(false);
  });
});

describe('16 版の番号', () => {
  it('ルールセットのツールの版は package.json の版と同じ', async () => {
    const { TOOL_VERSION, RULESET_VERSION } = await import('../src/rules/ruleset');
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(TOOL_VERSION).toBe(pkg.version);
    expect(RULESET_VERSION.endsWith(`-v${pkg.version}`)).toBe(true);
  });
});
