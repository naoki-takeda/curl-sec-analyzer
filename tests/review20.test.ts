// 20回目のレビュー（リポジトリ全体を新しい目で見直したもの）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { applySuppressions } from '../src/engine/suppress';
import { isCurrentKey, urlKey } from '../src/engine/targetKey';
import { isDeletion, parseSetCookie } from '../src/parser/setCookie';
import type { Finding } from '../src/model';
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
