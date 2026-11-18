// 4回目のレビュー（判定ロジック・画面・ドキュメント）で見つかった不具合の再現テスト
import { describe, expect, it } from 'vitest';
import { maskText } from '../../src/mask';
import { parseInput } from '../../src/parser/input';
import { looksLikeSession, parseSetCookie } from '../../src/parser/setCookie';
import { parseSuppressions } from '../../src/engine/suppress';
import { parseProfile } from '../../src/engine/profile';
import { parseBaseline } from '../../src/engine/diff';
import { validate } from '../../src/commands';
import { joinMessages, messageEn } from '../../src/messagesEn';
import { evaluate } from '../helpers';

const HSTS = 'strict-transport-security: max-age=63072000; includeSubDomains';
const JA = /[ぁ-んァ-ヶ一-龠]/;

describe('入力の解析', () => {
  it('-v の本文の JSON を %{header_json} の応答として読まない', () => {
    const input = [
      '#TARGET url=https://a.example/api/x label=t sensitive=1',
      '* Connected to a.example (192.0.2.1) port 443',
      '> GET /api/x HTTP/2', '> Host: a.example', '>',
      '< HTTP/2 200', '< content-type: application/json', `< ${HSTS}`, '< x-content-type-options: nosniff', '<',
      '{"items":[{"id":1}],"total":1}', '',
    ].join('\n');
    const { targets } = parseInput(input);
    expect(targets[0].responses).toHaveLength(1);
    expect(targets[0].responses[0].status).toBe(200);
    expect(evaluate(input).ids('t')).not.toContain('H-01.1');
  });
  it('-i の応答のあとに続く JSON の本文も、header_json として読まない', () => {
    const input = `#TARGET url=https://a.example/api/x label=t\nHTTP/2 200\ncontent-type: application/json\n${HSTS}\n\n{"items":[1]}\n`;
    expect(parseInput(input).targets[0].responses).toHaveLength(1);
  });
  it('C10（#META のあとの header_json）は今までどおり読む', () => {
    const input = `#TARGET url=https://a.example/ label=t\n#META response_code=200\n{"content-type":["text/html"],"strict-transport-security":["max-age=63072000"]}\n`;
    const r = parseInput(input).targets[0].responses;
    expect(r).toHaveLength(1);
    expect(r[0].headers.get('strict-transport-security')).toEqual(['max-age=63072000']);
  });
  it('200 の本文の中のステータス行らしき行で、新しい応答を始めない', () => {
    const input = `#TARGET url=https://a.example/docs label=t\nHTTP/2 200\ncontent-type: text/html\n${HSTS}\n\n<pre>\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n</pre>\n`;
    const { targets } = parseInput(input);
    expect(targets[0].responses).toHaveLength(1);
    expect(evaluate(input).ids('t')).not.toContain('H-01.1');
  });
  it('-L の転送（本文あり）のあとの応答は、今までどおり分ける', () => {
    const input = '#TARGET url=http://a.example/ label=t\nHTTP/1.1 301 Moved Permanently\nLocation: https://a.example/\n\n<html>moved</html>\n\nHTTP/2 200\ncontent-type: text/html\n';
    expect(parseInput(input).targets[0].responses.map(r => r.status)).toEqual([301, 200]);
  });
});

describe('マスク', () => {
  it('キャメルケースと角かっこのパラメータ名も伏せる', () => {
    const u = 'https://x.example/cb?accessToken=abcdef1234567890&user[password]=hunter2hunter2&user%5Bpassword%5D=s3cr3tvalue1&clientSecret=cs-0123456789&page=2';
    const m = maskText(u);
    for (const s of ['abcdef1234567890', 'hunter2hunter2', 's3cr3tvalue1', 'cs-0123456789']) expect(m).not.toContain(s);
    expect(m).toContain('page=2');
  });
  it('A-02：キャメルケースのトークン名も検出する', () => {
    const ids = evaluate('#TARGET url=https://a.example/cb?accessToken=opaque1234567890abcdef label=t\nHTTP/2 200\ncontent-type: text/html\n').ids('t');
    expect(ids).toContain('A-02.1');
  });
  it('長い英数字の並びでも時間がかからない（URLの user:pass@）', { tags: ['perf'] }, () => {
    const start = performance.now();
    maskText('a'.repeat(200_000));
    maskText('x://'.repeat(50_000));
    expect(performance.now() - start).toBeLessThan(1000);
  });
  it('URL の user:pass@ は今までどおり伏せる', () => {
    expect(maskText('see https://admin:Secr3tPass@db.example/')).toBe('see https://admin:****@db.example/');
  });
});

describe('E-01：本文が長くても時間がかからない', () => {
  it('絶対パスや System. が多数並ぶ本文', { tags: ['perf'] }, () => {
    for (const unit of ['/srv/', 'System.']) {
      const body = unit.repeat(Math.floor(60_000 / unit.length));
      const start = performance.now();
      evaluate(`#TARGET url=https://a.example/ label=t\nHTTP/2 500\ncontent-type: text/html\n\n${body}\n`);
      expect(performance.now() - start).toBeLessThan(1000);
    }
  });
});

describe('セッションCookieの名前の推定', () => {
  const s = (raw: string) => looksLikeSession(parseSetCookie(raw));
  it('語の一部に sid・auth などがあるだけの Cookie はセッションCookieとみなさない', () => {
    for (const raw of ['sidebar_collapsed=true; Path=/', 'considered=1; Max-Age=600', 'oauth_state=xyz; Max-Age=600', 'tokenizer_mode=fast; Max-Age=600'])
      expect(s(raw), raw).toBe(false);
  });
  it('よくあるセッションCookieの名前は、今までどおりセッションCookieとみなす', () => {
    for (const raw of ['PHPSESSID=abc; Max-Age=600', 'JSESSIONID=abc; Max-Age=600', 'ASP.NET_SessionId=abc; Max-Age=600', 'SSESSabcdef0123=x; Max-Age=600',
      'authToken=abc; Max-Age=600', 'connect.sid=s%3Aabc; Max-Age=600', 'laravel_session=abc; Max-Age=600', '.ASPXAUTH=abc; Max-Age=600', 'remember_token=abc; Max-Age=600'])
      expect(s(raw), raw).toBe(true);
  });
  it('sidebar_collapsed は C-02 の対象にならない', () => {
    const ids = evaluate('#TARGET url=https://a.example/ label=t\nHTTP/2 200\ncontent-type: text/html\nset-cookie: sidebar_collapsed=true; Path=/; Secure; SameSite=Lax\n').ids('t');
    expect(ids).not.toContain('C-02.1');
  });
});

describe('機密応答かどうか分からないとき（第0章 0.3）', () => {
  const html = (extra: string, sensitive = '') => `#TARGET url=https://a.example/mypage label=t ${sensitive}\nHTTP/2 200\ncontent-type: text/html\n${extra}\n\n<form method="post" action="/save"><input name="q"></form>\n`;
  it('R-08：Timing-Allow-Origin: * は na', () => {
    expect(evaluate(html('timing-allow-origin: *')).ids('t')).toContain('R-08.na');
    expect(evaluate(html('timing-allow-origin: *', 'sensitive=1')).ids('t')).toContain('R-08.1');
  });
  it('R-04・E-06：より弱い③・②で出し、根拠に「分からない」と書く', () => {
    const r = evaluate('#TARGET url=https://a.example/api/x?callback=cb1 label=t\nHTTP/2 200\ncontent-type: application/javascript\naccess-control-allow-origin: *\n\ncb1({"a":1})\n');
    expect(r.ids('t')).toEqual(expect.arrayContaining(['R-04.3', 'E-06.2']));
    for (const id of ['R-04.3', 'E-06.2']) expect(r.findings.find(f => f.ruleId === id)!.evidence).toContain('機密応答かどうか分からない');
  });
  it('E-12：機密かどうか分からなければ na', () => {
    expect(evaluate(html('')).ids('t')).toContain('E-12.na');
  });
  it('E-12：同じホストのセッションCookieがすべて SameSite=Lax/Strict なら合格。None なら①', () => {
    const cookie = (ss: string) => `set-cookie: sessionid=${'ab12'.repeat(8)}; Secure; HttpOnly; SameSite=${ss}; Path=/`;
    expect(evaluate(html(cookie('Strict'), 'sensitive=1')).ids('t')).toContain('E-12.ok');
    expect(evaluate(html(cookie('None'), 'sensitive=1')).ids('t')).toContain('E-12.1');
    expect(evaluate(html('', 'sensitive=1')).ids('t')).toContain('E-12.1');   // セッションCookieが見えない
  });
});

describe('英語UIのエラーメッセージ', () => {
  it('コマンド生成器・例外ファイル・組織プロファイル・前回の結果のエラーに日本語が残らない', () => {
    const msgs = [
      ...validate({ host: 'a.example;id', apex: 'b;c', apiPath: 'x', loginPath: 'y', mypagePath: 'z', logoutPath: 'w', staticPath: 'v', wsPath: 'u', dangerous: false }),
      ...parseSuppressions('{not json').errors,
      ...parseSuppressions('{"a":1}').errors,
      ...parseSuppressions(JSON.stringify([{ ruleId: 'x' }, { ruleId: 'H-01' }, { ruleId: 'H-01', target: 'a'.repeat(600) }, { ruleId: 'H-01', target: '*' },
        { ruleId: 'H-01', target: '*', reason: 'r', approver: 1 }, { ruleId: 'H-01', target: '*', reason: 'r', until: 'tomorrow' }])).errors,
      ...parseProfile('[]').errors,
      ...parseProfile('{not json').errors,
      ...parseProfile(JSON.stringify({ severity: { X: 'high', 'H-01': 'urgent' }, exclude: [1], trustedScriptOrigins: ['ftp://x'], sessionCookieNames: ['bad name'], sessionMaxAgeHours: 0 })).errors,
      parseBaseline('{not json').error!, parseBaseline('{}').error!,
    ];
    expect(msgs.length).toBeGreaterThan(15);
    const left = msgs.map(messageEn).filter(m => JA.test(m));
    expect(left).toEqual([]);
    expect(joinMessages(['JSONとして読めません', 'オブジェクトが必要です'], 'en')).toBe('The file is not valid JSON; Expected a JSON object');
    expect(joinMessages(['a', 'b'], 'ja')).toBe('a、b');
  });
});
