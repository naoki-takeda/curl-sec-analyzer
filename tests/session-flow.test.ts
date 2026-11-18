// ログイン・ログアウトの流れの判定（C-07②・C-09①・C-12①・H-15）。第48回のレビューで見つかった誤検知
import { describe, expect, it } from 'vitest';
import { evaluate } from './helpers';
import { NO_BODY_REC } from '../src/rules/util';

const AT = '#META at=2026-11-01T10:00:00';
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item && f.target !== 'pre-login' && f.target !== 'login').map(f => f.ruleId);
const LOGOUT = (head: string, body = '') => ['#TARGET url=https://www.example.com/logout label=logout', AT, head, '', body, ''].join('\n');
const AFTER = (body = '') => ['#TARGET url=https://www.example.com/mypage label=after-logout sensitive=1', AT, 'HTTP/2 200', 'content-type: text/html; charset=utf-8', '', body, ''].join('\n');
const DELETED = 'HTTP/2 302\nlocation: /login\nset-cookie: SESSIONID=deleted; Max-Age=0';

describe('第48回：C-12① ログアウト後', () => {
  it('本文のない after-logout の 200 は na（本文を採取し直す案内）。本文があれば今までどおり①', () => {
    const na = evaluate(LOGOUT(DELETED) + AFTER()).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout');
    expect(na.map(f => f.ruleId)).toEqual(['C-12.na']);
    expect(na[0].recommendation).toBe(NO_BODY_REC);
    expect(ids(LOGOUT(DELETED) + AFTER('<h1>My page</h1>'), 'C-12')).toContain('C-12.1');
  });
  it('GET でログアウトの確認画面を返すだけのアプリ（ASP.NET Core Identity）は、ログアウトできていないので C-12①②・H-15 を判定しない', () => {
    const confirm = LOGOUT('HTTP/2 200\ncontent-type: text/html', '<h1>Log out</h1><form method="post" action="/Identity/Account/Logout?returnUrl=%2F"><button>Click here to Logout</button></form>');
    const r = evaluate(confirm + AFTER('<h1>My page</h1>'));
    expect(r.findings.filter(f => f.item === 'C-12').map(f => f.ruleId).every(x => x === 'C-12.na')).toBe(true);
    expect(r.findings.filter(f => f.item === 'H-15').map(f => f.ruleId)).toEqual(['H-15.na']);
  });
  it('ログアウトして Cookie を消した 200 の画面（ログインのフォームへの案内）は、ログアウトできたものとして判定する', () => {
    const done = LOGOUT('HTTP/2 200\ncontent-type: text/html\nset-cookie: SESSIONID=deleted; Max-Age=0', '<p>ログアウトしました</p><form method="post" action="/login"><input type="password" name="pw"></form>');
    expect(ids(done + AFTER('<h1>My page</h1>'), 'C-12')).toContain('C-12.1');
  });
});

describe('第48回：C-09①・C-07② の比べる Cookie', () => {
  const PRE = ['#TARGET url=https://www.example.com/login label=pre-login', AT, 'HTTP/2 200', 'content-type: text/html',
    'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly',
    'set-cookie: __Secure-next-auth.callback-url=https%3A%2F%2Fwww.example.com%2Fmypage; Path=/; Secure; HttpOnly', '', ''].join('\n');
  const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('値が URL の Cookie（callback-url）を同じ値で送り直しても、セッションIDを新しくしていれば合格', () => {
    const login = ['#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /mypage',
      'set-cookie: JSESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly',
      'set-cookie: __Secure-next-auth.callback-url=https%3A%2F%2Fwww.example.com%2Fmypage; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(c09(PRE + login)).toEqual(['C-09.ok']);
  });
  it('サンプルごとに同じ値の callback-url で C-07②（予測可能）にしない', () => {
    const sample = (i: number) => [`#TARGET url=https://www.example.com/login label=session-sample-${i}`, AT, 'HTTP/2 302', 'location: /mypage',
      `set-cookie: JSESSIONID=${'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'.split('').sort(() => (i === 1 ? 1 : -1)).join('')}; Path=/; Secure; HttpOnly`,
      'set-cookie: __Secure-next-auth.callback-url=https%3A%2F%2Fwww.example.com%2Fmypage; Path=/; Secure; HttpOnly', '', ''].join('\n');
    const r = evaluate(sample(1) + sample(2)).findings.filter(f => f.item === 'C-07' && f.condition === 2);
    expect(r.map(f => f.evidence).join(' ')).not.toContain('callback-url');
  });
  it('JSON の API のログインが 200 でエラーの JSON を返したら、ログインの失敗として na', () => {
    const login = ['#TARGET url=https://www.example.com/api/login label=login', AT, 'HTTP/2 200', 'content-type: application/json', '',
      '{"success":false,"error":"invalid_credentials","message":"Invalid email or password"}', ''].join('\n');
    const pre = PRE.replace(/set-cookie: __Secure-next-auth[^\n]*\n/, '');
    expect(c09(pre + login)).toEqual(['C-09.na']);
    // 空の {} は成功でもありうるので、失敗とはみなさない（新しいセッションIDがなければ①のまま）
    const empty = login.replace('{"success":false,"error":"invalid_credentials","message":"Invalid email or password"}', '{}');
    expect(c09(pre + empty)).toEqual(['C-09.1']);
  });
});

describe('第48回：生成スクリプトの logout・after-logout', () => {
  it('logout は -v のまま本文も出し、after-logout は本文も取る', async () => {
    const { generateScript } = await import('../src/commands');
    const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false });
    const lines = s.split('\n');
    const logout = lines[lines.findIndex(l => l.includes('label=logout')) + 2];
    // -v の行（送った Cookie の名前）は標準エラー、本文はファイルに取り、#BODY の印のあとに出す（-v の出力に本文を混ぜると、パーサは本文を読まない）
    expect(logout).toMatch(/: > "\$body"; curl .*-v -o "\$body" -c jar\.txt -b jar\.txt "\$H"'\/logout' 2>&1; echo "#BODY run=\$RUN"; head -c 196608 "\$body"; echo/);
    const after = lines[lines.findIndex(l => l.includes('label=after-logout')) + 2];
    expect(after).toContain('-D "$hdr" -o "$body"');
    expect(after).toContain('-b old.txt');
  });
});

describe('第48回（束3〜5のレビュー）', () => {
  const RUN = '0123456789abcdef';
  it('本物のログアウトの画面（WebForms・action のないフォーム・購読のフォーム）を確認画面とみなさず、C-12① を隠さない', () => {
    for (const body of ['<form method="post" action="./Logout.aspx"><input type="hidden" name="__VIEWSTATE" value="x"><p>ログアウトしました</p></form>',
      '<p>ログアウトしました</p><form method="post"><input name="user"><input type="password" name="pw"></form>', '<p>Bye</p><form method="post"><input name="email"><button>Subscribe</button></form>']) {
      expect(ids(LOGOUT('HTTP/2 200\ncontent-type: text/html', body) + AFTER('<h1>My page</h1>'), 'C-12'), body).toContain('C-12.1');
    }
  });
  it('毎回の負荷分散の Cookie（AWSALB）があっても、確認画面は確認画面として扱う', () => {
    const confirm = LOGOUT('HTTP/2 200\ncontent-type: text/html\nset-cookie: AWSALB=abc; Path=/', '<form method="post" action="/Identity/Account/Logout"><button>Click here to Logout</button></form>');
    expect(evaluate(confirm + AFTER('<h1>My page</h1>')).findings.filter(f => f.item === 'C-12').every(f => f.status === 'na')).toBe(true);
  });
  it('生成スクリプトの形（-v と #BODY）の logout の確認画面も見分ける', () => {
    const input = [`#TARGET url=https://www.example.com/logout label=logout run=${RUN}`, `${AT} run=${RUN}`, '* Connected to www.example.com (192.0.2.1) port 443',
      '> GET /logout HTTP/2', '> Cookie: SESSIONID=abc', '>', '< HTTP/2 200', '< content-type: text/html', '<', `#BODY run=${RUN}`,
      '<form method="post" action="/logout"><button>Log out</button></form>', '',
      `#TARGET url=https://www.example.com/mypage label=after-logout sensitive=1 run=${RUN}`, `${AT} run=${RUN}`, 'HTTP/2 200', 'content-type: text/html', '', `#BODY run=${RUN}`, '<h1>My page</h1>', ''].join('\n');
    const r = evaluate(input);
    expect(r.findings.filter(f => f.item === 'C-12').every(f => f.status === 'na')).toBe(true);
  });
  it('Rails のセッション（値が %2F で始まる Base64）を URL の値とみなさない', () => {
    const r = evaluate('#TARGET url=https://www.example.com/ label=top\n' + AT + '\nHTTP/2 200\ncontent-type: text/html\nset-cookie: _myapp_session=%2Fx9YqZ8wVb7uT6sR5qP4oN3mL2kJ1hG0fE; path=/\n\n<p>x</p>\n');
    expect(r.findings.filter(f => f.item === 'C-01').map(f => f.ruleId)).toContain('C-01.1');
  });
  it('ログアウトの確認画面の判定は、<form の繰り返しでも入力の長さに比例する時間', { tags: ['perf'] }, () => {
    const body = '<form/method=post/action='.repeat(2600);   // 約64KB
    const t0 = performance.now(); evaluate(LOGOUT('HTTP/2 200\ncontent-type: text/html', body) + AFTER('<h1>x</h1>')); expect(performance.now() - t0).toBeLessThan(3000);
  });
});

describe('第49回：ログイン・ログアウトとセッション Cookie', () => {
  const AFTER49 = (ct: string, body: string) => ['#TARGET url=https://www.example.com/mypage label=after-logout sensitive=1', AT, 'HTTP/2 200', `content-type: ${ct}`, '', body, ''].join('\n');
  it('C-12①・A-01①：{"authenticated":false,"message":…} はデータを返していない', () => {
    expect(ids(LOGOUT(DELETED) + AFTER49('application/json', '{"authenticated":false,"message":"Not logged in"}'), 'C-12')).not.toContain('C-12.1');
    const unauth = evaluate(`#TARGET url=https://www.example.com/api/me label=unauth-me\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n{"authenticated":false,"message":"Not logged in"}\n`);
    expect(unauth.findings.filter(f => f.item === 'A-01').map(f => f.ruleId)).not.toContain('A-01.1');
  });
  it('C-12①：利用者が null の SPA の殻はデータを持たない（利用者のデータを埋め込んだ殻は今までどおり①）', () => {
    const shell = (user: string) => `<head><script>window.Laravel = {"csrfToken":"AbCdEfGh","user":${user}};</script></head><body><div id="app"></div><script src="/js/app.js"></script></body>`;
    expect(ids(LOGOUT(DELETED) + AFTER49('text/html', shell('null')), 'C-12')).not.toContain('C-12.1');
    expect(ids(LOGOUT(DELETED) + AFTER49('text/html', shell('{"id":1,"email":"a@example.com"}')), 'C-12')).toContain('C-12.1');
  });
  it('C-12：mypage がなく、送信先がログインらしくないパスワード欄の画面（アカウント画面）は合格にしない', () => {
    const acct = '<h1>Account: taro@example.com</h1><form method="post" action="/account/email"><input type="email" name="email" value="taro@example.com"><input type="password" name="password"></form>';
    expect(evaluate(LOGOUT(DELETED) + AFTER49('text/html', acct)).findings.filter(f => f.item === 'C-12' && f.target === 'after-logout').map(f => f.ruleId)).toEqual(['C-12.na']);
  });
  it('C-07①：区切りのある値の乱数の量を、区切りを除いて数える', () => {
    const r = evaluate(`#TARGET url=https://www.example.com/login label=login\n${AT}\nHTTP/2 302\nlocation: /\nset-cookie: SESSIONID=0a1b-2c3d-4e5f-6071-8293; Path=/; Secure; HttpOnly; SameSite=Lax\n\n`);
    expect(r.findings.filter(f => f.item === 'C-07').map(f => f.ruleId)).toContain('C-07.1');
  });
  it('http だけのサイトでも、セッション Cookie の HttpOnly（C-02）と HTTP での発行（C-10）を判定する', () => {
    const r = evaluate(`#TARGET url=http://intranet.example.com/ label=t\n${AT}\nHTTP/1.1 200 OK\ncontent-type: text/html\nset-cookie: SESSIONID=abcdefghijklmnopqrstuvwxyz0123456789ABCD; Path=/\n\n<p>x</p>\n`);
    const got = r.findings.map(f => f.ruleId);
    expect(got).toContain('C-02.1');
    expect(got).toContain('C-10.1');
    expect(got.filter(x => x.startsWith('C-01'))).toEqual([]);   // Secure は http では見ない（C-10 で見る）
  });
  it('C-09①：セッションIDを新しくしていれば、セッションらしくない名前の Cookie の送り直しでは①にしない', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, 'HTTP/2 200', 'content-type: text/html',
      'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; HttpOnly', 'set-cookie: visitor_ref=abcdefghijklmnopqrstuvwxyz012345; Path=/', '', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /mypage',
      'set-cookie: JSESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; HttpOnly', 'set-cookie: visitor_ref=abcdefghijklmnopqrstuvwxyz012345; Path=/', '', ''].join('\n');
    expect(evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.ok']);
  });
  it('C-09：送っただけの JSESSIONID を再発行せず、別の Cookie だけを発行したログインは na', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, '* Connected to www.example.com (192.0.2.1) port 443', '> GET /login HTTP/2',
      '> Cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '>', '< HTTP/2 200', '< content-type: text/html', '<', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /mypage', 'set-cookie: auth_token=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.na']);
  });
  it('C-09：login の応答がプロキシの CONNECT の応答だけ（curl が失敗した）なら na', () => {
    const R = '0123456789abcdef', at = `#META at=2026-11-01T10:00:00 run=${R}`;
    const input = [`#TARGET url=https://www.example.com/login label=pre-login run=${R}`, at, 'HTTP/1.1 200 Connection established', '', 'HTTP/2 200',
      'set-cookie: sessionid=Q2x8AAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', '',
      `#TARGET url=https://www.example.com/login label=login run=${R}`, at, 'HTTP/1.1 200 Connection established', '', `#BODY run=${R}`, '', ''].join('\n');
    expect(evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId)).toEqual(['C-09.na']);
  });
  it('nginx の負荷分散の Cookie（route）をセッション Cookie とみなさない', () => {
    const s = (i: number) => `#TARGET url=https://www.example.com/login label=session-sample-${i}\n${AT}\nHTTP/2 302\nlocation: /\nset-cookie: route=8f14e45fceea167a5a36dedd4bea2543; Path=/\n\n`;
    const got = evaluate(s(1) + s(2)).findings.map(f => f.ruleId);
    expect(got).not.toContain('C-07.2');
    expect(got).not.toContain('C-02.1');
  });
});

describe('第50回：暗号化した Cookie と解析用の Cookie', () => {
  const lv = (iv: string, value = 'U2Vzc2lvbklEZml4ZWRWYWx1ZUFBQUFBQUFBQUFBQUFBQUFB') => Buffer.from(JSON.stringify({ iv, value, mac: 'a'.repeat(64), tag: '' })).toString('base64');
  const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('C-09：Laravel の暗号化したセッションCookie は、値が変わっても再発行したとはみなさない（na）', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, 'HTTP/2 200', `set-cookie: laravel_session=${lv('MTIzNDU2Nzg5MDEyMzQ1Ng==')}; path=/; secure; httponly; samesite=lax`, '', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', `set-cookie: laravel_session=${lv('OTg3NjU0MzIxMDk4NzY1NA==')}; path=/; secure; httponly; samesite=lax`, '', ''].join('\n');
    expect(c09(input)).toEqual(['C-09.na']);
  });
  it('C-09：暗号化していない Cookie を新しくしたログインは、これまでどおり合格', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, 'HTTP/2 200', 'set-cookie: sessionid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', 'set-cookie: sessionid=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(c09(input)).toEqual(['C-09.ok']);
  });
  it('C-09：送っただけの解析用の Cookie（_hjSession・ai_session）では na にしない', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, '* Connected to www.example.com (192.0.2.1) port 443', '> GET /login HTTP/2',
      '> Cookie: _hjSessionUser_123=eyJpZCI6IjEifQ; _hjSession_123=eyJpZCI6IjIifQ; ai_session=abc|1|2; JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '>', '< HTTP/2 200', '<', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', 'set-cookie: JSESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(c09(input)).toEqual(['C-09.ok']);
  });
  it('C-07②：暗号化した Cookie は、値から推測可能性を判定しない（na）', () => {
    const s = (i: number) => `#TARGET url=https://www.example.com/login label=session-sample-${i}\n${AT}\nHTTP/2 302\nlocation: /\nset-cookie: laravel_session=${lv(`aXY${i}aXY${i}aXY${i}aXY${i}`)}; path=/; secure; httponly\n\n`;
    expect(evaluate(s(1) + s(2)).findings.filter(f => f.item === 'C-07' && f.target === 'session-sample-*').map(f => f.ruleId)).toEqual(['C-07.na']);
  });
  it('C-09：送っただけの classic ASP の ASPSESSIONID… を再発行せず、別の Cookie だけを発行したログインは na', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, '* Connected to www.example.com (192.0.2.1) port 443', '> GET /login HTTP/2',
      '> Cookie: ASPSESSIONIDQASDRTBC=AAAAAAAAAAAAAAAAAAAAAAAA', '>', '< HTTP/2 200', '< set-cookie: auth_token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '<', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', 'set-cookie: auth_token=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(c09(input)).toEqual(['C-09.na']);
  });
});

describe('第51回：主のセッションIDの名前・期限の Cookie', () => {
  const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login').map(f => f.ruleId);
  it('C-09①：__Host-sid・connect.sid を同じ値で送り直し、別の Cookie を発行しただけのログインは①', () => {
    for (const name of ['__Host-sid', 'connect.sid']) {
      const v = 'a'.repeat(64);
      const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, 'HTTP/2 200', `set-cookie: ${name}=${v}; Path=/; Secure; HttpOnly; Max-Age=86400`, '', '',
        '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', `set-cookie: ${name}=${v}; Path=/; Secure; HttpOnly; Max-Age=86400`,
        'set-cookie: visitor_id=Q2x8BBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n');
      expect(c09(input), name).toEqual(['C-09.1']);
    }
  });
  it('C-09：送っただけの connect.sid を再発行せず、auth_token だけを発行したログインは na', () => {
    const input = ['#TARGET url=https://www.example.com/login label=pre-login', AT, '* Connected to www.example.com (192.0.2.1) port 443', '> GET /login HTTP/2',
      '> Cookie: connect.sid=s%3AAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '>', '< HTTP/2 200', '<', '',
      '#TARGET url=https://www.example.com/login label=login', AT, 'HTTP/2 302', 'location: /home', 'set-cookie: auth_token=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n');
    expect(c09(input)).toEqual(['C-09.na']);
  });
  it('期限・時刻の Cookie（grafana_session_expiry・last_login）はセッションIDとしない。SESSIONID の数字の値はこれまでどおり', () => {
    const page = (c: string) => evaluate(`#TARGET url=https://www.example.com/ label=top\n${AT}\nHTTP/2 200\nset-cookie: ${c}\n\n`).ids('top').filter(i => i.startsWith('C-02'));
    expect(page('grafana_session_expiry=1763460007; Path=/; Max-Age=2592000; Secure; SameSite=Lax')).toEqual([]);
    expect(page('last_login=1731900000; Path=/; Secure')).toEqual([]);
    expect(page('SESSIONID=1731900000; Path=/; Secure')).toContain('C-02.1');
  });
  it('（束のレビュー）時刻の語のない名前の Unix 時刻の形の値（auth=1000000001）はセッションIDとして判定し、キャメルケースの sessionExpiry は除く', () => {
    const page = (c: string) => evaluate(`#TARGET url=https://www.example.com/ label=top\n${AT}\nHTTP/2 200\nset-cookie: ${c}\n\n`).ids('top').filter(i => i.startsWith('C-02'));
    expect(page('auth_token=1000000042; Path=/; Secure')).toContain('C-02.1');
    expect(page('sessionExpiry=1763460007; Path=/')).toEqual([]);
    const s = (i: number) => `#TARGET url=https://www.example.com/login label=session-sample-${i}\n${AT}\nHTTP/2 302\nlocation: /\nset-cookie: auth=100000000${i}; Path=/; Secure; HttpOnly\n\n`;
    expect(evaluate(s(1) + s(2) + s(3)).findings.filter(f => f.item === 'C-07' && f.target === 'session-sample-*' && f.status === 'fail').length).toBeGreaterThan(0);
  });
});
