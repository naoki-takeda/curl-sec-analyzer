// 本文を採取していない応答の扱い（A1：C-09①の誤検知、A2：本文のない HTML の [] とカバレッジの注記）
import { describe, expect, it } from 'vitest';
import { generateScript } from '../src/commands';
import { coverage, someTargets } from '../src/engine/coverage';
import { mergeNa } from '../src/engine/summarize';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { recommendationEn } from '../src/recommendationsEn';
import { NO_BODY_REC } from '../src/rules/util';
import { AT, evaluate, GEN_OPTS, RUN } from './helpers';

const PRE = ['#TARGET url=https://a.example/login label=pre-login', AT, 'HTTP/2 200', 'content-type: text/html',
  'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '', ''];
const c09 = (input: string) => evaluate(input).findings.filter(f => f.item === 'C-09' && f.target === 'pre-login/login');

describe('A1 C-09：本文を採取していない 2xx のログインは、①（高）にしない', () => {
  it('-v -o /dev/null の 200 で、新しいセッションIDがない → na（本文を採取し直す案内）', () => {
    const r = c09([...PRE, '#TARGET url=https://a.example/login label=login sensitive=1', AT,
      '* Connected to a.example (192.0.2.1) port 443', '> POST /login HTTP/2', '> Host: a.example', '>', '< HTTP/2 200', '< content-type: text/html', '<', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.na']);
    expect(r[0].recommendation).toBe(NO_BODY_REC);
    expect(r[0].evidence).toContain('本文を採取していない');
  });
  it('本文のある 200 で、パスワード欄のない画面を返し、新しいセッションIDがない → ①（高）のまま', () => {
    const r = c09([...PRE, '#TARGET url=https://a.example/login label=login sensitive=1', AT,
      'HTTP/2 200', 'content-type: text/html', '', '<h1>ようこそ</h1>', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.1']);
  });
  it('本文のある 200 で、パスワード欄のある画面を返し直した（失敗） → na（ログインに失敗）', () => {
    const r = c09([...PRE, '#TARGET url=https://a.example/login label=login sensitive=1', AT,
      'HTTP/2 200', 'content-type: text/html', '', '<form method="post"><input name="user"><input type="password" name="pw"></form>', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.na']);
    expect(r[0].evidence).toContain('ログインに失敗');
  });
  it('3xx は Location で見分けるので、本文がなくても①（高）のまま', () => {
    const r = c09([...PRE, '#TARGET url=https://a.example/login label=login sensitive=1', AT,
      'HTTP/2 302', 'location: /mypage', '', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.1']);
  });
  it('本文がなくても、新しいセッションIDを発行していれば合格', () => {
    const r = c09([...PRE, '#TARGET url=https://a.example/login label=login sensitive=1', AT,
      'HTTP/2 200', 'set-cookie: JSESSIONID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB; Path=/; Secure; HttpOnly', '', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.ok']);
  });
  it('生成スクリプトの #BODY の形で採取した login の、パスワード欄のある 200 を失敗と見分ける', () => {
    const r = c09([
      `#TARGET url=https://a.example/login label=pre-login run=${RUN}`, `${AT} run=${RUN}`, 'HTTP/2 200', 'content-type: text/html',
      'set-cookie: JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; Secure; HttpOnly', '',
      `#TARGET url=https://a.example/login label=login sensitive=1 run=${RUN}`, `${AT} run=${RUN}`, 'HTTP/2 200', 'content-type: text/html', '',
      `#BODY run=${RUN}`, '<form method="post"><input name="user"><input type="password" name="pw"></form>', ''].join('\n'));
    expect(r.map(f => f.ruleId)).toEqual(['C-09.na']);
    expect(r[0].evidence).toContain('ログインに失敗');
  });
});

describe('A1 生成スクリプト：login は本文も採取する', () => {
  const s = generateScript(GEN_OPTS);
  const loginLine = s.split('\n').find(l => l.includes('--data @login.txt') && !l.includes('s$i.txt'))!;
  it('ヘッダと本文を分けて取り、#BODY の印のあとに本文を出す', () => {
    expect(loginLine).toContain('-D "$hdr" -o "$body"');
    expect(loginLine).toContain('echo "#BODY run=$RUN"; head -c 196608 "$body"');
    expect(loginLine).toContain('-c jar.txt -b jar.txt -X POST');
    expect(loginLine).not.toContain('/dev/null');
  });
  it('pre-login は今までどおり -v（送った Cookie の名前を C-09 で使う）', () => {
    const pre = s.split('\n').findIndex(l => l.includes('label=pre-login'));
    // -b jar.txt は付けない（スクリプトの初めに jar.txt を消すので、-v の1行目に cookie file の警告が出る）
    expect(s.split('\n').slice(pre, pre + 3).join('\n')).toMatch(/curl .*-v -o \/dev\/null -c jar\.txt "\$H"/);
  });
});

describe('A2 本文のない 2xx の HTML では、本文の項目を na にする（[] は適用外だけ）', () => {
  const BODY_ITEMS = ['E-02', 'E-07', 'E-08', 'E-09', 'E-10', 'E-12'];
  const one = (head: string, extra = '') => evaluate(`#TARGET url=https://a.example/ label=page ${extra}\n${AT}\n${head}\n\n`)
    .findings.filter(f => BODY_ITEMS.includes(f.item));
  it('200 の text/html で本文なし → 6項目とも na（理由と推奨は同じ）', () => {
    const fs = one('HTTP/2 200\ncontent-type: text/html');
    expect(fs.map(f => f.ruleId).sort()).toEqual(BODY_ITEMS.map(i => `${i}.na`));
    expect(new Set(fs.map(f => `${f.evidence}|${f.recommendation}`))).toEqual(new Set([`本文を採取していない|${NO_BODY_REC}`]));
  });
  it('sensitive=0 なら E-12 は適用外のまま', () => {
    expect(one('HTTP/2 200\ncontent-type: text/html', 'sensitive=0').map(f => f.item)).not.toContain('E-12');
  });
  it('本文のある HTML は今までどおり判定する', () => {
    const fs = evaluate(`#TARGET url=https://a.example/ label=page\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<p>hi</p>\n`).findings.filter(f => BODY_ITEMS.includes(f.item));
    expect(fs.filter(f => f.status === 'na')).toEqual([]);
  });
  it('3xx・404・JSON の応答では、本文がなくても na を出さない（適用外）', () => {
    expect(one('HTTP/2 404\ncontent-type: text/html')).toEqual([]);
    expect(one('HTTP/2 200\ncontent-type: application/json')).toEqual([]);
    expect(one('HTTP/2 302\nlocation: /home\ncontent-type: text/html')).toEqual([]);
  });
});

describe('A2 画面：同じ理由の na を1行にまとめる', () => {
  it('証跡と推奨対応が同じ na だけをまとめ、fail・pass はそのまま', () => {
    const fs = evaluate(`#TARGET url=https://a.example/ label=page\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n`).findings.filter(f => f.target === 'page');
    const rows = mergeNa(fs);
    const body = rows.filter(r => r.evidence === '本文を採取していない');
    expect(body).toHaveLength(1);
    expect(body[0].items).toEqual(['E-02', 'E-07', 'E-08', 'E-09', 'E-10', 'E-12']);
    expect(rows.filter(r => r.status !== 'na')).toEqual(fs.filter(f => f.status !== 'na'));
    // na の行の数は、証跡と推奨対応の組の数
    const na = fs.filter(f => f.status === 'na');
    expect(rows.filter(r => r.status === 'na')).toHaveLength(new Set(na.map(f => `${f.evidence}|${f.recommendation}`)).size);
  });
});

describe('A2 カバレッジ：ターゲットごとの na の件数と理由を添える', () => {
  const input = [
    '#TARGET url=https://a.example/ label=page', AT, 'HTTP/2 200', 'content-type: text/html', '', '<p>hi</p>', '',
    '#TARGET url=https://a.example/about label=about', AT, 'HTTP/2 200', 'content-type: text/html', '', '',
    '#TARGET url=https://a.example/faq label=faq', AT, 'HTTP/2 200', 'content-type: text/html', '', ''].join('\n');
  const cov = coverage(evaluate(input).findings, IMPLEMENTED);
  it('本文のある HTML で判定済みの E-07 に、本文のない2件を示す', () => {
    const e07 = cov.find(c => c.item === 'E-07')!;
    expect(e07.status).toBe('evaluated');
    expect(e07.reasons).toEqual([someTargets(2), NO_BODY_REC]);
  });
  it('ほかの項目に任せた na（強制モードのCSPがない（H-03で判定））は入力不足に数えない', () => {
    const csp = '#TARGET url=https://a.example/x label=x\n' + AT + "\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy: script-src 'self'; object-src 'none'; base-uri 'none'\n\n<p>x</p>\n";
    const h07 = coverage(evaluate(`${input}${csp}`).findings, IMPLEMENTED).find(c => c.item === 'H-07')!;
    expect(h07.reasons.join('/')).not.toContain('一部のターゲット');
  });
  it('件数の注記は英訳できる', () => {
    expect(recommendationEn(someTargets(3))).toBe('Some targets (3) lack input');
  });
});

describe('E-04：本文を採取していない robots.txt・security.txt の 2xx は na', () => {
  const e04 = (url: string, head: string) => evaluate(`#TARGET url=${url} label=t\n${AT}\n${head}\n`).findings.filter(f => f.item === 'E-04');
  it('-I の 200（本文なし）→ na（本文を採取し直す案内）', () => {
    for (const url of ['https://a.example/robots.txt', 'https://a.example/.well-known/security.txt']) {
      const r = e04(url, 'HTTP/2 200\ncontent-type: text/plain\n');
      expect(r.map(f => f.ruleId), url).toEqual(['E-04.na']);
      expect(r[0].recommendation).toBe(NO_BODY_REC);
    }
  });
  it('2xx でない応答は、本文がなくても今までどおり判定する', () => {
    expect(e04('https://a.example/robots.txt', 'HTTP/2 404\n').map(f => f.ruleId)).toEqual(['E-04.ok']);
    expect(e04('https://a.example/.well-known/security.txt', 'HTTP/2 404\n').map(f => f.ruleId)).toEqual(['E-04.2']);
  });
});

describe('HAR のテキスト・XML の本文', () => {
  const har = (mime: string, text: string, status = 500) => JSON.stringify({ log: { entries: [{ startedDateTime: '2026-11-01T00:00:00Z',
    request: { method: 'GET', url: 'https://a.example/x', headers: [] },
    response: { status, httpVersion: 'HTTP/2', headers: [{ name: 'Content-Type', value: mime }], content: { mimeType: mime, text } } }] } });
  it('text/plain のスタックトレースは本文として読み、E-01② にする（「本文を採取していない」の na にしない）', async () => {
    const { analyze } = await import('./golden/analyze');
    const fs = analyze('', har('text/plain; charset=utf-8', 'Traceback (most recent call last):\n  File "/srv/app/main.py", line 41')).findings.filter(f => f.item === 'E-01');
    expect(fs.map(f => f.ruleId)).toEqual(['E-01.2']);
  });
  it('XML のエラー応答も本文として読む', async () => {
    const { analyze } = await import('./golden/analyze');
    const fs = analyze('', har('application/xml', '<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>', 404)).findings.filter(f => f.item === 'E-01');
    expect(fs.map(f => f.ruleId)).not.toContain('E-01.na');
  });
});

describe('HAR で残さない本文', () => {
  it('SVG と Office の文書（XML を含む種類名）の本文は残さない', async () => {
    const { importHar } = await import('../src/parser/har');
    for (const mime of ['image/svg+xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']) {
      const imp = importHar(JSON.stringify({ log: { entries: [{ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url: 'https://a.example/x', headers: [] },
        response: { status: 200, httpVersion: 'HTTP/2', headers: [], content: { mimeType: mime, text: '<svg/>' } } }] } }));
      expect(imp.chains[0].responses.at(-1)?.body, mime).toBeUndefined();
    }
  });
});

describe('本文がない 2xx の HTML（204・Content-Length: 0）は、本文を採取していない na にしない', () => {
  it('Content-Length: 0 の 200 → E-07 などは適用外', () => {
    const { ids } = evaluate('#TARGET url=https://a.example/ label=page\nHTTP/2 200\ncontent-type: text/html\ncontent-length: 0\n\n');
    expect(ids('page').filter(id => /^E-(?:02|07|08|09|10|12)\./.test(id))).toEqual([]);
  });
  it('-o /dev/null で本文を採取していない 200 → na のまま', () => {
    const { ids } = evaluate('#TARGET url=https://a.example/ label=page\nHTTP/2 200\ncontent-type: text/html\ncontent-length: 1234\n\n');
    expect(ids('page')).toContain('E-07.na');
  });
});
