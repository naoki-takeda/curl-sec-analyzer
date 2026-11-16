// 横断的なマスキングのテスト：既知の秘密情報を入力のあらゆる場所に置き、どの出力にも現れないことを確かめる
import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { coverage } from '../src/engine/coverage';
import { overall } from '../src/engine/summarize';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toMarkdown } from '../src/export/markdown';
import { toJson } from '../src/export/json';
import { toCsv } from '../src/export/csv';
import { harTargets, importHar } from '../src/parser/har';
import { maskText, TOKEN_PARAM_NAMES, SESSION_PARAM_NAMES } from '../src/mask';

// それぞれ固有の文字列にして、どこから漏れたかを特定できるようにする
const S = {
  jwtParam: 'S1jwtparamVALUE0001', sessionParam: 'S2sessparamVALUE0002', fragment: 'S3fragmentTOKEN0003', jsession: 'S4JSESSIONVALUE0004',
  cookie: 'S5cookievalue00000000000000000005', bearer: 'S6opaqueBearerToken0006', akia: 'AKIAS7S7S7S7S7S7S7S7', dbpass: 'S8dbPassw0rd0008',
  envSecret: 'S9envSECRET0009', nonce: 'S15nonceVALUE0015xyz', shortNonce: 'S16nc', code: 'S10authCODE0010', urlPass: 'S11urlPASS0011', refresh: 'S12refreshTOKEN00000012', clientSecret: 'S13clientSECRET0013',
};
const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTMTRqd3RTVUJKRUNUIn0.S14signature0014';
const b64 = (s: string) => Buffer.from(s).toString('base64');

const INPUT = `#TARGET url=https://www.example.com/cb?jwt=${S.jwtParam}&session=${S.sessionParam}&code=${S.code} label=top
* Connected to www.example.com (192.0.2.1) port 443
> GET /cb HTTP/2
> Authorization: Bearer ${S.bearer}
> Cookie: sid=${S.cookie}
>
< HTTP/2 302
< location: https://app.example.com/done#access_token=${S.fragment}&state=x
< set-cookie: sid=${S.cookie}; Path=/
< set-cookie: tok=${jwt}; Path=/
<
#TARGET url=https://www.example.com/login label=login
HTTP/2 302
location: /home;jsessionid=${S.jsession}?client_secret=${S.clientSecret}
set-cookie: JSESSIONID=${S.cookie}; Path=/

#TARGET url=https://www.example.com/x label=open-redirect
HTTP/2 302
location: https://user:${S.urlPass}@evil.example/?session=${S.sessionParam}

#TARGET url=https://www.example.com/page label=page
HTTP/2 200
content-type: text/html; charset=utf-8
content-security-policy: script-src 'nonce-${S.nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'

<script>var k="${S.akia}"; var t="${jwt}";</script><a href="http://app.internal/x?token=${S.jwtParam}">x</a>
#TARGET url=https://www.example.com/short label=short
HTTP/2 200
content-type: text/html
content-security-policy: script-src 'nonce-${S.shortNonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'

#TARGET url=https://www.example.com/err label=error-db
HTTP/1.1 500 Error
content-type: text/plain

jdbc:mysql://db:3306/app?user=app&password=${S.dbpass}
#TARGET url=https://www.example.com/api/me label=api sensitive=1
HTTP/2 200
content-type: application/json

{"id":1,"refresh_token":"${S.refresh}","password":"${S.dbpass}"}
#TARGET url=https://www.example.com/ label=probes
#PROBE path=/.env code=200 size=40 head=${b64(`APP_SECRET=${S.envSecret}\n`)} ct=text/plain
`;

const HAR = JSON.stringify({ log: { entries: [
  { request: { method: 'POST', url: `https://www.example.com/login?token=${S.jwtParam}`, headers: [{ name: 'authorization', value: `Bearer ${S.bearer}` }],
               postData: { mimeType: 'application/x-www-form-urlencoded', text: `u=a&p=${S.dbpass}` } },
    response: { status: 302, headers: [{ name: 'set-cookie', value: `sid=${S.cookie}; Path=/` }, { name: 'location', value: `/home#access_token=${S.fragment}` }], content: { mimeType: '', text: '' } } },
] } });

function everyOutput(): string {
  const { targets } = parseInput(INPUT);
  const fromHar = harTargets(importHar(HAR), new Set(['www.example.com'])).targets;
  const all = [...targets, ...fromHar];
  const fs = runAll(all);
  const cov = coverage(fs, IMPLEMENTED);
  return [JSON.stringify(fs), JSON.stringify(overall(fs)), toMarkdown(fs, cov, []), toJson(fs, cov, []), toCsv(fs, all), ...all.map(t => maskText(t.url ?? ''))].join('\n');
}

describe('マスキング（横断）', () => {
  const out = everyOutput();
  for (const [name, secret] of Object.entries({ ...S, jwtPayload: 'eyJzdWIiOiJTMTRqd3RTVUJKRUNUIn0', jwtSig: 'S14signature0014' }))
    it(`${name} はどの出力にも現れない`, () => expect(out).not.toContain(secret));

  it('検出に使うパラメータ名は、すべてマスクの対象になっている', () => {
    for (const n of [...TOKEN_PARAM_NAMES, ...SESSION_PARAM_NAMES]) {
      expect(maskText(`https://a.example/?${n}=SECRETVALUE123`)).not.toContain('SECRETVALUE123');
      expect(maskText(`https://a.example/#${n}=SECRETVALUE123`)).not.toContain('SECRETVALUE123');
    }
    expect(maskText('https://a.example/x;jsessionid=SECRETVALUE123')).not.toContain('SECRETVALUE123');
  });

  it('nonce は値を隠し、長さは残す（H-04⑥の判断材料）', () => {
    expect(out).toContain("'nonce-…(5 chars)'");
  });
  it('マスクしても、どの指摘かは分かる（A-02・C-09②・E-03 が出ている）', () => {
    expect(out).toContain('A-02.1');
    expect(out).toContain('C-09.2');
    expect(out).toContain('一致したパターン: dotenv');
  });
});

describe('二重減点の除去', () => {
  it('API応答では nosniff なし・CSP なしを A-09 だけで数え、カバレッジでは判定済みにする', () => {
    const fs = runAll(parseInput('#TARGET url=https://a.example/api label=top\nHTTP/2 200\ncontent-type: application/json\n\n{}\n').targets);
    const fails = fs.filter(f => f.status === 'fail').map(f => f.ruleId);
    expect(fails).toEqual(expect.arrayContaining(['A-09.2', 'A-09.3']));
    expect(fails).not.toContain('H-08.1');
    expect(fails).not.toContain('H-03.1');
    expect(fs.find(f => f.ruleId === 'H-08.1')?.dedupedBy).toBe('A-09.2');
    expect(coverage(fs, IMPLEMENTED).find(c => c.item === 'H-08')?.status).toBe('evaluated');
  });
  it('HTML応答では H-08 をそのまま数える', () => {
    const fs = runAll(parseInput('#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\n').targets);
    expect(fs.filter(f => f.status === 'fail').map(f => f.ruleId)).toContain('H-08.1');
  });
});
