// 性質のテスト（fast-check）：マスクと突き合わせのキーが守ることを、決めた入力の例ではなく、作った入力の全体で確かめる。
// 第22回〜第27回のどの回でも、直前の回の修正が、例で確かめていなかった入力で退行を入れた（キーへの秘密の漏れ、#META cmd= のオプションの値の漏れ）。
// 例のテストは、その例しか守らない。ここでは次の性質を、毎回ちがう入力で確かめる：
// - キー：もう一度かけても変わらない／値を持たない（値を変えてもキーが変わらない）／パスのトークンはキーに入らない／順番で変わらない／
//   マスク（mask.ts）に依存しない
// - マスク：もう一度かけても変わらない／秘密の置き場所にある値は出さない／コマンドのオプションの順番を変えても秘密を出さない
import { readFileSync } from 'node:fs';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { clip, maskText } from '../src/mask';
import { summarizeCommand } from '../src/export/cmdSummary';
import { legacyHarKey, targetKeys, urlKey } from '../src/engine/targetKey';
import { parseInput } from '../src/parser/input';
import { analyze } from './golden/analyze';

// 回数は FC_RUNS 倍にできる（手元で多く回して探すとき。CI は既定の回数）
const MULT = Number(process.env.FC_RUNS) || 1;
const RUNS = { numRuns: 300 * MULT };

// ---- 入力の部品 ----
/** 秘密のトークン（英大文字・小文字・数字をすべて含む16〜40文字）。キーでもマスクでも、どこに置いても出てはいけない形 */
const token = fc.stringMatching(/^[A-Za-z0-9]{16,40}$/).filter(t => /\d/.test(t) && /[a-z]/.test(t) && /[A-Z]/.test(t));
/**
 * 乱数で作ったトークン（文字を偏りなく選ぶ）。画面のマスクがパスの部分を伏せるかは、語と数字をつないだ名前（MyCompanyLogo2026Final）と
 * 見分けて決めるので、偏った文字の並び（abaaAbabaabaa000…。fast-check はこういう端の値を好んで作る）は名前とみなして残しうる
 * （第26回で「判断が要るもの」とした、10万個に数個の残り）。秘密の置き場所の性質は、実際のトークンの形で確かめる
 */
const randomToken = fc.noBias(token);
/** トークンが出ていないか：8文字の窓のどれも出力に含まれない（画面のマスクが残す先頭の4文字は窓より短い） */
const leaks = (out: string, t: string) => { for (let i = 0; i + 8 <= t.length; i++) if (out.includes(t.slice(i, i + 8))) return t.slice(i, i + 8); return undefined; };
const word = fc.constantFrom('reset', 'login', 'api', 'v2', 'users', 'AdminDashboard', 'docs', 'index.html', 'app.js', '2026-annual-report-v2', 'x64', '123', 'search');
const paramName = fc.constantFrom('q', 'token', 'code', 'state', 'page', 'sort', 'lang', 'redirect_uri', 'next', 'id', 'access_token', 'utm_source', 'offset', 'type',
  'user[password]', 'api%5Fkey', 'filter.name', 'X-Amz-Signature', 'ids[]');
const host = fc.constantFrom('a.example', 'www.example.com', 'api.example.co.jp:8443', 'localhost:8080', 'xn--r8jz45g.example', '例え.jp', '[::1]:8443', '192.0.2.1');

/** 構造から作る URL。値（クエリ・フラグメント・ユーザー情報・パス引数）とパスのトークンは、あとで差し替えられるように関数にする */
interface UrlShape { scheme: string; host: string; path: (string | { tok: number; prefix: string; suffix: string })[]; query: [string, number][]; frag: boolean; user: boolean; pathParam: boolean; }
const urlShape = fc.record<UrlShape>({
  scheme: fc.constantFrom('https', 'http'), host,
  path: fc.array(fc.oneof(word, fc.record({ tok: fc.nat(3), prefix: fc.constantFrom('', 'reset-', 'login_', 'x.', 'a%2F', '~', '('), suffix: fc.constantFrom('', '.pdf', '-v2', '.json', '%2Fx', ')', '~1') })), { maxLength: 5 }),
  query: fc.array(fc.tuple(paramName, fc.nat(3)), { maxLength: 5 }), frag: fc.boolean(), user: fc.boolean(), pathParam: fc.boolean(),
});
const buildUrl = (s: UrlShape, toks: string[]) => {
  const v = (i: number) => toks[i % toks.length];
  const path = s.path.map(p => (typeof p === 'string' ? p : `${p.prefix}${v(p.tok)}${p.suffix}`)).join('/');
  const q = s.query.length ? `?${s.query.map(([n, i]) => `${n}=${v(i)}`).join('&')}` : '';
  return `${s.scheme}://${s.user ? `alice:${v(1)}@` : ''}${s.host}/${path}${s.pathParam ? `;jsessionid=${v(2)}` : ''}${q}${s.frag ? `#${v(3)}` : ''}`;
};
const toks4 = fc.array(token, { minLength: 4, maxLength: 4 });

describe('突き合わせのキー（engine/targetKey.ts）の性質', () => {
  it('マスク（mask.ts）を読み込まない（マスクを変えてもキーが変わらないように）', () => {
    const src = readFileSync(new URL('../src/engine/targetKey.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/from ['"][./]*mask['"]/);
  });

  it('もう一度かけても変わらない（以前の形式のキーの見分けがこれに頼る）', () => {
    const anyUrl = fc.oneof(
      fc.tuple(urlShape, toks4).map(([s, t]) => buildUrl(s, t)),
      fc.webUrl({ withQueryParameters: true, withFragments: true }),
      fc.string().map(s => `https://a.example/${s}`),
      fc.string().map(s => `/${s}`),
      fc.stringMatching(/^[/.\\a-z]{0,12}$/),   // 相対のパス（/.//b、.//b、//cdn…）
      fc.constantFrom('https://a.example/(S(lit3py55t21z5v55vlm25s55))/default.aspx', 'https://a.example/x?=1&&q', 'https://a.example/a%2Fb%252F/c', '/x;a=1;b=2?z=1&a=2'));
    fc.assert(fc.property(anyUrl, u => {
      const k = urlKey(u);
      expect(urlKey(k)).toBe(k);
      expect(legacyHarKey(`HAR GET ${k}`)).toBe(false);
    }), RUNS);
  });

  it('値を持たない：クエリ・フラグメント・ユーザー情報・パス引数の値とパスのトークンを差し替えてもキーは同じで、トークンはキーに出ない', () => {
    fc.assert(fc.property(urlShape, toks4, toks4, (s, a, b) => {
      const ka = urlKey(buildUrl(s, a));
      expect(urlKey(buildUrl(s, b))).toBe(ka);
      for (const t of a) expect(leaks(ka, t)).toBeUndefined();
    }), RUNS);
  });

  it('クエリのパラメータの順番で変わらない', () => {
    const pair = fc.tuple(paramName, fc.oneof(token, fc.constantFrom('1', '2', 'asc', 'desc', 'ja', 'en', '')));
    fc.assert(fc.property(fc.array(pair, { maxLength: 6 }), fc.infiniteStream(fc.nat()), (ps, rnd) => {
      const it2 = rnd[Symbol.iterator]();
      const shuffled = ps.map(p => [it2.next().value as number, p] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
      const u = (xs: typeof ps) => `https://a.example/x?${xs.map(([n, v]) => `${n}=${v}`).join('&')}`;
      expect(urlKey(u(shuffled))).toBe(urlKey(u(ps)));
    }), RUNS);
  });

  it('貼り付けたターゲットの順番で、キーの集まりが変わらない', () => {
    const block = fc.tuple(fc.constantFrom('top', 'login', 'api'), fc.constantFrom('https://a.example/', 'https://a.example/x?page=1', 'https://a.example/x?page=2', 'https://b.example/'));
    fc.assert(fc.property(fc.array(block, { minLength: 1, maxLength: 6 }), fc.infiniteStream(fc.nat()), (bs, rnd) => {
      const it2 = rnd[Symbol.iterator]();
      const shuffled = bs.map(b => [it2.next().value as number, b] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
      const text = (xs: typeof bs) => xs.map(([l, u]) => `#TARGET url=${u} label=${l}\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n`).join('');
      const keys = (xs: typeof bs) => targetKeys(parseInput(text(xs)).targets).sort();
      expect(keys(shuffled)).toEqual(keys(bs));
    }), RUNS);
  });
});

describe('マスク（mask.ts）の性質', () => {
  /** 秘密の置き場所。t がトークン */
  const placements: ((t: string) => string)[] = [
    t => `https://a.example/cb?token=${t}`, t => `https://a.example/cb?x=1&password=${t}`, t => `https://a.example/#access_token=${t}&x=1`,
    t => `/app/index.jsp;jsessionid=${t}`, t => `?next=%2Fcb%3Ftoken%3D${t}`, t => `"url":"\\/cb?x=1\\u0026token=${t}"`, t => `<a href="/cb?x=1&amp;secret=${t}">`,
    t => `{"password":"${t}"}`, t => `{\\"client_secret\\":\\"${t}\\"}`, t => `https://alice:${t}@a.example/`, t => `https://a.example/reset/${t}`,
    t => `https://a.example/reset/${t}.pdf`, t => `<form action="/magic/${t}">`, t => `Location: /invite/${t}?x=1`,
    t => `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.${t}`, t => `script-src 'nonce-${t}'`, t => `https://a.example/(S(${t}))/default.aspx`,
  ];
  const context = fc.constantFrom('', ' ', '証跡：', 'see ', '"', "'", '(', '、', '\n', 'x ', 'Location: ', '<', '[', 'src=', '\\"', '%22');
  const after = fc.constantFrom('', ' ', '"', "'", ')', '。', '\n', ' end', '&y=2', ',', '詳しくは担当まで', '>', ']', '\\', '#x', ';', '%26y%3D2', '\\u0026y=2');

  it('秘密の置き場所にある値は出さない（前後の文字を変えても）', () => {
    fc.assert(fc.property(fc.nat(placements.length - 1), randomToken, context, after, (i, t, pre, post) => {
      const out = maskText(`${pre}${placements[i](t)}${post}`);
      expect(leaks(out, t), out).toBeUndefined();
    }), RUNS);
  });

  it('もう一度かけても変わらない', () => {
    const piece = fc.oneof(
      fc.tuple(fc.nat(placements.length - 1), token).map(([i, t]) => placements[i](t)),
      fc.constantFrom('…(32 chars)', 'abcd…(40 chars)', '?code=', '&', '=', '%3D', '%26', '\\u0026', "'nonce-", 'nonce-', '"', '\\"', ':', '/', '//', '%2F', '#', ';',
        'eyJ', '.', '_', '-', ' ', '\n', '日本語', 'https://a.example/', 'token', 'state=', 'sha256-'),
      fc.string({ maxLength: 8 }), token);
    fc.assert(fc.property(fc.array(piece, { maxLength: 8 }), ps => {
      const once = maskText(ps.join(''));
      expect(maskText(once)).toBe(once);
    }), { numRuns: 1000 * MULT });
  });

  it('切り詰め（clip）は秘密を出さず、伏せた値の印の途中で切らない', () => {
    fc.assert(fc.property(fc.nat(placements.length - 1), randomToken, context, after, fc.integer({ min: 1, max: 80 }), (i, t, pre, post, n) => {
      const out = clip(`${pre}${placements[i](t)}${post}`, n);
      expect(leaks(out, t), out).toBeUndefined();
      expect(out, out).not.toMatch(/…(?:\((?:\d+(?: (?:c(?:h(?:a(?:rs?)?)?)?)?)?)?)?$/);
    }), RUNS);
  });
});

describe('#META cmd= のコマンド（summarizeCommand）の性質', () => {
  /** 秘密を持つオプション（t が秘密）。#META の値に空白を入れられないので「_」で区切って書く形も作る */
  const secretOpts: ((t: string) => string[])[] = [
    t => ['-u', `alice:${t}`], t => ['--user', `alice:${t}`], t => [`-ualice:${t}`], t => ['-sSu', `alice:${t}`], t => ['--proxy-user', `p:${t}`],
    t => ['-H', `Authorization: Bearer ${t}`], t => ['-H', `Cookie: sid=${t}`], t => ['--header', `X-Api-Key: ${t}`], t => ['-b', `sid=${t}`],
    t => ['--cookie', `session=${t}`], t => ['--oauth2-bearer', t], t => ['-d', `password=${t}`], t => ['--data-raw', `user=a&token=${t}`],
    t => ['--url-query', `token=${t}`], t => ['--variable', `KEY=${t}`], t => ['-E', `client.pem:${t}`], t => ['--tlspassword', t],
    t => [`--user=alice:${t}`], t => [`--header=Authorization: Bearer ${t}`], t => ['-F', `token=${t}`], t => ['--json', `{"password":"${t}"}`],
    t => ['--data-urlencode', `secret=${t}`], t => [`-HAuthorization: Bearer ${t}`], t => ['-H', `Authorization:Basic ${t}`],
    t => ['-H', `X-Auth-Token: ${t}`], t => ['--proxy-header', `Proxy-Authorization: Basic ${t}`], t => [`https://alice:${t}@a.example/`],
    t => [`https://a.example/cb?access_token=${t}`],
    // 値の中に、ほかのオプションの書き方に似た「_-Hz:」「_-ux:」を含むもの（パスワードや Cookie の値）
    t => ['-u', `alice:pa_-Hz:${t}`], t => ['-b', `sid=Ab12_-Hx:${t}`], t => ['-d', `password=pa_-Hz:${t}`], t => ['-H', `Authorization: Bearer tok_-Hx:${t}`],
    t => ['-u', `alice:pa_-ux:${t}`],
  ];
  const plainOpts: string[][] = [['-X', 'POST'], ['-sS'], ['-L'], ['-k'], ['--compressed'], ['-i'], ['-v'], ['--max-time', '10'], ['-A', 'ua/1.0'],
    ['-H', 'Accept: */*'], ['-o', 'out.txt'], ['--http1.1'], ['-e', 'https://a.example/'], ['-w', '%{http_code}'], ['https://a.example/login'],
    ['-H', 'Authorization:'], ['-H', 'Cookie:']];   // 値のないヘッダ（curl でヘッダを消す書き方）

  const cmd = fc.record({
    secrets: fc.array(fc.tuple(fc.nat(secretOpts.length - 1), token), { minLength: 1, maxLength: 3 }),
    plain: fc.subarray(plainOpts, { maxLength: 6 }),
    order: fc.infiniteStream(fc.nat()),
    sep: fc.constantFrom(' ', '_'),
    quote: fc.boolean(),
    client: fc.constantFrom('curl', 'curl.exe', '/usr/bin/curl', 'C:\\Windows\\System32\\curl.exe'),
  });
  const render = (c: { client: string; secrets: [number, string][]; plain: string[][]; order: fc.Stream<number>; sep: string; quote: boolean }) => {
    const opts = [...c.secrets.map(([i, t]) => secretOpts[i](t)), ...c.plain];
    const it2 = c.order[Symbol.iterator]();
    const shuffled = opts.map(o => [it2.next().value as number, o] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
    const arg = (a: string) => (c.sep === ' ' && c.quote && a.includes(' ') ? `"${a}"` : a.replace(/ /g, c.sep));
    return `${c.client}${c.sep}${shuffled.map(o => o.map(arg).join(c.sep)).join(c.sep)}`;
  };

  it('オプションの順番と区切り（空白・「_」）を変えても、秘密を出さない', () => {
    fc.assert(fc.property(cmd, c => {
      const s = render(c);
      const out = summarizeCommand(s);
      for (const [, t] of c.secrets) expect(leaks(out, t), `${s}\n→ ${out}`).toBeUndefined();
      // 秘密を持たない URL は残す（値のないヘッダのあとの URL を、ヘッダの値として伏せない）。前に値を取るオプションがあると、その値になりうるので見ない。
      // 空白で区切ったものだけを見る。「_」で区切った書き方では、URL・ua/1.0 のパスの部分やクエリの値が後ろの引数まで続く
      // （伏せすぎで、漏れはしない。第28回の「未対応」）。前にクエリのある URL があるときも見ない。
      // URL のあとに @ があるとき（https://alice:…@a.example/ をあとに置いたもの）は、ユーザー情報の途中で切れた URL と見分けないので伏せる（第33回）
      const i = s.indexOf('https://a.example/login');
      if (c.sep === ' ' && i > 0 && !s.slice(i).includes('@') && !/[?&]/.test(s.slice(0, i)) &&/(?:^|[\s_])(?:curl|curl\.exe|\\curl\.exe)[\s_]$|[\s_]-H[\s_](?:Authorization|Cookie):[\s_]$|[\s_]-(?:sS|L|k|i|v)[\s_]$|--(?:compressed|http1\.1)[\s_]$|(?:POST|10|ua\/1\.0|\*\/\*|out\.txt|%\{http_code\})[\s_]$/.test(s.slice(0, i)))
        expect(out, `${s}\n→ ${out}`).toContain('https://a.example/login');
    }), { numRuns: 1000 * MULT });
  });

  it('もう一度かけても変わらない', () => {
    fc.assert(fc.property(cmd, c => {
      const once = summarizeCommand(render(c));
      expect(summarizeCommand(once)).toBe(once);
    }), RUNS);
  });
});

describe('判定の結果の性質', () => {
  it('貼り付けたターゲットの順番を変えても、指摘（ルールID・キー・状態・重要度）の集まりが変わらない', () => {
    const header = fc.constantFrom('Strict-Transport-Security: max-age=31536000', 'Content-Security-Policy: default-src \'self\'', 'X-Content-Type-Options: nosniff',
      'X-Frame-Options: DENY', 'Set-Cookie: sid=abc123def456ghi789; Path=/', 'Set-Cookie: sid=abc123def456ghi789; Path=/; Secure; HttpOnly; SameSite=Lax',
      'Server: Apache/2.4.1', 'Cache-Control: no-store', 'Access-Control-Allow-Origin: *');
    const block = fc.record({
      label: fc.constantFrom('top', 'login', 'api', 'http', 'apex'),
      url: fc.constantFrom('https://a.example/', 'https://a.example/login', 'http://a.example/', 'https://example.com/', 'https://a.example/api/x'),
      status: fc.constantFrom('200 OK', '302 Found', '404 Not Found'),
      headers: fc.subarray(['Content-Type: text/html'], { minLength: 0 }).chain(ct => fc.array(header, { maxLength: 4 }).map(h => [...ct, ...h])),
    });
    fc.assert(fc.property(fc.array(block, { minLength: 1, maxLength: 4 }), fc.infiniteStream(fc.nat()), (bs, rnd) => {
      const it2 = rnd[Symbol.iterator]();
      const shuffled = bs.map(b => [it2.next().value as number, b] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
      const text = (xs: typeof bs) => xs.map(b => `#TARGET url=${b.url} label=${b.label}\nHTTP/1.1 ${b.status}\n${b.status.startsWith('302') ? 'Location: /login\n' : ''}${b.headers.join('\n')}\n\n`).join('');
      // 同じラベルの付け直し（top と top#2）は入力の順番で決まるので、ラベルではなくキーで比べる。同じラベルで同じ URL のターゲットは
      // キーでも見分けられず、「 #2」は入力の順番で付く（engine/targetKey.ts）ので、番号を除いた集まりで比べる
      const result = (xs: typeof bs) => analyze(text(xs)).findings
        .map(f => `${f.ruleId} | ${(f.targetKey ?? f.target).replace(/#\d+$/, '').trim()} | ${f.status} | ${f.severity}`).sort();
      expect(result(shuffled)).toEqual(result(bs));
    }), { numRuns: 200 * MULT });
  // 単独で約1.5秒。ほかのテストと並べて流すと既定の5秒を超えることがあった（第48回。4000回試しても反例はなかった）
  }, 30_000);
});
