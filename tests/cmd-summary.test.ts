// CSV の「実施コマンド」「実施日時」の要約（src/export/cmdSummary.ts）の性質のテスト（第31回）。
// 要約は残してよい形だけを残す（許可リスト）。ここでは、出る語がどれも決めた形のどれかであること（許可リストの外の語が出ないこと）と、
// 値の置き場所に置いた秘密が出ないことを、作った入力の全体で確かめる。許可する形は、実装とは別にここで書き下す
import { readFileSync } from 'node:fs';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { summarizeAt, summarizeCommand } from '../src/export/cmdSummary';
import { urlKey } from '../src/engine/targetKey';

const MULT = Number(process.env.FC_RUNS) || 1;
const RUNS = { numRuns: 500 * MULT };

const PROGRAMS = ['curl', 'wget', 'http', 'https', 'xh', 'xhs', 'httpie', 'openssl', 'nc', 'ncat', 'nmap', 'sslscan', 'testssl', 'testssl.sh', 'grep', 'jq', 'sed', 'awk',
  'head', 'tail', 'cat', 'echo', 'printf', 'base64', 'timeout', 'sudo', 'env', 'powershell', 'pwsh', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'dig',
  'nslookup', 'host', 'python', 'python3', 'node', 'bash', 'sh', 'egrep', 'sleep', 'date', 'tee', 'sort', 'uniq', 'wc', 'xargs'];
/** 出てよい語（実装とは別に書く） */
const allowedWord = (w: string): boolean =>
  /^(?:C\d{1,2}|HAR|-|\*{4}|\*{4}=\*{4}|…)$/.test(w)
  || PROGRAMS.includes(w)
  || /^(?:\|\|?|&&|;|&|>>?|<|2>&1|[12]?>\/dev\/null)$/.test(w)
  || /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)$/i.test(w)
  || /^(?:s_client|s_server|s_time|x509|req|ciphers|version|verify|rsa|ec|pkey|dgst)$/.test(w)
  || /^--?[A-Za-z][A-Za-z0-9._-]{0,31}(?:=\*{4}|\*{4})?$/.test(w)                    // オプションの名前（値は ****）
  || /^-[A-Za-z0-9#]{1,6}(?:\*{4})?$/.test(w)                                            // 短いオプション（-0・-#・-sSu****）
  || /^[A-Za-z][A-Za-z0-9_-]{0,40}(?::|:=|==|=)(?:\*{4})?$/.test(w)                  // ヘッダ・httpie の項目・環境変数の名前（値は ****）
  || (/^(?:https?|wss?|ftp):\/\//.test(w) && urlKey(w) === w);                         // URL はキーの形
const words = (out: string) => out.split('・').flatMap(c => c.split(' ')).filter(Boolean);

/**
 * 乱数の秘密：英大文字・小文字・数字を含む12〜32文字と、base64url（「-」「_」を含む。JWT の署名やセッションIDの形）の16〜43文字。
 * 出力に6文字の窓が1つでもあれば漏れ（「_」で区切って読むので、base64url の秘密はかけらに分かれる。かけらが出ないことも確かめる）
 */
const alnum = fc.noBias(fc.stringMatching(/^[A-Za-z0-9]{12,32}$/).filter(t => /\d/.test(t) && /[a-z]/.test(t) && /[A-Z]/.test(t)));
const b64url = fc.noBias(fc.stringMatching(/^[A-Za-z0-9_-]{16,43}$/).filter(t => /\d/.test(t) && /[a-z]/.test(t) && /[A-Z]/.test(t) && /[-_]/.test(t)));
const secret = fc.oneof(alnum, b64url);
/** 英字だけのユーザー名（7〜10文字）。値として出ないことを、そのまま含まれないかで確かめる */
const userName = fc.noBias(fc.stringMatching(/^[a-z]{7,10}$/));
const leaks = (out: string, t: string) => {
  const n = /[-_]/.test(t) ? 6 : 8;
  for (let i = 0; i + n <= t.length; i++) { const w = t.slice(i, i + n); if (!/^[-_]|[-_]$/.test(w) && out.includes(w)) return w; }
  return undefined;
};

/** 値の置き場所（t が秘密）。#META の値には空白を入れられないので、「_」で区切る形も作る */
const VALUE_PLACES: ((t: string) => string[])[] = [
  t => ['-u', `alice:${t}`], t => [`-ualice:${t}`], t => ['-sSu', `alice:${t}`], t => ['--user', `alice:${t}`], t => [`--user=alice:${t}`],
  t => ['-H', `Authorization: Bearer ${t}`], t => [`-HAuthorization: Bearer ${t}`], t => ['-H', `"Authorization: Bearer ${t}"`], t => ['-H', `Cookie: sid=${t}; lang=ja`],
  t => ['--header', `X-Api-Key: ${t}`], t => [`--header=X-Api-Key: ${t}`], t => ['-b', `sid=${t}`], t => ['--oauth2-bearer', t], t => ['-d', `password=${t}`],
  t => ['--data-raw', `user=a&token=${t}`], t => ['--json', `{"password":"${t}"}`], t => ['-F', `token=${t}`], t => ['--variable', `KEY=${t}`], t => ['-E', `cert.pem:${t}`],
  t => [`https://a.example/cb?access_token=${t}&x=1`], t => [`https://alice:${t}@a.example/`], t => [`https://a.example/reset/${t}`], t => [`https://a.example/x#${t}`],
  t => [`https://a.example/app;jsessionid=${t}`], t => ['-x', `alice:${t}@proxy:3128`], t => [`Authorization:Bearer_${t}`], t => [`api_key==${t}`], t => [`password=${t}`],
  t => [`X-Api-Key:${t}`], t => [t], t => [`'${t}'`], t => [`"a b ${t}"`], t => [`-${t}`], t => [`--${t.toLowerCase()}=${t}`],
  // 値の中に「_--」「_-」「==」「#」を含むもの（第31回のレビューで見つかった形）
  t => ['-u', `alice:my_--${t}`], t => ['-b', `sid=abc_-${t}`], t => [`X-Token:abc_${t}==`], t => [`https://alice:2024#${t}@a.example/`],
  t => ['-a', `alice:${t}`], t => ['--auth', `alice:${t}`], t => [`admin:${t}@localhost:5000/api`], t => ['--cert-key-pass', t],
];
/** ユーザー名の置き場所（u がユーザー名） */
const USER_PLACES: ((u: string) => string[])[] = [
  u => ['-u', `${u}:pw`], u => [`-u${u}:pw`], u => ['-a', `${u}:pw`], u => [`${u}:pw@localhost:5000/api`], u => [`https://${u}:pw@a.example/`],
  u => ['-x', `${u}:pw@proxy:3128`], u => [`https://${u}:12#pw@a.example/`], u => ['--user', u], u => [`${u}==x`], u => [`${u}:x`],
  // 「_」「.」「\」を含むユーザー名、数字で始まるパスワード、引用符を含むパスワード（第31回の2回目のレビューで見つかった形）
  u => [`https://svc_${u}:Passw0rd@api.example.com/v1`], u => [`https://${u}.ext_x:pw@h.example/`], u => ['-x', `http://proxy_${u}:Secret99@proxy.local:3128`],
  u => [`https://${u}:12345_x@a.example/`], u => [`https://${u}:"Secret 1"@h.example/`], u => [`https://CONTOSO\\${u}:Secret1@a.example/`],
  u => [`HTTPS://${u}_x:pw@a.example/`], u => [`ftp://${u}_adm:pw@ftp.example/data.tar`], u => [`https://a.example/reset?${u}`], u => [`https://a.example/x?sort=${u}`],
];
const PLAIN: string[][] = [['-sS'], ['-L'], ['-k'], ['--compressed'], ['-i'], ['-v'], ['-X', 'POST'], ['--max-time', '10'], ['-o', '/dev/null'], ['-w', '%{http_code}'],
  ['--http1.1'], ['-H', 'Accept: */*'], ['https://a.example/login'], ['|'], ['grep', '-i'], [';'], ['&&']];
const PROGRAM_HEADS = ['curl', 'curl.exe', '/usr/bin/curl', 'C:\\Windows\\System32\\curl.exe', '"C:\\Program Files\\curl\\bin\\curl.exe"', 'http POST', 'http', 'xh',
  'wget', 'HTTPS_PROXY=http://u:p@proxy:8080 curl', 'https_proxy=http://p:3128 curl', 'C3:curl', 'unknowncmd', 'openssl s_client', 'iwr', ''];

const command = fc.record({
  head: fc.constantFrom(...PROGRAM_HEADS),
  values: fc.array(fc.tuple(fc.nat(VALUE_PLACES.length - 1), secret), { minLength: 1, maxLength: 3 }),
  users: fc.array(fc.tuple(fc.nat(USER_PLACES.length - 1), userName), { maxLength: 2 }),
  plain: fc.subarray(PLAIN, { maxLength: 5 }),
  order: fc.infiniteStream(fc.nat()),
  sep: fc.constantFrom(' ', '_'),
});
const PATH_PLACE = VALUE_PLACES.findIndex(f => f('X')[0] === 'https://a.example/reset/X');
const render = (c: { head: string; values: [number, string][]; users: [number, string][]; plain: string[][]; order: fc.Stream<number>; sep: string }) => {
  // base64url の秘密は URL のパスに置かない（突き合わせのキーはパスの英字の語を残す。CSV の URL 列と同じで、設計のとおり）
  const parts = [...c.values.map(([i, t]) => VALUE_PLACES[i === PATH_PLACE && /[-_]/.test(t) ? 0 : i](t)), ...c.users.map(([i, u]) => USER_PLACES[i](u)), ...c.plain];
  const it2 = c.order[Symbol.iterator]();
  const shuffled = parts.map(p => [it2.next().value as number, p] as const).sort((x, y) => x[0] - y[0]).map(x => x[1]);
  const arg = (a: string) => (c.sep === ' ' ? a : a.replace(/ /g, '_'));
  return [c.head.replace(/ /g, c.sep), ...shuffled.map(p => p.map(arg).join(c.sep))].filter(Boolean).join(c.sep);
};

describe('実施コマンドの要約の性質', () => {
  it('mask.ts を読み込まない（画面のマスクの変更で、実施コマンドの出方が変わらないように）', () => {
    const src = readFileSync(new URL('../src/export/cmdSummary.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/from ['"][./]*mask['"]/);
  });

  it('値の置き場所にある秘密は、オプションの順番・区切り・プログラムの書き方を変えても出ない', () => {
    fc.assert(fc.property(command, c => {
      const s = render(c);
      const out = summarizeCommand(s);
      for (const [, t] of c.values) expect(leaks(out, t), `${s}\n→ ${out}`).toBeUndefined();
      for (const [, u] of c.users) expect(out, `${s}\n→ ${out}`).not.toContain(u);
    }), RUNS);
  });

  it('出る語は、決めた形のどれか（許可リストの外の語は出ない）', () => {
    const anyInput = fc.oneof(command.map(render), fc.string({ maxLength: 200 }), fc.string({ unit: 'grapheme', maxLength: 80 }),
      fc.array(fc.constantFrom('curl', '-H', 'Authorization:', '_', ' ', '"', "'", 'https://', 'a.example', '/', '?', '=', '&', ':', '-', '--', 'x', '・', '\n', '…', '****', 'C1'), { maxLength: 30 }).map(a => a.join('')));
    fc.assert(fc.property(anyInput, s => {
      const out = summarizeCommand(s);
      for (const w of words(out)) expect(allowedWord(w), `${JSON.stringify(s)}\n→ ${JSON.stringify(out)}\n語：${JSON.stringify(w)}`).toBe(true);
    }), RUNS);
  });

  it('もう一度かけても変わらない', () => {
    const anyInput = fc.oneof(command.map(render), fc.string({ maxLength: 120 }));
    fc.assert(fc.property(anyInput, s => {
      const once = summarizeCommand(s);
      expect(summarizeCommand(once), JSON.stringify(s)).toBe(once);
    }), RUNS);
  });

  it('コマンドのID（コマンド生成器・HAR が書くもの）はそのまま', () => {
    for (const s of ['C4', 'C11・C12・C23', 'HAR', '-', 'C1・C2']) expect(summarizeCommand(s)).toBe(s);
  });

  it('長い入力でも時間が入力の長さの2乗にならない', () => {
    const t = performance.now();
    for (const unit of ['_-daaaaa', '_-HAuthorization:', '_-Hz:a', 'Cookie:a…(1 chars)_', '"', "'", 'https://a.example/_', '_-sSu', 'a_b=', 'A_', 'a_', '_a', 'A1_'])
      summarizeCommand(`curl${unit.repeat(20000)}`);
    summarizeCommand(`curl_https://h/${'a_'.repeat(50000)}`);
    summarizeCommand(`curl_${'A_'.repeat(50000)}`);
    expect(performance.now() - t).toBeLessThan(2000);
  });
});

describe('実施日時の要約', () => {
  it('日時の形だけをそのまま出し、それ以外は ****', () => {
    for (const s of ['2026-10-13', '2026-10-13T10:00', '2026-10-13T10:00:05', '2026-10-13T10:00:05.123Z', '2026-10-13T10:00:05+09:00', '2026-10-13 10:00']) expect(summarizeAt(s)).toBe(s);
    for (const s of ['token=abc', '2026-10-13T10:00_secret', 'yesterday']) expect(summarizeAt(s)).toBe('****');
    expect(summarizeAt('')).toBe('');
  });
});
