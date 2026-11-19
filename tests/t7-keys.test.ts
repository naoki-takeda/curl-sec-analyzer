// 性質のテスト（tests/properties.test.ts）が見つけた、突き合わせのキーとマスクの誤りの再現テスト。
// 性質のテストは入力を毎回作り直すので、見つけた反例はここに例として残す
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { summarizeCommand } from '../src/export/cmdSummary';
import { targetKeys, urlKey } from '../src/engine/targetKey';
import { parseInput } from '../src/parser/input';

const TOKEN = 'Xk9pQ2mZ7vR4tL8nW3bY';

describe('突き合わせのキー', () => {
  it('同じ名前のパラメータの値の順番で、キーが変わらない', () => {
    expect(urlKey('https://a.example/x?sort=1&q=1&sort=ja')).toBe(urlKey('https://a.example/x?sort=ja&q=1&sort=1'));
    expect(urlKey('https://a.example/x?sort=asc&sort=asc')).toBe('https://a.example/x?sort=asc');
    expect(urlKey('https://a.example/x?page=1&page=2')).toBe('https://a.example/x?page');
  });

  it('URL として読めないもののキー（*）は、もう一度かけても変わらない', () => {
    expect(urlKey('//')).toBe('*');
    expect(urlKey('*')).toBe('*');
  });

  it('相対のパスの先頭の「//」は1つにし、スキームのない「//ホスト/…」はホストを残す（もう一度かけても変わらない）', () => {
    for (const [u, k] of [['/.//b', '/b'], ['/a/..//b', '/b'], ['.//b', '/b'], ['//cdn.example/x', '//cdn.example/x']]) {
      expect(urlKey(u)).toBe(k);
      expect(urlKey(k)).toBe(k);
    }
  });

  it('ターゲットのキーは、マスクを使わずに作る（engine/targetKey.ts）', () => {
    const { targets } = parseInput(`#TARGET url=https://a.example/reset/${TOKEN}?token=${TOKEN} label=top\nHTTP/1.1 200 OK\n\n`
      + `#TARGET url=https://a.example/ label=top\nHTTP/1.1 200 OK\n\n`);
    const keys = targetKeys(targets);
    expect(keys).toEqual(['top https://a.example/reset/*?token', 'top https://a.example/']);
    for (const k of keys) expect(k).not.toContain(TOKEN.slice(0, 8));
  });
});

describe('#META cmd= の実施コマンド（残してよい形だけを残す要約）', () => {
  // 性質のテストが見つけた漏れの入力。要約は値を出さないので、どの入力でも秘密は出ない
  const cases: [string, string[]][] = [
    [`curl_--json_{"password":"pw"}_-HAuthorization:_Bearer_${TOKEN}_-u_alice:pw`, [TOKEN]],
    [`curl_https://a.example/cb?access_token=${TOKEN}_-L_-F_token=Zq8wErT5yUi9oP3a`, [TOKEN, 'Zq8wErT5yUi9oP3a']],
    [`C:\\Windows\\System32\\curl.exe_-u_alice:${TOKEN}`, [TOKEN, 'alice']],
    [`curl_-u_alice:${TOKEN}_-ualice:${TOKEN}_-u_alice:${TOKEN}`, [TOKEN, 'alice']],
    [`curl -H Authorization: Bearer ${TOKEN}`, [TOKEN]], [`curl --header=Authorization: Bearer ${TOKEN}`, [TOKEN]],
    [`curl -HAuthorization: Bearer ${TOKEN}`, [TOKEN]], [`curl -H Authorization:Basic ${TOKEN}`, [TOKEN]],
    [`curl_-u_alice:pa_-Hz:${TOKEN}`, [TOKEN]], [`curl_-b_sid=Ab12_-Hx:${TOKEN}`, [TOKEN]], [`curl_-d_password=pa_-Hz:${TOKEN}`, [TOKEN]],
    [`curl_-H_Authorization:_Bearer_tok_-Hx:${TOKEN}`, [TOKEN]], [`curl_-H_Authorization:_--json_{"password":"${TOKEN}"}`, [TOKEN]],
    [`http_POST_https://x.example/_Authorization:Bearer_-Abc_${TOKEN}`, [TOKEN]], [`xh_https://x.example/_Cookie:-ab_sid=${TOKEN}`, [TOKEN]],
    [`http POST https://x.example/ X-Api-Key:-Ab${TOKEN}`, [TOKEN]],
    ['curl_https://deploy:my_http_pass@git.example.com/', ['my_http_pass', 'deploy']], ['curl_https://x.example/cb?code=ab_http_SECRETTAIL123', ['SECRETTAIL']],
    ['C:\\bin\\curl.exe_https://x.example/cb?token=sk9Xq2Lm_xh_P4vR7tY1wZ', ['P4vR7tY1wZ', 'sk9Xq2Lm']], ['curl_https://x.example/reset/Xk9q2LmP4v_curl_R7tY1wZaB3', ['R7tY1wZaB3', 'Xk9q2LmP4v']],
    ['curl_--json_{"password":"Hunter2_-bX=9q"}_https://x/', ['Hunter2', '9q']], ['curl_--json_{"password":"Hunter2_-uX:9q"}_https://x/', ['Hunter2', '9q']],
    [`curl_-H_Cookie:ab…(5 chars)_sid=${TOKEN}_https://x/`, [TOKEN]], [`curl -H "Authorization: Bearer ab…(5 chars) ${TOKEN}"`, [TOKEN]],
    [`curl_-H_X-Api-Key:ab…(5 chars)${TOKEN}`, [TOKEN]], ['Authorization:_Bearer_abc_-uQw9z=resttokenpart', ['resttokenpart', 'Qw9z']],
    [`"C:\\Program Files\\curl\\bin\\curl.exe" -u alice:${TOKEN} https://x/`, [TOKEN, 'alice']],
    [`curl_-v_--data-raw_user=a&token=${TOKEN}_-o_out.txt_-u_alice:pw`, [TOKEN, 'alice']],
    [`/usr/bin/curl_-H_Authorization:_-X_POST_--http1.1_--cookie_session=${TOKEN}`, [TOKEN]],
  ];
  it('どの入力でも秘密を出さず、もう一度かけても変わらない', () => {
    for (const [s, secrets] of cases) {
      const out = summarizeCommand(s);
      for (const x of secrets) expect(out, `${s} → ${out}`).not.toContain(x);
      expect(summarizeCommand(out), s).toBe(out);
    }
  });

  it('コマンドの形（プログラム・オプションの名前・ヘッダの名前・URL のキーの形）は残す', () => {
    expect(summarizeCommand(`C:\\Windows\\System32\\curl.exe -u alice:${TOKEN} https://a.example/`)).toBe('curl -u **** https://a.example/');
    expect(summarizeCommand(`curl_https://a.example/cb?access_token=${TOKEN}_-L_-F_token=Zq8wErT5yUi9oP3a`)).toBe('curl https://a.example/cb?access_token -L -F ****');
    expect(summarizeCommand(`/usr/bin/curl_-H_Authorization:_-X_POST_--http1.1_--cookie_session=${TOKEN}`)).toBe('curl -H Authorization: -X POST --http1.1 --cookie ****');
    // 値のないヘッダ（curl でヘッダを消す書き方）のあとの URL・オプションはそのまま
    for (const [s, k] of [['curl_-H_Authorization:_https://a.example/login', 'curl -H Authorization: https://a.example/login'],
      ['curl_-H_Authorization:_-L_https://a.example/', 'curl -H Authorization: -L https://a.example/'],
      ['curl -H Authorization: -X POST https://a.example/', 'curl -H Authorization: -X POST https://a.example/']]) expect(summarizeCommand(s)).toBe(k);
  });

  it('長い入力でも時間が入力の長さの2乗にならない', { tags: ['perf'] }, () => {
    const t = performance.now();
    summarizeCommand(`curl_-d_${'_-HAuthorization:'.repeat(12000)}`);
    summarizeCommand(`curl_-d_x${'_-Hz:a'.repeat(33000)}`);
    summarizeCommand(`curl_${'Cookie:a…(1 chars)_'.repeat(8000)}`);
    summarizeCommand(`curl${'_-daaaaa'.repeat(8000)}`);   // 長い繰り返しでも時間がかからない
    expect(performance.now() - t).toBeLessThan(1500);
  });
});

describe('画面のマスク', () => {
  it('エンコードした URL のホスト名をユーザー情報として伏せない', () => {
    for (const s of ['?next=https%3A//a.example%2Fcb%3Fe=bob@example.com', '/a%20//bob@example.com']) expect(maskText(s)).toBe(s);
  });

  it('nonce を先に伏せたパラメータの値を、伏せ直さない', () => {
    expect(maskText(`?code=nonce-${TOKEN}`)).toBe('?code=nonce-Xk…(20 chars)');
    expect(maskText(`?token='nonce-${TOKEN}'`)).toBe("?token='nonce-Xk…(20 chars)'");
  });
});

describe('画面のマスク', () => {
  it('エンコードした引用符・= の直後の URL（%22https://…）のパスワードも伏せる', () => {
    expect(maskText(`%22https://alice:${TOKEN}@a.example/`)).toBe('%22https://alice:****@a.example/');
    expect(maskText(`?u=%3Dhttps://alice:${TOKEN}@a.example/`)).not.toContain(TOKEN.slice(0, 8));
    // 「-」でつないだ32文字を超える語の直後のスキーム
    expect(maskText(`proxy=corp-egress-gateway-primary-region-https://svc:${TOKEN}@internal.example/`)).toContain('https://svc:****@internal.example/');
  });

  it('伏せ済みの値は、先頭の4文字までと印だけのものに限る（印で終わるだけの値は伏せる）', () => {
    expect(maskText('?token=abcd…(40 chars)')).toBe('?token=abcd…(40 chars)');
    expect(maskText(`?token=${TOKEN}_x=vi…(17 chars)`)).not.toContain(TOKEN.slice(0, 8));
  });
});
