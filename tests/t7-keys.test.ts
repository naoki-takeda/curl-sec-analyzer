// 第28回（T7：突き合わせのキーをマスクから切り離し、性質のテストを加える）で、性質のテスト（tests/properties.test.ts）が見つけた誤りの再現テスト。
// 性質のテストは入力を毎回作り直すので、見つけた反例はここに例として残す
import { describe, expect, it } from 'vitest';
import { maskCommand, maskText } from '../src/mask';
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

describe('#META cmd= のコマンドのマスク', () => {
  it('値を続けて書いた -H（-HAuthorization:…）を、前の --json・-d の値の中に入れない', () => {
    const out = maskCommand(`curl_--json_{"password":"pw"}_-HAuthorization:_Bearer_${TOKEN}_-u_alice:pw`);
    expect(out).not.toContain(TOKEN.slice(0, 8));
    expect(out).toContain('-HAuthorization:_Bearer_****');
  });

  it('URL のクエリの値のあとに伏せた値が続いても、クエリの値を伏せる', () => {
    const out = maskCommand(`curl_https://a.example/cb?access_token=${TOKEN}_-L_-F_token=Zq8wErT5yUi9oP3a`);
    expect(out).not.toContain(TOKEN.slice(0, 8));
    expect(maskCommand(out)).toBe(out);
  });

  it('Windows のパスで書いた curl（C:\\Windows\\System32\\curl.exe）のオプションも伏せる', () => {
    expect(maskCommand(`C:\\Windows\\System32\\curl.exe_-u_alice:${TOKEN}`)).toBe('C:\\Windows\\System32\\curl.exe_-u_****');
    expect(maskCommand(`C:\\Windows\\System32\\curl.exe -u alice:${TOKEN} https://a.example/`)).toBe('C:\\Windows\\System32\\curl.exe -u **** https://a.example/');
  });

  it('伏せたあとの -u****・-b**** をもう一度伏せても変わらない（前の -u の値に入れない）', () => {
    const once = maskCommand(`curl_-u_alice:${TOKEN}_-ualice:${TOKEN}_-u_alice:${TOKEN}`);
    expect(once).toBe('curl_-u_****_-u****_-u_****');
    expect(maskCommand(once)).toBe(once);
  });

  it('引用符で囲まずに空白で書いたヘッダ（-H Authorization: Bearer …、--header=…、-HAuthorization: …、Authorization:Basic …）も伏せる', () => {
    for (const s of [`curl -H Authorization: Bearer ${TOKEN}`, `curl --header=Authorization: Bearer ${TOKEN}`, `curl -HAuthorization: Bearer ${TOKEN}`,
      `curl -H Authorization:Basic ${TOKEN}`]) {
      const out = maskCommand(s);
      expect(out, s).not.toContain(TOKEN.slice(0, 8));
      expect(maskCommand(out)).toBe(out);
    }
  });
});

describe('#META cmd= のコマンドのマスク（コミット前のレビューで見つかったもの）', () => {
  it('値の中の「_-Hz:」（秘密でない名前）では値を切らない（パスワード・Cookie の残りを出さない）', () => {
    for (const s of [`curl_-u_alice:pa_-Hz:${TOKEN}`, `curl_-b_sid=Ab12_-Hx:${TOKEN}`, `curl_-d_password=pa_-Hz:${TOKEN}`,
      `curl_-H_Authorization:_Bearer_tok_-Hx:${TOKEN}`]) expect(maskCommand(s), s).not.toContain(TOKEN.slice(0, 8));
  });

  it('値のないヘッダ（curl でヘッダを消す -H_Authorization:）のあとの URL・オプションを伏せない', () => {
    for (const s of ['curl_-H_Authorization:_https://a.example/login', 'curl_-H_Cookie:_https://a.example/login', 'curl -H Cookie: -HAuthorization:',
      'curl_-HAuthorization:_https://a.example/', 'curl_-H_Authorization:_-L_https://a.example/', 'curl -H Authorization: -X POST https://a.example/'])
      expect(maskCommand(s)).toBe(s);
    expect(maskCommand('curl_-H_Authorization:_Bearer_https://a.example/login')).toBe('curl_-H_Authorization:_****_https://a.example/login');
    const s = `curl_-H_Authorization:_--json_{"password":"${TOKEN}"}`;
    expect(maskCommand(s)).toBe('curl_-H_Authorization:_--json_{"password":"Xk…(20 chars)"}');
    expect(maskCommand(maskCommand(s))).toBe(maskCommand(s));
  });

  it('httpie・xh のヘッダの値が「-」で始まっても伏せる', () => {
    for (const s of [`http_POST_https://x.example/_Authorization:Bearer_-Abc_${TOKEN}`, `xh_https://x.example/_Cookie:-ab_sid=${TOKEN}`, `http POST https://x.example/ X-Api-Key:-Ab${TOKEN}`])
      expect(maskCommand(s), s).not.toContain(TOKEN.slice(0, 8));
  });

  it('プログラムは最初の語だけ（値の途中の「_http_」「_curl_」でコマンドを分けて、秘密を2つに切らない）', () => {
    for (const s of ['curl_https://deploy:my_http_pass@git.example.com/', 'curl_https://x.example/cb?code=ab_http_SECRETTAIL123',
      'C:\\bin\\curl.exe_https://x.example/cb?token=sk9Xq2Lm_xh_P4vR7tY1wZ', 'curl_https://x.example/reset/Xk9q2LmP4v_curl_R7tY1wZaB3']) {
      const out = maskCommand(s);
      for (const secret of ['my_http_pass', 'SECRETTAIL', 'P4vR7tY1wZ', 'R7tY1wZaB3']) expect(out, s).not.toContain(secret);
    }
  });

  it('JSON の本文の値の中の「_-bX=」「_-uX:」で値を切らない', () => {
    expect(maskCommand('curl_--json_{"password":"Hunter2_-bX=9q"}_https://x/')).toBe('curl_--json_{"password":"Hu…(14 chars)"}_https://x/');
    expect(maskCommand('curl_--json_{"password":"Hunter2_-uX:9q"}_https://x/')).toBe('curl_--json_{"password":"Hu…(14 chars)"}_https://x/');
  });

  it('伏せ済みとみなすのは値全体が伏せた形のときだけ（印の後ろに続く値は伏せる）', () => {
    for (const s of [`curl_-H_Cookie:ab…(5 chars)_sid=${TOKEN}_https://x/`, `curl -H "Authorization: Bearer ab…(5 chars) ${TOKEN}"`, `curl_-H_X-Api-Key:ab…(5 chars)${TOKEN}`])
      expect(maskCommand(s), s).not.toContain(TOKEN.slice(0, 8));
    const t = performance.now();
    maskCommand(`curl_${'Cookie:a…(1 chars)_'.repeat(8000)}`);
    maskCommand(`curl_${'-sHCookie:a…(1 chars)_'.repeat(8000)}`);
    expect(performance.now() - t).toBeLessThan(1500);   // 修正の途中の版は2乗の時間で、約4秒かかった
  });

  it('クライアントのないコマンドの、値を続けたオプションの後ろも伏せる', () => {
    expect(maskCommand('Authorization:_Bearer_abc_-uQw9z=resttokenpart')).toBe('Authorization:_Bearer_****');
  });

  it('引用符で囲んだ Windows のパスの curl を見て、ディレクトリの curl_ はクライアントとみなさない', () => {
    expect(maskCommand(`"C:\\Program Files\\curl\\bin\\curl.exe" -u alice:${TOKEN} https://x/`)).toBe('"C:\\Program Files\\curl\\bin\\curl.exe" -u **** https://x/');
    for (const s of ['D:\\tools\\curl_8.5\\bin\\openssl_x509_-subject_-issuer_-in_c.pem', 'D:\\work\\curl_logs\\grep_-E_secretpattern_x.txt']) expect(maskCommand(s)).toBe(s);
  });

  it('クエリ・オプションの値の中の「秘密らしい語:」から後ろを伏せない（「=」の直後を見るのは --header= だけ）', () => {
    for (const s of ['curl_https://a.example/search?q=token:abc&page=2_-sS', 'curl -o out=token:x.txt https://a.example/', 'curl_-H_X-Trace:a=Authorization:xyz'])
      expect(maskCommand(s)).toBe(s);
  });

  it('値を続けて書いた -H の続く入力でも、時間が入力の長さの2乗にならない', () => {
    // 修正の途中の版では、-H のたびに値の終わりまで読み、20万文字で約6秒かかった（線形なら数十ミリ秒）
    const t = performance.now();
    maskCommand(`curl_-d_${'_-HAuthorization:'.repeat(12000)}`);
    maskCommand(`curl_-d_x${'_-Hz:a'.repeat(33000)}`);
    expect(performance.now() - t).toBeLessThan(1500);
  });

  it('Windows のパスの「\\http_」をクライアントとみなさない', () => {
    expect(maskCommand('D:\\logs\\http_dump\\grep_-E_pattern_x.txt')).toBe('D:\\logs\\http_dump\\grep_-E_pattern_x.txt');
  });

  it('伏せた値のあとに続く引数を、その値に入れて伏せない', () => {
    expect(maskCommand(`curl_-v_--data-raw_user=a&token=${TOKEN}_-o_out.txt_-u_alice:pw`)).toBe('curl_-v_--data-raw_user=a&token=Xk…(20 chars)_-o_out.txt_-u_****');
  });

  it('プログラムのパス（/usr/bin/curl）のあとの引数を、パスの部分として伏せない（もう一度かけても変わらない）', () => {
    const s = `/usr/bin/curl_-H_Authorization:_-X_POST_--http1.1_--cookie_session=${TOKEN}`;
    expect(maskCommand(s)).toBe('/usr/bin/curl_-H_Authorization:_-X_POST_--http1.1_--cookie_****');
    expect(maskCommand(maskCommand(s))).toBe(maskCommand(s));
  });
});

describe('画面のマスク（コミット前のレビューで見つかったもの）', () => {
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
