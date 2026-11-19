// CSV の「実施コマンド」「実施日時」の要約（src/export/cmdSummary.ts）の漏れと誤りの再現テスト。
// 入力はすべて作ったもの（example のホスト、作った名前と値）
import { describe, expect, it } from 'vitest';
import { summarizeAt, summarizeCommand as f } from '../src/export/cmdSummary';
import { parseInput } from '../src/parser/input';

/** 出力に含まれてはいけない語（ユーザー名・パスワードのかけら・値） */
const noLeak = (s: string, ...bad: string[]) => {
  const out = f(s);
  for (const b of bad) expect(out, `${s}\n→ ${out}`).not.toContain(b);
  expect(f(out), `${s}\n→ ${out}`).toBe(out);
  return out;
};

describe('URL のユーザー情報の途中で切れた URL', () => {
  it('パスワードが空・数字だけで、ユーザー情報がパス・クエリ・フラグメントの @ まで続くもの', () => {
    for (const s of ['curl https://john.doe:2024/@api.example.com/v1', 'curl https://john.doe:/@api.example.com', 'curl https://john.doe:2024#x@localhost:8080/',
      'curl https://john.doe:2024?x@localhost/', 'curl https://john.doe:#@intranet/', "curl wss://JOHN.DOE:1#@!'@api.example.com",
      'curl https://john.doe:2024\\/@api.example.com/', "curl 'https://john.doe:'@api.example.com'", 'curl https://john.doe:2024#x@[::1]:8080/'])
      noLeak(s, 'john', 'JOHN', 'doe', '2024');
  });

  it('引用符・エスケープした引用符・・・改行で、URL がユーザー情報の途中で切れたもの', () => {
    for (const s of [`curl 'https://first.last:'"$PASS"'@api.example.com/v1'`, `curl "https://first.last:\\"Secret\\"@api.example.com/v1"`,
      `curl_'https://first.last:'Secret'@api.example.com/v1'`, `curl "https://first.last:1234\\"abc@a.example.com/x"`,
      `curl -x "http://first.last:1234\\"x@proxy.example.com:3128" https://a.example.com/`, 'curl https://first.last:1234・abc@a.example.com/x',
      'curl https://first.last:1234\nabc@a.example.com/x', `curl "https://first.last@corp.example.com:"Secret"@api.example.com/v1"`,
      `curl 'https://localhost:1234'x@a.example.com/`,
      // 空のコマンド・空白を挟んだもの
      'curl https://first.last:1234・・abc@a.example.com/x', 'curl https://first.last:1234\n\nabc@a.example.com/x', 'curl https://first.last:1234・ abc@a.example.com/x',
      `curl_'https://first.last:12/c'@api.example.com/`])
      noLeak(s, 'first', 'last', '1234', 'corp', 'Secret');
  });

  it('閉じていない引用符と、長いユーザー情報で「_」で切れたもの', () => {
    expect(noLeak('curl "https://john.doe_svc:Secret@corp.example/', 'john', 'svc', 'Secret')).toBe('curl https://corp.example/');
    expect(noLeak("curl 'https://john.doe_svc:Secret@corp.example/", 'john', 'svc', 'Secret')).toBe('curl https://corp.example/');
    noLeak(`curl "https://john.doe:2024_x@corp.example/'`, 'john', '2024');
    noLeak(`curl_https://john.doe:2024_${'x'.repeat(210)}@host.example/`, 'john', '2024');
  });

  it('「_」で区切ったコマンドで、ユーザー情報が後ろの引数（_-d_・_-F_・_-u_）まで続いたもの', () => {
    // ユーザー情報か、URL のあとの値か見分けられないので、URL を **** にする
    noLeak('curl_https://api.example.com_-d_@secrets-alice.json', 'secrets', 'alice');
    noLeak('curl_https://api.example.com:8443_-F_file=@alice-cv.pdf', 'alice');
    noLeak('curl_https://api.example.com_-u_john.doe@corp.example:2024', 'john', 'corp', '2024');
    noLeak('curl_https://api.example.com_-d_email=alice.smith@contoso.example', 'alice', 'contoso');
    noLeak('curl_https://api.example.com_-H_From:alice@home.example', 'alice', 'home');
    noLeak('http_https://api.example.com_X-Note:alice@home.example', 'alice', 'home');
    // ユーザー情報の中の「_-x」「_;」などで切れたもの
    for (const sep of ['-x', ';x', '|x', '<x', '>x', '&&x', 'https:x'])
      noLeak(`curl_https://john.doe:2024_${sep}@corp.example/`, 'john', '2024');
    noLeak('curl_https://john.doe_-x:pw@corp.example/', 'john');
    noLeak('curl_-x_http://john.doe:2024_-x@proxy.example.com:3128_https://a.example.com/', 'john', '2024');
  });

  it('「_」で区切ったコマンドで、@ と「_」を含むパスワードのかけらがホストとして出ない', () => {
    noLeak('curl_https://john.doe:p@ss.word_1@host.example/', 'john', 'ss.word', 'word');
  });

  it('引用符の中の空白・\\ ・全角の空白、引用符の入れ子、・・改行の前の引用符で切れたもの', () => {
    for (const s of ['curl https://first.last:2024"my secret"@api.example.com/', "curl https://first.last:2024'my secret'@api.example.com/",
      'curl -u x https://first.last:2024"$(pass show api)"@api.example.com/v1', 'curl https://first.last:1234\\ abc@a.example.com/',
      'curl https://first.last:1234　abc@a.example.com/', 'curl https://first.last:1234 abc@a.example.com/',
      `curl_"https://first.last:2024'x・y@api.example.com/"`, `curl_'https://first.last:2024"x・y@api.example.com/'`, `curl "https://first.last:2024'x y@api.example.com/`,
      'curl https://first.last:2024"・"y@api.example.com/', "curl https://first.last:1234'・'abc@a.example.com/", 'curl https://first.last:2024"\n"y@api.example.com/',
      'curl_https://first.last:1234"・abc@a.example.com/'])
      noLeak(s, 'first', 'last', '2024', '1234');
    noLeak('curl https://first.last@corp.example.com:2024"Se cret"@api.example.com/', 'first', 'corp', '2024');
  });

  it('「_」で区切ったコマンドで、ユーザー情報が httpie の項目・ファイル・リダイレクトを越えたもの', () => {
    for (const s of ['http_POST_https://api.example.com_email=alice@corp.example', 'http_POST_https://api.example.com:8443_email=alice@corp.example',
      'http_POST_https://api.example.com_cv=@alice-cv.pdf', 'http_-f_POST_https://api.example.com_cv@alice-cv.pdf', 'curl_https://api.example.com_2>alice@corp.example'])
      noLeak(s, 'alice', 'corp');
  });

  it('閉じない引用符のあとの引用符、2つ以上の・、・の前の全角の空白・NBSP・CR、メールアドレスのユーザー名', () => {
    const BS = String.fromCharCode(92);
    for (const s of [`curl "https://first.last:2024'x ・y@api.example.com/"`, `curl 'https://first.last:2024"a"b c@api.example.com/v1`,
      `curl "https://first.last:2024'x y'z w@api.example.com/`, 'curl https://first.last:12・34・56@api.example.com/', 'curl "https://first.last:2024\nk・@api.example.com/v1"',
      'curl https://first.last:1234　・abc@api.example.com/', 'curl https://first.last:1234 ・abc@api.example.com/', 'curl https://first.last:1234\r・abc@api.example.com/',
      'curl_https://first.last@corp.example:2024_-x@api.example.com/', 'curl_https://first.last:2024_-k"x y"@api.example.com/v1', 'curl_"https://first.last:2024"_-x@corp.example/',
      'curl_https://first.last:2024#ab_-x@host.example/', `curl_https://first.last:2024_-x${'y'.repeat(200)}@host.example/`,
      'curl https://first.last@corp.example:2024#Pass@api.example.com/v1', 'curl https://first.last@corp.example:2024/Pass@api.example.com/v1',
      'curl https://first.last@corp.example:2024?Pass@api.example.com/v1', `curl https://corp.example${BS}first:2024"my secret"@api.example.com/`])
      noLeak(s, 'first', 'last', 'corp', '2024', '1234', 'Pass');
  });

  it('#META の cmd= の値が引用符・空白で切れても、行のあとの @ で URL を伏せる', () => {
    for (const line of [`#META cmd="curl 'https://first.last:'"$PASS"'@example.com/'"`, '#META cmd="curl https://first.last:2024"$SUFFIX"@example.com/"',
      `#META cmd="curl 'https://first.last:2024'"'@example.com/'"`, `#META cmd=curl_'https://first.last:2024 x'@example.com/`, '#META cmd=curl_https://first.last:2024 @example.com/']) {
      const { targets } = parseInput(`#TARGET url=https://a.example/ label=top\n${line}\nHTTP/1.1 200 OK\n\n`);
      noLeak(targets[0].meta.cmd ?? '', 'first', 'last', '2024');
    }
    const { targets } = parseInput('#TARGET url=https://a.example/ label=top\n#META at=2026-10-13T10:00 cmd=C1\nHTTP/1.1 200 OK\n\n');
    expect(targets[0].meta.cmd).toBe('C1');
  });

  it('引用符の中に空白がある「_」で区切ったコマンドは、「_」で区切って読む', () => {
    expect(f('curl_-H_"X-Note: a b"_https://a.example.com/')).toBe('curl -H X-Note:**** https://a.example.com/');
    expect(f(`curl_-sS_'https://a.example.com/x'_-d_'a b'`)).toBe('curl -sS https://a.example.com/x -d ****');
  });

  it('URL のあとに @ がある URL は、ユーザー情報の @ が1つだけのもの以外 **** にする（どこで切れても、ユーザー情報の終わりの @ は URL のあとにある）', () => {
    for (const s of ['curl https://alice:p@ss@h.example/x', 'curl https://a.example/?email=alice@example.com&page=2', 'curl https://a.example.com:8443/?email=alice@example.com&page=2',
      'curl https://mastodon.example/@alice/1', 'curl https://a.example.com/x?q="alice@example.com"', 'curl https://a.example.com:8443・bob@corp.example',
      'curl https://a.example.com/x -u alice@corp.example']) expect(f(s).split(/・| -u /)[0], s).toBe('curl ****');
    expect(f('http_POST_https://a.example.com/x_email=alice@example.com')).toBe('http POST **** email=****');
    // @ より前の URL は出す
    expect(f('curl -u alice@corp.example https://a.example.com/x')).toBe('curl -u **** https://a.example.com/x');
    expect(f('curl https://alice:pw@h.example/x')).toBe('curl https://h.example/x');
  });

  it('ユーザー情報を正しく読めるものと、@ のない URL は今までどおり', () => {
    expect(f('curl https://svc_account:Passw0rd@api.example.com/v1')).toBe('curl https://api.example.com/v1');
    // 「_」で区切ったコマンドで「_」を含むユーザー情報は、次の引数（_account:）と見分けられないので **** にする
    expect(f('curl_https://svc_account:Passw0rd@api.example.com/v1')).toBe('curl ****');
    expect(f('curl -sS https://api.example.com:8443/v1')).toBe('curl -sS https://api.example.com:8443/v1');
    expect(f('curl "https://a.example/x" -o out.txt')).toBe('curl https://a.example/x -o ****');
    expect(f('curl https://host.example:8443・curl https://b.example/')).toBe('curl https://host.example:8443/・curl https://b.example/');
    expect(f('curl_https://a.example/_-H_X-Api-Key:abc')).toBe('curl https://a.example/ -H X-Api-Key:****');
    expect(f('curl https://a.example.com:/x')).toBe('curl https://a.example.com/x');
    expect(f('curl -o "C:\\out\\" -H "X-A: 1" https://a.example/')).toBe('curl -o **** -H X-A:**** https://a.example/');
  });
});

describe('実施コマンド・実施日時の要約のそのほかの誤り', () => {
  it('「_」を含むヘッダの名前は出さない（もう一度かけると変わった）', () => {
    for (const s of [`curl -H 'X-Foo_Bar: secretval' https://api.example.com/x`, `iwr https://api.example.com/x -Headers 'X-Foo_Bar: v'`]) {
      const out = noLeak(s, 'secretval', 'Foo_Bar');
      expect(out).toContain('https://api.example.com/x');
    }
  });

  it('トークンのかけら（_-ILkT…・_-bvK9…）を短いオプションとして出さない', () => {
    // 値を取る文字1つと値（-b****）は、-ualice:pw と見分けられないので残る（出るのはかけらの先頭の1文字だけ。history.md の未対応）
    noLeak('curl_-sS_-H_Authorization:Bearer_-bvK9FAWoMpA8XjrXjMMzD9vJGFz_-ILkTgKrjZP8lM_https://api.example.com/x', 'ILkT', 'bvK', 'ILk');
    noLeak('curl -H Authorization:Bearer_abc_-iLkvH9xQ_-sSLk_GET https://api.example.com/x', 'iLkv', 'sSLk', 'GET');
    expect(f('curl -sSLk -ualice:pw -o out.txt https://a.example/')).toBe('curl -sSLk -u**** -o **** https://a.example/');
    expect(f('curl_-sSLk_-H_Accept:x_https://a.example/')).toBe('curl -sSLk -H Accept:**** https://a.example/');
  });

  it('空白で区切ったコマンドの値の中の「_-H」を、ヘッダの名前として出さない', () => {
    // エスケープした引用符のあとの -H（-H "X-Note: \" -H X-Hunter-Pw:1 \""）は残る（\" で閉じないようにすると2乗の時間がかかる。history.md の未対応）
    noLeak('curl -u alice:x_-HX-Hunter-Two:1 https://api.example.com/x', 'Hunter');
    expect(f('curl -HX-Api-Key:abc https://a.example/')).toBe('curl -H X-Api-Key:**** https://a.example/');
  });

  it('コマンドのIDは C1〜C26・HAR・- だけ', () => {
    for (const s of ['C1', 'C9', 'C10', 'C26', 'HAR', '-', 'C11・C12・C23', 'C1・C2']) expect(f(s)).toBe(s);
    for (const s of ['C0', 'C27', 'C99', 'C01']) expect(f(s)).toBe('****');
  });

  it('実施日時は、ありうる日時だけ（月・日・時・分・秒・時差の範囲）。秒の小数は3桁まで', () => {
    for (const s of ['9999-99-99', '2026-13-01', '2026-10-32', '2026-10-13T24:00', '2026-10-13T10:60', '4111-11-11T11:11:11.111111+1111', '2026-10-13T10:00+15:00'])
      expect(summarizeAt(s), s).toBe('****');
    expect(summarizeAt('2026-10-13T10:00:05.123456+09:00')).toBe('2026-10-13T10:00:05.123+09:00');
    for (const s of ['2026-10-13', '2026-10-13T10:00', '2026-10-13 23:59:59', '2026-10-13T10:00:05.123Z', '2026-10-13T10:00:05+0530', '2026-10-13T10:00:05+09:00']) expect(summarizeAt(s)).toBe(s);
    for (const s of ['token=abc', '2026-10-13T10:00_secret', 'yesterday']) expect(summarizeAt(s)).toBe('****');
    expect(summarizeAt('')).toBe('');
  });
});

/** 性質のテストが見つけた漏れの入力で使うトークン */
const TOKEN = 'Xk9pQ2mZ7vR4tL8nW3bY';

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
      const out = f(s);
      for (const x of secrets) expect(out, `${s} → ${out}`).not.toContain(x);
      expect(f(out), s).toBe(out);
    }
  });

  it('コマンドの形（プログラム・オプションの名前・ヘッダの名前・URL のキーの形）は残す', () => {
    expect(f(`C:\\Windows\\System32\\curl.exe -u alice:${TOKEN} https://a.example/`)).toBe('curl -u **** https://a.example/');
    expect(f(`curl_https://a.example/cb?access_token=${TOKEN}_-L_-F_token=Zq8wErT5yUi9oP3a`)).toBe('curl https://a.example/cb?access_token -L -F ****');
    expect(f(`/usr/bin/curl_-H_Authorization:_-X_POST_--http1.1_--cookie_session=${TOKEN}`)).toBe('curl -H Authorization: -X POST --http1.1 --cookie ****');
    // 値のないヘッダ（curl でヘッダを消す書き方）のあとの URL・オプションはそのまま
    for (const [s, k] of [['curl_-H_Authorization:_https://a.example/login', 'curl -H Authorization: https://a.example/login'],
      ['curl_-H_Authorization:_-L_https://a.example/', 'curl -H Authorization: -L https://a.example/'],
      ['curl -H Authorization: -X POST https://a.example/', 'curl -H Authorization: -X POST https://a.example/']]) expect(f(s)).toBe(k);
  });
});
