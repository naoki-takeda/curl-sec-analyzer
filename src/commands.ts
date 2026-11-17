// commands.ts：コマンド生成器（C1〜C26 を #TARGET 付きで出力する）。生成したスクリプトは診断者が自分の端末で実行する
export interface CommandOptions {
  host: string;              // 例：www.example.com
  apex?: string;             // 例：example.com（www を使う場合）
  apiPath: string;           // 例：/api/me（機密のAPI）
  loginPath: string;         // 例：/login
  mypagePath: string;        // 例：/mypage（認証後のページ）
  logoutPath: string;        // 例：/logout
  staticPath: string;        // 例：/assets/app.js
  wsPath?: string;           // 例：/ws（WebSocket。任意。指定したときだけ C16 を出力する）
  dangerous: boolean;        // 検証環境でだけ行う試験（CRLF、メソッド上書き、送信元の偽装、A-08）を含めるか。DELETE などデータを消しうる試験は生成しない（手順書に書くだけ）
}

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const safeHost = (h: string) => /^[a-z0-9.-]+(:\d+)?$/i.test(h);
const safePath = (p: string) => /^\/[\w\-./~%]*$/.test(p);

/** 入力の検証。ホスト名とパスだけを受け付ける（シェルに展開される文字を入れない） */
export function validate(o: CommandOptions): string[] {
  const e: string[] = [];
  if (!safeHost(o.host)) e.push('ホスト名は英数字・ハイフン・ドット（必要なら :ポート）だけで書いてください');
  if (o.apex && !safeHost(o.apex)) e.push('apexドメインの書き方が正しくありません');
  for (const [k, v] of Object.entries({ API: o.apiPath, ログイン: o.loginPath, 認証後ページ: o.mypagePath, ログアウト: o.logoutPath, 静的リソース: o.staticPath, ...(o.wsPath ? { WebSocket: o.wsPath } : {}) }))
    if (!safePath(v)) e.push(`${k}のパスは / で始まる英数字と - . _ ~ % / で書いてください`);
  return e;
}

export function generateScript(o: CommandOptions): string {
  const H = `https://${o.host}`;
  const L: string[] = [];
  // 各ターゲットの前に #TARGET と #META（実施日時と推奨コマンドのID）を出す。CSV（第8章の様式）の「実施日時」「実施コマンド」に使う
  // どのマーカー行にも、実行ごとの乱数の印（run=$RUN）を付ける。ツールは最初の #TARGET の印と同じマーカー行だけを読む（parser/input.ts。
  // 診断対象のサーバが応答の本文に書いた #TARGET・#META・#PROBE で、ターゲットを作ったり分けたりできないように）
  const meta = (cmd: string) => `echo "#META at=$(date +%Y-%m-%dT%H:%M:%S) cmd=${cmd} run=$RUN"`;
  // #TARGET の前に改行を出す（curl -i の本文が改行で終わらないと、#TARGET が前の本文の行にくっついた）
  const t = (label: string, url: string, extra = '') => L.push('echo', `echo ${q(`#TARGET url=${url} label=${label}${extra}`)}" run=$RUN"`, meta(cmdOf(label)));
  L.push('#!/usr/bin/env bash',
    '# curl-sec-analyzer の推奨コマンド（コマンド生成器で作成）。出力を out.txt にまとめ、ツールに貼り付けて判定する',
    '# 実行前に：診断は自社で管理しているか書面で許可を得たシステムだけ。',
    '#   ログインには必ずテスト用アカウントを使い、login.txt（ログインのPOST本文）を用意して chmod 600 にする',
    '#   Gitリポジトリの中で実行する場合、出力ファイルは .gitignore で除外されていることを確認する',
    '# 実行後に：rm -f out.txt login.txt jar.txt old.txt s1.txt s2.txt s3.txt（login.txt にはパスワードが入っている）',
    'set -u', 'umask 077', `H=${q(H)}`,
    '# 実行ごとの印（応答の本文に書かれたマーカーと見分けるため）',
    "RUN=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \\n')",
    '# 本文を取るコマンドのヘッダと本文の一時ファイル（ヘッダと本文を分けて出す。#BODY の印のあとが本文）', 'hdr=$(mktemp); body=$(mktemp)', '{');

  L.push('', '# ---- 第1章：ヘッダ（C4・C2・C10） ----');
  t('top', `${H}/`); L.push('curl -sS -v -o /dev/null "$H/" 2>&1');
  t('page', `${H}/`); L.push('curl -sS -i "$H/"');
  t('static', `${H}${o.staticPath}`); L.push(`curl -sS -i "$H"${q(o.staticPath)}`);
  t('header-json', `${H}/`); L.push(`curl -sS -o /dev/null -w '#META response_code=%{response_code} run='"$RUN"'\\n%{header_json}\\n' "$H/"`);
  t('notfound', `${H}/no-such-page-csa404`); L.push('curl -sS -i "$H/no-such-page-csa404"');
  L.push('for i in 1 2; do', `  echo "#TARGET url=$H/ label=csp-sample-$i run=$RUN"; ${meta('C24')}; curl -sS -D - -o /dev/null "$H/"   # C24`, 'done');

  L.push('', '# ---- 第4章：HTTP→HTTPS（C5・C15） ----');
  t('http', `http://${o.host}/`);
  L.push(`curl -sS -L -D - -o /dev/null -w '\\n#META response_code=%{response_code} num_redirects=%{num_redirects} url_effective=%{url_effective} http_version=%{http_version} run='"$RUN"'\\n' ${q(`http://${o.host}/`)}`);
  if (o.apex) {
    t('apex', `https://${o.apex}/`); L.push(`curl -sS -D - -o /dev/null ${q(`https://${o.apex}/`)}`);
  }

  L.push('', '# ---- 第2章：ログインの流れ（C18）。login.txt にログインのPOST本文を書いておく ----');
  t('pre-login', `${H}${o.loginPath}`); L.push(`curl -sS -v -o /dev/null -c jar.txt -b jar.txt "$H"${q(o.loginPath)} 2>&1`);
  t('login', `${H}${o.loginPath}`, ' sensitive=1'); L.push(`curl -sS -v -o /dev/null -c jar.txt -b jar.txt -X POST --data @login.txt "$H"${q(o.loginPath)} 2>&1`);
  L.push('for i in 1 2 3; do', `  echo "#TARGET url=$H${o.loginPath} label=session-sample-$i run=$RUN"; ${meta('C18')}`, `  curl -sS -D - -o /dev/null -c "s$i.txt" -X POST --data @login.txt "$H"${q(o.loginPath)}`, 'done');
  t('mypage', `${H}${o.mypagePath}`, ' sensitive=1'); L.push(`curl -sS -i -b jar.txt "$H"${q(o.mypagePath)}`);
  t('api', `${H}${o.apiPath}`, ' sensitive=1'); L.push(`curl -sS -i -b jar.txt "$H"${q(o.apiPath)}`);
  t('unauth-api', `${H}${o.apiPath}`); L.push(`curl -sS -i "$H"${q(o.apiPath)}   # A-01：Cookie・Authorization を付けない`);

  L.push('', '# ---- 第3章：CORS（C6・C7・C8） ----');
  for (const [label, origin] of [['cors-reflect', 'https://evil.example'], ['cors-null', 'null'], ['cors-partial', `https://${o.host}.evil.net`]]) {
    t(label, `${H}${o.apiPath}`, ' sensitive=1');
    L.push(`curl -sS -v -o /dev/null -b jar.txt -H ${q(`Origin: ${origin}`)} "$H"${q(o.apiPath)} 2>&1`);
  }
  t('cors-preflight', `${H}${o.apiPath}`);
  L.push(`curl -sS -v -o /dev/null -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: authorization,content-type' "$H"${q(o.apiPath)} 2>&1`);

  if (o.wsPath) {                                             // C16：許可外の Origin でハンドシェイクし、101 が返るかを見る（R-09）
    t('websocket', `${H}${o.wsPath}`, ' sensitive=1');
    L.push(`curl -sS -v -o /dev/null --max-time 5 -b jar.txt -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' "$H"${q(o.wsPath)} 2>&1`);
  }

  L.push('', '# ---- 第4章：メソッド・転送・ヘッダ（C9・C14・C19・C22） ----');
  t('options', `${H}/`); L.push('curl -sS -i -X OPTIONS "$H/"');
  t('trace', `${H}/`); L.push('curl -sS -i -X TRACE "$H/"');
  t('host-inj', `${H}/`); L.push(`curl -sS -i -H 'X-Forwarded-Host: evil.example' "$H/"`);
  // T-06 は、転送した応答だけで判定する（ログイン画面が 200 を返すと na）。next= で実際に転送する URL があれば、そちらに置き換えるよう書いておく
  L.push('# T-06：ログイン画面が 200 を返すと判定できない（na）。next= などで実際に転送する URL（ログアウト、ログイン後の転送先）に置き換える');
  t('open-redirect', `${H}${o.loginPath}`); L.push(`curl -sS -D - -o /dev/null "$H"${q(`${o.loginPath}?next=https://evil.example&returnTo=https://evil.example&url=https://evil.example`)}`);
  t('jsonp', `${H}${o.apiPath}?callback=test123`, ' sensitive=1'); L.push(`curl -sS -i -b jar.txt "$H"${q(`${o.apiPath}?callback=test123`)}`);

  L.push('', '# ---- 第5章：エラー・既知ファイル（C13） ----');
  t('error-url', `${H}/%25%25%25`); L.push(`curl -sS -i "$H/%%%"`);
  t('error-api', `${H}${o.apiPath}/abc`); L.push(`curl -sS -i -b jar.txt "$H"${q(`${o.apiPath}/abc`)}`);
  t('robots', `${H}/robots.txt`); L.push('curl -sS -i "$H/robots.txt"');
  t('probes', `${H}/`);
  // 一時ファイルは mktemp で作る（共有の /tmp で決まった名前を使うと、他の利用者のシンボリックリンクで別のファイルを上書きされうる）。
  // 毎回空にしてから取得する（取得に失敗したとき、前のパスの中身が残って誤判定しないため）
  L.push('probe=$(mktemp)',
    `for p in /.git/HEAD /.env /.svn/entries /.DS_Store /WEB-INF/web.xml /package.json /composer.json /backup.zip /phpinfo.php /server-status /robots.txt /.well-known/security.txt ${q(`${o.staticPath}.map`)}; do`,
    '  : > "$probe"',
    `  info=$(curl -sS -o "$probe" -w 'code=%{response_code} size=%{size_download} ct=%{content_type}' "$H$p")`,
    `  printf '#PROBE run=%s path=%s head=%s %s\\n' "$RUN" "$p" "$(head -c 64 "$probe" | base64 | tr -d '\\n')" "$info"`,
    'done', 'rm -f "$probe"');

  L.push('', '# ---- 第4章：TLS（C11・C12・C23） ----');
  t('tls', `${H}/`);
  const hp = o.host.includes(':') ? o.host : `${o.host}:443`, sni = o.host.replace(/:\d+$/, '');
  // 診断対象のサーバは、ハンドシェイクのあとに任意のデータを送れ、s_client はそれを標準出力に出す（「unsupported protocol」「DNS:…」
  // 「notAfter=…」「New, TLSv1, Cipher is …」を書いて、T-09・T-10・T-11 の判定を変えられた）。サーバのデータは、ハンドシェイクの要約の
  // 最初の「Verify return code:」の行より後にしか出ないので、そこで切る。エラーは手元の openssl が標準エラーに出すものだけを見る
  const cut = `sed '/^ *Verify return code:/q'`;
  L.push(`openssl s_client -connect ${q(hp)} -servername ${q(sni)} -showcerts </dev/null 2>&1 | ${cut}`,
    `openssl s_client -connect ${q(hp)} -servername ${q(sni)} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName`,
    'tout=$(mktemp); terr=$(mktemp)',
    'for v in tls1 tls1_1 tls1_2 tls1_3; do',
    `  openssl s_client -connect ${q(hp)} -servername ${q(sni)} -$v -cipher 'DEFAULT@SECLEVEL=0' </dev/null >"$tout" 2>"$terr"; rc=$?`,
    // 手元の openssl がそのプロトコルに対応していない（no protocols available・unknown option）ときだけ err。「unsupported protocol」は、
    // サーバが別のバージョンを選んだ（このバージョンを拒否した）ときにも出るので、拒否として扱う
    `  if grep -qiE 'unknown option|no protocols available' "$terr"; then r=err`,
    // 「New, <版>, Cipher is <暗号>」の版は、OpenSSL 1.1 以降は暗号の最低の版（AES128-SHA は SSLv3）を出す。版は問わず、失敗したとき
    // の「New, (NONE), Cipher is (NONE)」だけを除く（TLS で始まるものだけにすると、TLS 1.0 の AES128-SHA を「拒否」とした）
    `  elif [ $rc -eq 0 ] && ${cut} "$tout" | grep -qE '^New, [^(,][^,]*, Cipher is [^(]'; then r=1`, '  else r=0; fi',
    `  printf '#TLSPROBE run=%s v=%s ok=%s\\n' "$RUN" "$v" "$r"`, 'done',
    'for c in RC4-SHA DES-CBC3-SHA NULL-SHA256 AES128-SHA ECDHE-RSA-AES128-SHA; do',
    `  openssl s_client -connect ${q(hp)} -servername ${q(sni)} -tls1_2 -cipher "$c:@SECLEVEL=0" </dev/null >"$tout" 2>"$terr"; rc=$?`,
    `  if grep -qiE 'no cipher match|unknown option' "$terr"; then r=err`,
    `  elif [ $rc -eq 0 ] && ${cut} "$tout" | grep -qE "^New, [^(,][^,]*, Cipher is $c\\$"; then r=1`, '  else r=0; fi',
    `  printf '#CIPHERPROBE run=%s c=%s ok=%s\\n' "$RUN" "$c" "$r"`, 'done', 'rm -f "$tout" "$terr"');

  if (o.dangerous) {
    L.push('', '# ---- 検証環境でだけ実行する試験（C20・C21・C17） ----');
    t('crlf', `${H}${o.loginPath}`); L.push(`curl -sS -D - -o /dev/null "$H"${q(`${o.loginPath}?next=%0d%0aSet-Cookie:%20crlf=1`)}`);
    // T-03：上書き先には副作用のない OPTIONS を使う（DELETE だと、上書きが効いた場合にデータが消える）。応答に Allow が出れば上書きが効いている
    t('method-override', `${H}${o.apiPath}`); L.push(`curl -sS -i -X POST -b jar.txt -H 'X-HTTP-Method-Override: OPTIONS' -H 'X-HTTP-Method: OPTIONS' "$H"${q(o.apiPath)}`);
    t('ctype', `${H}${o.apiPath}`); L.push(`curl -sS -i -X POST -b jar.txt -H 'Content-Type: text/plain' --data '{"a":1}' "$H"${q(o.apiPath)}   # A-08`);
    t('xff-spoof', `${H}/admin/`); L.push(`curl -sS -i -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' "$H/admin/"`);
  }

  L.push('', '# ---- 第2章：ログアウトと、ログアウト後の旧Cookie（C18） ----', 'cp jar.txt old.txt');
  t('logout', `${H}${o.logoutPath}`); L.push(`curl -sS -v -o /dev/null -c jar.txt -b jar.txt "$H"${q(o.logoutPath)} 2>&1`);
  t('after-logout', `${H}${o.mypagePath}`, ' sensitive=1'); L.push(`curl -sS -D - -o /dev/null -b old.txt "$H"${q(o.mypagePath)}`);

  L.push('} > out.txt', 'rm -f "$hdr" "$body"', `echo 'out.txt に書き出しました。ツールで読み込んだら、パスワードやCookieを含むファイルも削除してください：rm -f out.txt login.txt jar.txt old.txt s1.txt s2.txt s3.txt' >&2`);
  // 本文を取るコマンド（ここでは curl -sS -i と書く）は、ヘッダ（-D）と本文（-o）を別のファイルに取り、「ヘッダ・#BODY の印・本文」の順に出す。
  // -i の出力では本文と次の応答を見分けられず、診断対象のサーバが本文を「HTTP/1.1 200 OK」と偽のヘッダで始めると、本物の応答を置き換えられた。
  // 印は実行ごとの乱数を持つので、サーバは本文の終わりを作れない。取る前に2つのファイルを空にする（接続に失敗したとき、前のコマンドの
  // ヘッダ・本文を出さない）。最後に改行を出す（本文が改行で終わらないと、次の #TARGET が本文の続きになる）
  return L.map(l => l.replace(/^(\s*)curl -sS -i (.*?)(\s+#.*)?$/, (_, ind: string, args: string, comment = '') =>
    `${ind}: > "$hdr"; : > "$body"; curl -sS -D "$hdr" -o "$body" ${args}; cat "$hdr"; echo "#BODY run=$RUN"; cat "$body"; echo${comment}`)).join('\n') + '\n';
}

/** ラベルに対応する推奨コマンドのID（#META cmd= に出す） */
const CMD_BY_LABEL: [RegExp, string][] = [
  [/^top$/, 'C4'], [/^(page|static|notfound|mypage|api|unauth-api|robots)$/, 'C2'], [/^header-json$/, 'C10'], [/^http$/, 'C5'], [/^apex$/, 'C1'],
  [/^(pre-login|login|logout|after-logout)$/, 'C18'], [/^cors-null$/, 'C7'], [/^cors-preflight$/, 'C8'], [/^cors-/, 'C6'], [/^websocket$/, 'C16'],
  [/^(options|trace)$/, 'C9'], [/^host-inj$/, 'C14'], [/^open-redirect$/, 'C19'], [/^jsonp$/, 'C22'], [/^error-/, 'C25'], [/^probes$/, 'C13'],
  [/^tls$/, 'C11・C12・C23'], [/^crlf$/, 'C20'], [/^method-override$/, 'C21'], [/^xff-spoof$/, 'C17'], [/^ctype$/, 'C26'],
];
export const cmdOf = (label: string) => CMD_BY_LABEL.find(([re]) => re.test(label))?.[1] ?? '-';

/** 診断カバレッジの「入力不足」に添える、必要なコマンド */
export const ITEM_COMMANDS: Record<string, string> = {
  'H-02': 'C1（label=apex）', 'H-04': 'C24（csp-sample-*）', 'H-15': 'C18（logout）',
  'C-07': 'C18（session-sample-*）', 'C-09': 'C18（pre-login・login）', 'C-10': 'C15（label=http）', 'C-12': 'C18（logout・after-logout）',
  'R-01': 'C6', 'R-02': 'C7', 'R-03': 'C6（部分一致のOrigin）', 'R-04': 'C6', 'R-05': 'C8', 'R-06': 'C6', 'R-07': 'C6',
  'T-01': 'C9', 'T-04': 'C5（label=http）', 'T-05': 'C5', 'T-06': 'C19', 'T-07': 'C14', 'T-08': 'C20', 'T-09': 'C4・C12', 'T-10': 'C11・C23', 'T-11': 'C11', 'T-12': 'C5',
  'E-01': 'C25（label=error-*）', 'E-02': 'C2（ディレクトリのURL）', 'E-03': 'C13', 'E-04': 'C13・C2（/robots.txt）', 'E-05': 'C2（/actuator など）', 'E-06': 'C22',
  'A-01': 'unauth-*（認証なしでAPIを取得）', 'A-08': 'C26（label=ctype、検証環境）', 'A-11': 'method-*・old-*（DELETE などは手順書に従い手動で実行）', 'A-10': 'C25（label=error-*、APIのエラーを2つ以上）', 'R-09': 'C16（label=websocket）',
  'E-07': 'C2', 'E-08': 'C2', 'E-09': 'C2', 'E-10': 'C2（ログイン画面）', 'E-11': 'C1（ファイル配信URL）', 'E-12': 'C2（認証後ページ）', 'E-13': 'C2（JS）・C13（.map）',
};

/** 英語UI用（ITEM_COMMANDS と同じキーをそろえる。tests/i18n.test.ts が漏れを検出する） */
export const ITEM_COMMANDS_EN: Record<string, string> = {
  'H-02': 'C1 (label=apex)', 'H-04': 'C24 (csp-sample-*)', 'H-15': 'C18 (logout)',
  'C-07': 'C18 (session-sample-*)', 'C-09': 'C18 (pre-login, login)', 'C-10': 'C15 (label=http)', 'C-12': 'C18 (logout, after-logout)',
  'R-01': 'C6', 'R-02': 'C7', 'R-03': 'C6 (lookalike Origin)', 'R-04': 'C6', 'R-05': 'C8', 'R-06': 'C6', 'R-07': 'C6',
  'T-01': 'C9', 'T-04': 'C5 (label=http)', 'T-05': 'C5', 'T-06': 'C19', 'T-07': 'C14', 'T-08': 'C20', 'T-09': 'C4, C12', 'T-10': 'C11, C23', 'T-11': 'C11', 'T-12': 'C5',
  'A-01': 'unauth-* (fetch the API without credentials)', 'A-08': 'C26 (label=ctype, test environment)', 'A-11': 'method-*, old-* (run DELETE and similar tests manually, following the procedure)', 'A-10': 'C25 (label=error-*, 2 or more API errors)', 'R-09': 'C16 (label=websocket)',
  'E-01': 'C25 (label=error-*)', 'E-02': 'C2 (a directory URL)', 'E-03': 'C13', 'E-04': 'C13, C2 (/robots.txt)', 'E-05': 'C2 (/actuator, etc.)', 'E-06': 'C22',
  'E-07': 'C2', 'E-08': 'C2', 'E-09': 'C2', 'E-10': 'C2 (login page)', 'E-11': 'C1 (a file download URL)', 'E-12': 'C2 (page behind login)', 'E-13': 'C2 (JS), C13 (.map)',
};
