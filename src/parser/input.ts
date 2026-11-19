// parser/input.ts：#TARGET 形式の貼り付けを解析する（-i、-D -、-v、-L、%{header_json}、#META、#BODY、#PROBE、#TLSPROBE、#CIPHERPROBE）
import type { HttpResponse, ParseResult, ParseWarning, Target } from '../model';
import { assignHopUrls, baseLabel, BODY_LIMIT, cookieCapWarnings, isRedirectWithLocation, pushCookies, uniqueLabels } from './target';
import { autoAuthScheme, cookieNames, JWT_IN_TEXT, sentAuthOf, splitSetCookie } from './setCookie';

// curl と同じ緩さで読む：HTTP/ の大文字小文字を区別しない、理由句の前の空白がなくてもよい（HTTP/1.1 200OK）、コードは先頭の3桁（curl は
// 「HTTP/1.1 2000 OK」も 200 として受け付ける）。curl が受け付ける行を読めないと、次のヘッダ行「HTTP/1.1 302 Found: x」を応答にする偽装ができる
const STATUS_RE = /^HTTP\/(1\.0|1\.1|2|3)(?:\.0)?\s+(\d{3})\d*(?:\s*(.*))?$/i;
// #BODY：生成スクリプトが、ヘッダ（-D）のあと・本文（-o）の前に出す印。ここから次のマーカーまでを、直前の応答の本文としてそのまま読む
const MARKER_RE = /^#(TARGET|META|PROBE|TLSPROBE|CIPHERPROBE|BODY)\b(.*)$/;   // 既知のマーカーだけ。他の # 行は本文
const OPENSSL_START = /^(CONNECTED\(|depth=|Certificate chain|subject=|issuer=|notBefore=|notAfter=)/;
// OpenSSL 3.5 は CONNECTED( の前に「Connecting to 127.0.0.1」を出す
const CONNECTING = /^Connecting to \S+\s*$/;
// -v の出力の手がかり。今の curl は「*   Trying」（空白が3つ）や「* Established connection to」とも出すので、空白の数を問わない。
// プロキシを使うと、最初の行が「* Uses proxy env variable https_proxy == …」になる
const VERBOSE_HINT = /^\*\s+(Connected to|Established connection to|Trying|SSL connection|ALPN|Host |Uses proxy env variable )/;
// 改行のない本文（手で書いた curl -i の JSON・HTML）の直後にくっついたマーカー（{"id":1}#META at=…）。分けないと、マーカーが
// 前の本文に吸い込まれて黙って消える。#META（と #TARGET の at=・cmd= など）は、本文がたまたま含むことのまずない JSON・HTML の閉じ（} ] >）の
// 直後だけを分ける（#TARGET の url=・label= は下の STUCK_TARGET が分ける）
const STUCK_MARKER = /([}\]>])(#(?:TARGET|META)[ \t]+(?:url|label|at|cmd|response_code)=)/g;
// #TARGET は、どの文字の直後でも分ける（Express の res.sendStatus(401) の「Unauthorized」、text/plain の 404 の本文のように、改行のない本文は
// } ] > 以外でも終わる）。ただし、直前が空白・引用符のもの（本文の文中の「… #TARGET url=」、set -x の「+ echo '#TARGET …'」）は分けない
const STUCK_TARGET = /([^\n\s'"`])(#TARGET[ \t]+(?:url|label)=)/g;
// curl の進捗表示（-s を付けない実行で 2>&1 にしたもの）。見出しの行と数字の行は読み飛ばし、応答の行の前にくっついた部分は取り除く
// （遅い応答では、進捗表示とステータス行が同じ行に出る）。
// 欄の並び：% Total、Total、% Received、Received、% Xferd、Xferd、Dload、Upload、時刻の欄（0〜3個）、Speed。% の欄は 0〜100。
// 時刻の欄は curl の版で違う（--:--:--、0:00:02、curl 8.22 の 00:02、空欄）ので、あってもなくてもよい。
// 8個の数字の欄を続けて求めるので、本文の日時の行（2026-11-01 12:00:00）は当たらない
const PCT = String.raw`(?:100|\d{1,2})`, NUM = String.raw`[\d.]+[kMGTP]?`;
const METER = String.raw`\s*${PCT}\s+${NUM}\s+${PCT}\s+${NUM}\s+${PCT}\s+${NUM}\s+${NUM}\s+${NUM}(?:\s+(?:--:--:--|\d+:\d\d(?::\d\d)?))*\s+${NUM}\s*`;
// 進捗表示だけの行は、時刻の欄が1つ以上あるものだけ（本文の「1 2 3 4 5 6 7 8 9」のような数字の行を読み飛ばさない）。
// 応答の行の前にくっついたもの（METER_PREFIX）は、直後がステータス行・送受信の行なので、時刻の欄がなくてもよい
const METER_LINE = new RegExp(String.raw`^\s*(?:% Total\s+% Received|Dload\s+Upload\s+Total)|^(?=.*\d:\d\d)${METER}$`);
// curl 8.22 は時刻の欄を空欄にした行（「0      0   0 … 0                              0」）も出すので、時刻の欄の代わりに長い空白（10個以上）が
// 数字の欄のあいだにある行も進捗表示とする。ただし応答の本文の外だけ（本文の桁をそろえた数値の表を消さない）
const METER_LINE_NO_TIME = new RegExp(String.raw`^(?=.*\d {10,}\d)${METER}$`);
const METER_PREFIX = new RegExp(String.raw`^${METER}(?=(?:< )?HTTP\/[\d.]+ \d{3}|[<>*] )`);

// key=value を解析。ct= 以降は行末まで1つの値（空白を含むContent-Type対策）
export function attrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  // 行の最後の @ の位置は一度だけ求める（cmd= のたびに行の残りを調べると、cmd= を並べた本文の1行で入力の長さの2乗の時間がかかる）
  const lastAt = s.lastIndexOf('@');
  const ct = s.match(/(?:^|\s)ct=(.*)$/);
  if (ct) { out.ct = ct[1].trim(); s = s.slice(0, ct.index); }
  // 値は引用符で囲んでもよい（url="https://…"、label="top page"）。引用符は値に含めない
  for (const m of s.matchAll(/(?:^|\s)([^\s=]+)=(?:"([^"]*)"|'([^']*)'|(\S*))/g)) {
    out[m[1]] = m[2] ?? m[3] ?? m[4] ?? '';
    // cmd= の値が引用符・空白で切れ、行のあとに @ が残ったもの（cmd="curl 'https://first.last:'"$PASS"'@host/'"）は、値の終わりに「 @」を付ける。
    // CSV の実施コマンドの要約は、URL のあとの @ で URL を伏せる（export/cmdSummary.ts）。付けないと、ユーザー情報の終わりの @ が値から外れ、
    // 切れる前のユーザー名と数字のパスワードがホストとポートとして出る
    if (m[1] === 'cmd' && lastAt >= m.index + m[0].length) out.cmd += ' @';
  }
  return out;
}

/**
 * ラベルとして受け付ける形（英数字・日本語などの文字と _ . -、64文字まで。引用符で囲んだラベルの中の空白（label="top page"）も認める）。
 * * は使えない（例外の照合で任意の文字列の意味になる）。それ以外（引用符・記号を含むもの）は invalid-label にする。
 * ラベルは画面・エクスポート・例外ファイルにそのまま出るので、本文に入れた「#TARGET label=…」の残り（"password":"…"）を出さない
 */
const LABEL_OK = /^[\p{L}\p{N}_.-](?:[\p{L}\p{N}_. -]{0,62}[\p{L}\p{N}_.-])?$/u;
const SENS_TRUE = /^(?:1|true|yes)$/i, SENS_FALSE = /^(?:0|false|no)$/i;
/** #TARGET で読む名前（run= は採取の印） */
const TARGET_KEYS = new Set(['url', 'label', 'kind', 'sensitive', 'run']);
const newTarget = (a: Record<string, string>): Target => ({
  label: a.label === undefined ? 'default' : LABEL_OK.test(a.label) ? a.label : 'invalid-label', url: a.url, kind: (['html', 'api'].includes(a.kind?.toLowerCase() ?? '') ? a.kind.toLowerCase() : 'auto') as Target['kind'],   // kind=API も受け付ける
  // sensitive は 1・true・yes と 0・false・no を受け付ける。ほかの値は読まずに警告する（黙って無視すると、機密応答の項目が na や弱い判定になる）
  sensitive: SENS_TRUE.test(a.sensitive ?? '') ? true : SENS_FALSE.test(a.sensitive ?? '') ? false : undefined,
  verbose: false, responses: [], sentAuth: false, sentTokens: [], info: [], meta: {}, probes: [], tlsProbes: [], cipherProbes: [], openssl: [],
});
const hasData = (t: Target) =>
  t.responses.length + t.probes.length + t.tlsProbes.length + t.cipherProbes.length + t.openssl.length > 0;
/** この応答のあとに次の応答が続きうるか（転送・1xx・認証のやり直し）。200 の本文の中のステータス行らしき行では分けない */
const nextHopAfter = (status: number) => status < 200 || (status >= 300 && status < 400) || status === 401 || status === 407;
const newResponse = (sm: RegExpMatchArray): HttpResponse => ({ httpVersion: sm[1], status: +sm[2], reason: sm[3], headers: new Map(), rawNames: [], kind: 'final' });
/** 本文に1行を足す。本文は先頭64KBまで（1行が長い本文（圧縮したHTMLなど）も途中で切る） */
const appendBody = (r: HttpResponse, line: string) => {
  const room = BODY_LIMIT - (r.body?.length ?? 0);
  if (room > 0) r.body = (r.body ?? '') + (line.length < room ? `${line}\n` : line.slice(0, room));
};
const probeResult = (ok?: string): 'accepted' | 'rejected' | 'error' => (ok === '1' ? 'accepted' : ok === 'err' ? 'error' : 'rejected');

/** プロキシの CONNECT の応答の形：本文がなく、ヘッダがプロキシの決まったものだけ */
const PROXY_HEADERS = new Set(['proxy-agent', 'via', 'date', 'connection', 'keep-alive', 'content-length', 'proxy-connection']);
// 本文は、curl の失敗の行（curl: (35) …。-sS の標準エラー出力が混ざる）だけなら、ないものとみなす
const proxyShape = (r: HttpResponse) => !(r.body ?? '').replace(/^curl: \(\d+\).*$/gm, '').trim() && [...r.headers.keys()].every(k => PROXY_HEADERS.has(k)) && (r.headers.get('content-length') ?? ['0']).every(v => v.trim() === '0');
export function parseInput(input: string): ParseResult {
  const targets: Target[] = [];
  let t = newTarget({});
  let cur: HttpResponse | null = null, inHeaders = false, last = '', inOpenssl = false;
  let unparsed = 0; const emptyTargets: string[] = [];
  let json: string[] | null = null;                   // C10（%{header_json}）の読み取り中
  let jsonBytes = 0;
  // 読み取り中の JSON の括弧の深さと、文字列の中か（括弧が閉じたときだけ解析する。} で終わる行ごとに全体を解析し直すと、閉じない括弧の続く入力で遅い）
  const js = { depth: 0, inStr: false, esc: false };
  const sentNames = new WeakMap<Target, Set<string>>();   // 送った Cookie の名前（重なりを除くため）
  const pendingJson: HttpResponse[] = [];            // ステータスがまだない %{header_json} の応答（あとの #META response_code= で補う）
  let vBody = false;                                  // -v の受信ヘッダの終端（< の空行）のあと。次の「< HTTP/」の行までは本文として読み飛ばす
  let connectReq = false;                             // -v で「> CONNECT」を送った（プロキシのトンネル）。その応答のあとは本文がない
  let vHeaders = false;                               // 読み中の応答を -v の「< 」のステータス行で始めた
  const close = () => { if (cur) t.responses.push(cur); cur = null; inHeaders = false; last = ''; vHeaders = false; };
  const inBody = () => cur !== null && !inHeaders;
  const flush = () => { if (hasData(t)) targets.push(t); else if (t.label !== 'default') emptyTargets.push(t.label); };

  // 改行をそろえる。Windows の curl の -v（2>&1）は受信ヘッダの行を CR CR LF で終えるため、CR がいくつ続いても1つの改行にする
  // （CR CR LF を CR LF と CR に分けて読むと、受信ヘッダの各行のあとに空行ができ、ヘッダがすべて失われる）。
  // LF の付かない CR は1つずつ改行にする（古い Mac の改行。CR CR は空行）。結果は /\r+\n|\r/ と同じだが、CR の並びの先頭でだけ LF を探す
  // （/\r+\n|\r/ は、LF の付かない長い CR の並びで入力の長さの2乗の時間がかかる）
  const normalized = input.replace(/(?<!\r)\r+\n/g, '\n').replace(/\r/g, '\n');
  // 採取の印（run=）：コマンド生成器のスクリプトは、実行ごとの乱数を全部のマーカー行に付ける。最初の #TARGET に印があれば、同じ印のマーカー行だけを
  // マーカーとして読む。診断対象のサーバは印を知らないので、応答の本文に書いた「#TARGET label=login」「#META at=」「#PROBE」で、ターゲットを
  // 作ったり分けたりできない（印のないマーカーで偽の login を作れば、C-09①（高）を合格にできる）。印のない手書きの入力は、印なしで読む。
  // 印は、入力の最初の #TARGET の行からだけ取る（設計書のとおり）。印のある行ならどれでも取ると、手書きの入力で、診断対象のサーバが本文に書いた
  // 「#TARGET … run=<乱数>」で印を有効にし、利用者の本物のマーカーをすべて本文として読ませられる
  const firstTarget = normalized.match(/(?:^|\n)#TARGET[ \t]([^\n]*)/)?.[1];
  const runId = firstTarget !== undefined ? attrs(firstTarget).run?.match(/^[0-9a-f]{16,64}$/)?.[0] : undefined;
  const lines = runId
    // 印のある入力では、くっついたマーカーも印のあるものだけを分ける（行の中のマーカーの位置で分け、印のある部分だけを新しい行にする。
    // 先読みの正規表現で分けると、本文の1行に「#META 」が続く入力で、入力の長さの2乗の時間がかかる）
    ? splitRunMarkers(normalized, runId)
    : normalized.replace(STUCK_MARKER, '$1\n$2').replace(STUCK_TARGET, '$1\n$2').split('\n');
  const badSensitive: Target[] = [];                   // sensitive= の値を読めなかったターゲット（ラベルは付け直したあとのものを出す）
  const badTargetAttrs: string[] = [];                 // #TARGET の読めなかった指定（書き間違えた名前、受け付けないラベル・kind）
  let sawUnreadable = false;                          // このターゲットで、応答の前に読めない行があったか（コロンのあるステータス行の偽装の手がかり）
  let firstLine: 'pending' | 'hint' | 'other' = 'pending';   // 印のある入力で、ターゲットの最初の行が curl -v の「*」の行だったか
  // chunked の 3xx のあとに読んだホップ。-L で採取したターゲット（#META に num_redirects= がある）でなければ、トレーラの偽のホップなので捨てる
  // （curl 7.82 以前は、コロンのないトレーラの「HTTP/1.1 200 OK」も -D に書く。login の 302 のあとの偽の 200 の Set-Cookie で C-09 を合格にさせない）
  const trailerHops = new WeakSet<HttpResponse>();
  let ignoredMarkers = 0;                              // 印のない（違う）#TARGET の行の数。本文として読んだことを知らせる
  let inRaw = false;                                   // #BODY のあと：次のマーカーまでを本文としてそのまま読む（ステータス行・openssl の行・-v の行として読まない）
  let rawBody: HttpResponse | undefined;              // 本文を足す応答。#BODY の前に応答がない（curl が失敗した、ステータス行を読めなかった）ときは、
                                                       // 本文を捨てる（ふつうに読むと、本文の偽のステータス行が応答になる）
  for (let li = 0; li < lines.length; li++) {
    let line = lines[li]; let fromV = false;   // fromV：-v の「< 」の行（受信ヘッダ）
    // マーカー行（印のある入力では、印の同じものだけ）。マーカー行は進捗表示の行・接頭辞に当たらないので、ここで一度だけ見る
    const mk = line.match(MARKER_RE);
    const a = mk ? attrs(mk[2]) : undefined;
    const own = !!a && (!runId || a.run === runId);
    if (mk?.[1] === 'TARGET' && !own) ignoredMarkers++;   // 印の違う #TARGET（#BODY のあとの本文の中のものも）は、本文として読んだことを知らせる
    // #BODY のあとの本文は、次のマーカーまでそのまま本文に足す（本文の「HTTP/1.1 200 OK」・偽のヘッダ・CONNECTED(n) を読まない）
    if (inRaw && !own) {
      if (!rawBody) { if (line.trim()) unparsed++; continue; }
      appendBody(rawBody, line);
      continue;
    }
    if (METER_LINE.test(line) || (!inBody() && METER_LINE_NO_TIME.test(line))) continue;
    line = line.replace(METER_PREFIX, '');
    if (mk && a && own) {                              // マーカー行は必ず応答を閉じる
      // 前のターゲットの状態（CONNECT を送った、など）を持ち越さない（次のターゲットの本物の 200 をプロキシの応答とみなさない）
      close(); inOpenssl = false; vBody = false; connectReq = false; inRaw = false; rawBody = undefined; if (json) { unparsed += json.length; json = null; }
      const [, tag] = mk;
      // 印のある入力では、#BODY の前に本文として読んだ行（chunked の応答のトレーラ・curl の失敗の行）は捨て、本文は #BODY のあとだけにする
      // （トレーラはブラウザの本文ではない。トレーラにパスワード欄を書いて、ログアウト後の画面をログインのフォームに見せられないように）
      if (tag === 'BODY') { if (runId) for (const r of t.responses) r.body = undefined; inRaw = true; rawBody = t.responses[t.responses.length - 1]; continue; }   // 直前の応答（ヘッダだけ。-L では最後のホップ）の本文が続く
      if (tag === 'TARGET') {
        flush(); t = newTarget(a); pendingJson.length = 0; firstLine = 'pending'; sawUnreadable = false; if (a.sensitive !== undefined && t.sensitive === undefined) badSensitive.push(t);
        // 書き間違い（lable=）や受け付けない値（label=login/x、kind=page）は、sensitive= と同じく知らせる（黙って既定にすると、予約したラベルの
        // 横断の判定（C-09 など）が動かない理由が分からない）。値は出さない（ラベルは画面にそのまま出るので、受け付けない形のものは名前だけ）
        const unknown = Object.keys(a).filter(k => !TARGET_KEYS.has(k));
        if (unknown.length) badTargetAttrs.push(`${t.label}：${unknown.slice(0, 3).map(k => (/^[A-Za-z_][\w-]{0,30}$/.test(k) ? k : '…')).join('・')}=（使える名前は url・label・kind・sensitive）`);
        if (a.label !== undefined && t.label === 'invalid-label') badTargetAttrs.push('invalid-label：label= に使えるのは英数字・日本語などの文字と _ . - と空白（64文字まで）');
        if (a.kind !== undefined && !['html', 'api', 'auto'].includes(a.kind.toLowerCase())) badTargetAttrs.push(`${t.label}：kind= は html・api・auto のいずれか`);
      }
      else if (tag === 'META') {
        Object.assign(t.meta, a);
        // %{header_json} のあとに出した response_code（-w '%{header_json}' のあとの #META）も、その応答のステータスにする。
        // ステータスがまだない %{header_json} の応答だけを見る（行ごとに全応答を見直すと、#META の多い入力で2乗の時間になる）
        if (a.response_code) { for (const r of pendingJson) if (r.status === 0) r.status = Number(a.response_code) || 0; pendingJson.length = 0; }
      }
      else if (tag === 'PROBE') t.probes.push({ path: a.path ?? '', code: +a.code, size: +a.size, contentType: a.ct ?? '', headB64: a.head ?? '' });
      else if (tag === 'CIPHERPROBE') t.cipherProbes.push({ cipher: a.c ?? '', result: probeResult(a.ok) });
      else t.tlsProbes.push({ version: a.v ?? '', result: probeResult(a.ok) });
      continue;
    }
    // -v で本文も出力した（-o /dev/null のない）場合、本文の行（ドキュメントの例の「HTTP/1.1 200 OK」、「* 」「> 」で始まる行など）を
    // 応答・情報行・送信ヘッダとして読まない。-L の次の応答は、curl が「< HTTP/」の形で出す
    // -L や認証のやり直しで curl が次のリクエストを送るときの印（「* Issue another request」、「> GET /x HTTP/1.1」の要求行）でも終える
    // （2つ目のホップの TLS（* SSL connection）や送信した Origin・Cookie を失わない）。本文の「* SSL connection …」だけの行では終えない
    if (t.verbose && vBody) {
      // 「< HTTP/」で終えるのは、前の応答のあとに次の応答が続きうる（転送・1xx・認証のやり直し）ときだけ（200 の本文の中の「< HTTP/1.1 200 OK」
      // （curl の出力を載せたページなど）を次の応答にしない）
      const prev = t.responses.at(-1);
      if ((/^< HTTP\//.test(line) && (!prev || nextHopAfter(prev.status))) || /^\* Issue another request/.test(line) || /^> [A-Z]+ \S+ HTTP\/[\d.]+\s*$/.test(line)) vBody = false;
      else continue;
    }
    // 「Connecting to」は、次の行が CONNECTED( のときだけ openssl の出力の始まりとする（ほかの場所の同じ文言で、普通のターゲットを
    // openssl の出力にしない）。OpenSSL 3.5 は「Connecting to」のすぐあとに depth= の行を出す（2>&1）ので、tls のラベルでは次の行が
    // openssl の出力の始まりのときも含める。
    // 同じターゲットで HTTP の応答に続けた openssl の出力（CONNECTED( の行、Connecting to と CONNECTED( の2行）は、応答の本文の中でも
    // openssl の出力の始まりとして応答を閉じる（本文に入れると T-10・T-11 で使えない）。ほかの始まりの行（depth= など）は本文の外だけ
    const opensslHead = /^CONNECTED\(\d+\)\s*$/.test(line) || (CONNECTING.test(line) && (/^CONNECTED\(/.test(lines[li + 1] ?? '')
      || (baseLabel(t.label) === 'tls' && OPENSSL_START.test(lines[li + 1] ?? ''))));
    // 生成スクリプトの出力（印のある入力）では、openssl の出力を始めるのは tls のラベルだけ（生成スクリプトは tls 以外で openssl を実行しない。
    // 診断対象のサーバが本文に「CONNECTED(n)」を書いて、そのあとの本文を openssl の出力にし、E-07〜E-09・E-12 を消せないように）。
    // 始まりにするのは、応答の外（cur がない）の行と、本文の中の opensslHead だけ。ヘッダの中の行は始まりにしない（応答ヘッダに notAfter=2099… と
    // 「Verify return code: 0 (ok)」の行を書いて、本物の証明書の T-11①② を合格にさせない）。
    // 手書きの入力は、HTTP の応答に続けた openssl の出力をどのラベルでも読む
    const opensslAllowed = !runId ? (!inBody() ? (OPENSSL_START.test(line) || opensslHead) : opensslHead)
      : baseLabel(t.label) === 'tls' && (!cur || inBody()) && (cur ? opensslHead : (OPENSSL_START.test(line) || opensslHead));
    if (opensslAllowed) { close(); inOpenssl = true; }
    if (inOpenssl && !STATUS_RE.test(line) && !/^[*<>] /.test(line)) { t.openssl.push(line); continue; }
    inOpenssl = false;
    // 印のある入力では、ターゲットの最初の行（空行と、デバッグ版の curl の「WARNING:」「Note:」の行を除く）が curl -v の「*」の行のときだけ
    // -v として読む。curl -v 2>&1 の出力は必ず「*」の行で始まり（「* WARNING: failed to open cookie file」「* !!! WARNING !!!」も curl 自身の行）、
    // 診断対象のサーバは curl の行より前に行を書けない。応答の中で決めると、サーバがヘッダや読めないステータス行（2桁のコードなど）のあとに
    // 「* Connected to …」「> Cookie: …」を書いて Cookie を送ったことにし、認証なしの A-01①（高）を na に隠せる
    if (runId && firstLine === 'pending' && line.trim() && !/^(?:WARNING|Note):/.test(line)) {
      firstLine = /^\* /.test(line) || VERBOSE_HINT.test(line) ? 'hint' : 'other';
      if (firstLine === 'hint') t.verbose = true;   // デバッグ版の curl の「* !!! WARNING !!!」なども -v の情報行として読む
    }
    if (!runId && !inBody() && VERBOSE_HINT.test(line)) t.verbose = true;   // 印のある入力は、上の最初の行だけで決める
    if (t.verbose && !inBody()) {                      // -v の解釈は verbose ターゲットのヘッダ部だけ
      // 受信ヘッダ（< の行）の途中の空行は無視する。終端は「<」の行で、空行ではない。
      // Windows の curl は受信ヘッダの行を CR CR LF で終え、画面の入力欄（textarea）はそれを改行2つ（空行）に変えるため、
      // 空行で閉じると受信ヘッダがすべて失われる（パーサの CR CR LF の扱いは、入力欄を通ると効かない）
      if (cur && inHeaders && !line.trim()) continue;
      if (line.startsWith('* ')) { t.info.push(line.slice(2)); continue; }
      if (line.startsWith('> ')) {
        const h = line.slice(2);
        if (/^CONNECT /i.test(h)) connectReq = true;
        const o = h.match(/^origin:\s*(.*)$/i); if (o) t.sentOrigin = o[1].trim();
        const ck = h.match(/^cookie:\s*(.*)$/i), auv = h.match(/^authorization:(.*)$/i), au = !!auv;
        // 名前は増えた分だけを見る（行ごとに全体をコピーして推定し直すと、Cookie の行が多い -v で2乗の時間がかかる）
        const added: string[] = [];
        if (ck) {
          const names = t.sentCookieNames ?? (t.sentCookieNames = []);
          let seen = sentNames.get(t); if (!seen) { seen = new Set(names); sentNames.set(t, seen); }
          for (const n of cookieNames(ck[1])) if (!seen.has(n)) { seen.add(n); names.push(n); added.push(n); }
        }
        if (auv) { t.sentAuthorization = true; if (autoAuthScheme(auv[1])) t.sentAutoAuth = true; }
        if (ck || au) { t.sentAuth = t.sentAuth || sentAuthOf(au, added); for (const tok of h.match(JWT_IN_TEXT) ?? []) t.sentTokens.push(tok); }
        continue;
      }
      if (/^>\s*$/.test(line)) continue;               // 送信ヘッダの終端
      if (/^<\s*$/.test(line)) {
        // 1xx と、プロキシの CONNECT への応答（トンネル）のあとには本文がなく、本当のリクエスト（* SSL connection、> Cookie、> Origin）が続く。
        // そこを本文として読み飛ばすと、送信した Origin・Cookie や合意した TLS を失う
        const r = cur as HttpResponse | null;          // close() が書き換えるので、型の絞り込みに頼らない
        const st = r?.status ?? 0;
        const tunnel = st >= 200 && st < 300 && (connectReq || /connection established/i.test(r?.reason ?? ''));
        // CONNECT への応答が届いたら、トンネルができたかどうかにかかわらず CONNECT の状態を終える（407 で諦めた場合も）
        close(); vBody = st >= 200 && !tunnel; if (tunnel || (connectReq && st >= 200)) connectReq = false;
        continue;
      }  // 受信ヘッダの終端。-v では本文を解析しない
      // -i（-D -）と -v を一緒に端末で採取すると、-v の「< 」の行（標準エラー）と -i の同じ行（標準出力）が1行ずつ交互に並ぶ。
      // 「< 」の行で始めた応答のヘッダの途中にある「< 」のない行は、-i の写しとして読まない（中身のない応答を作ったり、ヘッダを二重に入れたりしない）
      if (vHeaders && cur && inHeaders && !line.startsWith('< ')) continue;
      if (line.startsWith('< ')) { line = line.slice(2); fromV = true; }
      else if (/^[{}] \[/.test(line)) continue;
    }
    const sm = line.match(STATUS_RE);
    // 印のある入力では、ヘッダの終わりの空行のあとのコロンのあるステータス行の形の行は、次の応答にしない（chunked の応答のトレーラ（curl は -D に
    // 書く）の「HTTP/1.1 401 Unauthorized: x」で応答を作り直させない）。今の curl はコロンのないトレーラの行を拒むので、コロンのないステータス行だけを
    // 次の応答（-L・1xx・401・407・CONNECT のあと）とする（コロンのないトレーラを書く古い curl は、下の chunked の扱いで見る）
    const trailer = !!sm && runId !== undefined && !!cur && !inHeaders && line.includes(':');
    // 印のある入力では、同じターゲットにすでに読めない行があったら、コロンのあるステータス行の形の行（「HTTP/1.1 302 Found: x」）は応答がまだなくても
    // 応答にしない（curl はこの行をヘッダとして出すので、読めないステータス行で始めた応答の2行目に書いて、本物の 200 を 302・401 にできる）。
    // 読めない行がなければ止めない（最初のステータス行そのものにコロンがある「HTTP/1.1 200 OK: x」も curl は受け付ける）。curl が受け付ける形は
    // STATUS_RE で読めるので、偽装は「読めない行のあとのコロンのある行」だけで起きる
    if (sm && runId !== undefined && !cur && line.includes(':') && sawUnreadable) { unparsed++; continue; }
    // 印のある入力で、chunked の HTTP/1.x の応答のヘッダのあと（#BODY の前）は、トレーラの行になりうる。curl 7.82 以前はコロンのない
    // トレーラの行も -D に書くので、コロンのないステータス行でも、次の応答にするのは -L・1xx・401・407 のあと（nextHopAfter）だけ
    // （200 のあとのトレーラの「HTTP/1.1 401 Unauthorized」で応答を作り直させない）。トレーラの行は本文にせず読み飛ばし、空行がなくても次の
    // ホップのステータス行を読む（curl はトレーラのあとに空行を書かずに次のホップを出す）
    if (runId && cur && !inHeaders && /^1/.test(cur.httpVersion) && (cur.headers.get('transfer-encoding') ?? []).some(v => /chunked/i.test(v))) {
      if (sm && !trailer && nextHopAfter(cur.status)) {
        const redirect = cur.status >= 300 && cur.status < 400;
        close(); cur = newResponse(sm); inHeaders = true; vHeaders = fromV;
        if (redirect) trailerHops.add(cur);   // -L でなければ、3xx のあとにホップは来ない（あとで #META の num_redirects= で確かめる）
        continue;
      }
      if (line.trim()) continue;
    }
    // 印のある入力では、ヘッダの途中（cur があり、まだヘッダを読んでいる）のステータス行の形の行は、新しい応答にしない（curl はコロンのある
    // 「HTTP/1.1 401 Unauthorized: x」をヘッダとして受け付けて出すので、診断対象のサーバがこの行で応答を作り直せる）。
    // -D・-v のどちらも、次の応答の前には空行（-v は「<」の行）がある
    if (sm && !inBody() && !(runId && cur && inHeaders)) { close(); cur = newResponse(sm); inHeaders = true; vHeaders = fromV; continue; }
    // 本文の直前の行が空行かは、本文の末尾だけを見る（本文全体を split すると、入力の長さの2乗の時間がかかる）。
    // -i の出力では、本文と次の応答を見分けられない（本文が「HTTP/1.1 200 OK」と偽のヘッダで始まると、次の応答として読む）。
    // 生成スクリプトは、ヘッダ（-D）と本文（-o）を分けて採取し、#BODY の印のあとを本文として読む（この分かれ目はサーバが作れない）
    if (sm && !trailer && inBody() && (cur!.body === undefined || nextHopAfter(cur!.status)) && /^\s*$/.test(lastLine(cur!.body ?? ''))) {   // -L で次のホップが続く場合
      close(); cur = newResponse(sm); inHeaders = true; continue;
    }
    // C10：ヘッダ名が小文字のJSON。-v の本文や、応答のあとの本文（{"items":[...]} など）は対象にしない
    if (!cur && !t.verbose && (json || (!t.responses.length && /^\s*\{\s*"[!#$%&'*+.^_`|~0-9A-Za-z-]+"\s*:\s*\[/.test(line)))) {
      if (!json) { json = []; jsonBytes = 0; js.depth = 0; js.inStr = false; js.esc = false; }
      json.push(line); jsonBytes += line.length;
      for (const ch of line) {
        if (js.inStr) { if (js.esc) js.esc = false; else if (ch === '\\') js.esc = true; else if (ch === '"') js.inStr = false; }
        else if (ch === '"') js.inStr = true; else if (ch === '{' || ch === '[') js.depth++; else if (ch === '}' || ch === ']') js.depth--;
      }
      // 解析するのは、括弧が閉じて } で終わる行だけ。上限は先に見る（どちらも、行ごとに全体をつないで解析し直す2乗の時間を避けるため）
      const r = jsonBytes > BODY_LIMIT || js.depth < 0 ? null : js.depth === 0 && /\}\s*$/.test(line) ? headerJson(json.join('\n'), t.meta.response_code) : undefined;
      // null：JSON としては読めたが、ヘッダの形ではない（curl -s で出力した API の本文など）。応答にせず、解析できない行として警告する
      if (r) { t.responses.push(r); if (r.status === 0) pendingJson.push(r); json = null; } else if (r === null || json.length > 500) { unparsed += json.length; json = null; }
      continue;
    }
    // curl の失敗の行（curl: (28) Operation timed out。WebSocket の 101 のあとの --max-time の時間切れなど）は、解析できない行に数えない
    if (!cur) { if (line.trim() && !/^curl: \(\d+\) /.test(line)) { unparsed++; sawUnreadable = true; } continue; }
    if (!inHeaders) { appendBody(cur, line); continue; }
    if (line.trim() === '') { inHeaders = false; continue; }
    // obs-fold：前の値に足すだけにする（毎回全体を trim し直すと、継続行の多い入力で2乗の時間がかかる。前の値はすでに trim 済み）
    if (/^[ \t]/.test(line) && last) {
      const v = cur.headers.get(last)!; const piece = line.trim();
      if (piece) v[v.length - 1] = v[v.length - 1] ? `${v[v.length - 1]} ${piece}` : piece;
      continue;
    }
    const i = line.indexOf(':'); if (i <= 0) continue;
    const raw = line.slice(0, i).trim(); last = raw.toLowerCase(); cur.rawNames.push(raw);
    const val = line.slice(i + 1).trim();
    // 値を push(...) に広げない（長い Set-Cookie の行でスタックがあふれる）
    const list = cur.headers.get(last) ?? cur.headers.set(last, []).get(last)!;
    if (last === 'set-cookie') { const d = pushCookies(list, splitSetCookie(val)); if (d) cur.droppedCookies = (cur.droppedCookies ?? 0) + d; }
    else list.push(val);
  }
  close(); flush();
  if (runId) for (const tg of targets) {
    const k = tg.responses.findIndex(r => trailerHops.has(r));
    if (k > 0 && tg.meta.num_redirects === undefined) {
      const body = tg.responses.at(-1)!.body;   // #BODY の本文は最後の応答に付けたので、本物の最後の応答に移す
      tg.responses.length = k; tg.responses[k - 1].body = body;
    }
  }
  for (const tg of targets) tg.responses.forEach((r, i) => {
    // CONNECT（プロキシ）の応答：本文のない 2xx のあとに応答が続くもの（理由句はプロキシによって違う）。理由句「Connection established」の扱いは下
    const proxyReply = r.status >= 200 && r.status < 300 && i < tg.responses.length - 1 && !r.body?.trim() && r.reason !== 'header_json';
    // プロキシの認証要求（407）と、curl が認証し直した 401 のあとには、同じリクエストの応答が続く。その URL 自身の応答ではないので、
    // 最初の応答（T-04・A-01・C-09・C-12 などが見るステータス）にしない。プロキシの 407 を最初の応答にすると、T-04 が「HTTP を拒否」と合格にする
    const retried = i < tg.responses.length - 1;
    if (r.status > 0 && r.status < 200) r.kind = 'informational';
    // 407 はプロキシだけが返すので、あとに応答が続かなくても（プロキシの認証に失敗して諦めた）サイトの応答にしない
    // 理由句「Connection established」でプロキシの応答とみなすのは、あとに応答が続くときだけ（最後の応答の理由句を変えるだけでサイトの応答を
    // 消させない）。ただし、あとに応答が続かない（CONNECT のあとで curl が失敗した。社内のプロキシ越しの Schannel の失効確認の失敗など）ときも、
    // 本文がなく、ヘッダがプロキシの応答の形（Proxy-Agent・Via・Date・Connection・Keep-Alive・Proxy-Connection・Content-Length: 0 だけ）なら connect。
    // この形をサーバが返しても、空の応答と同じで判定には使えない
    else if ((r.status === 200 && /connection established/i.test(r.reason ?? '') && (retried || proxyShape(r))) || proxyReply || r.status === 407) r.kind = 'connect';
    else if (r.status === 401 && retried) r.kind = 'challenge';
    else if (isRedirectWithLocation(r)) r.kind = 'redirect';
    if (r.body !== undefined && !r.body.trim()) r.body = undefined;
  });
  for (const tg of targets) assignHopUrls(tg);
  const dup = uniqueLabels(targets);
  const ignored: ParseWarning[] = ignoredMarkers ? [{ kind: 'ignored-marker',
    detail: `採取の印（run=）が最初の #TARGET と違う #TARGET の行が${ignoredMarkers}行あり、応答の本文として読みました（診断対象が本文に書いたもの、または別の採取の出力を付け足したもの。付け足した出力は別に判定してください）` }] : [];
  const badAttr: ParseWarning[] = badSensitive.length ? [{ kind: 'invalid-attr', detail: `sensitive= の値を読めませんでした（${badSensitive.slice(0, 5).map(x => x.label).join(', ')}${badSensitive.length > 5 ? ' など' : ''}）。1（機密）か 0（機密でない）を指定してください` }] : [];
  // 最初の #TARGET に印がなく、あとに印のある #TARGET（生成スクリプトの出力）が続く：印は最初の #TARGET からだけ取るので、生成スクリプトの出力も
  // 印のない入力として読み、応答の本文に書かれたマーカーを読む（手書きのターゲットを前に足すと印による保護が外れるので、知らせる）
  const mixedRun: ParseWarning[] = !runId && /(?:^|\n)#TARGET[ \t](?:[^\n]*[ \t])?run=[0-9a-f]{16,64}(?=[ \t\n]|$)/.test(normalized) ? [{ kind: 'mixed-run',
    detail: '生成スクリプトの出力（run= の印のある #TARGET）の前に、印のない #TARGET があります。この場合は印を使わずに読むので、応答の本文に書かれた #TARGET などのマーカーもターゲットとして読みます。生成スクリプトの出力だけを先頭から貼り付け、手書きの出力は別に貼り付けて判定してください' }] : [];
  if (badTargetAttrs.length) badAttr.push({ kind: 'invalid-attr', detail: `#TARGET の指定を読めませんでした（${badTargetAttrs.slice(0, 5).join('、')}${badTargetAttrs.length > 5 ? ' など' : ''}）` });
  return { targets, warnings: [...dup, ...ignored, ...mixedRun, ...badAttr, ...collectWarnings(targets, unparsed, emptyTargets), ...cookieCapWarnings(targets)] };
}

// %{header_json} にほぼ必ずある応答ヘッダ。どれもない JSON（{"tags":["a"]} など）はヘッダとみなさない
const TYPICAL_HEADER = /^(?:date|content-type|content-length|server|cache-control|set-cookie|strict-transport-security|vary|etag|last-modified|location|expires|age|via|connection|transfer-encoding)$/;
/**
 * curl -w '%{header_json}' の出力。ステータスは #META response_code（生成スクリプトは同じ -w で %{header_json} の前に出す）から取る。なければ0（不明。あとの #META で補う）。
 * undefined：まだ JSON として読めない（続きの行を待つ）。
 * null：JSON だがヘッダの形ではない（名前がヘッダに使える文字、値が文字列の配列、よくあるヘッダを含む、のどれかを満たさない）
 */
function headerJson(text: string, code?: string): HttpResponse | null | undefined {
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return undefined; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const entries = Object.entries(obj as Record<string, unknown>);
  const isHeaders = entries.some(([k]) => TYPICAL_HEADER.test(k.toLowerCase()))
    && entries.every(([k, v]) => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(k) && Array.isArray(v) && v.every(x => typeof x === 'string'));
  if (!isHeaders) return null;
  const headers = new Map<string, string[]>(); let dropped = 0;
  for (const [k, v] of entries)
    if (k.toLowerCase() === 'set-cookie') { const list: string[] = []; dropped += pushCookies(list, (v as string[]).flatMap(splitSetCookie)); headers.set('set-cookie', list); }
    else headers.set(k.toLowerCase(), v as string[]);
  return { httpVersion: '', status: Number(code) || 0, reason: 'header_json', headers, rawNames: [...headers.keys()], kind: 'final', ...(dropped ? { droppedCookies: dropped } : {}) };
}

const MARK_START = /#(?:TARGET|META|PROBE|TLSPROBE|CIPHERPROBE)[ \t]/g;
/**
 * 印のある入力の行分け：行の中のマーカー（#TARGET・#META など）の位置で部分に分け、自分の部分に「run=<印>」があるものだけを新しい行にする
 * （改行のない本文の直後にくっついた本物のマーカーを分ける）。ほかの部分は前の部分につなぎ直す。時間は入力の長さに比例する
 */
function splitRunMarkers(text: string, runId: string): string[] {
  const own = new RegExp(String.raw`[ \t]run=${runId}(?![\w])`);
  return text.split('\n').flatMap(line => {
    if (!line.includes(`run=${runId}`)) return [line];
    const starts = [...line.matchAll(MARK_START)].map(m => m.index).filter(i => i > 0);
    if (!starts.length) return [line];
    const out: string[] = []; let cur = line.slice(0, starts[0]);
    starts.forEach((s, i) => {
      const seg = line.slice(s, starts[i + 1] ?? line.length);
      if (own.test(seg)) { out.push(cur); cur = seg; } else cur += seg;
    });
    out.push(cur);
    return out;
  });
}

/** 本文の最後の行（本文は「行 + 改行」でつなぐので、最後の改行の前の行。body.split('\n').at(-2) と同じ）。改行がなければ空 */
function lastLine(body: string): string {
  const e = body.lastIndexOf('\n');
  return e < 0 ? '' : body.slice(body.lastIndexOf('\n', e - 1) + 1, e);
}

function collectWarnings(targets: Target[], unparsed: number, emptyTargets: string[]): ParseWarning[] {
  const w: ParseWarning[] = [];
  if (unparsed) w.push({ kind: 'unparsed-lines', detail: `どのターゲットにも属さない行が${unparsed}行ありました（HTTPのステータス行より前の行など）` });
  for (const l of emptyTargets) w.push({ kind: 'orphan-block', detail: `#TARGET label=${l} にデータがありません` });
  for (const t of targets) if (!t.url && !t.meta.url_effective)
    w.push({ kind: 'unknown-url', label: t.label, detail: `ターゲット「${t.label}」のURLが分かりません。HTTPSかどうかを使う項目は判定できません（#TARGET に url= を付けてください）` });
  // url= はあるが、スキームのある URL として読めない（a.example/r、https:/a.example）。HTTPS かどうかを使う項目が黙って適用外になる
  else if (t.url && !/^[a-z][\w+.-]*:\/\/[^/?#\s]/i.test(t.url))
    w.push({ kind: 'unknown-url', label: t.label, detail: `ターゲット「${t.label}」の url= を URL として読めません。HTTPSかどうかを使う項目は判定できません（https:// から書いてください）` });
  // ターゲットごとに1つにまとめ、どのプローブかを書く
  for (const t of targets) {
    const errs = [...t.tlsProbes.map(p => p.result === 'error' ? p.version : ''), ...t.cipherProbes.map(p => p.result === 'error' ? p.cipher : '')].filter(Boolean);
    if (errs.length) w.push({ kind: 'tls-probe-error', detail: `ターゲット「${t.label}」：手元のOpenSSLが対応していないプローブがあります（${[...new Set(errs)].slice(0, 10).join('・')}。判定不能）` });
  }
  // 応答がプロキシのもの（407・CONNECT）だけのターゲットは、サイトの応答を判定できない。黙って判定から消えないよう知らせる
  // WebSocket の 101（1xx）だけの応答は、プロキシの応答ではない
  for (const t of targets) if (t.responses.some(r => r.kind === 'connect') && t.responses.every(r => r.kind === 'connect' || r.kind === 'informational'))
    w.push({ kind: 'proxy-only', label: t.label, detail: `ターゲット「${t.label}」：プロキシの応答（HTTP ${t.responses.map(r => r.status).join('・')}）しかなく、サイトの応答を判定できません（プロキシの認証を確かめて採取し直してください）` });
  return w;
}
