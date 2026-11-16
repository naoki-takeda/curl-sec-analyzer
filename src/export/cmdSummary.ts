// export/cmdSummary.ts：CSV の「実施コマンド」「実施日時」に出す #META cmd=・at= の要約（第8章）
// 残してよい形だけを残す（許可リスト）。秘密らしい場所を推し量って伏せる作り（第30回までの maskCommand）は、直前の回の修正が
// 次の漏れを入れることを第25回〜第30回で毎回くり返したので、やめた。突き合わせのキー（engine/targetKey.ts）と同じ考え方で、
// 出す語は次のどれかに限る。それ以外の語（値・ユーザー名・パスワード・ヘッダの値・知らない語）はすべて **** にする：
// - コマンドのID（C1〜C26、HAR、-）。コマンド生成器と HAR の取り込みが書くのはこれだけ
// - プログラムの名前（一覧にあるもの。パスは除く。C:\Users\<名前>\… の名前を出さない）
// - シェルの区切り（|・;・&&・> など）
// - オプションの名前：プログラムごとの一覧にある長いオプションと、決まった文字だけのまとめ書きの短いオプション。値を続けて書いたもの
//   （-ualice:pw、--user=…）は名前と ****。一覧にない名前は ****（値の中の「_--secret」を名前として出さない）
// - -H のあとのヘッダの名前（決まった形のもの）と、httpie の項目の名前（一覧にあるもの）。値は ****
// - HTTP のメソッド、openssl のサブコマンド、環境変数の名前（決まった形のもの）
// - URL は突き合わせのキーと同じ形（urlKey：パスのトークンは *、クエリは名前だけ）
// このファイルは mask.ts を読み込まない（tests/cmd-summary.test.ts で確かめる）
import { urlKey } from '../engine/targetKey';

const ID = /^(?:C\d{1,2}|HAR|-)$/;
type Family = 'curl' | 'wget' | 'httpie' | 'openssl' | 'ps' | 'other';
const FAMILY: Record<string, Family> = {
  curl: 'curl', wget: 'wget', http: 'httpie', https: 'httpie', xh: 'httpie', xhs: 'httpie', httpie: 'httpie', openssl: 'openssl',
  powershell: 'ps', pwsh: 'ps', 'invoke-webrequest': 'ps', iwr: 'ps', 'invoke-restmethod': 'ps', irm: 'ps',
};
for (const p of ['nc', 'ncat', 'nmap', 'sslscan', 'testssl', 'testssl.sh', 'grep', 'egrep', 'jq', 'sed', 'awk', 'head', 'tail', 'cat', 'echo', 'printf', 'base64', 'timeout',
  'sudo', 'env', 'dig', 'nslookup', 'host', 'python', 'python3', 'node', 'bash', 'sh', 'sleep', 'date', 'tee', 'sort', 'uniq', 'wc', 'xargs']) FAMILY[p] = 'other';
const OPERATOR = /^(?:\|\|?|&&|;|&|>>?|<|2>&1|[12]?>\/dev\/null)$/;
const METHODS = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)$/i;
const SUBCOMMANDS = /^(?:s_client|s_server|s_time|x509|req|ciphers|version|verify|rsa|ec|pkey|dgst)$/;

const words = (s: string) => s.trim().split(/\s+/);
/** 長いオプション（名前 → 値を取るか）。プログラムごと。一覧にない名前は出さない */
const longTable = (withValue: string, flags: string) => new Map<string, boolean>([...words(withValue).map(n => [n, true] as const), ...words(flags).map(n => [n, false] as const)]);
const CURL_LONG = longTable(`
  abstract-unix-socket alt-svc aws-sigv4 cacert capath cert cert-type ciphers config connect-timeout connect-to continue-at cookie cookie-jar create-file-mode
  crlfile curves data data-ascii data-binary data-raw data-urlencode delegation dns-servers doh-url dump-header ech engine etag-compare etag-save expect100-timeout
  form form-string ftp-account ftp-method ftp-port happy-eyeballs-timeout-ms header hostpubmd5 hsts interface ipfs-gateway json keepalive-time key key-type krb
  libcurl limit-rate local-port login-options mail-auth mail-from mail-rcpt max-filesize max-redirs max-time netrc-file noproxy oauth2-bearer output output-dir
  parallel-max pass pinnedpubkey preproxy proto proto-default proto-redir proxy proxy-cacert proxy-capath proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile
  proxy-header proxy-key proxy-key-type proxy-pass proxy-pinnedpubkey proxy-service-name proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword proxy-tlsuser
  proxy-user proxy1.0 quote random-file range rate referer request request-target resolve retry retry-delay retry-max-time sasl-authzid service-name socks4 socks4a
  socks5 socks5-gssapi-service socks5-hostname speed-limit speed-time stderr telnet-option tftp-blksize time-cond tls-max tls13-ciphers tlsauthtype tlspassword
  tlsuser trace trace-ascii trace-config unix-socket upload-file url url-query user user-agent variable write-out`, `
  anyauth append basic ca-native cert-status compressed compressed-ssh create-dirs crlf digest disable disable-eprt disable-epsv disallow-username-in-url doh-cert-status
  doh-insecure fail fail-early fail-with-body false-start form-escape ftp-create-dirs ftp-pasv ftp-pret ftp-skip-pasv-ip ftp-ssl-ccc ftp-ssl-control get globoff
  haproxy-protocol head help http0.9 http1.0 http1.1 http2 http2-prior-knowledge http3 http3-only ignore-content-length include insecure ipv4 ipv6
  junk-session-cookies list-only location location-trusted manual metalink mptcp negotiate netrc netrc-optional next no-alpn no-buffer no-clobber no-keepalive
  no-npn no-progress-meter no-sessionid ntlm ntlm-wb parallel parallel-immediate path-as-is post301 post302 post303 progress-bar proxy-anyauth proxy-basic
  proxy-ca-native proxy-digest proxy-http2 proxy-insecure proxy-negotiate proxy-ntlm proxy-ssl-allow-beast proxy-ssl-auto-client-cert proxy-tlsv1 proxytunnel raw
  remote-header-name remote-name remote-name-all remote-time remove-on-error retry-all-errors retry-connrefused sasl-ir show-error show-headers silent skip-existing
  socks5-basic socks5-gssapi socks5-gssapi-nec ssl ssl-allow-beast ssl-auto-client-cert ssl-no-revoke ssl-reqd ssl-revoke-best-effort sslv2 sslv3 styled-output
  suppress-connect-headers tcp-fastopen tcp-nodelay tftp-no-options tls-earlydata tlsv1 tlsv1.0 tlsv1.1 tlsv1.2 tlsv1.3 tr-encoding trace-ids trace-time use-ascii
  verbose version xattr`);
const WGET_LONG = longTable(`
  output-document output-file user-agent header user password http-user http-password proxy-user proxy-password post-data post-file body-data body-file method
  load-cookies save-cookies timeout tries wait ca-certificate certificate private-key directory-prefix execute referer max-redirect`, `
  no-check-certificate server-response spider quiet verbose debug no-verbose keep-session-cookies save-headers content-on-error no-cookies https-only mirror
  recursive help version`);
const HTTPIE_LONG = longTable(`
  auth auth-type bearer print output session session-read-only verify cert cert-key cert-key-pass proxy timeout max-redirects style pretty format-options ssl ciphers
  default-scheme response-charset response-mime boundary raw history-print`, `
  json form multipart verbose headers body all follow check-status ignore-stdin offline download continue stream quiet chunked compress ignore-netrc debug traceback
  help version https path-as-is`);
/** 「-」1つで長い名前のオプション（PowerShell・openssl）。名前は大文字・小文字を区別しない */
const PS_LONG = longTable(`
  uri method headers body contenttype maximumredirection timeoutsec outfile credential authentication token websession sessionvariable useragent proxy
  proxycredential form infile responseheadersvariable statuscodevariable command executionpolicy`, `
  usebasicparsing skipcertificatecheck skiphttperrorcheck allowunencryptedauthentication noproxy noprofile nologo`);
const OPENSSL_LONG = longTable(`
  connect servername alpn cipher ciphersuites in out cafile capath nameopt inform outform starttls proxy cert key pass sess_out sess_in groups curves sigalgs ext
  checkend verify host port timeout`, `
  showcerts tls1 tls1_1 tls1_2 tls1_3 no_tls1 no_tls1_1 no_tls1_2 no_tls1_3 noout subject issuer dates text brief status verify_return_error crlf ign_eof quiet
  fingerprint sha256 sha1 pubkey serial enddate startdate purpose email hash modulus noverify legacy_renegotiation ct msg state debug prexit reconnect ocsp_uri`);
/**
 * 短いオプション：[値を取らない文字, 値を取る文字]。まとめ書きは、値を取らない文字だけを4文字まで（同じ文字を2回使わない）並べ、最後に値を取る文字を
 * 1つ置ける。curl のまとめ書きに使うのはよく使う文字だけ（-sSLk・-fsSL・-sSIv）。ほかの値を取らない文字（-O・-J・-R など）は1文字のときだけ。
 * 文字を広げると、値の中の「_-lBA」のようなトークンのかけらをオプションとして出した
 */
const CURL_RARE_FLAGS = 'aBijJlMnOpqRVZ0123456';   // 数字（-0・-4）も1文字のときだけ（-G102SA のようなかけらを出さない）
const SHORT: Record<Family, [string, string]> = {
  curl: ['fgGIikLNsSv#', 'AbcCdDeEFHKmoPQrtTuUwxXyYz'],
  wget: ['qvScNrkpmdx46', 'OoUePtTwi'],
  httpie: ['bhvfjFdScIqxm', 'aApos'],
  openssl: ['', ''], ps: ['', ''],
  // ほかのプログラム（grep・jq など）と知らないプログラムは、2文字まで（値の中の「_-xZX」のようなかけらを出さない）
  other: ['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', ''],
};
const HEADER_OPTIONS = new Set(['-H', '--header', '--proxy-header', '-headers', '--headers']);
const METHOD_OPTIONS = new Set(['-X', '--request', '--method', '-method']);
/** httpie の項目として名前を残すもの（一覧の外は ****。「_」で区切った値の続き（abc_DEF==）を項目の名前として出さない） */
const HTTPIE_HEADERS = new Set(words(`authorization proxy-authorization cookie accept accept-language accept-encoding content-type user-agent referer origin host
  api-key apikey dnt te expect forwarded via date
  cache-control pragma if-none-match if-modified-since x-requested-with x-forwarded-for x-forwarded-host x-forwarded-proto x-real-ip x-api-key x-auth-token
  x-csrf-token x-xsrf-token upgrade connection access-control-request-method access-control-request-headers x-http-method-override x-original-url x-rewrite-url
  content-length transfer-encoding range`));
/** CSV の実施コマンドの URL に名前を残すクエリ（一覧の外は *） */
const QUERY_NAMES = new Set(words(`q page per_page limit offset sort order lang locale hl format username user email password token api_key apikey access_token
  id_token refresh_token client_id client_secret grant_type scope redirect_uri response_type code state nonce code_challenge code_challenge_method prompt id name
  next redirect return returnto return_to callback url ticket samlrequest samlresponse relaystate utm_source utm_medium utm_campaign ref v s search query filter
  category tab view mode type dir fields include expand cursor after before from to start end size count sid session jsessionid phpsessid auth key signature sig
  expires`));
const ENV_NAMES = new Set(words(`HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY FTP_PROXY LANG LC_ALL TZ PATH HOME SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE
  SSLKEYLOGFILE CURL_HOME REQUESTS_CA_BUNDLE NODE_TLS_REJECT_UNAUTHORIZED NODE_EXTRA_CA_CERTS`));
const HTTPIE_PARAMS = new Set(words(`q page per_page limit offset sort order lang format username user email password token api_key apikey access_token client_id
  client_secret grant_type scope redirect_uri code state id name`));
/**
 * 名前の形（-H のあとのヘッダ、環境変数）：英字の語を - か _ でつなぎ、語の後ろに短い数字を付けてよい。40文字まで。語ごとに24文字まで、
 * 大文字・小文字の入れ替わりは4回まで（突き合わせのキーの keyPiece と同じ。X-Api-Key・HTTPS_PROXY は残し、乱数の英字は残さない）
 */
const NAME_SHAPE = /^(?=.{1,40}$)[A-Za-z]+(?:[0-9][0-9.]{0,3}[A-Za-z]{0,2})?(?:[-_][A-Za-z]+(?:[0-9][0-9.]{0,3}[A-Za-z]{0,2})?)*$/;
const nameLike = (x: string) => NAME_SHAPE.test(x) && x.split(/[-_.\d]+/).every(p => p.length <= 24 && (p.match(/[a-z]+|[A-Z]+/g) ?? []).length <= 4);
const MAX = 200;

/** 1つの語。引用符で囲んだもの、URL（「_」を含む）、それ以外（空白と「_」で区切る）。閉じない引用符で残り全部を取らないよう、行の中に限る */
// URL は、空白・引用符・次のオプション（_-）・次の URL・シェルの区切り（_|）・httpie のヘッダとクエリの項目（_Name:・_api_key==）の前まで。
// 「_name=」では止めない（?access_token=… の「_token=」で止まり、クエリの名前が切れた）。環境変数の指定（HTTPS_PROXY=…・https_proxy=…）と
// httpie の項目（api_key==…）、openssl の s_client・-tls1_2 は、名前に「_」を含むので1つの語として読む。
// 繰り返しは長さを区切る（区切らないと、「A_」の繰り返しで語の始まりごとに終わりまで読み、入力の長さの2乗の時間がかかった）
const URL_SCHEME = String.raw`(?:[hH][tT][tT][pP][sS]?|[wW][sS][sS]?|[fF][tT][pP])`;
const URL_STOPS = String.raw`-|(?:https?|wss?|ftp):|[|;<>]|&&|[A-Za-z][\w-]{0,40}(?::|==)`;
/**
 * 空白を含まないコマンド（#META の値は空白を入れられないので「_」で区切る）では、URL のパスの部分を「_」で終える。「_」で区切った URL のあとの値
 * （login__w-2-bL_…）がパスの続きとして読まれ、キーの形でも英字・数字のかけらが残った。パスに「_」を含む URL（/api/user_info）は
 * /api/user と **** になる。空白で区切ったコマンドでは、パスの「_」も URL の一部として読む
 */
const buildToken = (underscoreForm: boolean) => new RegExp([
  String.raw`"[^"\n]*"`, String.raw`'[^'\n]*'`,
  // パスの部分では「_name=」の前でも止める（httpie の本文の項目 _password=… を URL のパスとして読み、値のかけらをパスの語として出した）。
  // クエリ（? のあと）では止めない（?access_token=… の「_token=」で止まり、クエリの名前が切れた。クエリの値はキーに残らない）
  // ユーザー情報（@ まで）は先に読む（「_」「\」を含むユーザー名 svc_account:…@ で URL が切れ、前半がホストとして出た）
  underscoreForm
    ? String.raw`${URL_SCHEME}:\/\/(?:[^\s/?#@]{0,200}@)?[^\s"'?#_]*(?:[?#][^\s"']*?(?=[\s"']|_(?:${URL_STOPS})|$))?`
    : String.raw`${URL_SCHEME}:\/\/(?:[^\s/?#@]{0,200}@)?[^\s"'?#]*?(?:(?=[\s"']|_(?:${URL_STOPS}|[A-Za-z][\w-]{0,40}=)|$)|[?#][^\s"']*?(?=[\s"']|_(?:${URL_STOPS})|$))`,
  String.raw`[A-Za-z][A-Za-z0-9]{0,40}(?:_[A-Za-z0-9]{1,40}){1,6}(?:==|:=|=)[^\s_]*`,
  String.raw`s_(?:client|server|time)(?![A-Za-z])`, String.raw`-(?:no_)?tls1_[1-3](?![\w-])`,
  String.raw`-(?:verify_return_error|sess_out|sess_in|ign_eof|ocsp_uri|legacy_renegotiation)(?![\w-])`,
  String.raw`[^\s_]+`,
].join('|'), 'y');
const TOKEN_SPACED = buildToken(false);
const TOKEN_UNDERSCORE = buildToken(true);
const SEP = /[\s_]+/y;

/** 語を順に返す（出力が上限を超えたら、それ以上は読まない） */
function* tokenize(s: string): Generator<string> {
  const TOKEN = /\s/.test(s) ? TOKEN_SPACED : TOKEN_UNDERSCORE;
  let i = 0;
  while (i < s.length) {
    SEP.lastIndex = i; const sep = SEP.exec(s); if (sep) { i += sep[0].length; continue; }
    TOKEN.lastIndex = i; const t = TOKEN.exec(s);
    if (!t || !t[0]) { yield s[i]; i++; continue; }   // 閉じていない引用符の1文字など
    yield t[0]; i += t[0].length;
  }
}

const unquote = (t: string) => t.replace(/^["']|["']$/g, '');
const programName = (t: string): string => unquote(t).split(/[\\/]/).pop()!.replace(/\.exe$/i, '').toLowerCase();
/**
 * URL：突き合わせのキーの形にする。次のものは ****：
 * - ユーザー情報のパスワードに「/」「\」「?」「#」があり、ホストの前に @ がないもの（https://alice:2024#pw@…）。ホストの部分にユーザー名やパスワードが残る
 * - ホストが「.」を含まないもの（localhost と IP アドレスは除く）。URL がユーザー情報の途中で切れると（引用符を含むパスワード）、ユーザー名がホストとして出た
 * - キーが1つの語として読めない形（「_-」・引用符を含む。もう一度かけたときに変わらないように）
 * クエリは一覧にある名前だけ（ほかの名前は *。値は出さない。突き合わせのキーが残す ?sort=・?type= の値も出さない。値のない ?Sunshine の語と、
 * 「_」で区切ったコマンドでクエリに続いた引数（?x_password=…）を名前として出さない）
 */
const url = (raw: string): string => {
  const rest = raw.replace(/^[A-Za-z][\w+.-]*:\/\//, '');
  const authority = rest.match(/^[^/\\?#]*/)![0];
  if (rest.includes('@') && !authority.includes('@')) return '****';
  const q = raw.search(/[?#]/);
  const t = q < 0 ? raw : raw.slice(0, q);
  const names = q >= 0 && raw[q] === '?' ? raw.slice(q + 1).split('#')[0].split('&').map(x => x.split('=')[0]).filter(Boolean) : [];
  const query = [...new Set(names.map(n => (QUERY_NAMES.has(n.toLowerCase()) ? n : '*')))].sort().join('&');
  // パスの部分のうち、一部でも * になったもの（トークンを含む部分）は、全体を * にする（「_」で区切った URL のあとの値がパスの続きとして読まれたときに、
  // 値の英字のかけら（0-AAaa____*-A_aa の AAaa）を出さないように）
  const k = urlKey(t).replace(/^((?:[a-z][\w+.-]*:)?\/\/[^/?#]*)?([^?#]*)/i, (_, origin: string | undefined, path: string) =>
    `${origin ?? ''}${path.split('/').map(seg => (seg.includes('*') ? '*' : seg)).join('/')}`);
  const host = k.match(/^[a-z][\w+.-]*:\/\/([^/?#]*)/i)?.[1] ?? '';
  const hostname = host.replace(/:\d+$/, '');
  if (!(hostname.includes('.') || hostname === 'localhost' || hostname.startsWith('['))) return '****';
  if (k === '*' || /_-|_(?:https?|wss?|ftp):|["'\s]/.test(k)) return '****';
  return query ? `${k}?${query}` : k;
};
/**
 * -H の値（引用符の中のものを含む）：ヘッダの名前が一覧にあるか、決まった接頭辞（X-・Sec-・Accept-・Content-・If-・CF- など）で始まるものだけ名前を残し、
 * それ以外は ****。形だけで判断すると、値のかけら「_-H」のあとのユーザー名（-H alice:x）をヘッダの名前として出した
 */
const HEADER_PREFIX = /^(?:x|sec|accept|content|if|access-control-request|cf|cdn|ocp-apim|proxy)-/i;
const headerName = (n: string) => nameLike(n) && (HTTPIE_HEADERS.has(n.toLowerCase()) || (HEADER_PREFIX.test(n) && n.includes('-') && n.length > 2));
const header = (t: string): string => {
  const inner = unquote(t);
  const m = inner.match(/^([^:\s]+):/);
  return m && headerName(m[1]) ? `${m[1]}:${inner.length > m[0].length ? '****' : ''}` : '****';
};
/** 短いオプションのまとめ書き：決まった文字だけ（値を取らない文字を5文字まで、同じ文字は1回）。値を取る文字の後ろは **** */
const shortOption = (t: string, fam: Family): { text: string; takesValue: boolean } => {
  const [flags, withValue] = SHORT[fam];
  const body = t.slice(1); let k = 0; const seen = new Set<string>();
  if (fam === 'curl' && body.length === 1 && CURL_RARE_FLAGS.includes(body)) return { text: t, takesValue: false };
  const most = fam === 'other' ? 2 : 4;
  while (k < body.length && k < most && flags.includes(body[k]) && !seen.has(body[k])) seen.add(body[k++]);
  if (k < body.length && withValue.includes(body[k])) {
    const name = `-${body.slice(0, k + 1)}`;
    return k + 1 < body.length ? { text: `${name}****`, takesValue: false } : { text: name, takesValue: true };
  }
  if (k === 0 || k < body.length) return { text: '****', takesValue: false };
  return { text: `-${body}`, takesValue: false };
};

/** 1つのコマンド（・・改行で区切ったもの）を要約する */
function summarizeOne(raw: string): string {
  const s = raw.trim();
  if (!s) return '';
  if (ID.test(s)) return s;
  const out: string[] = []; let len = 0;
  let atProgram = true; let fam: Family = 'other'; let prog = ''; let expect: 'value' | 'header' | 'method' | undefined;
  // 続く **** は1つにまとめる（前の語が **** で終わるとき。-u****・Name:**** のあとの値も）
  const push = (x: string, merge = true) => {
    if (merge && x === '****' && out[out.length - 1]?.endsWith('****')) return;
    out.push(x); len += x.length + 1;
  };
  for (const t of tokenize(s)) {
    if (len > MAX) break;
    if (t === '…') { push('…'); continue; }   // 切り詰めの印（もう一度かけても変わらないように残す）
    if (OPERATOR.test(t)) { push(t); atProgram = true; expect = undefined; continue; }
    if (atProgram) {
      // 環境変数の指定（HTTPS_PROXY=… curl）は、一覧にある名前だけ（「_」で区切った curl_<ユーザー名>=… を環境変数の名前として出さない）
      const env = t.match(/^([A-Za-z][A-Za-z0-9_]{0,40})=/);
      // 一覧にない名前は ****=****（**** にすると、もう一度かけたときにプログラムの名前と区別できず、結果が変わった）
      if (env) { push(ENV_NAMES.has(env[1].toUpperCase()) ? `${env[1]}=****` : '****=****', false); continue; }
      if (t === '****=****') { push(t, false); continue; }
      // プログラムの位置の語は、前の **** とまとめない（まとめると、もう一度かけたときに次の語をプログラムと読んで結果が変わった）
      prog = programName(t); const f = FAMILY[prog];
      push(f ? prog : '****', false); fam = f ?? 'other'; atProgram = false;
      continue;
    }
    if (expect) {
      const e = expect; expect = undefined;
      if (/^["']?(?:https?|wss?|ftp):\/\//i.test(t)) { push(url(unquote(t))); continue; }
      if (e === 'header') { push(header(t)); continue; }
      if (e === 'method' && METHODS.test(t) && /^[A-Za-z]+$/.test(t)) { push(t); continue; }
      push('****'); continue;
    }
    if (/^["']?(?:https?|wss?|ftp):\/\//i.test(t)) { push(url(unquote(t))); continue; }
    if (METHODS.test(t) && /^[A-Za-z]+$/.test(t)) { push(t); continue; }
    if (prog === 'openssl' && SUBCOMMANDS.test(t)) { push(t); continue; }
    // 長いオプション（--name、--name=値。PowerShell・openssl は -Name）
    const single = fam === 'ps' || fam === 'openssl';
    const lm = t.match(single ? /^-([A-Za-z][\w.-]{0,40})(=)?/ : /^--([A-Za-z][\w.-]{0,40})(=)?/);
    if (lm) {
      const table = fam === 'curl' ? CURL_LONG : fam === 'wget' ? WGET_LONG : fam === 'httpie' ? HTTPIE_LONG : fam === 'ps' ? PS_LONG : fam === 'openssl' ? OPENSSL_LONG : undefined;
      const key = single ? lm[1].toLowerCase() : lm[1];
      const takes = table?.get(key);
      const dash = single ? '-' : '--';
      if (takes === undefined) { push('****'); continue; }
      if (lm[2]) { push(`${dash}${lm[1]}=****`); continue; }
      if (lm[0] !== t) { push(`${dash}${lm[1]}****`); continue; }
      push(t);
      if (takes) expect = HEADER_OPTIONS.has(`${dash}${key}`) ? 'header' : METHOD_OPTIONS.has(`${dash}${key}`) ? 'method' : 'value';
      continue;
    }
    if (/^-[A-Za-z0-9#]/.test(t) && !single) {
      // 値を続けて書いた -H（-HAuthorization:…）
      if (fam === 'curl' && /^-H[^\s]/.test(t)) { push('-H'); push(header(t.slice(2))); continue; }
      const o = shortOption(t, fam); push(o.text);
      if (o.takesValue) expect = fam === 'curl' && o.text.endsWith('X') ? 'method' : fam === 'curl' && o.text.endsWith('H') ? 'header' : 'value';
      continue;
    }
    // httpie の項目（Name:value はヘッダ、name=value・name:=json は本文、name==value はクエリ）。一覧にある名前だけを残す
    if (fam === 'httpie') {
      const m = t.match(/^([A-Za-z][\w-]{0,40})(:=|==|=|:)/);
      if (m && (m[2] === ':' ? HTTPIE_HEADERS : HTTPIE_PARAMS).has(m[1].toLowerCase())) { push(`${m[1]}${m[2]}****`); continue; }
    }
    push('****');
  }
  // 長いものは語の区切りで切り、「…」を付ける
  let text = '';
  for (const x of out) {
    const next = text ? `${text} ${x}` : x;
    if (next.length > MAX) { text += ' …'; break; }
    text = next;
  }
  if (len > MAX && !text.endsWith('…')) text += ' …';
  return text;
}

/** #META cmd= の値を要約する（・と改行で区切ったコマンドごと。区切りの「・」は残す） */
export const summarizeCommand = (s: string): string =>
  s.split(/・|\r?\n/).map(summarizeOne).filter(Boolean).join('・');

/** #META at= の値：日時の形だけをそのまま出し、それ以外は **** */
const DATE_TIME = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?(?:Z|[+-]\d{2}:?\d{2})?$/;
export const summarizeAt = (s: string): string => (!s ? '' : DATE_TIME.test(s.trim()) ? s.trim() : '****');
