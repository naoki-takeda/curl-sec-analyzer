// mask.ts：画面とエクスポートに出す値のマスキング（常に行う。切り替えはない）
import { lowerToken } from './tokenShape';
// 生のヘッダ行は画面・エクスポートに出さない（Cookie の値は rules/cookies.ts の cookieEvidence でマスクする）ので、ヘッダ行用の関数は持たない。
// 突き合わせのキー（engine/targetKey.ts）と CSV の実施コマンド（export/cmdSummary.ts）は、このファイルを使わずに許可リストで作る
// URLのパラメータ：検出（A-02・C-09②）の一覧は、マスクする名前に必ず含まれる（検出したものは必ずマスクされる）。
// マスクはそれより広く、名前を - _ . で区切った語に token・signature・credential などがあればマスクする（署名付きURLの X-Amz-Security-Token など）
/** トークン・認証情報として扱うパラメータ名（A-02 の検出に使う） */
export const TOKEN_PARAM_NAMES = ['access_token', 'id_token', 'refresh_token', 'token', 'api_key', 'apikey', 'auth', 'session', 'jwt', 'client_secret',
  'accessToken', 'idToken', 'refreshToken', 'clientSecret'];   // 照合は大文字小文字を区別しない（accesstoken も一致する）
/** セッションIDとして扱うパラメータ名（C-09② の検出に使う。;jsessionid= のパス引数も含む） */
export const SESSION_PARAM_NAMES = ['PHPSESSID', 'JSESSIONID', 'sid', 'sessionid', 'session_id'];
/**
 * マスクするパラメータ名：上の2つに、OAuth の認可コード・nonce、パスワード、ワンタイムの番号（passcode・pin）、ハッシュ（パスワードの再設定や
 * ログインの検証に使う）、CAS のチケット、SAML の応答・アサーション、JWT のクライアント認証（client_assertion）などを加えたもの
 */
const MASK_PARAM_NAMES = [...TOKEN_PARAM_NAMES, ...SESSION_PARAM_NAMES, 'code', 'password', 'passwd', 'pass', 'pw', 'secret', 'key', 'signature', 'sig',
  'ticket', 'oauth_verifier', 'SAMLResponse', 'SAMLart', 'SAMLAssertion', 'accesskey', 'nonce', 'passcode', 'pin', 'hash', 'client_assertion',
  'mac',   // mac は名前全体が mac のときだけ（mac_address・isMac は残す）
  // 略したパスワードの名前（pswd・psw、フランス語の mdp）と、暗証番号（pin_number）
  'pswd', 'psw', 'mdp', 'pin_number', 'pinnumber',
  // 個人の番号（米国の社会保障番号、カード番号とセキュリティコード）。値の形でも伏せる（SSN・CARD）
  // cc だけの名前は、mailto の宛先（?cc=team@…）や国のコード（?cc=US）と区別できないので含めない
  'ssn', 'ccnum', 'cc_number', 'cardnumber', 'card_number', 'creditcard', 'credit_card', 'cvv', 'cvv2', 'cvc'];
const alt = (names: string[]) => names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
/** クエリ（?・&）、フラグメント（#）、パス引数（;）のどれに置かれても一致する */
export const paramRegex = (names: string[], flags = 'i') => new RegExp(`([?&#;](?:${alt(names)})=)([^&\\s#;"'<>]+)`, flags);
const MASK_EXACT = new Set(MASK_PARAM_NAMES.map(n => n.toLowerCase()));
/** 区切った語にこれがあればマスクする（x-amz-security-token、x-goog-signature、private_token、x-api-key、access-token など） */
const MASK_WORDS = new Set(['token', 'secret', 'signature', 'sig', 'credential', 'credentials', 'password', 'passwd', 'pwd', 'pass', 'pw', 'key', 'apikey',
  'accesskey', 'auth', 'authorization', 'session', 'sessionid', 'sid', 'jwt', 'code', 'otp', 'ticket', 'verifier', 'samlresponse', 'samlart', 'samlassertion',
  // hdnts・hdnea は Akamai の署名トークン（acl=/* の値は持参人の資格情報）
  'assertion', 'nonce', 'passcode', 'hash', 'csrf', 'xsrf', 'hmac', 'hdnts', 'hdnea', 'bearer', 'authentication',
  // マジックリンク・招待・確認の番号（?magic=abcd-efgh-ijkl-mnop、?verification=482910）。短い番号や区切った番号は許可リストで残るため、名前で伏せる
  'magic', 'invite', 'verification']);
// pin は語にしない（名前全体が pin のときだけ伏せる。地図のピンの pin_lat を伏せない。pin_code は語 code で伏せる）
/**
 * 語 code と組み合わせても秘密ではない語（country_code、zip_code、error_code、currency_code）。名前の語が code とこれらだけなら伏せない。
 * code だけの名前と、auth_code・verification_code・otp_code・device_code のように秘密の語と組み合わせたものは伏せる
 */
const PLAIN_CODE_WORDS = new Set(['country', 'zip', 'postal', 'post', 'promo', 'coupon', 'discount', 'campaign', 'error', 'err', 'status', 'response',
  'result', 'reason', 'exit', 'return', 'http', 'currency', 'lang', 'language', 'locale', 'region', 'area', 'city', 'product', 'item', 'sku', 'color',
  'colour', 'iso', 'tax', 'airport', 'station', 'branch', 'bank', 'store', 'shop', 'dept', 'category', 'class', 'type']);
/**
 * 値によっては伏せない名前（OAuth の state は乱数だが、?state=open・?state=CA のような一覧の絞り込みにも使う）。伏せないのは、8文字未満か、
 * 16文字未満で英字の語（- _ 空白でつないだもの。California・in_progress）の値。長い値は英字だけでも乱数とみなす
 */
const STATE_PARAM = /^(?:oauth[_-]?)?state$/i;
const plainStateValue = (v: string) => v.length < 8 || (v.length < 16 && /^[A-Za-z]+(?:[-_ ][A-Za-z]+)*$/.test(v));
/**
 * マスクするパラメータ名か（検出用の一覧を含み、それより広い）。語の区切りは - _ . と角かっこ（user[password]、%5B・%5D）、キャメルケースの境目
 * （accessToken、clientSecret）。パーセントエンコードした名前（api%5Fkey）はデコードしてから照合する
 */
const isSecretParamName = (name: string): boolean => {
  let n: string;
  try { n = decodeURIComponent(name); } catch { n = name.replace(/%5[bd]/gi, '_'); }   // 不正なエンコードを含む名前は、角かっこだけ区切りにする
  // 全角の英数字（ｐａｓｓｗｏｒｄ）は半角にし、ゼロ幅の文字・ソフトハイフンと、末尾の + と空白（password+= は「password 」と読まれる）は除く
  n = n.normalize('NFKC').replace(/[\u00ad\u200b-\u200f\u2060\ufeff]/g, '').replace(/[+\s]+$/, '');
  // 名前全体の末尾の数字も外して照合する（WordPress のパスワードの再設定の pass1・pass2）
  if (MASK_EXACT.has(n.toLowerCase()) || STRIP_DIGIT_WORDS.has(n.toLowerCase().replace(/\d+$/, ''))) return true;
  // 語の末尾の数字は外す（otp1・pw2_hash の otp・pw を語として見る）
  const words = n.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[-_.[\]]+/).map(w => { const b = w.replace(/(?<=[a-z])\d+$/, ''); return STRIP_DIGIT_WORDS.has(b) ? b : w; }).filter(Boolean);
  // 最後の語が type・method などの名前は、種類や設定を表す公開の値（token_type=Bearer、code_challenge_method=S256、key_size=2048、
  // max_password_length=64）。PKCE の方式のようなセキュリティ上意味のある値を読めるように伏せない
  if (words.length > 1 && PUBLIC_LAST_WORDS.has(words[words.length - 1])) return false;
  // 日本語と主な外国語のパスワード・暗証番号の名前（?パスワード=…、{"暗証番号":"4821"}、?senha=…）
  if (LOCAL_SECRET.test(n) || words.some(w => LOCAL_WORDS.has(w)) || /mot[-_]?de[-_]?passe/i.test(n)) return true;
  if (words.includes('code') && words.every(w => w === 'code' || PLAIN_CODE_WORDS.has(w))) return false;
  // pass で終わる語（newpass1・newpass_confirm・user[newpass]・dbpass.value）。名前全体の末尾ではなく語ごとに見る。bypass・compass などは除く
  if (words.some(w => /pass\d*$/.test(w) && !NOT_PASS_WORD.test(w))) return true;
  // 区切りのない1語の名前（authtoken、apitoken、secretkey、cftoken、sesskey、passphrase など）は、部分一致でも見る（伏せすぎるほうが安全）
  return words.some(w => MASK_WORDS.has(w)) || SECRET_PART.test(n.toLowerCase());
};
/** pass で終わるが秘密ではない語の前の部分（bypass・compass・encompass・overpass・underpass・trespass・surpass・impass） */
const NOT_PASS = 'by|com|encom|over|under|tres|sur|im';
const NOT_PASS_WORD = new RegExp(String.raw`(?:${NOT_PASS})pass\d*$`);
// ラテン文字以外の名前は部分一致（パスワード確認・新しい暗証番号）、ラテン文字の名前は区切った語の完全一致（hasLogin の haslo・
// 「語」の意味の parola を伏せない）
const LOCAL_SECRET = /パスワード|暗証番号|合言葉|ワンタイム|密码|密碼|비밀번호|пароль/i;
const LOCAL_WORDS = new Set(['senha', 'wachtwoord', 'contrasena', 'contraseña', 'passwort', 'kennwort', 'motdepasse', 'hasło', 'haslo', 'lösenord', 'salasana', 'adgangskode']);
/** 末尾の数字を外して照合する語（pass1・pass2・otp1・token2）。key1・code128・mac1・pin2・hash1 は、例や品番などにも使うので外さない */
const STRIP_DIGIT_WORDS = new Set(['password', 'passwd', 'pass', 'pw', 'pwd', 'otp', 'token', 'secret', 'passcode']);
const PUBLIC_LAST_WORDS = new Set(['type', 'method', 'methods', 'size', 'length', 'len', 'policy', 'timeout', 'ttl', 'alg', 'algorithm']);
// 区切りのない1語の名前の部分一致。pw で終わる名前（userpw・loginpw）、nonce（WordPress の CSRF トークン _wpnonce）、ワンタイムコードの名前
// （authcode・otpcode・smscode・vcode・totp。zipcode・errorcode は含めない）、pass で終わる名前（userpass・newpass・dbpass。bypass・compass・
// overpass・trespass などは含めない）と pword・pswrd・pswd も含める
const SECRET_PART = new RegExp(String.raw`token|secret|passw|passphrase|pwd|(?<!${NOT_PASS})pass$|pword|pswr?d|apikey|authkey|accesskey|privatekey|sessid|sesskey|credential|signature|nonce|[a-z]pw$|(?:auth|otp|sms|mfa|pin|login|reset|verif\w*|activation|confirm|email|v)code$|^totp$|^otp`);
/** 値を伏せるパラメータか（名前のほかに、state は値も見る） */
const secretParam = (name: string, value: string) => isSecretParamName(name) || (STATE_PARAM.test(name) && !plainStateValue(value));
// パラメータの区切り：? & # ; と、そのエンコード（%3F・%26・%23・%3B と二重エンコードの %253F など、JS のエスケープ（\u0026 の6文字、\x26）、
// HTML の文字参照（&amp;・&#38;・&#x3D; など））。別のパラメータの値に入れたエンコードした URL（?next=%2Fcb%3Ftoken%3D…）やスクリプトの中の URL でも見つけるため
const SEP = String.raw`[?&#;]|%(?:25)*(?:3[Ff]|26|23|3[Bb])|\\u0026|\\x26|&amp;|&#0*(?:63|38);|&#[xX]0*(?:3[Ff]|26);|&quest;`;
const EQ = String.raw`=|%(?:25)*3[Dd]|\\u003[Dd]|\\x3[Dd]|&#0*61;|&#[xX]0*3[Dd];|&equals;`;
// ANY_PARAM：区切り・名前・=・値
// - 名前は最短一致（エンコードした = を名前に含めない）で300文字まで（Rails の入れ子のフォームをエンコードした名前は100文字を超える）。
//   +（password+= はフォームの読み方で「password 」という名前になる）、全角の英数字・記号（ｐａｓｓｗｏｒｄ）、ゼロ幅の文字・ソフトハイフンを
//   含んでよい（isSecretParamName が正規化してから照合する）
// - 値の前の引用符（?token='…'）は = の側に含める
// - 値はエンコードした区切りの前まで。長さの上限は付けない（6KB の JWT なども最後まで伏せる。繰り返しは入れ子でないので線形時間）。
//   JSON の「\/」（PHP の json_encode は / をこう書く）を越えて続ける
// - 伏せた値の印「…(N chars)」は空白を含むが、値の一部として読む（後ろに続く別の値の印の途中を値の終わりとして、伏せ済みとみなさないため。
//   #META cmd= の ?access_token=<トークン>_-L_-F_token=vi…(17 chars)）
// - 伏せ済みの値（先頭の4文字までと印。nonce- を先に伏せたものを含む）は、印の終わりで値を終える（後ろの引数まで値に入れない）
// SEMI_CONT：値の中の生の ; の続き（?password=Summer;2024）。; のあとが名前=（空白を含む接続文字列の Max Pool Size= も）・Cookie の属性
// （Secure・HttpOnly・Partitioned）・/ を含むパス・空白・引用符・区切り・終わり・CSP のディレクティブ（helmet は ;script-src のように
// 空白を入れない）なら、値はそこまで（後ろの属性・設定・ディレクティブの名前まで伏せない）。; の並び（?password=a;;b）はまとめて読み、
// 並びの後ろで同じ条件を見る（並びの途中は後ろが ; なので続きにならず、分け方が1通りに決まるので線形時間）
// CSP のディレクティブの名前は一覧で照合する（ハイフンでつないだ語の全般にすると、値の中の ;correct-horse-battery で切る）
const CSP_DIRECTIVE = String.raw`(?:(?:child|connect|default|font|frame|img|manifest|media|object|prefetch|script|style|worker)-src(?:-elem|-attr)?|base-uri|form-action|frame-ancestors|navigate-to|report-uri|report-to|sandbox|upgrade-insecure-requests|block-all-mixed-content|require-trusted-types-for|trusted-types|plugin-types|fenced-frame-src)`;
const SEMI_CONT = String.raw`;+(?![\s;"'<>&#\\]|$|(?:[Ss]ecure|SECURE|[Hh]ttp[Oo]nly|HTTPONLY|[Pp]artitioned)(?![\w-])|[\w.%+[\] -]{1,300}(?:=|%(?:25)*3[Dd])|[^;\s/]{0,300}\/|${CSP_DIRECTIVE}(?=[\s;]|$))`;
const anyParam = (stop: string, ch: string) => new RegExp(String.raw`(${SEP})([\w.%+[\]\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,300}?)((?:${EQ})['"]?)((?:nonce-)?[^…\s&#;"'<>\\=]{0,4}…\(\d+ chars\)|(?:…\(\d+ chars\)|(?!%(?:25)*(?:${stop})|\\u0026|\\x26)[^&\s#;"'<>\\${ch}]|${SEMI_CONT}|\\\/)+)`, 'g');
const ANY_PARAM = anyParam('26|23', '');
// 深さの上限（maskParams）を超えた値の中を1回で見る版：値を生の ? とエンコードした ? ;（%3F・%3B）でも終える（入れ子のパラメータを1つずつ見つける）
const FLAT_PARAM = anyParam('26|23|3[FfBb]', '?');
// JWT：直前が英数字・ハイフンでないところか、パーセントエンコードした文字（%3D・%20 など）の直後から（\b は「-eyJ」の繰り返しで2乗の時間になる）。
// 「Bearer_eyJ…」「access_token_eyJ…」のように語と _ でつないだものも含める（直前の語は _ を含めて40文字までで、その前が語の外のときだけ。
// 「_eyJ」の繰り返しで2乗の時間にしない）。JWE（5つの部分。鍵の部分が空の dir 形式「eyJ….. iv.暗号文.タグ」を含む）は5つ目まで、JWS は3つ目まで伏せる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-])|(?<=(?:^|[^\w-])[A-Za-z0-9_]{1,40}_))eyJ[\w-]+\.[\w-]*\.[\w-]*(?:\.[\w-]*\.[\w-]*)?/g;
// URL のユーザー情報（スキーム://ユーザー情報@ホスト）と、スキームのない「//ユーザー情報@ホスト」（<script src="//user:pass@cdn…">）
// - スキームは英字の直後でないところから32文字まで（数字・-・. の直後の %22https://…・corp-egress-…-https://… も含める。\b や \w+ は使わない。
//   \w+ は長い英数字の並びで2乗の時間になる）。JSON でエスケープした「\/\/」（postgres:\/\/alice:pw@db）も含める
// - ユーザー情報はホストの前の最後の @ まで（パスワードの @ も残さない）。パス・クエリ・フラグメントの @ には一致させない
// - 引用符（' "。new URL も curl も受け付ける）は、後ろに語の文字か @ が続くときだけ入れる（https://alice:Summer'2024@host/ は伏せ、
//   JSON の {"site":"https://a.example","id":"x@<トークン>"} の「","」や属性の「' title=」の後ろはユーザー情報とみなさない）
// - \ は、エスケープした「\/」（パスの始まり）の前でだけ止める（smb://CORP\alice:pw@ を伏せる）
const URL_CRED = /((?<![A-Za-z])[A-Za-z][\w+.-]{0,31}:(?:\/\/|\\\/\\\/)|(?<![\w:/])\/\/)((?:[^/\\\s?#<>"']|\\(?!\/)|["'](?=[\w@-])){1,512})@/g;
/**
 * 特別なスキーム（http・https・ws・wss・ftp）で、// の数が標準でないもの（https:///u:pw@h、https:\\u:pw@h、http:/u:pw@h、https:u:pw@h）。
 * WHATWG の URL はどれもユーザー情報として読む。// のものは URL_CRED が見る
 */
const URL_CRED_SPECIAL = /((?<![A-Za-z])(?:https?|wss?|ftp):)([\\/]*)((?:[^/\\\s?#<>"']|["'](?=[\w@-])){1,512})@/gi;
/**
 * コロンだけをエンコードしたスキームの URL（パラメータの値の https%3A//alice:<パスワード>@idp…）。ユーザー情報には、エンコードした
 * / ? #（%2F・%3F・%23）を含めない（?next=https%3A//a.example%2Fcb%3Fe=bob@example.com のパスの中のメールアドレスを、ユーザー情報とみなさない）
 */
const URL_CRED_PCT = /(?<=%(?:25)?3[Aa])(\/\/)((?:(?!%(?:25)?(?:2[Ff]|3[Ff]|23))[^/\s?#<>]){1,512})@/g;
/**
 * パラメータの値に入れた、エンコードした URL のユーザー情報（?redirect=https%3A%2F%2Falice%3A<パスワード>%40evil.example）。
 * パスワード（%3A の後ろ、%40 の前）を伏せる。伏せ済みの「****」は伏せ直さない。スキームのない「%2F%2Fユーザー%3Aパスワード%40」、多重のエンコード
 * （%253A%252F%252F…%2540）、スキームの前のエンコードした文字（%22https%3A…・%3Dhttps%3A…）、:// と %3A の混在（https:%2F%2F…・https%3A//…）、
 * ユーザー名のメールアドレス（bob%40corp%3A…）、パスワードの中のエンコードした / ? # も含める。ポートのあとのパス（host%3A8443%2Fusers%2Fbob%40…。
 * %3A の直後が数字と /）は伏せない
 */
// スキームは語の先頭からだけ試す（どの位置からも試すと、長い語の本文で位置ごとに32文字ずつ読む）。パスワードは、ホストの前の最後の @（深さを問わない
// %40・%2540 と生の @）で終える。生の URL の URL_CRED と同じく、コロンと同じ深さの %2F・%3F・%23 より前の最後のもの（エンコードし損ねた %40 を含む
// …%3AWinter%40Tokyo%40host、生の @ の …%3AWinter2024@host、深さの違う …%253AWinter%2540Tokyo%40host も残さない。正しくエンコードした
// パスワードの中の %2540 は、後ろにホストの前の @ があるので中身として読む）。後ろの @ を探す先読みは次の @ か区切りで止まるので、@ ごとに読む範囲は
// 重ならない。ユーザー名の先読みは256文字まで（上限がないと、%2F%2F%40 の繰り返しで2乗の時間）
const URL_CRED_ENCODED = new RegExp(String.raw`((?:(?:(?<![\w+.-])|(?<=%[0-9A-Fa-f]{2}))[A-Za-z][\w+.-]{0,31}(?::|%(?:25)*3A)|(?<![\w%]))(?:%(?:25)*2F%(?:25)*2F|\/\/))((?:[^\s?#&<>"'/%:@]|%(?:25)*40(?=[^\s?#&<>"'/]{0,256}?%(?:25)*3A)){0,256})(%(?<lv>(?:25)*)3A)(?!\*{4}%)(?!\d{1,5}(?:%(?:25)*2F|\/))(?:[^\s?#&<>"'/%]|%[0-9A-Fa-f]{2}){1,512}?(%(?:25)*40|@)(?!(?:[^\s?#&<>"'/@%]|%(?!\k<lv>(?:2F|3F|23))(?!(?:25)*40)[0-9A-Fa-f]{2}){0,512}(?:%(?:25)*40|@))`, 'gi');
/** エンコードした // のあとの、生の : と @ のユーザー情報（https:%2F%2Falice:<パスワード>@idp…） */
const URL_CRED_MIXED = new RegExp(String.raw`((?:(?<![\w+.-])|(?<=%[0-9A-Fa-f]{2}))[A-Za-z][\w+.-]{0,31}(?::|%(?:25)*3A)%(?:25)*2F%(?:25)*2F)([^\s?#&<>"'/%:@]{0,256}):(?!\*{4}@)(?!\d{1,5}(?:%|\/))[^\s?#&<>"'/@]{1,512}@`, 'gi');
/** パスワードがあればユーザー名を残してパスワードを伏せる。ユーザー名だけ（https://<トークン>@host/ の形）なら、それをトークンとしてマスクする */
const maskUserinfo = (u: string) => { const i = u.indexOf(':'); return i >= 0 ? `${u.slice(0, i)}:****` : maskValue(u); };

export function maskValue(v: string): string {
  const keep = v.length <= 8 ? 0 : v.length <= 20 ? 2 : 4;
  return `${v.slice(0, keep)}…(${v.length} chars)`;
}
/** CSP の nonce の値がマスク済み（maskValue の出力「…(N chars)」で終わる）か。伏せ直さない（冪等にするため） */
const MASKED = /…\(\d+ chars\)$/;
// 伏せ済みのパラメータの値：maskValue の出力そのもの（先頭の4文字までと印）。印で終わるだけでは見ない（印の前にトークンが続くものを残さない）。
// CSP の nonce を先に伏せた値（?code=nonce-Xk…(20 chars)）も伏せ済みとする（伏せ直すと長さが変わり、nonce- も読めなくなる）
const MASKED_PARAM = /^(?:nonce-)?[^…\s=]{0,4}…\(\d+ chars\)$/;

/**
 * パスに置いたトークン（/password/reset/<トークン>、/magic/<トークン>、Webhook の URL など）。
 * 完全な URL だけでなく、/ か %2F（二重エンコードを含む）のあとに続く部分なら、どこでも見る。相対パス（<form action="/reset/…">、
 * 相対の Location）、スキームのない //cdn…、別のパラメータの値（?next=/invite/…、%2Finvite%2F…）、フラグメントのルート（#/reset/…）も含めるため。
 * 部分を . : ~ + で分け（<トークン>.pdf、bot123:<トークン>）、末尾の = （Base64 の詰め物）を除いたかけらがトークンの形（secretPiece）なら、
 * そのかけらを伏せる（maskSegment）。マスク済みの「…(N chars)」は文字種が違うので、もう一度は伏せない
 */
// 「//」「%2F%2F」とコロンをエンコードしたスキーム（https%3A//<ホスト>）の「//」の直後はホスト名なので見ない（長いホスト名や ELB の名前まで
// 伏せると、URL で登録した例外が一致せず、CORS の証跡の Origin も読めない）。パスの途中の「//」「///」（/reset//<トークン>。直前がパスの文字か /）の
// 直後はパスなので見る。? # & のあと（= のないクエリ ?<トークン>、フラグメント #<トークン>）も見る。= を含むもの（?token=…）は ANY_PARAM と
// maskSegment が見る
const PATH_SEGMENT = /(?<=(?<!\/)\/|(?<=[\w.~%+/-]\/)(?<!%(?:25)*3[Aa]\/)\/|(?<!%(?:25)*2[Ff])%(?:25)*2[Ff]|[?#&])(?:[A-Za-z0-9_=.:~+-]|%2[Bb]|%3[Dd]){16,}/g;
/**
 * CSP のハッシュ（'sha256-…'）と SRI（integrity="sha384-…"）。秘密ではないので、Base64 の「/」のあとをパスの部分として伏せず、そのまま残す
 * （PATH_SEGMENT と一緒に探し、こちらに一致した部分は変えない）。ハッシュの長さ（SHA-256 は44文字、SHA-384 は64文字、SHA-512 は88文字）ちょうどで、
 * 後ろに Base64 の文字が続かないものだけ（/sha256-…/reset/<トークン> の後ろのパスまで一致させない）。shownText.ts の KEEP も同じ形を残す
 */
export const HASH_SOURCE = String.raw`(?<![\w-])(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![\w+/=-])`;
const HASH_OR_SEGMENT = new RegExp(`(${HASH_SOURCE})|${PATH_SEGMENT.source}`, 'g');
/** 秘密らしい語。これを含む名前は、語だけでできていても wordName としない */
const SECRET_WORD = /token|secret|session|passw|pwd|auth|cred|apikey|^keys?$/i;
/** 名前のかたまり：3文字までの語（csv・v2 の v）、4文字までの大文字の略語（API・PDF）、4桁までの数字、12文字までで母音（aeiou）が4分の1以上あり、
 *  子音が4つ・母音が3つ続かない語（History・Export） */
const wordChunk = (w: string) => (/^\d+$/.test(w) ? w.length <= 4 : w.length <= 3 || (/^[A-Z]+$/.test(w) ? w.length <= 4
  : w.length <= 12 && (w.match(/[aeiou]/gi) ?? []).length / w.length >= 0.25 && !/[^aeiouy]{4}|[aeiou]{3}/i.test(w)));
/**
 * 英語の語と短い数字をつないだ名前（MyCompanyLogo2026Final.png、/docs/GettingStartedV2Guide）か。トークンとして伏せると、読めないうえに
 * 別のページが同じ表示になる。- _ で区切った部分ごとに、かたまり（語・大文字の略語・数字）に分け、すべてが wordChunk で、かたまりの平均が3.5文字以上、
 * 4文字以上の語が全体で3つ以上あるものだけを名前とする。乱数のトークン（Dk3x9Lq2AbZ7…）はかたまりが短く、母音の少ない長いかたまりを含むので
 * 当たらない（16文字のトークンで、乱数1万個のうち当たるのは数個）
 */
const wordName = (p: string): boolean => {
  let words = 0;
  for (const part of p.split(/[-_]/)) {
    if (!part) continue;
    const ws = part.match(/[A-Z][a-z]+|[a-z]+|[A-Z]+(?![a-z])|\d+/g) ?? [];
    // 短い部分（_csv・_v12・-Q3）は平均を見ない
    if (!ws.length || (part.length > 4 && part.length / ws.length < 3.5) || !ws.every(wordChunk) || ws.some(w => SECRET_WORD.test(w)) || SECRET_WORD.test(part)) return false;
    // キャメルケースで小文字だけの語は先頭の1つだけ（小文字と数字だけのトークン kh8uerlepa7qxrul… を名前としない）
    if (ws.filter(w => /^[a-z]{4,}$/.test(w)).length > 1) return false;
    words += ws.filter(w => w.length >= 4 && /^[A-Za-z]+$/.test(w) && !/^[A-Z]+$/.test(w)).length;
  }
  return words >= 3;
};
// 小文字（または大文字）と数字だけの20文字以上の並び（base36・base32 のトークン。x7k2…・MFRGGZDF…）も、数字と英字が4つ以上ずつあれば伏せる。
// - _ で区切った部分ごとに見る（sk_live_<トークン>）。区切りのある読める名前（2026-annual-report-v2）は部分が短いので残る
const caseToken = (x: string) => x.length >= 20 && (/^[a-z0-9]+$/.test(x) || /^[A-Z0-9]+$/.test(x)) && (x.match(/\d/g) ?? []).length >= 4 && (x.match(/[A-Za-z]/g) ?? []).length >= 4;
/**
 * パスのかけらがトークンの形か（16文字以上の [A-Za-z0-9_-]）：英大文字・小文字・数字をすべて含むものと、数字を含む32文字以上のもの（語と短い数字を
 * つないだ名前（wordName）は除く）、24文字以上の16進数（UUID を含む）、- _ で区切った部分が caseToken・randomLetters・lowerToken（英小文字だけの
 * 16文字以上の乱数 /reset/kqzvwxmplrtbnhjd。tokenShape.ts で突き合わせのキーと共有する）のもの。「2026-annual-report-v2」のような普通の名前は残す
 */
const secretPiece = (p: string): boolean => /^[A-Za-z0-9_-]{16,}$/.test(p) && (
  (((/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p)) || (p.length >= 32 && /\d/.test(p))) && !wordName(p))
  || /^[0-9a-f]{24,}$/i.test(p.replace(/-/g, '')) || p.split(/[-_]/).some(x => caseToken(x) || randomLetters(x) || lowerToken(x)));
/**
 * 数字のない、大文字・小文字が頻繁に入れ替わり（かたまりの数が長さの4割以上）、母音が3割未満の16文字以上の並び（AbCdEfGhIjKlMnOpQrStUv）。
 * 英語の名前（GettingStartedGuide）は入れ替わりが少なく、キャメルケース（getUserByIdAndName）は母音が3〜4割ある（乱数の英字は2割ほど）。
 * 入れ替わりの多さだけで見ると、短い語をつないだ API のパスまで伏せる
 */
const randomLetters = (x: string) => x.length >= 16 && /^[A-Za-z]+$/.test(x) && (x.match(/[a-z]+|[A-Z]+/g) ?? []).length / x.length >= 0.4
  && (x.match(/[aeiou]/gi) ?? []).length / x.length < 0.3;
/** 語として残してよい接頭辞（application・login・AdminDashboard）。トークンの先頭（QwErTyUiOpAsDfGhJk）は残さない */
const wordPrefix = (w: string) => w.length <= 20 && (w.match(/[a-z]+|[A-Z]+/g) ?? []).length / w.length < 0.3;
/** 長さだけを残して伏せる（語を残した残りの部分と、個人の番号）。maskValue は先頭の数文字も残す */
const bare = (v: string) => `…(${v.length} chars)`;
// ビルドしたファイルの名前として伏せないのは、静的ファイルの拡張子が付いた部分だけ（/magic/login-Xy7Kp2Lm9Qa のようなトークンを伏せ忘れない）
const ASSET_EXT = /\.(?:m?js|css|map|woff2?|ttf|otf|svg|png|jpe?g|gif|webp|avif|ico)$/i;
// 公開の値を入れる決まった名前（utm_*・gclid・list・id・title・q など）。名前が一覧にないパラメータとしては値を見ない（キャンペーン名・動画の一覧・
// UUID の ID を伏せない）
const PUBLIC_PARAM = /^(?:utm_\w+|gclid|gbraid|wbraid|fbclid|msclkid|yclid|dclid|mc_cid|mc_eid|_ga|_gl|list|v|vid|video|id|ids|uuid|guid|title|name|slug|q|query|search|keyword|s|ref|ref_src|lang|locale|hl|page|sort|order|category|cat|tag|tags|format|type|mode|view|tab|ver|version)$/i;
/**
 * パスの部分を伏せる（. : ~ + で分けたかけらごと）。英字だけの短い語と - か _ で始まるもの（application-<ダイジェスト>.js）は、その語を残して
 * 残りだけを伏せる（別のファイルを区別できるように。残りは先頭の文字を残さず、もう一度マスクしても変わらないようにする）
 */
const maskSegment = (seg: string): string => { const asset = ASSET_EXT.test(seg); const one = (piece: string): string => {
  // 名前が一覧にないパラメータ（?t=<トークン>・&invite=<トークン>・?RelayState=…）は、「=」で分けたかけらごとに、パスと同じ基準で見る
  // （「=」を含んだままではトークンの形に当たらない）。末尾の「=」（Base64 の詰め物）は値の一部。split で一度に分ける（1つずつ再帰で切り出すと、
  // a=b の繰り返しで2乗の時間と深い再帰になる）
  const core = piece.replace(/=+$/, '');
  if (core.includes('=')) {
    const parts = core.split('='); parts[parts.length - 1] += piece.slice(core.length);
    if (parts.length === 2 && PUBLIC_PARAM.test(parts[0])) return piece;
    return parts.map(p => (p ? one(p) : p)).join('=');
  }
  // Base64 の + と = をエンコードしたもの（%2B・%3D）もトークンの一部として見る（%2B で区切ると、後ろのかけらが伏せられずに残る）
  const body = piece.replace(/(?:=|%3[Dd])+$/, ''); const pad = piece.slice(body.length);
  const plain = body.replace(/%2[Bb]/g, '');
  // 静的ファイルでは、ビルドしたファイルの名前（buildAssetName）と、webpack の [name].[contenthash].js（main.3f8a9c2e1b4d5f6a7b8c.js）の
  // 20文字以下の16進数のハッシュ（語のあとに「.」でつないだもの。JS・CSS とそのソースマップ・フォントだけ）は伏せない。名前全体が16進数のファイル
  // （3F8A….png）と画像（avatar.<ハッシュ>.png）は、アップロードしたファイルのランダムな名前のことがあるので伏せる
  if (!secretPiece(plain) || (asset && (buildAssetName(body) || (/^[0-9a-f]{8,20}$/i.test(body) && /^[A-Za-z][\w-]*\.[0-9a-f]{8,20}\.(?:(?:chunk\.)?(?:m?js|css)(?:\.map)?|woff2?|ttf|otf|eot)$/i.test(seg))))) return piece;
  const m = body.match(/^([A-Za-z]{3,20}[-_])(.+)$/);
  return (m && wordPrefix(m[1].slice(0, -1)) && secretPiece(m[2]) ? m[1] + bare(m[2]) : maskValue(body)) + pad;
}; return seg.replace(/[^.:~+]+/g, one); };
/**
 * ビルドしたファイルの名前（英字の語を - _ でつなぎ、最後に短いハッシュを付けたもの）。Vite の AdminDashboard-Dk3x9Lq2、vendor-react-BxYz12Ab、
 * webpack の main-3f8a9c2e1b4d5f6a7b8c。ハッシュは12文字未満か、20文字以下の16進数。トークンではないので伏せない（伏せると、別のファイルが
 * 同じ表示になる）。語が token・reset・magic・login などのものは除く
 */
const buildAssetName = (p: string): boolean => {
  if (/^(?:token|reset|magic|share|login|invite|verify|confirm|auth|session|secret|key|code|otp|download)[-_]/i.test(p)) return false;
  const m = p.match(/^((?:[A-Za-z]+[-_])+)([A-Za-z0-9]+)$/);
  return !!m && (m[2].length < 12 || (m[2].length <= 20 && /^[0-9a-f]+$/i.test(m[2])));
};
/**
 * ASP.NET の Cookie を使わないセッション（/(S(<セッションID>))/、フォーム認証のチケット /(F(<チケット>))/、匿名ID の A(…)）。
 * パスの部分が「(」で始まるので、PATH_SEGMENT では見つからない
 */
const ASPNET_COOKIELESS = /\/\(((?:[A-Z]\([^()\s/]+\))+)\)/g;

/**
 * CSP の nonce の値（'nonce-…'）。どの証跡でも同じようにマスクする（H-04⑤ と同じ扱い）。値は空白を含まないが、マスク済みの「…(N chars)」は
 * 空白を含むので、その形だけは空白を認める（認めないと、閉じ引用符を次の nonce の開き引用符と読み、2回目のマスクで結果が変わる）
 */
const CSP_NONCE = /'nonce-([^'\s]*…\(\d+ chars\)|[^'\s]+)'/g;
/**
 * 閉じ引用符のない 'nonce-…（長さを問わず伏せる）と、引用符のない nonce-…（script-src nonce-…。ブラウザは nonce として扱わないが、値はサーバの nonce）。
 * 引用符のないものは、値が6文字以上で英大文字か数字を含むときだけ（/posts/nonce-reuse-attacks-explained、class="nonce-container" は普通の語）。
 * マスク済みの「…」の直前で止まった値は伏せない（先読みで値を取り切ってから見るので、短く区切り直して一致させない）
 */
const BARE_NONCE = /(?<![\w-])(')?nonce-(?=([A-Za-z0-9+/_=-]+))\2(?!…)/g;
const bareNonce = (all: string, q: string | undefined, v: string) =>
  q ? `'nonce-${maskValue(v)}` : v.length >= 6 && /[A-Z0-9]/.test(v) ? `nonce-${maskValue(v)}` : all;
/**
 * JSON の組（"password":"…"）。そのまま、エスケープ（\"…\"、JS の文字列やログの中）、パーセントエンコード（%22…%22%3A%22…%22。二重エンコード
 * と、コロンをエンコードしていないものを含む）の3つと、数値の値（"pin":123456）。名前がパラメータと同じ基準（secretParam）で秘密なら値を伏せる。
 * 値は閉じの引用符まで（長さの上限は付けない。繰り返しは入れ子でないので線形）。グループは「値の前・名前・値・値の後」
 */
const Q = '%(?:25)*22', SP = '(?:%(?:25)*20|\\+)*';
// キーは全角の英数字・ゼロ幅の文字を含んでよい（{"ｐａｓｓｗｏｒｄ":"…"}。secretParam が正規化してから照合する。ANY_PARAM と同じ）
const JSON_KEY = String.raw`[\w.$\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,64}`;
/** パーセントエンコードした組の「%22名前%22%3A」（値の前の空白 %20・+ まで） */
const ENC_KEY = String.raw`${Q}([\w.$-]{1,64})${Q}${SP}(?:%(?:25)*3[Aa]|:)${SP}`;
const JSON_PAIRS: RegExp[] = [
  new RegExp(String.raw`("(${JSON_KEY})"\s*:\s*")((?:[^"\\\r\n]|\\.)*)(")`, 'g'),
  new RegExp(String.raw`(\\"(${JSON_KEY})\\"\s*:\s*\\")((?:[^"\\\r\n]|\\[^"\r\n])*)(\\")`, 'g'),
  new RegExp(String.raw`(${ENC_KEY}${Q})((?:(?!${Q})[^&\s"'<>#])*)(${Q})`, 'g'),
];
// 数値の値は、ワンタイムの番号・パスワード・個人の番号らしい名前だけ（"code":404・"status":500 のようなエラーの番号は残す）。
// 3桁から（カードのセキュリティコード "cvv":123）。文字列の組と同じく、そのまま・エスケープ・パーセントエンコードの3つ。グループは「値の前・名前・値」
const JSON_NUMBERS: RegExp[] = [
  new RegExp(String.raw`("(${JSON_KEY})"\s*:\s*)(\d{3,})(?![\d.])`, 'g'),
  new RegExp(String.raw`(\\"(${JSON_KEY})\\"\s*:\s*)(\d{3,})(?![\d.])`, 'g'),
  new RegExp(String.raw`(${ENC_KEY})(\d{3,})(?![\d.])`, 'g'),
];
const NUMERIC_SECRET = /pin|otp|passcode|passw|pwd|secret|token|ssn|cvv|cvc|card|ccnum|暗証番号|パスワード/i;
/**
 * 配列の値（"password":["a","b"]・入れ子の [["a"]]・エスケープした \"password\":[…]・URL エンコードした %22password%22%3A%5B…）の、すべての
 * 文字列の要素を伏せる。中身は 64K 文字まで（入れ子の [ … ] は1つに数える）、入れ子は1段まで
 */
// 中身：括弧の外の文字（整形した JSON の改行を含む）と、1段の入れ子の [ … ]。] で中身を終える（, のあとの別のキーの配列まで読まない）。
// 閉じの ] を待たない（中身が上限を超えた配列でも、上限までの要素を伏せる）
const IN_ARRAY = String.raw`((?:[^[\]]|\[[^[\]]*\]){0,65536})`;
const E_OPEN = String.raw`%(?:25)*5[Bb]|\[`, E_CLOSE = String.raw`%(?:25)*5[Dd]|\]`, E_CH = String.raw`(?:(?!${E_OPEN}|${E_CLOSE})[^&\s"'<>#])`;
// 値がオブジェクト（"password":{"value":"…"}）のときも、中の文字列の値を伏せる。中身は入れ子のない { … } の 64K 文字まで
const IN_OBJECT = String.raw`([^{}]{0,65536})`;
const O_OPEN = String.raw`%(?:25)*7[Bb]|\{`, O_CH = String.raw`(?:(?!${O_OPEN}|%(?:25)*7[Dd]|\})[^&\s"'<>#])`;
// 中身の文字列。あとに : が続くもの（オブジェクトのキー "v":）は伏せずに読み進める（キーの閉じの " から次の " までを文字列として読まない）。
// 空の文字列（""）も要素として読む（"" の閉じと次の要素の開きを組にしない）
const RAW_STR = /(")((?:[^"\\\r\n]|\\.)*)(")(\s*:)?/g, ESC_STR = /(\\")((?:[^"\\\r\n]|\\[^"\r\n])*)(\\")(\s*:)?/g;
const ENC_STR = new RegExp(String.raw`(${Q})((?:(?!${Q})[^&\s"'<>#])*)(${Q})(${SP}(?:%(?:25)*3[Aa]|:))?`, 'g');
/**
 * [キーと開きの括弧, 中身（キーの直後から読む。y フラグ）, 中身の文字列]。キーと中身を別の正規表現で読み、中身は秘密の名前のときだけ読む
 * （1つで読むと、秘密でない親のキー（"user":{）が中身を読み込み、その中の "password":{…}・"password":[…] を見逃す）
 */
const JSON_ARRAYS: [RegExp, RegExp, RegExp][] = [
  [new RegExp(String.raw`"(${JSON_KEY})"\s*:\s*\[`, 'g'), new RegExp(IN_ARRAY, 'y'), RAW_STR],
  [new RegExp(String.raw`\\"(${JSON_KEY})\\"\s*:\s*\[`, 'g'), new RegExp(IN_ARRAY, 'y'), ESC_STR],
  [new RegExp(String.raw`${ENC_KEY}(?:${E_OPEN})`, 'g'), new RegExp(String.raw`((?:${E_CH}|(?:${E_OPEN})${E_CH}*(?:${E_CLOSE})){0,65536})`, 'y'), ENC_STR],
  [new RegExp(String.raw`"(${JSON_KEY})"\s*:\s*\{`, 'g'), new RegExp(IN_OBJECT, 'y'), RAW_STR],
  [new RegExp(String.raw`\\"(${JSON_KEY})\\"\s*:\s*\{`, 'g'), new RegExp(IN_OBJECT, 'y'), ESC_STR],
  [new RegExp(String.raw`${ENC_KEY}(?:${O_OPEN})`, 'g'), new RegExp(String.raw`(${O_CH}{0,65536})`, 'y'), ENC_STR],
];
const maskArrays = (s: string) => JSON_ARRAYS.reduce((acc, [keyRe, bodyRe, str]) => {
  let out = '', last = 0; keyRe.lastIndex = 0;
  for (let m = keyRe.exec(acc); m; m = keyRe.exec(acc)) {
    if (!secretParam(m[1], '')) continue;   // 秘密でない名前は中身を読まずに進む（中の秘密の名前を見つけるため）
    const end = m.index + m[0].length; bodyRe.lastIndex = end;
    const body = bodyRe.exec(acc)?.[1] ?? '';
    out += acc.slice(last, end) + body.replace(str, (a: string, o: string, v: string, c: string, colon?: string) => (colon || !v || /…\(\d+/.test(v) ? a : `${o}${maskValue(v)}${c}`));
    last = end + body.length; keyRe.lastIndex = last;
  }
  return out + acc.slice(last);
}, s);
const maskJsonPairs = (s: string) => {
  const rep = (all: string, pre: string, k: string, v: string, close: string) => (v && secretParam(k, v) && !/…\(\d+/.test(v) ? `${pre}${maskValue(v)}${close}` : all);
  const strings = JSON_PAIRS.reduce((acc, re) => acc.replace(re, rep), maskArrays(s));
  return JSON_NUMBERS.reduce((acc, re) => acc.replace(re, (all, pre: string, k: string, v: string) => (NUMERIC_SECRET.test(k) ? rep(all, pre, k, v, '') : all)), strings);
};

/**
 * URL・JSON の外で名前を付けた秘密（コメントの password=hunter2、JS の password: "hunter2"・{'password': 'x'}、X-Auth-Token: x）。
 * 短い合言葉は形では見分けられない（shownText.ts の許可リストは hunter2 を語として残す）ので、名前で伏せる。名前は、最後の語が
 * password・secret・token・api_key などのものだけ（Access-Control-Allow-Credentials・token_type は対象外）。値は ASCII の文字だけ
 */
// 名前の前置きは64文字まで（SPRING_DATASOURCE_PRIMARY_CONNECTIONPOOL_PASSWORD）。区切りのない pass で終わる名前（dbpass・userpass）も含める。
// ワンタイムの番号・暗証番号（otp: 482913、pin: 4821）も名前で伏せる（短い数字は許可リストで残るため）。pin は名前全体が pin のときだけ
// （パラメータ名と同じ。pin2・map_pin・pin_lat・spinner・pinned は伏せない）
const FREE_NAME = String.raw`(?:(?:[A-Za-z][\w-]{0,62}[_-])?(?:password|passwd|passphrase|pwd|pass|[a-z]{1,16}pass(?<!(?:${NOT_PASS})pass)|secret|api[_-]?key|apikey|token|private[_-]?key|otp|passcode|ssn|cvv2?|cvc|card[_-]?number|ccnum)\d{0,3}|pin)`;
// 名前と値の区切り：= : と、PHP の配列の =>、define('DB_PASSWORD', '…') のカンマ（値が引用符で囲まれているときだけ）
const FREE_SEP = String.raw`\s*(?:=>|[:=]|,(?=\s*["']))\s*`;
// 値が配列（"password":["…"]・password: [Winter2024, Summer2025]）なら、要素を伏せる（括弧の1文字を値として伏せない）
const FREE_ARRAY = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2\s*(?:=>|[:=])\s*\[)${IN_ARRAY}`, 'gi');
// 値がオブジェクト（password: {value: '…'}・password = {"value": "…"}・=> {"value" => "…"}）なら、最初のキーのあとの値を伏せる（キーを値として伏せない）
const FREE_INNER_KEY = String.raw`(?:\{\s*["']?[\w$-]{1,64}["']?\s*(?::|=>)\s*)`;
// 引用符で囲んだ値は、閉じの引用符まで（secret="Tr0ub4dor&3" の & で切らない）
const FREE_QUOTED = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2${FREE_SEP}(?:\[\s*|${FREE_INNER_KEY})?(["']))((?:(?!\3)[^\\\r\n]|\\.)+)(?=\3)`, 'gi');
const FREE_PAIR = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2\s*(?:=>|[:=])\s*(?:${FREE_INNER_KEY}|(?:[[{]\s*){0,2}))(?![[{"']|[\w$-]{1,64}\s*(?::|=>))((?:[^\s"'<>,;&)}\]\\]|${SEMI_CONT})+)`, 'gi');
// XML（<password>…</password>）と .NET の設定（<add key="Password" value="…"/>）
const FREE_XML = new RegExp(String.raw`(<(${FREE_NAME})>)([^<]{1,512})(<\/\2>)`, 'gi');
const FREE_KEY_VALUE = new RegExp(String.raw`(\bkey\s*=\s*(["'])${FREE_NAME}\2\s+value\s*=\s*(["']))([^"']{1,512})(?=\3)`, 'gi');
// 状態を表す語・Cookie の属性（secret: none、XSRF-TOKEN: Secure）は秘密ではないので伏せない（証跡を読めるように）
const FREE_PLAIN = /^(?:true|false|yes|no|none|null|nil|empty|set|unset|required|optional|enabled|disabled|secure|httponly|samesite|lax|strict|present|missing|n\/a|-)$/i;
// パスワードの名前（password: secure）では、Cookie の属性の語（secure・strict・lax など）も値として伏せる（弱いパスワードがその語のことがある）。
// 残すのは真偽値・空の値だけ。名前は語（_ - とキャメルケースの境目で区切る）として見る（compass_token・passport_api_key・bypass_secret は対象外）
const passwordName = (pre: string) => /(?:^|[^a-z])(?:pass(?:word|wd|phrase|code)?|pwd|psw)(?:[^a-z]|$)/i.test(pre.replace(/([a-z\d])([A-Z])/g, '$1_$2'));
const PASSWORD_PLAIN = /^(?:true|false|null|nil|empty|n\/a|-)$/i;
const freeValue = (all: string, pre: string, v: string, post = '') =>
  (v.includes('…') || (passwordName(pre) ? PASSWORD_PLAIN : FREE_PLAIN).test(v) || !/^[\x21-\x7e][\x20-\x7e]*$/.test(v) ? all : `${pre}${maskValue(v)}${post}`);
const maskFreePairs = (s: string) => s
  // 配列の要素：引用符で囲んだもの（オブジェクトのキーは除く）と、引用符のないもの（password: [Winter2024, Summer2025]）
  .replace(FREE_ARRAY, (_all, pre: string, _q: string, body: string) => pre + body.replace(/[^\s,"'[\]{}]*…\(\d+ chars\)|(["'])((?:(?!\1)[^\\\r\n]|\\.)*)\1(\s*:)?|(?<=^|[\s,[])([^\s,"'[\]{}()…]+)(?=\s*[,\]]|\s*$)/g,
    // 伏せ済みの値（…(N chars)。空白を含む）はそのまま（引用符のない要素として「chars)」を伏せ直さない。冪等にするため）
    (a: string, q: string | undefined, v: string | undefined, colon: string | undefined, unquoted: string | undefined) =>
      (q ? (colon ? a : freeValue(a, q, v!, q)) : unquoted ? freeValue(a, '', unquoted) : a)))
  .replace(FREE_XML, (all, open: string, _n: string, v: string, close: string) => freeValue(all, open, v, close))
  .replace(FREE_KEY_VALUE, (all, pre: string, _q1: string, _q2: string, v: string) => freeValue(all, pre, v))
  .replace(FREE_QUOTED, (all, pre: string, _q1: string, _q2: string, v: string) => freeValue(all, pre, v))
  .replace(FREE_PAIR, (all, pre: string, _q: string, v: string) => freeValue(all, pre, v));

/**
 * パラメータの値をマスクする。秘密でない名前の値も、その中に埋め込まれたパラメータ（エンコードした URL）を見る。
 * 入れ子は深さ10まで値ごとに見る。それより深い値は、入れ子に戻らずに FLAT_PARAM で1回だけ走査し、中のすべてのパラメータの名前を見る
 * （?next=/a?r=/b?r=/…?access_token=… のトークンを残さない。線形時間）
 */
function maskParams(s: string, depth = 0): string {
  return s.replace(ANY_PARAM, (all: string, sep: string, k: string, eq: string, v: string) => {
    if (MASKED_PARAM.test(v)) return all;
    if (secretParam(k, v)) return `${sep}${k}${eq}${maskValue(v)}`;
    if (depth < 10) return `${sep}${k}${eq}${maskParams(v, depth + 1)}`;
    return `${sep}${k}${eq}${v.replace(FLAT_PARAM, (a: string, s2: string, k2: string, e2: string, v2: string) =>
      (!MASKED_PARAM.test(v2) && secretParam(k2, v2) ? `${s2}${k2}${e2}${maskValue(v2)}` : a))}`;
  });
}

/**
 * 名前によらず値の形で伏せる個人の番号：米国の社会保障番号（123-45-6789）と、Luhn の検査に通るカード番号（4つずつ空白か - で区切ったもの
 * （4111 1111 1111 1111、0738-9781-0828-3555。. で区切ったものと、American Express の 4-6-5 の区切り 3782 822463 10005 も）と、
 * 区切りのない15・16桁で 3〜6 で始まるもの）。13桁のミリ秒の時刻などは対象外。
 * 前後が英数字・_・- のもの（パスのトークンの途中 ab12…123-45-6789ij…）は対象外（途中を伏せると、残りのかけらが短くなり、パスの部分として伏せられない）。
 * 区切りをパーセントエンコードしたもの（%20・%2D・%2E。encodeURIComponent で組み立てた ?card=4111%201111%201111%201111）と、エンコードした文字・+ の
 * 直後の番号（?q=card%204111…・?q=ssn+123-45-6789。%20 の 0 は語の文字なので、前を見る条件を別に置く）も含める
 */
const SEP_NUM = String.raw`(?:[ .+-]|%2[0DdEe])`;
const SSN = /(?:(?<![\w-])|(?<=%[0-9A-Fa-f]{2}|\+))\d{3}(-|%2[Dd]|\+)\d{2}\1\d{4}(?![\w-])/g;
const CARD = new RegExp(String.raw`(?:(?<![\w.-])|(?<=%[0-9A-Fa-f]{2}|\+))(?:\d{4}(${SEP_NUM})\d{4}\1\d{4}\1\d{1,7}|\d{4}(${SEP_NUM})\d{6}\2\d{5}|[3-6]\d{14,15})(?![\w-]|\.\d)`, 'g');
/** 番号の数字だけ（エンコードした区切りの「20」「2D」を数字に数えない） */
const numDigits = (v: string) => v.replace(/%2[0DdEe]/g, '').replace(/\D/g, '');
const luhn = (d: string) => {
  let sum = 0;
  for (let i = 0; i < d.length; i++) { let x = d.charCodeAt(d.length - 1 - i) - 48; if (i % 2) { x *= 2; if (x > 9) x -= 9; } sum += x; }
  return d.length >= 13 && sum % 10 === 0;
};
/**
 * 同じクエリにユーザー名（u・user・username・login・usr・uid・email など）があるときの p の値（Subsonic などの ?u=admin&p=<パスワード>）。
 * p だけの名前はページ番号（?p=2）にも使うので、ユーザー名と組のときだけ伏せる。伏せ済みの値（Su…(10 chars)）は値の空白で切らずにそのまま残す
 * （「Su…(10」を伏せ直さない。冪等にするため）。HTML の &amp;・エンコードした %26・; の区切りも見る
 */
const USER_PARAM = /(?:[?&;#]|&amp;|%3F|%26)(?:u|user|username|user_name|login|login_id|loginid|usr|uid|userid|user_id|email|mail|account)(?:=|%3D)/i;
const P_PARAM = /((?:[?&;#]|&amp;|%3F|%26)p(?:=|%3D))((?:nonce-)?[^…\s&#;"'<>=]{0,4}…\(\d+ chars\)|(?:(?!%26|&amp;)[^&\s#;"'<>])+)/gi;
const maskUserPass = (s: string) => s.replace(/[?#](?:…\(\d+ chars\)|[^\s"'<>]){0,4096}/g, q => (!USER_PARAM.test(q) ? q
  : q.replace(P_PARAM, (all: string, k: string, v: string) => (MASKED_PARAM.test(v) ? all : `${k}${maskValue(v)}`))));
function mask(s: string): string {
  // 順序：nonce → JSON の組（値の中の JSON を、パラメータの区切りで分ける前に見る） → パラメータ → 名前を付けた値 → u=…&p= → JWT（パスに置いた
  // JWT を、かけらに分けずに丸ごと伏せる） → 個人の番号 → ユーザー情報 → ASP.NET のセッション → パスの部分
  // 値が「…」だけのもの（推奨対応の決まった文言 script-src 'nonce-…'）は伏せ済みとして残す（'nonce-…(1 chars)' にしない）
  const nonce = s.replace(CSP_NONCE, (all, v: string) => (MASKED.test(v) || v === '…' ? all : `'nonce-${maskValue(v)}'`)).replace(BARE_NONCE, (all, q: string | undefined, v: string) => bareNonce(all, q, v));
  return maskUserPass(maskFreePairs(maskParams(maskJsonPairs(nonce))))
          .replace(JWT, t => maskValue(t))
          .replace(SSN, v => bare(v))
          .replace(CARD, v => (luhn(numDigits(v)) ? bare(v) : v))
          .replace(URL_CRED, (_, sc: string, u: string) => `${sc}${maskUserinfo(u)}@`)
          .replace(URL_CRED_SPECIAL, (all: string, sc: string, sl: string, u: string) => (sl === '//' ? all : `${sc}${sl}${maskUserinfo(u)}@`))
          .replace(URL_CRED_PCT, (_, sc: string, u: string) => `${sc}${maskUserinfo(u)}@`)
          .replace(URL_CRED_ENCODED, (_, sc: string, user: string, colon: string, _lv: string, at: string) => `${sc}${user}${colon}****${at}`)
          .replace(URL_CRED_MIXED, (_, sc: string, user: string) => `${sc}${user}:****@`)
          .replace(ASPNET_COOKIELESS, (_, inner: string) => `/(${inner.replace(/([A-Z])\(([^()]+)\)/g, (__, k: string, v: string) => `${k}(${maskValue(v)})`)})`)
          .replace(HASH_OR_SEGMENT, (seg, hash: string | undefined) => (hash ? seg : maskSegment(seg)));
}

/**
 * ヘッダ以外の文字列（URL、証跡）に含まれるトークン類をマスクする。マスク済みの文字列に使っても結果は変わらない（冪等）。
 * 1回の処理では、前の手順で伏せた結果が後の手順の手がかり（直前の文字など）を変えることがあるので、変わらなくなるまで繰り返す
 * （?code=xyz'nonce-… は、code を伏せたあとで初めて nonce が見つかる）。ふつうは2回で止まる
 */
export const maskText = (s: string): string => {
  let out = mask(s);
  for (let i = 0; i < 4; i++) { const next = mask(out); if (next === out) break; out = next; }
  return out;
};

/**
 * 証跡の抜粋：マスクしてから切り詰める。切り詰めてからマスクすると、途中で切れた JWT（ドットが足りない）や
 * パラメータが一致せず、生の値が残るため
 */
export const clip = (s: string, n: number) => clipMasked(maskText(s), n);
/** マスク済みの文字列 m を切り詰める（clip・excerpt で共有し、マスクを2回かけない） */
const clipMasked = (m: string, n: number) => {
  if (m.length <= n) return m;
  // 伏せた値の印（…(N chars)）の途中で切らない（「abcd…(3」では長さが読めない）。印にかかるなら、印の終わりまで含める
  const re = /…\(\d+ chars\)/g; re.lastIndex = Math.max(0, n - 20);
  for (let x = re.exec(m); x && x.index < n; x = re.exec(m)) if (x.index + x[0].length > n) return m.slice(0, x.index + x[0].length);
  return m.slice(0, n);
};
/**
 * 証跡の抜粋（ルールが使う）：clip と同じく切り詰め、語の途中で切ったら、そのかけらを残さない（切れたトークンの先頭（ghp_R8kQ）は、あとで通す
 * 許可リスト（showText）が短い語として残す）
 */
export const excerpt = (s: string, n: number) => {
  const m = maskText(s); const c = clipMasked(m, n);
  return c.length < m.length && /[\w-]/.test(m[c.length]) ? c.replace(/[\w-]+$/, '') : c;
};
