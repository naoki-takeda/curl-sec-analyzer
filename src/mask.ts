// mask.ts：画面とエクスポートに出す値のマスキング（常に行う。切り替えはない）
import { lowerToken } from './tokenShape';
// 生のヘッダ行は画面・エクスポートに出さない（Cookie の値は rules/cookies.ts の cookieEvidence でマスクする）ので、ヘッダ行用の関数は持たない
// URLのパラメータ：検出（A-02・C-09②）の一覧は、マスクする名前に必ず含まれる（検出したものは必ずマスクされる）。
// マスクはそれより広く、名前を - _ . で区切った語に token・signature・credential などがあればマスクする（署名付きURLの X-Amz-Security-Token など）
/** トークン・認証情報として扱うパラメータ名（A-02 の検出に使う） */
export const TOKEN_PARAM_NAMES = ['access_token', 'id_token', 'refresh_token', 'token', 'api_key', 'apikey', 'auth', 'session', 'jwt', 'client_secret',
  'accessToken', 'idToken', 'refreshToken', 'clientSecret'];   // 照合は大文字小文字を区別しない（accesstoken も一致する）
/** セッションIDとして扱うパラメータ名（C-09② の検出に使う。;jsessionid= のパス引数も含む） */
export const SESSION_PARAM_NAMES = ['PHPSESSID', 'JSESSIONID', 'sid', 'sessionid', 'session_id'];
/** マスクするパラメータ名：上の2つに、OAuthの認可コードやパスワード、CAS のチケット、SAML の応答などを加えたもの */
// OAuth・OpenID Connect の nonce、ワンタイムの番号（passcode・pin）、ハッシュ（パスワードの再設定やログインの検証に使う）、
// JWT のクライアント認証（client_assertion）と SAML のアサーション
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
  'assertion', 'nonce', 'passcode', 'hash', 'csrf', 'xsrf', 'hmac', 'hdnts', 'hdnea', 'bearer', 'authentication',
  // マジックリンク・招待・確認の番号（?magic=abcd-efgh-ijkl-mnop、?verification=482910、?invite=…）。短い番号や区切った番号は許可リストで残るため
  'magic', 'invite', 'verification']);   // hdnts・hdnea は Akamai の署名トークン（acl=/* の値は持参人の資格情報）   // pin は名前全体が pin のときだけ（pin_lat のような地図のピンを伏せない。pin_code は語 code で伏せる）
/**
 * 語 code と組み合わせても秘密ではない語（country_code、zip_code、error_code、currency_code）。名前の語が code とこれらだけなら伏せない。
 * code だけの名前と、auth_code・verification_code・otp_code・device_code のように秘密の語と組み合わせたものは伏せる
 */
const PLAIN_CODE_WORDS = new Set(['country', 'zip', 'postal', 'post', 'promo', 'coupon', 'discount', 'campaign', 'error', 'err', 'status', 'response',
  'result', 'reason', 'exit', 'return', 'http', 'currency', 'lang', 'language', 'locale', 'region', 'area', 'city', 'product', 'item', 'sku', 'color',
  'colour', 'iso', 'tax', 'airport', 'station', 'branch', 'bank', 'store', 'shop', 'dept', 'category', 'class', 'type']);
/** 値が短い状態の語なら伏せない名前（OAuth の state は乱数だが、?state=open・?state=CA のような一覧の絞り込みにも使う） */
// 伏せないのは、8文字未満か、16文字未満で英字の語（- _ 空白でつないだもの）の値（?state=open・?state=California・in_progress）。長い値は英字だけでも乱数とみなす
const STATE_PARAM = /^(?:oauth[_-]?)?state$/i;
const plainStateValue = (v: string) => v.length < 8 || (v.length < 16 && /^[A-Za-z]+(?:[-_ ][A-Za-z]+)*$/.test(v));
/** マスクするパラメータ名か（検出用の一覧を含み、それより広い） */
// 語の区切り：- _ . と角かっこ（user[password]、%5B・%5D）、キャメルケースの境目（accessToken、clientSecret）。
// 名前がパーセントエンコードされていても（api%5Fkey）、デコードしてから照合する
export const isSecretParamName = (name: string): boolean => {
  let n: string;
  try { n = decodeURIComponent(name); } catch { n = name.replace(/%5[bd]/gi, '_'); }   // 不正なエンコードを含む名前は、角かっこだけ区切りにする
  // 全角の英数字（ｐａｓｓｗｏｒｄ）は半角にし、ゼロ幅の文字・ソフトハイフンと、末尾の + と空白（password+= は「password 」と読まれる）は除く
  n = n.normalize('NFKC').replace(/[\u00ad\u200b-\u200f\u2060\ufeff]/g, '').replace(/[+\s]+$/, '');
  // 語の末尾の数字は外して照合する（WordPress のパスワードの再設定の pass1・pass2、pw1・otp1・key1 を伏せなかった）
  if (MASK_EXACT.has(n.toLowerCase()) || STRIP_DIGIT_WORDS.has(n.toLowerCase().replace(/\d+$/, ''))) return true;
  // 語の末尾の数字は外す（otp1・pw2_hash の otp・pw を語として見る）
  const words = n.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[-_.[\]]+/).map(w => { const b = w.replace(/(?<=[a-z])\d+$/, ''); return STRIP_DIGIT_WORDS.has(b) ? b : w; }).filter(Boolean);
  // 最後の語が type・method などの名前は、種類や設定を表す公開の値（client_assertion_type=urn:…、token_type=Bearer、code_challenge_method=S256、
  // token_endpoint_auth_method、key_size=2048、max_password_length=64）。伏せると、PKCE の方式のようなセキュリティ上意味のある値が読めなくなる
  if (words.length > 1 && PUBLIC_LAST_WORDS.has(words[words.length - 1])) return false;
  // 日本語と主な外国語のパスワード・暗証番号の名前（?パスワード=…、{"暗証番号":"4821"}、?senha=…。伏せなかった。第49回）
  if (LOCAL_SECRET.test(n) || words.some(w => LOCAL_WORDS.has(w)) || /mot[-_]?de[-_]?passe/i.test(n)) return true;
  if (words.includes('code') && words.every(w => w === 'code' || PLAIN_CODE_WORDS.has(w))) return false;
  // pass で終わる語（newpass1・newpass_confirm・user[newpass]・dbpass.value）。名前全体の末尾だけを見ると、語のあとに数字・区切りが続く名前を
  // 見逃した（束のレビュー）。bypass・compass などは除く
  if (words.some(w => /pass\d*$/.test(w) && !/(?:by|com|encom|over|under|tres|sur|im)pass\d*$/.test(w))) return true;
  // 区切りのない1語の名前（authtoken、apitoken、secretkey、cftoken、sesskey、passphrase など）は、部分一致でも見る（伏せすぎるほうが安全）
  return words.some(w => MASK_WORDS.has(w)) || SECRET_PART.test(n.toLowerCase());
};
/** 末尾の数字を外して照合する語（pass1・pass2・otp1・token2）。key1・code128・mac1・pin2・hash1 は、例や品番などにも使うので外さない */
// ラテン文字以外の名前は部分一致（パスワード確認・新しい暗証番号）、ラテン文字の名前は区切った語の完全一致（hasLogin の haslo・
// 「語」の意味の parola を伏せない。束のレビュー）
const LOCAL_SECRET = /パスワード|暗証番号|合言葉|ワンタイム|密码|密碼|비밀번호|пароль/i;
const LOCAL_WORDS = new Set(['senha', 'wachtwoord', 'contrasena', 'contraseña', 'passwort', 'kennwort', 'motdepasse', 'hasło', 'haslo', 'lösenord', 'salasana', 'adgangskode']);
const STRIP_DIGIT_WORDS = new Set(['password', 'passwd', 'pass', 'pw', 'pwd', 'otp', 'token', 'secret', 'passcode']);
const PUBLIC_LAST_WORDS = new Set(['type', 'method', 'methods', 'size', 'length', 'len', 'policy', 'timeout', 'ttl', 'alg', 'algorithm']);
// pw で終わる名前（userpw・loginpw）と nonce（WordPress の CSRF トークン _wpnonce）も含める
// 区切りのない1語のワンタイムコードの名前（authcode・otpcode・smscode・mfacode・vcode・totp）も含める（zipcode・errorcode は含めない）
// pass で終わる名前（userpass・newpass・dbpass・confirmpass）と pword・pswrd・pswd も含める（bypass・compass・overpass・trespass などは含めない。
// pass で終わる名前の値をまったく伏せず、GET のログインフォームの HAR でパスワードを出した。第50回）
const SECRET_PART = /token|secret|passw|passphrase|pwd|(?<!by|com|encom|over|under|tres|sur|im)pass$|pword|pswr?d|apikey|authkey|accesskey|privatekey|sessid|sesskey|credential|signature|nonce|[a-z]pw$|(?:auth|otp|sms|mfa|pin|login|reset|verif\w*|activation|confirm|email|v)code$|^totp$|^otp/;
/** 値を伏せるパラメータか（名前のほかに、state は値も見る） */
const secretParam = (name: string, value: string) => isSecretParamName(name) || (STATE_PARAM.test(name) && !plainStateValue(value));
// パラメータの区切り：? & # ; と、そのエンコード（%3F・%26・%23・%3B と二重エンコードの %253F など、JS のエスケープ（\u0026 の6文字、\x26）、HTML の文字参照（&amp;・&#38;・&#x3D; など））。
// エンコードした URL を別のパラメータの値に入れたもの（?next=%2Fcb%3Ftoken%3D…）や、スクリプトの中の URL でも見つけるため
const SEP = String.raw`[?&#;]|%(?:25)*(?:3[Ff]|26|23|3[Bb])|\\u00(?:26)|\\x26|&amp;|&#0*(?:63|38);|&#[xX]0*(?:3[Ff]|26);|&quest;`;
const EQ = String.raw`=|%(?:25)*3[Dd]|\\u003[Dd]|\\x3[Dd]|&#0*61;|&#[xX]0*3[Dd];|&equals;`;
// 値はエンコードした区切りの前まで（長さの上限は付けない。上限で切ると、6KB の JWT などの残りが伏せられずに残る。繰り返しは入れ子でないので時間は線形）。
// 名前は最短一致（エンコードした = を名前に含めない）
// 値の前の引用符（?token='…'）は = の側に含め、値は JSON の「\/」（PHP の json_encode は / をこう書く）を越えて続ける
// （\ で値を切ると、?token=abc\/def の残りが伏せられずに残った）
// 伏せた値の印「…(N chars)」は空白を含むが、値の一部として読む（空白で切ると、値の終わりが後ろに続く別の値の印の途中になり、
// 伏せ済みとみなしてトークンを残した：#META cmd= の ?access_token=<トークン>_-L_-F_token=vi…(17 chars)）
// 伏せ済みの値（先頭の4文字までと印。nonce- を先に伏せたものを含む）は、印の終わりで値を終える（続けて読むと、#META cmd= の
// &token=00…(16 chars)_-o_out.txt_https://… の後ろの引数まで値に入れて伏せた）
// 値は、生の ; のあとが「名前=」・空白・引用符・区切り・終わりでなければ続ける（?password=Summer;2024 の ;2024 を残した。第50回）
// 名前は300文字まで（Rails の入れ子のフォームをエンコードした名前は100文字を超え、値を伏せなかった。第50回）
// 名前は + を含んでよい（password+= は、フォームの読み方で「password 」という名前になる。+ で名前が切れて、値を伏せなかった）
// 名前は全角の英数字・記号（ｐａｓｓｗｏｒｄ）とゼロ幅の文字・ソフトハイフン（pass<U+200B>word）を含んでよい（含めないと、isSecretParamName の
// 正規化を通らず、値を伏せなかった）
// 値の中の生の ; の続き（?password=Summer;2024）。; のあとが名前=（空白を含む接続文字列の Max Pool Size= も）・Cookie の属性（Secure・
// HttpOnly・Partitioned）・空白・引用符・区切り・終わりなら、値はそこまで（後ろの属性・設定まで伏せすぎた。束のレビュー）。
// CSP のディレクティブ（;script-src 'self'。helmet は ; のあとに空白を入れない）の前でも切る（ディレクティブの名前まで伏せ、証跡の 'unsafe-inline' が
// どのディレクティブのものか読めなかった。第51回）
// CSP のディレクティブの名前（一覧で照合する。ハイフンでつないだ語の全般にすると、値の中の ;correct-horse-battery で切った。束のレビュー）
const CSP_DIRECTIVE = String.raw`(?:(?:child|connect|default|font|frame|img|manifest|media|object|prefetch|script|style|worker)-src(?:-elem|-attr)?|base-uri|form-action|frame-ancestors|navigate-to|report-uri|report-to|sandbox|upgrade-insecure-requests|block-all-mixed-content|require-trusted-types-for|trusted-types|plugin-types|fenced-frame-src)`;
const SEMI_CONT = String.raw`;(?![\s;"'<>&#\\]|$|(?:[Ss]ecure|SECURE|[Hh]ttp[Oo]nly|HTTPONLY|[Pp]artitioned)(?![\w-])|[\w.%+[\] -]{1,300}(?:=|%(?:25)*3[Dd])|[^;\s/]{0,300}\/|${CSP_DIRECTIVE}(?=[\s;]|$))`;
const ANY_PARAM = new RegExp(String.raw`(${SEP})([\w.%+[\]\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,300}?)((?:${EQ})['"]?)((?:nonce-)?[^…\s&#;"'<>\\=]{0,4}…\(\d+ chars\)|(?:…\(\d+ chars\)|(?!%(?:25)*(?:26|23)|\\u00(?:26)|\\x26)[^&\s#;"'<>\\]|${SEMI_CONT}|\\\/)+)`, 'g');
// JWT：直前が英数字・ハイフンでないところから（パーセントエンコードした文字の直後（%3D・%20 など）も含める）。\b だと「-eyJ」の繰り返しで入力の長さの2乗の時間がかかる。
// 「Bearer_eyJ…」「access_token_eyJ…」のように語と _ でつないだものも含める（直前の語は _ を含めて40文字までで、その前が語の外のときだけ。
// 「_eyJ」の繰り返しで2乗の時間にしない）。JWE（5つの部分。鍵の部分が空の dir 形式「eyJ….. iv.暗号文.タグ」を含む）は5つ目まで、JWS は3つ目まで伏せる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-])|(?<=(?:^|[^\w-])[A-Za-z0-9_]{1,40}_))eyJ[\w-]+\.[\w-]*\.[\w-]*(?:\.[\w-]*\.[\w-]*)?/g;
// URL のユーザー情報（スキーム://ユーザー情報@ホスト）。スキームは語の先頭から32文字まで（\w+ だと長い英数字の並びで、入力の長さの2乗の時間がかかる）。
// ユーザー情報はホストの前の最後の @ まで（パスワードに @ を含む場合も残さない）。パス・クエリ・フラグメントの @ には一致させない。
// スキームのない「//ユーザー情報@ホスト」（<script src="//user:pass@cdn…">）も含める
// スキームの前が数字のとき（エンコードした引用符 %22https://…、%3Dhttps://…）も含める（\b だと「2」と「h」の間を語の先頭とみなさず、パスワードを残した）。
// スキームは英字の直後でないところから始める（「-」「.」の直後も含める。除くと、32文字を超える corp-egress-…-https://user:pw@ を見逃した）
// ユーザー情報には引用符（' "）も入る（new URL も curl も受け付ける。除くと、https://alice:Summer'2024@host/ のパスワードをまったく伏せなかった）。
// ただし、引用符は後ろに語の文字か @ が続くとき（パスワードの末尾の Summer2024'@ も。第49回）だけ（JSON の {"site":"https://a.example","id":"x@<トークン>"} の「","」や、属性の「' title=」の後ろを
// ユーザー情報とみなすと、@ の後ろのトークンをホスト名として残し、メールアドレスを伏せた。第48回の束1のレビュー）
// JSON でエスケープした「\/\/」（PHP の json_encode の既定。postgres:\/\/alice:pw@db）も含める（特別なスキームしか見ておらず、ほかのスキームの
// パスワードを残した。第51回）
// ユーザー情報の \ は、エスケープした「\/」（パスの始まり）の前でだけ止める（\ を止めると、smb://CORP\alice:pw@・pw に \ を含むものを伏せなかった。
// 束のレビュー）
const URL_CRED = /((?<![A-Za-z])[A-Za-z][\w+.-]{0,31}:(?:\/\/|\\\/\\\/)|(?<![\w:/])\/\/)((?:[^/\\\s?#<>"']|\\(?!\/)|["'](?=[\w@-])){1,512})@/g;
/**
 * 特別なスキーム（http・https・ws・wss・ftp）で、// の数が標準でないもの（https:///u:pw@h、https:\\u:pw@h、http:/u:pw@h、https:u:pw@h）。
 * WHATWG の URL はどれもユーザー情報として読む（HTML の属性・CSP の生の文字列で、パスワードをそのまま出した。第49回）。// のものは URL_CRED が見る
 */
const URL_CRED_SPECIAL = /((?<![A-Za-z])(?:https?|wss?|ftp):)([\\/]*)((?:[^/\\\s?#<>"']|["'](?=[\w@-])){1,512})@/gi;
/**
 * コロンだけをエンコードしたスキームの URL（パラメータの値の https%3A//alice:<パスワード>@idp…。伏せなかった）。ユーザー情報には、エンコードした
 * / ? #（%2F・%3F・%23）を含めない（?next=https%3A//a.example%2Fcb%3Fe=bob@example.com のパスの中のメールアドレスを、ユーザー情報とみなさない）
 */
const URL_CRED_PCT = /(?<=%(?:25)?3[Aa])(\/\/)((?:(?!%(?:25)?(?:2[Ff]|3[Ff]|23))[^/\s?#<>]){1,512})@/g;
/**
 * パラメータの値に入れた、エンコードした URL のユーザー情報（?redirect=https%3A%2F%2Falice%3A<パスワード>%40evil.example）。
 * パスワード（%3A の後ろ、%40 の前）を伏せる。伏せ済みの「****」は伏せ直さない
 */
// スキームは語の先頭から（どの位置からも試すと、長い語の本文で位置ごとに32文字ずつ読み、マスク全体の時間が2倍になった）
// スキームのない「%2F%2Fユーザー%3Aパスワード%40」、多重のエンコード（%253A%252F%252F…%2540）、スキームの前のエンコードした文字（%22https%3A…・
// 入れ子の %3Dhttps%3A…）、:// と %3A の混在（https:%2F%2F…・https%3A//alice%3A…%40）、ユーザー名のメールアドレス（bob%40corp%3A…）、パスワードの中の
// エンコードした / ? # も含める（どれも伏せなかった）。ポートのあとのパス（host%3A8443%2Fusers%2Fbob%40…）は伏せない（%3A の直後が数字と / のもの）。
// パスワードは、コロンと同じ深さのエンコードの %40 で終える（中の URL を正しくエンコードすると、パスワードの @ は %2540 になる。深さを見ずに
// 最初の %40 で終えると、%2540 の後ろのパスワードを残した）。ユーザー名の先読みは256文字まで（上限がないと、%2F%2F%40 の繰り返しで2乗の時間）
const URL_CRED_ENCODED = new RegExp(String.raw`((?:(?:(?<![\w+.-])|(?<=%[0-9A-Fa-f]{2}))[A-Za-z][\w+.-]{0,31}(?::|%(?:25)*3A)|(?<![\w%]))(?:%(?:25)*2F%(?:25)*2F|\/\/))((?:[^\s?#&<>"'/%:@]|%(?:25)*40(?=[^\s?#&<>"'/]{0,256}?%(?:25)*3A)){0,256})(%(?<lv>(?:25)*)3A)(?!\*{4}%)(?!\d{1,5}(?:%(?:25)*2F|\/))(?:[^\s?#&<>"'/@%]|%(?!\k<lv>40)[0-9A-Fa-f]{2}){1,512}?(%\k<lv>40)`, 'gi');
/** エンコードした // のあとの、生の : と @ のユーザー情報（https:%2F%2Falice:<パスワード>@idp…） */
const URL_CRED_MIXED = new RegExp(String.raw`((?:(?<![\w+.-])|(?<=%[0-9A-Fa-f]{2}))[A-Za-z][\w+.-]{0,31}(?::|%(?:25)*3A)%(?:25)*2F%(?:25)*2F)([^\s?#&<>"'/%:@]{0,256}):(?!\*{4}@)(?!\d{1,5}(?:%|\/))[^\s?#&<>"'/@]{1,512}@`, 'gi');
/** パスワードがあればユーザー名を残してパスワードを伏せる。ユーザー名だけ（https://<トークン>@host/ の形）なら、それをトークンとしてマスクする */
const maskUserinfo = (u: string, h: Hider) => { const i = u.indexOf(':'); return i >= 0 ? `${u.slice(0, i)}:****` : h.value(u); };

export function maskValue(v: string): string {
  const keep = v.length <= 8 ? 0 : v.length <= 20 ? 2 : 4;
  return `${v.slice(0, keep)}…(${v.length} chars)`;
}
/**
 * マスク済みの値（maskValue の出力「…(N chars)」で終わる）。もう一度マスクしても変えない（ルールで切り詰める前にマスクし、engine/run.ts でもマスクするため）。
 * 「…」を含むだけで判定すると、URL の直後に続く日本語の文（?token=…詳しくは担当まで）の値を伏せずに残してしまう
 */
const MASKED = /…\(\d+ chars\)$/;
// 伏せ済みのパラメータの値：maskValue の出力そのもの（先頭の4文字までと印）。印で終わるだけでは見ない（印の前にトークンが続くものを残した）
// CSP の nonce を先に伏せた値（?code=nonce-Xk…(20 chars)）も伏せ済みとする（伏せ直すと、長さが伏せた文字列の長さになり、nonce- も読めなくなった）
const MASKED_PARAM = /^(?:nonce-)?[^…\s=]{0,4}…\(\d+ chars\)$/;

/**
 * パスに置いたトークン（/password/reset/<トークン>、/magic/<トークン>、Webhook の URL など）。
 * 完全な URL だけでなく、/ か %2F（二重エンコードを含む）のあとに続く部分なら、どこでも見る。相対パス（<form action="/reset/…">、
 * 相対の Location）、スキームのない //cdn…、別のパラメータの値（?next=/invite/…、%2Finvite%2F…）、フラグメントのルート（#/reset/…）も含めるため。
 * 部分を . と : で分け（<トークン>.pdf、bot123:<トークン>）、末尾の = （Base64 の詰め物）を除いたかけらが、英大文字・小文字・数字をすべて含む
 * 16文字以上、24文字以上の16進数（UUID を含む）、または数字を含む32文字以上の [A-Za-z0-9_-] なら、そのかけらを伏せる。
 * 「2026-annual-report-v2」のような普通の名前は残す。マスク済みの「…(N chars)」は文字種が違うので、もう一度は伏せない
 */
// 「//」「%2F%2F」の直後はホスト名（オーソリティ）なので見ない。見ると、長いホスト名（staging-customer-portal-frontend-01.example.com、
// ELB の名前）まで伏せ、URL で登録した例外が一致しなくなり、CORS の証跡の Origin も読めなくなる。
// ただし、パスの途中の「//」「///」（/reset//<トークン>。直前がパスの文字か /）の直後はパスなので見る（すべての「//」の直後を飛ばすと、トークンが残った）。
// コロンをエンコードしたスキーム（?redirect_uri=https%3A//<ホスト>）の「//」の直後はホスト名なので見ない
// ? # & のあと（= のないクエリ ?<トークン>、フラグメント #<トークン>）も見る。= を含むもの（?token=…）は、かけらが秘密の形にならないので ANY_PARAM に任せる
const PATH_SEGMENT = /(?<=(?<!\/)\/|(?<=[\w.~%+/-]\/)(?<!%(?:25)*3[Aa]\/)\/|(?<!%(?:25)*2[Ff])%(?:25)*2[Ff]|[?#&])(?:[A-Za-z0-9_=.:~+-]|%2[Bb]|%3[Dd]){16,}/g;
/**
 * CSP のハッシュ（'sha256-…'）と SRI（integrity="sha384-…"）。Base64 の「/」のあとをパスの部分と読んで伏せ、証跡が読めなくなった。
 * ハッシュは秘密ではないので、そのまま残す（PATH_SEGMENT と一緒に探し、こちらに一致した部分は変えない）。ハッシュの長さ（SHA-256 は44文字、
 * SHA-384 は64文字、SHA-512 は88文字）ちょうどで、後ろに Base64 の文字が続かないものだけ（長さを決めないと、/sha256-…/reset/<トークン> の
 * ように後ろのパスまで一致して、トークンを伏せずに残した）
 */
const HASH_SOURCE = String.raw`(?<![\w-])(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![\w+/=-])`;
const HASH_OR_SEGMENT = new RegExp(`(${HASH_SOURCE})|${PATH_SEGMENT.source}`, 'g');
/**
 * 英語の語と短い数字をつないだ名前（MyCompanyLogo2026Final.png、/docs/GettingStartedV2Guide）。トークンとして伏せると、読めないうえに
 * 別のページが同じ表示になった。- _ で区切った部分ごとに、かたまり（語・大文字の略語・数字）に分け、すべてが次のどれかで、かたまりの平均が3.5文字以上、
 * 4文字以上の語が3つ以上あるものだけを名前とする：3文字までの語（csv・v2 の v）、4文字までの大文字の略語（API・PDF）、4桁までの数字、
 * 12文字までで母音（aeiou）が4分の1以上あり、子音が4つ・母音が3つ続かない語（History・Export）。乱数のトークン（Dk3x9Lq2AbZ7…）はかたまりが短く、母音の少ない長いかたまりを含むので当たらない
 * （16文字のトークンで、乱数1万個のうち当たるのは数個）。秘密らしい語（token・secret・session・key・pass など）を含む名前は、語だけでできていても伏せる
 */
const SECRET_WORD = /token|secret|session|passw|pwd|auth|cred|apikey|^key$|^keys$/i;
const wordChunk = (w: string) => (/^\d+$/.test(w) ? w.length <= 4 : w.length <= 3 || (/^[A-Z]+$/.test(w) ? w.length <= 4
  : w.length <= 12 && (w.match(/[aeiou]/gi) ?? []).length / w.length >= 0.25 && !/[^aeiouy]{4}|[aeiou]{3}/i.test(w)));
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
// 英大文字・小文字・数字をすべて含むものと、数字を含む32文字以上のものは、語と短い数字をつないだ名前（wordName）なら伏せない
const secretPiece = (p: string): boolean => /^[A-Za-z0-9_-]{16,}$/.test(p) && (
  (((/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p)) || (p.length >= 32 && /\d/.test(p))) && !wordName(p))
  || /^[0-9a-f]{24,}$/i.test(p.replace(/-/g, '')) || p.split(/[-_]/).some(caseToken) || p.split(/[-_]/).some(randomLetters) || p.split(/[-_]/).some(lowerToken));
/**
 * 数字のない、大文字・小文字が頻繁に入れ替わる16文字以上の並び（AbCdEfGhIjKlMnOpQrStUv）。英語の名前（GettingStartedGuide）は入れ替わりが少ない
 * （かたまりの数が長さの半分未満）。数字を求めると、英字だけのトークンを伏せずに残した
 */
// 母音の割合でも見る（英語のキャメルケース（getUserByIdAndName）は母音が3〜4割、乱数の英字は2割ほど）。入れ替わりの多さだけで見ると、
// 短い語をつないだ API のパスまで伏せた
const randomLetters = (x: string) => x.length >= 16 && /^[A-Za-z]+$/.test(x) && (x.match(/[a-z]+|[A-Z]+/g) ?? []).length / x.length >= 0.4
  && (x.match(/[aeiou]/gi) ?? []).length / x.length < 0.3;
// 英小文字だけの16文字以上の乱数のトークン（/reset/kqzvwxmplrtbnhjd）は lowerToken（tokenShape.ts。突き合わせのキーと共有する）
/** 語として残してよい接頭辞（application・login・AdminDashboard）。トークンの先頭（QwErTyUiOpAsDfGhJk）は残さない */
const wordPrefix = (w: string) => w.length <= 20 && (w.match(/[a-z]+|[A-Z]+/g) ?? []).length / w.length < 0.3;
/** 伏せ方：画面・エクスポート用（先頭の数文字と長さを残す）と、突き合わせのキー用（記録し直しても変わらないよう、何も残さない） */
interface Hider { value: (v: string) => string; bare: (v: string) => string }
const SHOW: Hider = { value: v => maskValue(v), bare: v => `…(${v.length} chars)` };
/**
 * かけらを伏せる。英字だけの短い語と - か _ で始まるもの（application-<ダイジェスト>.js、vendor-<ダイジェスト>.js）は、その語を残して
 * 残りだけを伏せる（別のファイルを区別できるように。残りは先頭の文字を残さず、もう一度マスクしても変わらないようにする）
 */
// ビルドしたファイルの名前として伏せないのは、静的ファイルの拡張子が付いた部分だけ（/magic/login-Xy7Kp2Lm9Qa のようなトークンを伏せ忘れない）
const ASSET_EXT = /\.(?:m?js|css|map|woff2?|ttf|otf|svg|png|jpe?g|gif|webp|avif|ico)$/i;
const PUBLIC_PARAM = /^(?:utm_\w+|gclid|gbraid|wbraid|fbclid|msclkid|yclid|dclid|mc_cid|mc_eid|_ga|_gl|list|v|vid|video|id|ids|uuid|guid|title|name|slug|q|query|search|keyword|s|ref|ref_src|lang|locale|hl|page|sort|order|category|cat|tag|tags|format|type|mode|view|tab|ver|version)$/i;
const maskSegment = (seg: string, h: Hider = SHOW): string => { const asset = ASSET_EXT.test(seg); const one = (piece: string): string => {
  // 名前が一覧にないパラメータ（?t=<トークン>・&invite=<トークン>・?RelayState=…）は、「=」の後ろを値として同じ基準で見る
  // （「=」を含んだまま見ると、トークンの形に当たらず、パスに置いた同じトークンは伏せるのに値のトークンを残した）。末尾の「=」（Base64 の詰め物）は値の一部
  // 「=」で分けたかけらごとに見る（再帰で1つずつ切り出すと、a=b の繰り返しで入力の長さの2乗の時間と深い再帰になった）
  const core = piece.replace(/=+$/, '');
  // 公開の値を入れる決まった名前（utm_*・gclid・list・id・title・q など）の値は見ない（キャンペーン名・動画の一覧・UUID の ID まで伏せた）
  if (core.includes('=')) {
    const parts = core.split('='); parts[parts.length - 1] += piece.slice(core.length);
    if (parts.length === 2 && PUBLIC_PARAM.test(parts[0])) return piece;
    return parts.map(p => (p ? one(p) : p)).join('=');
  }
  // Base64 の + と = をエンコードしたもの（%2B・%3D）もトークンの一部として見る（%2B で区切ると、後ろのかけらが伏せられずに残った）
  const body = piece.replace(/(?:=|%3[Dd])+$/, ''); const pad = piece.slice(body.length);
  const plain = body.replace(/%2[Bb]/g, '');
  // webpack の [name].[contenthash].js（main.3f8a9c2e1b4d5f6a7b8c.js）のハッシュ（20文字以下の16進数）も伏せない
  // 16進数のハッシュは、語のあとに「.」でつないだもの（main.<ハッシュ>.js）だけ。名前全体が16進数のファイル（3F8A….png）はアップロードした
  // ファイルのランダムな名前のことがあるので伏せる
  // 画像（avatar.<ハッシュ>.png）は、アップロードしたファイルのランダムな名前のことがあるので、JS・CSS（とそのソースマップ）・フォントだけにする
  if (!secretPiece(plain) || (asset && (buildAssetName(body) || (/^[0-9a-f]{8,20}$/i.test(body) && /^[A-Za-z][\w-]*\.[0-9a-f]{8,20}\.(?:(?:chunk\.)?(?:m?js|css)(?:\.map)?|woff2?|ttf|otf|eot)$/i.test(seg))))) return piece;
  const m = body.match(/^([A-Za-z]{3,20}[-_])(.+)$/);
  if (m && !wordPrefix(m[1].slice(0, -1))) return h.value(body) + pad;
  return m && secretPiece(m[2]) ? m[1] + h.bare(m[2]) + pad : h.value(body) + pad;
}; return seg.replace(/[^.:~+]+/g, one); };
/**
 * ビルドしたファイルの名前（英字の語を - _ でつなぎ、最後に短いハッシュを付けたもの）。Vite の AdminDashboard-Dk3x9Lq2、vendor-react-BxYz12Ab、
 * webpack の main-3f8a9c2e1b4d5f6a7b8c。ハッシュは12文字未満か、20文字以下の16進数。トークンではないので伏せない
 * （伏せると、別のファイルが同じ表示・同じキーになる）
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
const bareNonce = (all: string, q: string | undefined, v: string, h: Hider) =>
  q ? `'nonce-${h.value(v)}` : v.length >= 6 && /[A-Z0-9]/.test(v) ? `nonce-${h.value(v)}` : all;
/**
 * JSON の組（"password":"…"）。そのまま、エスケープ（\"…\"、JS の文字列やログの中）、パーセントエンコード（%22…%22%3A%22…%22。二重エンコード
 * と、コロンをエンコードしていないものを含む）の3つと、数値の値（"pin":123456）。名前がパラメータと同じ基準（secretParam）で秘密なら値を伏せる。
 * 値は閉じの引用符まで（長さの上限は付けない。繰り返しは入れ子でないので線形）。グループは「値の前・名前・値・値の後」
 */
const Q = '%(?:25)*22', SP = '(?:%(?:25)*20|\\+)*';
// キーは全角の英数字・ゼロ幅の文字を含んでよい（{"ｐａｓｓｗｏｒｄ":"…"}。secretParam が正規化してから照合する。ANY_PARAM と同じ）
const JSON_PAIRS: RegExp[] = [
  /("([\w.$\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,64})"\s*:\s*")((?:[^"\\\r\n]|\\.)*)(")/g,
  /(\\"([\w.$\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,64})\\"\s*:\s*\\")((?:[^"\\\r\n]|\\[^"\r\n])*)(\\")/g,
  new RegExp(`(${Q}([\\w.$-]{1,64})${Q}${SP}(?:%(?:25)*3[Aa]|:)${SP}${Q})((?:(?!${Q})[^&\\s"'<>#])*)(${Q})`, 'g'),
];
// 数値の値は、ワンタイムの番号・パスワード・個人の番号らしい名前だけ（"code":404・"status":500 のようなエラーの番号は残す）。
// 3桁から（カードのセキュリティコード "cvv":123）
const JSON_NUMBER = /("([\w.$\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,64})"\s*:\s*)(\d{3,})(?![\d.])()/g;
const NUMERIC_SECRET = /pin|otp|passcode|passw|pwd|secret|token|ssn|cvv|cvc|card|ccnum|暗証番号|パスワード/i;
/**
 * 配列の値（"password":["a","b"]・入れ子の [["a"]]・エスケープした \"password\":[…]・URL エンコードした %22password%22%3A%5B…）の、すべての
 * 文字列の要素を伏せる。中身は 4096 文字まで、入れ子は1段まで
 */
const ARRAY_KEY = String.raw`[\w.$\-\u00ad\u200b-\u200f\u2060\ufeff\uff01-\uff5e\u3040-\u30ff\u4e00-\u9fff\u00c0-\u024f\u0400-\u04ff\uac00-\ud7af]{1,64}`;
// 中身：括弧の外の文字（改行を含む。整形した JSON の2つ目からの要素を伏せなかった）と、1段の入れ子の [ … ]。] で中身を終える（, のあとの別の
// キーの配列まで読まない）。閉じの ] を待たない（中身が上限を超えた配列で、正規表現が丸ごと外れた。束のレビュー）。中身は 64KB まで
const IN_ARRAY = String.raw`((?:[^[\]]|\[[^[\]]*\]){0,65536})`;
const E_OPEN = String.raw`%(?:25)*5[Bb]|\[`, E_CLOSE = String.raw`%(?:25)*5[Dd]|\]`, E_CH = String.raw`(?:(?!${E_OPEN}|${E_CLOSE})[^&\s"'<>#])`;
// 要素の文字列。あとに : が続くもの（配列の中のオブジェクトのキー "v":）は伏せずに読み進める（読み飛ばすだけだと、キーの閉じの " から次の " までを
// 文字列として伏せた。束のレビュー）。空の文字列（""）も要素として読む（1文字以上にすると、"" の閉じと次の要素の開きを組にして、後ろの要素の
// パスワードを残した。第51回）
// 値がオブジェクト（"password":{"value":"…"}）のときも、中の文字列の値を伏せる（中身を伏せなかった。第51回）。中身は入れ子のない { … } の 64KB まで
const IN_OBJECT = String.raw`([^{}]{0,65536})`;
const O_OPEN = String.raw`%(?:25)*7[Bb]|\{`, O_CH = String.raw`(?:(?!${O_OPEN}|%(?:25)*7[Dd]|\})[^&\s"'<>#])`;
const RAW_STR = /(")((?:[^"\\\r\n]|\\.)*)(")(\s*:)?/g, ESC_STR = /(\\")((?:[^"\\\r\n]|\\[^"\r\n])*)(\\")(\s*:)?/g;
const ENC_STR = new RegExp(String.raw`(${Q})((?:(?!${Q})[^&\s"'<>#])*)(${Q})(${SP}(?:%(?:25)*3[Aa]|:))?`, 'g');
/**
 * [キーと開きの括弧, 中身（キーの直後から読む。y フラグ）, 中身の文字列]。キーと中身を1つの正規表現で読むと、秘密でない親のキー（"user":{）が
 * 中身を読み込み、その中の "password":{…}・"password":[…] を伏せなかった（束のレビュー）。中身は、秘密の名前のときだけ読む
 */
const JSON_ARRAYS: [RegExp, RegExp, RegExp][] = [
  [new RegExp(String.raw`"(${ARRAY_KEY})"\s*:\s*\[`, 'g'), new RegExp(IN_ARRAY, 'y'), RAW_STR],
  [new RegExp(String.raw`\\"(${ARRAY_KEY})\\"\s*:\s*\[`, 'g'), new RegExp(IN_ARRAY, 'y'), ESC_STR],
  [new RegExp(String.raw`${Q}([\w.$-]{1,64})${Q}${SP}(?:%(?:25)*3[Aa]|:)${SP}(?:${E_OPEN})`, 'g'), new RegExp(String.raw`((?:${E_CH}|(?:${E_OPEN})${E_CH}*(?:${E_CLOSE})){0,65536})`, 'y'), ENC_STR],
  [new RegExp(String.raw`"(${ARRAY_KEY})"\s*:\s*\{`, 'g'), new RegExp(IN_OBJECT, 'y'), RAW_STR],
  [new RegExp(String.raw`\\"(${ARRAY_KEY})\\"\s*:\s*\{`, 'g'), new RegExp(IN_OBJECT, 'y'), ESC_STR],
  [new RegExp(String.raw`${Q}([\w.$-]{1,64})${Q}${SP}(?:%(?:25)*3[Aa]|:)${SP}(?:${O_OPEN})`, 'g'), new RegExp(String.raw`(${O_CH}{0,65536})`, 'y'), ENC_STR],
];
const maskArrays = (s: string, h: Hider) => JSON_ARRAYS.reduce((acc, [keyRe, bodyRe, str]) => {
  let out = '', last = 0; keyRe.lastIndex = 0;
  for (let m = keyRe.exec(acc); m; m = keyRe.exec(acc)) {
    if (!secretParam(m[1], '')) continue;   // 秘密でない名前は中身を読まずに進む（中の秘密の名前を見つけるため）
    const end = m.index + m[0].length; bodyRe.lastIndex = end;
    const body = bodyRe.exec(acc)?.[1] ?? '';
    out += acc.slice(last, end) + body.replace(str, (a: string, o: string, v: string, c: string, colon?: string) => (colon || !v || /…\(\d+/.test(v) ? a : `${o}${h.value(v)}${c}`));
    last = end + body.length; keyRe.lastIndex = last;
  }
  return out + acc.slice(last);
}, s);
const maskJsonPairs = (s: string, h: Hider) => {
  const rep = (all: string, pre: string, k: string, v: string, close: string) => (v && secretParam(k, v) && !/…\(\d+/.test(v) ? `${pre}${h.value(v)}${close}` : all);
  return JSON_PAIRS.reduce((acc, re) => acc.replace(re, rep), maskArrays(s, h))
    .replace(JSON_NUMBER, (all, pre: string, k: string, v: string) => (NUMERIC_SECRET.test(k) ? rep(all, pre, k, v, '') : all));
};

/**
 * URL・JSON の外で名前を付けた秘密（コメントの password=hunter2、JS の password: "hunter2"・{'password': 'x'}、X-Auth-Token: x）。
 * 短い合言葉は形では見分けられない（shownText.ts の許可リストは hunter2 を語として残す）ので、名前で伏せる。名前は、最後の語が
 * password・secret・token・api_key などのものだけ（Access-Control-Allow-Credentials・token_type は対象外）。値は ASCII の文字だけ
 */
// 名前の前置きは64文字まで（SPRING_DATASOURCE_PRIMARY_CONNECTIONPOOL_PASSWORD）。区切りのない pass で終わる名前（dbpass・userpass）も含める（第50回）
const FREE_NAME = String.raw`(?:[A-Za-z][\w-]{0,62}[_-])?(?:password|passwd|passphrase|pwd|pass|[a-z]{1,16}pass(?<!(?:by|com|encom|over|under|tres|sur|im)pass)|secret|api[_-]?key|apikey|token|private[_-]?key|ssn|cvv2?|cvc|card[_-]?number|ccnum)\d{0,3}`;
// 名前と値の区切り：= : と、PHP の配列の =>、define('DB_PASSWORD', '…') のカンマ（値が引用符で囲まれているときだけ）
const FREE_SEP = String.raw`\s*(?:=>|[:=]|,(?=\s*["']))\s*`;
// 引用符で囲んだ値は、閉じの引用符まで（secret="Tr0ub4dor&3" の & で切って、残りを出した）
// 値が配列（"password":["…"]）なら、最初の要素を伏せる（括弧の1文字を値として伏せ、中身を残した。第50回）
const FREE_ARRAY = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2\s*(?:=>|[:=])\s*\[)${IN_ARRAY}`, 'gi');
// 値がオブジェクト（password: {value: '…'}・password = {"value": "…"}・{'password': {'value': '…'}}・=> {"value" => "…"}）なら、最初のキーのあとの値を
// 伏せる（キーを値として伏せ、値を残した。束のレビュー）
const FREE_INNER_KEY = String.raw`(?:\{\s*["']?[\w$-]{1,64}["']?\s*(?::|=>)\s*)`;
const FREE_QUOTED = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2${FREE_SEP}(?:\[\s*|${FREE_INNER_KEY})?(["']))((?:(?!\3)[^\\\r\n]|\\.)+)(?=\3)`, 'gi');
const FREE_PAIR = new RegExp(String.raw`((?<![\w-])(["']?)${FREE_NAME}\2\s*(?:=>|[:=])\s*(?:${FREE_INNER_KEY}|(?:[[{]\s*){0,2}))(?![[{"']|[\w$-]{1,64}\s*(?::|=>))((?:[^\s"'<>,;&)}\]\\]|${SEMI_CONT})+)`, 'gi');
// XML（<password>…</password>）と .NET の設定（<add key="Password" value="…"/>）
const FREE_XML = new RegExp(String.raw`(<(${FREE_NAME})>)([^<]{1,512})(<\/\2>)`, 'gi');
const FREE_KEY_VALUE = new RegExp(String.raw`(\bkey\s*=\s*(["'])${FREE_NAME}\2\s+value\s*=\s*(["']))([^"']{1,512})(?=\3)`, 'gi');
// 状態を表す語・Cookie の属性（secret: none、XSRF-TOKEN: Secure）は秘密ではないので伏せない（証跡が読めなくなった）
const FREE_PLAIN = /^(?:true|false|yes|no|none|null|nil|empty|set|unset|required|optional|enabled|disabled|secure|httponly|samesite|lax|strict|present|missing|n\/a|-)$/i;
// パスワードの名前（password: secure）では、Cookie の属性の語（secure・strict・lax など）も値として伏せる（弱いパスワードがその語のことがある）。
// 残すのは真偽値・空の値だけ。名前は語（_ - とキャメルケースの境目で区切る）として見る（compass_token・passport_api_key・bypass_secret は対象外）
const PASSWORD_NAME = { test: (pre: string) => /(?:^|[^a-z])(?:pass(?:word|wd|phrase|code)?|pwd|psw)(?:[^a-z]|$)/i.test(pre.replace(/([a-z\d])([A-Z])/g, '$1_$2')) };
const PASSWORD_PLAIN = /^(?:true|false|null|nil|empty|n\/a|-)$/i;
const freeValue = (all: string, pre: string, v: string, h: Hider, post = '') =>
  (v.includes('…') || (PASSWORD_NAME.test(pre) ? PASSWORD_PLAIN : FREE_PLAIN).test(v) || !/^[\x21-\x7e][\x20-\x7e]*$/.test(v) ? all : `${pre}${h.value(v)}${post}`);
const maskFreePairs = (s: string, h: Hider) => s
  // 配列の要素：引用符で囲んだもの（オブジェクトのキーは除く）と、引用符のないもの（password: [Winter2024, Summer2025] の2つ目。束のレビュー）
  .replace(FREE_ARRAY, (_all, pre: string, _q: string, body: string) => pre + body.replace(/[^\s,"'[\]{}]*…\(\d+ chars\)|(["'])((?:(?!\1)[^\\\r\n]|\\.)*)\1(\s*:)?|(?<=^|[\s,[])([^\s,"'[\]{}()…]+)(?=\s*[,\]]|\s*$)/g,
    // 伏せ済みの値（…(N chars)。空白を含む）はそのまま（引用符のない要素として「chars)」を伏せ直し、冪等でなかった）
    (a: string, q: string | undefined, v: string | undefined, colon: string | undefined, bare: string | undefined) =>
      (q ? (colon ? a : freeValue(a, q, v!, h, q)) : bare ? freeValue(a, '', bare, h) : a)))
  .replace(FREE_XML, (all, open: string, _n: string, v: string, close: string) => freeValue(all, open, v, h, close))
  .replace(FREE_KEY_VALUE, (all, pre: string, _q1: string, _q2: string, v: string) => freeValue(all, pre, v, h))
  .replace(FREE_QUOTED, (all, pre: string, _q1: string, _q2: string, v: string) => freeValue(all, pre, v, h))
  .replace(FREE_PAIR, (all, pre: string, _q: string, v: string) => freeValue(all, pre, v, h));

/**
 * パラメータの値をマスクする。秘密でない名前の値も、その中に埋め込まれたパラメータ（エンコードした URL）を見る。
 * 入れ子は深さ10まで見て、それより深い値も、秘密の名前のパラメータは伏せる（入れ子に戻らないだけ）。
 * 深さで打ち切って値をそのまま返すと、?next=/a?r=/b?r=/c?r=/d?access_token=… のトークンが A-02①（高）の証跡に出た
 */
function maskParams(s: string, h: Hider, depth = 0): string {
  return s.replace(ANY_PARAM, (all: string, sep: string, k: string, eq: string, v: string) => {
    if (MASKED_PARAM.test(v)) return all;
    if (secretParam(k, v)) return `${sep}${k}${eq}${h.value(v)}`;
    if (depth < 10) return `${sep}${k}${eq}${maskParams(v, h, depth + 1)}`;
    return `${sep}${k}${eq}${v.replace(ANY_PARAM, (a: string, s2: string, k2: string, e2: string, v2: string) => (secretParam(k2, v2) ? `${s2}${k2}${e2}${h.value(v2)}` : a))}`;
  });
}

/**
 * 名前によらず値の形で伏せる個人の番号：米国の社会保障番号（123-45-6789）と、Luhn の検査に通るカード番号（4つずつ空白か - で区切ったもの
 * （4111 1111 1111 1111、0738-9781-0828-3555。. で区切ったものと、American Express の 4-6-5 の区切り 3782 822463 10005 も）と、
 * 区切りのない15・16桁で 3〜6 で始まるもの）。13桁のミリ秒の時刻などは対象外。
 * 前後が英数字・_・- のもの（パスのトークンの途中 ab12…123-45-6789ij…）は対象外（途中を伏せると、残りのかけらが短くなり、パスの部分として伏せられなくなった）
 */
// 区切りをパーセントエンコードしたもの（%20・%2D・%2E。encodeURIComponent で組み立てた URL の ?card=4111%201111%201111%201111）も含める
// （伏せずに、すべての行の URL に出た）
const SEP_NUM = String.raw`(?:[ .+-]|%2[0DdEe])`;
const SSN = /(?:(?<![\w-])|(?<=%[0-9A-Fa-f]{2}|\+))\d{3}(-|%2[Dd]|\+)\d{2}\1\d{4}(?![\w-])/g;
const CARD = new RegExp(String.raw`(?:(?<![\w.-])|(?<=%[0-9A-Fa-f]{2}|\+))(?:\d{4}(${SEP_NUM})\d{4}\1\d{4}\1\d{1,7}|\d{4}(${SEP_NUM})\d{6}\2\d{5}|[3-6]\d{14,15})(?![\w-]|\.\d)`, 'g');
/** 番号の数字だけ（エンコードした区切りの「20」「2D」を数字に数えない） */
const numDigits = (v: string) => v.replace(/%2[0DdEe]/g, '').replace(/\D/g, '');
// ↑ エンコードした区切り・+ の直後の番号（?q=card%204111%201111…・?q=ssn+123-45-6789）も伏せる（%20 の 0 が語の文字なので、前を見る条件で外れた）
const luhn = (d: string) => {
  let sum = 0;
  for (let i = 0; i < d.length; i++) { let x = d.charCodeAt(d.length - 1 - i) - 48; if (i % 2) { x *= 2; if (x > 9) x -= 9; } sum += x; }
  return d.length >= 13 && sum % 10 === 0;
};
/**
 * 同じクエリにユーザー名（u・user・username・login・usr・uid・email など）があるときの p の値（Subsonic などの ?u=admin&p=<パスワード>）。
 * p だけの名前はページ番号（?p=2）にも使うので、ユーザー名と組のときだけ伏せる。伏せ済みの値（Su…(10 chars)）は値の空白で切らずにそのまま残す
 * （切ると「Su…(10」を伏せ直し、かけるたびに長くなった。第48回の束1のレビュー）。HTML の &amp;・エンコードした %26・; の区切りも見る
 */
const USER_PARAM = /(?:[?&;#]|&amp;|%3F|%26)(?:u|user|username|user_name|login|login_id|loginid|usr|uid|userid|user_id|email|mail|account)(?:=|%3D)/i;
const P_PARAM = /((?:[?&;#]|&amp;|%3F|%26)p(?:=|%3D))((?:nonce-)?[^…\s&#;"'<>=]{0,4}…\(\d+ chars\)|(?:(?!%26|&amp;)[^&\s#;"'<>])+)/gi;
const maskUserPass = (s: string, h: Hider) => s.replace(/[?#](?:…\(\d+ chars\)|[^\s"'<>]){0,4096}/g, q => (!USER_PARAM.test(q) ? q
  : q.replace(P_PARAM, (all: string, k: string, v: string) => (MASKED_PARAM.test(v) ? all : `${k}${h.value(v)}`))));
function mask(s: string, h: Hider): string {
  // 順序：nonce → JSON の組（値の中の JSON を、パラメータの区切りで分ける前に見る） → パラメータ → JWT（パスに置いた JWT を、かけらに分けずに丸ごと伏せる）
  // → ユーザー情報 → ASP.NET のセッション → パスの部分
  // 値が「…」だけのもの（推奨対応の決まった文言 script-src 'nonce-…'）は伏せ済みとして残す（'nonce-…(1 chars)' に化けた）
  const nonce = s.replace(CSP_NONCE, (all, v: string) => (MASKED.test(v) || v === '…' ? all : `'nonce-${h.value(v)}'`)).replace(BARE_NONCE, (all, q: string | undefined, v: string) => bareNonce(all, q, v, h));
  return maskUserPass(maskFreePairs(maskParams(maskJsonPairs(nonce, h), h), h), h)
          .replace(JWT, t => h.value(t))
          .replace(SSN, v => h.bare(v))
          .replace(CARD, v => (luhn(numDigits(v)) ? h.bare(v) : v))
          .replace(URL_CRED, (_, sc: string, u: string) => `${sc}${maskUserinfo(u, h)}@`)
          .replace(URL_CRED_SPECIAL, (all: string, sc: string, sl: string, u: string) => (sl === '//' ? all : `${sc}${sl}${maskUserinfo(u, h)}@`))
          .replace(URL_CRED_PCT, (_, sc: string, u: string) => `${sc}${maskUserinfo(u, h)}@`)
          .replace(URL_CRED_ENCODED, (_, sc: string, user: string, colon: string, _lv: string, at: string) => `${sc}${user}${colon}****${at}`)
          .replace(URL_CRED_MIXED, (_, sc: string, user: string) => `${sc}${user}:****@`)
          .replace(ASPNET_COOKIELESS, (_, inner: string) => `/(${inner.replace(/([A-Z])\(([^()]+)\)/g, (__, k: string, v: string) => `${k}(${h.value(v)})`)})`)
          .replace(HASH_OR_SEGMENT, (seg, hash: string | undefined) => (hash ? seg : maskSegment(seg, h)));
}

/**
 * ヘッダ以外の文字列（URL、証跡）に含まれるトークン類をマスクする。マスク済みの文字列に使っても結果は変わらない（冪等）。
 * 1回の処理では、前の手順で伏せた結果が後の手順の手がかり（直前の文字など）を変えることがあるので、変わらなくなるまで繰り返す
 * （?code=xyz'nonce-… は、code を伏せたあとで初めて nonce が見つかる）。ふつうは2回で止まる
 */
export const maskText = (s: string): string => {
  let out = mask(s, SHOW);
  for (let i = 0; i < 4; i++) { const next = mask(out, SHOW); if (next === out) break; out = next; }
  return out;
};

// 差分・例外の突き合わせのキーは、マスクと切り離して engine/targetKey.ts で作る（このファイルの関数を使わない）

/**
 * 証跡の抜粋：マスクしてから切り詰める。切り詰めてからマスクすると、途中で切れた JWT（ドットが足りない）や
 * パラメータが一致せず、生の値が残るため
 */
export const clip = (s: string, n: number) => {
  const m = maskText(s);
  if (m.length <= n) return m;
  // 伏せた値の印（…(N chars)）の途中で切らない（「abcd…(3」のように長さが読めなくなった）。印にかかるなら、印の終わりまで含める
  const re = /…\(\d+ chars\)/g; re.lastIndex = Math.max(0, n - 20);
  for (let x = re.exec(m); x && x.index < n; x = re.exec(m)) if (x.index + x[0].length > n) return m.slice(0, x.index + x[0].length);
  return m.slice(0, n);
};

// #META cmd= のコマンド（CSV の「実施コマンド」）は、ここで伏せない。残してよい形だけを残す要約（export/cmdSummary.ts）を出す
