// mask.ts：画面とエクスポートに出す値のマスキング（常に行う。切り替えはない）
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
  'ticket', 'oauth_verifier', 'SAMLResponse', 'SAMLart', 'SAMLAssertion', 'accesskey', 'nonce', 'passcode', 'pin', 'hash', 'client_assertion', 'mac'];   // mac は名前全体が mac のときだけ（mac_address・isMac は残す）
const alt = (names: string[]) => names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
/** クエリ（?・&）、フラグメント（#）、パス引数（;）のどれに置かれても一致する */
export const paramRegex = (names: string[], flags = 'i') => new RegExp(`([?&#;](?:${alt(names)})=)([^&\\s#;"'<>]+)`, flags);
const MASK_EXACT = new Set(MASK_PARAM_NAMES.map(n => n.toLowerCase()));
/** 区切った語にこれがあればマスクする（x-amz-security-token、x-goog-signature、private_token、x-api-key、access-token など） */
const MASK_WORDS = new Set(['token', 'secret', 'signature', 'sig', 'credential', 'credentials', 'password', 'passwd', 'pwd', 'pass', 'pw', 'key', 'apikey',
  'accesskey', 'auth', 'authorization', 'session', 'sessionid', 'sid', 'jwt', 'code', 'otp', 'ticket', 'verifier', 'samlresponse', 'samlart', 'samlassertion',
  'assertion', 'nonce', 'passcode', 'hash', 'csrf', 'xsrf', 'hmac', 'hdnts', 'hdnea', 'bearer', 'authentication']);   // hdnts・hdnea は Akamai の署名トークン（acl=/* の値は持参人の資格情報）   // pin は名前全体が pin のときだけ（pin_lat のような地図のピンを伏せない。pin_code は語 code で伏せる）
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
  // 語の末尾の数字は外して照合する（WordPress のパスワードの再設定の pass1・pass2、pw1・otp1・key1 を伏せなかった）
  if (MASK_EXACT.has(n.toLowerCase()) || STRIP_DIGIT_WORDS.has(n.toLowerCase().replace(/\d+$/, ''))) return true;
  // 語の末尾の数字は外す（otp1・pw2_hash の otp・pw を語として見る）
  const words = n.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[-_.[\]]+/).map(w => { const b = w.replace(/(?<=[a-z])\d+$/, ''); return STRIP_DIGIT_WORDS.has(b) ? b : w; }).filter(Boolean);
  // 最後の語が type・method などの名前は、種類や設定を表す公開の値（client_assertion_type=urn:…、token_type=Bearer、code_challenge_method=S256、
  // token_endpoint_auth_method、key_size=2048、max_password_length=64）。伏せると、PKCE の方式のようなセキュリティ上意味のある値が読めなくなる
  if (words.length > 1 && PUBLIC_LAST_WORDS.has(words[words.length - 1])) return false;
  if (words.includes('code') && words.every(w => w === 'code' || PLAIN_CODE_WORDS.has(w))) return false;
  // 区切りのない1語の名前（authtoken、apitoken、secretkey、cftoken、sesskey、passphrase など）は、部分一致でも見る（伏せすぎるほうが安全）
  return words.some(w => MASK_WORDS.has(w)) || SECRET_PART.test(n.toLowerCase());
};
/** 末尾の数字を外して照合する語（pass1・pass2・otp1・token2）。key1・code128・mac1・pin2・hash1 は、例や品番などにも使うので外さない */
const STRIP_DIGIT_WORDS = new Set(['password', 'passwd', 'pass', 'pw', 'pwd', 'otp', 'token', 'secret', 'passcode']);
const PUBLIC_LAST_WORDS = new Set(['type', 'method', 'methods', 'size', 'length', 'len', 'policy', 'timeout', 'ttl', 'alg', 'algorithm']);
// pw で終わる名前（userpw・loginpw）と nonce（WordPress の CSRF トークン _wpnonce）も含める
const SECRET_PART = /token|secret|passw|passphrase|pwd|apikey|authkey|accesskey|privatekey|sessid|sesskey|credential|signature|nonce|[a-z]pw$/;
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
const ANY_PARAM = new RegExp(String.raw`(${SEP})([\w.%[\]-]{1,100}?)((?:${EQ})['"]?)((?:nonce-)?[^…\s&#;"'<>\\=]{0,4}…\(\d+ chars\)|(?:…\(\d+ chars\)|(?!%(?:25)*(?:26|23)|\\u00(?:26)|\\x26)[^&\s#;"'<>\\]|\\\/)+)`, 'g');
// JWT：直前が英数字・ハイフンでないところから（パーセントエンコードした文字の直後（%3D・%20 など）も含める）。\b だと「-eyJ」の繰り返しで入力の長さの2乗の時間がかかる。
// 「Bearer_eyJ…」「access_token_eyJ…」のように語と _ でつないだものも含める（直前の語は _ を含めて40文字までで、その前が語の外のときだけ。
// 「_eyJ」の繰り返しで2乗の時間にしない）。JWE（5つの部分。鍵の部分が空の dir 形式「eyJ….. iv.暗号文.タグ」を含む）は5つ目まで、JWS は3つ目まで伏せる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-])|(?<=(?:^|[^\w-])[A-Za-z0-9_]{1,40}_))eyJ[\w-]+\.[\w-]*\.[\w-]*(?:\.[\w-]*\.[\w-]*)?/g;
// URL のユーザー情報（スキーム://ユーザー情報@ホスト）。スキームは語の先頭から32文字まで（\w+ だと長い英数字の並びで、入力の長さの2乗の時間がかかる）。
// ユーザー情報はホストの前の最後の @ まで（パスワードに @ を含む場合も残さない）。パス・クエリ・フラグメントの @ には一致させない。
// スキームのない「//ユーザー情報@ホスト」（<script src="//user:pass@cdn…">）も含める
// スキームの前が数字のとき（エンコードした引用符 %22https://…、%3Dhttps://…）も含める（\b だと「2」と「h」の間を語の先頭とみなさず、パスワードを残した）。
// スキームは英字の直後でないところから始める（「-」「.」の直後も含める。除くと、32文字を超える corp-egress-…-https://user:pw@ を見逃した）
const URL_CRED = /((?<![A-Za-z])[A-Za-z][\w+.-]{0,31}:\/\/|(?<![\w:/])\/\/)([^/\s?#<>"']{1,512})@/g;
/**
 * パラメータの値に入れた、エンコードした URL のユーザー情報（?redirect=https%3A%2F%2Falice%3A<パスワード>%40evil.example）。
 * パスワード（%3A の後ろ、%40 の前）を伏せる。伏せ済みの「****」は伏せ直さない
 */
// スキームは語の先頭から（どの位置からも試すと、長い語の本文で位置ごとに32文字ずつ読み、マスク全体の時間が2倍になった）
const URL_CRED_ENCODED = /((?<![\w+.-])[A-Za-z][\w+.-]{0,31}%3A%2F%2F)([^\s?#&<>"'/%]{0,256})%3A(?!\*{4}%40)(?:(?!%2[Ff]|%3[Ff]|%23)[^\s?#&<>"'/]){1,512}?%40/gi;
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
/**
 * 英小文字だけの16文字以上で、母音の少ない（4分の1未満）並び（/reset/kqzvwxmplrtbnhjd）。英語の語をつないだもの（internationalization）は
 * 母音が4割ほどあるので残る。英小文字だけのトークンを、画面にもキーにもそのまま出していた
 */
export const lowerToken = (x: string) => x.length >= 16 && /^[a-z]+$/.test(x) && (x.match(/[aeiouy]/g) ?? []).length / x.length < 0.25;
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
const JSON_PAIRS: RegExp[] = [
  /("([\w.$-]{1,64})"\s*:\s*")((?:[^"\\\r\n]|\\.)*)(")/g,
  /(\\"([\w.$-]{1,64})\\"\s*:\s*\\")((?:[^"\\\r\n]|\\[^"\r\n])*)(\\")/g,
  new RegExp(`(${Q}([\\w.$-]{1,64})${Q}${SP}(?:%(?:25)*3[Aa]|:)${SP}${Q})((?:(?!${Q})[^&\\s"'<>#])*)(${Q})`, 'g'),
];
// 数値の値は、ワンタイムの番号・パスワードらしい名前だけ（"code":404・"status":500 のようなエラーの番号は残す）
const JSON_NUMBER = /("([\w.$-]{1,64})"\s*:\s*)(\d{4,})(?![\d.])()/g;
const NUMERIC_SECRET = /pin|otp|passcode|passw|pwd|secret|token/i;
const maskJsonPairs = (s: string, h: Hider) => {
  const rep = (all: string, pre: string, k: string, v: string, close: string) => (v && secretParam(k, v) && !/…\(\d+/.test(v) ? `${pre}${h.value(v)}${close}` : all);
  return JSON_PAIRS.reduce((acc, re) => acc.replace(re, rep), s)
    .replace(JSON_NUMBER, (all, pre: string, k: string, v: string) => (NUMERIC_SECRET.test(k) ? rep(all, pre, k, v, '') : all));
};

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

function mask(s: string, h: Hider): string {
  // 順序：nonce → JSON の組（値の中の JSON を、パラメータの区切りで分ける前に見る） → パラメータ → JWT（パスに置いた JWT を、かけらに分けずに丸ごと伏せる）
  // → ユーザー情報 → ASP.NET のセッション → パスの部分
  const nonce = s.replace(CSP_NONCE, (all, v: string) => (MASKED.test(v) ? all : `'nonce-${h.value(v)}'`)).replace(BARE_NONCE, (all, q: string | undefined, v: string) => bareNonce(all, q, v, h));
  return maskParams(maskJsonPairs(nonce, h), h)
          .replace(JWT, t => h.value(t))
          .replace(URL_CRED, (_, sc: string, u: string) => `${sc}${maskUserinfo(u, h)}@`)
          .replace(URL_CRED_ENCODED, (_, sc: string, user: string) => `${sc}${user}%3A****%40`)
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

// #PROBE の head は判定にだけ使い、表示・エクスポートにはパターン名だけを出す。
// [パターン名, 判定する項目, 対象パス, 先頭64バイトの目安]（ツール設計1「プローブの判定パターン」）
// パスと中身の両方が一致したときだけ、その項目のルールが使う（1つのプローブを複数の項目で計上しない）
const PROBE_PATTERNS: [string, string, RegExp, RegExp][] = [
  ['git-head',      'E-03', /\/\.git\/HEAD$/,        /^ref: refs\//],
  // 中身のパターンは、エラーページ（JSON・XMLのエラー応答）に一致しないものにする（<?xml だけ、{ だけでは判定しない）
  ['svn-entries',   'E-03', /\/\.svn\/entries$/,     /^\d+\s*$|<wc-entries\b/m],
  // eslint-disable-next-line no-control-regex -- .DS_Store のマジックバイト（00 00 00 01 Bud1）を照合する
  ['ds-store',      'E-03', /\/\.DS_Store$/,         /^\x00\x00\x00\x01Bud1/],
  ['dotenv',        'E-03', /\/\.env$/,              /^[A-Z_][A-Z0-9_]*=/m],
  ['web-xml',       'E-03', /\/WEB-INF\/web\.xml$/,  /<web-app\b|<!DOCTYPE web-app/i],
  ['package-json',  'E-03', /\/package\.json$/,      /^\s*\{\s*"(?:name|version|private|description|scripts|dependencies|devDependencies|type|license|main|workspaces)"\s*:/],
  ['composer-json', 'E-03', /\/composer\.json$/,     /^\s*\{\s*"(?:name|description|type|require|require-dev|license|autoload|minimum-stability|config|repositories)"\s*:/],
  // eslint-disable-next-line no-control-regex -- ZIP のマジックバイト（PK 03 04）を照合する
  ['backup',        'E-03', /\/backup\.zip$/,        /^PK\x03\x04/],
  ['phpinfo',       'E-03', /\/phpinfo\.php$/,       /phpinfo\(\)|PHP Version/],
  ['server-status', 'E-03', /\/server-status$/,      /Apache Server Status|Server Version:/],
  ['security-txt',  'E-04', /\/security\.txt$/,      /^(Contact|Expires):/m],
  ['robots',        'E-04', /\/robots\.txt$/,        /^(User-agent|Disallow|Allow|Sitemap):/im],
  ['source-map',    'E-13', /\.map$/,                /^\s*\{\s*"(?:version|file|sources|sourceRoot|mappings|names|sections)"\s*:/]];
/**
 * プローブのパスと中身が既知のファイルに一致するか。取得できた（HTTP 2xx の）ときだけ一致とする。
 * 404・403 のエラーページの中身（JSON・XML）がパターンに一致しても、そのファイルを取得できたことにはならない
 */
export function probePattern(path: string, headB64: string, code: number): { name: string; item: string } | undefined {
  if (!(code >= 200 && code < 300)) return undefined;
  let head = '';
  try { head = atob(headB64); } catch { return undefined; }
  const hit = PROBE_PATTERNS.find(([, , p, re]) => p.test(path) && re.test(head));
  return hit && { name: hit[0], item: hit[1] };
}
