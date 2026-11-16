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
  'ticket', 'oauth_verifier', 'SAMLResponse', 'SAMLart', 'SAMLAssertion', 'accesskey', 'nonce', 'passcode', 'pin', 'hash', 'client_assertion'];
const alt = (names: string[]) => names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
/** クエリ（?・&）、フラグメント（#）、パス引数（;）のどれに置かれても一致する */
export const paramRegex = (names: string[], flags = 'i') => new RegExp(`([?&#;](?:${alt(names)})=)([^&\\s#;"'<>]+)`, flags);
const MASK_EXACT = new Set(MASK_PARAM_NAMES.map(n => n.toLowerCase()));
/** 区切った語にこれがあればマスクする（x-amz-security-token、x-goog-signature、private_token、x-api-key、access-token など） */
const MASK_WORDS = new Set(['token', 'secret', 'signature', 'sig', 'credential', 'credentials', 'password', 'passwd', 'pwd', 'pass', 'pw', 'key', 'apikey',
  'accesskey', 'auth', 'authorization', 'session', 'sessionid', 'sid', 'jwt', 'code', 'otp', 'ticket', 'verifier', 'samlresponse', 'samlart', 'samlassertion',
  'assertion', 'nonce', 'passcode', 'hash', 'csrf', 'xsrf']);   // pin は名前全体が pin のときだけ（pin_lat のような地図のピンを伏せない。pin_code は語 code で伏せる）
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
  if (MASK_EXACT.has(n.toLowerCase())) return true;
  const words = n.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[-_.[\]]+/).filter(Boolean);
  // 最後の語が type の名前は、種類を表す公開の値（client_assertion_type=urn:…、token_type=Bearer、grant_type）
  if (words.length > 1 && words[words.length - 1] === 'type') return false;
  if (words.includes('code') && words.every(w => w === 'code' || PLAIN_CODE_WORDS.has(w))) return false;
  // 区切りのない1語の名前（authtoken、apitoken、secretkey、cftoken、sesskey、passphrase など）は、部分一致でも見る（伏せすぎるほうが安全）
  return words.some(w => MASK_WORDS.has(w)) || SECRET_PART.test(n.toLowerCase());
};
const SECRET_PART = /token|secret|passw|passphrase|pwd|apikey|authkey|accesskey|privatekey|sessid|sesskey|credential|signature/;
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
const ANY_PARAM = new RegExp(String.raw`(${SEP})([\w.%[\]-]{1,100}?)((?:${EQ})['"]?)((?:(?!%(?:25)*(?:26|23)|\\u00(?:26)|\\x26)[^&\s#;"'<>\\]|\\\/)+)`, 'g');
// JWT：直前が英数字・ハイフンでないところから（パーセントエンコードした文字の直後（%3D・%20 など）も含める）。\b だと「-eyJ」の繰り返しで入力の長さの2乗の時間がかかる。
// 「Bearer_eyJ…」「access_token_eyJ…」のように語と _ でつないだものも含める（直前の語は _ を含めて40文字までで、その前が語の外のときだけ。
// 「_eyJ」の繰り返しで2乗の時間にしない）。JWE（5つの部分。鍵の部分が空の dir 形式「eyJ….. iv.暗号文.タグ」を含む）は5つ目まで、JWS は3つ目まで伏せる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-])|(?<=(?:^|[^\w-])[A-Za-z0-9_]{1,40}_))eyJ[\w-]+\.[\w-]*\.[\w-]*(?:\.[\w-]*\.[\w-]*)?/g;
// URL のユーザー情報（スキーム://ユーザー情報@ホスト）。スキームは語の先頭から32文字まで（\w+ だと長い英数字の並びで、入力の長さの2乗の時間がかかる）。
// ユーザー情報はホストの前の最後の @ まで（パスワードに @ を含む場合も残さない）。パス・クエリ・フラグメントの @ には一致させない。
// スキームのない「//ユーザー情報@ホスト」（<script src="//user:pass@cdn…">）も含める
const URL_CRED = /(\b[A-Za-z][\w+.-]{0,31}:\/\/|(?<![\w:/])\/\/)([^/\s?#<>"']{1,512})@/g;
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
// パラメータの値は空白の前で切れるので、「…(N」まで取り、直後が「 chars)」かを見る
const maskedParam = (v: string, rest: string) => /…\(\d+$/.test(v) && rest.startsWith(' chars)');

/**
 * パスに置いたトークン（/password/reset/<トークン>、/magic/<トークン>、Webhook の URL など）。
 * 完全な URL だけでなく、/ か %2F（二重エンコードを含む）のあとに続く部分なら、どこでも見る。相対パス（<form action="/reset/…">、
 * 相対の Location）、スキームのない //cdn…、別のパラメータの値（?next=/invite/…、%2Finvite%2F…）、フラグメントのルート（#/reset/…）も含めるため。
 * 部分を . と : で分け（<トークン>.pdf、bot123:<トークン>）、末尾の = （Base64 の詰め物）を除いたかけらが、英大文字・小文字・数字をすべて含む
 * 16文字以上、24文字以上の16進数（UUID を含む）、または数字を含む32文字以上の [A-Za-z0-9_-] なら、そのかけらを伏せる。
 * 「2026-annual-report-v2」のような普通の名前は残す。マスク済みの「…(N chars)」は文字種が違うので、もう一度は伏せない
 */
// 「//」「%2F%2F」の直後はホスト名（オーソリティ）なので見ない。見ると、長いホスト名（staging-customer-portal-frontend-01.example.com、
// ELB の名前）まで伏せ、URL で登録した例外が一致しなくなり、CORS の証跡の Origin も読めなくなる
// ? # & のあと（= のないクエリ ?<トークン>、フラグメント #<トークン>）も見る。= を含むもの（?token=…）は、かけらが秘密の形にならないので ANY_PARAM に任せる
const PATH_SEGMENT = /(?<=(?<!\/)\/|(?<!%(?:25)*2[Ff])%(?:25)*2[Ff]|[?#&])(?:[A-Za-z0-9_=.:~+-]|%2[Bb]|%3[Dd]){16,}/g;
// 小文字（または大文字）と数字だけの20文字以上の並び（base36・base32 のトークン。x7k2…・MFRGGZDF…）も、数字と英字が4つ以上ずつあれば伏せる。
// - _ で区切った部分ごとに見る（sk_live_<トークン>）。区切りのある読める名前（2026-annual-report-v2）は部分が短いので残る
const caseToken = (x: string) => x.length >= 20 && (/^[a-z0-9]+$/.test(x) || /^[A-Z0-9]+$/.test(x)) && (x.match(/\d/g) ?? []).length >= 4 && (x.match(/[A-Za-z]/g) ?? []).length >= 4;
const secretPiece = (p: string): boolean => /^[A-Za-z0-9_-]{16,}$/.test(p) && (
  (/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p)) || /^[0-9a-f]{24,}$/i.test(p.replace(/-/g, '')) || (p.length >= 32 && /\d/.test(p)) || p.split(/[-_]/).some(caseToken));
/** 伏せ方：画面・エクスポート用（先頭の数文字と長さを残す）と、突き合わせのキー用（記録し直しても変わらないよう、何も残さない） */
interface Hider { value: (v: string) => string; bare: (v: string) => string }
const SHOW: Hider = { value: v => maskValue(v), bare: v => `…(${v.length} chars)` };
/**
 * かけらを伏せる。英字だけの短い語と - か _ で始まるもの（application-<ダイジェスト>.js、vendor-<ダイジェスト>.js）は、その語を残して
 * 残りだけを伏せる（別のファイルを区別できるように。残りは先頭の文字を残さず、もう一度マスクしても変わらないようにする）
 */
// ビルドしたファイルの名前として伏せないのは、静的ファイルの拡張子が付いた部分だけ（/magic/login-Xy7Kp2Lm9Qa のようなトークンを伏せ忘れない）
const ASSET_EXT = /\.(?:m?js|css|map|woff2?|ttf|otf|svg|png|jpe?g|gif|webp|avif|ico)$/i;
const maskSegment = (seg: string, h: Hider = SHOW): string => { const asset = ASSET_EXT.test(seg); return seg.replace(/[^.:~+]+/g, piece => {
  // Base64 の + と = をエンコードしたもの（%2B・%3D）もトークンの一部として見る（%2B で区切ると、後ろのかけらが伏せられずに残った）
  const body = piece.replace(/(?:=|%3[Dd])+$/, ''); const pad = piece.slice(body.length);
  const plain = body.replace(/%2[Bb]/g, '');
  if (!secretPiece(plain) || (asset && buildAssetName(body))) return piece;
  const m = body.match(/^([A-Za-z]{3,20}[-_])(.+)$/);
  return m && secretPiece(m[2]) ? m[1] + h.bare(m[2]) + pad : h.value(body) + pad;
}); };
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
  return s.replace(ANY_PARAM, (all: string, sep: string, k: string, eq: string, v: string, offset: number) => {
    if (maskedParam(v, s.slice(offset + all.length, offset + all.length + 7))) return all;
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
          .replace(ASPNET_COOKIELESS, (_, inner: string) => `/(${inner.replace(/([A-Z])\(([^()]+)\)/g, (__, k: string, v: string) => `${k}(${h.value(v)})`)})`)
          .replace(PATH_SEGMENT, seg => maskSegment(seg, h));
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

/**
 * 例外と前回の結果の突き合わせに使う URL（HAR の targetKey）。マスクとは切り離し、URL の形だけで作る：
 * スキーム・ホスト・パス（トークンらしい部分は *、ASP.NET のセッション (S(…)) は (*)）と、クエリのパラメータの名前だけ（値は持たない）。
 * マスクの出力をキーにすると、マスクの一覧を変えるたびに（v0.4.26・v0.4.27）キーが変わり、以前の例外と前回の結果が黙って突き合わなくなった。
 * 値を持たないので秘密は入らず、同じページを記録し直しても変わらない。ユーザー情報とフラグメントは持たない
 */
export function maskKey(raw: string): string {
  let u: URL; let relative = false;
  try { u = new URL(raw); } catch {
    try { u = new URL(raw, 'https://relative.invalid'); relative = true; } catch { return '*'; }
  }
  // デコードするが、%2F（エンコードした /）はそのまま残す（Base64 のトークンの / で分けると、後ろのかけらが残る）
  const dec = (s: string) => { try { return decodeURIComponent(s.replace(/%2F/gi, '%252F')); } catch { return s; } };
  const path = u.pathname.split('/').map(seg => {
    if (/^\((?:[A-Z]\([^()]*\))+\)$/.test(seg)) return '(*)';                 // ASP.NET の Cookie を使わないセッション
    // パス引数（;jsessionid=…）は名前だけを残す。値はセッションIDのことが多い
    const [head, ...params] = seg.split(';');
    return [keySegment(dec(head)), ...params.map(p => keySegment(dec(p.split('=')[0])))].join(';');
  }).join('/');
  // パラメータは名前だけを並べ替えて持つ。値は、ページ送り（数字）と並べ替え・表示の切り替え（英字の語）の決まった名前のときだけ残す
  const params = new Map<string, string>();
  for (const [n, v] of u.searchParams) {
    const name = keySegment(n); if (params.has(name)) continue;
    const keep = (KEY_NUMBER_NAMES.test(n) && /^\d{1,4}$/.test(v)) || (KEY_WORD_NAMES.test(n) && /^[A-Za-z][A-Za-z_-]{0,19}$/.test(v));
    params.set(name, keep ? `${name}=${v}` : name);
  }
  const query = params.size ? `?${[...params.keys()].sort().map(k => params.get(k)).join('&')}` : '';
  return relative ? `${path}${query}` : `${u.protocol}//${u.host}${path}${query}`;
}

/**
 * キーのパスの部分とパラメータの名前は、残してよい形だけを残す（許可リスト）。部分を - _ . で区切ったかけらのうち、
 * 英字の語（24文字まで。大文字・小文字の入れ替わりは4回まで（AdminDashboard）。大文字だけは10文字まで（API・SAML））、6桁までの数字、
 * 「v2」「x64」のような短い語と数字を残し、それ以外は * にする（続く * は1つにまとめる）。
 * 秘密らしい形を数え上げて伏せる作り（v0.4.29・v0.4.30）は、;jsessionid= の値や、小文字と数字だけのトークン（t2ybctp0…）を見分けられず、
 * JSON のエクスポートと例外ファイルに出した。残す形を決めておけば、トークンがどんな形でもキーには入らない。
 * 別のページが同じキーになることはある（GettingStartedV2Guide と MigrationGuideV3 はどちらも *）が、秘密は漏れない
 */
const keyPiece = (p: string): boolean => {
  if (p === '*' || /^\d{1,6}$/.test(p) || /^[A-Za-z]{1,2}\d{1,2}$/.test(p)) return true;
  if (!/^[A-Za-z]{1,24}$/.test(p)) return false;
  if (/^[A-Z]+$/.test(p)) return p.length <= 10;
  return (p.match(/[a-z]+|[A-Z]+/g) ?? []).length <= 4;
};
const keySegment = (s: string): string => s.replace(/[^-_.~]+/g, piece => (keyPiece(piece) ? piece : '*')).replace(/\*(?:[-_.~]\*)+/g, '*');
/** キーに値を残すパラメータの名前（秘密や個人情報を入れない決まった名前だけ）。数字の値（ページ送り）と英字の語の値（並べ替え・表示の切り替え） */
const KEY_NUMBER_NAMES = /^(?:page|per_page|page_size|pagesize|offset|limit|start)$/i;
const KEY_WORD_NAMES = /^(?:sort|order|orderby|dir|lang|locale|hl|tab|view|mode|type|format|_task)$/i;

/**
 * 証跡の抜粋：マスクしてから切り詰める。切り詰めてからマスクすると、途中で切れた JWT（ドットが足りない）や
 * パラメータが一致せず、生の値が残るため
 */
export const clip = (s: string, n: number) => maskText(s).slice(0, n);

/**
 * 手で書いた #META cmd= のコマンド（CSV の「実施コマンド」）。maskText に加えて、curl の認証情報の引数を伏せる：
 * -u・--user（ユーザー:パスワード）、-b・--cookie（Cookie）、-H の Authorization・Cookie・Proxy-Authorization の値。
 * 区切りは空白のほか、#META の値に空白を入れられないので書く「_」も認める
 */
export const maskCommand = (s: string): string => maskText(s)
  .replace(/(^|[\s_])(-u|--user|-b|--cookie|--oauth2-bearer)([\s_=]+)(['"]?)[^\s'"]+/g, '$1$2$3$4****')
  .replace(/((?:Proxy-)?Authorization|Cookie)(:[\s_]*)(?:(Basic|Bearer|Digest|Negotiate|NTLM)([\s_]+))?[^\s'"]+/gi, (_, h: string, c: string, scheme?: string, sp?: string) => `${h}${c}${scheme ? `${scheme}${sp}` : ''}****`);

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
