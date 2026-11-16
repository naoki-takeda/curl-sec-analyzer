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
const MASK_PARAM_NAMES = [...TOKEN_PARAM_NAMES, ...SESSION_PARAM_NAMES, 'code', 'password', 'passwd', 'pass', 'pw', 'secret', 'key', 'signature', 'sig',
  'ticket', 'oauth_verifier', 'SAMLResponse', 'SAMLart', 'accesskey'];
const alt = (names: string[]) => names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
/** クエリ（?・&）、フラグメント（#）、パス引数（;）のどれに置かれても一致する */
export const paramRegex = (names: string[], flags = 'i') => new RegExp(`([?&#;](?:${alt(names)})=)([^&\\s#;"'<>]+)`, flags);
const MASK_EXACT = new Set(MASK_PARAM_NAMES.map(n => n.toLowerCase()));
/** 区切った語にこれがあればマスクする（x-amz-security-token、x-goog-signature、private_token、x-api-key、access-token など） */
const MASK_WORDS = new Set(['token', 'secret', 'signature', 'sig', 'credential', 'credentials', 'password', 'passwd', 'pwd', 'pass', 'pw', 'key', 'apikey',
  'accesskey', 'auth', 'authorization', 'session', 'sessionid', 'sid', 'jwt', 'code', 'otp', 'ticket', 'verifier', 'samlresponse', 'samlart']);
/** マスクするパラメータ名か（検出用の一覧を含み、それより広い） */
// 語の区切り：- _ . と角かっこ（user[password]、%5B・%5D）、キャメルケースの境目（accessToken、clientSecret）。
// 名前がパーセントエンコードされていても（api%5Fkey）、デコードしてから照合する
export const isSecretParamName = (name: string): boolean => {
  let n: string;
  try { n = decodeURIComponent(name); } catch { n = name.replace(/%5[bd]/gi, '_'); }   // 不正なエンコードを含む名前は、角かっこだけ区切りにする
  if (MASK_EXACT.has(n.toLowerCase())) return true;
  const words = n.replace(/([a-z\d])([A-Z])/g, '$1_$2').toLowerCase().split(/[-_.[\]]+/);
  // 区切りのない1語の名前（authtoken、apitoken、secretkey、cftoken、sesskey、passphrase など）は、部分一致でも見る（伏せすぎるほうが安全）
  return words.some(w => MASK_WORDS.has(w)) || SECRET_PART.test(n.toLowerCase());
};
const SECRET_PART = /token|secret|passw|passphrase|pwd|apikey|authkey|accesskey|privatekey|sessid|sesskey|credential|signature/;
// パラメータの区切り：? & # ; と、そのエンコード（%3F・%26・%23・%3B と二重エンコードの %253F など、JS のエスケープ（\u0026 の6文字、\x26）、HTML の文字参照（&amp;・&#38;・&#x3D; など））。
// エンコードした URL を別のパラメータの値に入れたもの（?next=%2Fcb%3Ftoken%3D…）や、スクリプトの中の URL でも見つけるため
const SEP = String.raw`[?&#;]|%(?:25)*(?:3[Ff]|26|23|3[Bb])|\\u00(?:26)|\\x26|&amp;|&#0*(?:63|38);|&#[xX]0*(?:3[Ff]|26);|&quest;`;
const EQ = String.raw`=|%(?:25)*3[Dd]|\\u003[Dd]|\\x3[Dd]|&#0*61;|&#[xX]0*3[Dd];|&equals;`;
// 値はエンコードした区切りの前まで（長さの上限は付けない。上限で切ると、6KB の JWT などの残りが伏せられずに残る。繰り返しは入れ子でないので時間は線形）。
// 名前は最短一致（エンコードした = を名前に含めない）
const ANY_PARAM = new RegExp(String.raw`(${SEP})([\w.%[\]-]{1,100}?)(${EQ})((?:(?!%(?:25)*(?:26|23)|\\u00(?:26)|\\x26)[^&\s#;"'<>\\])+)`, 'g');
// JWT：直前が英数字・ハイフンでないところから（パーセントエンコードした文字の直後（%3D・%20 など）も含める）。\b だと「-eyJ」の繰り返しで入力の長さの2乗の時間がかかる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-]))eyJ[\w-]+\.[\w-]+\.[\w-]*/g;
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
const PATH_SEGMENT = /(?<=(?<!\/)\/|(?<!%(?:25)*2[Ff])%(?:25)*2[Ff])[A-Za-z0-9_=.:~+-]{16,}/g;
const secretPiece = (p: string): boolean => /^[A-Za-z0-9_-]{16,}$/.test(p) && (
  (/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p)) || /^[0-9a-f]{24,}$/i.test(p.replace(/-/g, '')) || (p.length >= 32 && /\d/.test(p)));
/** 伏せ方：画面・エクスポート用（先頭の数文字と長さを残す）と、突き合わせのキー用（記録し直しても変わらないよう、何も残さない） */
interface Hider { value: (v: string) => string; bare: (v: string) => string }
const SHOW: Hider = { value: v => maskValue(v), bare: v => `…(${v.length} chars)` };
const KEY: Hider = { value: () => '…', bare: () => '…' };
/**
 * かけらを伏せる。英字だけの短い語と - か _ で始まるもの（application-<ダイジェスト>.js、vendor-<ダイジェスト>.js）は、その語を残して
 * 残りだけを伏せる（別のファイルを区別できるように。残りは先頭の文字を残さず、もう一度マスクしても変わらないようにする）
 */
const maskSegment = (seg: string, h: Hider = SHOW): string => seg.replace(/[^.:~+]+/g, piece => {
  const body = piece.replace(/=+$/, ''); const pad = piece.slice(body.length);
  if (!secretPiece(body)) return piece;
  const m = body.match(/^([A-Za-z]{3,20}[-_])(.+)$/);
  return m && secretPiece(m[2]) ? m[1] + h.bare(m[2]) + pad : h.value(body) + pad;
});
/**
 * ASP.NET の Cookie を使わないセッション（/(S(<セッションID>))/、フォーム認証のチケット /(F(<チケット>))/、匿名ID の A(…)）。
 * パスの部分が「(」で始まるので、PATH_SEGMENT では見つからない
 */
const ASPNET_COOKIELESS = /\/\(((?:[A-Z]\([^()\s/]+\))+)\)/g;

/** CSP の nonce の値（'nonce-…'）。どの証跡でも同じようにマスクする（H-04⑤ と同じ扱い） */
const CSP_NONCE = /'nonce-([^']+)'/g;

/** パラメータの値をマスクする。秘密でない名前の値も、その中に埋め込まれたパラメータ（エンコードした URL）を見る（深さ3まで） */
function maskParams(s: string, h: Hider, depth = 0): string {
  return s.replace(ANY_PARAM, (all: string, sep: string, k: string, eq: string, v: string, offset: number) => {
    if (maskedParam(v, s.slice(offset + all.length, offset + all.length + 7))) return all;
    if (isSecretParamName(k)) return `${sep}${k}${eq}${h.value(v)}`;
    return depth < 3 ? `${sep}${k}${eq}${maskParams(v, h, depth + 1)}` : all;
  });
}

function mask(s: string, h: Hider): string {
  // 順序：パラメータ → JWT（パスに置いた JWT を、かけらに分けずに丸ごと伏せる） → ユーザー情報 → ASP.NET のセッション → パスの部分
  return maskParams(s.replace(CSP_NONCE, (all, v: string) => (MASKED.test(v) ? all : `'nonce-${h.value(v)}'`)), h)
          .replace(JWT, t => h.value(t))
          .replace(URL_CRED, (_, sc: string, u: string) => `${sc}${maskUserinfo(u, h)}@`)
          .replace(ASPNET_COOKIELESS, (_, inner: string) => `/(${inner.replace(/([A-Z])\(([^()]+)\)/g, (__, k: string, v: string) => `${k}(${h.value(v)})`)})`)
          .replace(PATH_SEGMENT, seg => maskSegment(seg, h));
}

/** ヘッダ以外の文字列（URL、証跡）に含まれるトークン類をマスクする。マスク済みの文字列に使っても結果は変わらない */
export const maskText = (s: string): string => mask(s, SHOW);

/**
 * 例外と前回の結果の突き合わせに使う URL（HAR の targetKey）。伏せる場所は maskText と同じだが、伏せた値を「…」だけにする。
 * maskText の出力（先頭の数文字と長さを残す）をキーにすると、同じページを記録し直したときに ?code= などの値でキーが変わり、
 * 例外が効かず、差分ではすべて「新規」になる
 */
export const maskKey = (s: string): string => mask(s, KEY);

/**
 * 証跡の抜粋：マスクしてから切り詰める。切り詰めてからマスクすると、途中で切れた JWT（ドットが足りない）や
 * パラメータが一致せず、生の値が残るため
 */
export const clip = (s: string, n: number) => maskText(s).slice(0, n);

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
