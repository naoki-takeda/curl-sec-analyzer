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
  return words.some(w => MASK_WORDS.has(w));
};
// パラメータの区切り：? & # ; と、そのエンコード（%3F・%26・%23・%3B、JS のエスケープ（\u0026 の6文字、\x26）、HTML の &amp;）。
// エンコードした URL を別のパラメータの値に入れたもの（?next=%2Fcb%3Ftoken%3D…）や、スクリプトの中の URL でも見つけるため
const SEP = String.raw`[?&#;]|%3[Ff]|%26|%23|%3[Bb]|\\u00(?:26)|\\x26|&amp;`;
const EQ = String.raw`=|%3[Dd]|\\u003[Dd]|\\x3[Dd]`;
// 値はエンコードした区切りの前まで。名前は最短一致（エンコードした = を名前に含めない）
const ANY_PARAM = new RegExp(String.raw`(${SEP})([\w.%[\]-]{1,100}?)(${EQ})((?:(?!%26|%23|\\u00(?:26)|\\x26)[^&\s#;"'<>\\]){1,4096})`, 'g');
// JWT：直前が英数字・ハイフンでないところから（パーセントエンコードした文字の直後（%3D・%20 など）も含める）。\b だと「-eyJ」の繰り返しで入力の長さの2乗の時間がかかる
const JWT = /(?:(?<=%[0-9A-Fa-f]{2})|(?<![\w-]))eyJ[\w-]+\.[\w-]+\.[\w-]*/g;
// URL のユーザー情報（スキーム://ユーザー情報@ホスト）。スキームは語の先頭から32文字まで（\w+ だと長い英数字の並びで、入力の長さの2乗の時間がかかる）。
// ユーザー情報はホストの前の最後の @ まで（パスワードに @ を含む場合も残さない）。パス・クエリ・フラグメントの @ には一致させない
const URL_CRED = /\b([A-Za-z][\w+.-]{0,31}:\/\/)([^/\s?#<>"']{1,512})@/g;
/** パスワードがあればユーザー名を残してパスワードを伏せる。ユーザー名だけ（https://<トークン>@host/ の形）なら、それをトークンとしてマスクする */
const maskUserinfo = (u: string) => { const i = u.indexOf(':'); return i >= 0 ? `${u.slice(0, i)}:****` : maskValue(u); };

export function maskValue(v: string): string {
  const keep = v.length <= 8 ? 0 : v.length <= 20 ? 2 : 4;
  return `${v.slice(0, keep)}…(${v.length} chars)`;
}
/** マスク済みの値（「…(N chars)」を含む）。もう一度マスクしても変えない（ルールで切り詰める前にマスクし、engine/run.ts でもマスクするため） */
const masked = (v: string) => v.includes('…');

/** CSP の nonce の値（'nonce-…'）。どの証跡でも同じようにマスクする（H-04⑤ と同じ扱い） */
const CSP_NONCE = /'nonce-([^']+)'/g;

/** パラメータの値をマスクする。秘密でない名前の値も、その中に埋め込まれたパラメータ（エンコードした URL）を見る（深さ3まで） */
function maskParams(s: string, depth = 0): string {
  return s.replace(ANY_PARAM, (all, sep: string, k: string, eq: string, v: string) => {
    if (masked(v)) return all;
    if (isSecretParamName(k)) return `${sep}${k}${eq}${maskValue(v)}`;
    return depth < 3 ? `${sep}${k}${eq}${maskParams(v, depth + 1)}` : all;
  });
}

/** ヘッダ以外の文字列（URL、証跡）に含まれるトークン類をマスクする。マスク済みの文字列に使っても結果は変わらない */
export function maskText(s: string): string {
  return maskParams(s.replace(CSP_NONCE, (all, v: string) => (masked(v) ? all : `'nonce-${maskValue(v)}'`)))
          .replace(JWT, t => maskValue(t))
          .replace(URL_CRED, (_, sc: string, u: string) => `${sc}${maskUserinfo(u)}@`);
}

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
