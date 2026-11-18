// shownText.ts：画面・エクスポートに出す証跡と URL の最後の関門（許可リスト）
// mask.ts の maskText は、秘密らしい名前（?token=・"password":）と形（JWT・パスの長い乱数）を推し量って伏せる。推し量る作りは、名前の
// 付いていない値（本文の ghp_…・AKIA…・sk_live_…）や、どの形にも当たらない値を残し、直しても次の漏れが見つかることをくり返した
// （突き合わせのキーと実施コマンドの要約で同じことが起き、許可リストに変えた。engine/targetKey.ts・export/cmdSummary.ts）。
// ここでは、maskText のあとの文字列から ASCII の英数字の並び（語）を取り出し、残してよい形の語だけを残す。それ以外の語は「…(N chars)」にする：
// - 4文字までの語（maskValue が残す先頭の数文字、v2・TLS・443 など）と、10桁までの数字（ポート・秒数・大きさ・日付の部分）
// - 英字だけの語：小文字だけ・大文字だけ（12文字まで）・語をつないだキャメルケース（includeSubDomains・XMLHttpRequest）。24文字まで。
//   英小文字の乱数（tokenShape.ts の lowerToken、母音の少ない並び）と、大文字・小文字が頻繁に入れ替わるもの（QwErTyUiOp）は残さない
// - 英字と数字の語は、決まった語に数字を付けたもの（sha256・AES128・TLSv1・secp256r1・utf8・ubuntu2）と、日時・単位（01T10・30s・64KB）だけ
// - URL のホスト名、CSP のハッシュ（'sha256-…'）、伏せた印「…(N chars)」は、そのまま残す
// 名前の付いた短い秘密（password=hunter2 の hunter2）は形では見分けられないので、maskText の名前による伏せ方と組み合わせて使う。
// このファイルは mask.ts の maskText と一緒に showText として使う。もう一度かけても結果は変わらない（冪等）
import { maskText } from './mask';
import { rareBigrams, wordLike } from './tokenShape';

/** 英字に数字を付けた語のうち、残してよい英字の部分（暗号・プロトコル・文字コード・版の名前）。小文字で照合する */
const MIXED_STEMS = new Set(('sha md aes rc des chacha poly secp sect prime ed curve x rsa ecdsa dsa dh ffdhe ecdhe dhe tls tlsv ssl sslv http https h brainpoolp ' +
  'utf base ipv iso ucs cp windows win latin v r ubuntu deb el fc jdk java node php python net pkcs mp gzip ws wss rfc es hs rs ps cve cwe owasp ie ' +
  'chrome firefox safari edge android ios macos jre asvs api level l a').split(' '));
const STEM_DIGITS = /^([a-z]{1,10})(\d{1,5})(?:([a-z]{1,2})\d{1,3})?$/i;
/** 日時（2026-11-01T10:00:00Z の 01T10）と、数字に単位を付けたもの（30s・500ms・64KB・2xx・1st） */
const DATE_OR_UNIT = /^(?:x25519|x448|\d{1,2}T\d{1,2}|\d{1,6}(?:ms|s|m|h|d|w|y|kb|mb|gb|tb|px|em|rem|vh|vw|x|xx|st|nd|rd|th|k)|\d{1,3}(?:ubuntu|deb|el|fc|build|beta|alpha|rc|dev|p|pl)\d{1,3})$/i;

/**
 * 英字の語と数字をつないだ語（oauth2・app01・CookiesC1・sha1WithRSAEncryption・1024bit）：英字と数字のかたまりが3つまでで、英字のかたまりは
 * 3文字以上の語として読めるもの、数字は合わせて4桁まで。乱数のトークン（Dk3x9Lq2・AKIAIOSFODNN7EXAMPLE）はかたまりが多いか、英字が語として読めない。
 * 名前の付いていない短い合言葉（hunter2）は、この形では見分けられない（maskText が名前で伏せる）
 */
function joinedWords(w: string): boolean {
  const chunks = w.match(/[A-Za-z]+|\d+/g) ?? [];
  const digits = chunks.filter(c => /^\d/.test(c)).join('').length;
  // 単位（KB・ms・k）は数字の直後だけ（K7MDENG の K を単位と読んだ）。大文字だけのかたまりは5文字まで（AKIAIOSFODNN7EXAMPLE を残さない）。
  // 英字のかたまりは、短くてもまれな2文字の並びが半分未満のもの（GitLab のトークンのかけら rbdO66tkD の rbd・tkD を語とみなした）
  return chunks.length <= 3 && digits <= 4 && chunks.every((c, i) => /^\d/.test(c) || (UNITS.test(c) && i > 0 && /^\d/.test(chunks[i - 1]))
    || (c.length >= 3 && wordLike(c) && !/^[A-Z]{6,}$/.test(c) && rareBigrams(stem(c).toLowerCase()) < 0.5));
}
/** 末尾の1文字の大文字（分割した Cookie の CookiesC の C）を除いた部分 */
const stem = (c: string) => (/[a-z][A-Z]$/.test(c) ? c.slice(0, -1) : c);
const UNITS = /^(?:bit|bits|byte|bytes|ms|s|m|h|d|w|y|kb|mb|gb|tb|px|em|rem|vh|vw|x|xx|st|nd|rd|th|k)$/i;

/** 残してよい語か */
export function allowedWord(w: string): boolean {
  if (w.length <= 4) return true;
  if (/^\d+$/.test(w)) return w.length <= 10;
  if (/^[A-Za-z]+$/.test(w)) return wordLike(w);
  if (DATE_OR_UNIT.test(w) || joinedWords(w)) return true;
  const m = w.match(STEM_DIGITS);
  // 1文字の語（v・x・h・r）に付ける数字は3桁まで（v2・x509・h264。a12345b123 のようなかけらを残さない）
  return !!m && MIXED_STEMS.has(m[1].toLowerCase()) && (m[1].length > 1 || m[2].length <= 3);
}

// 語として見ずにそのまま残す部分：伏せた印、CSP・SRI のハッシュ（長さちょうどのもの。mask.ts の HASH_SOURCE と同じ）、URL のホスト名（ユーザー情報のあと）
// パーセントエンコードした文字（%2F。二重エンコードの %252F も）は区切りとして残す（%2Fv1 を1つの語 2Fv1 と読んで伏せた）。4つ以上の並びは escapeRun で見る
// URL のホスト名は、ユーザー情報（user:****@）のあとか、ユーザー情報のない URL の「//」の直後だけ。「//」の直後をいつも残すと、ユーザー名に
// 置いたトークン（https://<トークン>:x-oauth-basic@api…）をホスト名として残した。ユーザー情報には ? # / と空白・引用符・<> を含めない
// （?ref=bob@<トークン> の @ のあとをホスト名とみなした）。伏せた印「…(N chars)」はユーザー情報の中にあってよい（もう一度かけても同じ結果にする）
// ユーザー情報は256文字まで（上限がないと、「@」の多い入力で、位置ごとに「//」まで読み戻して、入力の長さの2乗の時間がかかった）
// 引用符（' "）は、後ろに語の文字が続くときだけユーザー情報に入る（mask.ts の URL_CRED と同じ）
const USERINFO = String.raw`(?:[^/\s?#@<>"']|["'](?=[\w-])|…\(\d+ chars\)){0,256}@`;
// 英小文字のドメイン名（スキームのない CSP のホスト ajax.aspnetcdn.com、Via の app01.prod.example.com）。決まった最上位ドメインのものだけ
// （/reset/<トークン>.pdf のようなファイル名を残さない）
const DOMAIN = String.raw`(?<![\w.@%/-])(?:\*\.)?(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|jp|co|uk|de|cn|gov|edu|dev|app|cloud|info|biz|me|us|fr|kr|tw|au|ca|in|ru|br|nl|se|ch|it|es|example|internal|local|test|invalid|localhost)(?![\w-])`;
const KEEP = String.raw`…\(\d+ chars\)|(?<![\w-])(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![\w+/=-])|(?<=:\/\/${USERINFO})[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|(?<=:\/\/)(?=(?<hostRun>[A-Za-z0-9.-]+))\k<hostRun>(?!${USERINFO})|${DOMAIN}`;
// ↑ ユーザー情報のない URL のホスト名は、並び全体を一度に取ってから後ろを見る（先読みと後方参照で、短く区切り直して試さない）。
// 区切り直すと、長いホスト名らしい並びのあとに @ がある入力（Location: https://a.a.a…@evil/）で、1文字ずつ短くするたびに @ まで読み直し、
// 入力の長さの2乗の時間がかかった（64KB で4秒）
// - _ + でつないだ語の並び（glpat-<トークン>・sk_live_<トークン>・Strict-Transport-Security）は、まとめて見る
// パーセントエンコードした + / =（%2B・%2F・%3D、二重エンコードを含む）も並びの区切りとする（エンコードした Base64 のトークンが、%XX で
// 短いかけらに分かれて残った）。区切りは「- _ +」の並びか、エンコードした文字の並び
// エンコードした空白・-・.（%20・%2D・%2E）も区切りとする（1234%205678%209012 のような区切った番号が、4桁のかけらに分かれて残った）
const JOIN = String.raw`(?:[-_+]|%(?:25)*(?:2[BbFf0DdEe]|3[Dd]))+`;
// パーセントエンコードした文字の並び（%2F。二重エンコードの %252F も）。1つずつを区切りとして残すと、エンコードしたバイナリ・暗号文
// （?d=%8F%1A%C3%77%E2%99…）がそのまま残ったので、並びとして見る（escapeRun）
const ESCAPES = String.raw`(?:%(?:25)*[0-9A-Fa-f]{2})+`;
const WORDS = new RegExp(`(${ESCAPES})|(${KEEP})|[A-Za-z0-9]+(?:${JOIN}[A-Za-z0-9]+)*`, 'g');
const JOIN_SPLIT = new RegExp(`(${JOIN})`);
/**
 * 語の並びの、残してよい部分。かけらを1つずつ見ると、- _ で区切った乱数のトークン（URL-safe の Base64・GitLab の glpat-…）の短いかけらが
 * 語に見えて残った（4文字までのかけらは残すため）。並びの中に残せないかけらが1つでもあれば、そこから並びの終わりまでを伏せる。
 * それより前は、英字だけの3文字以上の語のかけら（glpat・sk・live・wordpress_logged_in）だけを残す（種類が分かるように）
 */
/**
 * 番号のかけらとして、語として読めないもの：英字と数字が混ざる（K7QX・a1b2。ただし rc4・md5・sha1 のような残してよい語は除く）か、英字だけでまれな
 * 2文字の並びが半分以上（ZXCV・ASDF）。暗号の略語（CBC・GCM・DHE・ADH・SRP）はまれな並びが多いが、乱数とみなさない（ECDHE-RSA-RC4-SHA を伏せた）
 */
const CRYPTO_WORDS = new Set('aes des ede rc2 rc4 md5 sha cbc gcm ccm rsa dss dhe edh ecdh ecdhe adh aecdh srp psk idea exp null anon seed aria camellia chacha poly ecdsa tls ssl sm2 sm3 sm4 gost'.split(' '));
const randomPiece = (p: string) => !CRYPTO_WORDS.has(p.toLowerCase()) && (/\d/.test(p) && /[A-Za-z]/.test(p) ? !STEM_DIGITS.test(p) || !MIXED_STEMS.has((p.match(STEM_DIGITS)?.[1] ?? '').toLowerCase())
  : /^[A-Za-z]{4,}$/.test(p) && rareBigrams(p.toLowerCase()) >= 0.5);   // 英字3文字（pdf・img・MIT）は略語として乱数とみなさない
/** 6桁までの数字だけのかけらが3つ以上続き、合わせて12桁以上になる部分があるか（日付の 20261118 のような8桁を含む並び（db-backup-20261118-0300-01）は番号としない） */
const digitRun = (nums: string[]): boolean => { let n = 0, len = 0; for (const p of nums) { if (/^\d{1,6}$/.test(p)) { n++; len += p.length; if (n >= 3 && len >= 12) return true; } else { n = 0; len = 0; } } return false; };
function allowRun(run: string): string {
  const pieces = run.split(JOIN_SPLIT);   // 偶数番目がかけら、奇数番目が区切り
  // 数字だけのかけらが3つ以上続き、合わせて12桁以上の部分があるもの（カード番号 4111-1111-1111-1111・電話番号、語のあとの card%204111%201111…）は、
  // まとめて伏せる（4桁ずつ残った。並び全体が数字のときだけにすると、前に語が付いたものを残した）
  const nums = pieces.filter((_, i) => i % 2 === 0);
  if (digitRun(nums)) return `…(${run.length} chars)`;
  // 同じ長さ（3〜5文字）の英数字のかけらを3つ以上つないだ番号（招待・パスワードの再設定・マジックリンクの /invite/QWER-TYUI-ZXCV-ASDF・K7QX-9MZP-A2B4-C6D8）は、
  // （長さのそろわない暗号の名前 ECDHE-RSA-RC4-SHA・製品の型番は対象外）
  // かけらの半分以上が語として読めない（英字と数字が混ざる、まれな2文字の並びが半分以上）なら、まとめて伏せる（4文字までのかけらとして残った）
  if (nums.length >= 3 && nums.every(p => /^[A-Za-z0-9]{3,5}$/.test(p) && p.length === nums[0].length) && !nums.every(p => /^\d+$/.test(p))
    && nums.filter(randomPiece).length * 2 >= nums.length) return `…(${run.length} chars)`;
  const bad = pieces.findIndex((p, i) => i % 2 === 0 && !allowedWord(p));
  if (bad < 0) return run;
  let keep = 0;
  // 2つ目からは4文字以上の、まれな2文字の並びの少ない語だけ（glpat-mfo_… の mfo のような乱数のかけらを、語として残さない）
  for (let i = 0; i < bad; i += 2) {
    const p = pieces[i];
    if (!/^[A-Za-z]{2,}$/.test(p) || !wordLike(p) || (i > 0 && (p.length < 4 || rareBigrams(p.toLowerCase()) >= 0.3))) break;
    keep = i + 2;
  }
  const kept = pieces.slice(0, keep).join(''), rest = pieces.slice(keep).join('');
  return `${kept}…(${rest.length} chars)`;
}

/** 残してよい形の語だけを残す（それ以外は「…(N chars)」） */
export const allowText = (s: string): string => s.replace(WORDS, (w: string, esc: string | undefined, keep: string | undefined) => (esc ? escapeRun(esc) : keep ? w : allowRun(w)));

/**
 * パーセントエンコードした文字の並び。3つまで（区切りの %2F・%3D、1文字の日本語）はそのまま残す。4つ以上は戻して見て、読める文字
 * （日本語などの文字・数字・記号・空白。ASCII の語は残してよい形のもの）だけならそのまま、それ以外（UTF-8 として読めないバイト、制御文字、
 * 残せない形の ASCII の語）は伏せる。エンコードした日本語のパス（/%E3%81%8A%E7%9F%A5%E3%82%89%E3%81%9B）は残す
 */
function escapeRun(run: string): string {
  if ((run.match(/%/g) ?? []).length < 4) return run;
  let d = run;
  for (let i = 0; i < 3 && /%[0-9A-Fa-f]{2}/.test(d); i++) { try { d = decodeURIComponent(d); } catch { return `…(${run.length} chars)`; } }
  if (!/^[\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]*$/u.test(d) || /\uFFFD/.test(d)) return `…(${run.length} chars)`;
  // 戻すと名前や形で伏せる値になるもの（全体をエンコードしたカード番号 %34%31%31%31%20…）は伏せる
  if (maskText(d) !== d) return `…(${run.length} chars)`;
  return (d.match(/[A-Za-z0-9]+/g) ?? []).every(allowedWord) ? run : `…(${run.length} chars)`;
}

/** 画面・エクスポートに出す文字列（証跡・URL）：名前による伏せ方（maskText）のあとに、許可リストを通す */
// もう一度かけても変わらないようにする（伏せた語「…(8 chars)」の直後の「//…@」をユーザー情報として伏せ直すなど、1回目の結果が2回目の手がかりを変える）。
// ふつうは2回で止まる
export const showText = (s: string): string => {
  let out = allowText(maskText(s));
  for (let i = 0; i < 4; i++) { const next = allowText(maskText(out)); if (next === out) break; out = next; }
  return out;
};
