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
import { lowerToken, rareBigrams } from './tokenShape';

/** 英字に数字を付けた語のうち、残してよい英字の部分（暗号・プロトコル・文字コード・版の名前）。小文字で照合する */
const MIXED_STEMS = new Set(('sha md aes rc des chacha poly secp sect prime ed curve x rsa ecdsa dsa dh ffdhe ecdhe dhe tls tlsv ssl sslv http https h brainpoolp ' +
  'utf base ipv iso ucs cp windows win latin v r ubuntu deb el fc jdk java node php python net pkcs mp gzip ws wss rfc es hs rs ps cve cwe owasp ie ' +
  'chrome firefox safari edge android ios macos jre asvs api level l a').split(' '));
const STEM_DIGITS = /^([a-z]{1,10})(\d{1,5})(?:([a-z]{1,2})\d{1,3})?$/i;
/** 日時（2026-11-01T10:00:00Z の 01T10）と、数字に単位を付けたもの（30s・500ms・64KB・2xx・1st） */
const DATE_OR_UNIT = /^(?:x25519|x448|\d{1,2}T\d{1,2}|\d{1,6}(?:ms|s|m|h|d|w|y|kb|mb|gb|tb|px|em|rem|vh|vw|x|xx|st|nd|rd|th|k)|\d{1,3}(?:ubuntu|deb|el|fc|build|beta|alpha|rc|dev|p|pl)\d{1,3})$/i;

/** 語として残す、英語の読み方の規則に当たらない名前（製品・プロトコル） */
const KNOWN_WORDS = new Set(['xmlrpc', 'nginx', 'lighttpd', 'nodejs', 'nextjs', 'nuxtjs', 'webpack', 'fastly', 'varnish', 'wsgi', 'cgi', 'fcgi', 'grpc', 'hsts', 'csrf', 'xsrf', 'jwks']);
/** キャメルケースの2文字の部分として残してよい語（By・Id・Of・My。乱数の Dg・Ng・Xk を残さない）。大文字だけの略語（JS・IO・DB）は別に認める */
const SHORT_WORDS = new Set('of by id to in on at is my no or up if as be do go it me us we ok'.split(' '));
/**
 * 部分（キャメルケースの語）の中の、英語でよく現れる2文字の並びにないものの割合。語の境目（Asp|Net の pn）は数えない。大文字だけの略語（XML・JS）
 * と2文字までの部分は数えない。数えた並びがなければ0
 */
function partRare(parts: string[]): number {
  let rare = 0, n = 0;
  for (const p of parts) if (p.length >= 3 && !/^[A-Z]+$/.test(p)) { rare += rareBigrams(p.toLowerCase()) * (p.length - 1); n += p.length - 1; }
  return n ? rare / n : 0;
}
/**
 * 英字だけの語が、語として読めるか：
 * - 大文字だけは12文字まで（SAMEORIGIN・ECDHE）
 * - 小文字だけは、乱数のトークン（lowerToken）でなく、6文字以上ならまれな2文字の並びが6割未満（乱数の英小文字は3分の2ほど）
 * - キャメルケースは、部分（Akamai|G|Host・XML|Http|Request）に分けて：2つ目からは大文字で始まる。大文字だけの略語は5文字まで。2文字の部分は
 *   決まった語（By・Id・Of）か略語、1文字の部分は1つまで。部分は4つまで（すべて3文字以上の語なら7つまで。HttpMessageNotReadableException）。
 *   部分の中のまれな2文字の並びが45%未満（tByYjxuIhbLwqalx・NoDgY のような乱数は、語の数や長さだけでは見分けられなかった）
 */
function wordLike(w: string): boolean {
  if (w.length > 48) return false;
  if (KNOWN_WORDS.has(w.toLowerCase())) return true;
  if (/^[A-Z]+$/.test(w)) return w.length <= 12;
  // 10文字以上は45%未満（英語の長い語は4割まで。乱数の英小文字の12〜15文字は、6割の基準では2割が残った）
  if (/^[a-z]+$/.test(w)) return w.length <= 24 && !lowerToken(w) && !(w.length >= 6 && rareBigrams(w) >= (w.length >= 10 ? 0.45 : 0.6));
  const parts = w.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+/g) ?? [];
  if (parts.join('') !== w) return false;
  const singles = parts.filter(p => p.length === 1).length;
  const allWords = parts.every(p => p.length >= 3 || SHORT_WORDS.has(p.toLowerCase()) || /^[A-Z]{2}$/.test(p) || p.length === 1);
  return parts.length <= (allWords && singles === 0 ? 7 : 4) && singles <= 1
    && parts.every((p, i) => (i === 0 || /^[A-Z]/.test(p)) && !/^[A-Z]{6,}$/.test(p)
      && (p.length !== 2 || SHORT_WORDS.has(p.toLowerCase()) || /^[A-Z]{2}$/.test(p)))
    && partRare(parts) < 0.45;
}
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
// パーセントエンコードした文字（%2F。二重エンコードの %252F も）は区切りとして残す（%2Fv1 を1つの語 2Fv1 と読んで伏せた）
// URL のホスト名は、ユーザー情報（user:****@）のあとか、ユーザー情報のない URL の「//」の直後だけ。「//」の直後をいつも残すと、ユーザー名に
// 置いたトークン（https://<トークン>:x-oauth-basic@api…）をホスト名として残した。ユーザー情報には ? # / と空白・引用符・<> を含めない
// （?ref=bob@<トークン> の @ のあとをホスト名とみなした）。伏せた印「…(N chars)」はユーザー情報の中にあってよい（もう一度かけても同じ結果にする）
const USERINFO = String.raw`(?:[^/\s?#@<>"']|…\(\d+ chars\))*@`;
// 英小文字のドメイン名（スキームのない CSP のホスト ajax.aspnetcdn.com、Via の app01.prod.example.com）。決まった最上位ドメインのものだけ
// （/reset/<トークン>.pdf のようなファイル名を残さない）
const DOMAIN = String.raw`(?<![\w.@%/-])(?:\*\.)?(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|jp|co|uk|de|cn|gov|edu|dev|app|cloud|info|biz|me|us|fr|kr|tw|au|ca|in|ru|br|nl|se|ch|it|es|example|internal|local|test|invalid|localhost)(?![\w-])`;
const KEEP = String.raw`…\(\d+ chars\)|%(?:25)*[0-9A-Fa-f]{2}|(?<![\w-])(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![\w+/=-])|(?<=:\/\/${USERINFO})[A-Za-z0-9.-]+|(?<=:\/\/)[A-Za-z0-9.-]+(?!${USERINFO})|${DOMAIN}`;
// - _ + でつないだ語の並び（glpat-<トークン>・sk_live_<トークン>・Strict-Transport-Security）は、まとめて見る
const WORDS = new RegExp(`(${KEEP})|[A-Za-z0-9]+(?:[-_+]+[A-Za-z0-9]+)*`, 'g');
/**
 * 語の並びの、残してよい部分。かけらを1つずつ見ると、- _ で区切った乱数のトークン（URL-safe の Base64・GitLab の glpat-…）の短いかけらが
 * 語に見えて残った（4文字までのかけらは残すため）。並びの中に残せないかけらが1つでもあれば、そこから並びの終わりまでを伏せる。
 * それより前は、英字だけの3文字以上の語のかけら（glpat・sk・live・wordpress_logged_in）だけを残す（種類が分かるように）
 */
function allowRun(run: string): string {
  const pieces = run.split(/([-_+]+)/);   // 偶数番目がかけら、奇数番目が区切り
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
export const allowText = (s: string): string => s.replace(WORDS, (w: string, keep: string | undefined) => (keep ? w : allowRun(w)));

/** 画面・エクスポートに出す文字列（証跡・URL）：名前による伏せ方（maskText）のあとに、許可リストを通す */
export const showText = (s: string): string => allowText(maskText(s));
