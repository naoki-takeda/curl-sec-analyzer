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
const MIXED_STEMS = new Set(('sha md aes rc des chacha poly secp sect prime ed curve x rsa ecdsa dsa dh ffdhe ecdhe dhe tls tlsv ssl sslv http https h ' +
  'utf base ipv iso ucs cp windows win latin v r ubuntu deb el fc jdk java node php python net pkcs mp gzip ws wss rfc es hs rs ps cve cwe owasp ie ' +
  'chrome firefox safari edge android ios macos jre asvs api level l a').split(' '));
const STEM_DIGITS = /^([a-z]{1,10})(\d{1,5})(?:([a-z]{1,2})\d{1,3})?$/i;
/** 日時（2026-11-01T10:00:00Z の 01T10）と、数字に単位を付けたもの（30s・500ms・64KB・2xx・1st） */
const DATE_OR_UNIT = /^(?:x25519|x448|\d{1,2}T\d{1,2}|\d{1,6}(?:ms|s|m|h|d|w|y|kb|mb|gb|tb|px|em|rem|vh|vw|x|xx|st|nd|rd|th|k)|\d{1,3}(?:ubuntu|deb|el|fc|build|beta|alpha|rc|dev|p|pl)\d{1,3})$/i;

/** 英字だけの語が、語として読めるか */
function wordLike(w: string): boolean {
  if (w.length > 24) return false;
  if (/^[A-Z]+$/.test(w)) return w.length <= 12;
  // 6文字以上は、英語でよく現れる2文字の並びにないものが半分以上なら、語ではない（乱数の英字は3分の2ほど。webkit・jsdelivr・csrfToken は4割まで）。
  // キャメルケースの乱数（tByYjxuIhbLwqalx）は、語の数だけでは見分けられなかった
  if (w.length >= 6 && rareBigrams(w.toLowerCase()) >= 0.5) return false;
  if (/^[a-z]+$/.test(w)) return !lowerToken(w) && !(w.length >= 8 && (w.match(/[aeiouy]/g) ?? []).length / w.length < 0.2);
  // キャメルケース：語（Asp・Net・Core・XML）の数が3つまでか、長さの3分の1以下（includeSubDomains・AspNetCore は3語。QwErTyUiOp は5語で残さない）。
  // 1文字の語は、先頭と末尾（分割した Cookie の CookiesC の C）だけ
  // 大文字だけの部分（略語の XML・HTTP・SAML）は5文字まで（bPxRfiCYEXAMPLEKEY・HxYzABCDEFGHIJ のような乱数の大文字の並びを残さない）
  // 大文字・小文字の混ざる10文字以上は、まれな2文字の並びが35%未満のものだけ（突き合わせのキーの lowerToken と同じ基準。
  // XMLHttpRequest は31%、AspNetCore は22%。乱数の NtZhbLsDbUMSHrtbxm は47%）
  if (w.length >= 10 && rareBigrams(w.toLowerCase()) >= 0.35) return false;
  const parts = w.match(/[A-Z]{2,}(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[A-Z]+/g) ?? [];
  return parts.join('') === w && parts.length <= Math.min(4, Math.max(3, Math.ceil(w.length / 3)))
    // 2つ目からの語は大文字で始まる（XUtn の tn のように、小文字だけの語が途中にあるのは乱数の並び）
    && parts.every((p, i) => (p.length >= 2 || i === 0 || i === parts.length - 1) && !/^[A-Z]{6,}$/.test(p) && (i === 0 || /^[A-Z]/.test(p)));
}
/**
 * 英字の語と数字をつないだ語（oauth2・app01・CookiesC1・sha1WithRSAEncryption・1024bit）：英字と数字のかたまりが3つまでで、英字のかたまりは
 * 3文字以上の語として読めるもの、数字は合わせて4桁まで。乱数のトークン（Dk3x9Lq2・AKIAIOSFODNN7EXAMPLE）はかたまりが多いか、英字が語として読めない。
 * 名前の付いていない短い合言葉（hunter2）は、この形では見分けられない（maskText が名前で伏せる）
 */
function joinedWords(w: string): boolean {
  const chunks = w.match(/[A-Za-z]+|\d+/g) ?? [];
  const digits = chunks.filter(c => /^\d/.test(c)).join('').length;
  // 単位（KB・ms・k）は数字の直後だけ（K7MDENG の K を単位と読んだ）。大文字だけのかたまりは5文字まで（AKIAIOSFODNN7EXAMPLE を残さない）
  return chunks.length <= 3 && digits <= 4 && chunks.every((c, i) => /^\d/.test(c) || (UNITS.test(c) && i > 0 && /^\d/.test(chunks[i - 1]))
    || (c.length >= 3 && wordLike(c) && !/^[A-Z]{6,}$/.test(c)));
}
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
const KEEP = String.raw`…\(\d+ chars\)|%(?:25)*[0-9A-Fa-f]{2}|(?<![\w-])(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![\w+/=-])|(?<=:\/\/(?:[^/\s@]*@)?)[A-Za-z0-9.-]+`;
const WORDS = new RegExp(`(${KEEP})|[A-Za-z0-9]+`, 'g');

/** 残してよい形の語だけを残す（それ以外は「…(N chars)」） */
export const allowText = (s: string): string => s.replace(WORDS, (w: string, keep: string | undefined) => (keep || allowedWord(w) ? w : `…(${w.length} chars)`));

/** 画面・エクスポートに出す文字列（証跡・URL）：名前による伏せ方（maskText）のあとに、許可リストを通す */
export const showText = (s: string): string => allowText(maskText(s));
