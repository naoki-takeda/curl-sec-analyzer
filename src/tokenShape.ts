// tokenShape.ts：乱数のトークンと英字の語の形の判定。画面のマスク（mask.ts）・許可リスト（shownText.ts）・突き合わせのキー（engine/targetKey.ts）・ルール（rules/util.ts）で
// 共有する（キーはマスクを読み込まないので、同じ規則を別々に書いて食い違わないよう、このファイルだけを両方から読む。このファイルは何も読み込まない）

/** 英語でよく現れる2文字の並び。乱数の英小文字では、並びの3分の2ほどがこの一覧にない（英語の語をつないだものでは4分の1以下） */
const COMMON_BIGRAMS = new Set(('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo fs ks ws nk kn yp dy wr sk rp dg nv hy ze zi ka yi').split(' '));

/**
 * 英小文字だけの16文字以上の乱数のトークン（/invite/qwrtzxkpmnbvcdfgh）か。次のどちらか：
 * - 母音（y を含む）が4分の1未満（登録済みの例外のキーを変えないため）
 * - よく現れる2文字の並びにないものが35%以上（乱数の16〜24文字の約98%。英語の語をつないだもの（healthcheckstatus・nightschoolprograms・
 *   internationalization）は24%以下なので残る）
 */
export function lowerToken(x: string): boolean {
  if (x.length < 16 || !/^[a-z]+$/.test(x)) return false;
  if ((x.match(/[aeiouy]/g) ?? []).length / x.length < 0.25) return true;
  return rareBigrams(x) >= 0.35;
}

// ---- 区切った番号・コードの形。画面の許可リスト（shownText.ts の allowRun）と突き合わせのキー（engine/targetKey.ts の keySegment）で共有する ----
/**
 * 6桁までの数字だけのかけらが3つ以上続き、合わせて12桁以上になる部分があるか（カード番号 4111-1111-1111-1111 など。10〜11桁の電話番号は
 * 含まない（画面は電話番号を残す。キーは phoneRun も見る）。日付の 20261118 のような8桁を含む並び（db-backup-20261118-0300-01）は番号としない）
 */
export const digitRun = (pieces: string[]): boolean => {
  let n = 0, len = 0;
  for (const p of pieces) { if (/^\d{1,6}$/.test(p)) { n++; len += p.length; if (n >= 3 && len >= 12) return true; } else { n = 0; len = 0; } }
  return false;
};
/**
 * 電話番号の形の部分があるか。数字のかけらが3つ以上続き、合わせて10〜11桁で、次のどちらか（突き合わせのキーだけが使う）：
 * - 先頭のかけらが 0 で始まる2桁以上（090-1234-5678・03-1234-5678・0312-34-5678・01267-2-3456・0120-123-456・01-23-45-67-89）
 * - 2〜4桁・3〜4桁・3〜4桁の3つ（555-123-4567）
 * 先頭のかけらには数字でない文字が前に付いてよく（tel090-…・tel:090-…・(090)-…・+1-555-…）、最後のかけらには英字が3文字まで付いてよい
 * （内線の 5678x）。国番号のあとの番号は、市外局番の先頭の 0 を落としたものとして数える（+81-3-1234-5678・81-90-1234-5678・+33-1-23-45-67-89）。
 * 月・日の2桁が続く日付（2026-11-19-01）は当たらない
 */
export const phoneRun = (pieces: string[]): boolean => {
  for (let i = 0; i < pieces.length; i++) {
    const m = pieces[i].match(/^\D*(\d{1,5})\)?$/); if (!m) continue;
    // 国番号：+ の付いた1〜3桁のあとの4桁までか、+ のない1〜3桁のあとの1〜2桁（IPv4 の 192.168.100.200 を国番号のある番号と読まない。
    // IPv4 のかけらは3桁までなので、0 を足した1〜2桁と2つのかけらで9桁までにしかならない）
    const prev = i > 0 ? pieces[i - 1] : '';
    const cc = !m[1].startsWith('0') && ((/^\D*\+\d{1,3}$/.test(prev) && m[1].length <= 4) || (/^\d{1,3}$/.test(prev) && m[1].length <= 2));
    const head = cc ? `0${m[1]}` : m[1];
    let n = 1, len = head.length;
    // 12桁を超えたら打ち切る（かけらは1桁以上なので、1つの始まりから見るのは12個まで。線形時間）
    for (let j = i + 1; j < pieces.length && len <= 11; j++) {
      const d = pieces[j].match(/^(\d{1,5})([A-Za-z]{0,3})$/); if (!d) break;
      n++; len += d[1].length;
      // 0 で始まるのは2桁以上の市外局番だけ（版 10.0.19045.3803 の「0」から数えない）
      if (n >= 3 && len >= 10 && len <= 11 && (/^0\d/.test(head)
        || (n === 3 && /^\d{2,4}$/.test(head) && /^\d{3,4}$/.test(pieces[j - 1]) && /^\d{3,4}$/.test(d[1])))) return true;
      if (d[2]) break;   // 英字の付いたかけらで、番号は終わる
    }
  }
  return false;
};
/** 英字に数字を付けた語のうち、残してよい英字の部分（暗号・プロトコル・文字コード・版の名前）。小文字で照合する */
export const MIXED_STEMS = new Set(('sha md aes rc des chacha poly secp sect prime ed curve x rsa ecdsa dsa dh ffdhe ecdhe dhe tls tlsv ssl sslv http https h brainpoolp ' +
  'utf base ipv iso ucs cp windows win latin v r ubuntu deb el fc jdk java node php python net pkcs mp gzip ws wss rfc es hs rs ps cve cwe owasp ie ' +
  'chrome firefox safari edge android ios macos jre asvs api level l a').split(' '));
export const STEM_DIGITS = /^([a-z]{1,10})(\d{1,5})(?:([a-z]{1,2})\d{1,3})?$/i;
// 暗号の略語（CBC・GCM・DHE・ADH・SRP）。まれな2文字の並びが多いが、番号のかけらとみなさない（ECDHE-RSA-RC4-SHA を伏せない）
const CRYPTO_WORDS = new Set('aes des ede rc2 rc4 md5 sha cbc gcm ccm rsa dss dhe edh ecdh ecdhe adh aecdh srp psk idea exp null anon seed aria camellia chacha poly ecdsa tls ssl sm2 sm3 sm4 gost'.split(' '));
/** 残してよい英字に数字を付けた語（rc4・md5・sha1・ipv4・win10） */
const stemmedWord = (p: string) => { const m = p.match(STEM_DIGITS); return !!m && MIXED_STEMS.has(m[1].toLowerCase()); };
/**
 * 番号・コードのかけらとして、語として読めないもの：英字と数字が混ざる（K7QX・a1b2。rc4・md5・sha1 のような残してよい語は除く）か、英字4文字以上で
 * まれな2文字の並びが半分以上（ZXCV・ASDF）。英字3文字（pdf・img・MIT）は略語として乱数とみなさない
 */
export const randomPiece = (p: string) => !CRYPTO_WORDS.has(p.toLowerCase()) && (/\d/.test(p) && /[A-Za-z]/.test(p) ? !stemmedWord(p)
  : /^[A-Za-z]{4,}$/.test(p) && rareBigrams(p.toLowerCase()) >= 0.5);
/**
 * 英数字のかけらをつないだコード（招待・パスワードの再設定の QWER-TYUI-ZXCV-ASDF・K7QX-9MZP・7Gk-p2Q-xZ81-m）か。次のどちらか：
 * - 同じ長さ（3〜5文字）のかけら：3つ以上なら半分以上、2つなら両方が乱数のかけら（randomPiece）。数字だけのものは digitRun で見る
 * - 6文字までのかけらで、乱数のかけらが半分以上、うち大文字・小文字・数字の混ざるもの（7Gk・p2Q・xZ81）が2つ以上（長さのそろわないコード）。
 *   大文字と小文字の両方を求めるのは、小文字だけ・大文字だけの英字と数字の語（i18n・a11y・16x16・1080p・ec2・T10・TQ3A・X25519・00Z）は
 *   略語・単位・版・ビルドの名前に多いため（伏せると、ファイル名や User-Agent が読めない）
 */
export const codeGroups = (pieces: string[]): boolean => {
  if (pieces.length < 2 || !pieces.every(p => /^[A-Za-z0-9]{1,6}$/.test(p))) return false;
  const random = pieces.filter(randomPiece);
  if (pieces.every(p => /^[A-Za-z0-9]{3,5}$/.test(p) && p.length === pieces[0].length) && !pieces.every(p => /^\d+$/.test(p))
    && (pieces.length >= 3 ? random.length * 2 >= pieces.length : random.length === pieces.length)) return true;
  return random.length * 2 >= pieces.length && random.filter(p => /\d/.test(p) && /[A-Z]/.test(p) && /[a-z]/.test(p)).length >= 2;
};

/** 英小文字の並びのうち、よく現れる2文字の並びにないものの割合（2文字未満は0）。画面の許可リスト（shownText.ts）も使う */
export function rareBigrams(x: string): number {
  if (x.length < 2) return 0;
  let rare = 0;
  for (let i = 0; i + 1 < x.length; i++) if (!COMMON_BIGRAMS.has(x.slice(i, i + 2))) rare++;
  return rare / (x.length - 1);
}

// ---- 英字の語として読めるか。画面の許可リスト（shownText.ts）と突き合わせのキー（engine/targetKey.ts）で共有する ----
/**
 * 語として残す、英語の読み方の規則に当たらない名前（H-16 の製品名・ヘッダの語 Proxy-Authorization・CherryPy・WebSEAL など）。まれな2文字の並びの
 * 規則を緩めると、3文字のかけらでできた乱数のトークンまで残るので、一覧で持つ
 */
const KNOWN_WORDS = new Set(['proxy', 'web', 'cherrypy', 'webseal', 'zyxel', 'jexus', 'kohana', 'nancy', 'proxmox', 'xmlrpc', 'nginx', 'lighttpd', 'nodejs', 'nextjs', 'nuxtjs', 'webpack', 'fastly', 'varnish', 'wsgi', 'cgi', 'fcgi', 'grpc', 'hsts', 'csrf', 'xsrf', 'jwks', 'jsdelivr', 'cloudflare', 'akamai', 'csrftoken', 'xsrftoken', 'aspnetmvc', 'aspnet', 'azure',
  // よくあるセッション Cookie の名前（大文字だけの13文字以上・6文字以上の略語を含むキャメルケース）。伏せると、どの Cookie の指摘か分からない
  'awselbauthsessioncookie', 'obssocookie', 'jsessionidsso', 'aspxformsauth', 'aspxauth', 'authsessionid', 'cfauthorization', 'awselb', 'awsalb', 'awsalbcors', 'awsalbtg', 'awsalbtgcors']);
/** キャメルケースの2文字の部分として残してよい語（By・Id・Of・My。乱数の Dg・Ng・Xk を残さない）。大文字だけの略語（JS・IO・DB）は別に認める */
const SHORT_WORDS = new Set('of by id to in on at is my no or up if as be do go it me us we ok py'.split(' '));   // Py（CherryPy）
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
 * 英字だけの語が、語として読めるか（48文字まで。KNOWN_WORDS は無条件に読める）：
 * - 大文字だけは12文字まで（SAMEORIGIN・ECDHE）。7文字以上は、まれな2文字の並びが35%未満のもの（乱数の英大文字を残さない）
 * - 小文字だけは24文字までで、乱数のトークン（lowerToken）でなく、まれな2文字の並びが6文字なら6割未満、7〜9文字なら4割未満、10文字以上なら
 *   45%未満（英語の長い語は4割まで。乱数の英小文字は3分の2ほど。短い乱数は6割の基準では4〜5割が残る）
 * - キャメルケースは、部分（Akamai|G|Host・XML|Http|Request）に分けて：2つ目からは大文字で始まる。大文字だけの略語は5文字まで。2文字の部分は
 *   決まった語（By・Id・Of）か略語、1文字の部分は1つまで。部分は4つまで（1文字の部分がなければ7つまで。HttpMessageNotReadableException）。
 *   部分の中のまれな2文字の並びが45%未満（tByYjxuIhbLwqalx・NoDgY のような乱数は、語の数や長さだけでは見分けられない）
 */
export function wordLike(w: string): boolean {
  if (w.length > 48) return false;
  if (KNOWN_WORDS.has(w.toLowerCase())) return true;
  if (/^[A-Z]+$/.test(w)) return w.length <= 12 && !(w.length >= 7 && rareBigrams(w.toLowerCase()) >= 0.35);
  if (/^[a-z]+$/.test(w)) return w.length <= 24 && !lowerToken(w) && !(w.length >= 6 && rareBigrams(w) >= (w.length >= 10 ? 0.45 : w.length >= 7 ? 0.4 : 0.6));
  const parts = w.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+/g) ?? [];
  if (parts.join('') !== w) return false;
  const singles = parts.filter(p => p.length === 1).length;
  return parts.length <= (singles === 0 ? 7 : 4) && singles <= 1
    && parts.every((p, i) => (i === 0 || /^[A-Z]/.test(p)) && !/^[A-Z]{6,}$/.test(p)
      && (p.length !== 2 || SHORT_WORDS.has(p.toLowerCase()) || /^[A-Z]{2}$/.test(p)))
    && partRare(parts) < 0.45;
}
