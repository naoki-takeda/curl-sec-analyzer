// tokenShape.ts：乱数のトークンと英字の語の形の判定。画面のマスク（mask.ts）・許可リスト（shownText.ts）と突き合わせのキー（engine/targetKey.ts）で
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
