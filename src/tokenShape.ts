// tokenShape.ts：英小文字だけの乱数のトークンの判定。画面のマスク（mask.ts）と突き合わせのキー（engine/targetKey.ts）で共有する
// （キーはマスクを読み込まない。同じ規則を別々に書くと、片方だけ直して食い違ったため、この小さなファイルだけを両方から読む）

/** 英語でよく現れる2文字の並び。乱数の英小文字では、並びの3分の2ほどがこの一覧にない（英語の語をつないだものでは4分の1以下） */
const COMMON_BIGRAMS = new Set(('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo fs ks ws nk kn yp dy wr sk rp dg nv hy ze zi ka yi').split(' '));

/**
 * 英小文字だけの16文字以上の乱数のトークン（/invite/qwrtzxkpmnbvcdfgh）か。次のどちらか：
 * - 母音（y を含む）が4分の1未満（以前の版の規則。キーを変えないために残す）
 * - よく現れる2文字の並びにないものが35%以上（乱数の16〜24文字の約98%。英語の語をつないだもの（healthcheckstatus・nightschoolprograms・
 *   internationalization）は24%以下なので残る。母音の割合と子音の続きで見ると、これらの語まで伏せて、例外のキーを変えた）
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
