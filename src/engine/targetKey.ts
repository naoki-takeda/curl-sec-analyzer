// engine/targetKey.ts：差分・例外の突き合わせのキー（Finding.targetKey）
// 画面・エクスポートに出すマスク（mask.ts）とは別のものとして、ここだけで作る。このファイルは mask.ts を読み込まない
// （tests/properties.test.ts で確かめる）。マスクの一覧を変えるたびにキーが変わり、以前の例外と前回の結果が黙って突き合わなくなったため
// （v0.4.26〜v0.4.30）。キーが守ること（tests/properties.test.ts の性質テスト）：
// - もう一度かけても変わらない（以前の形式のキーを、かけ直して変わるかで見分けるため）
// - 値を持たない（クエリ・フラグメント・ユーザー情報・パス引数の値は、変えてもキーが変わらない）。パスのトークンは * にする
// - 入力の順番で変わらない（クエリのパラメータの順番、同じ名前の値の順番、貼り付けたターゲットの順番）
import type { Target } from '../model';
import { baseLabel } from '../parser/target';
import { lowerToken } from '../tokenShape';

/**
 * 例外と前回の結果の突き合わせに使う URL（HAR の targetKey）。URL の形だけで作る：
 * スキーム・ホスト・パス（トークンらしい部分は *、ASP.NET のセッション (S(…)) は (*)）と、クエリのパラメータの名前だけ（値は持たない）。
 * 値を持たないので秘密は入らず、同じページを記録し直しても変わらない。ユーザー情報とフラグメントは持たない
 */
export function urlKey(raw: string): string {
  if (raw === '*') return '*';   // URL として読めないもののキー（もう一度かけても変わらないように。変わると「/*」になった）
  let u: URL; let relative = false;
  try { u = new URL(raw); } catch {
    try { u = new URL(raw, 'https://relative.invalid'); relative = true; } catch { return '*'; }
  }
  // デコードするが、%2F（エンコードした /）はそのまま残す（Base64 のトークンの / で分けると、後ろのかけらが残る）
  const dec = (s: string) => { try { return decodeURIComponent(s.replace(/%2F/gi, '%252F')); } catch { return s; } };
  const path = u.pathname.split('/').map(seg => {
    // ASP.NET の Cookie を使わないセッション。キーの (*) はそのまま残す（もう一度 urlKey をかけても変わらないように。変わると、この版で出力した
    // 結果まで「以前の形式」と知らせた）
    if (seg === '(*)' || /^\((?:[A-Z]\([^()]*\))+\)$/.test(seg)) return '(*)';
    // パス引数（;jsessionid=…）は名前だけを残す。値はセッションIDのことが多い
    const [head, ...params] = seg.split(';');
    return [keySegment(dec(head)), ...params.map(p => keySegment(dec(p.split('=')[0])))].join(';');
  }).join('/');
  // パラメータは名前だけを並べ替えて持つ。値は、ページ送り（数字）と並べ替え・表示の切り替え（英字の語）の決まった名前のときだけ残す
  // 同じ名前が2回以上あれば、値がすべて同じで残してよいときだけ値を残す（最初の値を残すと、?sort=1&sort=ja と ?sort=ja&sort=1 が別のキーになった）
  const params = new Map<string, string>();
  for (const [n, v] of u.searchParams) {
    const name = keySegment(n); if (!name) continue;   // 名前のないパラメータ（?=x）は持たない（URLSearchParams は「?&q」の空の名前を読まない）
    const keep = (KEY_NUMBER_NAMES.test(n) && /^\d{1,4}$/.test(v)) || (KEY_WORD_NAMES.test(n) && /^[A-Za-z][A-Za-z_-]{0,19}$/.test(v));
    const k = keep ? `${name}=${v}` : name;
    params.set(name, params.has(name) && params.get(name) !== k ? name : k);
  }
  const query = params.size ? `?${[...params.keys()].sort().map(k => params.get(k)).join('&')}` : '';
  if (!relative) return `${u.protocol}//${u.host}${path}${query}`;
  // スキームのない「//ホスト/…」はホストを残す。ほかの相対のパスは、先頭の「//」を1つにする（/.//b のキーが //b になり、もう一度かけると
  // //b をホスト b と読んで「/」になった）
  if (/^\s*[\\/]{2}/.test(raw)) return `//${u.host}${path}${query}`;
  return `${path.replace(/^\/{2,}/, '/')}${query}`;
}

/**
 * キーのパスの部分とパラメータの名前は、残してよい形だけを残す（許可リスト）。部分を - _ . で区切ったかけらのうち、
 * 英字の語（24文字まで。大文字・小文字の入れ替わりは4回まで（AdminDashboard）。大文字だけは10文字まで（API・SAML））、6桁までの数字、
 * 「v2」「x64」のような短い語と数字を残し、それ以外は * にする（続く * は1つにまとめる）。
 * 秘密らしい形を数え上げて伏せる作り（v0.4.29・v0.4.30）は、;jsessionid= の値や、小文字と数字だけのトークン（t2ybctp0…）を見分けられず、
 * JSON のエクスポートと例外ファイルに出した。残す形を決めておけば、トークンがどんな形でもキーには入らない。
 * 別のページが同じキーになることはある（GettingStartedV2Guide と MigrationGuideV3 はどちらも *）が、秘密は漏れない
 */
// 日本語などの ASCII 以外の文字の語（お知らせ・採用情報）も残す（大文字・小文字の入れ替わりは英字と同じく4回まで）。すべて * にすると、別のページが
// 同じキーになり、記録の順番だけで「 #2」が入れ替わって、差分（新規と解消が同時に出る）と例外の対象がずれた。
// 数字は6桁まで（7〜8桁にすると、パスに置いたワンタイムの番号がキーに入り、JSON と例外ファイルに出た）
const keyPiece = (p: string): boolean => {
  if (p === '*' || /^\d{1,6}$/.test(p) || /^[A-Za-z]{1,2}\d{1,2}$/.test(p)) return true;
  // 長音（ー）・踊り字（々）など（\p{Lm}）も語の一部として数える（数えないと、ユーザーデータベースを語が5つとみなして * にした）
  if (/[^\p{ASCII}]/u.test(p)) return /^[\p{L}\p{M}]{1,24}$/u.test(p) && (p.match(/\p{Lu}+|[\p{Ll}\p{Lo}\p{Lm}\p{M}]+/gu) ?? []).length <= 4;
  if (!/^[A-Za-z]{1,24}$/.test(p)) return false;
  // 英小文字だけの16文字以上の乱数のトークン（kqzvwxmplrtb…）は * にする（tokenShape.ts。画面のマスクと同じ規則。12文字にすると、cryptography・
  // strengthening のような実在の語まで * にした）
  if (lowerToken(p)) return false;
  if (/^[A-Z]+$/.test(p)) return p.length <= 10;
  return (p.match(/[a-z]+|[A-Z]+/g) ?? []).length <= 4;
};
const keySegment = (s: string): string => s.replace(/[^-_.~]+/g, piece => (keyPiece(piece) ? piece : '*')).replace(/\*(?:[-_.~]\*)+/g, '*');
/** キーに値を残すパラメータの名前（秘密や個人情報を入れない決まった名前だけ）。数字の値（ページ送り）と英字の語の値（並べ替え・表示の切り替え） */
const KEY_NUMBER_NAMES = /^(?:page|per_page|page_size|pagesize|offset|limit|start)$/i;
const KEY_WORD_NAMES = /^(?:sort|order|orderby|dir|lang|locale|hl|tab|view|mode|type|format|_task)$/i;

/**
 * ターゲットごとのキー（targets と同じ順番）。
 * - HAR：ラベル（har-4 など）は記録し直すと番号が変わるため、「HAR メソッド URL」で突き合わせる
 * - curl：ラベル。同じラベルが複数あれば「元のラベル URL」にする（貼り付けの順番を変えると top と top#2 が入れ替わり、差分と例外がずれるため）
 * キーが重なるターゲットには、2つ目から「 #2」を付ける（重なったままだと、差分で片方の指摘が消え、例外が両方に効く）：
 * - curl の同じラベルで同じ URL（Cookie の有無を変えて2回採取したなど）
 * - HAR で、URL は違うがキーが同じになるもの（値を持たないパラメータの値だけが違う ?q=a と ?q=b）
 * HAR で URL まで同じもの（ポーリングで同じ URL を何度も取得した）には付けない。同じページなので、例外はすべてに効き、記録し直して回数が
 * 変わっても差分がずれない。番号は貼り付け・記録の順番で決まるので、付けるのは見分けられないときだけにする
 */
export function targetKeys(targets: readonly Pick<Target, 'label' | 'url' | 'meta'>[]): string[] {
  // 同じラベルが2つ以上あるラベル（付け直した top#2 があるもの）。付け直しの番号は入力の順番で決まるので、突き合わせには使わない
  const duplicated = new Set(targets.filter(t => /#\d+$/.test(t.label)).map(t => baseLabel(t.label)));
  const keys = targets.map(t => (t.meta.source === 'har' ? `HAR ${t.meta.method ?? 'GET'} ${t.url ? urlKey(t.url) : t.label}`
    : duplicated.has(baseLabel(t.label)) && t.url ? `${baseLabel(t.label)} ${urlKey(t.url)}` : t.label));
  const seenKeys = new Map<string, number>(); const seenUrls = new Map<string, Set<string>>();
  return keys.map((k, i) => {
    const t = targets[i];
    if (k === t.label) return k;
    if (t.meta.source === 'har') {
      const urls = seenUrls.get(k) ?? new Set<string>(); seenUrls.set(k, urls);
      if (urls.has(t.url ?? '')) return k;
      urls.add(t.url ?? '');
    }
    const n = (seenKeys.get(k) ?? 0) + 1; seenKeys.set(k, n);
    return n > 1 ? `${k} #${n}` : k;
  });
}

/**
 * 以前の版の形式のキー。今のキーは urlKey の出力なので、キーの URL の部分にもう一度 urlKey をかけても変わらない。変わるものは以前の形式
 * （v0.4.26〜v0.4.28：伏せた値の「…」やクエリの値、v0.4.29：パス引数の値や並べ替えていない名前、v0.4.30：残す形が違うパスの部分）。
 * 形式ごとに見分けると、パスの部分の伏せ方が変わったキーを見逃し、黙って突き合わなくなった。読み込んだときに件数を知らせる
 */
export function legacyHarKey(k?: string): boolean {
  const m = k?.match(/^(?:HAR \S+|\S+) ((?:https?:\/\/|\/)\S*)/);
  return !!m && urlKey(m[1]) !== m[1];
}
