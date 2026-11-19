// rules/probes.ts：C13 のプローブ（#PROBE）の判定パターン（ツール設計1「プローブの判定パターン」）。E-03・E-04・E-13 が使う

// #PROBE の head は判定にだけ使い、表示・エクスポートにはパターン名だけを出す。
// 採る長さは生成スクリプトが決める（目印が後ろにあるテキストの形式は4KB、server-status は1KB、ほかは64バイト。commands.ts の C13）。
// 長く採るほどほかの応答の中の語に一致しやすいので、中身の目安はファイルの先頭に固定するか、そのファイルの決まった形に絞る

/** UTF-8 の BOM（latin1 で読んだもの）と空白のあとの先頭 */
const START = String.raw`^(?:\xEF\xBB\xBF)?\s*`;
/** HTML の画面の始まり（<!doctype html・<html・<head・<body）。<!-- は含めない（web.xml は使用許諾のコメントで始まることがある） */
const HTML_START = new RegExp(`${START}<(?:!doctype\\s+html|html|head|body)\\b`, 'i');

/**
 * JSON のオブジェクトの最上位のキーと、その値が文字列ならその値（それ以外は空）。切れた先頭でも読めたところまで。入れ子の中のキー
 * （API の応答の "data":{"main":…}）は数えない。文字列と括弧を1回ずつ読むだけなので線形時間
 */
function topLevelKeys(head: string): Map<string, string> | undefined {
  const open = new RegExp(`${START}\\{`).exec(head);
  if (!open) return undefined;
  const out = new Map<string, string>(); const n = head.length;
  let i = open[0].length, depth = 1;
  const str = (): string | undefined => {         // head[i] は " 。閉じれば次の位置に進めて中身を返す。切れていれば undefined
    let s = ''; i++;
    while (i < n) { const c = head[i]; if (c === '\\') { s += head[i + 1] ?? ''; i += 2; } else if (c === '"') { i++; return s; } else { s += c; i++; } }
    return undefined;
  };
  const ws = () => { while (i < n && /\s/.test(head[i])) i++; };
  while (i < n && depth > 0) {
    const c = head[i];
    if (c === '"') {
      const k = str(); if (k === undefined) break;
      if (depth !== 1) continue;
      ws(); if (head[i] !== ':') continue;
      i++; ws();
      let v = '';
      if (head[i] === '"') { const s = str(); if (s === undefined) { out.set(k, ''); break; } v = s; }
      out.set(k, v);
      continue;
    }
    if (c === '{' || c === '[') depth++; else if (c === '}' || c === ']') depth--;
    i++;
  }
  return out;
}
/**
 * 最上位にそのファイルに特有のキーがあるか、name の値が決まった形か。汎用の語のキー（package.json の main・module・exports・bin）は、
 * name か version と組のときだけ数える（どのパスにも {"module":"auth","error":…} を返す API に一致させない）
 */
const jsonFile = (keys: RegExp, name: RegExp, generic?: RegExp) => (head: string) => {
  const m = topLevelKeys(head);
  if (!m) return false;
  const ks = [...m.keys()];
  return ks.some(k => keys.test(k)) || name.test(m.get('name') ?? '') || (!!generic && ks.some(k => generic.test(k)) && (m.has('name') || m.has('version')));
};

type Content = RegExp | ((head: string) => boolean);
// [パターン名, 判定する項目, 対象パス, 中身の目安]。パスと中身の両方が一致したときだけ、その項目のルールが使う（1つのプローブを複数の項目で計上しない）
const PROBE_PATTERNS: [string, string, RegExp, Content][] = [
  // detached HEAD（CI・デプロイで多い）は、コミットの ID（SHA-1 の40桁、SHA-256 の64桁）だけの1行
  ['git-head',      'E-03', /\/\.git\/HEAD$/,        /^(?:ref: refs\/|[0-9a-f]{40}(?:[0-9a-f]{24})?\s*$)/],
  // 中身のパターンは、エラーページ（JSON・XMLのエラー応答）に一致しないものにする（<?xml だけ、{ だけでは判定しない）
  ['svn-entries',   'E-03', /\/\.svn\/entries$/,     /^\d+\s*$|<wc-entries\b/m],
  // eslint-disable-next-line no-control-regex -- .DS_Store のマジックバイト（00 00 00 01 Bud1）を照合する
  ['ds-store',      'E-03', /\/\.DS_Store$/,         /^\x00\x00\x00\x01Bud1/],
  // export KEY=…（シェルで読み込む形）と、= の前後の空白（KEY = value）も。小文字の名前は、ほかの平文の応答と見分けにくいので入れない
  ['dotenv',        'E-03', /\/\.env$/,              /^(?:export[ \t]+)?[A-Z_][A-Z0-9_]*[ \t]*=/m],
  // ファイルの先頭（XML 宣言などの処理命令と、使用許諾などのコメントのあと）の <web-app>（名前空間の接頭辞 <j:web-app> も）か DOCTYPE だけ
  // （本文の途中のカスタム要素 <web-app> に一致させない）。処理命令は <? から > までを1つの並び（[^>]*）で、コメントの中身は --> を含まない並びで
  // 読む（区切り方が1通りに決まり、閉じないものでも線形時間。処理命令の名前を [\w-]+\b で分けると、名前の - の位置ごとに分け方ができて指数的に増える）
  ['web-xml',       'E-03', /\/WEB-INF\/web\.xml$/,  new RegExp(`${START}(?:<\\?[^>]*>\\s*|<!--(?:(?!-->)[\\s\\S])*-->\\s*)*(?:<!DOCTYPE\\s+web-app\\b|<(?:[\\w-]+:)?web-app\\b)`, 'i')],
  // package.json・composer.json は、最上位にそのファイルに特有のキーがあるか、名前の形（@scope/名前、vendor/名前）のときだけ。
  // name・version だけでは、どのパスにも {"name":"api","version":"1.0"} を返す API と区別できない。入れ子の中のキー（"data":{"main":…}）は数えない。
  // 特有のキーが採った先頭より後ろにある本物のファイルは、②（判定保留。中身を手動で確認する）になる
  ['package-json',  'E-03', /\/package\.json$/,      jsonFile(/^(?:private|scripts|dependencies|devDependencies|peerDependencies|workspaces|engines|packageManager)$/, /^@[\w.-]+\//, /^(?:main|module|exports|bin)$/)],
  ['composer-json', 'E-03', /\/composer\.json$/,     jsonFile(/^(?:require|require-dev|autoload|autoload-dev|minimum-stability|prefer-stable|repositories)$/, /^[\w.-]+\/[\w.-]+$/)],
  // eslint-disable-next-line no-control-regex -- ZIP のマジックバイト（PK 03 04）を照合する
  ['backup',        'E-03', /\/backup\.zip$/,        /^PK\x03\x04/],
  // phpinfo() の出力の決まった形だけ（title の「… phpinfo()」、見出しの <h1 class="p">PHP Version、CLI の形の「phpinfo()」の行と「PHP Version =>」）。
  // 「PHP Version」の語だけでは、記事の「Requires PHP Version 8.1」に一致する
  ['phpinfo',       'E-03', /\/phpinfo\.php$/,       /<title>[^<]{0,60}phpinfo\(\)\s*<\/title>|<h1 class="p">PHP Version |^phpinfo\(\)\r?\nPHP Version =>/m],
  // mod_status の見出しと、サーバの版の項目の形だけ
  ['server-status', 'E-03', /\/server-status$/,      /<h1>Apache Server Status for |<dt>Server Version: /],
  // security.txt は、RFC 9116 のフィールドのどれか（大文字・小文字を区別しない）が採った先頭の行の始めにあるもの。
  // Canonical・Policy などで始まり、Contact が後ろにあるものもある。
  // コメント（#）で始めてもよいが、コメントだけのもの（security-txt-comment）は本当の security.txt かが分からない（どのパスにも
  // 「# …」の平文を返すサーバもある）ので、E-04 は na にする。見るのはファイルの先頭の # だけ（行の始めの # では、CSS の #app{ を含む HTML に一致する）
  ['security-txt',  'E-04', /\/security\.txt$/,      /^(?:Contact|Expires|Encryption|Acknowledgments|Preferred-Languages|Canonical|Policy|Hiring):/im],
  ['security-txt-comment', 'E-04', /\/security\.txt$/, /^#/],
  // XSSI 対策の前置き（)]}' の行）を付けたソースマップも認める（ブラウザの開発ツールは読む）。
  // "version":3 か、ソースマップに特有のキーがあるときだけ（"version"・"file" だけでは、どのパスにも {"version":"2.1.0"} を返す API と区別できない）
  ['source-map',    'E-13', /\.map$/,                /^(?:\)\]\}'[^\n]*\n)?\s*\{[\s\S]*?(?:"version"\s*:\s*3\b|"(?:sources|sourceRoot|sourcesContent|mappings|names|sections)"\s*:)/]];

/** 本物も HTML の画面のパス（HTML が返っても、そのファイルでないとは言えない） */
export const HTML_PROBE_PATHS = /\/(?:phpinfo\.php|server-status)$/;
const decode = (headB64: string): string | undefined => { try { return atob(headB64); } catch { return undefined; } };
/**
 * 中身が HTML の画面か。どのパスにも index.html を返す SPA や共通のエラー画面で、HTML でない形式のファイル（.env・.git/HEAD・backup.zip
 * など）のパスに HTML が返ったら、そのファイルではない
 */
export function htmlProbe(headB64: string): boolean {
  const head = decode(headB64);
  return head !== undefined && HTML_START.test(head);
}
/**
 * プローブのパスと中身が既知のファイルに一致するか。取得できた（HTTP 2xx の）ときだけ一致とする。
 * 404・403 のエラーページの中身（JSON・XML）がパターンに一致しても、そのファイルを取得できたことにはならない。
 * HTML の画面は、本物も HTML のパス（phpinfo・server-status）のほかは、どのパターンにも一致としない（画面の中の語・要素に一致させない）
 */
export function probePattern(path: string, headB64: string, code: number): { name: string; item: string } | undefined {
  if (!(code >= 200 && code < 300)) return undefined;
  const head = decode(headB64);
  if (head === undefined || (!HTML_PROBE_PATHS.test(path) && HTML_START.test(head))) return undefined;
  const hit = PROBE_PATTERNS.find(([, , p, c]) => p.test(path) && (typeof c === 'function' ? c(head) : c.test(head)));
  return hit && { name: hit[0], item: hit[1] };
}
