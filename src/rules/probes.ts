// rules/probes.ts：C13 のプローブ（#PROBE）の判定パターン（ツール設計1「プローブの判定パターン」）。E-03・E-04・E-13 が使う
// 以前は mask.ts にあったが、マスクとは関係がないので分けた（判定に使うだけで、表示・エクスポートにはパターン名だけを出す）

// #PROBE の head は判定にだけ使い、表示・エクスポートにはパターン名だけを出す。
// [パターン名, 判定する項目, 対象パス, 先頭64バイトの目安]（ツール設計1「プローブの判定パターン」）
// パスと中身の両方が一致したときだけ、その項目のルールが使う（1つのプローブを複数の項目で計上しない）
const PROBE_PATTERNS: [string, string, RegExp, RegExp][] = [
  // detached HEAD（CI・デプロイで多い）は、コミットの ID（SHA-1 の40桁、SHA-256 の64桁）だけの1行
  ['git-head',      'E-03', /\/\.git\/HEAD$/,        /^(?:ref: refs\/|[0-9a-f]{40}(?:[0-9a-f]{24})?\s*$)/],
  // 中身のパターンは、エラーページ（JSON・XMLのエラー応答）に一致しないものにする（<?xml だけ、{ だけでは判定しない）
  ['svn-entries',   'E-03', /\/\.svn\/entries$/,     /^\d+\s*$|<wc-entries\b/m],
  // eslint-disable-next-line no-control-regex -- .DS_Store のマジックバイト（00 00 00 01 Bud1）を照合する
  ['ds-store',      'E-03', /\/\.DS_Store$/,         /^\x00\x00\x00\x01Bud1/],
  // export KEY=…（シェルで読み込む形）と、= の前後の空白（KEY = value）も。小文字の名前は、ほかの平文の応答と見分けにくいので入れない
  ['dotenv',        'E-03', /\/\.env$/,              /^(?:export[ \t]+)?[A-Z_][A-Z0-9_]*[ \t]*=/m],
  ['web-xml',       'E-03', /\/WEB-INF\/web\.xml$/,  /<web-app\b|<!DOCTYPE web-app/i],
  // package.json・composer.json は、そのファイルに特有のキーか、名前の形（@scope/名前、vendor/名前）が先頭64バイトにあるときだけ。name・version・
  // type のような一般的なキーだけで一致させると、どのパスにも {"name":"api","version":"1.0"} を返す API で E-03①（高）の誤検知になった。
  // 特有のキーが64バイトより後ろにある本物のファイルは、②（判定保留。中身を手動で確認する）になる
  ['package-json',  'E-03', /\/package\.json$/,      /^\s*\{[\s\S]*?(?:"(?:private|scripts|dependencies|devDependencies|peerDependencies|workspaces|main|module|exports|bin|engines|packageManager)"\s*:|"name"\s*:\s*"@[\w.-]+\/)/],
  ['composer-json', 'E-03', /\/composer\.json$/,     /^\s*\{[\s\S]*?(?:"(?:require|require-dev|autoload|autoload-dev|minimum-stability|prefer-stable|repositories)"\s*:|"name"\s*:\s*"[\w.-]+\/[\w.-]+")/],
  // eslint-disable-next-line no-control-regex -- ZIP のマジックバイト（PK 03 04）を照合する
  ['backup',        'E-03', /\/backup\.zip$/,        /^PK\x03\x04/],
  ['phpinfo',       'E-03', /\/phpinfo\.php$/,       /phpinfo\(\)|PHP Version/],
  ['server-status', 'E-03', /\/server-status$/,      /Apache Server Status|Server Version:/],
  // security.txt はコメント（# で始まる行）から始めてよい（先頭の64バイトがコメントだけのものを「ない」とした）。HTML・JSON のエラー画面は # で始まらない
  // コメントで始まるのは、ファイルの先頭が「#」のときだけ（行の始めの # を見ると、CSS の #app{ を含む HTML の画面まで security.txt とした）
  // 先頭の64バイトに Contact・Expires がなくコメントだけのもの（security-txt-comment）は、本当の security.txt かが分からない（どのパスにも
  // 「# …」の平文を返すサーバもある）ので、E-04 は合格にせず na にする
  // RFC 9116 のフィールドのどれか（Canonical・Policy などで始まり、Contact が64バイトより後ろにあるものを「ない」とした）。
  // フィールド名は大文字・小文字を区別しない（RFC 9116）
  ['security-txt',  'E-04', /\/security\.txt$/,      /^(?:Contact|Expires|Encryption|Acknowledgments|Preferred-Languages|Canonical|Policy|Hiring):/im],
  ['security-txt-comment', 'E-04', /\/security\.txt$/, /(?<![\s\S])#/],
  ['robots',        'E-04', /\/robots\.txt$/,        /^(User-agent|Disallow|Allow|Sitemap):/im],
  // XSSI 対策の前置き（)]}' の行）を付けたソースマップもある（ブラウザの開発ツールは読む。前置きがあると「取得できない」とした）
  // "version":3（ソースマップの版）か、ソースマップに特有のキーがあるときだけ。"version"・"file" だけで一致させると、どのパスにも
  // {"version":"2.1.0"} を返す API で E-13①（中）の誤検知になった
  ['source-map',    'E-13', /\.map$/,                /^(?:\)\]\}'[^\n]*\n)?\s*\{[\s\S]*?(?:"version"\s*:\s*3\b|"(?:sources|sourceRoot|sourcesContent|mappings|names|sections)"\s*:)/]];
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
