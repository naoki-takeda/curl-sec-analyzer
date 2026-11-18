// messagesEn.ts：画面に出すエラーメッセージ（設定ファイルの読み込み、コマンド生成器の入力）の英訳
// キーは engine/suppress.ts・engine/profile.ts・engine/diff.ts・commands.ts が返す日本語の文言。新しい文言を足したら、ここにも足す
// （tests/i18n.test.ts が、不正な入力で出るメッセージに日本語が残らないことを確かめる）
const EXACT: Record<string, string> = {
  'JSONとして読めません': 'The file is not valid JSON',
  '配列、または suppressions を持つオブジェクトが必要です': 'Expected an array, or an object with a suppressions array',
  'オブジェクトが必要です': 'Expected a JSON object',
  'このツールでエクスポートしたJSONを選んでください（findings がありません）': 'Choose a JSON file exported by this tool (it has no findings)',
  'exclude：項目ID（例：H-17）の配列にしてください': 'exclude: use an array of check IDs (such as H-17)',
  'trustedScriptOrigins：https://cdn.example.com や *.example.com の形の配列にしてください': 'trustedScriptOrigins: use an array of origins such as https://cdn.example.com or *.example.com',
  'sessionCookieNames：Cookie名（英数字と記号）の配列にしてください': 'sessionCookieNames: use an array of cookie names (letters, digits and symbols)',
  'severity：項目ID（例：H-10）と重要度の組のオブジェクトにしてください': 'severity: use an object that maps check IDs (such as H-10) to severities',
  'sessionMaxAgeHours は 1 以上 9600 以下の時間数にしてください（既定の24時間を使います）':'sessionMaxAgeHours must be a number of hours from 1 to 9600 (the default of 24 hours is used)',
  'ホスト名は英数字・ハイフン・ドット（必要なら :ポート）だけで書いてください': 'Use only letters, digits, hyphens and dots in the host name (plus :port if needed)',
  'apexドメインの書き方が正しくありません': 'The apex domain is not valid',
};
const FIELD: Record<string, string> = { API: 'API', ログイン: 'Login', 認証後ページ: 'Page after login', ログアウト: 'Logout', 静的リソース: 'Static resource', WebSocket: 'WebSocket' };
const PATTERNS: [RegExp, (m: RegExpMatchArray) => string][] = [
  [/^(\d+)件目：ruleId が不正です$/, m => `Entry ${m[1]}: invalid ruleId`],
  [/^例外は(\d+)件までです（(\d+)件のうち、(\d+)件目からは読みません）$/, m => `At most ${m[1]} exceptions are read (the file has ${m[2]}; entries from ${m[3]} on are ignored)`],
  [/^(\d+)件目：target がありません$/, m => `Entry ${m[1]}: target is missing`],
  [/^(\d+)件目：target が長すぎます（(\d+)文字まで）$/, m => `Entry ${m[1]}: target is too long (${m[2]} characters at most)`],
  [/^(\d+)件目：reason（理由）がありません$/, m => `Entry ${m[1]}: reason is missing`],
  [/^(\d+)件目：approver は文字列で書きます$/, m => `Entry ${m[1]}: approver must be a string`],
  [/^(\d+)件目：until は YYYY-MM-DD で書きます$/, m => `Entry ${m[1]}: until must be YYYY-MM-DD`],
  [/^「(.*)」は組織プロファイルの項目ではありません$/s, m => `"${m[1]}" is not a profile setting`],
  [/^severity：「(.*)」は項目IDではありません$/s,m => `severity: "${m[1]}" is not a check ID`],
  [/^severity：「(.*)」の重要度は high・medium・low・info のいずれか$/s, m => `severity: the severity for "${m[1]}" must be high, medium, low or info`],
  [/^(.+)のパスは \/ で始まる英数字と - \. _ ~ % \/ で書いてください$/, m => `${FIELD[m[1]] ?? m[1]} path: start with / and use only letters, digits and - . _ ~ % /`],
];

export function messageEn(ja: string): string {
  if (EXACT[ja]) return EXACT[ja];
  for (const [re, f] of PATTERNS) { const m = ja.match(re); if (m) return f(m); }
  return ja;
}

/** エラーの一覧を画面の言語でつなぐ */
export const joinMessages = (list: string[], lang: string) => (lang === 'en' ? list.map(messageEn).join('; ') : list.join('、'));
