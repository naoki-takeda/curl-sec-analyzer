// i18n.ts：画面の文言（日本語と英語）。推奨対応の英訳は recommendationsEn.ts。判定の証跡と解析警告は日本語のみ
import type { CoverageStatus, Severity, Status } from './model';
import type { DiffKind } from './engine/diff';
import { ITEMS } from './engine/coverage';

export type Lang = 'ja' | 'en';
let lang: Lang = 'ja';
export const getLang = () => lang;
export function setLang(l: Lang) {
  l = l === 'en' ? 'en' : 'ja';                       // 想定外の値でも文言の表を引けるようにする
  lang = l; document.documentElement.lang = l;
  document.title = l === 'en' ? 'curl-sec-analyzer: check web security settings from curl output' : 'curl-sec-analyzer：curlの出力でWebセキュリティ設定を判定';
}

const ja = {
  tagline: 'curl と openssl の出力、またはブラウザの HAR を読み込むと、HTTPヘッダ・Cookie・CORS・リダイレクト・TLS・APIの設定を判定します。',
  notice1: '入力はこのページの外に送信されません（通信を禁止するCSPを設定しています）。',
  notice2: '診断は、自社で管理しているシステムか、書面で許可を得たシステムだけを対象にしてください。',
  notice3: '判定できるのは設定の一部です。合格でも、安全であることの保証にはなりません。',
  versions: (t: string, r: string) => `ツール ${t}／ルールセット ${r}`,
  langSwitch: 'English', license: 'ライセンス（MIT）', thirdParty: '第三者のライセンス',
  inputLabel: 'curlの出力', urlLabel: '#TARGET がない入力のURL（任意）',
  analyze: '判定する', openFile: 'ファイルを開く', sample: 'サンプルを入れる', clear: '消去',
  maskNote: 'Cookie・Authorization・トークンの値と、既知ファイルの中身は、画面とエクスポートでマスクします。読み込んだ出力ファイルやHARは、使い終わったら削除してください。',
  settings: '設定ファイル', loadSuppressions: '例外ファイルを読み込む', loadProfile: '組織プロファイルを読み込む', profileTemplate: 'プロファイルのひな形',
  loadBaseline: '前回の結果（JSON）を読み込む',
  noSuppressions: '例外の登録はありません', suppressionsStatus: (n: number, a: number) => `例外 ${n}件（有効 ${a}件、期限切れ ${n - a}件）`,
  noProfile: '組織プロファイル：なし（既定の重要度）', profileStatus: (name: string) => `組織プロファイル：${name || '（名前なし）'}`,
  noBaseline: '前回の結果：なし', baselineSkipped: (n: number) => `前回の結果のうち${n}件は、形式が正しくないため除外しました（このツールでエクスポートしたJSONを使ってください）。`, baselineStatus: (at: string) => `前回の結果：${at || '日時不明'}`,
  emptyInput: 'curlの出力を貼り付けてから「判定する」を押してください。', tooLarge: '入力が大きすぎます（上限5MB）。',
  fileTooLarge: 'ファイルが大きすぎます（上限5MB）。ターゲットを分けて読み込んでください。',
  noResponse: 'HTTPの応答が見つかりませんでした。curl に -i、-D -、-v のいずれかを付けて実行した出力を貼り付けてください。',
  emptyTitle: 'まだ判定していません',
  emptySteps: ['「コマンドを作る」で、対象のホスト名とパスから採取用のスクリプトを作る', '自分の端末でスクリプトを実行し、out.txt を作る（ログインにはテスト用アカウントを使う）', 'out.txt を左に貼り付けるか「ファイルを開く」で読み込み、「判定する」を押す'],
  openGenerator: 'コマンドの生成へ', trySample: 'サンプルで試す', emptyHave: 'curl の出力やブラウザの HAR がすでにあれば、そのまま貼り付けるか読み込んでください。',
  inputHidden: (n: number) => `貼り付けた出力（${n}行）は隠しています。パスワードやCookieが含まれるため、画面共有やスクリーンショットに注意してください。`,
  showInput: '入力を表示する', hideInput: '入力を隠す', confirmReplace: '貼り付けた内容をサンプルで置き換えます。よろしいですか？',
  showInfo: (n: number) => `「情報」の${n}件も表示`, hideInfo: '「情報」を隠す',
  emptyBody: '左に curl の出力を貼り付けて「判定する」を押します。形式を試すには「サンプルを入れる」を押してください。',
  emptyHint: '1つの貼り付けに複数の応答を入れるときは、各応答の前に #TARGET url=… label=… の行を置きます。label で適用する項目が決まります（例：login、logout、cors-…、http、apex、probes、tls）。認証後のページには sensitive=1 を付けます。',
  severity: (s: string) => `重要度「${s}」`, save: '保存（マスク済み）：', csv: 'CSV（第8章の様式）', suppressionsFile: '例外ファイル',
  warnings: '解析の警告', findings: '指摘（項目×条件）', count: (n: number) => `${n}件`, countHidden: (n: number, i: number) => `${n}件（うち「情報」${i}件は非表示）`, allChapters: 'すべての章', filterChapter: '章で絞り込む',
  chapters: ['HTTPレスポンスヘッダ', 'Cookie', 'CORS', 'メソッド・通信・TLS', 'エラー・情報露出', 'WebAPI'],
  chapter: (i: number, name: string) => `第${i}章 ${name}`,
  noFindings: '指摘はありませんでした。判定できた範囲での結果です（下の「診断カバレッジ」で判定していない項目を確認してください）。', noFindingsInChapter: 'この章の指摘はありません。',
  tables: { findings: '指摘の一覧', targets: 'ターゲットの一覧', target: (l: string) => `ターゲット「${l}」の判定`, diff: '前回との差分の一覧', coverage: '診断カバレッジの一覧', har: 'HARのエントリの一覧' },
  cols: { actions: '操作', severity: '重要度', item: '項目', title: '内容', targets: '該当ターゲット', label: 'ラベル', url: 'URL', kind: '種類', sensitive: '機密', status: '判定', evidence: '証跡（マスク済み）', recommendation: '推奨対応', reason: '理由・必要な入力', category: '区分', change: '変化', target: 'ターゲット' },
  perTarget: 'ターゲットごとの結果', showAll: '合格・判定不能・例外も表示', showFails: '指摘だけを表示',
  kinds: { html: 'HTML', api: 'API', other: 'その他' }, unknown: '不明', yes: 'はい', no: 'いいえ', urlUnknown: 'URL不明', noResp: '応答なし',
  nothingToShow: '表示する指摘はありません。', crossTitle: 'ホスト単位・ターゲット横断の判定',
  suppressedNote: (r: string, a: string, u: string) => `例外：${r}（${a || '承認者なし'}、${u || '期限なし'}）`, addSuppression: '例外に登録',
  profileChanged: (from: string) => `プロファイルで変更（元：${from}）`,
  coverage: '診断カバレッジ', coverageRate: (e: number, d: number, ni: number, m: number) => `${e} / ${d} 項目を判定（未対応 ${ni} 項目、手動確認 ${m} 項目）`,
  coverageNote: '「入力不足」の項目は、必要なラベルのターゲットを追加して採取すると判定できます。率が高くても、安全であることの保証にはなりません。項目名に添えた ASVS（OWASP ASVS 5.0.0）と IPA（安全なウェブサイトの作り方 改訂第7版）の番号は関連する要件で、その要件を満たすかどうかの判定ではありません。',
  allCategories: 'すべての区分', filterCategory: '区分で絞り込む', manualNote: '第8章の様式に記録する', command: 'コマンド',
  outOfScope: '範囲外（第7章）：認可・業務ロジック、入力値の処理（XSS・SQLインジェクションなど）、ログ・監視などは、OWASP ZAP や Burp Suite、ソースコードレビューで確認します。',
  diff: '前回との差分', diffSummary: (n: number, r: number, s: number, sup: number, nr: number, c: number) => `新規 ${n}件、解消 ${r}件、重要度の変化 ${s}件、例外登録 ${sup}件、再診断していない ${nr}件、継続 ${c}件`,
  diffNote: '「再診断していない」は、前回の指摘のうち今回の入力で同じターゲット・項目を判定していないものです。「例外登録」は、今回は例外を適用した指摘で、解消には数えません。curl はラベルで、HAR はメソッドとURLで突き合わせます。',
  diffProfileWarning: '前回と今回で組織プロファイルが違います。「重要度の変化」や「解消」には、設定の違いによるものが含まれます。',
  diffRulesetWarning: (a: string, b: string) => `前回（ルールセット ${a}）と今回（${b}）でルールセットの版が違います。ルールの追加・変更による差分が含まれます。`,
  missingPair: (a: string, b: string, item: string) => `「${a}」はありますが「${b}」がありません。横断ルール（${item}）を判定できません。`,
  preloadNoApex: 'HSTS に preload がありますが「apex」ラベルのターゲットがありません（H-02③）。',
  englishNote: '',
  dlg: { title: '例外に登録', scope: '範囲', onlyCond: (x: string) => `この条件だけ（${x}）`, wholeItem: (x: string) => `この項目すべて（${x}）`, reason: '理由（必須）', approver: '承認者', until: '期限', needReason: '理由を入力してください。', save: '登録する', cancel: 'やめる', note: (t: string, target: string) => `${t}（対象：${target}）。登録した例外は「例外ファイル」で保存し、次回は読み込んで使います。` },
  gen: { title: 'コマンドを作る（推奨コマンド C1〜C26）', note: 'ホスト名とパスを入れると、#TARGET 付きのコマンドを作ります。実行は自分の端末で行い、出力（out.txt）をここに貼り付けます。ログインには login.txt（POST本文）を用意してください。',
    fields: { host: 'ホスト名', apex: 'apexドメイン（任意）', apiPath: '機密のAPI', loginPath: 'ログイン', mypagePath: '認証後のページ', logoutPath: 'ログアウト', staticPath: '静的リソース（JS）', wsPath: 'WebSocket（任意）' } as Record<string, string>,
    danger: '検証環境でだけ行う試験（CRLF、メソッド上書き、送信元の偽装、Content-Type）も含める。DELETE など、データを消しうる試験は生成しません', make: 'コマンドを作る', copy: 'コピー', saveSh: 'run.sh として保存',
    copied: 'コピーしました。', copyFailed: 'コピーできませんでした。選択した状態にしたので、手動でコピーしてください。', output: '生成したコマンド' },
  har: { loading: 'HARを読み込んでいます…', tooLarge: 'HARが大きすぎます（上限50MB）。対象の操作だけを記録して書き出してください。', failed: (e: string) => `HARを読み込めませんでした（${e}）。`, invalidJson: 'JSONの形式が正しくありません',
    loaded: (name: string, n: number) => `HAR（${name}）から ${n}件のリクエストを読み込みました。対象ホストとラベルを確認して「判定する」を押してください。読み込んだHARファイルは、使い終わったら削除してください。`,
    title: (name: string) => `HARのエントリ一覧（${name}）`, note: 'ラベルはリダイレクトをまとめた単位で付けます。after-logout・session-sample・CORS・TLS・既知ファイルなど細工したリクエストが必要な項目は、curl で別に採取してください。',
    sanitized: 'Cookie・Set-Cookie が含まれていません。ブラウザの設定で機密情報を含めて書き出すと、Cookie の項目も判定できます。', hosts: '対象ホスト：', remove: 'HARを外す', exclude: '除外',
    method: 'メソッド', status: 'ステータス', hops: (n: number) => `（${n}ホップ）`, labelFor: (m: string, u: string) => `${m} ${u} のラベル`, sensFor: (u: string) => `${u} の機密区分`, auto: (y: boolean): string => (y ? '自動（はい）' : '自動（不明）') },
  readErrors: (what: string, e: string) => `${what}の一部を読み込めませんでした：${e}`,
};
type Dict = typeof ja;

const en: Dict = {
  tagline: 'Load curl and openssl output, or a browser HAR file, to check HTTP headers, cookies, CORS, redirects, TLS and API settings.',
  notice1: 'Nothing you load leaves this page (a CSP blocks all network connections).',
  notice2: 'Only test systems you manage or have written permission to test.',
  notice3: 'This tool checks a subset of settings. A pass does not mean the system is secure.',
  versions: (t, r) => `Tool ${t} / Ruleset ${r}`,
  langSwitch: '日本語', license: 'License (MIT)', thirdParty: 'Third-party licenses',
  inputLabel: 'curl output', urlLabel: 'URL for input without #TARGET (optional)',
  analyze: 'Analyze', openFile: 'Open file', sample: 'Load sample', clear: 'Clear',
  maskNote: 'Cookie, Authorization and token values and the contents of known files are masked on screen and in exports. Delete output files and HAR files when you are done.',
  settings: 'Settings files', loadSuppressions: 'Load exceptions', loadProfile: 'Load organization profile', profileTemplate: 'Profile template',
  loadBaseline: 'Load previous results (JSON)',
  noSuppressions: 'No exceptions', suppressionsStatus: (n, a) => `${n} exceptions (${a} active, ${n - a} expired)`,
  noProfile: 'Organization profile: none (default severities)', profileStatus: name => `Organization profile: ${name || '(unnamed)'}`,
  noBaseline: 'Previous results: none', baselineSkipped: n => `${n} of the previous findings were skipped because their format is invalid (use JSON exported by this tool).`, baselineStatus: at => `Previous results: ${at || 'date unknown'}`,
  emptyInput: 'Paste curl output, then select Analyze.', tooLarge: 'The input is too large (5 MB limit).',
  fileTooLarge: 'The file is too large (5 MB limit). Split it by target.',
  noResponse: 'No HTTP response found. Paste output from curl run with -i, -D - or -v.',
  emptyTitle: 'Nothing analyzed yet',
  emptySteps: ['Build a capture script from the host name and paths with “Build commands”', 'Run the script on your own machine to create out.txt (use a test account for login)', 'Paste out.txt on the left or load it with “Open file”, then select Analyze'],
  openGenerator: 'Go to command builder', trySample: 'Try the sample', emptyHave: 'If you already have curl output or a browser HAR file, paste or load it directly.',
  inputHidden: n => `Your pasted output (${n} lines) is hidden. It contains passwords and cookies, so take care when sharing your screen or taking screenshots.`,
  showInput: 'Show input', hideInput: 'Hide input', confirmReplace: 'Replace your pasted content with the sample?',
  showInfo: n => `Show ${n} info findings`, hideInfo: 'Hide info findings',
  emptyBody: 'Paste curl output on the left and select Analyze. To see the format, select Load sample.',
  emptyHint: 'To include several responses, put a #TARGET url=… label=… line before each one. The label decides which checks apply (for example login, logout, cors-…, http, apex, probes, tls). Add sensitive=1 to pages behind login.',
  severity: s => `${s} severity`, save: 'Save (masked):', csv: 'CSV (record format)', suppressionsFile: 'Exceptions file',
  warnings: 'Parsing warnings', findings: 'Findings (check × condition)', count: n => `${n}`, countHidden: (n, i) => `${n} (${i} info hidden)`, allChapters: 'All chapters', filterChapter: 'Filter by chapter',
  chapters: ['HTTP response headers', 'Cookies', 'CORS', 'Methods, transport and TLS', 'Errors and information exposure', 'Web APIs'],
  chapter: (i, name) => `Ch. ${i} ${name}`,
  noFindings: 'No findings within what could be checked. See Coverage below for checks that were not run.', noFindingsInChapter: 'No findings in this chapter.',
  tables: { findings: 'Findings', targets: 'Targets', target: l => `Results for target ${l}`, diff: 'Changes since previous results', coverage: 'Coverage', har: 'HAR entries' },
  cols: { actions: 'Actions', severity: 'Severity', item: 'Check', title: 'Description', targets: 'Targets', label: 'Label', url: 'URL', kind: 'Type', sensitive: 'Sensitive', status: 'Result', evidence: 'Evidence (masked)', recommendation: 'Recommendation', reason: 'Reason / input needed', category: 'Status', change: 'Change', target: 'Target' },
  perTarget: 'Results by target', showAll: 'Show passes, N/A and exceptions', showFails: 'Show findings only',
  kinds: { html: 'HTML', api: 'API', other: 'Other' }, unknown: 'Unknown', yes: 'Yes', no: 'No', urlUnknown: 'URL unknown', noResp: 'No response',
  nothingToShow: 'Nothing to show.', crossTitle: 'Host-level and cross-target checks',
  suppressedNote: (r, a, u) => `Exception: ${r} (${a || 'no approver'}, ${u || 'no expiry'})`, addSuppression: 'Add exception',
  profileChanged: from => `Changed by profile (was ${from})`,
  coverage: 'Coverage', coverageRate: (e, d, ni, m) => `${e} of ${d} checks run (${ni} not implemented, ${m} manual)`,
  coverageNote: 'Checks marked “Missing input” run once you capture a target with the label shown. High coverage does not mean the system is secure. The ASVS (OWASP ASVS 5.0.0) and IPA (IPA “How to Secure Your Web Site”, 7th ed.) numbers next to each check are related requirements, not a verdict on whether the requirement is met.',
  allCategories: 'All statuses', filterCategory: 'Filter by status', manualNote: 'Record in the test record sheet', command: 'command',
  outOfScope: 'Out of scope (Ch. 7): authorization and business logic, input handling (XSS, SQL injection, etc.), logging and monitoring. Check these with OWASP ZAP, Burp Suite or code review.',
  diff: 'Changes since previous results', diffSummary: (n, r, s, sup, nr, c) => `${n} new, ${r} resolved, ${s} severity changed, ${sup} exception registered, ${nr} not rechecked, ${c} unchanged`,
  diffNote: '“Not rechecked” means the previous finding’s target and check were not evaluated this time. “Exception registered” means an exception now applies to the finding; it is not counted as resolved. curl targets are matched by label, HAR targets by method and URL.',
  diffProfileWarning: 'The organization profile differs from the previous run, so some severity changes or resolutions come from the settings, not the system.',
  diffRulesetWarning: (a, b) => `The previous results used ruleset ${a}; this run uses ${b}. Some changes come from added or changed rules.`,
  missingPair: (a, b, item) => `Label “${a}” is present but “${b}” is missing, so ${item} cannot be checked.`,
  preloadNoApex: 'HSTS includes preload, but there is no target with the “apex” label (H-02③).',
  englishNote: 'Evidence is currently shown in Japanese. Recommendations are in English.',
  dlg: { title: 'Add exception', scope: 'Scope', onlyCond: x => `This condition only (${x})`, wholeItem: x => `Whole check (${x})`, reason: 'Reason (required)', approver: 'Approver', until: 'Expires', needReason: 'Enter a reason.', save: 'Add exception', cancel: 'Cancel', note: (t, target) => `${t} (target: ${target}). Save exceptions with “Exceptions file” and load them next time.` },
  gen: { title: 'Build commands (recommended commands C1–C26)', note: 'Enter a host name and paths to build commands with #TARGET lines. Run them on your own machine and paste the output (out.txt) here. Prepare login.txt (the login POST body) first.',
    fields: { host: 'Host name', apex: 'Apex domain (optional)', apiPath: 'Sensitive API', loginPath: 'Login', mypagePath: 'Page behind login', logoutPath: 'Logout', staticPath: 'Static resource (JS)', wsPath: 'WebSocket path (optional)' },
    danger: 'Include tests for test environments only (CRLF, method override, IP spoofing, Content-Type). Tests that may delete data, such as DELETE, are never generated', make: 'Build commands', copy: 'Copy', saveSh: 'Save as run.sh',
    copied: 'Copied.', copyFailed: 'Could not copy. The text is selected so you can copy it manually.', output: 'Generated commands' },
  har: { loading: 'Loading HAR…', tooLarge: 'The HAR file is too large (50 MB limit). Record only the steps you need.', failed: e => `Could not load the HAR file (${e}).`, invalidJson: 'invalid JSON',
    loaded: (name, n) => `Loaded ${n} requests from ${name}. Check the hosts and labels, then select Analyze. Delete the HAR file when you are done.`,
    title: name => `HAR entries (${name})`, note: 'Labels apply to each redirect chain. Capture after-logout, session samples, CORS, TLS and known files separately with curl.',
    sanitized: 'This HAR has no Cookie or Set-Cookie headers. Export it with sensitive data included to check cookies.', hosts: 'Hosts:', remove: 'Remove HAR', exclude: 'Exclude',
    method: 'Method', status: 'Status', hops: n => ` (${n} hops)`, labelFor: (m, u) => `Label for ${m} ${u}`, sensFor: u => `Sensitivity for ${u}`, auto: y => (y ? 'Auto (yes)' : 'Auto (unknown)') },
  readErrors: (what, e) => `Part of the ${what} could not be loaded: ${e}`,
};

export const tr = (): Dict => (lang === 'en' ? en : ja);

const SEV = { ja: { high: '高', medium: '中', low: '低', info: '情報' }, en: { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } };
const STATUS = { ja: { pass: '合格', fail: '指摘', na: '判定不能', suppressed: '例外' }, en: { pass: 'Pass', fail: 'Finding', na: 'N/A', suppressed: 'Exception' } };
const COV = { ja: { evaluated: '判定済み', 'missing-input': '入力不足', manual: '手動確認', 'not-implemented': '未対応', excluded: '対象外' },
              en: { evaluated: 'Checked', 'missing-input': 'Missing input', manual: 'Manual', 'not-implemented': 'Not implemented', excluded: 'Excluded' } };
const DIFF = { ja: { new: '新規', resolved: '解消', continuing: '継続', 'severity-changed': '重要度の変化', 'not-rechecked': '再診断していない', suppressed: '例外登録' },
               en: { new: 'New', resolved: 'Resolved', continuing: 'Unchanged', 'severity-changed': 'Severity changed', 'not-rechecked': 'Not rechecked', suppressed: 'Exception registered' } };
export const sevLabel = (s: Severity) => SEV[lang][s];
export const statusLabel = (s: Status) => STATUS[lang][s];
export const covLabel = (s: CoverageStatus) => COV[lang][s];
export const diffLabel = (k: DiffKind) => DIFF[lang][k];
const TITLES = new Map(ITEMS.map(i => [i.id, i]));
/** 項目名（英語UIでは英語の項目名） */
export const itemTitle = (id: string, fallback = '') => (lang === 'en' ? TITLES.get(id)?.titleEn : TITLES.get(id)?.title) ?? fallback;
