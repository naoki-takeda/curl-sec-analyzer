/**
 * このツール自身の Content Security Policy（CSP）。
 *
 * GitHub Pages は HTTP の応答ヘッダを設定できないため、本番ビルドの index.html に
 * <meta http-equiv="Content-Security-Policy"> として埋め込む（vite.config.ts の metaCsp）。
 * 開発サーバ（npm run dev）には付けない。HMR がインラインスクリプトと WebSocket を使うため。
 *
 * 方針
 * - 解析中に外部へ通信できないよう、fetch・WebSocket などの通信を禁止する（connect-src 'none'）。
 *   E2E（e2e/app.spec.ts）で、メタCSPが入っていることと外部へのリクエストがないことを確かめている。
 * - HAR の Worker は blob: URL で作り、ページの CSP を引き継がせる（src/ui/har.ts）。
 *   別ファイルの Worker にはメタCSPが効かない（Worker 自身の HTTP 応答の CSP が使われ、GitHub Pages は返さない）。
 * - 通信先・スクリプトの読み込み元の許可は増やさない。緩める場合は、プルリクエストに理由を書く
 *   （.github/pull_request_template.md）。tests/csp.test.ts が主要な指定を検査する。
 *
 * 注意：meta タグでは frame-ancestors（クリックジャッキング対策）と report-uri は効かない。
 * その分は、埋め込まれたときに入力欄を出さないこと（src/main.ts）、innerHTML の禁止（eslint.config.js）とマスキングで補う
 * （docs/design.md「最大の制約」）。
 */
export const CSP_DIRECTIVES: Readonly<Record<string, string>> = {
  'default-src': "'none'",
  'script-src': "'self'",
  'style-src': "'self'",
  'img-src': "'self' data:",
  'font-src': "'self'",
  'connect-src': "'none'",
  'worker-src': 'blob:',
  'base-uri': "'none'",
  'form-action': "'none'",
};

export const CSP = Object.entries(CSP_DIRECTIVES)
  .map(([k, v]) => `${k} ${v}`)
  .join('; ');
