# セキュリティポリシー / Security policy

## このツールの脆弱性を報告する

curl-sec-analyzer 自体の脆弱性（マスキングの漏れ、XSS、外部への通信が発生する、など）を見つけた場合は、**公開の Issue には書かず**、GitHub の「Report a vulnerability」（Security タブ → Advisories）から非公開で報告してください。内容を確認し、修正とあわせて公開します。

報告に含めてほしいもの：

- 再現手順と、影響（どの情報が、どこに出るか）
- 再現用の入力。**実在のシステムの出力は使わず、値をダミーに置き換えたもの**にしてください

## 対象

修正の対象は、`main` の最新版と、そこから公開しているページ（`https://<組織名>.github.io/curl-sec-analyzer/`）だけです。過去の版や、手元でビルドしたものへの修正は提供しません。フォークや、ほかの場所に置かれたコピーは対象外です。

## 設計上の安全対策

詳しくは設計書（[docs/design.md](docs/design.md)）の「ツール設計3」にあります。

- **外部への通信を禁止**：本番ビルドの `<meta>` の CSP で `connect-src 'none'` などを指定しています（[csp.config.ts](csp.config.ts)）。HAR を解析する Worker も blob: の URL で作り、ページの CSP を引き継がせています。
- **HTML として挿入しない**：描画に `innerHTML` などを使わず、ESLint で禁止しています。
- **マスキング**：Cookie・Authorization・トークン・パスワードは、画面とエクスポートのどちらにも生の値で出しません。
- **何も保存しない**：localStorage・sessionStorage・IndexedDB・Cookie を使いません。
- **埋め込みの拒否**：他のサイトに埋め込まれたときは、入力欄を表示しません。

## 既知の制約

- **`<meta>` の CSP で効かない指定がある**：GitHub Pages は HTTP の応答ヘッダを設定できないため、CSP を `<meta>` で入れています。`<meta>` では `frame-ancestors`・`report-uri`・`sandbox` が効きません。クリックジャッキングは、埋め込まれたときに入力欄を出さないことで防いでいます。
- **CSP では防げない持ち出しがある**：ページの移動（リンクやフォームの遷移など）や WebRTC は、`connect-src` では止められません。XSS や依存パッケージへの悪意あるコードの混入でページ上のコードが動けば、入力内容が外に出る可能性があります。
- **同じ組織の Pages とオリジンを共有する**：同じ組織の他の GitHub Pages のページは、このツールと同じオリジンです。同じオリジンのページは、このツールをウィンドウで開いて画面の内容を読めます。そのため、同じ組織の Pages に、信頼できないコードや外部のスクリプトを読み込むページを置かない前提で運用しています（設計書の「公開先とオリジン」）。

これらの制約を突く具体的な方法を見つけた場合も、上の手順で報告してください。

## 診断結果や curl の出力を共有するときの注意

- curl の `-v` の出力、HAR、`login.txt`、Cookie の jar には、パスワード・Cookie・トークンがそのまま入っています。**Issue・Pull Request・チャットに貼らないでください。**
- 誤検知や見落としを報告するときは、ツールの「保存（マスク済み）」で出力した Markdown か JSON を使い、URL やホスト名も必要に応じて伏せてください。
- マスク済みの診断結果にも、未修正の脆弱性の情報が含まれます。公開の場に出す前に、対象システムの管理者の了承を得てください。

## Reporting a vulnerability in this tool

Please do not open a public issue. Use GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab). Never include raw curl output, HAR files or credentials from real systems; replace values with dummies.

Only the latest version on `main` and the page published from it are supported. Known limitations: the CSP is delivered via `<meta>` (GitHub Pages cannot set response headers), so `frame-ancestors`, `report-uri` and `sandbox` do not apply; CSP does not block navigation or WebRTC, so code injected through XSS or a compromised dependency could still exfiltrate input; the page shares its origin with other GitHub Pages sites of the same organization.
