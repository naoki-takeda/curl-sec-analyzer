# 開発の決まり

curl-sec-analyzer の開発に参加するときの決まりです。使い方と構成は [README.md](README.md)、仕様は [docs/design.md](docs/design.md)（正本）にあります。

## 大切にしていること

- **入力をブラウザの外に出さない。** 外部と通信するコード（fetch・外部の画像やスクリプトなど）は追加しません。ツール自身の CSP（[csp.config.ts](csp.config.ts)）も緩めません。
- **秘密情報を画面にもファイルにも出さない。** Cookie・Authorization・トークン・パスワードは、画面・Markdown・JSON・CSV のどれにも生の値で出しません（`tests/masking.test.ts` で検査しています）。
- **判定の根拠を示す。** 項目・条件・重要度は設計書に根拠（OWASP・MDN・ASVS など）とあわせて書きます。

## 開発環境と検査

Node.js は `.nvmrc` の版を使います（`engines` の下限は 22.12）。

```sh
npm ci
npm run lint         # 型チェックと ESLint
npm test             # 単体テスト（変更を監視するときは npm run test:watch）
npm run audit        # 依存の署名の検証と、公開物に含まれる依存の既知の脆弱性の検査
npm run build
npx playwright install chromium firefox webkit
npm run test:e2e     # 本番ビルドに対する E2E（先に npm run build が必要）
```

プルリクエストでは、CI（`.github/workflows/ci.yml`）が同じ検査を実行します。検査の中身は `.github/workflows/checks.yml` にあります。

## コードの書き方

- **描画**：`innerHTML`・`outerHTML`・`insertAdjacentHTML`・`document.write` を使わず、`textContent`・`el()`（`src/ui/dom.ts`）で描画します。`eval` 系も使いません。どちらも ESLint で禁止しています。
- **ルール**（`src/rules/`）：評価したら必ず `.ok` か fail を返し、判定できなければ `.na` を返します。空配列は「適用外」のときだけに使います。
- **文言**：画面の文言・推奨対応を足したら、英語（`src/messagesEn.ts`・`src/recommendationsEn.ts`）もそろえます。訳の漏れは `tests/i18n.test.ts` が検出します。
- **ブラウザの保存領域**：localStorage・sessionStorage・IndexedDB・Cookie は使いません（理由は設計書の「ブラウザの保存領域」）。
- **依存パッケージ**：追加はできるだけ避けます。追加する場合は、理由と、自前で実装しない理由をプルリクエストに書きます。

## テスト用の入力（fixture）

- 実在のシステムから採取した値は使いません。ホスト名は `example.com` などに、Cookie・トークンはダミーの値に置き換えます。
- `tests/fixtures/*.txt` は、採取したままの改行（サーバの応答ヘッダは CRLF、curl 自身の行は LF）を保ちます。`.gitattributes` で改行を変換しない設定にしています。エディタで保存し直して改行を変えないでください。
- テスト用の HAR は `tests/fixtures/` に置きます。ほかの場所の `*.har` は `.gitignore` で除外しています。

## 回帰テスト（ゴールデン・同値性）

判定を変えたときの退行（直したつもりのない入力の結果が変わる）を、機械的に見つけるためのテストです。これまでのレビューで毎回のように見つかった「直前の修正の退行」を、修正の前後で同じ入力を比べる作業の代わりに検出します。

- **ゴールデン**（`tests/golden.test.ts`）：`tests/golden/cases/` の入力と、ほかの fixture・画面のサンプルを、画面と同じ流れ（`tests/golden/analyze.ts`）で判定し、結果の全体（指摘・証跡・解析警告・突き合わせのキー・診断カバレッジ）を `tests/golden/expected/*.out` と比べます。入力の秘密の値には `CANARY` を入れてあり、画面とエクスポートのどこにも出ないことも確かめます。
- **同値性**（`tests/equivalence.test.ts`）：同じ応答を、改行の違う形（CRLF、Windows の curl -v の CR CR LF、入力欄が空行に変えたもの）と、curl の出力・HAR の両方で入力し、判定が同じになることを確かめます。形式の違いで結果が違ってよいものは、理由と一緒に `KNOWN_DIFFERENCES` に書きます。

判定を意図して変えたら、期待結果を書き直して、その差分をレビューします。

```sh
npx vitest run tests/golden.test.ts -u   # 期待結果（tests/golden/expected）を今の結果で書き直す
git diff tests/golden/expected           # 変わった行が、直したものだけかを確かめる
```

- 期待結果は「正しい結果」ではなく「今の結果」です。変わった行が意図したものだけなら、テストと同じコミットに含めます。意図しない行が変わっていたら、それは退行です。
- 書き直さずにテストが通らないまま、`-u` で上書きしないでください（退行を期待結果に取り込んでしまいます）。CI（環境変数 `CI`）では期待結果のファイルを書き換えないので、書き直し忘れは CI で失敗します。
- 新しい項目・条件を足したら、その入力を `tests/golden/cases/` にも足します。時刻で結果が変わらないよう、ターゲットには `#META at=` を付けます。

## 設計書と変更履歴

- 仕様（項目・条件・重要度・ラベル・入力の形式）を変えるときは、実装と同じプルリクエストで `docs/design.md` も更新します。
- 設計書のレビューの指摘と対応は `docs/history.md` に記録します。
- 画面を変えたら、リリースの前に `npm run screenshot` で README の画像と共有用の画像を撮り直します。

## コミットとプルリクエスト

- **ブランチ**：`main` への push はそのまま GitHub Pages に公開されます。作業はブランチで行い、プルリクエストを通して `main` に入れます。
- **コミットメッセージ**：先頭に種類を付け、日本語で書きます。1つのコミットには1つの目的だけを入れます。

  | 種類 | 使う場面 |
  |---|---|
  | `feat:` | 機能・判定項目の追加 |
  | `fix:` | 不具合・誤判定の修正 |
  | `refactor:` | 動きを変えないコードの整理 |
  | `test:` | テストだけの追加・変更 |
  | `docs:` | ドキュメントだけの変更 |
  | `ci:` | GitHub Actions などの変更 |
  | `build:` | 依存関係・ビルド設定の変更 |
  | `chore:` | その他（エディタの設定など） |

  誤判定の修正では、本文に「どんな入力（マスク済み）で何が起きていたか」と「どう直したか」を書きます。Dependabot のコミットも、この種類（`build`・`ci`）にそろえています。

- **プルリクエスト**：テンプレートの確認項目を埋めます。CI が通ってからレビューします。
- **GitHub Actions**：Action はコミット SHA で固定し、末尾に `# vX.Y.Z` のコメントを書きます。権限は最小にします。`tests/workflows.test.ts` で検査しています。

## AI エージェントに作業させるとき

- ファイルの編集とテストの実行は、指示がなくても行ってかまいません。
- 次の操作は、利用者がチャットで明示的に指示したときだけ行います。指示は操作ごとに受け、前の指示を次の操作に流用しません（「コミットして」は push の指示を含みません）。
  - コミット、push、ブランチの作成・削除
  - プルリクエストの作成・マージ、Issue やコメントの投稿
  - GitHub やリポジトリの設定の変更
- 次の操作はエージェントには行わせず、人が行います。
  - force push と、push 済みのコミットの書き換え（取り消せないためです）
  - `main` への直接の push（公開されるためです）
- 実在のシステムの curl の出力・HAR・診断結果を、エージェントに読ませたり外部のサービスに送らせたりしないでください。

## 脆弱性の報告

このツール自体の脆弱性は、公開の Issue ではなく非公開で報告してください（[SECURITY.md](SECURITY.md)）。

## ライセンス

コントリビューションは、このリポジトリのライセンス（[MIT License](LICENSE)）で提供されるものとします。
