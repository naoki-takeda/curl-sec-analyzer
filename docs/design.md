# Web/API自主セキュリティ診断チェックリストとcurl診断ツール設計

> **この文書の扱い**：このファイル（リポジトリの `docs/design.md`）を設計書の正本とします。仕様を変えるときは、実装と同じプルリクエストでこのファイルも直してください。以前に作業に使っていた別の文書は更新を止めています。

## 注意書きとTL;DR

curlとopensslの出力で判定できる「設定系」の項目は本書のチェックリストで確認し、「動作系」の脆弱性はOWASP ZAPやBurp Suiteで別に診断します。診断ツールは、対象に一切アクセスせず、貼り付けた出力をブラウザ内だけで解析する静的サイト（GitHub Pages）として作ります。

**注意**：診断は、自社で管理しているシステムか、書面で許可を得たシステムだけを対象にしてください。Origin偽装、メソッド試行、既知ファイル探索、ヘッダインジェクション試験は、可能な限り自社の検証環境で行います。

- **範囲**：ヘッダ、Cookie、CORS、リダイレクト、TLS、情報露出、ヘッダインジェクション、HTML本文、WebSocketのOrigin検証、APIの応答。SQLi・XSS・認可不備などは範囲外（第7章）。
- **重要度**：第0章の定義に従い、各項目の「NG判定基準」の条件（①②…）ごとに1つだけ割り当てる。幅のある値（「中〜高」など）は使わない。ツールのルールIDは`項目ID.条件番号`（例：H-01.1）で、条件番号と一対一に対応する。
- **非推奨ヘッダ**：X-XSS-Protection、Expect-CT、Public-Key-Pins、Feature-Policy、Pragmaの5つは「付いていないこと」を確認する（H-17）。
- **ツール**：入力は`#TARGET`マーカーで対象URLごとに区切る。「ログイン前・ログイン時・ログアウト」は予約ラベルで、「機密応答かどうか」は`sensitive`属性でツールに伝える。主な指標は重要度別の件数とする。Mozilla HTTP Observatory互換スコアは、配点が未確認のため実装しない（v1.0以降で再検討）。判定できなかった項目は診断カバレッジとして示し、v0.3からはブラウザのHAR形式も取り込める。CSPの解析にはGoogle `csp_evaluator`（Apache-2.0）を使う。
- **最大の制約**：GitHub Pagesは独自のHTTPヘッダを返せない。ツール自身のCSPは`<meta>`で設定し、frame-ancestorsなどが使えない分は、innerHTML禁止、`connect-src 'none'`、マスキングで補う。

### 重要度「高」になる条件の一覧（本文の表から抽出）

| 章 | 項目IDと条件 |
| --- | --- |
| 第1章 ヘッダ | H-01①③ HSTSがない・解釈できない、H-03①③ 強制モードのCSPがない・解析できない、H-04①②⑤ script-srcの'unsafe-inline'・ワイルドカード・固定nonce、H-12① 機密応答にno-storeがない |
| 第2章 Cookie | C-01① セッションCookieにSecureがない、C-02① セッションCookieにHttpOnlyがない、C-07①② セッションIDが推測可能、C-09①② セッション固定化、C-10① HTTP応答でSecureなしのセッションCookieを発行、C-12① ログアウト後もセッションが有効、C-13① セッションCookieを共有キャッシュ可能な応答で発行 |
| 第3章 CORS | R-01① Origin反射＋資格情報許可、R-02① null許可＋資格情報許可、R-03① 部分一致の不備＋資格情報許可、R-09① Cookie認証のWebSocketが任意のOriginで接続できる |
| 第4章 メソッド・通信・TLS | T-02① PUT/DELETEで作成・削除できる、T-04① HTTP→HTTPSリダイレクトがない、T-07①③ Hostヘッダが再設定リンクやキャッシュに反映、T-08① CRLFインジェクション、T-09① TLS 1.0/1.1で接続できる、T-10①② 弱い暗号・鍵、T-11① 証明書の期限切れ・不一致、T-13① X-Forwarded-Forなどの偽装でIP許可リストを回避できる |
| 第5章 情報露出・HTML本文 | E-01① エラーに認証情報、E-03① /.git・/.envなどの中身を取得できる、E-05① 管理機能が未認証、E-06① 認証付きデータのJSONP、E-09① 本文に秘密情報、E-10① パスワードフォームの送信先がhttp、E-11① アップロードファイルをHTMLとして配信 |
| 第6章 API | A-01①③ 未認証で保護データを取得できる・HTTPでBasic認証、A-02① URLにトークン、A-03① JWTがalg:none、A-07① パスワードハッシュなどの露出 |

## 第0章 前提・重要度・実施手順

診断は下記の基準と重要度の定義で判定し、実施手順の順に進めます。

### 0.1 基準と版

| 基準 | 版 | 本書での扱い |
| --- | --- | --- |
| OWASP ASVS | 5.0.0（2025年5月30日、全17章） | 関連する要件のIDを参考文献列に「ASVS 5.0.0 3.4.1」の形で記載（v1.0。ツール設計2「ASVS 5.0・IPAとの対応」） |
| OWASP API Security Top 10 | 2023年版 | 第6章の対応付け |
| ISOG-J/OWASP Japan Webアプリケーション脆弱性診断ガイドライン | 第1.2.4版（2023年11月） | 情報露出・範囲外項目 |
| IPA 安全なウェブサイトの作り方 | 改訂第7版（2021年3月、第4刷） | 項番（4-(iii)、2.3-1)など）を参考文献列に記載（原典で確認済み） |
| OWASP Secure Headers Project、Cheat Sheet Series | 2026-10時点の最新 | ヘッダの推奨値とActive/Deprecatedの区分 |
| Mozilla Server Side TLS | v5.7として参照 | 最新版は要確認 |
| MDN HTTP Observatory | 2026-10時点の最新 | スコアの参考値。配点は要確認 |

### 0.2 重要度と判定ステータス

重要度は、NG判定基準の条件ごとに下表で決めます。同じ項目でも条件が違えば重要度は変わります。

| 重要度 | 定義 | 例 |
| --- | --- | --- |
| 高 | 単独で情報漏えい・なりすまし・改ざんに直結する。または主要な防御層がなく、既知の攻撃が容易になる | HSTSなし、CORS反射＋資格情報、/.envの露出 |
| 中 | 他の脆弱性と組み合わさると影響が大きい。または多層防御の一層が欠ける | nosniffなし、クリックジャッキング対策なし |
| 低 | 影響が限定的。攻撃の手がかりになる程度 | バージョン番号の露出 |
| 情報 | 脆弱性ではないが、推奨設定や参考情報 | Permissions-Policyなし、HTTP/2非対応 |

- **判定ステータス**：pass（推奨を満たす）、fail（いずれかのNG条件に該当）、na（対象外、または入力不足で判定不能）、suppressed（例外登録済み）の4つ。
- failの重要度は、該当した条件の重要度とする。複数の条件に該当したら、最も高いものを採る。
- 「推奨水準に届かないが最低限は満たす」状態も、独立した条件として低い重要度を割り当てる（例：H-01② max-ageが1年未満→中）。
- 同じ事象は1つの項目でだけ減点する（例：JSONをtext/htmlで返す件はA-09①で判定し、H-13では扱わない。H-17②は常に情報・スコア0なので、他の項目と重なっても減点は重複しない）。

### 0.3 採取対象とAPI応答の扱い

- 最低限、次の応答を採取する：トップページ（HTML）、`http://`でのトップページ、apexドメイン（wwwを使う場合）、ログイン前のログイン画面、ログイン処理の応答（Set-Cookie）、ログイン後のページ、APIエンドポイント（JSON）、エラー（404/500）、ログアウト応答、ログアウト後に旧Cookieで認証後ページへアクセスした応答。
- セキュリティヘッダは200応答には付いていても、リダイレクトやエラーの応答で抜けていることが多い。各応答を別のターゲット（`#TARGET`）として評価する。
- **API応答の判定**：Content-Typeが`application/json`、`application/*+json`、`application/problem+json`ならAPI応答とみなす。API応答では、HTML向けの項目（H-03〜H-07、H-09、H-10、H-11、H-14）の重要度を「情報」に下げる。理由は、OWASP Secure Headers Projectが、ブラウザ以外のクライアントによるこれらのヘッダのサポートは標準化されていないとしているため。代わりにA-09（JSON応答のヘッダ）を適用する（MVPから）。
- **機密応答の判定**：H-11①、H-12①②、R-04①、R-08①、R-09①、E-06①、E-12①は「機密応答かどうか」で判定が変わる。ツールは、①`#TARGET ... sensitive=1`または`sensitive=0`の明示、②明示がなければ送信側にCookieかAuthorizationがある場合（`-v`の` >  `行で確認）は機密、③どちらでもなければ「分からない」、の順で決める。分からないときは、機密応答を前提とする条件（①）を判定しない。H-11①・H-12①②・R-08①・R-09①・E-12①はnaにする。R-04とE-06は、`*`やJSONPがあること自体は確かなので、より弱い条件（R-04③・E-06②）として出し、根拠に「機密応答かどうか分からない」と書く。診断者は認証後ページと個人情報を含むAPIに`sensitive=1`を付ける。
- **静的リソースの扱い**：H-12は、静的リソース（URLの拡張子、またはContent-TypeがJS・CSS・画像・フォント）を、`sensitive=1`を明示したときだけ機密応答として扱う。Cookieを送っただけ（上の②の推定）では機密としない。長くキャッシュさせる静的リソースが、すべてH-12①（高）になるのを防ぐため。
- **ラベル**：ラベルはターゲットの目的を表し、ツールはラベルごとに適用する項目を絞る（対応表はツール設計1）。予約ラベルは`http`、`apex`、`pre-login`、`login`、`logout`、`after-logout`、`session-sample-1`〜`session-sample-N`。確認用ラベルは`cors-*`、`websocket`、`options`、`trace`、`method-override`、`host-inj`、`crlf`、`xff-spoof`、`probes`、`error-*`、opensslの出力用のtls、オープンリダイレクト確認用のopen-redirect、CSPのnonce比較用のcsp-sample-\*、v0.3で追加した`unauth-*`（A-01：認証情報を付けずに取得）、`ctype`（A-08）、`method-*`・`old-*`（A-11）。apexドメインはhttpsをlabel=apexで、HTTP→HTTPSの転送をlabel=http（url=http://apex/）で採取する。それ以外のラベル（`top`など）は一般ターゲットとして扱う。C-09は`pre-login`と`login`を、C-07②は`session-sample-*`を比べる。

### 0.4 実施手順

1. 対象と許可範囲を確定する（URL一覧、環境、実施日時、緊急連絡先）。第8章の記録様式を用意する。
2. 未認証でヘッダを採取する（トップ、静的リソース、404、CSPのnonce比較用に同じURLを2回（C24）、apexドメイン（httpsはlabel=apex）、`label=http`で`http://`）。第1・4章。
3. TLSと証明書を確認する（openssl）。第4章。
4. 既知ファイル（ソースマップの.mapを含む）とメソッドを確認する。第4・5章。
5. テスト用アカウントで、`pre-login`（ログイン画面のGET）→`login`（ログインPOST）の順に採取する。セッションIDの比較用に、別のjarで2〜3回ログインして`session-sample-N`として採取する。第2章。
6. 認証後のページとAPIを`sensitive=1`で採取する。第1・6章。
7. CORSとWebSocketのOrigin検証を確認する。第3章。
8. `logout`でログアウトし、続けて`after-logout`で旧Cookieを使って認証後ページにアクセスする。第1・2章。
9. 検証環境で、エラー誘発、ヘッダインジェクション、送信元の偽装、PUT/DELETE、レート制限を試す。第4・5・6章。
10. 出力をツールで判定し、結果を記録する。修正後に同じコマンドで再診断する。

HARを使う場合（v0.3）は、手順5〜8のうち、ログイン前後、認証後のページとAPI、ログアウトをブラウザで操作してHARに書き出せます。`after-logout`（旧Cookieでのアクセス）、`session-sample-*`、TLS、既知ファイル、CORS、ヘッダインジェクションは、HARには入らないためcurlで別に採取します（ツール設計1「HAR形式の取り込み」）。

### 0.5 認証付きcurlの安全な実行

- トークンやパスワードをコマンドラインに直接書かない。シェル履歴やプロセス一覧（ps）に残るため。
- ヘッダはファイルから渡す：`curl -H @headers.txt ...`（headers.txtに`Authorization: Bearer ...`を書き、`chmod 600`。使用後に削除）。または`curl -K auth.conf ...`で設定ファイルを使う。
- Cookieは`-c jar.txt -b jar.txt`で受け渡し、jar.txtも`chmod 600`にして終了後に削除する。
- **出力ファイル**：`-v`の出力には送信した`Cookie`や`Authorization`がそのまま入る。`out.txt`などの出力ファイルも`chmod 600`にし、ツールで読み込んだら削除する。生の出力をチャットやチケットに貼らず、共有はツールのマスク済みエクスポートで行う。
- テスト専用アカウントと短命トークンを使う。ツールのマスキングは保険と考え、診断終了後にトークンを失効させる。

## 第1章 HTTPレスポンスヘッダ

防御の中心はHSTS、CSP、機密応答の`Cache-Control: no-store`の3つです。取得は原則としてGETで行い（C1またはC4）、HEAD（C3）は補助にとどめます。HEADに別の応答を返すサーバがあるためです。コマンドID（C1など）はツール設計の推奨コマンド表を参照してください。

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H-01 | Strict-Transport-Security | C1（https）。HTTP応答のHSTSはブラウザが無視するため判定に使わない | `max-age=63072000; includeSubDomains` | ①ない ②max-ageが31536000（1年）未満 ③構文を解釈できない ④includeSubDomainsがない | SSLストリッピング、Cookieの盗聴 | ①高 ②中 ③高 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.1、IPA 2.3-1) |
| H-02 | HSTS preload | C1（label=apexのターゲットとwwwのターゲット） | preloadを付けるならmax-age 31536000以上＋includeSubDomains。apexはhttpsの同一ホストに転送し、apex自身もHSTSを返す | ①preloadがあるのに条件不足 ②preloadなし ③preloadを付けているのにapexがHSTSを返さない | 登録拒否。登録後の取り消しに数か月かかる | ①低 ②情報 ③低 | hstspreload.org、ASVS 5.0.0 3.7.4 |
| H-03 | CSP（存在・強制） | C1。`Content-Security-Policy`と`-Report-Only`を全件抽出 | 強制モードのCSPが1つ以上 | ①ない ②Report-Onlyのみ ③解析できない | XSSの影響が軽減されない | ①高 ②中 ③高 | OWASP CSP CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.3 |
| H-04 | CSP：script-src | csp\_evaluatorで解析。複数CSPはポリシーごとに評価 | nonceまたはhash＋`'strict-dynamic'` | ①`'unsafe-inline'`（nonce/hashなし） ②`*`、`https:`、`http:`、`data:` ③`'unsafe-eval'` ④JSONPを提供するホストを許可 ⑤nonceが応答ごとに変わらない（C24で同じURLを2回取得して比較） ⑥csp_evaluatorのその他の指摘（nonceが短い、IPアドレスでの許可、unsafe-hashes、スキームなしの指定） | XSSの回避 | ①高 ②高 ③中 ④中 ⑤高 ⑥中または情報（csp_evaluatorの重要度に従う） | Google CSP Evaluator、web.dev Strict CSP、ASVS 5.0.0 3.4.3 |
| H-05 | CSP：object-src・base-uri | 同上 | `object-src 'none'`、`base-uri 'none'`または`'self'` | ①object-srcもdefault-srcも未制限 ②base-uri未指定（default-srcにフォールバックしない） | プラグイン経由の実行、`<base>`注入 | ①中 ②中 | Chrome Lighthouse csp-xss、ASVS 5.0.0 3.4.3 |
| H-06 | クリックジャッキング対策（frame-ancestors・X-Frame-Options） | 同上＋XFOヘッダ | `frame-ancestors 'none'`または`'self'`。旧ブラウザ向けにXFO `DENY`/`SAMEORIGIN`を併用 | ①両方ない ②XFOが`ALLOW-FROM`のみ（モダンブラウザ非対応） ③frame-ancestorsがなくXFOのみ ④frame-ancestorsが広い（`*`、`https:`などのスキームだけ、`*.example.com`。XFOより優先されるので、XFOが`DENY`でも守れない） | クリックジャッキング | ①中 ②中 ③情報 ④中 | MDN、OWASP Secure Headers、ASVS 5.0.0 3.4.6、IPA 9-(i)-a |
| H-07 | CSP：非推奨ディレクティブ・混在コンテンツ・構文 | 同上 | 報告は`report-to`。混在コンテンツがあるなら`upgrade-insecure-requests` | ①`block-all-mixed-content`、`referrer`、`plugin-types` ②`report-uri`のみ ③混在コンテンツ（E-07）があるのに`upgrade-insecure-requests`なし ④構文の誤り（不明なディレクティブ、キーワードの引用符、セミコロン、nonceの文字種。csp_evaluatorの構文検査） | 防御が効いていない | ①低 ②情報 ③低 ④低 | W3C CSP3、OWASP Secure Headers、ASVS 5.0.0 3.4.3, 3.4.7, 12.2.1 |
| H-08 | X-Content-Type-Options | C1 | `nosniff` | ①ない・値が不正 | MIMEスニッフィングによるXSS | ①中 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.4 |
| H-09 | Referrer-Policy | C1 | `strict-origin-when-cross-origin`、`strict-origin`、`same-origin`、`no-referrer` | ①`unsafe-url` ②`no-referrer-when-downgrade`、`origin`、`origin-when-cross-origin` ③ない（現行ブラウザの既定はstrict-origin-when-cross-origin） ④不正な値 | URL内のトークンや個人情報の外部漏えい | ①中 ②低 ③情報 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.5 |
| H-10 | Permissions-Policy | C1 | 使わない機能を無効化（例：`camera=(), microphone=(), geolocation=()`） | ①ない ②旧`Feature-Policy`のみ | 埋め込まれた第三者による機能の悪用 | ①情報 ②低 | OWASP Secure Headers |
| H-11 | COOP・COEP・CORP | C1 | COOP `same-origin`。COEPは分離が必要なら`require-corp`または`credentialless`。CORP `same-origin`/`same-site` | ①機密応答（0.3）にCORPなし ②COOPなし ③分離が必要なのにCOEPなし（手動確認。ツールは判定しない） | XS-Leaks、Spectre系攻撃 | ①低 ②情報 ③低 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.8, 3.5.8 |
| H-12 | Cache-Control | C1（認証後ページ、API、ログイン応答）。機密かどうかは0.3の判定に従う | 機密応答は`no-store` | ①機密応答にno-storeがない（未指定、`public`、`no-cache`のみ、Pragmaのみ） ②機密応答が`private`のみ ③静的リソースで未指定（静的リソースは、`sensitive=1`の明示がなければ機密応答としない。0.3） | 共有PCやプロキシ、CDNに機密データが残る | ①高 ②中 ③情報 | OWASP HTTP Headers CS、REST Security CS、ASVS 5.0.0 14.3.2, 14.2.2 |
| H-13 | Content-Typeとcharset | C1 | HTMLは`text/html; charset=utf-8`、JSONは`application/json` | ①Content-Typeなし ②HTMLでcharsetなし（JSONを`text/html`で返す件はA-09①で判定） | 文字コードを利用したXSS、スニッフィング | ①中 ②中 | OWASP HTTP Headers CS、ASVS 5.0.0 4.1.1、IPA 5-(viii) |
| H-14 | X-Permitted-Cross-Domain-Policies | C1 | `none`（または`master-only`） | ①ない ②`all`など、ポリシーファイルによる読み込みを許す値 | PDFなどからのクロスドメイン読み込み | ①低 ②低 | OWASP Secure Headers（Active） |
| H-15 | Clear-Site-Data | C1（`label=logout`のターゲット） | `"cache", "cookies", "storage"` | ①ない | 端末に情報が残る | ①情報 | OWASP Secure Headers、ASVS 5.0.0 14.3.1 |
| H-16 | 製品・バージョン・デバッグ情報の露出 | `Server`、`X-Powered-By`、`X-AspNet-Version`、`X-AspNetMvc-Version`、`X-Generator`、`Via`、`X-Runtime`、`X-Backend-Server`、`X-Debug-Token`、`X-Debug-Token-Link`、`Server-Timing` | 製品名・バージョン・内部ホスト名・内部処理の内訳を含まない | ①バージョン番号が分かる ②製品名のみ ③デバッグ系ヘッダ（プロファイラへのリンクなど） ④内部ホスト名・IP ⑤`Server-Timing`にDBや内部処理の名前・時間 | 既知の脆弱性を狙う手がかり、内部情報の露出 | ①低 ②情報 ③中 ④低 ⑤低 | OWASP WSTG、ISOG-J、ASVS 5.0.0 13.4.2, 13.4.6 |
| H-17 | 廃止・非推奨ヘッダ | `X-XSS-Protection`、`Expect-CT`、`Public-Key-Pins(-Report-Only)`、`Feature-Policy`、`Pragma` | X-XSS-Protectionは送らないか`0`。他は付けない | ①X-XSS-Protectionが`1`または`1; mode=block` ②その他が付いている | XSS Auditorの副作用、効果のない設定、HPKPの運用事故 | ①低 ②情報 | OWASP Secure Headers（Deprecated）、OWASP HTTP Headers CS |

H-17②のうち、Pragmaへの依存はH-12、Feature-Policyのみの状態はH-10で判定します。H-17では「付いている」ことだけを情報として報告し、二重に減点しません。

## 第2章 Cookie（Set-Cookie）

セッションCookieのSecureとHttpOnly、セッションIDの推測困難性、ログイン時の再発行が最重要です。ログイン応答は次のように採取します（認証情報の渡し方は0.5節）。

```sh
umask 077   # jarと出力ファイルを本人だけが読めるようにする（0.5）
H=https://HOST
# ログイン前（C-09の比較元）
echo "#TARGET url=$H/login label=pre-login"
curl -sS -v -o /dev/null -c jar.txt -b jar.txt "$H/login" 2>&1
# ログイン処理
echo "#TARGET url=$H/login label=login sensitive=1"
curl -sS -v -o /dev/null -c jar.txt -b jar.txt -X POST --data @login.txt "$H/login" 2>&1
# セッションIDの複数採取（C-07②）。jarを分けて3回ログイン
for i in 1 2 3; do
  echo "#TARGET url=$H/login label=session-sample-$i"
  curl -sS -D - -o /dev/null -c "s$i.txt" -X POST --data @login.txt "$H/login"
done
# ログアウトと、ログアウト後の旧Cookie利用（H-15・C-12）。ログアウトがPOSTなら -X POST
cp jar.txt old.txt
echo "#TARGET url=$H/logout label=logout"
curl -sS -v -o /dev/null -c jar.txt -b jar.txt "$H/logout" 2>&1
echo "#TARGET url=$H/mypage label=after-logout sensitive=1"
curl -sS -D - -o /dev/null -b old.txt "$H/mypage"
# C15: HTTP応答でのCookie発行確認（apexも url=http://apex/ で同様に）
echo "#TARGET url=http://HOST/ label=http"
curl -sS -D - -o /dev/null http://HOST/
# 終了後にjarを削除: rm -f jar.txt old.txt s1.txt s2.txt s3.txt
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-01 | Secure | 各Set-Cookieの属性 | すべてのCookieに付ける | ①セッションCookieにない ②その他のCookieにない（HSTSなし） ③その他のCookieにない（HSTSあり） | 平文通信での盗聴 | ①高 ②中 ③低 | MDN HTTP Observatory、ASVS 5.0.0 3.3.1、IPA 4-(iii) |
| C-02 | HttpOnly | 同上 | セッションCookieに必須 | ①セッションCookieにない | XSSでのセッション窃取 | ①高 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.4、IPA 5-(ix) |
| C-03 | SameSite | 同上 | `Lax`または`Strict`。`None`ならSecure必須 | ①セッションCookieで未指定 ②値が不正 ③正当な理由のない`None` ④`None`でSecureなし（ブラウザが拒否し機能不全） | CSRF、クロスサイトでの漏えい | ①中 ②中 ③中 ④低 | OWASP Session Mgmt CS、MDN HTTP Observatory、ASVS 5.0.0 3.3.2 |
| C-04 | Domain・Path | 同上 | Domainは原則付けない。Pathは必要最小限 | ①`Domain=.example.com`など親ドメインへ拡大 ②同じホストに複数アプリがあるのにPathが広い（手動確認。ツールは判定しない） | 侵害されたサブドメインや他アプリへの漏えい | ①中 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.3 |
| C-05 | Expires・Max-Age | 同上 | セッションCookieは期限なしか、アプリのセッション有効期間以下 | ①セッションIDにセッション有効期間を超える期限 | 端末に残ったCookieの悪用 | ①中 | IPA 4-(vi) |
| C-06 | \_\_Host-・\_\_Secure-プレフィックス | Cookie名と属性 | セッションは`__Host-`（Secure、Domainなし、`Path=/`） | ①プレフィックスなし ②プレフィックスの条件を満たさない（ブラウザが拒否） | サブドメインからの上書き（Cookie Tossing） | ①情報 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.1, 3.3.3 |
| C-07 | セッションIDの長さ・推測可能性 | ①は各値の長さと文字種。②は`session-sample-1`〜`N`の値を比較 | エントロピー128bit以上（ランダムな16進なら32文字以上） | ①推定128bit未満 ②連番・時刻・ユーザーIDを含む、固定部分がある（JWTは、ヘッダとクレームが共通になるため署名の部分で比べる） | 総当たりや推測によるなりすまし | ①高 ②高 | OWASP Session Mgmt CS、ASVS 5.0.0 7.2.3、IPA 4-(i), 4-(v) |
| C-08 | 既定のCookie名 | Cookie名 | 汎用的な名前 | ①`PHPSESSID`、`JSESSIONID`、`ASP.NET_SessionId` | 技術スタックが分かる | ①情報 | OWASP Session Mgmt CS |
| C-09 | セッション固定化 | `pre-login`で発行・送信したIDと、`login`のSet-Cookieを比較（`-c`/`-b`でjarを引き継ぐ） | ログイン成功時にIDを再発行 | ①ログイン前後でIDが同じ（`login`で再発行されない） ②URLにセッションID（`;jsessionid=`など） | セッション固定化攻撃 | ①高 ②高 | ASVS 5.0.0 7.2.4, 14.2.1、IPA 4-(iv)-a, 4-(ii) |
| C-10 | HTTP応答でのCookie発行 | C15（`label=http`） | HTTP応答ではSet-Cookieしない（HTTPSへ転送するだけ） | ①HTTP応答でSecureなしのセッションCookieを発行 ②HTTP応答でその他のCookieを発行 | 平文区間での盗聴、Secure属性の確認だけでは見落とす | ①高 ②中 | ASVS 5.0.0 3.3.1, 12.2.1、IPA 4-(iii) |
| C-11 | Partitioned（CHIPS） | 第三者として埋め込まれるCookie | クロスサイト埋め込み用のCookieは`Partitioned` | ①`SameSite=None`の埋め込み用Cookieにない | サイト横断の追跡、将来のブラウザ制限での機能不全 | ①情報 | MDN |
| C-12 | ログアウト後のセッション無効化 | `after-logout`（ログアウト前の旧Cookieで認証後ページへアクセス） | 401、403、またはログイン画面への転送 | ①旧Cookieで認証後ページが200で返る ②ログアウト応答でCookieを削除しない（`Max-Age=0`などがない） | 盗まれたセッションがログアウト後も使える | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.4.1 |
| C-13 | Set-Cookieと共有キャッシュ | Set-Cookieを含む応答のCache-Control | Set-Cookieを含む応答は`private`または`no-store` | ①セッションCookieを含む応答が`public`または`s-maxage`付き ②その他のCookieを含む応答が`public` | CDNやプロキシ経由で他人にセッションが配られる | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 14.2.2 |
| C-14 | セッションタイムアウト | 認証後ページに、アプリの無操作タイムアウトより長くアクセスせずに置き、同じCookieで再アクセス（手動） | 無操作タイムアウトと絶対期限で失効する | ①無操作タイムアウトを過ぎても200で返る ②絶対期限を超えても使い続けられる | 盗まれたセッションの長期悪用 | ①中 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.3.1, 7.3.2 |
| C-15 | アカウントの列挙 | 存在するIDと存在しないIDでログインとパスワード再設定を試し、ステータス・本文・応答時間（-w '%{time\_total}'）を比べる（手動、検証環境） | どちらのIDでも同じステータス・同じメッセージを返す | ①ステータスや本文の違いでIDの存在が分かる ②応答時間の差でIDの存在が分かる | ユーザーIDの収集、パスワードリスト攻撃の効率化 | ①中 ②低 | OWASP Authentication CS、ASVS 5.0.0 6.3.8、IPA 2.5-3) |

- SameSite未指定時の扱いはブラウザで異なります（ChromeはLax扱い、FirefoxとSafariは挙動が違う）。「未指定＝安全」とも「未指定＝None」とも言えないため、明示を求めます。
- セッションCookieは、名前のパターンと期限がないことで推定します。名前は語（`-`・`_`・`.`とキャメルケースの境目）に分けて照合し、`sess`で始まる語（session、PHPSESSID、JSESSIONIDなど）か、sid・token・auth・jwt・loginの語があればセッションCookieとみなします（部分一致にすると sidebar_collapsed や oauth_state まで含めてしまうため）。CSRFトークンや設定用の名前（csrf・xsrf・consent を含むもの、区切り（- _ .）で分けた語が lang・locale・theme・ga・gid・pref… のもの）は除きます。推定が外れる場合は、ツールで手動指定します。
- ASVSの項番は5.0.0のものです。5.0では、Cookieの要件がV3.3（Cookie Setup）、セッション管理がV7（Session Management）に再編されています。

## 第3章 CORS

重要度は「許可してはいけないOriginを許可したか」と「`Access-Control-Allow-Credentials: true`（ACAC）を返すか」の組み合わせで決まります。送信したOriginをツールが照合できるよう、確認コマンドは`-v`付きで実行します（C6〜C8）。

```sh
T=https://HOST/api/me
echo "#TARGET url=$T label=cors-reflect sensitive=1"
curl -sS -v -o /dev/null -b jar.txt -H 'Origin: https://evil.example' "$T" 2>&1          # C6
echo "#TARGET url=$T label=cors-null sensitive=1"
curl -sS -v -o /dev/null -b jar.txt -H 'Origin: null' "$T" 2>&1                          # C7
echo "#TARGET url=$T label=cors-partial sensitive=1"
curl -sS -v -o /dev/null -b jar.txt -H 'Origin: https://example.com.evil.net' "$T" 2>&1  # 部分一致
echo "#TARGET url=https://HOST/api/items/1 label=cors-preflight"
curl -sS -v -o /dev/null -X OPTIONS -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: authorization,content-type' https://HOST/api/items/1 2>&1  # C8
echo "#TARGET url=https://HOST/ws label=websocket sensitive=1"
curl -sS -v -o /dev/null --max-time 5 -b jar.txt -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://evil.example' https://HOST/ws 2>&1                                  # C16
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | Origin反射 | C6 | 許可リスト外のOriginにACAOを返さない | ①ACAOが送信Originを反射＋ACAC:true ②反射（ACACなし） | 任意のサイトから認証付き応答を読まれる | ①高 ②中 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 3.4.2 |
| R-02 | null許可 | C7 | `null`を許可しない | ①`ACAO: null`＋ACAC:true ②`ACAO: null` | sandboxed iframeからの窃取 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-03 | 部分一致の不備 | `example.com.evil.net`、`evilexample.com`などをOriginに指定（`-v`必須） | 完全一致で判定 | ①許可される＋ACAC:true ②許可される（ACACなし） | 同上 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-04 | ワイルドカード | C6 | `*`は公開データのみ | ①機密応答（0.3）に`*` ②`*`＋ACAC:true（仕様上ブラウザが拒否。設定ミスの兆候） ③公開データに`*` | 公開すべきでないデータの露出 | ①中 ②低 ③情報 | MDN、MDN HTTP Observatory、ASVS 5.0.0 3.4.2 |
| R-05 | プリフライト応答 | C8 | Allow-Methods/Allow-Headersは必要最小限 | ①許可外OriginにPUT・DELETEなど状態を変えるメソッドを許可 ②`Access-Control-Max-Age`が極端に長い（Chromeは7200秒で打ち切り） | 他サイトからの状態変更、設定変更が反映されない | ①中 ②情報 | MDN、OWASP WSTG、ASVS 5.0.0 3.4.2, 4.1.4 |
| R-06 | Vary: Origin | C6 | ACAOを動的に返すなら`Vary: Origin` | ①ない | キャッシュ経由で別Origin向けの応答が配信される | ①低 | MDN |
| R-07 | Access-Control-Expose-Headers | C6 | 必要なヘッダのみ | ①認証トークンや内部ヘッダを公開 ②`*` | クロスオリジンでのヘッダ情報の漏えい | ①中 ②低 | MDN |
| R-08 | Timing-Allow-Origin | C1（機密応答のターゲット） | 不要なら付けない。付けるなら限定 | ①機密応答（0.3）に`*` | タイミング情報の漏えい（XS-Leaks） | ①低 | MDN |
| R-09 | WebSocketのOrigin検証 | C16（握手の応答ステータスだけを見る。合格は401・403だけで、200・404などはWebSocketのエンドポイントではない可能性があるため判定不能とする） | 許可外Originのハンドシェイクは403などで拒否 | ①Cookie認証のWebSocketが許可外Originで`101 Switching Protocols` ②認証なしのWebSocketが101 | クロスサイトWebSocketハイジャック（他サイトから利用者として通信される） | ①高 ②情報 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 4.4.2 |

`-v`を付けずに実行した出力でも、ACAOが既知のテスト値（`https://evil.example`、`null`）と一致すれば、ツールは反射と判定します。それ以外のOriginを試す場合は`-v`が必要です。

## 第4章 メソッド・通信・TLS・ヘッダインジェクション

HTTP→HTTPSの転送、TLS 1.2以上と証明書の有効性、ヘッダインジェクションがないことが中心です。T-02、T-03、T-07、T-08は副作用があり得るため、検証環境で実施します。

```sh
umask 077
T=https://HOST/
echo "#TARGET url=$T label=options";   curl -sS -i -X OPTIONS "$T"                                  # C9
echo "#TARGET url=$T label=trace";     curl -sS -i -X TRACE "$T"                                    # C9
echo "#TARGET url=$T label=host-inj";  curl -sS -i -H 'X-Forwarded-Host: evil.example' "$T"         # C14（Host・X-Host・Forwardedも同様に）
echo "#TARGET url=${T}redirect label=open-redirect"
curl -sS -D - -o /dev/null "${T}redirect?url=https://evil.example"                            # T-06（next・returnToも同様に）
echo "#TARGET url=${T}redirect label=crlf"
curl -sS -D - -o /dev/null "${T}redirect?url=%0d%0aSet-Cookie:%20crlf=1"                      # CRLF（検証環境）
echo "#TARGET url=${T}api/items/1 label=method-override"
curl -sS -i -X POST -H 'X-HTTP-Method-Override: OPTIONS' -H 'X-HTTP-Method: OPTIONS' "${T}api/items/1"                      # メソッド上書き（検証環境）
echo "#TARGET url=${T}admin/ label=xff-spoof"
curl -sS -i -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' "${T}admin/"            # C17（検証環境）
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | OPTIONS・TRACE | C9 | `Allow`は必要最小限。TRACEは405か501 | ①TRACEが200でリクエストを反射 ②不要な`PUT`、`DELETE`、`PROPFIND`がAllowにある | XST、攻撃対象の増加 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.4, 4.1.4、IPA 5-(ix) |
| T-02 | PUT・DELETE（静的パス） | `curl -sS -i -X PUT --data 'x' https://HOST/test.txt`（検証環境） | 401、403、405 | ①201または204で作成・削除できる | ファイルの改ざん・設置 | ①高 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-03 | メソッド上書き | C21。`X-HTTP-Method`、`X-Method-Override`も試す | 上書きヘッダを無視 | ①上書きでメソッド制御を迂回できる | アクセス制御の迂回 | ①中 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-04 | HTTP→HTTPSリダイレクト | C5（`label=http`のターゲットで実行） | 最初の応答で同じホストのhttpsへ301か308 | ①転送せずHTTPでコンテンツを返す ②最初の転送先がhttp ③別ホストへ転送（HSTSが効かない） ④302または307 | 中間者攻撃 | ①高 ②中 ③低 ④情報 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1, 4.1.2、IPA 2.3-1) |
| T-05 | リダイレクトチェーン | C5 | 最終的にhttpsで、ホップが少ない | ①途中にhttpが挟まる ②Locationに内部ホスト名やポート | 中間者攻撃、内部情報の露出 | ①中 ②低 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1 |
| T-06 | オープンリダイレクト | `?url=`、`next`、`returnTo`に`https://evil.example`を指定 | 外部ホストへのLocationを拒否 | ①`Location: https://evil.example` | フィッシング、OAuthトークンの窃取 | ①中 | OWASP Unvalidated Redirects CS、ASVS 5.0.0 3.7.2、IPA 2.4-3) |
| T-07 | Host・X-Forwarded-Hostヘッダインジェクション | C14。①③はパスワード再設定に付けて実行し、届いたメールや再取得した応答を手動で確認（検証環境） | 偽装した値をLocation・本文・リンク生成に使わない | ①再設定メールなどのURLに反映 ②Locationや本文の絶対URLに反映 ③キャッシュされた応答に反映 | 再設定リンクの乗っ取り、キャッシュポイズニング | ①高 ②中 ③高 | OWASP WSTG、PortSwigger Web Security Academy、ASVS 5.0.0 4.1.3 |
| T-08 | CRLFインジェクション | C20（検証環境） | 改行が応答ヘッダに入らない | ①応答に`Set-Cookie: crlf=1`など注入したヘッダが現れる | ヘッダ分割、Cookie注入、XSS | ①高 | OWASP WSTG、ASVS 5.0.0 1.2.1, 4.2.4、IPA 7-(i)-a, 7-(i)-b, 7-(ii) |
| T-09 | TLSバージョン | ①はC12（プロトコルごとの接続可否）。②はC4の`* SSL connection using`行。C4で分かるのは合意したバージョンだけで、旧バージョンを受け入れるかは分からない | TLS 1.2と1.3のみ（Mozilla Intermediate） | ①TLS 1.0・1.1・SSLv3で接続できる ②TLS 1.3非対応 | 暗号の弱化 | ①高 ②情報 | Mozilla Server Side TLS、OWASP TLS CS、ASVS 5.0.0 12.1.1、IPA 2.3-1) |
| T-10 | 暗号スイート・鍵 | ①③は`openssl s_client -cipher`で個別に接続可否を確認（C23）。②はC11の証明書。C4で分かるのは合意した暗号だけ | ECDHE＋AEAD（AES-GCM、ChaCha20-Poly1305）。ECDSA P-256かRSA 2048bit以上 | ①RC4、3DES、EXPORT、NULL、aNULLが通る ②RSA 2048bit未満（鍵の種類が出力にないOpenSSL 1.1・LibreSSLでは長さから推定）、SHA-1署名（自己署名のルート証明書は除く） ③TLS 1.2でCBCや静的RSA鍵交換が通る | 既知の攻撃、前方秘匿性がない | ①高 ②高 ③中 | Mozilla Server Side TLS、ASVS 5.0.0 12.1.2 |
| T-11 | 証明書 | C11 | `notAfter`まで30日以上。SANに対象ホスト。`Verify return code: 0 (ok)` | ①期限切れ・ホスト名不一致・チェーン不備 ②期限まで30日以内 | サービス停止、中間者攻撃 | ①高 ②中 | OWASP TLS CS、ASVS 5.0.0 12.2.2 |
| T-12 | HTTP/2・HTTP/3 | `-w '%{http_version}'`、`alt-svc`ヘッダ。HTTP/3の確認は`--http3`対応のcurlが必要 | 任意 | ①HTTP/1.1のみ | — | ①情報 | RFC 9114 |
| T-13 | 送信元IPの偽装（X-Forwarded-Forなど） | C17。IP許可リストの管理画面や、レート制限（A-04）の試験時に`X-Forwarded-For`の値を変えて比べる（検証環境） | 信頼できるプロキシが付けた値だけを使う | ①偽装でIP許可リストを回避できる（403→200） ②偽装でレート制限がリセットされる ③偽装したIPが本文やログにそのまま反映 | アクセス制御や総当たり対策の回避、監査ログの改ざん | ①高 ②中 ③低 | OWASP WSTG、ASVS 5.0.0 4.1.3, 15.3.4 |

OpenSSL 3系は既定で古いプロトコルを拒否するため、T-09でTLS 1.0/1.1を試すときは`-cipher 'DEFAULT@SECLEVEL=0'`を付けます。付けないと、サーバが許可していても「接続不可」と誤判定します。手元のOpenSSLがそのプロトコル自体に対応していない場合、C12は ok=err を出し、ツールは判定不能（na）とします。

このほか、h2cへのアップグレード（`curl -sS -i --http2 http://HOST/`で`101 Switching Protocols`が返るか）は、プロキシの制御を迂回される兆候として手動で確認します。返る場合の重要度は低で、ツールの対象外です。

## 第5章 エラー・情報露出・HTML本文

認証情報やソースコードが取得できる状態は、他の項目と関係なく重要度「高」です。E-07〜E-10とE-12は、C2（`-i`）で取得したHTML本文で判定し、E-11はファイル配信URLの応答ヘッダで判定します。

```sh
H=https://HOST
echo "#TARGET url=$H/%25%25%25 label=error-url";    curl -sS -i "$H/%%%"
echo "#TARGET url=$H/api/items/abc label=error-api"; curl -sS -i "$H/api/items/abc"
# C13: 既知ファイル。Content-Typeは空白を含むことがあるため、必ず行末に置く
echo "#TARGET url=$H/ label=probes"
probe=$(mktemp)                   # 共有の /tmp で決まった名前を使わない
for p in /.git/HEAD /.env /.svn/entries /.DS_Store /WEB-INF/web.xml /package.json /composer.json \
         /backup.zip /phpinfo.php /server-status /robots.txt /.well-known/security.txt; do   # .map を確認する場合はパスを追加
  : > "$probe"                    # 取得に失敗したとき、前のパスの中身を使わない
  info=$(curl -sS -o "$probe" -w 'code=%{response_code} size=%{size_download} ct=%{content_type}' "$H$p")
  printf '#PROBE path=%s head=%s %s\n' "$p" "$(head -c 64 "$probe" | base64 | tr -d '\n')" "$info"
done
rm -f "$probe"
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E-01 | スタックトレース・デバッグ情報 | 不正なURL、型違いのID、壊れたJSONを送る | 汎用エラー、またはRFC 9457の問題詳細形式 | ①接続文字列（`Server=…;Password=…;`、`jdbc:`、`mongodb://user:pass@`）・AWSアクセスキー ②スタックトレース（`Traceback`、`at java.`）、SQL文（`SQLSTATE`）、絶対パス ③フレームワーク既定のエラーページ（`Whitelabel Error Page`など） | 内部構造・秘密情報の露出 | ①高 ②中 ③低 | ISOG-J、ASVS 5.0.0 16.5.1, 13.4.2、IPA 1-(iii) |
| E-02 | ディレクトリリスティング | `curl -sS https://HOST/images/` | 403か404 | ①`Index of /`など一覧が表示される | ファイルの列挙 | ①中 | ISOG-J、ASVS 5.0.0 13.4.3 |
| E-03 | 既知ファイル（/.git、/.envなど） | C13。先頭64バイトは判定にだけ使い、画面とエクスポートには「一致したパターン名」だけを出す | 404 | ①中身を取得できる（HTTP 2xxで、中身がパターンに一致する。/.git/HEADが`ref: refs/heads/`で始まる、/.envに`KEY=value`行、phpinfoの出力など） ②200だが中身が一致しない（どのパスにも200を返すSPAなど。判定保留）。パターンと項目の対応はツール設計1「プローブの判定パターン」。robots.txtとsecurity.txtは対象外（E-04で判定） | ソースコードや認証情報の漏えい | ①高 ②情報 | ISOG-J、OWASP WSTG、ASVS 5.0.0 13.4.1, 13.4.7、IPA 2.1-5) |
| E-04 | robots.txt・security.txt | C13では存在確認だけ。中身は本文を取得して確認：`curl -sS https://HOST/robots.txt` | robotsに機密パスを書かない。security.txtに`Contact:`と`Expires:` | ①robotsに機密パス（`Disallow: /admin-secret/`など） ②security.txtがない・期限切れ | 隠しパスの露出、報告窓口がない | ①低 ②情報 | OWASP WSTG、RFC 9116 |
| E-05 | API仕様・管理機能 | `/swagger-ui/`、`/openapi.json`、`/v2/api-docs`、`/graphql`（introspection）、`/actuator`、`/actuator/env` | 本番では無効、または認証の内側 | ①管理機能・actuatorが未認証で使える ②API仕様が未認証で公開 ③GraphQL introspectionが有効 | 攻撃対象の全容が分かる、設定値の露出 | ①高 ②中 ③中 | OWASP API Top 10 2023（API9）、ISOG-J GraphQL診断ガイドライン、ASVS 5.0.0 13.4.5, 4.3.2 |
| E-06 | JSONP | `curl -sS -i 'https://HOST/api/x?callback=test123'` | JSONPに対応しない | ①機密応答（0.3）を`test123(...)`で返す ②公開データのJSONP（CSP回避の足がかりになる） | クロスサイトでのデータ窃取、CSPの回避 | ①高 ②低 | Google CSP Evaluator、PortSwigger、ASVS 5.0.0 3.5.6, 3.5.7 |
| E-07 | HTML本文：混在コンテンツ | C2の本文 | 資源はすべてhttps | ①`http://`のscript・iframe・stylesheet ②`http://`のimgなど | 通信途中でのスクリプト差し替え | ①中 ②低 | MDN、ASVS 5.0.0 12.2.1、IPA 2.3-1) |
| E-08 | HTML本文：第三者スクリプトのSRI | C2の本文 | 外部CDNのscriptに`integrity`と`crossorigin` | ①外部オリジンのscriptにintegrityがない（配信元ごとに1件にまとめる。組織プロファイルで自社の配信元とした所は対象外） | CDN侵害時のスクリプト改ざん | ①低 | MDN（Subresource Integrity）、ASVS 5.0.0 3.6.1 |
| E-09 | HTML本文：機密・内部情報 | C2の本文 | 本番HTMLに秘密情報や開発用コメントがない | ①APIキー・トークン・認証情報（代入の値はASCIIの英数字・記号のものだけ。日本語の文言は対象外） ②内部URLや開発コメント ③`<meta name="generator">`のバージョン | 秘密情報の漏えい、攻撃の手がかり | ①高 ②低 ③情報 | ISOG-J、ASVS 5.0.0 13.4.6 |
| E-10 | HTML本文：パスワードフォーム | C2の本文 | `action`がhttps、`method="post"` | ①送信先（action）が`http://` ②パスワードをGETで送信 | 平文送信、URL経由の漏えい | ①高 ②中 | OWASP Authentication CS、ASVS 5.0.0 12.2.1, 14.2.1、IPA 2.3-1) |
| E-11 | ダウンロード応答 | ファイル配信URLをC1で採取 | `Content-Disposition: attachment`、`nosniff`、正しいContent-Type | ①ユーザーがアップロードしたファイルを同一オリジンでinline・`text/html`などスクリプトを実行しうる種類（XHTML、SVG、XML）として配信 ②Content-Dispositionがない（画像・音声・動画、`+json`・`+xml`のAPI応答は対象外） | アップロードファイル経由のXSS | ①高 ②低 | OWASP File Upload CS、ASVS 5.0.0 3.2.1, 5.4.1 |
| E-12 | HTML本文：CSRFトークンの有無 | C2の本文（認証後ページ） | 状態を変える`<form method="post">`に隠しトークンがある（実効性の確認は第7章の範囲外） | ①POSTフォームにトークンらしき項目がなく、SameSiteもLax/Strictでない（同じホストで見えたセッションCookieがすべてLax/Strictなら合格。セッションCookieが見えなければ①とする。機密応答かどうか分からなければna） | CSRFの可能性の兆候 | ①情報 | OWASP CSRF Prevention CS、ASVS 5.0.0 3.5.1、IPA 6-(i)-a |
| E-13 | ソースマップの露出 | 本番JSの応答ヘッダ（SourceMap、X-SourceMap）と本文末尾の //# sourceMappingURL= を確認し、示された .map のパスをC13のパス一覧に追加して実行する | 本番では .map を配信しないか、認証の内側に置く | ① .map を取得できる（HTTP 2xxで、中身がソースマップの形。元のソースコード（sourcesContent）を含むかは手動で確認） ② .map への参照（ヘッダ・コメント）がある | ソースコードや内部APIの露出 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.7 |

## 第6章 WebAPI特有（OWASP API Security Top 10 2023）

APIでは、未認証アクセス、トークンの露出、過剰なデータ露出がcurl出力で判定できる主な「高」の項目です。A-04、A-05、A-06は負荷をかけるため、検証環境で少ない回数に限って実施します。

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | 未認証アクセス | `curl -sS -i https://HOST/api/me`（Authorizationなし。`label=unauth-*`。③はHTTPの応答のWWW-Authenticate） | 401＋`WWW-Authenticate`（例：`Bearer realm="api"`） | ①200で保護データが返る ②302でログイン画面へ転送（APIとして不適切） ③HTTPでBasic認証を受け付ける | なりすまし、情報漏えい | ①高 ②低 ③高 | API2（Broken Authentication）、ASVS 5.0.0 8.2.1, 12.2.1、IPA 11-(i) |
| A-02 | トークンの露出 | URLのクエリ、本文、`Location`ヘッダ | トークンはAuthorizationヘッダだけで扱う | ①URLにトークン（`?access_token=`など） ②Locationや本文に長期トークン・他者のトークン | ログやRefererからの漏えい | ①高 ②中 | API2、API8、ASVS 5.0.0 14.2.1、IPA 4-(ii) |
| A-03 | JWTの中身 | headerとpayloadをツール内でBase64デコード | `alg`が`none`でない。`exp`が短い。PIIを含まない | ①`alg: none` ②`exp`がない ③個人情報を含む | トークン偽造、無期限の再利用、情報漏えい | ①高 ②中 ③中 | API2、ASVS 5.0.0 9.1.2, 9.2.1 |
| A-04 | レート制限 | 同じリクエストを少数回連続で送る（検証環境） | 429＋`Retry-After`。`RateLimit`/`RateLimit-Policy`（IETF draft）か`X-RateLimit-*` | ①ログイン・OTPなど認証系で制限の兆候がない ②その他のエンドポイントで兆候がない | 総当たり、リソース枯渇 | ①中 ②情報 | API4、ASVS 5.0.0 2.4.1 |
| A-05 | ページングの上限 | `?limit=100000` | 上限で切り詰めるか400 | ①指定件数がそのまま返る | リソース枯渇、大量取得 | ①中 | API4、ASVS 5.0.0 15.2.2 |
| A-06 | リクエストサイズの上限 | 大きな本文を送る（検証環境） | 413 | ①上限なしで処理される | リソース枯渇 | ①低 | API4、ASVS 5.0.0 15.2.2 |
| A-07 | 過剰なデータ露出 | JSONのキーを確認 | 必要な項目だけ | ①`password`、`passwordHash`、`secret`などのキーに、秘密情報らしい値（空白や日本語を含まない文字列）がある ②`isAdmin`、`internal_*`などの内部属性 | 秘密情報の漏えい、攻撃の手がかり | ①高 ②中 | API3（BOPLA）、ASVS 5.0.0 8.2.3, 14.2.6 |
| A-08 | リクエストのContent-Type | `curl -sS -i -X POST -H 'Content-Type: text/plain' --data '{"a":1}' https://HOST/api/x`（`label=ctype`、検証環境） | 415 | ①200で処理される | CSRFの単純リクエストを許す | ①中 | API8、ASVS 5.0.0 3.5.2 |
| A-09 | JSON応答のヘッダ | 応答ヘッダ | `application/json`、`nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` | ①`text/html`で返す ②nosniffがない ③CSPがない | ブラウザで開かれた場合のXSS | ①中 ②中 ③情報 | OWASP REST Security CS、API8、ASVS 5.0.0 4.1.1, 3.4.4, 3.4.3 |
| A-10 | エラー形式 | 400、404、500を発生させる（C25、`label=error-*`。HTMLのエラーページと`error-*`以外の応答は比べない） | 統一形式（例：`application/problem+json`） | ①形式が統一されていない（内部情報の露出はE-01で判定） | クライアントの誤動作 | ①情報 | API8、RFC 9457、ASVS 5.0.0 16.5.1 |
| A-11 | メソッド制御・旧版 | `-X DELETE`や`-X PATCH`（`label=method-*`。データを消しうるため手動で、検証環境で行い、コマンド生成器では作らない）、`/api/v1/`、`/beta/`、`/internal/`（`label=old-*`） | 405＋`Allow`。廃止版は410か404 | ①想定外のメソッドが通る ②古い版が動いたまま | 権限外の操作、修正漏れの旧版経由の攻撃 | ①中 ②中 | API5（兆候）、API9、ASVS 5.0.0 4.1.4 |

- JSON応答の`Cache-Control: no-store`はH-12で判定します。JSONを`text/html`で返す件はA-09①だけで判定し、H-13では減点しません。
- A-01①は、`unauth-*`（認証情報を付けずに取得するラベル）の応答が2xxなら指摘します。`unauth-*`は、保護されているはずのAPIにだけ付けてください（公開APIに付けると①になります）。`sensitive`の指定は判定に使いません。
- レート制限ヘッダはIETFでまだInternet-Draftです。ヘッダがないことだけを脆弱性とは断定せず、429が返るかどうかも含めて「兆候」として判定します。X-Forwarded-Forの偽装で制限がリセットされるかはT-13②で確認します。

## 第7章 curl出力では判定できない項目（ツールの範囲外）

以下は「動作系」の脆弱性で、本書のチェックリストにすべて合格しても安全性は保証されません。

| 項目 | 判定できない理由 | 必要なツール・手法 |
| --- | --- | --- |
| SQL/NoSQL/OSコマンドインジェクション | 大量の値を入れて応答の違いを分析する必要がある | OWASP ZAP（Active Scan）、Burp Suite Pro、sqlmap（検証環境）、ISOG-Jガイドラインに沿った手動診断 |
| XSS（反射型・格納型・DOM型） | ブラウザでの描画とJS実行の観察が必要 | ZAP、Burp、DOM Invader、DevTools |
| BOLA/IDOR（API1）、BFLA（API5）、BOPLAの書き込み側・マスアサインメント（API3） | 複数アカウント・ロールでの比較が必要 | Burp拡張Autorize、ZAP Access Control Testing、手動 |
| CSRFの実効性 | トークン検証ロジックの確認が必要 | Burp（CSRF PoC生成）、手動 |
| 業務ロジック（API6） | 仕様の理解が前提 | 手動診断、脅威モデリング |
| SSRF（API7） | 外部へのコールバック観測が必要 | Burp Collaborator、interactsh |
| 認証の強度（総当たり、MFA回避、パスワード再設定） | シナリオ試験が必要 | 手動、Burp Intruder（検証環境） |
| ファイルアップロード、XXE、デシリアライズ、SSTI | ペイロード試験が必要 | ZAP、Burp、手動 |
| HTTPリクエストスマグリング（Desync） | プロキシとバックエンドの解釈差を細工した通信で確かめる必要がある | Burp拡張HTTP Request Smuggler（検証環境） |
| Webキャッシュポイズニング・Web Cache Deception | キャッシュキーの推測と複数回の観測が必要（兆候はT-07③で一部検出） | Burp拡張Param Miner、手動 |
| サブドメインテイクオーバー | DNSレコードとクラウド資源の突合が必要 | DNS棚卸し、専用スキャナ |
| DNSのCAA・SPF・DMARC | HTTPではなくDNSの設定 | `dig CAA HOST`、`dig TXT HOST`、`dig TXT _dmarc.HOST` |
| 依存ライブラリの既知脆弱性、安全でないAPI利用（API10） | バージョン特定やサーバ側コードの確認が必要 | SCA（Dependabot、Trivy）、コードレビュー、SAST |

## 第8章 診断結果の記録様式

結果は下表の列で記録します。ツールのJSON・CSVエクスポートは、この列構成に合わせて出力します。証跡はマスク済みの抜粋だけを載せ、生の出力は社内のアクセス制限された場所に保管します。

| 項目ID | 対象（ラベル・URL） | 実施日時 | 実施コマンド | 判定 | 該当条件 | 重要度 | 証跡（マスク済み） | 対応方針 | 例外理由・期限 | 再診断日 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| H-01 | top（https://example.com/） | 2026-10-13 10:00 | C1 | fail | ① | 高 | `strict-transport-security`なし | Webサーバ設定で付与 | — | 修正後 |
| C-03 | login（https://example.com/login） | 2026-10-13 10:20 | ログインPOST | fail | ① | 中 | `__Host-sid=abcd…(64 chars); Path=/; Secure; HttpOnly` | SameSite=Laxを追加 | — | 修正後 |

- 対象環境（本番・検証）、実施者、許可範囲は、表の上にまとめて記載します。
- 「該当条件」列には条件番号（①②…）を書きます。ツールのルールID（例：H-01.1）の末尾の数字と一致します。
- 「実施日時」と「実施コマンド」は、各ターゲットに`#META at=2026-10-13T10:00 cmd=C1`のように付けるとツールが転記します。付けない場合は空欄で出力します。
- `#META at`（HARは`startedDateTime`）は、期限の判定（証明書のnotAfter、CookieのExpires、security.txtのExpires）の基準にも使います。前に採取した出力を読み直しても、採取時の状態で判定するためです。ない場合は判定した時刻を使います。例外の期限（until）は手元の日付で比べます。
- 再診断では同じコマンドを実行し、前回の結果と比べます（ツールの差分表示はv0.4）。

## ツール設計1：入力モデル・推奨コマンド・パース

ツールは対象にアクセスせず、`#TARGET`マーカーで区切られた複数コマンドの出力を、ターゲットごとに解析・評価します。

### 入力モデル

- **ターゲット**：`#TARGET url=https://HOST/PATH label=top kind=auto sensitive=1`の行から次の`#TARGET`行までを1ターゲットとする。`kind`は`html`、`api`、`auto`。`sensitive`は`1`か`0`で省略可（第0章 0.3）。`#TARGET`がない入力は「default」ターゲットを1つだけ持つ。
- **ラベルと適用範囲**：ラベルはターゲットの目的を表す（第0章 0.3）。ツールは下の対応表でターゲットごとに適用する項目を絞ってからルールを実行する。絞らないと、CORS確認やTRACEの応答にもCSPなどのヘッダ系ルールが当たり、指摘が重複したり的外れになったりする。予約・確認用ラベルが足りないとき、それを前提とする項目はnaになる。
- **評価の単位**：ヘッダ系ルールはターゲットごとの最終応答（1xx、CONNECT応答を除いた最後の応答）に、リダイレクト系ルールはチェーン全体に適用する。ホスト単位のルール（T-09〜T-11、E-03）は、ラベルに関係なく、URLから導いたホストごとに全ターゲットのデータを集約して1回だけ評価する。
- **URLとHTTPS判定**：URLは「`#TARGET url=`→`#META url_effective=`→`-v`の`* Connected to ... port`行→画面のURL入力欄」の順で決める。どれもなければHTTPSかどうかは「不明」とし、HSTSなどのルールはnaにしてURLの入力を促す。C5（`http://`開始）は`#TARGET url=`と食い違わないよう、`label=http`の別ターゲットで実行する。
- **API判定（MVPから）**：`kind`の指定を優先し、`auto`なら最終応答のContent-Typeで判定する（第0章 0.3）。
- **マーカー**：`#TARGET`、`#META`、`#PROBE`、`#TLSPROBE`、v0.2で追加する#CIPHERPROBEの5種類だけをマーカーとして扱い、それ以外の`#`で始まる行（robots.txtや.envのコメントなど）は普通の本文として扱う。マーカー行は必ず直前の応答を閉じる。
- **同じラベル**：同じラベルのターゲットが複数あれば（貼り付けとHARの両方に`login`を付けた場合を含む）、2つ目以降を`top#2`のように付け直して別に判定し、解析警告（duplicate-label）を出す。適用する項目は元のラベル（`#2`を除いたもの）と同じにする（`label=http`をwwwとapexの2つで採取した場合も、2つ目でT-04・C-10を判定する）。横断の判定には最初のものだけを使う。
- **`-v`のプレフィックス**：本文の読み取り中は` *  `、` >  `、` <  `で始まる行も本文として扱う。`-v`として解釈するのは、ターゲット内で`* Connected to`などの行を検出した場合（verboseモード）だけで、`-v`の出力では本文を解析しない。

### ラベルと適用する項目

ラベルは前方一致で判定し（`cors-*`など）、どれにも当てはまらなければ一般ターゲットとして扱います。診断カバレッジで案内する「必要なラベル」は、この対応表から実行時に作り（`engine/labels.ts`の`requiredLabels`）、横断ルールが必要とするラベル（C-07②、C-09①、C-12①、H-02③、H-04⑤、A-10）を足します。`csp-sample-*`はH-04⑤のためだけに案内します。ルールの中でラベルを確かめる場合も、この対応表と同じ範囲にそろえます。この一覧はengine/labels.json（ラベルの接頭辞と項目IDの配列）としてルールセットと同じ版で管理し、ツールとコマンド生成器で共有します。項目IDの後ろに条件を付けて絞ることもできます（例：T-05.2、E-04.1）。条件を付けた指定は、ルールを実行した後の結果（Finding）に適用します。手動確認項目のうち、T-03、T-07①③、T-13、A-04〜A-06は、対応するラベルのターゲットで取り込んだ応答（ステータスコードなど）を「手動確認」として表示するだけで、合否は判定しません。T-02、C-14、C-15はツールでは扱わず、第8章の様式に直接記録します。opensslの出力をまとめるtlsラベルのターゲットには、ホスト単位のルール（T-09〜T-11）だけを適用します。

| ラベル | 目的 | 適用する項目 |
| --- | --- | --- |
| 一般（下記以外。ラベルなしを含む） | 通常のページ・API | 第1章（H-15とH-02③を除く）、C-01〜C-06・C-08・C-11・C-13、R-04・R-06〜R-08、T-05②・T-12、E-01・E-02・E-04①・E-05〜E-12・E-13②、第6章（A-01は③だけ。A-01①②は`unauth-*`、A-08は`ctype`、A-11は`method-*`・`old-*`、A-10は横断ルールで判定する。A-04〜A-06は手動確認） |
| `error-*` | エラー応答 | 第1章（H-15とH-02③を除く）、E-01、A-10 |
| `http` | HTTPでの採取（apexのhttpも含む） | T-04、T-05、C-10、A-01③（HTTPでのBasic認証） |
| `apex` | apexドメイン（https） | H-01、H-02①② |
| `pre-login`、`login`、`session-sample-*` | ログイン関連 | C-01〜C-09、C-11、C-13、H-12（C-07②・C-09は横断ルール）。`pre-login`と`login`にはA-02・A-03も適用する |
| `logout` | ログアウト | H-15、C-12②（C-12①は横断ルール） |
| `after-logout` | ログアウト後 | C-12①（横断ルール。`logout`と比べる） |
| `cors-*` | CORS確認 | R-01〜R-07 |
| `websocket` | WebSocketのOrigin確認 | R-09 |
| `options`、`trace` | メソッド確認 | T-01 |
| `method-override` | メソッド上書き | T-03（手動） |
| `open-redirect` | オープンリダイレクト | T-06 |
| `host-inj` | Hostヘッダインジェクション | T-07 |
| `crlf` | CRLFインジェクション | T-08 |
| `xff-spoof` | 送信元IPの偽装 | T-13（手動） |
| `probes` | 既知ファイル | E-03（ホスト単位）、E-04②、E-13① |
| `tls` | opensslの出力 | T-09〜T-11（ホスト単位） |
| `unauth-*` | 未認証アクセス（v0.3） | A-01、A-02、A-07 |
| `ctype` | リクエストのContent-Type（v0.3） | A-08 |
| `method-*`、`old-*` | メソッド制御・旧版（v0.3） | A-11 |
| csp-sample-\* | CSPのnonce比較 | H-04⑤（横断ルール）。そのほかは一般ターゲットと同じ項目 |

### 既知のテスト値

ルールは、推奨コマンドが送る固定のテスト値が応答に現れるかどうかで判定します。値を変える場合は、ツールの設定とコマンドの両方を変えます。

| テスト値 | 使うコマンド | 検出する場所 | 対応項目 |
| --- | --- | --- | --- |
| `https://evil.example` | C6、C8、C16、C19 | ACAO、`Location`、WebSocketの101応答 | R-01、R-05、R-09、T-06 |
| `null`（Origin） | C7 | ACAO | R-02 |
| `evil.example`（X-Forwarded-Host） | C14 | `Location`、本文 | T-07② |
| `crlf=1` | C20 | 応答の`Set-Cookie` | T-08 |
| `test123`（callback） | C22 | 本文の先頭`test123(` | E-06 |
| `127.0.0.1`（X-Forwarded-For） | C17 | ステータスコード、本文 | T-13 |

### プローブの判定パターン

C13の`#PROBE`は、HTTP 2xxで取得でき、パスと先頭64バイトの両方がパターンに一致したときだけ、対応する1つの項目で判定します。1つのプローブが複数の項目で計上されることはありません。

404・403のエラーページ（JSONやXMLのエラー応答）がパターンに一致しても、そのファイルを取得できたことにはならないので、2xx以外は一致としません。中身のパターンも、エラー応答に一致しない形にしています（`<?xml`だけ、`{`だけでは判定しない）。

| パターン名 | 対象パス | 中身の目安（先頭64バイト） | 判定する項目 | 一致したとき |
| --- | --- | --- | --- | --- |
| git-head | /.git/HEAD | `ref: refs/`で始まる | E-03 | ①（高） |
| svn-entries | /.svn/entries | 数字だけの行、または`<wc-entries` | E-03 | ① |
| ds-store | /.DS\_Store | マジックバイト（`00 00 00 01 Bud1`） | E-03 | ① |
| dotenv | /.env | `KEY=value`の行 | E-03 | ① |
| web-xml | /WEB-INF/web.xml | `<web-app`または`<!DOCTYPE web-app` | E-03 | ① |
| package-json、composer-json | /package.json、/composer.json | `{`の直後に、そのファイルらしいキー（`"name"`、`"version"`、`"require"`など） | E-03 | ① |
| backup | /backup.zip | ZIPのマジックバイト（`PK\x03\x04`） | E-03 | ① |
| phpinfo、server-status | /phpinfo.php、/server-status | 「PHP Version」「Apache Server Status」。先頭64バイトに現れないことが多い | E-03 | 一致すれば①。200で一致しなければ②（判定保留） |
| security-txt | /.well-known/security.txt | `Contact:`または`Expires:` | E-04 | E-04②をpassにする |
| robots | /robots.txt | `User-agent:`など | E-04 | 存在確認のみ（E-04①は本文で判定） |
| source-map | 追加した.mapのパス | `{`の直後に、ソースマップのキー（`"version"`、`"mappings"`、`"sources"`など） | E-13 | ①（中） |

- robots.txtとsecurity.txtはE-03の対象外です。
- E-03の対象パスで200が返ったのに、どのパターンにも一致しない場合は、E-03②（判定保留）とします。
- ディレクトリリスティング（`Index of /`）は、一般ターゲットの本文からE-02として判定し、プローブでは使いません。

### 推奨コマンド

各コマンドの前に`echo "#TARGET url=$T label=..."`を出力してから実行します。v0.2では、ホスト名を入れるとこれらをまとめて生成する機能を付けます。

| ID | 目的 | コマンド | 出力の特徴・備考 |
| --- | --- | --- | --- |
| C1 | ヘッダ（GET） | `curl -sS -D - -o /dev/null "$T"` | ヘッダブロックのみ |
| C2 | ヘッダと本文 | `curl -sS -i "$T"` | ヘッダ、空行、本文。curl 8.10.0以降の正式名は`--show-headers` |
| C3 | HEAD（補助） | `curl -sS -I "$T"` | GETと結果が違うサーバがある |
| C4 | 詳細（推奨） | `curl -sS -v -o /dev/null "$T" 2>&1` | `>`送信、`<`受信、`*`情報。合意したTLSバージョンと暗号が分かる（T-09②、T-10③の一部） |
| C5 | リダイレクト追跡 | `curl -sS -L -D - -o /dev/null -w '\n#META response_code=%{response_code} num_redirects=%{num_redirects} url_effective=%{url_effective} http_version=%{http_version}\n' "http://HOST/"` | 複数のヘッダブロック＋`#META`行。`label=http`のターゲットで実行 |
| C6 | CORS反射 | `curl -sS -v -o /dev/null -H 'Origin: https://evil.example' "$T" 2>&1` | `> Origin:`で送信値を照合 |
| C7 | CORS null | C6のOriginを`null`にしたもの | 同上 |
| C8 | CORSプリフライト | 第3章のコマンド例 | Allow-Methods、Allow-Headers、Max-Age |
| C9 | メソッド | `curl -sS -i -X OPTIONS "$T"`、`curl -sS -i -X TRACE "$T"` | `Allow`ヘッダ、TRACEの反射 |
| C10 | ヘッダJSON（v0.2） | `curl -sS -o /dev/null -w '%{header_json}' "$T"` | ヘッダ名が小文字のJSON（curl 7.83以降）。パーサの対応はv0.2 |
| C11 | TLS・証明書 | 下記コードブロック | `Protocol`、`Cipher is`、`Verify return code`、`notAfter=` |
| C12 | 旧TLSの拒否 | 下記コードブロック | 1行1プロトコルの`#TLSPROBE`行（T-09①） |
| C13 | 既知ファイル | 第5章のコマンド例 | 1行1パスの`#PROBE`行。`path`、`head`（先頭64バイトのBase64）、`code`、`size`の後、行末に`ct=`（空白を含んでよい） |
| C14 | Hostヘッダインジェクション | `curl -sS -i -H 'X-Forwarded-Host: evil.example' "$T"` | テスト値がLocationや本文に現れるかを検出 |
| C15 | HTTP応答のCookie | `curl -sS -D - -o /dev/null http://HOST/` | C-10の判定。`label=http` |
| C16 | WebSocketのOrigin | 第3章のコマンド例 | ハンドシェイク応答のステータス（101かどうか） |
| C17 | 送信元IPの偽装 | 第4章のコマンド例 | 偽装ありとなしのステータスの差（手動で比較） |
| C18 | ログイン手順 | 第2章のコマンド例（pre-login、login、session-sample、logout、after-logout） | 予約ラベル付きの複数ターゲット（C-07②、C-09、C-12、H-15） |
| C19 | オープンリダイレクト | 第4章のコマンド例（label=open-redirect） | テスト値がLocationに現れるか（T-06） |
| C20 | CRLFインジェクション | 第4章のコマンド例（label=crlf、検証環境） | 注入したSet-Cookie: crlf=1が現れるか（T-08） |
| C21 | メソッド上書き | 第4章のコマンド例（label=method-override、検証環境） | 手動で比較（T-03） |
| C22 | JSONP | curl -sS -i 'https://HOST/api/x?callback=test123' | 本文の先頭がtest123(か（E-06） |
| C23 | 暗号の個別確認（v0.2） | 下記コードブロック | 1行1暗号の#CIPHERPROBE行（T-10①③） |
| C24 | CSPのnonce比較 | for i in 1 2; do echo "#TARGET url=$T label=csp-sample-$i"; curl -sS -D - -o /dev/null "$T"; done | 2つの応答のCSPのnonceを比較（H-04⑤） |
| C25 | エラーの誘発 | `curl -sS -i "$H/%%%"`（label=error-url）、`curl -sS -i "$H/api/items/abc"`（label=error-api）など。第5章のコマンド例 | エラー応答のヘッダと本文（E-01、A-10。A-10はAPIのエラー応答を2つ以上） |
| C26 | リクエストのContent-Type | `curl -sS -i -X POST -H 'Content-Type: text/plain' --data '{"a":1}' "$T"`（label=ctype、検証環境） | 415で拒否されるか（A-08） |

```sh
# C11: 証明書とTLS情報
echo "#TARGET url=https://HOST/ label=tls"
openssl s_client -connect HOST:443 -servername HOST -showcerts </dev/null 2>&1
openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# C12: プロトコルごとの接続可否（OpenSSL 3系は SECLEVEL=0 が必要）
#   ok=1   : ハンドシェイク成功（終了コードが0で、かつ Protocol 行がある）
#   ok=0   : サーバが拒否
#   ok=err : 手元のOpenSSLがそのプロトコルに非対応 → ツールでは na
for v in tls1 tls1_1 tls1_2 tls1_3; do
  out=$(openssl s_client -connect HOST:443 -servername HOST -$v -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1); rc=$?
  if printf '%s' "$out" | grep -qiE 'unknown option|no protocols available|unsupported protocol'; then r=err
  elif [ $rc -eq 0 ] && printf '%s' "$out" | grep -qE 'Protocol *: *TLS'; then r=1
  else r=0; fi
  printf '#TLSPROBE v=%s ok=%s\n' "$v" "$r"
done
```

```sh
# C23: 弱い暗号・鍵交換を個別に試す（T-10①③、v0.2）。TLS 1.2で確認する
#   ok=1   : その暗号で接続できた（サーバが受け入れる）
#   ok=0   : サーバが拒否
#   ok=err : 手元のOpenSSLがその暗号に非対応 → ツールでは na
# RC4-SHA・DES-CBC3-SHA・NULL-SHA256 は T-10①、AES128-SHA（静的RSA＋CBC）・ECDHE-RSA-AES128-SHA（CBC）は T-10③
echo "#TARGET url=https://HOST/ label=tls"
for c in RC4-SHA DES-CBC3-SHA NULL-SHA256 AES128-SHA ECDHE-RSA-AES128-SHA; do
  out=$(openssl s_client -connect HOST:443 -servername HOST -tls1_2 -cipher "$c:@SECLEVEL=0" </dev/null 2>&1); rc=$?
  if printf '%s' "$out" | grep -qiE 'no cipher match|unknown option'; then r=err
  elif [ $rc -eq 0 ] && printf '%s' "$out" | grep -qE "Cipher *: *$c"; then r=1
  else r=0; fi
  printf '#CIPHERPROBE c=%s ok=%s\n' "$c" "$r"
done
```

これらを`#TARGET`付きでまとめて実行する場合は、次のようなラッパーを使います。出力ファイルをそのままツールに読み込めます。

```sh
# run.sh: t <label> <url> <sensitive(1/0/空)> <curlの引数...>
umask 077                         # out.txt を本人だけが読めるようにする（0.5）
t() { local label=$1 url=$2 s=$3; shift 3
  echo "#TARGET url=$url label=$label${s:+ sensitive=$s}"
  echo "#META at=$(date +%Y-%m-%dT%H:%M:%S)"
  curl -sS "$@" "$url" 2>&1; echo; }

H=https://HOST
t top    "$H/"           "" -v -o /dev/null           >  out.txt
t page   "$H/"           "" -i                        >> out.txt
t http   "http://HOST/"  "" -L -D - -o /dev/null      >> out.txt
t mypage "$H/mypage"     1  -v -o /dev/null -b jar.txt >> out.txt
# ツールで読み込んだら削除する: rm -f out.txt
```

### パース上の注意点

| 論点 | 内容 | 実装方針 |
| --- | --- | --- |
| 改行 | HTTP/1.1のヘッダはCRLF。貼り付けでは混在する | 最初にCRLFとCRをLFに統一 |
| マーカーの判定 | 本文にも`#`で始まる行（robots.txt、.env、設定ファイルのコメント）がある | `#TARGET`、`#META`、`#PROBE`、`#TLSPROBE`、#CIPHERPROBE（単語境界付き）だけをマーカーとする |
| `-v`のプレフィックス | ` >  `送信、` <  `受信、` *  `情報、`{ [n bytes data]`本文。本文にも` *  `や` >  `で始まる行（箇条書きや引用）がある | verboseモードのターゲットで、かつ本文の読み取り中でないときだけ解釈する。` >  `行には送信したCookieやAuthorizationも含まれるためマスキング対象にする |
| `-v`のヘッダ終端 | 終端は` <  `だが、貼り付けで末尾の空白が落ちて`<`だけになることがある | `^<\s*$`を終端として扱い、その応答を閉じる（-vの出力では本文を解析せず、本文はC2で取る） |
| ブロック境界 | ステータス行`HTTP/(1.0・1.1・2・3) コード`。HTTP/2と3はreason phraseなし | ステータス行から空行までを1応答とする |
| 応答の閉じ忘れ | 本文の後に別コマンドの出力が続くと、本文に混入する | マーカー行とopensslの開始行（`CONNECTED(`、`depth=`、`subject=`、`notAfter=`など）で応答を閉じる。本文は64KBで打ち切る |
| `#PROBE`の属性 | Content-Typeは`text/html; charset=utf-8`のように空白を含む | `ct=`は行末に置き、`ct=`以降を行末まで値とする。`=`を含まない語は無視する |
| `-L`の複数応答 | すべてのホップのヘッダが順に出る | `responses[]`で保持し、`kind`（final・redirect・informational・connect）を付与 |
| 1xx・CONNECT | 100 Continue、103 Early Hints、プロキシの`200 Connection established` | 評価対象から除外 |
| 大文字・小文字 | HTTP/2と3ではヘッダ名を小文字で送ることが求められる | 名前は小文字に正規化し、表示用に元の表記も残す |
| 重複ヘッダ | Set-Cookieは複数行。CSPが複数あればすべて適用される | 名前ごとに配列で保持。Set-Cookieはカンマで結合しない |
| 折り返し（obs-fold） | 行頭が空白かタブの継続行（RFC 9112で非推奨） | 前の行に連結し、情報として報告 |
| opensslの出力 | OpenSSL 1.1系と3系で形式が違う | 複数の正規表現を順に試す |

### HAR形式の取り込み（v0.3）

ブラウザの開発者ツールで書き出したHAR（HTTP Archive）ファイルを、curlの出力と同じターゲットの集まりに変換して評価します。ログイン前後・API・ログアウトの一連の通信をブラウザの操作だけで採取でき、横断ルール（C-09、C-12など）を手早く適用できます。

- **判別と結合**：HARはファイル読込で受け、JSONとして解釈できて`log.entries`を持てばHARとして扱う。テキストエリアの入力はこれまでどおり`#TARGET`形式で解析し、両方から作ったターゲットを結合して評価する。
- **変換**：`log.entries`の1件を1ターゲットにする。URLは`request.url`、応答は`response.status`、`response.httpVersion`、`response.headers`（nameとvalueの配列）から作る。HTTPバージョンは、ブラウザごとの表記（h2、HTTP/2.0など）を1.1・2・3に正規化する。名前が`:`で始まるHTTP/2の疑似ヘッダ（`:status`など）は除外する。本文は`response.content.text`のうちHTMLとJSONだけを先頭64KBまで残す（`encoding: base64`ならデコード）。リクエスト側は、CookieとAuthorizationの有無（`sentAuth`）だけを取り出す。
- **由来の記録**：HAR由来のターゲットには`meta.source = 'har'`と`meta.cmd = 'HAR'`を設定する。診断カバレッジの理由（HARに機密情報が含まれないなど）と、第8章の「実施コマンド」列に使う。除外したエントリの数（har-excluded）と、機密情報が除かれたHARの検出（har-sanitized）は、解析警告としても表示する。
- **リダイレクト**：HARではリダイレクトの各ホップが別のエントリになる。`response.redirectURL`と次のエントリのURLでつなぎ、1つのターゲットの応答チェーンに組み直す。
- **対象ホストの選択**：解析の前に対象ホストを選ばせ、それ以外（解析タグ、CDN、外部APIなど）のエントリは既定で除外する。
- **ラベルの付与**：HARにはラベルがないため、取り込んだ後にエントリ一覧で付ける。一覧はリダイレクトを組み直した後のチェーン単位で表示し、ラベルはチェーン（1つのターゲット）に付ける。ツールは候補を示し、診断者が確定する。候補の例：パスワード入力欄のあるページのGET→`pre-login`、新しいセッションCookieを発行したPOST→`login`、パスにlogoutを含む→`logout`。`sensitive`は送信側のCookie・Authorizationの有無で自動で決め、一覧で上書きできる。次の制約を設ける。
  - 予約ラベルは1つのエントリにだけ付けられる（横断ルールが比べる対象を一意にするため）。
  - `cors-*`ラベルは付けられない（ブラウザが送る正規のOriginを、R-01が「反射」と誤判定するため）。ほかにも、細工したリクエストを前提とするラベル（websocket、options、trace、method-override、open-redirect、host-inj、crlf、xff-spoof、probes、tls）は付けられない。テスト値を送っていないのに、ルールが「確認して問題なし」（.ok）を返してしまうため。HARで付けられるのは、一般、error-\*、http、apex、pre-login、login、logout、csp-sample-\* だけで、この許可リストはlabels.jsonに「HARで使えるか」の属性として持たせる。同じ理由で`sentOrigin`も設定しない。
  - `after-logout`（旧Cookieでのアクセス）と`session-sample-*`はブラウザの通常の操作では生じないため、curl（C18）で採取する。
- **HARでは判定できない項目**：TLS（T-09〜T-11）、既知ファイル（E-03）、偽装OriginによるCORS確認（R-01〜R-03）、メソッド確認（T-01）、ヘッダインジェクション（T-07、T-08）など、細工したリクエストが必要な項目はHARには含まれない。これらは診断カバレッジで「入力不足」として示し、推奨コマンドで別に採取するよう案内する。
- **秘密情報の扱い**：HARには、ログイン時のパスワード（`request.postData`）、すべてのCookie、トークン、応答本文が入る。読み込みはWeb Worker内で行い、`request.postData`と不要な本文は読み込んだ直後に破棄し、残す値にもマスキングを適用する。HARファイルは使用後に削除するよう画面で案内する（第0章 0.5と同じ扱い）。テスト用アカウントで採取する。
- **ブラウザによる違い**：ブラウザによっては、既定の書き出しでCookieやSet-Cookieなどの機密情報を除く（要確認事項）。CookieやSet-CookieがないHARでは、第2章の項目を「入力不足」とし、機密情報を含める書き出し方を画面で案内する。
- **サイズ**：HARは数十MBになることがあるため上限を50MBとし、必要な項目を取り出したら元のJSONは破棄する。

## ツール設計2：ルールエンジン・スコアリング・例外登録

ルールはチェックリストの項目IDと条件番号をそのまま使い、結果は重要度別の件数で示します。意図した設定は例外登録で抑制できます。

### ルールIDと定義の形

- **IDの形**：`<項目ID>.<条件番号>`で統一する（例：H-01の①は`H-01.1`、②は`H-01.2`）。合格は`H-01.ok`、判定不能は`H-01.na`。ルールは、評価したら必ず.okかfailを返し、判定できなければ.naを返す。空の配列は「このターゲットには適用外」（例：httpのターゲットに対するH-01）の意味にだけ使う。診断カバレッジは、この返り値で「判定済み」かどうかを決める。読みやすさのために`name`（例：`missing`）を、Observatoryに同等のテストがある場合は`obsId`（例：`hsts-not-implemented`）を別名として持つ。
- **ルールの書き方**：ルールはすべてTypeScriptの関数で書き、`rules/ruleset.ts`に登録する。当初は、有無・許可値・正規表現で決まる単純なルールを宣言的なJSONにする案だったが、条件の分岐が多く、型と単体テストで守れる関数に統一した。
- **適用範囲**：各ルールに`appliesTo`（`html`・`api`・`any`）を持たせる。API応答に対してHTML向けルールが該当した場合は、重要度を「情報」に下げる。
- **二重減点の防止**：同じ事象を複数のルールが検出した場合は、チェックリストで「判定する項目」と定めた側だけで減点する（例：PragmaはH-12、JSONを`text/html`で返す件はA-09）。
- **根拠の版管理**：各ルールに`basis`（根拠文書）を持たせる。ルールセット全体の版（`RULESET_VERSION`、例：`2026.11-v0.4.5`）を画面とエクスポートに出す。判定の範囲や条件を変えたら、ルールセットの版を上げる。

### スコアリング

- **主な指標**：ターゲットごとと全体の、重要度別のfail件数（高・中・低・情報）。全体の件数は「項目×条件」（ルールID）で一意に数え、同じ指摘が複数ターゲットで出ても1件として、該当ターゲットを一覧で示す。ターゲットごとの件数は別に表示する。suppressedは件数に含めず、別に件数を表示する。
- **Observatory互換スコア（保留）**：配点と最高点が未確認（要確認事項）のまま点数を出すと誤解を招くため、実装しない。v1.0以降で、mdn/mdn-http-observatory のソースで配点を確認してから再検討する。その際の方針の案は次のとおりで、ルールの`obsId`はそのために残しておく。
  - ホストごとに、HTMLの一般ターゲット、ログイン関連ターゲット、http・apexターゲットの結果を合わせて計算する。API応答のターゲットは含めない（MDNのFAQが、ObservatoryはAPIエンドポイント向けではないとしているため）。
  - `obsId`があるルールだけがスコアを持つ。同じホスト内では項目ごとに1回だけ数え、最も悪い結果を採る。
  - 配点の参考値（アーカイブ済みの旧版scoring.md、2024-02-27更新）：CSP未実装−25、unsafe-inline−20、unsafe-eval−10、HSTS未実装−20、6か月未満−10、セッションCookieのSecureなし−40、HttpOnlyなし−30、リダイレクトなし−20 など。

### CSPパーサとSet-Cookieパーサ

- **CSP**：Google `csp_evaluator`（npm、Apache-2.0、TypeScript）の`CspParser`と`CspEvaluator`を組み込む。自作するのは、複数CSPとReport-Onlyの区別、frame-ancestorsとXFOの総合評価（H-06）、非推奨ディレクティブの検出（H-07）だけ。
  - **振り分け**：csp_evaluatorの指摘を、チェックリストの条件に振り分ける（`rules/csp.ts`）。`SCRIPT_UNSAFE_INLINE`→H-04①、script系の`PLAIN_URL_SCHEMES`・`PLAIN_WILDCARD`・`SRC_HTTP`・`WILDCARD_URL`とscript-srcの`MISSING_DIRECTIVES`→H-04②、`SCRIPT_UNSAFE_EVAL`→H-04③、`SCRIPT_ALLOWLIST_BYPASS`（JSONP・AngularJSを置くホスト）→H-04④、`NONCE_LENGTH`・`IP_SOURCE`・`SCRIPT_UNSAFE_HASHES`・`SRC_NO_PROTOCOL`→H-04⑥、object-srcの問題と`OBJECT_ALLOWLIST_BYPASS`→H-05①、`DEPRECATED_DIRECTIVE`→H-07①、構文の検査（`MISSING_SEMICOLON`・`UNKNOWN_DIRECTIVE`・`INVALID_KEYWORD`・`NONCE_CHARSET`）→H-07④。
  - **使わない指摘**：「〜かもしれない」（`HIGH_MAYBE`・`MEDIUM_MAYBE`。`'self'`や未知のホストへの注意など）、Strict CSPの推奨、後方互換・Trusted Typesの指摘は、誤検知が多いため使わない。ただし`'unsafe-eval'`はcsp_evaluatorでは`MEDIUM_MAYBE`だが、H-04③（中）として扱う。
  - **自前で残す判定**：H-05②（base-uriがない。csp_evaluatorはnonceやhashを使う場合だけ指摘するが、チェックリストでは常に確認する）、H-07②③、H-06、H-03、H-04⑤（横断ルール）。
- **Set-Cookie**：最初の`;`より前を`name=value`、残りを属性（名前は大文字小文字を区別しない）とする。値の長さ・文字種・推定エントロピーの上限を出し（C-07）、プレフィックスの条件を検証する（C-06）。

### ターゲット横断ルールと評価の順序

- **ラベル依存ルール**：特定のラベルが付いたターゲット1つを見るルール。H-15とC-12②は`logout`、T-04は`http`（apexのhttpも`label=http`で採取する）。
- **横断ルール**：複数ターゲットを比べるルール。C-07②は`session-sample-*`のセッションIDの共通接頭辞・連番性、C-09①は`pre-login`で発行されたIDと`login`のSet-Cookie、C-12①は`logout`と`after-logout`、H-02③は一般ターゲット（www）のpreloadと`apex`のHSTS、H-04⑤のcsp-sample-\*同士のCSPのnonce。ラベルが足りなければnaとし、画面で不足しているラベルを示す。
- **ルール間の依存**：C-01②③は同じホストのH-01（HSTS）の結果を、H-07③は同じターゲットのE-07の結果を使う。ログイン関連ターゲットではH-01を実行しないため、HSTSの有無はホストごとに一般・`apex`ターゲットの結果から先に求めて参照する。依存先は各ルールの`dependsOn`に書く。
- **評価の順序**：①ラベルと適用項目の対応表で項目を絞り込み→②ターゲット単位のルール→③ホスト単位のルール（ホストごとに集約）→④横断ルール。②〜④の各スコープの中では`dependsOn`の順に実行する。その後、⑤条件単位の絞り込み（ターゲット単位のルールの結果に適用）→⑥API応答での重要度の引き下げ→⑦組織プロファイルで対象外にした項目の除外→⑧二重減点の除去→⑨組織プロファイルによる重要度の上書き→⑩例外の適用。除外を二重減点の除去より先に行うのは、除外した項目の代わりに数えている指摘を「数えない」扱いにしないため。実装は`engine/run.ts`（ツール設計4）。
- **二重減点の除去（DEDUPE）**：同じターゲットで、keep が fail のときは drop を数えない（`status`を`na`にし、`dedupedBy`にkeepを残す。診断カバレッジでは判定済みとして扱う）。

| keep | drop | 理由 |
| --- | --- | --- |
| A-09② | H-08① | API応答の nosniff なしは A-09② で数える |
| A-09③ | H-03① | API応答の CSP なしは A-09③ で数える |
| A-09① | H-13② | JSONをtext/htmlで返す件は A-09① で数える（第0章 0.2） |
- **機密応答の判定**：第0章 0.3の順序で`RuleContext.sensitive`に入れる。`undefined`のとき、機密応答を前提とする条件はnaにする（R-04とE-06は、より弱い③・②で出す。第0章 0.3）。

### 例外登録（抑制）

- 「意図した設定」を例外として登録できるようにする。登録項目は、ルールID、対象（ラベルまたはURLパターン）、理由、承認者、期限。
- 例外に該当した結果はステータスをsuppressedにし、件数とスコアから除外する。エクスポートには理由付きで残す。
- 期限を過ぎた例外は自動で無効になり、結果がfailに戻る。
- 例外は`suppressions.json`としてインポート・エクスポートする。localStorageなどブラウザには保存しない（ツール設計3「ブラウザの保存領域」）。
- URLのパターン（`*`は任意の文字列）は、正規表現に変換せずに照合する（`*`の多いパターンでバックトラックが爆発し、画面が固まるため）。パターンは500文字までとする。

### 診断カバレッジ（MVP）

チェックリストの全項目について、今回の入力で判定できたかどうかを一覧にします。結果が合格だけでも、判定していない項目が多ければ安全とは言えないため、「何を確認していないか」を明示します。

| 区分 | 条件 | 画面に示すもの |
| --- | --- | --- |
| 判定済み | その項目のFindingが1つ以上、pass・fail・suppressedになった | failの件数と重要度 |
| 入力不足 | すべてnaだった、または適用できるターゲットがなかった | 理由と、不足しているラベル・コマンド（例：「`tls`ラベルのターゲットがない。C11・C12を実行」） |
| 手動確認 | 手動確認項目（T-02、T-03、T-13、C-14、C-15、A-04〜A-06） | 第8章の様式への記録を促す |
| 未対応 | 今のルールセットではまだ実装していない | 実装予定のフェーズ（例：v0.2） |
| 対象外 | 組織プロファイルの`exclude`で判定しないとした項目 | 「組織プロファイルで対象外」 |

- **集計の単位**：項目ID単位で集計し、詳細では条件ごとの状態も示す。一部の条件だけが手動の項目（T-07）は、自動の条件で集計し、手動の条件は詳細に示す。
- **範囲外の項目**：第7章の項目は、カバレッジ表の下に常に一覧で示し、必要なツール・手法を案内する。
- **カバレッジ率**：判定済みの項目数を、実装済みの自動判定項目の数（全項目から手動確認と未対応を除いた数）で割った値。全体で示し（ホストごとの率は今後の検討）、未対応の項目数は別に示す。率が高くても安全の保証ではないことを併記する。
- **入力不足の理由**：ラベルの不足、HTTPSかどうか不明（URLなし）、機密応答かどうか不明（`sensitive`なし）、HARに機密情報が含まれない、ok=errのプローブ、を区別して示す。理由はnaのFindingに持たせる（例：C-09.naの「必要なラベル: pre-login, login」）。
- **項目の台帳**：全項目の一覧（項目ID、項目名（日本語・英語）、章、手動かどうか、実装フェーズ）を`engine/items.json`で、ルールセットと同じ版で管理する。必要なラベルは台帳に持たず、`labels.json`から実行時に作る（`engine/labels.ts`の`requiredLabels`）。実装済みの項目の集合は、ルールセットに登録したルールの項目IDから作る。

- **エクスポート**：MarkdownとJSONにカバレッジ表を含める。

### 組織プロファイル（v0.4）

組織ごとの基準を`profile.json`で読み込みます。ブラウザには保存しません。

```json
{
  "name": "組織名・プロファイル名",
  "severity": { "H-10": "low", "H-14.1": "info" },
  "exclude": ["T-12"],
  "sessionCookieNames": ["APPSESSION"],
  "sessionMaxAgeHours": 12,
  "trustedScriptOrigins": ["https://assets.example.com"]
}
```

- **severity**：項目ID（`H-10`）か条件（`H-14.1`）ごとの重要度。条件の指定が項目の指定より優先する。変えた重要度には「*」を付け、元の重要度（`originalSeverity`）を残す。
- **exclude**：判定しない項目。結果から除き、診断カバレッジでは「対象外」とする。
- **sessionCookieNames**：セッションCookieとして扱う名前。指定すると、名前と期限による推定より優先する。
- **sessionMaxAgeHours**：C-05で指摘する期限の基準（既定24時間）。
- **trustedScriptOrigins**：自社の配信元（`https://cdn.example.com`、`cdn.example.com`、`*.example.com`の形）。ここからのscriptはE-08（第三者スクリプトのSRI）の対象外にする。
- 不正な値は読み込み時に指摘し、正しい部分だけを使う。エクスポートしたJSONにはプロファイルを含める。

### 前回との差分（v0.4）

以前にエクスポートしたJSONを読み込み、今回の結果と比べます。

- **突き合わせ**：指摘（fail）を「ルールID×ターゲット」で突き合わせる。ターゲットは、curlはラベル、HARは「HAR メソッド URL（マスク済み）」（`targetKey`）で識別する。HARのラベルの番号は記録し直すと変わるため。`targetKey`のない以前のJSONはラベルで突き合わせる。例外の照合にも同じキーを使う。
- **区分**：新規、解消、重要度の変化、例外登録、継続、再診断していない。「再診断していない」は、前回の指摘のうち今回の入力で同じターゲット・項目を判定していないもの（採取していないのに「解消」と表示しないため）。突き合わせには fail と suppressed の両方を使う。「例外登録」は、今回 suppressed になった指摘（前回も suppressed なら変化なしとして出さない）。例外は直したことにならないので「解消」には数えない。前回 suppressed で今回 fail（例外の期限切れなど）は、既知の指摘として「継続」か「重要度の変化」にする。
- **警告**：前回と今回で、組織プロファイル（重要度・対象外の項目・セッションCookieの指定。名前は除く）またはルールセットの版が違う場合は、差分に設定やルールの変更が混ざるため警告する。
- **読み込み時の検査**：前回の結果の各指摘は、`ruleId`（`H-01.1`の形）、`item`（`ruleId`と一致すること）、`severity`、`status`、`target`を確かめ、合わないものは除いて件数を表示する。条件番号は`ruleId`から作り直す。前回の結果に含まれるプロファイルも、組織プロファイルと同じ検査を通す。手で編集したJSONや別のツールのJSONでも、表示が崩れないようにするため。
- **出力**：画面とMarkdownに差分の表を出す。

### ASVS 5.0・IPAとの対応（v1.0）

- **原典**：OWASP ASVSはGitHubのOWASP/ASVSリポジトリの`v5.0.0`タグの`5.0/en`（要件345件）、IPAは「安全なウェブサイトの作り方」改訂第7版（2021年3月、第4刷、IPAの公式ページのPDF）を読んで対応付けた。
- **持ち方**：対応は`src/engine/items.json`の各項目の`asvs`（要件ID）と`ipa`（項番）に持つ。ASVSの要件の文言はCC BY-SA 4.0のため取り込まず、要件IDとレベル（L1〜L3）だけを`src/engine/asvs-levels.json`に持つ（原典から機械的に作成）。第1〜6章の表の参考文献列は`items.json`と同じ内容にし、食い違いはテスト（`tests/standards.test.ts`）で検出する。
- **意味**：「関連する要件」であり、その要件を満たすかどうかの判定ではない。ツールの合格は、ASVSのその要件への適合を意味しない。
- **表記**：ASVSは、ASVSが推奨する`v<version>-<要件ID>`（例：`v5.0.0-3.4.1`）で引用する。画面とMarkdownでは「ASVS 3.4.1」と略し、レベルを添える。IPAは、第1章は「4-(iii)」「4-(iv)-a」、第2章は節番号と番号をつないで「2.3-1)」とする。
- **出す場所**：画面の項目名の横（指摘の一覧、差分、診断カバレッジ）、Markdown（指摘の項目名の横と、診断カバレッジの表の「ASVS 5.0.0」「IPA」列）、JSON（`standards`）。CSVは第8章の記録様式の列を変えないため出さない。
- **対応付けない項目**：ASVS 5.0・IPAに該当する要件がない項目（H-10、H-14、H-17、C-08、C-11、R-06〜R-08、T-12、E-04）は空にする。IPA 5-(x)は`X-XSS-Protection: 1; mode=block`とCSPの`reflected-xss`（廃止）を勧めており、H-17と向きが逆なので対応付けない（判断の根拠2）。
- **基準をASVSに合わせた点**：ASVS 5.0は、HSTSのmax-ageを1年以上（L2以上はincludeSubDomainsも）とし（3.4.1）、セッションIDに128bit以上のエントロピーを求める（7.2.3）。v1.0（ルールセット`2026.11-v0.4.16`）で、H-01②の基準を6か月から1年に上げ、H-01④（includeSubDomainsがない、低）を追加し、C-07①の基準を64bitから128bitに上げた。Observatoryの`obsId`は、Observatoryの区切り（6か月）のまま付ける。

### 英語UI（v0.4）

- **切り替え**：画面右上の切り替え、または`?lang=en`。ブラウザの言語が日本語以外なら英語で始める。
- **英語にする範囲**：画面の文言、項目名（`items.json`の`titleEn`）、ラベル名（`labels.json`の`nameEn`）、重要度・判定・区分、推奨対応、診断カバレッジの理由とコマンドの案内、Markdown。
- **日本語のまま**：証跡（応答から取った値と短い説明）、CSV（第8章の記録様式）、解析警告、入力エラー。
- **管理**：推奨対応の英訳は`src/recommendationsEn.ts`にまとめる。ルールの推奨対応を構文木から集めて英訳の漏れを検出するテスト（`tests/i18n.test.ts`）を置く。

## ツール設計3：既存OSS・セキュリティとプライバシー・非機能要件

外部通信を一切しないことと、貼り付けた秘密情報を表示しないことが、このツールの前提です。

### 既存ツール・OSS

| ツール | 方式 | 参考にできる点 | ライセンス・注意 |
| --- | --- | --- | --- |
| MDN HTTP Observatory（mdn/mdn-http-observatory） | URLスキャン（サーバ側） | テスト体系、ルールID、配点、グレード | MPL-2.0。コードを流用するとファイル単位でソース開示義務。考え方の参考にとどめる |
| 旧Mozilla HTTP Observatory | Python | scoring.md（配点表） | MPL-2.0、2024年11月4日にアーカイブ |
| Google CSP Evaluator | ライブラリとWeb UI | CSP解析・評価の中核 | Apache-2.0（npm `csp_evaluator`）。配布物にLICENSEを同梱する（パッケージにNOTICEファイルはない）。`THIRD_PARTY_LICENSES.txt`に自動で含まれる |
| securityheaders.com | URLスキャン（SaaS） | Recommended/Optionalの分け方 | ソース非公開。基準の参考のみ |
| OWASP Secure Headers Project | 文書とデータ | Active/Deprecatedの分類、推奨値 | 出典を明記して参照 |
| 0xelitesystem/http-header-analyzer、techshield-tech/http-headers、meduuv/security-headers-analyzer | 貼り付け型（ブラウザ内で完結） | ヘッダ解説、設定例の生成、「送信しない」設計 | ライセンス未確認。流用前に各リポジトリのLICENSEを確認 |
| rfc-st/humble | CLI（Python）。URLを取得するほか、保存した生の応答ファイルも解析できる | 指紋になるヘッダの検出、非推奨・不正な値の検査、testssl.shとの連携 | ライセンス要確認。考え方の参考にとどめる |
| offseckit/headers | CLI（Python）。curl -sIの出力をパイプで受ける | CI向けのJSON出力 | MITと表示されている（要確認） |
| headerpulse | CLI（Python）。対象に自らアクセスする | ヘッダ・Cookie・CORSのOrigin反射を1回で確認する構成 | ライセンス要確認 |
| 貼り付け型のWebツール（jmrp.io、hidekazu-konishi.com、elysiatoolsなど） | ブラウザ内で完結（一部はURL取得の機能もある） | 1応答のヘッダの採点と解説。hidekazu-konishi.comは日本語 | ソースとライセンスは各サイトで確認 |

差別化のポイントは、複数ターゲット・`-v`・`-L`・openssl・プローブをまとめた1つの貼り付けを解析できること、API Top 10 2023に対応したルール、送信OriginとACAOの照合、日本語の解説とIPA・ISOG-Jへの対応付け、ログイン前後やログアウト後を比べるターゲット横断の判定、何を確認していないかを示す診断カバレッジ、ブラウザのHARの取り込み（v0.3）です。既存の貼り付け型ツールは、1つの応答のヘッダを採点するものがほとんどです。

### セキュリティとプライバシー

| 論点 | 方針 |
| --- | --- |
| 外部送信の禁止 | `fetch`、`XMLHttpRequest`、`WebSocket`、`sendBeacon`は使わない。分析タグやCDNもなし（すべて同梱）。メタCSPの`connect-src 'none'`で技術的にも止める |
| マスキングの対象 | 常に行う（切り替えはない）。生のヘッダ行（Authorization、Cookie、Set-Cookieなど）は画面にもエクスポートにも出さない。証跡に出すSet-Cookieは値だけ伏せ、属性は残す。URL（ターゲット、Location、証跡）のパラメータは、検出（A-02・C-09②）に使う名前に加え、名前を`-`・`_`・`.`・角かっこ（`user[password]`）・キャメルケースの境目（`accessToken`）で区切った語に`token`・`secret`・`signature`・`credential`・`password`・`key`・`session`・`sid`・`code`などがあるものを伏せる（署名付きURLの`X-Amz-Security-Token`など）。ほかにJWT、CSPのnonce、URLの`user:pass@`の部分。一覧の正本は`src/mask.ts` |
| マスキングの方法 | 値の長さで残す文字数を変える：8文字以下はすべて伏せる、9〜20文字は先頭2文字、21文字以上は先頭4文字。いずれも文字数を付記（例：`abcd…(64 chars)`）。Set-Cookieは値だけ伏せて属性は残す。エントロピー評価はマスク前の値でメモリ内だけで行う |
| プローブの中身 | `#PROBE`の`head`（先頭64バイト）は.envなどの秘密を含み得る。判定にだけ使い、画面とエクスポートには「一致したパターン名」（例：`git-head`、`dotenv`、`phpinfo`）だけを出す |
| 生データのエクスポート | 提供しない。エクスポートは常にマスク済み。生の出力は診断者の手元のファイルを社内の保管場所に置く（第8章） |
| ツール自身のCSP（meta） | `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src blob:; base-uri 'none'; form-action 'none'">`（`object-src`は`default-src 'none'`で禁止される）。あわせて`<meta name="referrer" content="no-referrer">`を入れる。これらは`<head>`の先頭（charsetより前）、どのスクリプトよりも前に置く。開発サーバはCSSをstyle要素で注入するため、メタCSPは本番ビルド時だけViteプラグインで挿入する。CSSはTailwind CSS v4を@tailwindcss/viteでビルド時に静的ファイルとして生成し、実行時にstyle要素を注入するものは使わない |
| メタCSPの制約 | W3C CSP3では`frame-ancestors`、`report-uri`、`sandbox`、Report-Onlyはmetaで無効。GitHub Pagesは独自ヘッダを設定できない。クリックジャッキング対策はJSの`top !== self`による表示抑止で補う。厳密さが必要ならCloudflare Pagesなどヘッダを設定できるホストへ移す |
| XSS対策 | 入力由来の文字列は`textContent`か`createTextNode`で描画し、`innerHTML`、`insertAdjacentHTML`、`eval`、`new Function`は禁止。ESLint（`no-restricted-properties`で`innerHTML`・`outerHTML`・`insertAdjacentHTML`・`document.write`、`no-eval`・`no-implied-eval`・`no-new-func`）で機械的に止める。可能ならメタCSPに`require-trusted-types-for 'script'`（ブラウザ対応は要確認） |
| Worker | HARの解析はWeb Workerで行う（curlの貼り付けはメインスレッドで解析する）。Viteの`?worker&inline`でblob: URLのWorkerとして作り、メタCSPに`worker-src blob:`を加える。別ファイルのWorkerには、そのファイルのHTTP応答のCSPが使われ、GitHub PagesはCSPヘッダを返さないため、生のHAR（Cookie・パスワード）を持つWorkerから通信できてしまう。blob: のWorkerはページのCSP（`connect-src 'none'`）を引き継ぐ（E2Eで確認） |
| ファイル読込・ReDoS | `FileReader.readAsText`でサイズ上限5MB（HARは50MB）。正規表現は線形時間のパターンに限る |
| ブラウザの保存領域 | localStorage・sessionStorage・IndexedDB・Cookieは使わない（何も保存しない）。共有PCに秘密情報が残るうえ、同じオリジン（`<組織名>.github.io`）の他のリポジトリのページから読めるため。例外ファイル・組織プロファイル・前回の結果は、毎回ファイルで読み込む |
| 公開先とオリジン | 専用の組織アカウントのリポジトリで管理し、`https://<組織名>.github.io/curl-sec-analyzer/`で公開する。個人アカウントの他のGitHub Pagesとはオリジンが分かれる。ただし同じ組織の他のPagesとはオリジンを共有するので、次を前提にする。①ブラウザの保存領域を使わない（上の行）。②他のページへの埋め込みを拒否する（同じ組織の他のページからの埋め込みも含む）。③同じ組織のPagesに、信頼できないコードや外部のスクリプトを読み込むページを置かない（同じオリジンのページは、このツールをウィンドウで開いて画面の内容を読めるため）。③を守れなくなったら、ツールごとに組織を分けるか、独自ドメイン（有料）を割り当てる |
| サプライチェーン | 依存は最小限。`package-lock.json`をコミットし、CIで`npm ci --ignore-scripts`→`npm audit signatures`（レジストリの署名の検証）→`npm audit --omit=dev --audit-level=high`を実行（手元では`npm run audit`）。GitHub ActionsはコミットSHAで固定し、バージョンをコメントに書く（`tests/workflows.test.ts`で検査）。Dependabotは`npm`と`github-actions`の両方を有効にし、公開直後のリリースを取り込まないよう待機期間（cooldown）を置く。公開リポジトリでは、CodeQLとdependency-reviewで、コード・ワークフローの脆弱性と新しく入る依存を検査する |
| ライセンス表記 | 同梱するOSS（csp\_evaluatorなど）のLICENSEとNOTICEを、`rollup-plugin-license`などで`dist/THIRD_PARTY_LICENSES.txt`に出力し、画面からリンクする。Viteはバンドル時にコメントを削除するため、別ファイルが必要 |
| 免責表示 | 画面の入力欄の上に、「自社管理または許可を得た対象のみ」「合格は安全性の保証ではない」「入力は外部送信されない」の3点を常時表示する |

### 非機能要件

| 項目 | 目標 |
| --- | --- |
| 対応ブラウザ | Chrome、Edge、Firefox、Safariの最新版 |
| アクセシビリティ | WCAG 2.1 AA。重要度を色だけでなく文字ラベルでも示す。キーボードだけで操作できる |
| 入力上限と性能 | 5MBまで。目安として1MBの入力を2秒以内で解析。HARは50MBまでで、必要な項目だけを取り出す。HARの目安は50MBを15秒以内とし、読み込み中は進捗を表示する |
| オフライン | 外部参照がないため、ページを開いたままならネットワークなしで動作する。再読込にはネットワークが必要（必要になればService Workerを検討） |
| 言語 | 日本語。英語UIはv0.4 |

### 画面設計

画面は「入力→HARのエントリ一覧（v0.3）→ターゲット一覧→結果→詳細→診断カバレッジ」の1ページ構成で、上から順に使います。何も入力していないときは、結果の欄に「①コマンドを作る→②自分の端末で実行する→③貼り付けて判定する」の手順を示し、コマンド生成器とサンプルへの入口を置きます。

| 領域 | 内容 | 操作 |
| --- | --- | --- |
| ヘッダ | ツール名、ツールとルールセットの版、免責表示（3点）、ライセンスへのリンク | — |
| 入力 | テキストエリア、ファイル読込（v0.3からHARも可）、URL入力欄（`#TARGET`がない入力用）、設定ファイル（例外ファイル、組織プロファイル、前回の結果のJSON）、言語の切り替え（v0.4） | 「判定する」ボタン、入力のクリア、プロファイルのひな形の保存。判定できたら、生の出力（Cookieやトークンを含む）を入力欄から隠し、画面共有への注意を表示する（「入力を表示する」で戻す）。入力があるときにサンプルを入れる場合は確認する |
| ターゲット一覧 | ターゲットごとにラベル、URL、応答の種類（html・api・other）、機密かどうか、重要度別件数。不足している予約ラベルと「HTTPS不明」を警告として表示。解析警告として、解釈できなかった行数、ターゲットにならなかったブロック、URL不明のターゲット、ok=errのTLS・暗号プローブ、HARの除外件数と機密情報の欠落も表示 | ターゲットの絞り込み、`kind`と`sensitive`の手動上書き |
| 結果表 | 項目ID、条件番号、重要度（色＋文字）、ステータス、ターゲット、短い説明。重要度順 | 重要度・ステータス・章での絞り込み、並べ替え。重要度「情報」の指摘は既定で隠し、切り替えで表示する（件数は重要度別の件数に常に出す） |
| 詳細 | 証跡（マスク済み）、推奨値、参考文献、根拠の版、該当するチェックリストの行 | 「例外に登録」（理由・承認者・期限を入力）。ターゲットごとに折りたたみ、情報以外の指摘があるものだけを開く。指摘は、判定（指摘→例外→判定不能→合格）、重要度、項目IDの順に並べる |
| エクスポート | Markdown、JSON、CSV、例外ファイル（`suppressions.json`） | ダウンロード |
| 診断カバレッジ | 項目ごとの区分（判定済み・入力不足・手動確認・未対応・対象外）、カバレッジ率、入力不足の理由と不足しているラベル・コマンド。下に第7章の範囲外項目 | 区分での絞り込み、不足分のコマンドの表示（v0.2のコマンド生成器と連携）。既定では「入力不足」の項目だけを表示する |
| HARのエントリ一覧（v0.3） | 対象ホストの選択、エントリごとのURL・ステータス・ラベル候補・機密かどうか | ラベルの確定・変更、sensitiveの上書き、エントリの除外 |

## ツール設計4：技術スタック・デプロイ・実装の対応

技術スタックはTypeScript＋Vite（フレームワークなし）＋Tailwind CSS v4＋Vitest＋Playwright（Node.js版）です。型付きのルール定義とVitestによるテストができ、外部CDNなしのバンドルにできるため、メタCSPと相性がよいからです。

- **UI**：フレームワークは使わず、素のTypeScriptでDOMを組み立てる1画面のSPAとする。入力由来の文字列は`textContent`と`createTextNode`で描画し、`innerHTML`は使わない（ツール設計3のセキュリティの表）。ルーティングは使わない。
- **CSS**：Tailwind CSS v4を`@tailwindcss/vite`で使い、ビルド時に静的CSSファイルを生成する（`src/styles.css`に`@import "tailwindcss";`）。SCSSは採用しない。ネストやカスタムプロパティなどSCSSの主要機能の多くは標準CSSで使え、CSSの方が転用性・汎用性・保守性が高いため。
- **テスト**：ユニットテストはVitest、E2EテストはPlaywrightのNode.js版（`@playwright/test`）。
- **CSPとの関係**：Viteの開発サーバはCSSを`<style>`で注入するため、メタCSPは本番ビルド時だけ挿入する（Viteプラグインの`transformIndexHtml`）。実行時に`<style>`を注入するTailwindのブラウザ版（`@tailwindcss/browser`）やCSS-in-JSは、`style-src 'self'`に抵触するため使わない。

### 構成

```
curl-sec-analyzer/
├─ index.html                 # UIの骨格（メタCSPは本番ビルドで挿入）
├─ run.sh                     # 簡易版の採取スクリプト（正式にはコマンド生成器を使う）
├─ src/
│  ├─ main.ts i18n.ts recommendationsEn.ts commands.ts mask.ts model.ts worker.ts styles.css sample.txt
│  ├─ ui/      state.ts dom.ts results.ts har.ts generator.ts dialog.ts
│  ├─ parser/  input.ts har.ts target.ts openssl.ts setCookie.ts
│  ├─ rules/   ruleset.ts util.ts headers.ts csp.ts cookies.ts cors.ts transport.ts hostRules.ts
│  │           exposure.ts html.ts api.ts cross.ts
│  ├─ engine/  run.ts labels.ts labels.json items.json coverage.ts suppress.ts profile.ts diff.ts summarize.ts
│  └─ export/  markdown.ts json.ts csv.ts
├─ scripts/screenshot.mjs     # README の画像を撮り直す（npm run screenshot）
├─ tests/                     # Vitest の単体テストと fixture（実際の curl 8.5.0・OpenSSL 3.0.13 の出力を含む）
├─ e2e/                       # Playwright の E2E と axe-core のアクセシビリティ検査（本番ビルドに対して実行）
├─ docs/design.md             # 設計書（正本）。docs/history.md はレビューの経緯、docs/screenshot.png は README の画像
├─ .github/                   # workflows/（checks・ci・deploy・codeql・dependency-review）、dependabot.yml、ISSUE_TEMPLATE/、pull_request_template.md
├─ SECURITY.md LICENSE README.md CONTRIBUTING.md
├─ csp.config.ts             # このツール自身の CSP（vite.config.ts が本番ビルドに埋め込む）
└─ vite.config.ts eslint.config.js playwright.config.ts tsconfig.json .gitattributes .editorconfig .nvmrc
```

### GitHub Actionsによるデプロイ

Settings→PagesでSourceを「GitHub Actions」にし、「Enforce HTTPS」を有効にします（独自ドメインの場合はDNS設定とドメインの検証も行います）。ワークフローは`.github/workflows/`にあり、検査は`checks.yml`（再利用するワークフロー）にまとめ、Pull Requestの`ci.yml`と公開の`deploy.yml`の両方から呼ぶ（検査の内容がずれないようにするため）。

- **Pull Request（`ci.yml`）とmainへのpush（`deploy.yml`）**：`npm ci --ignore-scripts`→署名の検証と`npm audit`→`npm run lint`（tsc と ESLint）→単体テスト→本番ビルド→E2E（外部へのリクエストがないこと、マスキング、埋め込みの拒否、アクセシビリティなどを含む）。E2EはChromium・Firefox・WebKit（Safari）の3つで実行する（スマートフォンの画面幅の検査は、エミュレーションに対応しないFirefoxを除く）。
- **共有用の情報（OGP）**：`index.html`に説明とOGPを置く。共有用の画像の絶対URLは、ビルドのときに環境変数`SITE_URL`で渡す。CIでは、APIを呼ばずにリポジトリの情報から`https://<組織名>.github.io/<リポジトリ名>`を組み立てる（追加の権限が要らず、Pagesを有効にする前でも失敗しないため。当初は`actions/configure-pages`で取得していたが、ビルドのジョブには`pages`の権限がなく失敗するおそれがあった）。独自ドメインの場合は、リポジトリの変数`SITE_URL`で上書きする。画像には説明（`og:image:alt`）を付ける。画像は`npm run screenshot`で`public/og.png`も撮り直す。
- **main への push**：上記が通ったら、E2E まで通ったのと同じ`dist`を GitHub Pages に公開する（検査していないビルドを公開しない）。公開は1つずつ行い、実行中の公開は取り消さない。
- **権限**：どのワークフローも既定の権限を`{}`で無効にし、検査は`contents: read`だけ。公開のジョブだけに`pages: write`と`id-token: write`を与える。checkoutで認証情報を残さない（`persist-credentials: false`）。
- **SHA固定**：外部のActionはすべてコミットSHAで固定し、末尾に`# vX.Y.Z`のコメントを書く。更新はDependabotが行う。
- **CodeQL・dependency-review**：公開リポジトリのときだけ実行する（privateではGitHub Advanced Securityが必要なため、スキップする）。
- **ワークフローの検査**：`.github/`の下のYAMLが構文として読めることと、ワークフローの主要な設定（権限、SHA固定、認証情報を残さないこと、検査の順序、ブラウザ、`SITE_URL`）を単体テストで確かめる（`tests/workflows.test.ts`）。当初のワークフローは、フロー形式`{ }`の中に`${{ }}`を書いていたためYAMLとして読めず、一度も動かない状態だった。

### エクスポートとテスト

- **エクスポート**：Markdown（重要度順の表。前回の結果を読み込んでいれば差分の表、組織プロファイルの名前も含める）、JSON（Findingの配列、ツールとルールセットの版、生成日時、組織プロファイル、例外一覧）、CSV（BOM付きUTF-8、第8章の列構成）。`Blob`と`URL.createObjectURL`で保存する。常にマスク済みで、生データは出力しない。CSVの「実施日時」「実施コマンド」は、指摘の元になったターゲットの`#META`から埋める（ホスト単位の判定は同じホストの`tls`・`probes`など、横断の判定は比べたラベルのターゲット。コマンドは重複を除いてつなぎ、日時は最も新しいもの）。
- **パーサのテスト**：fixtureごとにターゲット数、応答数、最終ステータス、Set-Cookie件数を検証する。実際の curl 8.5.0 と OpenSSL 3.0.13 の出力（ローカルのTLSサーバに対してコマンド生成器のスクリプトを実行したもの）も fixture にする。複数コマンドを続けて貼っても本文へ混入しないこと、`#`で始まる本文行や` *  `・` >  `で始まる本文行が本文として残ること、空白を含むContent-Typeを`#PROBE`から正しく読めること、複数ホストの結果をホスト単位で集約できることを確認する。HARでは、取り込み後のデータにリクエスト本文（postData。パスワードを含む）が残っていないことも確認する。
- **ルールのテスト**：条件ごとに、passとfailになる最小の入力を用意する。横断ルールは、予約ラベルが欠けたときにnaになることも確認する。
- **横断的なテスト**：既知の秘密情報を入力のあらゆる場所に置き、どの出力（画面用のデータ、Markdown、JSON、CSV）にも現れないことを確かめる（`tests/masking.test.ts`）。推奨対応と判定不能の理由の英訳の漏れを、ルールのソースコードの構文木から検出する（`tests/i18n.test.ts`）。案内する「必要なラベル」で実際に判定されることを確かめる（`tests/labels.test.ts`）。
- **アクセシビリティ**：axe-core（`@axe-core/playwright`）で、未入力・判定後・「情報」の表示・例外のダイアログ・コマンド生成器・英語UI・HARのエントリ一覧・ダークモード、スマートフォンの画面幅（390px）を検査し、軽微より重い違反がないことを確かめる（`e2e/a11y.spec.ts`）。スマートフォンの画面幅では、判定後にページが横にはみ出さないことも確かめる。表の枠は名前を持ち（`role="region"`と`aria-label`）、横にはみ出しているときだけフォーカスできる（`tabindex="0"`。画面幅や折りたたみの変化に合わせて判定し直す）。枠は`position: relative`にする（読み上げ用の非表示の文字が枠の外に出て、ページ全体の幅を広げた不具合があったため）。
- **性能と耐性**（`tests/robustness.test.ts`）：1MBの通常の出力の解析・判定時間（計測値は約0.5秒。CIの差を見込んで上限6秒で検査）。悪意のある入力（`*`の多い例外のURLパターン、閉じていないタグが大量にある本文）でも短時間で終わること。fast-checkで、curlの出力の行の部品を組み合わせた壊れた入力と、壊れたJSONの設定ファイル（例外、プロファイル、前回の結果、HAR）で例外を出さないこと。fast-checkは導入時に、例外ファイルの`[null]`で落ちる不具合を見つけた。前回の結果・組織プロファイル・例外ファイルにおかしな値を入れて組み合わせても、Markdown・CSVに`undefined`などが出ないことも確かめる。

### 実装の対応表

コードの詳細は設計書に写さず、ソースコードを正とします。設計書には方針・仕様・表だけを置きます。

| 設計書の節 | 実装 |
| --- | --- |
| 型（Target、Finding、Rule、Profile など） | `src/model.ts` |
| 入力モデル・パース（#TARGET、-i、-D -、-v、-L、header_json、openssl） | `src/parser/input.ts`、`src/parser/openssl.ts`、`src/parser/target.ts` |
| HAR形式の取り込み | `src/parser/har.ts`、`src/worker.ts` |
| ラベルと適用する項目、必要なラベル | `src/engine/labels.json`、`src/engine/labels.ts` |
| ルール（第1〜6章） | `src/rules/`（登録は`ruleset.ts`、CSPの振り分けは`csp.ts`、横断ルールは`cross.ts`、ホスト単位は`hostRules.ts`） |
| 評価の順序、二重減点の除去 | `src/engine/run.ts` |
| 組織プロファイル、例外登録、差分 | `src/engine/profile.ts`、`src/engine/suppress.ts`、`src/engine/diff.ts` |
| 診断カバレッジ、集計 | `src/engine/coverage.ts`、`src/engine/items.json`、`src/engine/summarize.ts` |
| マスキング、プローブの判定パターン | `src/mask.ts` |
| コマンド生成器 | `src/commands.ts` |
| 画面、英語UI | `src/main.ts`（入口）、`src/ui/`（結果、HAR、コマンド生成器、例外のダイアログ、状態）、`src/i18n.ts`、`src/recommendationsEn.ts` |
| エクスポート | `src/export/` |
| メタCSP、ライセンス一覧 | `vite.config.ts` |

## MVPとロードマップ

MVPでは、複数ターゲットの入力モデル、マスキング、例外登録、ルールセットの版管理までを入れ、実運用に耐える最小構成にします。期間は1人で3〜4週間が目安です。

| フェーズ | 範囲 |
| --- | --- |
| フェーズ0（最小構成） | MVPの前に、最後まで一度通す最小構成。貼り付け→パース（#TARGETのurl・label・sensitive、-i、-D -、-v）→約10ルール（H-01、H-03、H-08、H-12、C-01〜C-03、R-01、T-04など。実装ではHTML応答でよく使うH-06も加えて10項目にした）→結果表→マスキング→GitHub Pagesで公開。ラベル対応表、横断ルール、例外登録、Observatory互換スコアは含めず、ラベルに関係なく全ルールを全ターゲットに適用する（指摘の重複は許容）。T-04はURLがhttpで始まるターゲットで判定する。期間の目安は1人で1週間。fixtureは自社の検証環境と、わざと設定を甘くしたローカルサーバから採取する |
| MVP | 貼り付けとファイル読込。`#TARGET`（`label`・`kind`・`sensitive`）・`#META`・`#PROBE`・`#TLSPROBE`による入力モデルと予約ラベル。`-i`、`-D -`、`-v`、`-L`に対応するパーサ（1xx、CONNECT、重複ヘッダ、obs-fold、本文への混入防止、本文中の`#`・`*`行の保持）。URLとHTTPSの導出、API判定、機密応答の判定、ホスト単位の集約。ルールはH系全項目（H-07③はE-07に依存するためv0.2）、C-01〜C-10・C-12・C-13（C-07②・C-09・C-12は横断ルール。H-02③・H-04⑤の横断ルールも含む）、R-01〜R-07、T-04、T-05、T-07②、T-08、T-09（①は`#TLSPROBE`、②はC4）、E-03、A-09。診断カバレッジの表示、マスキングとプローブ内容の非表示、例外登録（JSONのインポート・エクスポート）、ルールセットの版と根拠、Markdown・JSONエクスポート。画面設計どおりのUI、メタCSP、免責表示、ライセンス表記、Vitest、Actionsによるデプロイ（SHA固定は後に対応） |
| v0.2 | コマンド生成器（C1〜C26を`#TARGET`付きで出力。各ターゲットの直後に`#META at=… cmd=…`を出し、CSVの「実施日時」「実施コマンド」を埋める。WebSocketのパスを入れたときだけC16を出す。DELETEなどデータを消しうる試験は作らない）。opensslパーサ（証明書の期限・SAN・チェーン・鍵長・署名。T-10②、T-11）と、`-cipher`による個別確認の取り込み（C23の#CIPHERPROBE。T-10①③）。C10（`header_json`）の取り込み。HTML本文のルール（E-07〜E-10、E-12）、E-01・E-02・E-04・E-05・E-06・E-11・E-13、T-01、T-06、T-12。CSVエクスポート |
| v0.3 | APIモードの拡充：A-01〜A-03、A-07、A-08、A-10、A-11、JWTのデコード、API Top 10との対応表示。C-11、R-08、R-09。HAR形式の取り込み（対象ホストの選択、ラベル付与の画面、リクエスト本文の破棄） |
| v0.4 | 修正前後の差分表示、組織ごとの重要度プロファイル、英語UI |
| v1.0 | ASVS 5.0とIPAの項目番号への対応付け（範囲は実装済み。ツールの版は0.xのまま。下の「版の付け方」）。当初予定していたCLI版は作らない（判断の根拠14） |
| 手動確認（ツール対象外） | T-02、T-03、T-07①③、T-13、C-14、C-15、A-04〜A-06。T-03、T-07①③、T-13、A-04〜A-06はツールが取り込み結果を表示するだけで、T-02、C-14、C-15はツールでは扱わない。いずれも合否は人が判断し、第8章の様式に記録する |

**版の付け方**：表の「v0.2」〜「v1.0」は機能の段階（マイルストーン）の名前で、ツールの版（`package.json`の`version`）とは別に扱う。v1.0の範囲は実装済みだが、ツールの版は当面0.xのまま（0.4系）とし、1.0.0として出す時期は別に決める（2026-11-12）。ルールセットの版（`RULESET_VERSION`）は`年.月-v<ツールの版>`の形で、判定の範囲や条件を変えたときに、そのときのツールの版に上げる。

どのフェーズにも割り当てていない項目はありません。`-v`だけで分かるのは合意したバージョンと暗号だけなので、旧TLSの受け入れ（T-09①）は`#TLSPROBE`で、弱い暗号・鍵（T-10）はv0.2のopenssl対応で判定します。

## 判断の根拠・要確認事項・出典

主な設計判断は下記14点で、数値や版のうち未確認のものは「要確認事項」にまとめています。

### 判断の根拠

1. **HSTSのpreloadは既定で推奨しない**：hstspreload.orgがpreloadを既定で付けないよう求めているため。preloadなしは情報、条件を満たさないpreloadだけを低とする（H-02）。
2. **X-XSS-Protectionは「付いていると指摘」の向きで扱う**：古いObservatory CLIは未実装を減点していたが、現行のOWASPは`0`か送らないことを推奨している（H-17）。IPA「安全なウェブサイトの作り方」改訂第7版の5-(x)は`X-XSS-Protection: 1; mode=block`を勧めているが、主要なブラウザがXSSフィルタを廃止したため、本書はOWASPに従い、IPA 5-(x)をH-17に対応付けない。
3. **CSPの評価はcsp\_evaluatorを使う**：Apache-2.0で配布の制約が小さい。ObservatoryのコードはMPL-2.0の義務が生じるため、配点の考え方だけを参考にする。
4. **API応答には評価軸を切り替える**：OWASP REST Security CSが勧める`no-store`、`frame-ancestors 'none'`、`nosniff`、正しいContent-Typeを中心にし、HTML向けヘッダでは減点しない（第0章 0.3、A-09）。
5. **レート制限ヘッダは「兆候」としてだけ扱う**：IETFの`RateLimit`/`RateLimit-Policy`はまだInternet-Draftで仕様が変わっているため（A-04）。
6. **ライセンスはMIT**：短く、利用者にも貢献者にも分かりやすいため。依存パッケージのライセンス一覧はビルド時に生成し、画面から参照できるようにする。
7. **設計書の正本はリポジトリの`docs/design.md`**：実装と同じコミットで直せるため、設計と実装のずれが起きにくい。
8. **Observatory互換スコアは実装しない**：配点が未確認のまま点数を出すと誤解を招くため。主な指標は重要度別の件数とする（v1.0以降で再検討）。
9. **コマンド生成器はデータを消しうる試験を作らない**：チェックを付けたまま本番で実行する事故を防ぐため、DELETE は生成せず手順書に書くだけにする。メソッド上書き（T-03）の確認も、上書き先に副作用のない OPTIONS を使う。
10. **英語UIでは推奨対応だけを英訳する**：証跡は応答から取った値と短い説明なので日本語のままとし、利用者が行動を決める推奨対応を優先した。英訳は`src/recommendationsEn.ts`で管理し、訳漏れはテストで検出する。CSV（第8章の記録様式）は日本語のまま。
11. **差分は、curlはラベル、HARはメソッドとURLで突き合わせる**：curlはラベルを診断者が付けるので安定している。HARはラベルの番号が記録し直すたびに変わるため。前回と組織プロファイルが違う場合は警告する。
12. **A-10（エラー形式）は`error-*`ラベルのAPIのエラー応答だけを比べる**：ブラウザ向けのHTMLのエラーページや、`unauth-*`の401などまで比べると、正しい設計でも「統一されていない」と出るため。HTMLのエラーページの情報露出はE-01で判定する。
13. **専用の組織アカウントで管理・公開する**：他のGitHub Pagesとオリジンを分けるため（無料）。一時は「実績として個人のプロフィールに並べる」ために個人アカウントを検討したが、組織の公開リポジトリでも、①自分がコミットしたリポジトリは個人のプロフィールにピン留めでき、②コミットは個人のコントリビューションのグラフに反映され、③組織のメンバーシップを公開にすればプロフィールに組織のアイコンが出るため、オリジンを分けられる組織アカウントに戻した。
14. **CLI版は作らない**：ブラウザだけで使う運用のため。判定の部分（`src/parser`・`src/rules`・`src/engine`・`src/export`）は画面の部品に依存しないまま保ち（単体テストはNode.jsで実行している）、CIでの自動検査が必要になったときにCLIの入口を足せるようにしておく。

### 要確認事項

- [x] ASVS 5.0の章構成と項番（CookieがV3、セッション管理がV7か）をOWASP/ASVSリポジトリで確認し、第2章の項番を対応付ける（v1.0：`v5.0.0`タグで確認。CookieはV3.3、セッション管理はV7。全項目を対応付けた）
- [x] ASVS 5.0との基準の差をどう扱うか決める：HSTSのmax-age（ASVS 3.4.1は1年以上、H-01②は6か月未満で中）と、セッションIDのエントロピー（ASVS 7.2.3は128bit以上、C-07①は64bit未満で高）（既定値をASVSに合わせて上げた。ツール設計2「ASVS 5.0・IPAとの対応」）
- [ ] Mozilla Server Side TLSの最新版（v5.7より新しい版があるか）を確認する
- [ ] MDN HTTP Observatoryの現行の配点と最高点（MDNの「Tests & Scoring」は145、旧版scoring.mdは135）をソースで確認する（互換スコアを再検討するときだけ必要）
- [ ] Trusted Types（`require-trusted-types-for`）の各ブラウザの対応状況を確認する
- [x] GitHub Actionsの各アクションの最新メジャーバージョンとコミットSHAを確認する（2026-11-16：各タグのSHAを`git ls-remote`で確認して固定した。以後の更新はDependabot）
- [ ] 貼り付け型OSS（3件）のライセンスを確認する（コードを流用する場合）
- [ ] curlが`-v`や`-i`でHTTP/2・3のヘッダ名を小文字で表示するかは公式文書で明言されていない。パーサは大文字小文字の両方を受け付ける前提を維持する
- [ ] `openssl s_client`がハンドシェイク失敗時に0以外を返すか、成功時に`Protocol  : TLSv1.x`行を出すか（OpenSSL 1.1系・3系）を確認する。C12の判定はこの前提に依存している
- [ ] ChromeのプリフライトMax-Ageの上限（7200秒、R-05②の根拠）を確認する
- [ ] curlの`-v`出力の行形式（`* Host ... was resolved`、`* Connected to`、`* SSL connection using`など）が利用するcurlのバージョンで変わらないか確認する（パーサの`VERBOSE_HINT`の前提）
- [ ] 出典のURL（OWASP Cheat Sheet、WSTG、RFC 9116・9457、PortSwigger、IPA公式）を開いて、リンク切れと内容を確認する
- [x] IPAの項番（1-(iii)、4-(i)〜(vi)、5-(viii)・(ix)、6-(i)、7-(i)、9-(i)）とASVS 4.0.3の項番（V3.2.1、V3.2.2、V3.3.1、V3.3.2、V3.4.4、V3.4.5）を原典で確認する（v1.0：IPAは改訂第7版のPDFで確認し、4-(iv)・6-(i)・7-(i)・9-(i)は枝番（-a・-b）まで付けた。ASVS 4.0.3の項番は5.0.0に置き換えた）
- [ ] C23で使う暗号名（OpenSSLの表記）と、`openssl s_client`の`Cipher :`行の形式を確認する
- [ ] プローブの判定パターン（.DS\_Store、web.xml、phpinfo、server-status、ソースマップなど）が先頭64バイトで判別できるかを、実際の応答で確認する。任意のパスにJSONを返すAPIでは、package.jsonなどのパターンが誤検知しないかも確認する
- [ ] 各ブラウザ（Chrome、Edge、Firefox、Safari）のHARの書き出しで、Cookie・Set-Cookie・Authorizationや応答本文が既定で含まれるか、含めるにはどう操作するかを確認する。HAR 1.2の仕様（`redirectURL`、`content.encoding`など）との差も確認する

レビューの指摘と対応の経緯は`docs/history.md`にまとめています。

### 出典

- [OWASP Secure Headers Project：Response Headers](https://owasp.github.io/www-project-secure-headers/response-headers/)
- [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)、[Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)、[File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)、[Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)、[CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)（V3 Web Frontend Security、V7 Session Management など。CC BY-SA 4.0）
- [Mozilla HTTP Observatory scoring.md（旧版）](https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md)、[@mdn/mdn-http-observatory](https://www.npmjs.com/package/@mdn/mdn-http-observatory)
- [csp\_evaluator（npm）](https://www.npmjs.com/package/csp_evaluator)、[web.dev：Strict CSP](https://web.dev/articles/strict-csp)、[W3C CSP Level 3](https://www.w3.org/TR/CSP3/)
- [hstspreload.org](https://hstspreload.org/)
- [PortSwigger Web Security Academy：CORS](https://portswigger.net/web-security/cors)、[HTTP Host header attacks](https://portswigger.net/web-security/host-header)、[Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)
- [Mozilla Server Side TLS](https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS)
- [IETF draft：RateLimit header fields](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers)、[RFC 9114（HTTP/3）](https://datatracker.ietf.org/doc/html/rfc9114)、[RFC 9116（security.txt）](https://www.rfc-editor.org/rfc/rfc9116)、[RFC 9457（Problem Details）](https://www.rfc-editor.org/rfc/rfc9457)
- [curl man page](https://curl.se/docs/manpage.html)、[everything curl：Verbose](https://everything.curl.dev/usingcurl/verbose/index.html)
- [GitHub Community Discussion #54257（PagesのHTTPヘッダ）](https://github.com/orgs/community/discussions/54257)
- [ISOG-J 活動成果](https://isog-j.org/activities/result.html)、[IPA「安全なウェブサイトの作り方」](https://www.ipa.go.jp/security/vuln/websecurity/about.html)
- [MDN Web Docs：HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)、[Chrome Lighthouse：Ensure CSP is effective against XSS attacks](https://developer.chrome.com/docs/lighthouse/best-practices/csp-xss/)
