# Web/API自主セキュリティ診断チェックリストとcurl診断ツール設計

> **この文書の扱い**：このファイル（リポジトリの `docs/design.md`）を設計書の正本とします。仕様を変えるときは、実装と同じプルリクエストでこのファイルも直してください。レビューの経緯は`docs/history.md`に書きます。

## 注意書きとTL;DR

curlとopensslの出力で判定できる「設定系」の項目は本書のチェックリストで確認し、「動作系」の脆弱性はOWASP ZAPやBurp Suiteで別に診断します。診断ツールは、対象に一切アクセスせず、貼り付けた出力をブラウザ内だけで解析する静的サイト（GitHub Pages）として作ります。

**注意**：診断は、自社で管理しているシステムか、書面で許可を得たシステムだけを対象にしてください。Origin偽装、メソッド試行、既知ファイル探索、ヘッダインジェクション試験は、可能な限り自社の検証環境で行います。

- **範囲**：ヘッダ、Cookie、CORS、リダイレクト、TLS、情報露出、ヘッダインジェクション、HTML本文、WebSocketのOrigin検証、APIの応答。SQLi・XSS・認可不備などは範囲外（第7章）。
- **重要度**：第0章の定義に従い、各項目の「NG判定基準」の条件（①②…）ごとに1つだけ割り当てる。幅のある値（「中〜高」など）は使わない（例外はH-04⑥で、csp_evaluatorの重要度に従う）。ツールのルールIDは`項目ID.条件番号`（例：H-01.1）で、条件番号と一対一に対応する。
- **非推奨ヘッダ**：X-XSS-Protection、Expect-CT、Public-Key-Pins、Feature-Policy、Pragmaの5つは「付いていないこと」を確認する（H-17）。
- **ツール**：入力は`#TARGET`マーカーで対象URLごとに区切る。「ログイン前・ログイン時・ログアウト」は予約ラベルで、「機密応答かどうか」は`sensitive`属性でツールに伝える。主な指標は重要度別の件数とする。Mozilla HTTP Observatory互換スコアは作らない（判断の根拠8）。判定できなかった項目は診断カバレッジとして示す。ブラウザのHAR形式も取り込める。CSPの解析にはGoogle `csp_evaluator`（Apache-2.0）を使う。
- **最大の制約**：GitHub Pagesは独自のHTTPヘッダを返せない。ツール自身のCSPは`<meta>`で設定し、frame-ancestorsなどが使えない分は、innerHTML禁止、`connect-src 'none'`、マスキングで補う。

### 重要度「高」になる条件の一覧（本文の表から抽出）

| 章 | 項目IDと条件 |
| --- | --- |
| 第1章 ヘッダ | H-01①③ HSTSがない・解釈できない、H-03①③ 強制モードのCSPがない・解析できない、H-04①②⑤ script-srcの'unsafe-inline'・ワイルドカード・固定nonce、H-12① 機密応答にno-storeがない |
| 第2章 Cookie | C-01① セッションCookieにSecureがない、C-02① セッションCookieにHttpOnlyがない、C-07①② セッションIDが推測可能、C-09① セッション固定化・② URLにセッションID、C-10① HTTP応答でSecureなしのセッションCookieを発行、C-12① ログアウト後もセッションが有効、C-13① セッションCookieを共有キャッシュ可能な応答で発行 |
| 第3章 CORS | R-01① Origin反射＋資格情報許可、R-02① null許可＋資格情報許可、R-03① 部分一致の不備＋資格情報許可、R-09① Cookie認証のWebSocketが任意のOriginで接続できる |
| 第4章 メソッド・通信・TLS | T-02① PUT/DELETEで作成・削除できる、T-04① HTTP→HTTPSリダイレクトがない、T-07①③ Hostヘッダが再設定リンクやキャッシュに反映、T-08① CRLFインジェクション、T-09① TLS 1.0/1.1で接続できる、T-10①② 弱い暗号・鍵、T-11① 証明書の期限切れ・不一致、T-13① X-Forwarded-Forなどの偽装でIP許可リストを回避できる |
| 第5章 情報露出・HTML本文 | E-01① エラーに認証情報、E-03① /.git・/.envなどの中身を取得できる、E-05① 管理機能が未認証、E-06① 認証付きデータのJSONP、E-09① 本文に秘密情報、E-10① パスワードフォームの送信先がhttp、E-11① アップロードファイルをHTMLとして配信 |
| 第6章 API | A-01①③ 未認証で保護データを取得できる・HTTPでBasic認証、A-02① URLにトークン、A-03① JWTがalg:none、A-07① パスワードハッシュなどの露出 |

## 第0章 前提・重要度・実施手順

診断は下記の基準と重要度の定義で判定し、実施手順の順に進めます。

### 0.1 基準と版

| 基準 | 版 | 本書での扱い |
| --- | --- | --- |
| OWASP ASVS | 5.0.0（2025年5月30日、全17章） | 関連する要件のIDを参考文献列に「ASVS 5.0.0 3.4.1」の形で記載（ツール設計2「ASVS 5.0・IPAとの対応」） |
| OWASP API Security Top 10 | 2023年版 | 第6章の対応付け |
| ISOG-J/OWASP Japan Webアプリケーション脆弱性診断ガイドライン | 第1.2.4版（2023年11月） | 情報露出・範囲外項目 |
| IPA 安全なウェブサイトの作り方 | 改訂第7版（2021年3月、第4刷） | 項番（4-(iii)、2.3-1)など）を参考文献列に記載（原典で確認済み） |
| OWASP Secure Headers Project、Cheat Sheet Series | 2026-10時点の最新 | ヘッダの推奨値とActive/Deprecatedの区分 |
| Mozilla Server Side TLS | v5.7として参照 | 最新は6.0（2026-11-18に確認。5.8でIntermediateからDHEを外し、6.0でOldを廃止）。T-10のDHEの扱いは判断の根拠15 |
| MDN HTTP Observatory | 2026-10時点の最新 | テストの分け方の参考。互換スコアは作らない（判断の根拠8） |

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
- 同じ事象は1つの項目でだけ減点する（例：JSONをtext/htmlで返す件はA-09①で判定し、H-13では扱わない。H-17②は常に情報なので、他の項目と重なっても重要度別の件数は重複しない）。重なる項目の組と、どちらで判定するかはツール設計2「ターゲット横断ルールと評価の順序」の重複の表にまとめる。

### 0.3 採取対象とAPI応答の扱い

- 最低限、次の応答を採取する：トップページ（HTML）、`http://`でのトップページ、apexドメイン（wwwを使う場合）、ログイン前のログイン画面、ログイン処理の応答（Set-Cookie）、ログイン後のページ、APIエンドポイント（JSON）、エラー（404/500）、ログアウト応答、ログアウト後に旧Cookieで認証後ページへアクセスした応答。
- セキュリティヘッダは200応答には付いていても、リダイレクトやエラーの応答で抜けていることが多い。各応答を別のターゲット（`#TARGET`）として評価する。
- **API応答の判定**：Content-Typeが`application/json`、`application/*+json`、`application/problem+json`ならAPI応答とみなす。API応答では、HTML向けの項目（H-03〜H-07、H-09、H-10、H-11、H-14）の重要度を「情報」に下げる。理由は、OWASP Secure Headers Projectが、ブラウザ以外のクライアントによるこれらのヘッダのサポートは標準化されていないとしているため。代わりにA-09（JSON応答のヘッダ）を適用する。
- **機密応答の判定**：H-11①、H-12①②、R-04①、R-08①、R-09①、E-06①、E-12①は「機密応答かどうか」で判定が変わる。ツールは、①`#TARGET ... sensitive=1`または`sensitive=0`の明示（`true`・`yes`・`false`・`no`も受け付け、読めない値は警告して明示がないものとする）、②明示がなければ送信側にAuthorizationか、セッションCookieらしい名前（第2章の推定。組織プロファイルの指定があればそれ）のCookieがある場合（`-v`の` >  `行とHARのリクエストで確認）は機密（`_ga`・`theme`のような解析用・設定用のCookieだけでは機密としない。curlとHARで同じ判定にする）、③どちらでもなければ「分からない」、の順で決める。分からないときは、機密応答を前提とする条件（①）を判定しない。H-11①・H-12①②・R-08①・R-09①・E-12①はnaにする。R-04とE-06は、`*`やJSONPがあること自体は確かなので、より弱い条件（R-04③・E-06②）として出し、根拠に「機密応答かどうか分からない」と書く。診断者は認証後ページと個人情報を含むAPIに`sensitive=1`を付ける。
- **静的リソースの扱い**：H-11①・H-12①②・R-04①・R-08①は、静的リソース（URLのパスの末尾の拡張子（クエリは見ない。`/api/me?avatar=me.png`は静的リソースではない）、またはContent-TypeがJS・CSS・画像・フォント・動画・音声・WebAssembly（拡張子は`.mp4`・`.webm`・`.mp3`・`.ogg`・`.wasm`・`.eot`なども））と、誰にでも同じ内容を返す公開ファイル（`robots.txt`、`sitemap*.xml`、`favicon.ico`、`ads.txt`、`humans.txt`、`security.txt`、`crossdomain.xml`、`manifest.json`、`*.webmanifest`、`/.well-known/`の下）を、`sensitive=1`を明示したときだけ機密応答として扱う。Cookieを送っただけ（上の②の推定）では機密としない。ブラウザは静的リソースや公開ファイルにもセッションCookieを送るため、長くキャッシュさせる静的リソースがすべてH-12①（高）になったり、CDNから`*`で配るJS・フォントがR-04①になったりするのを防ぐ。ただし`?callback=`・`?jsonp=`を持つURL（JSONP）は、Content-TypeがJSでも利用者ごとのデータを返すので静的リソースとしない（E-06は常に機密応答の判定に従う）。H-12は、静的リソースで`Cache-Control`がなければ③（情報）とする。E-01は静的リソースの本文を見ない（圧縮したJSの文字列の`ORA-`や例外の名前はエラーの詳細ではない）が、エラーの応答（4xx・5xx）と、HTML・JSONを返した応答（`/img/missing.png`の500のエラーページ）は、URLの拡張子によらず見る（パスだけで除くと、そのスタックトレース・接続文字列（①（高））を見逃す）。
- **ラベル**：ラベルはターゲットの目的を表し、ツールはラベルごとに適用する項目を絞る。一覧はツール設計1「ラベルと適用する項目」。

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

HARを使う場合は、手順5〜8のうち、ログイン前後、認証後のページとAPI、ログアウトをブラウザで操作してHARに書き出せます。`after-logout`（旧Cookieでのアクセス）、`session-sample-*`、TLS、既知ファイル、CORS、ヘッダインジェクションは、HARには入らないためcurlで別に採取します（ツール設計1「HAR形式の取り込み」）。

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
| H-01 | Strict-Transport-Security | C1（https）。HTTP応答のHSTSはブラウザが無視するため判定に使わない | `max-age=63072000; includeSubDomains` | ①ない・`max-age=0`（ブラウザにHSTSの記録を消させる指定） ②max-ageが31536000（1年）未満 ③構文を解釈できない ④includeSubDomainsがない（③は、RFC 6797 6.1のとおりに`;`で分けたディレクティブを読み、構文の誤り（カンマ区切り、`;`のない区切り）・同じディレクティブの重複・数字でないmax-ageのあるヘッダ。ブラウザはこのヘッダを無視する。C-01②③のホストのHSTSも同じ読み方）。`apex`は、apex自身のhttpsの応答（ホストがapexのホップ）のHSTSで見る。apex自身のhttpsの応答がないもの（httpで採取して`-L`でwwwへ転送したもの）は、wwwのHSTSで判定せずna（H-02も同じ） | SSLストリッピング、Cookieの盗聴 | ①高 ②中 ③高 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.1、IPA 2.3-1) |
| H-02 | HSTS preload | C1（label=apexのターゲットとwwwのターゲット）。スキームが分からない（URLがない）ときはna（H-01と同じ）。apexの見方はH-01と同じ（`-L`やHARでwwwへの転送をたどった最後の応答はwwwのもの） | preloadを付けるならmax-age 31536000以上＋includeSubDomains。apexはhttpsの同一ホストに転送し、apex自身もHSTSを返す | ①preloadがあるのに条件不足 ②preloadなし（HSTSの構文が誤っていれば、ブラウザが無視するのでH-01③で判定し、H-02はna） ③preloadを付けているのにapexがHSTSを返さない（`max-age=0`も返さないのと同じ。preloadを付けたのがapexのドメイン（apex自身かそのサブドメイン）のときだけ。別のサイトのpreloadでは判定しない。httpで採取してhttpsのapexに転送したものは、そのhttpsのホップで見る。apexのhttpsの応答がなければ、HSTSを返すかが分からないのでna） | 登録拒否。登録後の取り消しに数か月かかる | ①低 ②情報 ③低 | hstspreload.org、ASVS 5.0.0 3.7.4 |
| H-03 | CSP（存在・強制） | C2（本文を含む採取。C1の`-D - -o /dev/null`では`<meta>`のCSPが分からないのでna）。`Content-Security-Policy`と`-Report-Only`を全件抽出 | 強制モードのCSPが1つ以上。HTMLの応答で、強制モードのヘッダが効かず（ない・Report-Onlyのみ・ディレクティブがない）、本文も採取していなければ（`-D - -o /dev/null`、`-v`）、metaのCSPがあるかが分からないのでna（JSONのAPIの応答は①を情報に下げ、①〜③はA-09③として数える。ツール設計2の二重減点の除去）。`<body>`の位置は、`<head>`の中のコメントとスクリプトの中の`<body>`を飛ばして探す。ヘッダがなくても、HTMLの`<head>`の中（`<body>`より前）の`<meta http-equiv="Content-Security-Policy">`のCSPがあれば、ブラウザは強制するので①②にしない（GitHub Pages・S3などヘッダを付けられない配信では普通の形）。ヘッダがあっても、どのポリシーにもディレクティブがない（空の`Content-Security-Policy: `）ときは、効くのはmetaのCSPだけなので、metaのCSPで判定する（③にしない）。H-04・H-05・H-07とH-04⑤（固定のnonce）もmetaのCSPで判定する。frame-ancestors・report-uri・report-to・sandboxはmetaでは効かないので除き、H-06はヘッダだけで見る | ①ない ②Report-Onlyのみ ③解析できない（ヘッダ値のどのポリシーにもディレクティブがない。カンマのあとのかけら（`report-uri`のURLの中のカンマ、`img-src 'self', data:`）だけが読めなくても、前のポリシーは効くので③にしない。読めないかけらは評価から除く。③は、どのヘッダ値にもディレクティブがないときだけ（空のヘッダが1つあっても、ほかのヘッダのポリシーは効く））。`<template>`・`<noscript>`の中とスクリプトの文字列の中の`<meta>`のCSPは、ブラウザが要素として使わないので数えない | XSSの影響が軽減されない | ①高 ②中 ③高 | OWASP CSP CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.3 |
| H-04 | CSP：script-src | csp\_evaluatorで解析。複数CSPはポリシーごとに評価（ただし、ほかのポリシーが同じ条件の指摘なしにスクリプトを制限していれば（`script-src`か`default-src`がある）、そのポリシーの①〜④・⑥は出さない。ブラウザはすべてのポリシーを満たすものだけを許すため） | nonceまたはhash＋`'strict-dynamic'` | ①`'unsafe-inline'`（nonce/hashなし） ②`*`、`https:`、`http:`、`data:`（`script-src`も`default-src`もないものも②） ③`'unsafe-eval'` ④JSONP・AngularJSを提供するホストを許可 ⑤nonceが応答ごとに変わらない（C24で同じURLを2回取得して比較。`<script>`の要素に効くディレクティブ（CSP3のとおり`script-src-elem`、なければ`script-src`、なければ`default-src`）のnonceだけを比べ、2つ以上の応答に同じnonceがあれば⑤。`style-src`の固定のnonceと、`script-src`があるときの`default-src`の固定のnonceでは⑤にしない。`'nonce-'`の部分は大文字・小文字を区別しない） ⑥csp_evaluatorのその他の指摘（nonceが短い（中）、IPアドレスでの許可（情報）、`'unsafe-hashes'`（情報。イベントハンドラに効くディレクティブ（`script-src-attr`、なければ`script-src`、なければ`default-src`）にあり、同じディレクティブにハッシュがあるときだけ。ハッシュがなければ何も許さないので出さない。ほかのポリシーがハンドラを止めていれば（`'unsafe-hashes'`も`'unsafe-inline'`もない）出さない）） | XSSの回避 | ①高 ②高 ③中 ④中 ⑤高 ⑥中または情報（csp_evaluatorの重要度に従う） | Google CSP Evaluator、web.dev Strict CSP、ASVS 5.0.0 3.4.3 |
| H-05 | CSP：object-src・base-uri | 同上 | `object-src 'none'`、`base-uri 'none'`または`'self'` | ①object-srcもdefault-srcも未制限 ②base-uri未指定（default-srcにフォールバックしない）か、`*`・スキームだけ（`https:`・`data:`）の指定（どの`<base>`も止めない。制限するbase-uriのあるポリシーが1つあれば満たす）（csp_evaluatorが解析できないポリシー（`img-src data:image/png`など）があり、①②がなければ、object-srcの問題を見逃しているかもしれないので合格にせずna。H-04と同じ。ただし`object-src 'none'`と制限する`base-uri`のあるポリシーが1つでもあれば合格（ポリシーは重ねて効く）） | プラグイン経由の実行、`<base>`注入 | ①中 ②中 | Chrome Lighthouse csp-xss、ASVS 5.0.0 3.4.3 |
| H-06 | クリックジャッキング対策（frame-ancestors・X-Frame-Options） | 同上＋XFOヘッダ | `frame-ancestors 'none'`または`'self'`。旧ブラウザ向けにXFO `DENY`/`SAMEORIGIN`を併用 | ①両方ない・XFOの値が不正（`ALLOWALL`や綴りの誤り。ブラウザは無視する） ②XFOが`ALLOW-FROM`のみ（モダンブラウザ非対応） ③frame-ancestorsがなくXFOのみ ④frame-ancestorsが広い（`*`、`https:`などのスキームだけ、`*.example.com`、ホストが`*`だけのもの（`https://*`・`*:443`・`https://*:*`）。XFOより優先されるので、XFOが`DENY`でも守れない。frame-ancestorsを指定したポリシーが複数あれば、すべてが広いときだけ④。1つでも狭いものがあれば、埋め込みはそれで制限される）。XFOはHTML Standardの手順で読む（すべての値をカンマで分けた小文字の集合。2つ以上で`deny`・`sameorigin`・`allowall`のどれかを含めば拒否、同じ値の繰り返しは1つ） | クリックジャッキング | ①中 ②中 ③情報 ④中 | MDN、OWASP Secure Headers、ASVS 5.0.0 3.4.6、IPA 9-(i)-a |
| H-07 | CSP：非推奨ディレクティブ・混在コンテンツ・構文 | 同上 | 報告は`report-to`。混在コンテンツがあるなら`upgrade-insecure-requests` | ①`block-all-mixed-content`、`referrer`、`plugin-types`、csp_evaluatorが非推奨とする`reflected-xss`・`disown-opener`・`prefetch-src` ②`report-uri`のみ ③混在コンテンツ（E-07）があるのに`upgrade-insecure-requests`なし（httpのページは対象外。E-07と同じ） ④構文の誤り（不明なディレクティブ、キーワードの引用符、セミコロン、nonceの文字種。csp_evaluatorの構文検査） | 防御が効いていない | ①低 ②情報 ③低 ④低 | W3C CSP3、OWASP Secure Headers、ASVS 5.0.0 3.4.3, 3.4.7, 12.2.1 |
| H-08 | X-Content-Type-Options | C1 | `nosniff` | ①ない・値が不正（Fetch Standardのとおり、すべての値をカンマで分けた最初の値で見る。プロキシが付け足した`nosniff, nosniff`は合格。A-09②も同じ。本文のない204・304はna（H-11・H-12と同じ）。Locationのある3xxと`Content-Length: 0`の応答も、スニッフィングする本文がないのでna） | MIMEスニッフィングによるXSS | ①中 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.4 |
| H-09 | Referrer-Policy | C1 | `strict-origin-when-cross-origin`、`strict-origin`、`same-origin`、`no-referrer` | ①`unsafe-url` ②`no-referrer-when-downgrade`、`origin`、`origin-when-cross-origin` ③ない（現行ブラウザの既定はstrict-origin-when-cross-origin） ④不正な値（本文の`<meta name="referrer">`は、その位置から文書の方針を上書きする（metaより前に読み込んだ画像・スクリプトにはヘッダや前のmetaの方針が効く）ので、metaがあれば、ヘッダとmetaのうち最も弱いもので①②を判定する。`<script>`などテキストの要素の中身と`<template>`の中のmetaは、ブラウザが使わないので見ない。metaの古い値（`never`・`always`・`default`・`origin-when-crossorigin`）はHTMLの仕様どおりに読み替える。ヘッダの古い値は、ブラウザと同じく知らない値として無視する） | URL内のトークンや個人情報の外部漏えい | ①中 ②低 ③情報 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.5 |
| H-10 | Permissions-Policy | C1 | 使わない機能を無効化（例：`camera=(), microphone=(), geolocation=()`） | ①ない（Structured Fieldの辞書として読めない値（Feature-Policyの書き方の`camera 'none'`、大文字の`Camera=()`）は、ブラウザがヘッダ全体を捨てるので①） ②旧`Feature-Policy`のみ | 埋め込まれた第三者による機能の悪用 | ①情報 ②低 | OWASP Secure Headers |
| H-11 | COOP・COEP・CORP | C1 | COOP `same-origin`。COEPは分離が必要なら`require-corp`または`credentialless`。CORP `same-origin`/`same-site` | ①機密応答（0.3）にCORPなし ②COOPなし（守りにならない値（CORPの`cross-origin`、COOPの`unsafe-none`）と、読めない値（知らない値・2つ以上の値）は、ないのと同じに扱う） ③分離が必要なのにCOEPなし（手動確認。ツールは判定しない）。機密応答かどうか分からず、守りになるCORP（`same-origin`・`same-site`）もなければ、①を判定していないので、COOPがあっても合格にせずna。値は大文字・小文字を区別する（`Same-Origin`はブラウザが読めない）。本文のない応答（204・304）とLocationのある3xx（ブラウザは転送先を読み込む）はna | XS-Leaks、Spectre系攻撃 | ①低 ②情報 ③低 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.8, 3.5.8 |
| H-12 | Cache-Control | C1（認証後ページ、API、ログイン応答）。機密かどうかは0.3の判定に従う | 機密応答は`no-store`（本文のない応答（204・304）は対象外。H-11も同じ） | ①機密応答にno-storeがない（鮮度の指定（`max-age`・`s-maxage`・`public`・`Expires`）のない、経験的にキャッシュしてよいステータス（200・203・204・206・300・301・308・404・405・410・414・501）以外の応答（302・303・307、401・403・500など）はキャッシュされないのでna（`private`も保存を許す指定として数える。ステータスが分からない応答（C10で`response_code`がない）もna）。未指定、`public`、`no-cache`のみ、Pragmaのみ） ②機密応答が`private`のみ（`private="Set-Cookie"`のような値のある`private`は、仕様ではそのヘッダだけを除いて本文を共有キャッシュに保存してよい指定だが、多くのキャッシュは値を無視して値のない`private`として扱う（RFC 9111 5.2.2.7の注記）ので②のままにし、証跡に書く。カンマで区切るとき、引用符の中のカンマでは区切らない） ③静的リソースで未指定（静的リソースは、`sensitive=1`の明示がなければ機密応答としない。0.3）。①のnaの判定では、Locationのある3xxの`private`を鮮度の指定に数えない（ASP.NETは既定ですべての応答に`private`を付けるので、`private`だけの302・303はna） | 共有PCやプロキシ、CDNに機密データが残る | ①高 ②中 ③情報 | OWASP HTTP Headers CS、REST Security CS、ASVS 5.0.0 14.3.2, 14.2.2 |
| H-13 | Content-Typeとcharset | C1 | HTMLは`text/html; charset=utf-8`、JSONは`application/json` | ①Content-Typeなし（本文が空の応答（`Content-Length: 0`の401・201など。HTTP/2でContent-Lengthがなく、本文のない201・202・401・403も）は対象外。別のサイトへの転送で終わるターゲット（`-L`でたどった転送先は対象の応答として判定しない）はnaとして示す） ②HTMLでcharsetなし（JSONを`text/html`で返す件はA-09①で判定） | 文字コードを利用したXSS、スニッフィング | ①中 ②中 | OWASP HTTP Headers CS、ASVS 5.0.0 4.1.1、IPA 5-(viii) |
| H-14 | X-Permitted-Cross-Domain-Policies | C1 | `none`（または`master-only`） | ①ない ②`all`など、ポリシーファイルによる読み込みを許す値 | PDFなどからのクロスドメイン読み込み | ①低 ②低 | OWASP Secure Headers（Active） |
| H-15 | Clear-Site-Data | C1（`label=logout`のターゲット） | `"cache", "cookies", "storage"` | ①ない（引用符で囲んだ種類（`"cookies"`など）のない値（`cookies, storage`）は、ブラウザが無視するので①。C-12と同じ見方。`logout`の応答が4xx・5xxのとき、同じページへの転送を採取していないときはna。同じページへの転送はたどった先で見る） | 端末に情報が残る | ①情報 | OWASP Secure Headers、ASVS 5.0.0 14.3.1 |
| H-16 | 製品・バージョン・デバッグ情報の露出 | `Server`、`X-Powered-By`、`X-AspNet-Version`、`X-AspNetMvc-Version`、`X-Generator`、`Via`、`X-Runtime`、`X-Backend-Server`、`X-Served-By`、`X-Host`、`X-Debug-Token`、`X-Debug-Token-Link`、`Server-Timing`（④の内部ホスト名は`Via`・`X-Backend-Server`・`X-Served-By`・`X-Host`で見る） | 製品名・バージョン・内部ホスト名・内部処理の内訳を含まない（⑤の`Server-Timing`は、引用符の外のカンマで項目に分け、項目の名前だけを証跡に出す。`desc`の中のカンマで分けない） | ①バージョン番号が分かる（`X-Generator`は`Drupal 10`のような主な版だけでも①。`Server`・`X-Powered-By`は`AmazonS3`のような製品名の数字があるので`1.2`の形だけ。`Via`は、先頭のプロトコルの版（`1.1`・`HTTP/1.1`・`HTTPS/1.1`・`SPDY/3.1`）と区別するため、`Varnish/7.4`のような「名前/版」の形だけ。製品名だけの`Via`（`1.1 vegur`）は②にしない） ②製品名のみ（`X-Generator`なども含む） ③デバッグ系ヘッダ（プロファイラへのリンクなど） ④内部ホスト名・IP（プライベート・ループバックのIPv4アドレス（`10.0.0.0/8`・`172.16.0.0/12`・`192.168.0.0/16`・`127.0.0.0/8`）か`localhost`そのもの、またはホスト名の最後が`.internal`・`.local`・`.lan`・`.corp`・`.intra`のもの。そのアドレスで始まるだけ・その先に続くもの（`10.cdn.example.com`・`localhost.example.com`）と、`edge01.local.example-cdn.net`の`.local.`は公開のホスト名なので対象外。T-05②も同じ定義） ⑤`Server-Timing`・`X-Runtime`にDBや内部処理の名前・時間（CDNが付ける項目（Cloudflareの`cfL4`・`cfExtPri`、CloudFrontの`cdn-*`、Akamaiの`edge`・`origin`・`ak_p`、Fastly）だけなら対象外。証跡は項目の名前だけで、`desc`・`dur`の値は出さない（`desc`にSQLやメールアドレスを入れる実装がある）） | 既知の脆弱性を狙う手がかり、内部情報の露出 | ①低 ②情報 ③中 ④低 ⑤低 | OWASP WSTG、ISOG-J、ASVS 5.0.0 13.4.2, 13.4.6 |
| H-17 | 廃止・非推奨ヘッダ | `X-XSS-Protection`、`Expect-CT`、`Public-Key-Pins(-Report-Only)`、`Feature-Policy`、`Pragma` | X-XSS-Protectionは送らないか`0`。他は付けない | ①X-XSS-Protectionが`1`または`1; mode=block` ②その他が付いている | XSS Auditorの副作用、効果のない設定、HPKPの運用事故 | ①低 ②情報 | OWASP Secure Headers（Deprecated）、OWASP HTTP Headers CS |

## 第2章 Cookie（Set-Cookie）

セッションCookieのSecureとHttpOnly、セッションIDの推測困難性、ログイン時の再発行が最重要です。ログイン応答は次のように採取します（認証情報の渡し方は0.5節）。

```sh
umask 077   # jarと出力ファイルを本人だけが読めるようにする（0.5）
H=https://HOST
# ログイン前（C-09の比較元）
echo "#TARGET url=$H/login label=pre-login"
curl -sS -v -o /dev/null -c jar.txt "$H/login" 2>&1   # -b を付けない（jar.txt がまだないと、-v の1行目に curl の WARNING の行が出る）
# ログイン処理
echo "#TARGET url=$H/login label=login sensitive=1"
curl -sS -i -c jar.txt -b jar.txt -X POST --data @login.txt "$H/login"   # 本文も採取する（200 でフォームを返し直す失敗を見分ける。C-09）
# セッションIDの複数採取（C-07②）。jarを分けて3回ログイン
for i in 1 2 3; do
  echo "#TARGET url=$H/login label=session-sample-$i"
  curl -sS -D - -o /dev/null -c "s$i.txt" -X POST --data @login.txt "$H/login"
done
# ログイン後のページ（C-12①が、ログインできていたかを確かめる）
echo "#TARGET url=$H/mypage label=mypage sensitive=1"
curl -sS -i -b jar.txt "$H/mypage"
# ログアウトと、ログアウト後の旧Cookie利用（H-15・C-12）。ログアウトがPOSTなら -X POST
cp jar.txt old.txt
echo "#TARGET url=$H/logout label=logout"
curl -sS -v -o logout-body.txt -c jar.txt -b jar.txt "$H/logout" 2>&1; echo "#BODY"; head -c 196608 logout-body.txt; echo   # 本文も採取する（#BODY の行のあとに置く。確認画面を見分ける。C-12・H-15）
echo "#TARGET url=$H/mypage label=after-logout sensitive=1"
curl -sS -i -b old.txt "$H/mypage"   # 本文も採取する（ログインのフォーム・SPA の殻を見分ける。C-12）
# C15: HTTP応答でのCookie発行確認（apexも url=http://apex/ で同様に）
echo "#TARGET url=http://HOST/ label=http"
curl -sS -D - -o /dev/null http://HOST/
# 終了後にjarを削除: rm -f jar.txt old.txt s1.txt s2.txt s3.txt logout-body.txt
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-01 | Secure | 各Set-Cookieの属性 | すべてのCookieに付ける | ①セッションCookieにない ②その他のCookieにない（HSTSなし） ③その他のCookieにない（HSTSあり） | 平文通信での盗聴 | ①高 ②中 ③低 | MDN HTTP Observatory、ASVS 5.0.0 3.3.1、IPA 4-(iii) |
| C-02 | HttpOnly | 同上 | セッションCookieに必須（OpenID Connectのセッション管理（check_session_iframe）のために仕様上JSから読むCookie（IdentityServerの`idsrv.session`、Keycloakの`KEYCLOAK_SESSION`）はセッションCookieとしない。解析用のCookie（Application Insightsの`ai_session`・`ai_user`、Adobeの`s_sess`、Brazeの`ab.storage.*`）と、名前がセッションらしくても値が真偽値・`0`・`1`のフラグ（`has_session=1`）もセッションCookieとしない（ほかの数字の値（`SESSIONID=1234`）はセッションIDとしてC-07で判定する）。0.3の機密応答の推定も同じ） | ①セッションCookieにない | XSSでのセッション窃取 | ①高 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.4、IPA 5-(ix) |
| C-03 | SameSite | 同上 | `Lax`または`Strict`。`None`ならSecure必須 | ①セッションCookieで未指定 ②値が不正 ③正当な理由のない`None` ④`None`でSecureなし（ブラウザが拒否し機能不全） | CSRF、クロスサイトでの漏えい | ①中 ②中 ③中 ④低 | OWASP Session Mgmt CS、MDN HTTP Observatory、ASVS 5.0.0 3.3.2 |
| C-04 | Domain・Path | 同上 | Domainは原則付けない。Pathは必要最小限 | ①`Domain=.example.com`など親ドメインへ拡大（CDN・WAFのCookie（`__cf_bm`など）はCDNがDomainを決めるので対象外。比べるのは、そのCookieを発行したホップのホスト（`-L`で転送した先のwwwが発行したCookieはwwwと比べる）。ホストの親ドメインでないDomain（サブドメイン・別のドメイン）は、ブラウザがCookieごと拒否するので対象外） ②同じホストに複数アプリがあるのにPathが広い（手動確認。ツールは判定しない） ③Domainがホストと同じ（付けるとサブドメインにも送られる。空の`Domain=`はブラウザが無視するので対象外） | 侵害されたサブドメインや他アプリへの漏えい | ①中 ②低 ③低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.3 |
| C-05 | Expires・Max-Age | 同上 | セッションCookieは期限なしか、アプリのセッション有効期間以下 | ①セッションIDにセッション有効期間を超える期限（空や数字でない`Max-Age`はブラウザが無視し、`Expires`が効く） | 端末に残ったCookieの悪用 | ①中 | IPA 4-(vi) |
| C-06 | \_\_Host-・\_\_Secure-プレフィックス | Cookie名と属性 | セッションは`__Host-`（Secure、Domainなし、`Path=/`） | ①プレフィックスなし ②プレフィックスの条件を満たさない（ブラウザが拒否。プレフィックスは大文字小文字を区別しない（RFC 6265bis。今のChrome・Firefoxは`__host-sid`にも条件を求める）） | サブドメインからの上書き（Cookie Tossing） | ①情報 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.1, 3.3.3 |
| C-07 | セッションIDの長さ・推測可能性（値を囲む引用符（`sid="…"`）とパーセントエンコード（`%2B`は1文字）は乱数の量に数えない。文字種は、小文字と数字だけ・大文字と数字だけの値を36種で数える）。ASP.NET Coreの分割したCookieの印（`.AspNetCore.Cookies=chunks-2`）は、値を比べるとき（C-07①②・C-09）は除く。属性の判定（C-01〜C-06）では、同じ応答に中身（`…C1`）があれば印は数えない（1つのCookieを2回指摘しない）。分割した中身の`…C1`・`C2`もセッションCookieとして扱う（oauth2-proxyの`_oauth2_proxy`・`_oauth2_proxy_1`も）。ただし①は、2つ目以降のかけら（`…C2`・`_oauth2_proxy_1`）を単独で判定しない（最後のかけらは端数の長さなので、約59bitのような誤検知になる）。JWT、Flask（itsdangerous）の圧縮したセッション（`.eJw…`で始まる「.ペイロード.時刻.署名」）、Djangoの署名付きのセッション（「ペイロード:時刻:署名」）は、同じアカウントではペイロードの大部分が共通になるので、署名の部分だけで比べる | ①は各値の長さと文字種。②は`session-sample-1`〜`N`の値を比較 | エントロピー128bit以上（ランダムな16進なら32文字以上） | ①推定128bit未満（時刻から作るUUIDは、乱数の部分だけで数える。v1・v2・v6は14bit、v7は74bit。v4は文字種で推定する） ②連番・時刻・ユーザーIDを含む、固定部分がある（JWTは、ヘッダとクレームが共通になるため署名の部分で比べる。ツールは、同じ値の繰り返し、先頭の共通部分（4文字以上かつ値の長さの半分以上）、差が1000未満の数値の並びで判定する。値がすべて暗号化したCookie（Laravelの`eyJpdiI6…`、ASP.NET CoreのData Protectionの`CfDJ8…`）ならna。中のセッションIDの推測可能性は暗号文から分からない）。①で、16進数のかたまりを`-`・`.`・`_`・`:`で区切った値（`0a1b-2c3d-…`）は、区切りを除いて16種で数える。base64urlの`-`・`_`は文字そのものなので除かない | 総当たりや推測によるなりすまし | ①高 ②高 | OWASP Session Mgmt CS、ASVS 5.0.0 7.2.3、IPA 4-(i), 4-(v) |
| C-08 | 既定のCookie名 | Cookie名 | 汎用的な名前 | ①`PHPSESSID`、`JSESSIONID`、`ASP.NET_SessionId`、`connect.sid`、`laravel_session`、`CFID`・`CFTOKEN` | 技術スタックが分かる | ①情報 | OWASP Session Mgmt CS |
| C-09 | セッション固定化 | `pre-login`で発行・送信したIDと、`login`のSet-Cookieを比較（`-c`/`-b`でjarを引き継ぐ） | ログイン成功時にIDを再発行（2xx・3xxでもログインに失敗した応答はna：`?error`などのクエリへの転送、同じホストのログインらしいパス（`/login`・`/signin`など。認可コード・チケット（`?code=`・`?ticket=`）を持つSSOのコールバックは除く）への転送、`login`のURLのパス（末尾の`/`を除いて比べる。`login`のURLがトップ（`/`）ならクエリまで比べる）への転送、`pre-login`のチェーンの最後の応答（ログインのフォームの画面）のURLのパス（トップを除く）への転送、ログインらしいパスへ転送した先とlogin自身の応答のパスワード欄。SSOのコールバック（`?code=`・`?ticket=`）へ転送しただけでその先を採取していなければ、セッションはコールバックで発行されるのでna（`-L`で採取し直す）。2xxの`login`で本文を採取していない（`-v -o /dev/null`、HARの本文なし）ときは、パスワード欄のある画面を返し直す失敗と成功を見分けられないので、①にせずna（本文も含めて採取し直す。3xxは`Location`で見分けるので判定する。生成スクリプトのC18は`login`の本文も採取する）。`pre-login`の最初のURL（`/mypage`→`/login`の`/mypage`）とは比べない（ログインに成功して元のページへ戻る普通の流れを失敗とみなすため）。多要素認証の途中（`login`の転送先が`/two_factor`・`/mfa`・`/otp`・`/2fa`・`/totp`・`/webauthn`など。Fortifyの`/two-factor-challenge`、GitHubの`/sessions/two-factor/app`、Auth0の`/u/mfa-otp-challenge`、allauthの`/accounts/2fa/authenticate/`も含める。設定の画面の語（`setup`・`settings`・`reminder`・`backup`・`recovery`など）が続くもの（`/mfa/setup-reminder`・`/users/otp_settings`・`/2fa/backup-codes`）は含めない。メールの確認の案内（`/verify-email`・`/email/verify`）は、ログインが済んでいるので含めない。パスの最後の部分の拡張子を除いて見る（`/2fa.php`・`/Account/TwoFactor.aspx`も含める））は、ログインが終わっていないのでna。2xxの`login`がエラーだけのJSON（A-01で定義。空の`{}`は除く）を返したら、ログインの失敗としてna） | ①ログイン前後でIDが同じ（`login`で再発行されない。ログイン前のIDは、`pre-login`で発行したものと、`pre-login`で送ったもの（トップページで発行され、ログイン画面では送るだけ。ブラウザの普通の流れ）の両方を数える。送っただけの値は分からないので、`login`で新しいセッションCookieを発行したかで見る。`login`の応答が2xx・3xxでない（ログインに失敗した）ときはna。ログインで名前がセッションらしいCookieを新しい値で発行していれば、名前がセッションIDらしくないCookie（`device_token`・`visitor_ref`など。`sess`を含む名前と`sid`は除かない）を、期限の有無によらずログイン前と同じ値で送り直しただけでは①にしない。`pre-login`で送っただけの主のセッションID（`-v`・HARの`Cookie:`の`JSESSIONID`）を`login`で再発行せず、ほかのCookieだけを発行したときもna（発行したものと同じ扱い）。`login`で値を変えたセッションCookieがすべて暗号化したCookie（Laravelの`eyJpdiI6…`、ASP.NET CoreのData Protectionの`CfDJ8…`）で、ログイン前にも同じ名前があった（暗号化した値で発行したか、送っただけ）ときはna（暗号化した値は応答ごとに変わるので、再発行したかは値から分からない）。`pre-login`で送っただけの名前のうち、解析用・負荷分散などのセッションCookieでない名前（Hotjarの`_hjSession_…`・`ai_session`）は数えない（classic ASPの`ASPSESSIONID…`は数える）） ②URLにセッションID（`;jsessionid=`など） | セッション固定化攻撃 | ①高 ②高 | ASVS 5.0.0 7.2.4, 14.2.1、IPA 4-(iv)-a, 4-(ii) |
| C-10 | HTTP応答でのCookie発行 | C5（`label=http`。転送をたどらないC15でもよい） | HTTP応答ではSet-Cookieしない（HTTPSへ転送するだけ）（`-L`でたどったhttpのホップすべてを見る） | ①HTTP応答でSecureなしのセッションCookieを発行 ②HTTP応答でその他のCookieを発行（httpかどうかはホップごとのURLで見る。HARのターゲットのURLは転送先のhttpsなので、ターゲットのURLだけで見るとhttpのホップで発行したCookieを見逃す。URLの分からない最初のホップはターゲットのURLで見る）。対象のサイトのホップだけを見る（`-L`で別のサイトへ転送した先のhttpのホップは見ない）。`http`のほか、一般・`pre-login`・`login`・`session-sample-*`のターゲットにも適用する（httpだけのサイト） | 平文区間での盗聴、Secure属性の確認だけでは見落とす | ①高 ②中 | ASVS 5.0.0 3.3.1, 12.2.1、IPA 4-(iii) |
| C-11 | Partitioned（CHIPS） | 第三者として埋め込まれるCookie | クロスサイト埋め込み用のCookieは`Partitioned` | ①`SameSite=None`の埋め込み用Cookieにない（負荷分散・CDNのCookieは対象外。C-03③と同じ） | サイト横断の追跡、将来のブラウザ制限での機能不全 | ①情報 | MDN |
| C-12 | ログアウト後のセッション無効化 | `after-logout`（ログアウト前の旧Cookieで認証後ページへアクセス） | 401、403、またはログイン画面への転送（200でもログインのフォーム（パスワード欄）を返したなら、セッションは使えていないので合格。`mypage`自身にパスワード欄があるときは使わない。②は、消したCookieがセッションCookieらしい名前のときだけ合格（`remember-me`だけを消すSpring Securityの既定のログアウトは②））（同じページ（末尾の`/`の違い、同じサイトの別のホスト・httpsへの、パスとクエリが同じもの）への転送は、mypageもafter-logoutもたどって、その先で判定する。合格にするのは、401・403、ログイン画面・認証の入り口への転送（`/login`・`/signin`・Deviseの`/users/sign_in`・WordPressの`/wp-login.php`・OIDCの`…/openid-connect/auth`・`/authorize`・oauth2-proxyの`/oauth2/start`・Spring Securityの`/oauth2/authorization/<登録名>`、IdPの入り口（Googleの`/o/oauth2/v2/auth`、Shibbolethの`/idp/profile/SAML2/Redirect/SSO`、ADFSの`/adfs/ls`、SimpleSAMLphpの`SSOService.php`）、拡張子の付いた`/Account/Login.aspx`・`/login.php`・`.jsp`・`.do`など、SAMLの入り口（Entraの`/saml2`、Oktaの`/sso/saml`、Googleの`/o/saml2/idp`））。トップ（`/`）への転送はログイン画面とみなさない（トップが利用者の画面を返すアプリがある）。`-L`でたどった転送は最後まで見て、途中の転送先がログイン画面か、先がログインのフォームか401・403でもよい）、ログインのフォーム（フォームごとに、inputのタグを1つずつ取り出して見る。パスワード欄が1つで、そのname・id・autocompleteにパスワードを決める欄の印（`new`・`confirm`・`retype`・`repeat`・`new-password`・`password_confirmation`など）がなく、name・idに`current`・`old`がある欄（アカウントの削除・メールアドレスの変更などの再認証の画面）は、nameに`current_password`・`old_password`があるもの（Deviseの再認証のフォーム`name="user[current_password]" autocomplete="current-password"`など）だけを除く（nameがちょうど`current-password`でautocompleteも`current-password`のもの（web.devが勧めるログイン画面）と、idだけが`currentPassword`のものは除かない。idの`old-password`・`old_password`は除く）（web.devが勧めるログイン画面は`id="current-password"`と`autocomplete="current-password"`）、ほかの入力欄かhiddenのユーザー名があるもの。パスワード欄だけのフォームは、`autocomplete="current-password"`で、送り先（action）がログインらしいもの（`/login`・`/signin`・`/session`など。`sudo`・`reauth`・`confirm`・`verify`を含むものは除く）だけ（ユーザー名を文字で表示した2段階目の画面。GitHubのsudoモードのような再認証の画面と分けるため））を200で返したときだけ。`mypage`がなく、パスワード欄のあるフォームの送信先がログインらしいパス（`/login`・`/session`など。送信先なしを含む）でない画面（メールアドレスの変更などで再入力を求めるアカウント画面）は、ログイン画面か分からないので合格にせずna。404・5xx・ほかのページへの転送はna。SPAの殻（`<div id="root">`とスクリプトだけで、文字がないか読み込み中の案内だけのHTML。Inertiaの`data-page`やNext.jsの`__NEXT_DATA__`のようにデータを持つものは除く）の200も、どのセッションでも同じものを返すのでna（A-01・E-05と同じ考え方）。利用者・状態のデータを埋め込んだ画面（インラインのスクリプトの代入・`JSON.parse(`・`application/json`のうち、`"user":`・`"email":`などの名前や、state・store・propsの名前への代入があるもの、`__NUXT`・`ng-state`、ルートの要素の`data-`・`:`・`v-bind:`の属性）はSPAの殻とみなさない。設定（`window.__ENV__ = {"API_URL":…}`・`dataLayer`）と構造化データ（`ld+json`）だけのもの、埋め込んだ利用者の名前（`"user":`など）の値がすべて`null`・`false`・空のもの（`window.Laravel = {"csrfToken":…,"user":null}`、Reduxの`__INITIAL_STATE__ = {"user":null}`）は殻のまま。②は、`Clear-Site-Data: "cookies"`でも合格。ログアウトの応答がセッションCookieを消さずに発行し直した（Laravelの`invalidate`・Railsの`reset_session`）ときは、新しい値か（期限を延ばしただけの同じ値か）が分からないので②をnaにし、古いセッションが使えないかは①で確かめる。WordPress（`wordpress_logged_in_…`）・Shibboleth（`_shibsession_…`）・oauth2-proxy（`_oauth2_proxy`）のCookieもセッションCookieとして扱う | ①旧Cookieで認証後ページが200で返る（`logout`の応答が4xx・5xx・ログアウトの確認画面のとき（同じページへの転送はたどった先で見て、採取していなければna）、`mypage`の応答が2xxでない（ログインできていない）とき、`mypage`の同じページへの転送を採取していないときはna。本文のない2xxはna（ログインのフォーム・SPAの殻・データのないJSONを見分けられない）。データのないJSON・エラーだけのJSON（A-01で定義）とGraphQLのエラーはna、GraphQLの認証の拒否（`UNAUTHENTICATED`など）は合格） ②ログアウト応答でCookieを削除しない（`Max-Age=0`などがない。`-L`で別のサイト（IdP）へ転送した先のSet-Cookie・Clear-Site-Dataは、Cookieを消したかの判定に使わない（H-15も））（`logout`の応答が4xx・5xx（GETを受け付けないなど、ログアウトできていない）ときは①②ともna。`logout`が2xxで、セッションCookieらしい名前のCookieを消しも発行し直しもせず、Clear-Site-Dataもなく、送信先にlogout・signout・logoffの語があるPOSTのフォームの中にログアウトのボタンの文言がある画面（パスワード欄と`__VIEWSTATE`のあるものを除く）は、ログアウトの確認画面としてログアウトできていない扱い（①②・H-15はna）） | 盗まれたセッションがログアウト後も使える | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.4.1 |
| C-13 | Set-Cookieと共有キャッシュ | Set-Cookieを含む応答のCache-Control | Set-Cookieを含む応答は`private`または`no-store` | ①セッションCookieを含む応答が`public`または`s-maxage`付き（`no-store`か`private`もあれば共有キャッシュは保存しないので対象外） ②その他のCookieを含む応答が`public`（同じ） | CDNやプロキシ経由で他人にセッションが配られる | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 14.2.2 |
| C-14 | セッションタイムアウト | 認証後ページに、アプリの無操作タイムアウトより長くアクセスせずに置き、同じCookieで再アクセス（手動） | 無操作タイムアウトと絶対期限で失効する | ①無操作タイムアウトを過ぎても200で返る ②絶対期限を超えても使い続けられる | 盗まれたセッションの長期悪用 | ①中 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.3.1, 7.3.2 |
| C-15 | アカウントの列挙 | 存在するIDと存在しないIDでログインとパスワード再設定を試し、ステータス・本文・応答時間（-w '%{time\_total}'）を比べる（手動、検証環境） | どちらのIDでも同じステータス・同じメッセージを返す | ①ステータスや本文の違いでIDの存在が分かる ②応答時間の差でIDの存在が分かる | ユーザーIDの収集、パスワードリスト攻撃の効率化 | ①中 ②低 | OWASP Authentication CS、ASVS 5.0.0 6.3.8、IPA 2.5-3) |

- SameSite未指定時の扱いはブラウザで異なります（ChromeはLax扱い、FirefoxとSafariは挙動が違う）。「未指定＝安全」とも「未指定＝None」とも言えないため、明示を求めます。
- セッションCookieは、名前のパターンと期限がないことで推定します。名前は語（`-`・`_`・`.`とキャメルケースの境目）に分けて照合し、`sess`で始まる語（session、PHPSESSID、JSESSIONIDなど）か、sid・token・auth・jwt・loginの語があればセッションCookieとみなします（部分一致にすると sidebar_collapsed や oauth_state まで含めてしまうため）。CSRFトークンや設定用の名前（csrf・xsrf・consent と、ASP.NET の CSRF 対策の antiforgery・RequestVerificationToken を含むもの、区切り（- _ .）で分けた語が lang・locale・theme・ga・gid・pref… のもの）は除きます。負荷分散・WAFのCookie（`BIGipServer…`、`ARRAffinity…`、`AWSALB…`、`AWSELB…`、`TS01…`、`SERVERID`、`ROUTEID`、Kubernetesのingress-nginxの`INGRESSCOOKIE`、Google Cloudの`GCLB`）も、転送先のサーバの印で利用者ごとの秘密ではないため除きます（全員に同じ値を返すものがあり、C-07②の誤検知になる）。負荷分散のCookieは、CORSのリクエストでも同じサーバに届けるため仕組み上`SameSite=None`にする（`AWSALBCORS`、`ARRAffinitySameSite`）ので、C-03③にもしない。Azure Front Door（`ASLBSA`・`ASLBSACORS`）、Application Gateway（`ApplicationGatewayAffinity`）、Citrix ADC（`NSC_…`）、Traefik（`_TRAEFIK_BACKEND`）、nginxのスティッキーセッション（nginx-sticky-moduleの既定の名前`route`）も負荷分散の印として除く。ただしALBの認証（OIDC・Cognito）のセッションCookie（`AWSELBAuthSessionCookie-…`）は、`AWSELB`で始まっても利用者ごとのセッションなので除かない。ASP.NETの認証のCookie（`.AspNetCore.Identity.Application`・`.AspNetCore.Cookies`・`.AspNetCore.Session`・`.ASPXAUTH`）は、名前の語にセッションらしい語がなく、「ログインしたままにする」では期限付きで発行するが、セッションCookieとみなす。WAF・CDN・ボット対策のCookie（Cloudflareの`__cf`で始まるもの（`__cf_bm`・`__cflb`・`__cfruid`など）・`cf_clearance`・`cf_ob_info`・`cf_use_ob`・`cf_chl_…`・`_cfuvid`、Impervaの`incap_ses_…`・`nlbi_…`・`visid_incap_…`、Akamaiの`ak_bmsc`・`bm_sv`・`bm_sz`・`bm_mi`・`_abck`）も、CDNが発行して属性を運営者が変えられないので、セッションCookieの推定から除き、C-03③・C-04①にしない。解析・チャット・決済などの外部サービスのCookie（Hotjarの`_hj…`、`intercom-session-…`、`AMP_TOKEN`、`__stripe_…`、`optimizely…`、Datadogの`_dd_s`、Bingの`_uet…`、Clarityの`_clck`・`_clsk`、HubSpotの`__hs…`、Segmentの`ajs_…`、Amplitude、Mixpanelの`mp_…`、`_fbp`、`_gcl_…`）も、名前にsession・sid・tokenを含んでもログインの状態ではないので除く（HARで機密応答と推定し、公開ページをH-12①（高）にしないため）。推定が外れる場合は、ツールで手動指定します。
- 値がURL（`https://…`、エンコードした`https%3A%2F%2F…`）のCookieと、戻り先らしい名前（url・redirect・return・callback・next・dest・path）でエンコードした`/`（`%2F`）で始まる値のCookieは、名前にauth・sessionを含んでもセッションCookieとしない（NextAuthの`callback-url`をC-09①・C-07②で比べないため。名前によらない`%2F`は、RailsのセッションのBase64と見分けられないので含めない）。
- httpのターゲット（httpsに転送しないhttpだけのサイトを含む）で判定しないのは、Secure（C-01）、Domain（C-04）とプレフィックス（C-06）だけ（http の応答のCookieはC-10で見る）。HttpOnly・SameSite・期限・推測可能性などは通信路によらないので判定する。
- `=`のないSet-Cookie（`Set-Cookie: <値>; Path=/`）は、名前が空で値だけを持つCookieとして扱います（RFC 6265bis 5.6。ChromeとFirefoxも同じ）。値が長く期限がなければセッションCookieと推定し、証跡では「（名前なし）=」に続けて値を伏せます（名前として読むと値が空になり、削除用とみなしてC-01・C-02の判定から外れ、C-12の証跡に値が出るため）。
- `Expires`はRFC 6265 5.1.1の手順で読みます（時刻・日・月の名前・年がそろわないもの、範囲の外のもの、実在しない日は読めない）。読めない`Expires`はブラウザが無視するので、期限のないCookie（セッションCookie）として扱います（`Expires=0`・`Expires=-1`・`Expires=2099`を日時として読むと、生きているセッションCookieを削除用とみなし、C-01①・C-02①を見逃し、logoutの`Expires=0`でC-12を合格にするため）。
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
curl -sS -v -o /dev/null --http1.1 --max-time 5 -b jar.txt -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://evil.example' https://HOST/ws 2>&1                                  # C16
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | Origin反射 | C6 | 許可リスト外のOriginにACAOを返さない（R-01は`Origin: null`を送った応答ではna、R-02は`Origin: null`を送った応答（送ったOriginが分からない`-i`では`cors-null`のラベル）だけで判定し、それ以外はna） | ①ACAOが送信Originを反射＋ACAC:true ②反射（ACACなし）（ACAOのない転送の応答（期限切れのCookieでログインへの302など）とACAOのない5xx・429（CORSの処理より前に返る）は、APIがリクエストを処理していないので、R-01〜R-04とも合格にせずna。`cors-partial`のラベルで送ったOriginが分からない`-i`の応答は、R-03に任せて適用外。対象のURL自身のオリジン（スキーム・ホスト・ポートが同じ）を送った応答は、許可外のOriginを試していないのでna。httpのオリジン、サブドメイン、共用のホスティング（`*.herokuapp.com`、`*.github.io`）の隣のホストは、偽れるか他人のものでありうるので自サイトとしない） | 任意のサイトから認証付き応答を読まれる | ①高 ②中 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 3.4.2 |
| R-02 | null許可 | C7 | `null`を許可しない（`-v`でOriginを送っていなければna。R-01も同じ。CORSのミドルウェアの多くはOriginがあるときだけACAOを返すので、ACAOがないことは合格の根拠にならない） | ①`ACAO: null`＋ACAC:true ②`ACAO: null` | sandboxed iframeからの窃取 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-03 | 部分一致の不備 | `example.com.evil.net`、`evilexample.com`などをOriginに指定（`-v`必須。送ったOriginが見えない`-i`の`cors-partial`は、ACAOが似せたOriginならそれを送ったものとみなし、そうでなければna）。対象がサブドメイン（`api.example.com`）でも、そのドメイン（`example.com`）に似せたOriginはR-03で判定する（ドメインは最後の2つのラベル（`co.jp`などの国別の第2レベルなら3つ）の目安で、公開接尾辞の一覧は持たない。同じドメインのサブドメインは似せたものではなくR-01で判定する） | 完全一致で判定 | ①許可される＋ACAC:true ②許可される（ACACなし） | 同上 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-04 | ワイルドカード | C6 | `*`は公開データのみ | ①機密応答（0.3）に`*` ②`*`＋ACAC:true（仕様上ブラウザが拒否。設定ミスの兆候） ③公開データに`*`（ACAOがなく、Originを送っていない（`-v`・HARで送っていないと分かる）か、送ったかが分からない（`-i`で、ラベルが`cors-*`でない）ときは、合格にせずna。多くのミドルウェアはOriginがあるときだけACAOを返すので、ACAOがないことは`*`を返さないことの証拠にならない。R-01・R-02と同じ） | 公開すべきでないデータの露出 | ①中 ②低 ③情報 | MDN、MDN HTTP Observatory、ASVS 5.0.0 3.4.2 |
| R-05 | プリフライト応答 | C8 | Allow-Methods/Allow-Headersは必要最小限（許可外のOriginはR-01と同じく、送ったOrigin（自サイト以外）を反射したもの。送ったOriginが分からない`-i`では、テスト値のACAO） | ①許可外OriginにPUT・DELETEなど状態を変えるメソッドを許可（`Access-Control-Allow-Methods: *`も、ACAC:trueがなければすべてのメソッドの許可。ACAC:trueのときは「*」という名前のメソッドの意味なので対象外） ②`Access-Control-Max-Age`が極端に長い（Chromeは7200秒、Safariは600秒で打ち切り。Firefoxは86400秒）（`cors-preflight`でAllow-MethodsもMax-Ageもない応答（プリフライトを許可しなかった）は合格。ただし`-v`・HARでOriginを送っていなければ、プリフライトではないのでna） | 他サイトからの状態変更、設定変更が反映されない | ①中 ②情報 | MDN、OWASP WSTG、ASVS 5.0.0 3.4.2, 4.1.4 |
| R-06 | Vary: Origin | C6 | ACAOを動的に返すなら`Vary: Origin`（`-v`かHARでOriginを送っていないのに返したACAOは、Originによらない固定の値なので適用外） | ①ない（カンマで区切った1つの値として`Origin`か`*`があるかで見る。`X-Origin-Id`のような名前の一部は対象外。送ったOriginが分からない（`-v`なし・`Origin`の指定なしで、HARでもない）ときの固定のACAOはna（Originによって変わる値かが分からない。ただしACAOが既知のテスト値（`https://evil.example`）なら、R-01と同じく送ったOriginを反射した値とみなして判定する）。プリフライト（`cors-preflight`）の応答はHTTPのキャッシュに保存されない（RFC 9110 9.3.7）ので対象外。ACAOが送ったOriginを含まない（`https://evil.example`を送って`https://app.example.com`が返った）とき、自サイトのOriginを送ったときは、Originによって変わる値かが分からないのでna（許可外のOrigin・許可したOriginを送って採取し直す）） | キャッシュ経由で別Origin向けの応答が配信される | ①低 | MDN |
| R-07 | Access-Control-Expose-Headers | C6 | 必要なヘッダのみ（レート制限の項目（`x-ratelimit-remaining-tokens`）と利用量の項目（`X-Tokens-Used`・`X-Total-Count`。`used`・`count`・`limit`は語として見る。`X-Account-Token`は対象）も対象外。除外はtokenを含む名前だけに使う） | ①認証トークンや内部ヘッダを公開（名前に token を含んでも、CSRF対策やページ送りのトークン（`X-CSRF-Token`、`X-Next-Page-Token`）は認証のトークンではないので対象外。`Set-Cookie`は禁止された応答ヘッダで、書いてもスクリプトに公開されないので対象外） ②`*`（ACAC:trueがないときだけ。ACAC:trueのときは「*」という名前のヘッダの意味なので対象外。R-05と同じ） | クロスオリジンでのヘッダ情報の漏えい | ①中 ②低 | MDN |
| R-08 | Timing-Allow-Origin | C1（機密応答のターゲット） | 不要なら付けない。付けるなら限定 | ①機密応答（0.3）に`*`（機密応答かどうか分からなければna） | タイミング情報の漏えい（XS-Leaks） | ①低 | MDN |
| R-09 | WebSocketのOrigin検証 | C16（握手の応答ステータスだけを見る。合格は401・403だけで、200・404などはWebSocketのエンドポイントではない可能性があるため判定不能とする。送ったOriginが対象と同じホスト（自サイト）なら、許可外のOriginを試していないため、101・401・403でも判定不能とする） | 許可外Originのハンドシェイクは403などで拒否（`-v`・HARでOriginを送っていなければ、401・403でもna。機密かどうかは0.3の判定に従い（`sensitive=0`の明示を優先）、`-v`・HARでCookie・Authorizationを送っていなければ認証なし（②）、分からなければna。`-v`・HARで送信ヘッダが見え、送った認証がBearerなどのトークンだけ（セッションCookieも、ブラウザが自動で送る方式（Basic・Digest・Negotiate・NTLM）のAuthorizationもない）なら、攻撃者のページからのハンドシェイクには付かないので②。`sensitive=1`の明示があれば従う（セッションCookieの名前の推定から漏れたCookieで認証するWebSocketを②にしない）） | ①Cookie認証のWebSocketが許可外Originで`101 Switching Protocols` ②認証なしのWebSocketが101 | クロスサイトWebSocketハイジャック（他サイトから利用者として通信される） | ①高 ②情報 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 4.4.2 |

`-v`を付けずに実行した出力でも、ACAOが既知のテスト値（`https://evil.example`、`null`）と一致すれば、ツールは反射と判定します。それ以外のOriginを試す場合は`-v`が必要です。

## 第4章 メソッド・通信・TLS・ヘッダインジェクション

HTTP→HTTPSの転送、TLS 1.2以上と証明書の有効性、ヘッダインジェクションがないことが中心です。T-02、T-03、T-07、T-08は副作用があり得るため、検証環境で実施します。

```sh
umask 077
T=https://HOST/
echo "#TARGET url=$T label=options";   curl -sS -i -X OPTIONS "$T"                                  # C9
echo "#TARGET url=$T label=trace";     curl -sS -i -X TRACE "$T"                                    # C9
CB=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')   # キャッシュよけの乱数（採取の印 run= とは別にする。印はサーバに送らない）
echo "#TARGET url=$T label=host-inj";  curl -sS -i -H 'X-Forwarded-Host: evil.example' "${T}?csa=$CB"   # C14（Host・X-Host・Forwardedも同様に）
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
| T-01 | OPTIONS・TRACE | C9 | `Allow`は必要最小限。TRACEは405か501 | ①TRACEが200でリクエストを反射（200で本文を採取していなければna。転送（C9は`-L`を付けない）・5xx・429は受け付けるかが分からないのでna） ②不要な`PUT`、`DELETE`、`PROPFIND`がAllow（と`Access-Control-Allow-Methods`）にある（どちらもなければna） | XST、攻撃対象の増加 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.4, 4.1.4、IPA 5-(ix) |
| T-02 | PUT・DELETE（静的パス） | `curl -sS -i -X PUT --data 'x' https://HOST/test.txt`（検証環境） | 401、403、405 | ①201または204で作成・削除できる | ファイルの改ざん・設置 | ①高 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-03 | メソッド上書き | C21。`X-HTTP-Method`、`X-Method-Override`も試す | 上書きヘッダを無視 | ①上書きでメソッド制御を迂回できる | アクセス制御の迂回 | ①中 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-04 | HTTP→HTTPSリダイレクト | C5（`label=http`のターゲットで実行） | 最初の応答で同じホストのhttpsへ301か308（ステータスが分からない応答（C10で`response_code`がない）はna） | ①転送せずHTTPでコンテンツを返す（4xxで断るのは、HTTPでコンテンツを返していないので合格。CloudFrontの「HTTPSのみ」、HTTPを拒否するAPIなど。5xxと429（レート制限）は設定が分からないのでna） ②最初の転送先がhttp ③別ホストへ転送（HSTSが効かない） ④302、303または307 | 中間者攻撃 | ①高 ②中 ③低 ④情報 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1, 4.1.2、IPA 2.3-1) |
| T-05 | リダイレクトチェーン | C5 | 最終的にhttpsで、ホップが少ない | ①途中にhttpが挟まる ②Locationに内部ホスト名（H-16④と同じ定義）やポート（診断したURL自身のホストとポート（`https://example.com:8443/`）への転送は対象外。別のホストへの転送は同じポートでも対象） | 中間者攻撃、内部情報の露出 | ①中 ②低 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1 |
| T-06 | オープンリダイレクト | `?url=`、`next`、`returnTo`に`https://evil.example`を指定 | 外部ホストへのLocationを拒否（`Refresh: 0; url=https://evil.example/`も①。HTML Standardのとおり`url=`は省略でき、`Refresh: 0; https://evil.example/`も①。転送先のない`Refresh: 5`や同じページへのRefreshは、転送を試していないのでna。転送しなかった応答（200・404）は、転送先を検証しているかが分からないのでna）（ログイン画面・認証の入り口への転送（C-12と同じ一覧。SAMLの入り口を含む。テスト値を持ち越したかによらない。Spring・Devise・Laravelは保存したリクエストでログインのあとに戻る）と同じページ（パスとクエリが同じ）への転送は、転送先の検証を試していないのでna。ターゲットのURLが絶対URLでなくても、転送先を読んで判定する。ログイン画面以外への転送（`/home?blocked=…`、`/redirect?error=…`）は合格。C19の採取先（ログイン画面）が200を返すとnaになるので、`next=`で実際に転送するURLに置き換える） | ①`Location: https://evil.example`（転送先はブラウザと同じ読み方（WHATWG URL）で解釈する。`/\evil.example`・`https:\\evil.example/`・`///evil.example`も外部ホストへの転送。末尾のドットの付いた`evil.example.`も同じホスト。`evil.example.a.example`は外部ホストではない） | フィッシング、OAuthトークンの窃取 | ①中 | OWASP Unvalidated Redirects CS、ASVS 5.0.0 3.7.2、IPA 2.4-3) |
| T-07 | Host・X-Forwarded-Hostヘッダインジェクション | C14。①③はパスワード再設定に付けて実行し、届いたメールや再取得した応答を手動で確認（検証環境） | 偽装した値をLocation・本文・リンク生成に使わない | ①再設定メールなどのURLに反映 ②Locationや本文の絶対URLに反映（2xxで本文を採取していなければ、本文に反映したかが分からないのでna。反映していない5xx・429もna） ③キャッシュされた応答に反映 | 再設定リンクの乗っ取り、キャッシュポイズニング | ①高 ②中 ③高 | OWASP WSTG、PortSwigger Web Security Academy、ASVS 5.0.0 4.1.3 |
| T-08 | CRLFインジェクション | C20（検証環境） | 改行が応答ヘッダに入らない | ①応答に`Set-Cookie: crlf=1`など注入したヘッダが現れる（現れない5xx・429はna） | ヘッダ分割、Cookie注入、XSS | ①高 | OWASP WSTG、ASVS 5.0.0 1.2.1, 4.2.4、IPA 7-(i)-a, 7-(i)-b, 7-(ii) |
| T-09 | TLSバージョン。プローブがなく、合意したバージョン（C4）しかなければ、①はnaとして出す（②だけで判定済みとしない）。合意した`SSLv3`も① | ①はC12（プロトコルごとの接続可否）。C4の`* SSL connection using`行で旧バージョン（`TLSv1`・`TLSv1.1`・`SSLv3`）を合意した場合も、そのバージョンで接続できたので①。②もC4の同じ行。C4で分かるのは合意したバージョンだけで、TLS 1.2以上を合意しても旧バージョンを受け入れるかは分からない。TLS 1.3のプローブ（`#TLSPROBE v=tls1_3 ok=1`）で接続できたなら、合意が1.2なのはcurl側の事情なので②にしない。旧バージョンのプローブが拒否されても、そのホストにTLSで接続できたと分からない（1.2・1.3のプローブや弱くない暗号のプローブで接続できた、C4で合意した、opensslの出力に証明書がある、のどれもない）ときは、合格にせずna（プロキシ経由の環境では、curlはつながってもopensslはつながらず、すべてのプローブが失敗する。T-10も同じ） | TLS 1.2と1.3のみ（Mozilla Intermediate） | ①TLS 1.0・1.1・SSLv3で接続できる ②TLS 1.3非対応 | 暗号の弱化 | ①高 ②情報 | Mozilla Server Side TLS、OWASP TLS CS、ASVS 5.0.0 12.1.1、IPA 2.3-1) |
| T-10 | 暗号スイート・鍵。③は、AEADでも前方秘匿性のない静的RSAの鍵交換（`AES128-GCM-SHA256`など、ECDHE・DHEで始まらないもの）も含む | ①③は`openssl s_client -cipher`で個別に接続可否を確認（C23）。C4で合意した暗号（TLS 1.3以外）も①③で判定する。②はC11の証明書。C4で分かるのは合意した暗号だけ。合意した暗号（C4の`* SSL connection using`、C11のCipher）だけでは、弱い暗号を受け入れるか（①）も鍵・署名（②）も分からないので合格にせず、C23（暗号ごとの確認）かC11（証明書）があるときだけ合格にする。C23の弱い暗号がすべて拒否されても、そのホストにTLSで接続できたと分からなければna（T-09と同じ） | ECDHE＋AEAD（AES-GCM、ChaCha20-Poly1305）。ECDSA P-256かRSA 2048bit以上 | ①RC4、3DES、EXPORT、NULL、aNULLが通る ②RSA 2048bit未満（鍵の種類が出力にないOpenSSL 1.1・LibreSSLでは長さから推定。224・256・384・521bitは楕円曲線、253bitはEd25519、456bitはEd448とみなす。512bitはbrainpoolP512r1とRSAを区別できないのでRSAとする）、SHA-1署名（自己署名のルート証明書は除く。OpenSSL 3.5はEC鍵の長さを出さず`a:PKEY: EC, (prime256v1)`のように曲線の名前を出すので、名前から長さを引く） ③TLS 1.2以下でCBCや静的RSA鍵交換が通る | 既知の攻撃、前方秘匿性がない | ①高 ②高 ③中 | Mozilla Server Side TLS、ASVS 5.0.0 12.1.2 |
| T-11 | 証明書 | C11（同じホストのopensslの出力が複数あるときは、証明書の情報があるもの、採取した時刻（`#META at`）が新しいもの（時刻のないものは最後）、ラベルの順で選ぶ。T-10②も同じ順で、鍵・署名の分かる出力を選ぶ。入力の順番では選ばない） | `notAfter`まで30日以上。SANに対象ホスト。`Verify return code: 0 (ok)` | ①期限切れ・ホスト名不一致・チェーン不備・SANがない（今のブラウザはCNを見ない。SANがないかは、`-showcerts`の最初の証明書（PEM）にSANの拡張があるかで見る。PEMがない出力、切れたPEM（DERの長さが合わない、空行が入った）ではSANがあるか分からないので、CNで比べる。x509の出力にSANの行があればSANはある。SANのIPアドレス（`IP Address:192.0.2.10`）も読み、IPアドレスで接続した証明書はそれで比べる。IPv6は書き方をそろえて比べる） ②期限まで30日以内 | サービス停止、中間者攻撃 | ①高 ②中 | OWASP TLS CS、ASVS 5.0.0 12.2.2 |
| T-12 | HTTP/2・HTTP/3 | `-w '%{http_version}'`、`alt-svc`ヘッダ。HTTP/3の確認は`--http3`対応のcurlが必要 | 任意 | ①HTTP/1.1のみ | — | ①情報 | RFC 9114 |
| T-13 | 送信元IPの偽装（X-Forwarded-Forなど） | C17。IP許可リストの管理画面や、レート制限（A-04）の試験時に`X-Forwarded-For`の値を変えて比べる（検証環境） | 信頼できるプロキシが付けた値だけを使う | ①偽装でIP許可リストを回避できる（403→200） ②偽装でレート制限がリセットされる ③偽装したIPが本文やログにそのまま反映 | アクセス制御や総当たり対策の回避、監査ログの改ざん | ①高 ②中 ③低 | OWASP WSTG、ASVS 5.0.0 4.1.3, 15.3.4 |

OpenSSL 3系は既定で古いプロトコルを拒否するため、T-09でTLS 1.0/1.1を試すときは`-cipher 'DEFAULT@SECLEVEL=0'`を付けます。付けないと、サーバが許可していても「接続不可」と誤判定します。手元のOpenSSLがそのプロトコル自体に対応していない場合、C12は ok=err を出し、ツールは判定不能（na）とします（T-10は、ok=errの暗号を「拒否」に数えず、合格の証跡に「手元のOpenSSLが非対応で試していない」と書く。OpenSSL 1.1以降はRC4・3DESを試せないため、naにはしない）。

診断対象のサーバは、ハンドシェイクのあとに任意のデータを送れ、`openssl s_client`はそれを標準出力に出します。そのため生成スクリプトは、出力を最初の`Verify return code:`の行（ハンドシェイクの要約の終わり。サーバのデータはこれより後にしか出ない）で切ってから見ます（サーバが`unsupported protocol`・`DNS:…`・`notAfter=…`を書いて、T-09・T-10・T-11の判定を変えられないように）。採り方と`ok=`の決め方は、ツール設計1「推奨コマンド」のC11・C12・C23の例のとおりです。補足は次の2つです。
- `New, <版>, Cipher is <暗号>`の版は問いません（OpenSSL 1.1以降は暗号の最低の版を出す。TLS 1.0のAES128-SHAも`New, SSLv3, Cipher is AES128-SHA`）。`unsupported protocol`は、サーバが別のバージョンを選んだ（そのバージョンを拒否した）ときにも出るので、拒否として扱います。
- 手で採取した出力（印のないもの）は切っていないので、サーバのデータが混ざりえます。

このほか、h2cへのアップグレード（`curl -sS -i --http2 http://HOST/`で`101 Switching Protocols`が返るか）は、プロキシの制御を迂回される兆候として手動で確認します。返る場合の重要度は低で、ツールの対象外です。

## 第5章 エラー・情報露出・HTML本文

認証情報やソースコードが取得できる状態は、他の項目と関係なく重要度「高」です。E-07〜E-10とE-12は、C2（`-i`）で取得したHTML本文で判定し（本文を採取していない2xxのHTML応答ではna）、E-11はファイル配信URLの応答ヘッダで判定します。

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
  case $p in /phpinfo.php|/WEB-INF/web.xml|/package.json|/composer.json|/.well-known/security.txt) n=4096 ;; /server-status) n=1024 ;; *) n=64 ;; esac
  printf '#PROBE path=%s head=%s %s\n' "$p" "$(head -c "$n" "$probe" | base64 | tr -d '\n')" "$info"
done
rm -f "$probe"
```

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E-01 | スタックトレース・デバッグ情報 | 不正なURL、型違いのID、壊れたJSONを送る | 汎用エラー、またはRFC 9457の問題詳細形式（資格情報を含む`jdbc:`は①だけで、②にはしない）（②のスタックトレースは、Java・Python・PHP・.NETに加え、Node.jsの`at 関数 (/パス:行:列)`と`node:internal`、Goの`goroutine N [running]`、Symfonyの例外も見る。Node.jsのフレームは、ファイル（`.js`・`.ts`など）か`node:`の行と列まであるもの（無名のフレーム`at /app/index.js:7:9`も）。無名のフレームは、行の始め・タグの直後・JSONの配列の要素や`stack`などの値の始めにあるもの、または同じ行の前に`Error`・`Exception`（小文字も見る。`Internal server error at /app/src/handler.js:10:5`）があるもの（文章の`Look at /src/app.js:10:5`は対象外）で、直前が引用符のもの（スクリプトの文字列`"at /static/js/chunk.js:1:20345"`）と、パスに引用符・カンマを含むもの（JSONの`{"tip":"look at /docs","entry":"main.js:1:2"}`）は対象外。JSONの文字列に入れたスタックトレース（Springの`"trace":"…\n\tat com.example…"`、エスケープしたPythonの`File \"/app/main.py\"`）は、エスケープを戻した本文でも照合する。PHPの`html_errors`の形（`<b>/app/index.php</b> on line <b>3</b>`）と`Stack trace: #0`、.NETのフレーム（行の始めの`at Npgsql.Internal.…(`）も見る。Railsの`/app/…/x.rb:12:in`、Pythonの`File "/app/main.py", line 41`の形も見る。`/app`は絶対パスの一覧には入れない（`serviceWorker.register("/app/sw.js")`のようなスクリプトのパスで誤検知するため）） | ①接続文字列（`Server=…;Password=…;`、資格情報を含む`jdbc:`（`//user:pass@`（ユーザー名とパスワードに`;`・`?`・`&`を含まないもの。`jdbc:sqlserver://db;user=svc@corp`はパスワードがないので対象外）、`?password=`・`;password=`、Oracleの`thin:user/pass@`）、`mongodb://user:pass@`。ユーザー名・パスワードに引用符・`/`・`@`を含まないもの（資格情報のない`mongodb://host/app`のあとのメールアドレスの`@`で誤検知しない））・AWSアクセスキー（HTMLの応答のAWSアクセスキーは、そのラベルでE-09を判定するときはE-09①で数える。同じ値を2回、高として数えない。`error-*`のようにE-09を判定しないラベルと、組織プロファイルでE-09を対象外にしたときはE-01①で数える）。`Server=…;`の形は、キーを大文字小文字を区別して照合し、`Password`は`;`の直後のキーに限る（小文字のJSの`var host = …; var password = …;`には一致させない） ②スタックトレース（`Traceback`、`at java.`）、SQL文（`SQLSTATE`、語の境目からの`ORA-`。`FLORA-12345`のような品番は対象外）、資格情報のない`jdbc:`の接続文字列（証跡は`jdbc:mysql:`までで、接続先のホスト名は出さない）、絶対パス（URLのパスの一部（`https://cdn…/opt/app.js`、`src="/srv/main.js"`、`url(/srv/…)`）は対象外） ③フレームワーク既定のエラーページ（`Whitelabel Error Page`、Expressの既定のページ（タイトルがちょうど`Express`。`Example Express`のような普通のページは対象外）、Railsの既定の404・500のページと開発用の画面など。Jettyの`<title>Error 404 …</title>`は本文の`HTTP ERROR 404`か`Powered by Jetty`と合わせて見る。独自のエラーページのタイトルや、本文の「Ruby on Rails」の語は対象外。nginxの既定のエラーページ（`<hr><center>nginx…</center>`）とApacheの`<address>Apache… Server at …</address>`は、エラーの応答（4xx・5xx）のときだけ③（同じ署名が既定の301・302の本文にもある）） | 内部構造・秘密情報の露出 | ①高 ②中 ③低 | ISOG-J、ASVS 5.0.0 16.5.1, 13.4.2、IPA 1-(iii) |
| E-02 | ディレクトリリスティング | `curl -sS https://HOST/images/`（nginx・Apacheの`Index of /`、IISの`[To Parent Directory]`、Tomcatの`Directory Listing For`、Jettyの`Directory: /`、serve-indexの`<title>listing directory`） | 403か404 | ①`Index of /`など一覧が表示される（オブジェクトストレージの一覧（S3・GCSの`<ListBucketResult>`、Azure Blobの`<EnumerationResults>`。XMLの応答）も①） | ファイルの列挙 | ①中 | ISOG-J、ASVS 5.0.0 13.4.3 |
| E-03 | 既知ファイル（/.git、/.envなど） | C13。採った先頭（長さはツール設計1「プローブの判定パターン」）は判定にだけ使い、画面とエクスポートには「一致したパターン名」だけを出す | 404 | ①中身を取得できる（HTTP 2xxで、中身がパターンに一致する。/.git/HEADが`ref: refs/heads/`で始まる、/.envに`KEY=value`行、phpinfoの出力など） ②200だが中身が一致しない（判定保留。HTMLの形式でないファイルのパスにHTMLの画面（`<!doctype html`・`<html`・`<head`・`<body`で始まる）が返ったものは、どのパスにも同じ画面を返すSPAなどで、そのファイルではないので②にしない。phpinfo・server-statusは本物もHTMLなので②）。コードが`000`（接続できなかった）、5xx（サーバのエラー）か429（レート制限）のパスが1つでもあれば、ほかで①②がなくても合格にせずna（E-04②・E-13①も同じ）。C13は`-L`を付けないので、転送（3xx。apexからwwwへなど）されたパスがあるときも、転送先を確かめていないのでna（E-04・E-13①も同じ）。パターンと項目の対応はツール設計1「プローブの判定パターン」。robots.txtとsecurity.txtは対象外（E-04で判定） | ソースコードや認証情報の漏えい | ①高 ②情報 | ISOG-J、OWASP WSTG、ASVS 5.0.0 13.4.1, 13.4.7、IPA 2.1-5) |
| E-04 | robots.txt・security.txt | C13では存在確認だけ。中身は本文を取得して確認：`curl -sS https://HOST/robots.txt` | robotsに機密パスを書かない。security.txtに`Contact:`と`Expires:` | ①robotsに機密パス（`Disallow: /admin-secret/`など。admin・secret・backup・private・internal・staging・dev・devel・development・test・testing・testsite・config・manage・console・phpmyadminとその複数形を英字の語の境目で見る。adminはadministratorなどの続く語と、sys・my・web・db・site・superの接頭辞も含む。`/devices/`の`dev`、`/latest/`の`test`、`/badminton/`は対象外。`/robots.txt`の本文がHTML（`<`で始まる。どのパスにも`index.html`を返すSPA）のときは、robots.txtなし（合格）。Content-Typeが`text/html`でも、本文がrobots.txtなら中身を見る。`-L`なしで採取した3xxは、転送先を見ていないのでna。5xxと429は、robots.txtがあるかが分からないのでna。ほかの2xxでない応答はrobots.txtなし（合格）） ②security.txtがない・期限切れ（`Expires`が日時として読めないもの（`never`など）も含む。2xxでない応答と、HTMLの画面（どのパスにもindex.htmlを返すSPA）はsecurity.txtがないとする。5xxと429（レート制限）は、あるかが分からないのでna）（①②とも、2xxで本文を採取していなければna、304は適用外。3xxは、`-L`なしでは転送先を見ていないのでna） | 隠しパスの露出、報告窓口がない | ①低 ②情報 | OWASP WSTG、RFC 9116 |
| E-05 | API仕様・管理機能 | `/swagger-ui/`、`/openapi.json`、`/v2/api-docs`、`/graphql`（introspection）、`/actuator`、`/actuator/env`。パスは`/`で区切った1つの部分として照合する（`/category/actuator-kits`のような普通のページには一致させない）。ステータスは、そのURL自身の応答（転送の最初のホップ）で見る（ログイン画面への転送先の200で①にしない）。ただし、同じサイトで同じ機能のページへの転送（転送元のパスに`/`か`/index.html`を足しただけのもの、同じサイトの別のホスト（apexからwwwなど）・httpsへの、パスが同じ転送。`/swagger-ui`→`/swagger-ui/index.html`、`/swagger-ui.html`→`/swagger-ui/index.html`）は転送先で見る（転送先を採取していなければna）。ステータスが分からない応答（`%{header_json}`だけで`response_code`がない）はna | 本番では無効、または認証の内側（HTMLの200は、その機能の画面と分かるとき（`<title>`のSwagger UI・ReDoc・RapiDoc・Scalar、`<div id="swagger-ui">`、`swagger-ui-bundle.js`、`<redoc>`、`<rapi-doc>`、`@scalar/api-reference`。本文の「Swagger UI」の語だけでは見ない）だけ②にする。actuatorとAPI仕様の本体はJSON・YAMLなので、HTMLの200はna（推奨対応に、そのパスをブラウザで開いて確かめるよう書く）。どのパスにも`index.html`を200で返すSPA（Netlify・Vercel・Firebase Hosting・S3＋CloudFront）で誤検知しないため） | ①管理機能・actuatorが未認証で使える（Spring Boot actuatorが既定で公開する状態だけの応答（`/actuator/health`・`info`で`status`（`{"status":"UP"}`）とKubernetesの`groups`だけのもの、`/actuator`の一覧でリンクが`self`・`health`・`health-path`・`info`だけのもの）は合格。本文のない`/actuator`・`/actuator/health`・`/actuator/info`の2xxは、状態だけの応答かが分からないのでna。`/actuator/env`などは取得できれば①） ②API仕様が未認証で公開（①②とも、CookieかAuthorizationを送った応答（0.3の②の推定と同じ）の200は、未認証で使えるかが分からないのでna。5xx・429（レート制限）と304（キャッシュの確認の応答）は、公開していないとは言えない（認証の前に落ちた、一時的な障害の可能性）のでna（A-01と同じ）） ③GraphQL introspectionが有効（introspectionのクエリを送った応答だけで判定する。`__schema`があれば③、本文が introspection を拒否していれば合格、それ以外（`GET /graphql`の400「Must provide query string」や405など）はna。HTMLの応答は introspection の応答ではないので合格にしない（IDEのJSが introspection の語を含んでも拒否とみなさない）。GraphiQLなどのIDEの画面が200で開ければ②） | 攻撃対象の全容が分かる、設定値の露出 | ①高 ②中 ③中 | OWASP API Top 10 2023（API9）、ISOG-J GraphQL診断ガイドライン、ASVS 5.0.0 13.4.5, 4.3.2 |
| E-06 | JSONP | `curl -sS -i 'https://HOST/api/x?callback=test123'` | JSONPに対応しない | ①機密応答（0.3）を`test123(...)`で返す（Expressの`res.jsonp`の形`/**/ typeof test123 === 'function' && test123(...)`も含む） ②公開データのJSONP（CSP回避の足がかりになる）（2xxで本文を採取していなければna。2xxでない応答（404の画面など）に反映されないことは合格にせず適用外） | クロスサイトでのデータ窃取、CSPの回避 | ①高 ②低 | Google CSP Evaluator、PortSwigger、ASVS 5.0.0 3.5.6, 3.5.7 |
| E-07 | HTML本文：混在コンテンツ | C2の本文 | 資源はすべてhttps | ①`http://`のscript・iframe・embed・object・stylesheet（`<link>`の`rel`がpreload・modulepreloadのものも） ②`http://`のimg・audio・video・source | 通信途中でのスクリプト差し替え | ①中 ②低 | MDN、ASVS 5.0.0 12.2.1、IPA 2.3-1) |
| E-08 | HTML本文：第三者スクリプトのSRI | C2の本文 | 外部CDNのscriptに`integrity`と`crossorigin` | ①外部オリジンのscriptにintegrityがない（外部かは、HTMLを返したページ（`-L`で転送したときは転送先）のホストと比べる。配信元ごとに1件にまとめる。組織プロファイルで自社の配信元とした所は対象外） | CDN侵害時のスクリプト改ざん | ①低 | MDN（Subresource Integrity）、ASVS 5.0.0 3.6.1 |
| E-09 | HTML本文：機密・内部情報 | C2の本文 | 本番HTMLに秘密情報や開発用コメントがない（OpenID Connectの`response_mode=form_post`の画面で、POSTするフォームのhiddenの`id_token`・`access_token`・`code`・`state`の値は、ブラウザに渡すのが仕事なので対象外）（除くのはそのinputのタグだけで、値をページ全体からは消さない） | ①APIキー・トークン・認証情報（属性の中の文字参照（`data-page="{&quot;api_key&quot;:…}"`）と、JSの文字列の中のエスケープ（`JSON.parse("{\"api_key\":…}")`）でつないだJSONも、引用符を戻して見る。代入の値はASCIIの英数字・記号で12文字以上のものだけ。日本語の文言は対象外。名前の前は語の境目（`forgot_password:`は対象外）。「秘密の値とみなさない値（E-09①・A-07①共通）」の値は対象外。JWTは、公開を前提にしたもの（ペイロードの`role`が`anon`。Supabaseのanon key）は対象外。ブラウザで使う前提のSDKの呼び出しの中の`apiKey`（Algoliaの`docsearch`・`algoliasearch`、Bugsnag・Sentry・Mixpanelなどの初期化）も対象外） ②内部URL（ホストがH-16④と同じ内部ホスト（プライベート・ループバックのIPv4アドレス、localhost、`.internal`などの接尾辞。`db.prod.internal`のような複数のラベルのホスト名も含む）のURL。別のURLのパラメータの中のURLも見る。ユーザー情報を含むURLと、診断したURL自身のホスト（社内のポータルの自サイトへのリンク）は対象外）や開発コメント（`TODO`・`FIXME`・`XXX`・`HACK`・`debug`・`staging`は大文字・小文字を区別し、前後が英字でないもの（`debug_mode`・`debugMode`・`staging_db`と、キャメルケースの途中の`isDebug`も）。`password`（複数形も）・`パスワード`・`本番`は、部品の説明（`<!-- Password field -->`、`password reset`、`パスワード欄`）を除く。`pass`だけの語は「Tests pass」のような文に出るので、値の代入（`pass: …`・`pass=…`）と、数字か英字で始まり数字を含む語が続くもの（`admin/pass123`・`pass admin123`。`tests pass 100%`・`pass 2 of 3`は除く）だけを見る。Knockoutの制御のコメント（`<!-- ko if: … -->`・`<!-- /ko -->`）は開発用コメントとしない） ③`<meta name="generator">`のバージョン（`Drupal 10`のような主な版だけも含む） | 秘密情報の漏えい、攻撃の手がかり | ①高 ②低 ③情報 | ISOG-J、ASVS 5.0.0 13.4.6 |
| E-10 | HTML本文：パスワードフォーム | C2の本文 | `action`がhttps、`method="post"` | ①送信先（action）が`http://`（ページのURLを基準に読む。httpのページの相対・空の送信先も①） ②パスワードをGETで送信（①②とも、同じ名前の属性が2つあれば、ブラウザと同じく最初の値で判定する） | 平文送信、URL経由の漏えい | ①高 ②中 | OWASP Authentication CS、ASVS 5.0.0 12.2.1, 14.2.1、IPA 2.3-1) |
| E-11 | ダウンロード応答 | ファイル配信URLをC1で採取。①のアップロードしたファイルは、アップロード先らしいディレクトリ（uploads・files・attachments・media・download）の下で、最後がファイル名（拡張子付き）のURLで判断する（`/media/press-releases/`のような普通のページと、サーバ側で動くページ（`.php`・`.aspx`・`.jsp`・`.cgi`など）やディレクトリの`index.html`は対象外。ビルドしたファイル（Create React Appの`/static/media/logo.6ce24c58.svg`、Next.jsの`/_next/static/…`）も対象外。名前のハッシュだけでは除かない（`/uploads/avatar.5f3a9c2e.svg`、日付の`minutes.20241231.html`を見逃すため））。判定するのは、そのURLがファイルを返した応答（転送のない2xx）だけ（404のエラーページや、ログイン画面への転送先は対象外） | `Content-Disposition: attachment`、`nosniff`、正しいContent-Type（`/download/`の下の`.html`は、配布物を案内する普通のページなので①にしない。ただし、uploads・files・attachmentsも含むもの（Redmineの`/attachments/download/42/evil.html`）は①。CMSの配布物の置き場にも使う`media`（`/media/download/press.html`）は①にしない。旧式のフォント（`application/vnd.ms-fontobject`）とHLS・DASHのプレイリスト（`application/vnd.apple.mpegurl`・`dash+xml`）は②の対象外。ビルドの置き場（`/static/media/`・`/_next/static/`）の下でも、uploads・attachmentsの下（`/static/media/uploads/evil.html`）は①） | ①ユーザーがアップロードしたファイルを同一オリジンでinline（Content-Dispositionの種類（最初のトークン）がattachmentでない。`inline; filename="attachment.html"`もinline）・`text/html`などスクリプトを実行しうる種類（XHTML、SVG、XML）として配信 ②Content-Dispositionがない（画像・音声・動画、`+json`・`+xml`のAPI応答、Content-TypeがJSONのAPIの応答（パスがアップロード先らしい`/api/files/123.json`でも。`kind=api`の明示では除かない）と、ビルドしたCSS・JS・フォント（Drupalの`/sites/default/files/css/…`、Next.jsの`/_next/static/media/…`）は対象外） | アップロードファイル経由のXSS | ①高 ②低 | OWASP File Upload CS、ASVS 5.0.0 3.2.1, 5.4.1 |
| E-12 | HTML本文：CSRFトークンの有無 | C2の本文（認証後ページ） | 状態を変える`<form method="post">`に隠しトークンがある（実効性の確認は第7章の範囲外） | ①POSTフォームにトークンらしき項目がなく、SameSiteもLax/Strictでない（同じホストで見えたセッションCookieがすべてLax/Strictなら合格。セッションCookieが見えなければ①とする。機密応答かどうか分からなければna） | CSRFの可能性の兆候 | ①情報 | OWASP CSRF Prevention CS、ASVS 5.0.0 3.5.1、IPA 6-(i)-a |
| E-13 | ソースマップの露出 | 本番JSの応答ヘッダ（SourceMap、X-SourceMap）と本文末尾の //# sourceMappingURL= を確認し、示された .map のパスをC13のパス一覧に追加して実行する | 本番では .map を配信しないか、認証の内側に置く | ① .map を取得できる（HTTP 2xxで、中身がソースマップの形。元のソースコード（sourcesContent）を含むかは手動で確認） ② .map への参照（ヘッダ・コメント）がある（本文に埋め込んだソースマップ（`data:application/json;base64,…`）は、.map を配信しているのと同じなので、証跡と推奨を分ける（.map の取得は勧めない。中身は証跡に出さない）。JSの本文を採取していないとき、本文が先頭64K文字で切れているとき（参照は末尾にあることが多い）は、参照がなくてもna。拡張子でJSとみなした2xxでない応答（404の画面、ログインへの転送）とHTMLの応答は、参照がなければ適用外） | ソースコードや内部APIの露出 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.7 |

### 秘密の値とみなさない値（E-09①・A-07①共通）

E-09①（HTML本文の代入）とA-07①（JSONのキー）は、秘密らしい名前に付いた値でも、次のものを秘密の値としない。

- 公開を前提にした値：Stripeの公開キー`pk_live_…`・`pk_test_…`と`client_secret`（`pi_…_secret_…`・`seti_…_secret_…`）、GoogleのAPIキー`AIza…`（Maps・Firebaseなどブラウザから使う前提のキーで、HTTPリファラーやAPIの制限で守る）、PostHogのプロジェクトのキー`phc_…`。
- 伏せ字：`********`・`***`・`[REDACTED]`・Railsの`[FILTERED]`・`<hidden>`など。
- 文言：英語の画面の文言（`"password":"Password"`のように、名前と同じ語か、先頭だけ大文字の語をつないだもの）と、JSONでエスケープした日本語などの文言（`パ…`が2つ以上で、値の半分以上のもの）。
- 入力の検証の規則（`required`・`min:8`のように規則の名前を縦線でつないだもの）、正規表現（`^…$`）、autocompleteの値（`current-password`）。
- セレクタ（`#password-input`・`.js-password`・`input[name=password]`）と項目の名前（`user_password`・`loginPassword`・`password_confirmation`のように、秘密の語と項目の部品の語（`user`・`login`・`new`・`confirm`など）だけからなるもの。`admin_pass`・`super-secret-key`はほかの語を含むので除かない）。
- パス・翻訳キー・URL：パス（`/users/password/new`・`/Account/ForgotPassword`）と、ドットでつないだ翻訳キー（`auth.password.label`）は、`/`・`.`などで区切ったかけらがすべて語として読め、秘密の語を含むものだけを除く。URLはユーザー情報のないものだけを除く。テンプレート（`{{…}}`・`${…}`で始まるもの）も除く。`/`で始まるbase64の秘密と、`correct.horse.battery`のような合言葉は除かない。

E-09①だけの除外（公開用のJWT、SDKの`apiKey`）とA-07①だけの除外（状態を表す決まった語、`errors`・`validation`の直下の値）は、それぞれの表に書く。

## 第6章 WebAPI特有（OWASP API Security Top 10 2023）

APIでは、未認証アクセス、トークンの露出、過剰なデータ露出がcurl出力で判定できる主な「高」の項目です。A-04、A-05、A-06は負荷をかけるため、検証環境で少ない回数に限って実施します。

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | 未認証アクセス | `curl -sS -i https://HOST/api/me`（Authorizationなし。`label=unauth-*`。③はHTTPの応答のWWW-Authenticate。`-L`で転送をたどった場合は、URLがhttpのホップだけを見る（httpsに転送した先のBasicは対象外）。複数のチャレンジのどれにBasicがあってもよい） | 401＋`WWW-Authenticate`（例：`Bearer realm="api"`）（同じページ（末尾の`/`、同じサイトの別のホスト（apexからwwwなど）・httpsへの、パスとクエリが同じもの）への転送はたどった先のステータスで見る。転送先を採取していなければna。A-11も同じ。A-08は、送った本文を送り直す307・308の転送だけをたどる（301・302・303ではPOSTが本文のないGETになる）） | ①200で保護データが返る（HTMLの画面の200は、どのパスにも同じ画面を返すSPAの可能性があり、ログインのフォームがあってもゲスト用のログイン欄と利用者のデータを並べる画面があるので、データを返したかが分からずna。HTMLの画面とみなすのは本文がタグで始まるものだけ（先頭の1KBに`<!doctype html>`・`<html`があるもの（PHPのNoticeの行のあとに続くHTMLも）か、`text/html`でタグで始まるもの。JSON・CSV・平文の本文はHTMLの画面としない。本文を採取していない`text/html`はna。本文がJSON（`{`・`[`で始まる）なら、HTMLの文字列を含んでもHTMLの画面としない。A-11も同じ）。データのないJSON（`{}`・`[]`、値がすべて`null`・空のもの。`false`はログインの状態の名前（`authenticated`・`loggedIn`など）の値のときだけ空とみなす。`{"authenticated":false,"user":null}`、NextAuthの未認証の`/api/auth/session`）と、エラーだけのJSON（`{"success":false,"error":"Unauthorized"}`のように、エラーの項目かsuccess:falseがあり、ほかは`message`・`code`などの決まった名前と空の`data`だけのもの。ログインの状態の名前が`false`で、ほかがエラーの項目・決まった名前だけのもの（`{"authenticated":false,"message":"Not logged in"}`）も含む）はna（C-09・C-12もこの定義を使う）。本文のない2xx（204、`Content-Length: 0`）と本文を採取していない2xxもna。GraphQLの200で、`errors`があり`data`がnull（値がすべてnull）のものは、認証・認可の拒否（`UNAUTHENTICATED`・`FORBIDDEN`など）なら合格、それ以外のエラーはna） ②認証なしのAPIが3xxで転送する（ログイン画面への転送など。APIとして不適切。Locationのない3xx（条件付きのGETの304）は転送ではないのでna） ③HTTPでBasic認証を受け付ける（①②の合格は401・403・405だけ。404（URLの誤りの可能性）・5xx（認証の前に落ちた可能性）・400などはna） | なりすまし、情報漏えい | ①高 ②低 ③高 | API2（Broken Authentication）、ASVS 5.0.0 8.2.1, 12.2.1、IPA 11-(i) |
| A-02 | トークンの露出 | URLのクエリ、本文、`Location`ヘッダ | トークンはAuthorizationヘッダだけで扱う | ①URLにトークン（`?access_token=`など。状態を伝える短い語（小文字の英字を`-`・`_`でつないだ16文字以下。`?session=expired`、`?auth=required`）と真偽値（`true`・`1`など）は除く。大文字を含む英字だけの値、長い値、6桁以上の数字だけの値（ワンタイムの番号）はトークンとする（5桁までの数字（講演の番号の`?session=12`）は対象外）） ②Locationや本文に長期トークン・他者のトークン（ツールは、本文の`refresh_token`（16文字以上）だけを見る。`login`・`pre-login`のラベルと、トークンを発行するエンドポイント（パスが`/token`で終わるもの。`/oauth/token`、`/connect/token`）は対象外） | ログやRefererからの漏えい | ①高 ②中 | API2、API8、ASVS 5.0.0 14.2.1、IPA 4-(ii) |
| A-03 | JWTの中身 | headerとpayloadをツール内でBase64デコード | `alg`が`none`でない。`exp`が短い。PIIを含まない（curlの`-v`の送信ヘッダと、HARのリクエストのAuthorization・Cookieで送ったJWTも見る）（HARでは、同じJWTを送ったエントリが多いので、最初に送ったエントリでだけ判定する） | ①`alg: none` ②`exp`がない ③個人情報を含む（OpenID ConnectのIDトークン（`id_token`の欄・Cookieで返したもの、または`iss`・`aud`と`nonce`・`at_hash`があり`typ`が`Bearer`でないもの）は、仕様上ユーザーの属性を運ぶものなので③にしない。`azp`・`auth_time`はアクセストークンにもあるので見ない） | トークン偽造、無期限の再利用、情報漏えい | ①高 ②中 ③中 | API2、ASVS 5.0.0 9.1.2, 9.2.1 |
| A-04 | レート制限 | 同じリクエストを少数回連続で送る（検証環境） | 429＋`Retry-After`。`RateLimit`/`RateLimit-Policy`（IETF draft）か`X-RateLimit-*` | ①ログイン・OTPなど認証系で制限の兆候がない ②その他のエンドポイントで兆候がない | 総当たり、リソース枯渇 | ①中 ②情報 | API4、ASVS 5.0.0 2.4.1 |
| A-05 | ページングの上限 | `?limit=100000` | 上限で切り詰めるか400 | ①指定件数がそのまま返る | リソース枯渇、大量取得 | ①中 | API4、ASVS 5.0.0 15.2.2 |
| A-06 | リクエストサイズの上限 | 大きな本文を送る（検証環境） | 413 | ①上限なしで処理される | リソース枯渇 | ①低 | API4、ASVS 5.0.0 15.2.2 |
| A-07 | 過剰なデータ露出 | JSONのキーを確認 | 必要な項目だけ（証跡に出すキーの名前は、値をキーにしたもの（`sk-proj-…`、`glpat-…`、`-`・`_`で区切ったかけらが英大文字・小文字・数字を含む16文字以上のものなど）を`*`にする） | ①`password`、`passwordHash`、`secret`などのキーに、秘密情報らしい値（空白や日本語を含まない文字列。「秘密の値とみなさない値（E-09①・A-07①共通）」の値、状態を表す決まった語（`set`・`configured`・`enabled`・`true`など。英小文字の語をすべて除くと英小文字だけのパスワードを見逃すので一覧で見る）、`errors`・`validation`（`validation_errors`）の直下の値（`{"errors":{"password":"TOO_SHORT"}}`）は除く）がある。キーの名前は、`_`・`-`とキャメルケースの境目で語に分ける（大文字の略語の並びも続く語との境目で分ける。`DBPassword`・`AWSSecretKey`）。キーの名前は、最後の語が状態・設定・方式を表すもの（`password_policy`・`passwordScheme`・`password_changed_by`）、操作と`password`の2語のもの（`forgotPassword`・`lostPassword`。`resetPassword`・`changePassword`は仮のパスワードを返す API があるので①のまま）、公開して使う API キー（`publicApiKey`・`browserApiKey`、Algolia などの検索専用キーの名前`searchApiKey`・`search_only_api_key`。`azureSearchApiKey`などのサーバ側の検索のキーは①のまま）を除く。Django のフォームの`password1`・`password2`、`db_pwd`・`user_pwd`、WordPress の`user_pass`などのアカウントの`_pass`、Rails の`secret_key_base`・`secret_token`・`master_key`、Laravel の`remember_token`、Supabase の`service_role_key`も①のキーとする（`app_key`は Pusher の公開キーと、`pwd`だけの名前は環境変数の`PWD`（作業ディレクトリ）と、`service_role`だけの名前はロールの名前と区別できないので見ない）。`salt`・`password_salt`は②（内部属性） ②`isAdmin`、`internal_*`、`__`で始まるものなどの内部属性（GraphQLの`__typename`とMongooseの`__v`はライブラリが必ず付けるので対象外。判定は元のキーで行う。①②とも、証跡のキーの経路では、データの値をキーにしたもの（`{"users":{"alice@example.com":{…}}}`のメールアドレス、`sk_live_…`、AWSのアクセスキー、数字だけのIDや、数字を含む区切りのない16文字以上のID）を`*`にする） | 秘密情報の漏えい、攻撃の手がかり | ①高 ②中 | API3（BOPLA）、ASVS 5.0.0 8.2.3, 14.2.6 |
| A-08 | リクエストのContent-Type | `curl -sS -i -X POST -H 'Content-Type: text/plain' --data '{"a":1}' https://HOST/api/x`（`label=ctype`、検証環境） | 415（401・403・404は、Content-Typeを確かめる前に断られたのでna。同じページへの307・308（本文を送り直す転送）はたどった先で判定する（転送先を採取していなければna）。3xx・5xx・405・429は、Content-Typeを確かめるところまで届いたかが分からないのでna（同じページへの301・302・303はPOSTがGETに変わるので、転送先に直接POSTして採取し直す）。そのほかの4xxは合格） | ①200で処理される | CSRFの単純リクエストを許す | ①中 | API8、ASVS 5.0.0 3.5.2 |
| A-09 | JSON応答のヘッダ | 応答ヘッダ | `application/json`、`nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` | ①`text/html`で返す ②nosniffがない ③CSPがない | ブラウザで開かれた場合のXSS | ①中 ②中 ③情報 | OWASP REST Security CS、API8、ASVS 5.0.0 4.1.1, 3.4.4, 3.4.3 |
| A-10 | エラー形式 | 400、404、500を発生させる（C25、`label=error-*`。HTMLのエラーページと`error-*`以外の応答、付け直したラベル（`error-api#2`）は比べない） | 統一形式（例：`application/problem+json`） | ①形式が統一されていない（内部情報の露出はE-01で判定） | クライアントの誤動作 | ①情報 | API8、RFC 9457、ASVS 5.0.0 16.5.1 |
| A-11 | メソッド制御・旧版 | `-X DELETE`や`-X PATCH`（`label=method-*`。データを消しうるため手動で、検証環境で行い、コマンド生成器では作らない）、`/api/v1/`、`/beta/`、`/internal/`（`label=old-*`） | 405＋`Allow`。廃止版は410か404（合格にするのは、メソッドが405・501、旧版が404・410のときだけ。401・403（認証の内側で動くかは分からない）・3xx（ログイン画面への転送など）・そのほかの4xx・5xxはna。A-08の401・403・404と同じ考え方） | ①想定外のメソッドが通る ②古い版が動いたまま（①②とも、HTMLの画面の200（SPAの`index.html`・ログイン画面）は、APIが処理したかが分からないのでna） | 権限外の操作、修正漏れの旧版経由の攻撃 | ①中 ②中 | API5（兆候）、API9、ASVS 5.0.0 4.1.4 |

- JSON応答の`Cache-Control: no-store`はH-12で判定します。
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

結果は下表の列で記録します。ツールのCSVエクスポートは、この列構成で出力します（JSONの形はツール設計4「エクスポートとテスト」）。証跡はマスク済みの抜粋だけを載せ、生の出力は社内のアクセス制限された場所に保管します。

| 項目ID | 対象（ラベル・URL） | 実施日時 | 実施コマンド | 判定 | 該当条件 | 重要度 | 証跡（マスク済み） | 対応方針 | 例外理由・期限 | 再診断日 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| H-01 | top（https://example.com/） | 2026-10-13 10:00 | C1 | fail | ① | 高 | `strict-transport-security`なし | Webサーバ設定で付与 | — | 修正後 |
| C-03 | login（https://example.com/login） | 2026-10-13 10:20 | C18 | fail | ① | 中 | `__Host-sid=abcd…(64 chars); Path=/; Secure; HttpOnly` | SameSite=Laxを追加 | — | 修正後 |

- 対象環境（本番・検証）、実施者、許可範囲は、表の上にまとめて記載します。
- 「該当条件」列には条件番号（①②…）を書きます。ツールのルールID（例：H-01.1）の末尾の数字と一致します。
- 「実施日時」と「実施コマンド」は、各ターゲットに`#META at=2026-10-13T10:00 cmd=C1`のように付けるとツールが転記します。付けない場合は空欄で出力します。手で書いたコマンドの出し方はツール設計4「エクスポートとテスト」の「実施コマンドの要約」に従います。
- `#META at`（HARは`startedDateTime`）は、期限の判定（証明書のnotAfter、CookieのExpires、security.txtのExpires）の基準にも使います。前に採取した出力を読み直しても、採取時の状態で判定するためです。ない場合は応答の`Date`ヘッダ（サーバが応答した時刻）を、それもなければ判定した時刻を使います。ただし証明書のnotAfter（T-11）は、`#META at`がない・読めなければ判定した時刻で見ます（過去の`Date`（CDNのキャッシュの古い応答）では、期限の近い・切れた証明書を合格にしてしまうため）。判定した時刻より5分以上先の`Date`は使いません（`Date`は診断対象のサーバが書くので、未来の時刻にしてCookieの期限を短く見せ、C-05①を合格にできるため）。例外の期限（until）は手元の日付で比べます。
- 再診断では同じコマンドを実行し、前回の結果と比べます（ツール設計2「前回との差分」）。

## ツール設計1：入力モデル・推奨コマンド・パース

ツールは対象にアクセスせず、`#TARGET`マーカーで区切られた複数コマンドの出力を、ターゲットごとに解析・評価します。

### 入力モデル

- **ターゲット**：`#TARGET url=https://HOST/PATH label=top kind=auto sensitive=1`の行から次の`#TARGET`行までを1ターゲットとする。`kind`は`html`、`api`、`auto`。`auto`は、Content-Typeが`application/json`（`+json`を含む）ならAPIの応答、`text/html`か`application/xhtml+xml`ならHTMLの応答、Content-Typeがなく本文がHTMLの始まり（`<!doctype html`・`<html`）ならHTMLの応答（ブラウザが本文から推測してHTMLとして描画するため）、それ以外はそのほか（HTML向けの項目を判定しない）とする。`sensitive`は省略可（値の決まりは第0章 0.3）。`#TARGET`がない入力は「default」ターゲットを1つだけ持つ。
- **ラベルと適用範囲**：ラベルはターゲットの目的を表す（第0章 0.3）。ツールは下の対応表でターゲットごとに適用する項目を絞ってからルールを実行する。絞らないと、CORS確認やTRACEの応答にもCSPなどのヘッダ系ルールが当たり、指摘が重複したり的外れになったりする。予約・確認用ラベルが足りないとき、それを前提とする項目はnaになる。
- **評価の単位**：ヘッダ系ルールはターゲットごとの最終応答（1xx、CONNECT応答を除いた最後の応答。`-L`で別のサイトへ転送したときは、ターゲットのURLと同じサイト（登録ドメインの近似：最後の2つのラベル。`co.jp`のような2段の国別ドメインは3つ。apexから`www`への転送はたどる）の最後の応答（httpsのターゲットはhttpsのホップ）。転送先のIdPやほかのサイトの応答を対象の応答として判定しない）に、リダイレクト系ルールはチェーン全体に適用する。ホスト単位のルール（T-09〜T-11、E-03）は、ラベルに関係なく、URLから導いたホストごとに全ターゲットのデータを集約して1回だけ評価する。Locationのある3xxの本文は、ブラウザが表示しないのでHTMLの項目（ヘッダ・描画）を判定しない。本文の秘密（E-09）は利用者に届くので判定する。Cookieの項目（C-01〜C-07・C-11・C-12②）とH-15は、ターゲットのURLと同じサイトの応答（URLの分からない応答を含む）だけを見る（`-L`で転送したIdPのCookieを対象の指摘にせず、IdPのCookieを消しただけのログアウトを合格にしない）。1xx（103 Early Hintsなど）とプロキシの応答（CONNECT・407）のSet-Cookie・Clear-Site-Dataは、ブラウザが使わないので、Cookieの項目（C-09を含む）とH-15で見ない。
- **URLとHTTPS判定**：URLは`#TARGET url=`（`#TARGET`のない入力の`default`ターゲットでは画面のURL入力欄）→`#META url_effective=`の順で決める。どちらもなければ、`-v`の情報行（`SSL connection`・`ALPN`の行ならHTTPS、`Connected to … port 80`ならHTTP）でHTTPSかどうかだけを決め、それもなければ「不明」とし、HSTSなどのルールはnaにしてURLの入力を促す。C5（`http://`開始）は`#TARGET url=`と食い違わないよう、`label=http`の別ターゲットで実行する。
- **API判定**：`kind`の指定を優先し、`auto`なら最終応答のContent-Typeで判定する（第0章 0.3）。
- **マーカー**：`#TARGET`、`#META`、`#PROBE`、`#TLSPROBE`、`#CIPHERPROBE`、`#BODY`の6種類（行頭から、単語境界付き）だけをマーカーとして扱い、それ以外の`#`で始まる行（robots.txtや.envのコメントなど）は普通の本文として扱う。マーカー行は必ず直前の応答を閉じる。
- **採取の印（`run=`）**：コマンド生成器のスクリプト（と`run.sh`）は、実行ごとの乱数（16桁の16進数）を`run=`として全部のマーカー行に付ける。入力の最初の`#TARGET`の行（ほかの行ではない。本文の`#TARGET … run=…`で印を有効にさせない）に印があれば、同じ印のマーカー行だけをマーカーとし、印のないものや違う印のものは本文として読む。診断対象のサーバは印を知らないので、応答の本文に書いた`#TARGET label=login`・`#META at=`・`#PROBE`で、ターゲットを作ったり分けたりして判定を変えられない。印のない手書きの入力は、印を使わずに読む（どのマーカー行もマーカーとする）。印の違う`#TARGET`を本文として読んだときは、警告する（別の採取の出力を付け足したものは、別に判定する。`#BODY`のあとの本文の中のものも）。印は診断対象のサーバに送らない（URL・ヘッダ・送る本文に入れない。C14のキャッシュよけには別の乱数を使う）。
- **本文の印（`#BODY`）**：コマンド生成器のスクリプトは、本文を取るコマンドを`-i`ではなく`-D "$hdr" -o "$body"`で採取し、ヘッダ、`#BODY run=…`の行、本文の順に出す（取る前に2つのファイルを空にし、curl が失敗したときに前のコマンドのヘッダ・本文を出さない）。`#BODY`のあとは、次のマーカーまで（本文は64K文字で打ち切る）を、直前の応答（`-L`では最後のホップ）の本文としてそのまま読み、ステータス行・ヘッダ・openssl の出力・`-v`の行として読まない。`-i`の出力では本文と次の応答を見分けられず、本文を「HTTP/1.1 200 OK」と偽のヘッダで始めると、本物の応答を置き換えられるため。`#BODY`の前に読める応答がない（curl が失敗した、ステータス行を読めなかった（2桁のコードなど）とき）ときは、本文を捨て、解析できない行として警告する（ふつうに読むと、本文の偽のステータス行が応答になる）。印のない手書きの入力では、どの`#BODY`の行もマーカーとして読む。手書きの`curl -i`の採取（`#BODY`のないもの）は、本文の先頭のステータス行で偽装できる（`-i`の出力のまま読むため）。
- **curlの共通の指定**：コマンド生成器のスクリプトは、すべてのcurlを`curl -q -sS --connect-timeout 10 --max-time 30`で始める。`-q`（最初の引数でないと効かない）で利用者の`~/.curlrc`を読まない（`header = "Authorization: …"`で、認証を付けないはずの`unauth-api`やCORSの採取にトークンが付くため）。時間の上限で、応答しないサーバでスクリプトが止まらないようにし、プローブ（`/backup.zip`など）は全体をダウンロードせずに打ち切る（打ち切っても採った先頭とステータスは残る）。WebSocket（C16）は`--http1.1`で採取する（HTTP/2ではcurlが`Connection`・`Upgrade`を送らない）。一時ファイル（ヘッダ・本文・プローブ・TLSの出力。認証後の応答を含む）は、`trap`でCtrl-Cやkillで止めたときも消す。出力ファイル（`out.txt`・`jar.txt`など）は、最初に消してから作る（`umask`は新しく作るファイルにだけ効くため）。http の採取（C5）と部分一致のOrigin（C6）には、ホストのポートを付けない（https の8443番にhttpで送ると400になり、T-04を誤って合格にするため）。`run.sh`も`-q`・時間の上限を付け、`sh`（dash）で動く。opensslの時間の上限と、証明書の期限・SANの出し方は「推奨コマンド」のC11・C12・C23の例のとおり。
- **ラベルの形**：英数字・日本語などの文字と`_`・`.`・`-`・空白（前後を除く）の64文字まで（`*`は例外の照合で任意の文字列の意味になるので使えない。「HAR 」で始まるものも、HARのターゲットの突き合わせのキー（`HAR メソッド URL`）と同じ形になるので使えない）。それ以外（引用符・波かっこを含むもの）は`invalid-label`にする（ラベルは画面・エクスポート・例外ファイルにそのまま出るため）。`#TARGET`で読む名前は`url`・`label`・`kind`（`html`・`api`・`auto`。大文字小文字を区別しない）・`sensitive`・`run`で、書き間違えた名前（`lable=`）、受け付けない形のラベル、知らない`kind`は、解析警告（invalid-attr）で知らせる（黙って`default`・`auto`にすると、予約したラベルの横断の判定が動かない理由が分からないため）。
- **同じラベル**：同じラベルのターゲットが複数あれば（貼り付けとHARの両方に`login`を付けた場合を含む）、2つ目以降を`top#2`のように付け直して別に判定し、解析警告（duplicate-label）を出す。適用する項目は元のラベル（`#2`を除いたもの）と同じにする（`label=http`をwwwとapexの2つで採取した場合も、2つ目でT-04・C-10を判定する）。横断の判定には最初のものだけを使う（`session-sample-*`・`csp-sample-*`のように接頭辞で集める横断ルールも、付け直したもの（`#2`）は比べない）。

### ラベルと適用する項目

ラベルは前方一致で判定し（`cors-*`など）、どれにも当てはまらなければ一般ターゲットとして扱います。診断カバレッジで案内する「必要なラベル」は、この対応表から実行時に作り（`engine/labels.ts`の`requiredLabels`）、横断ルールが必要とするラベル（C-07②、C-09①、C-12①、H-02③、H-04⑤、A-10）を足します。`csp-sample-*`はH-04⑤のためだけに案内します。ルールの中でラベルを確かめる場合も、この対応表と同じ範囲にそろえます。この一覧はengine/labels.json（ラベルの接頭辞と項目IDの配列）としてルールセットと同じ版で管理します。項目IDの後ろに条件を付けて絞ることもできます（例：T-05.2、E-04.1）。条件を付けた指定は、ルールを実行した後の結果（Finding）に適用します。手動確認の項目（T-02、T-03、T-13、C-14、C-15、A-04〜A-06）は合否を判定しません。対応するラベルのターゲット（T-03の`method-override`、T-13の`xff-spoof`）はターゲットごとの一覧に応答のステータスとともに表示され、診断カバレッジでは「手動確認」となります。自動の項目の手動の条件（T-07①③・C-04②・H-11③）とあわせて、結果は第8章の様式に記録します。opensslの出力をまとめるtlsラベルのターゲットには、ホスト単位のルール（T-09〜T-11）だけを適用します。

| ラベル | 目的 | 適用する項目 |
| --- | --- | --- |
| 一般（下記以外。ラベルなしを含む） | 通常のページ・API | 第1章（H-15とH-02③を除く）、C-01〜C-06・C-08・C-10・C-11・C-13、R-04・R-06〜R-08、T-05②・T-12、E-01・E-02・E-04（②は、URLが`security.txt`のとき。条件は第5章の表）・E-05〜E-12・E-13②、第6章（A-01は③だけ。A-01①②は`unauth-*`、A-08は`ctype`、A-11は`method-*`・`old-*`、A-10は横断ルールで判定する。A-04〜A-06は手動確認） |
| `error-*` | エラー応答 | 第1章（H-15とH-02③を除く）、E-01、A-10 |
| `http` | HTTPでの採取（apexのhttpも含む） | T-04、T-05、C-10、A-01③（HTTPでのBasic認証） |
| `apex` | apexドメイン（https） | H-01、H-02①② |
| `pre-login`、`login`、`session-sample-*` | ログイン関連 | C-01〜C-11、C-13、H-12（C-07②・C-09①は横断ルール）。`pre-login`と`login`にはA-02・A-03も適用する |
| `logout` | ログアウト | H-15、C-12②（C-12①は横断ルール） |
| `after-logout` | ログアウト後 | C-12①（横断ルール。`logout`と比べ、`mypage`があればログインできていたかも見る） |
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
| `unauth-*` | 未認証アクセス（認証情報を付けずに取得） | A-01、A-02、A-07 |
| `ctype` | リクエストのContent-Type | A-08 |
| `method-*`、`old-*` | メソッド制御・旧版 | A-11 |
| csp-sample-\* | CSPのnonce比較 | H-04⑤（横断ルール）。そのほかは一般ターゲットと同じ項目 |

### 既知のテスト値

ルールは、推奨コマンドが送る固定のテスト値が応答に現れるかどうかで判定します。値を変える場合は、ツールの設定とコマンドの両方を変えます。

| テスト値 | 使うコマンド | 検出する場所 | 対応項目 |
| --- | --- | --- | --- |
| `https://evil.example` | C6、C8、C16、C19 | ACAO、`Location`、WebSocketの101応答 | R-01、R-05、R-09、T-06 |
| `null`（Origin） | C7 | ACAO | R-02 |
| `https://<ホスト名>.evil.net`（Origin） | C6（label=cors-partial） | ACAO | R-03 |
| `evil.example`（X-Forwarded-Host） | C14 | `Location`、本文 | T-07② |
| `crlf=1` | C20 | 応答の`Set-Cookie` | T-08 |
| `test123`（callback） | C22 | 本文の先頭`test123(` | E-06 |
| `127.0.0.1`（X-Forwarded-For） | C17 | ステータスコード、本文 | T-13 |

### プローブの判定パターン

C13の`#PROBE`は、HTTP 2xxで取得でき、パスと採った先頭の両方がパターンに一致したときだけ、対応する1つの項目で判定します。採る長さは64バイトで、目印が後ろにあるテキストの形式（phpinfo・web.xml・package.json・composer.json・security.txt）は4KB、server-statusは1KB（目印は先頭にあり、後ろはほかの利用者のリクエストのURLの一覧）。長く採るほど、ほかの応答（SPAのHTML、どのパスにもJSONを返すAPI、記事）の中の語に一致しやすいので、中身の目安はファイルの先頭に固定するか、そのファイルの決まった形に絞り、HTMLの画面はphpinfo・server-statusのほかはどのパターンにも一致としません。git のHEAD（ブランチ・detached・SHA-256・bare）、zip、package.json（node\_modulesの実物189件）、ソースマップ（実物168件）、どのパスにもHTMLを返すSPA（`vite preview`）は実物で確かめました。

404・403のエラーページ（JSONやXMLのエラー応答）がパターンに一致しても、そのファイルを取得できたことにはならないので、2xx以外は一致としません。中身のパターンも、エラー応答に一致しない形にしています（`<?xml`だけ、`{`だけでは判定しない）。

| パターン名 | 対象パス | 中身の目安（採った先頭） | 判定する項目 | 一致したとき |
| --- | --- | --- | --- | --- |
| git-head | /.git/HEAD | `ref: refs/`で始まる。またはコミットのID（40桁・64桁の16進数）だけの1行（detached HEAD。CI・デプロイで多い） | E-03 | ①（高） |
| svn-entries | /.svn/entries | ファイルの先頭が、形式番号・空行・`dir`の3行（Subversion 1.4〜1.6。形式番号は8〜10）か、`12`だけ（1.7以降）か、ファイルの先頭（XML宣言のあと）の`<wc-entries`（1.3まで）。行の始めのどこかの数字だけの行では、200で返すsoft-404の「404」や、数字だけの本文（件数を返すAPI）に一致する | E-03 | ① |
| ds-store | /.DS\_Store | マジックバイト（`00 00 00 01 Bud1`） | E-03 | ① |
| dotenv | /.env | `KEY=value`の行（`export KEY=`、`KEY = value`も。名前は英大文字・数字・`_`だけ。小文字の名前はほかの平文の応答と見分けにくいので入れない） | E-03 | ① |
| web-xml | /WEB-INF/web.xml | ファイルの先頭（XML宣言などの処理命令と、使用許諾などのコメントのあと）の`<web-app`（名前空間の接頭辞の`<j:web-app`も）か`<!DOCTYPE web-app`。本文の途中のもの（SPAのHTMLのカスタム要素`<web-app>`）には一致としない | E-03 | ① |
| package-json、composer-json | /package.json、/composer.json | 最上位に（入れ子の中のキーは数えない）、そのファイルに特有のキー（package.jsonは`"private"`・`"scripts"`・`"dependencies"`など。汎用の語の`"main"`・`"module"`・`"exports"`・`"bin"`は`"name"`か`"version"`と組のときだけ、composer.jsonは`"require"`・`"autoload"`など）か、名前の形（`"@scope/名前"`、`"vendor/名前"`）。`"name"`・`"version"`・`"type"`のような一般的なキーだけでは一致としない（どのパスにも`{"name":"api","version":"1.0"}`を返すAPIで①（高）の誤検知になるため）。特有のキーが採った先頭より後ろにある本物のファイルは②になる（4KBで、node\_modulesの実物の約9割が一致する。64バイトでは33%） | E-03 | ① |
| backup | /backup.zip | ZIPのマジックバイト（`PK\x03\x04`） | E-03 | ① |
| phpinfo、server-status | /phpinfo.php、/server-status | 出力の決まった形（phpinfoはtitleの「… phpinfo()」、見出しの`<h1 class="p">PHP Version`、CLIの形の「phpinfo()」と「PHP Version =>」の行。mod\_statusは見出しの`<h1>Apache Server Status for`と`<dt>Server Version:`）。「PHP Version」の語だけでは、記事の「Requires PHP Version 8.1」に一致する。phpinfoのtitleはCSSのあと（約1.3KB）にあるので4KB、mod\_statusの見出しはDOCTYPEのすぐあとにあるので1KBを採る | E-03 | 一致すれば①。200で一致しなければ②（判定保留） |
| security-txt | /.well-known/security.txt | RFC 9116のフィールド（`Contact:`・`Expires:`・`Canonical:`・`Policy:`・`Encryption:`など）で始まる行（大文字・小文字を区別しない。採った先頭がコメント`#`で始まり、フィールドがないもの（security-txt-comment）は、本当のsecurity.txtかが分からない（どのパスにも`# …`の平文を返すサーバもある）のでE-04をnaにする） | E-04 | E-04②をpassにする |
| source-map | 追加した.mapのパス | 採った先頭（64バイト）に`"version":3`か、ソースマップに特有のキー（`"mappings"`、`"sources"`など）。`"version"`・`"file"`だけでは一致としない（どのパスにも`{"version":"2.1.0"}`を返すAPIで誤検知になるため） | E-13 | ①（中） |

- robots.txt・security.txt・追加した.mapのパスはE-03の対象外です（E-04・E-13で判定）。robots.txtのプローブは判定に使わず、E-04①は`robots.txt`のターゲットの本文で判定します。
- ディレクトリリスティング（`Index of /`）は、一般ターゲットの本文からE-02として判定し、プローブでは使いません。

### 推奨コマンド

各コマンドの前に`echo "#TARGET url=$T label=..."`を出力してから実行します。画面の「コマンドを作る」（コマンド生成器、`src/commands.ts`）は、ホスト名とパスからこれらをまとめたスクリプトを作ります。

| ID | 目的 | コマンド | 出力の特徴・備考 |
| --- | --- | --- | --- |
| C1 | ヘッダ（GET） | `curl -sS -D - -o /dev/null "$T"` | ヘッダブロックのみ |
| C2 | ヘッダと本文 | `curl -sS -i "$T"` | ヘッダ、空行、本文。curl 8.10.0以降の正式名は`--show-headers`。コマンド生成器は、`-i`のコマンドを`-D "$hdr" -o "$body"`に置き換え、ヘッダ、`#BODY run=…`の行、本文、改行の順に出す（本文の印。最後の改行は、本文が改行で終わらないと、次の`#TARGET`の行が本文の続きになり、ターゲットが合わさるため） |
| C3 | HEAD（補助） | `curl -sS -I "$T"` | GETと結果が違うサーバがある。コマンド生成器は作らない |
| C4 | 詳細（推奨） | `curl -sS -v -o /dev/null "$T" 2>&1` | `>`送信、`<`受信、`*`情報。合意したTLSバージョンと暗号が分かる（T-09②、T-10③の一部） |
| C5 | リダイレクト追跡 | `curl -sS -L -D - -o /dev/null -w '\n#META response_code=%{response_code} num_redirects=%{num_redirects} url_effective=%{url_effective} http_version=%{http_version}\n' "http://HOST/"` | 複数のヘッダブロック＋`#META`行。`label=http`のターゲットで実行 |
| C6 | CORS反射 | `curl -sS -v -o /dev/null -H 'Origin: https://evil.example' "$T" 2>&1` | `> Origin:`で送信値を照合 |
| C7 | CORS null | C6のOriginを`null`にしたもの | 同上 |
| C8 | CORSプリフライト | 第3章のコマンド例 | Allow-Methods、Allow-Headers、Max-Age |
| C9 | メソッド | `curl -sS -i -X OPTIONS "$T"`、`curl -sS -i -X TRACE "$T"` | `Allow`ヘッダ、TRACEの反射 |
| C10 | ヘッダJSON | `curl -sS -o /dev/null -w '%{header_json}' "$T"` | ヘッダ名が小文字のJSON（curl 7.83以降）。ヘッダの形（名前がヘッダに使える文字、値が文字列の配列、`date`・`content-type`などよくあるヘッダを含む）でないJSON（`curl -s`で出力したAPIの本文など）は応答にせず、解析警告にする。ステータスは`#META response_code`から取り、JSONのあとに出したものも使う。ステータスが分からない応答では、ステータスで判定する項目（C-12①、A-01①②）をnaにする。最初のヘッダの名前に`.`などヘッダに使える記号があっても、JSONの始まりとして読む |
| C11 | TLS・証明書 | 下記コードブロック | `Protocol`、`Cipher is`、`Verify return code`、`notAfter=` |
| C12 | 旧TLSの拒否 | 下記コードブロック | 1行1プロトコルの`#TLSPROBE`行（T-09①） |
| C13 | 既知ファイル | 第5章のコマンド例 | 1行1パスの`#PROBE`行。`path`、`head`（採った先頭のBase64。長さは「プローブの判定パターン」）、`code`、`size`の後、行末に`ct=`（空白を含んでよい） |
| C14 | Hostヘッダインジェクション | `curl -sS -i -H 'X-Forwarded-Host: evil.example' "${T}?csa=$CB"`（`CB`は実行ごとの乱数） | テスト値がLocationや本文に現れるかを検出。クエリにキャッシュよけの乱数を付けて、共有キャッシュ（CDN・リバースプロキシ）のキーをほかの利用者のリクエストと分ける（偽装した応答をほかの利用者に返させないため）。乱数は採取の印（`run=`）と別にする（印をサーバに送ると、サーバが本文に正しい印のマーカーを書けるため） |
| C15 | HTTP応答のCookie | `curl -sS -D - -o /dev/null http://HOST/` | C-10の判定。`label=http`。コマンド生成器はC5の`http`ターゲットで兼ねる |
| C16 | WebSocketのOrigin | 第3章のコマンド例 | ハンドシェイク応答のステータス（101かどうか） |
| C17 | 送信元IPの偽装 | 第4章のコマンド例 | 偽装ありとなしのステータスの差（手動で比較） |
| C18 | ログイン手順 | 第2章のコマンド例（pre-login、login、session-sample、mypage、logout、after-logout） | 予約ラベル付きの複数ターゲット（C-07②、C-09、C-12、H-15） |
| C19 | オープンリダイレクト | 第4章のコマンド例（label=open-redirect） | テスト値がLocationに現れるか（T-06） |
| C20 | CRLFインジェクション | 第4章のコマンド例（label=crlf、検証環境） | 注入したSet-Cookie: crlf=1が現れるか（T-08） |
| C21 | メソッド上書き | 第4章のコマンド例（label=method-override、検証環境） | 手動で比較（T-03） |
| C22 | JSONP | curl -sS -i 'https://HOST/api/x?callback=test123' | 本文の先頭がtest123(か（E-06） |
| C23 | 暗号の個別確認 | 下記コードブロック | 1行1暗号の#CIPHERPROBE行（T-10①③） |
| C24 | CSPのnonce比較 | for i in 1 2; do echo "#TARGET url=$T label=csp-sample-$i"; curl -sS -D - -o /dev/null "$T"; done | 2つの応答のCSPのnonceを比較（H-04⑤） |
| C25 | エラーの誘発 | `curl -sS -i "$H/%%%"`（label=error-url）、`curl -sS -i "$H/api/items/abc"`（label=error-api）など。第5章のコマンド例 | エラー応答のヘッダと本文（E-01、A-10。A-10はAPIのエラー応答を2つ以上） |
| C26 | リクエストのContent-Type | `curl -sS -i -X POST -H 'Content-Type: text/plain' --data '{"a":1}' "$T"`（label=ctype、検証環境） | 415で拒否されるか（A-08） |

```sh
# C11・C12・C23：コマンド生成器の出力の抜粋（#TARGET・#META の行は除く。HOST は診断対象のホスト）
# openssl には、timeout があれば20秒の上限を付ける（timeout のない環境ではそのまま実行する）
if timeout --foreground 1 true 2>/dev/null; then ossl() { timeout --foreground 20 openssl "$@"; }
elif command -v timeout >/dev/null 2>&1; then ossl() { timeout 20 openssl "$@"; }
else ossl() { openssl "$@"; }; fi
# C11：サーバはハンドシェイクのあとに任意のデータを送れるので、最初の Verify return code: の行で切る（切らないと、サーバが notAfter=・DNS:・
#   a:PKEY: を書いて T-10・T-11 を変えられる）。SAN は x509 が名前を改行ごと出すので、見出しと値の2行だけを取る
# C12（#TLSPROBE、T-09①）・C23（#CIPHERPROBE、T-10①③）：
#   ok=1   : ハンドシェイク成功（終了コードが0で、要約の中に「New, <版>, Cipher is <暗号>」の行がある。版は問わない）
#   ok=0   : サーバが拒否（unsupported protocol を含む）
#   ok=err : 手元の openssl がその指定に対応しない・実行できない・時間切れ（証明書の検証の行を除いた標準エラーに OSSL_ERR の語があるか、
#            終了コードが124以上）→ ツールでは na（C23 は「試していない」）
# C23 の RC4-SHA・DES-CBC3-SHA・NULL-SHA256 は T-10①、AES128-SHA（静的RSA＋CBC）・ECDHE-RSA-AES128-SHA（CBC）は T-10③
ossl s_client -connect 'HOST:443' -servername 'HOST' -showcerts </dev/null 2>&1 | sed '/^ *Verify return code:/q'
cert=$(ossl s_client -connect 'HOST:443' -servername 'HOST' </dev/null 2>/dev/null | openssl x509)
if [ -n "$cert" ]; then printf '%s\n' "$cert" | openssl x509 -noout -subject -issuer -dates; printf '%s\n' "$cert" | openssl x509 -noout -ext subjectAltName | tr -d '\r' | head -n 2; fi
OSSL_ERR='unknown option|no protocols available|no cipher match|invalid command|error with command|ssl_conf_cmd|command not found'
tout=$(mktemp); terr=$(mktemp)
for v in tls1 tls1_1 tls1_2 tls1_3; do
  ossl s_client -connect 'HOST:443' -servername 'HOST' -$v -cipher 'DEFAULT@SECLEVEL=0' </dev/null >"$tout" 2>"$terr"; rc=$?
  if [ $rc -ge 124 ] || grep -vE '^(depth=|verify (error|return))' "$terr" | grep -qiE "$OSSL_ERR"; then r=err
  elif [ $rc -eq 0 ] && sed '/^ *Verify return code:/q' "$tout" | grep -qE '^New, [^(,][^,]*, Cipher is [^(]'; then r=1
  else r=0; fi
  printf '#TLSPROBE run=%s v=%s ok=%s\n' "$RUN" "$v" "$r"
done
for c in RC4-SHA DES-CBC3-SHA NULL-SHA256 AES128-SHA ECDHE-RSA-AES128-SHA; do
  ossl s_client -connect 'HOST:443' -servername 'HOST' -tls1_2 -cipher "$c:@SECLEVEL=0" </dev/null >"$tout" 2>"$terr"; rc=$?
  if [ $rc -ge 124 ] || grep -vE '^(depth=|verify (error|return))' "$terr" | grep -qiE "$OSSL_ERR"; then r=err
  elif [ $rc -eq 0 ] && sed '/^ *Verify return code:/q' "$tout" | grep -qE "^New, [^(,][^,]*, Cipher is $c\$"; then r=1
  else r=0; fi
  printf '#CIPHERPROBE run=%s c=%s ok=%s\n' "$RUN" "$c" "$r"
done
rm -f "$tout" "$terr"
```

一部のコマンドだけを`#TARGET`付きでまとめて実行する簡易版のラッパーは、リポジトリの`run.sh`です（top・http・notfound・cors-reflectの4つだけ。ログインの流れ、CORSのnull・部分一致・プリフライト、TLSは含まない。出力の`out.txt`をそのままツールに読み込めます）。

### パース上の注意点

| 論点 | 内容 | 実装方針 |
| --- | --- | --- |
| 改行 | HTTP/1.1のヘッダはCRLF。貼り付けでは混在する。Windowsのcurlの`-v`（`2>&1`）は受信ヘッダの行をCR CR LFで終える | 最初に、続くCRとLF（CR CR LFを含む）と単独のCRをLFに統一する（CR CR LFを2つの改行と読むと、受信ヘッダがすべて失われる）。CRの並びの先頭でだけLFを探す（LFの付かない長いCRの並びで、入力の長さの2乗の時間にしない）。ただし画面の入力欄（textarea）は、値を受け取った時点でCR CR LFを改行2つに変えるので（貼り付けもファイルの読み込みも入力欄を通る）、`-v`の受信ヘッダ（`< `の行）の途中の空行は無視し、`<`の行だけを終端とする。E2E（`e2e/app.spec.ts`）で入力欄を通して確かめる |
| 印のある入力の応答のヘッダ・トレーラ | 診断対象のサーバは応答のヘッダとchunkedのトレーラ（curlは`-D`に書く）に任意の行（`notAfter=…`、`Verify return code: 0`、`* Connected to …`、`> Cookie: …`、ステータス行の形の行）を書ける | 印のある入力では次のように読む。openssl の出力を始めるのは`tls`のラベルだけで、応答の外の行か、本文の中の`CONNECTED(`の行（`Connecting to`の行のあとのものを含む）だけ（ヘッダの中の行では始めない）。`-v`として読むのは、ターゲットの最初の行（空行とデバッグ版のcurlの`WARNING:`・`Note:`の行を除く）が`* `で始まるcurlの行（`* WARNING: failed to open cookie file`・`* !!! WARNING !!!`を含む）のときだけ（サーバはcurlの行より前に行を書けない）。ヘッダの途中（空行の前）のステータス行の形の行と、ヘッダの終わりの空行のあとのコロンのあるステータス行の形の行（`HTTP/1.1 401 Unauthorized: x`。curlはヘッダとして受け付けて出す）で新しい応答を始めない（次の応答の前には、`-D`では空行、`-v`では`<`の行がある）。chunkedのHTTP/1.xの応答のヘッダのあと（`#BODY`の前）の行はトレーラとして読み飛ばし、次の応答にするのは、1xx・3xx・401・407のあとのコロンのないステータス行だけ（curl 7.82以前はコロンのないトレーラの行も書く）。chunkedの3xxのあとに読んだホップは、`#META`に`num_redirects=`がある（`-L`で採取した）ターゲットのときだけ残し、ほかは捨てて、`#BODY`の本文を3xxまでの最後の応答に付ける。`#BODY`の前に本文として読んだ行（トレーラ・curlの失敗の行）は捨て、本文は`#BODY`のあとだけにする。印のない`#TARGET`のあとに印のある出力が続くと、印を使わずに読むので警告（mixed-run）を出す |
| `-v`のプレフィックス | ` >  `送信、` <  `受信、` *  `情報、`{ [n bytes data]`本文。本文にも` *  `や` >  `で始まる行（箇条書きや引用）がある | verboseモードのターゲットで、かつ本文の読み取り中でないときだけ解釈する。verboseモードかは、curlの情報行（`* Connected to`・`* Trying`・`* SSL connection`など。プロキシを使うと最初の行になる`* Uses proxy env variable`も）で見分ける。` >  `行には送信したCookieやAuthorizationも含まれるためマスキング対象にする |
| `-v`のヘッダ終端 | 終端は` <  `だが、貼り付けで末尾の空白が落ちて`<`だけになることがある | `^<\s*$`を終端として扱い、その応答を閉じる（-vの出力では本文を解析せず、本文はC2で取る）。`-o /dev/null`がなく本文も出力した場合は、次の`< HTTP/`の行（`-L`の次の応答）、`* Issue another request`の行、`> GET /x HTTP/1.1`の形の要求行までを読み飛ばす。本文の中の`HTTP/1.1 200 OK`や、`* `・`> `で始まる行を、応答・情報行・送信ヘッダとして読まないため |
| ブロック境界 | ステータス行`HTTP/(1.0・1.1・2・3) コード`（curlと同じく、大文字小文字を区別せず、`HTTP/2.0`・`HTTP/1.1 200OK`・4桁以上のコード（先頭の3桁を使う）も受け付ける）。HTTP/2と3はreason phraseなし | ステータス行から空行までを1応答とする |
| 応答の閉じ忘れ | 本文の後に別コマンドの出力が続くと、本文に混入する | マーカー行とopensslの開始行（`CONNECTED(`、`depth=`、`subject=`、`notAfter=`など。OpenSSL 3.5が`CONNECTED(`の前に出す`Connecting to <アドレス>`も。次の行が`CONNECTED(`のときだけ。`tls`のラベルでは、次の行が`depth=`などopensslの出力の始まりのときも（OpenSSL 3.5は`2>&1`で`Connecting to`のすぐあとに`depth=`を出す））で応答を閉じる（`CONNECTED(`の行と、`Connecting to`の次の行が`CONNECTED(`のものは、応答の本文の中でも閉じる。同じターゲットでHTTPの応答に続けたopensslの出力を本文に入れないため。ただし生成スクリプトの出力（印のある入力）では、本文の中で閉じるのは`tls`のラベルだけ。サーバが本文に`CONNECTED(n)`を書いて、そのあとの本文を消せないようにするため）。本文は64K文字で打ち切る。`#TARGET`・`#META`の値は引用符で囲んでもよい（`url="https://…"`）。`url=`がスキームのあるURLとして読めないときは警告する（画面のURL入力欄の値（`www.example.com`）も同じ。httpとして扱うので、H-01①・C-01①が黙って消えないようにする） |
| `#PROBE`の属性 | Content-Typeは`text/html; charset=utf-8`のように空白を含む | `ct=`は行末に置き、`ct=`以降を行末まで値とする。`=`を含まない語は無視する |
| `-L`の複数応答 | すべてのホップのヘッダが順に出る | `responses[]`で保持し、`kind`（final・redirect・informational・connect・challenge（curlが認証し直した401））を付与。各ホップには、ターゲットのURLから`Location`をたどったURLを持たせる（HARと同じ）。`url=`がhttpで、`-L`で同じサイト（apexとwww。`http://example.com`→`https://www.example.com`）のhttpsに転送されたターゲットは、`http`ラベル以外ならHTTPSの応答として判定する（URLがhttpのままだと、H-・C-の項目がすべて黙って適用外になる）。httpのホップで発行したCookieも判定する |
| 1xx・CONNECT・認証のやり直し | 100 Continue、103 Early Hints、プロキシの`200 Connection established`、プロキシの認証要求`407`（`-x … -U`）、curlが認証し直す`401`（`--digest`・`--ntlm`・`--negotiate`・`--anyauth`） | 評価対象から除外。理由句が違うプロキシもあるため、本文のない2xxのあとに応答が続く場合もCONNECTの応答とみなす（ヘッダの形でプロキシを見分ける作りは、ヘッダを足す本物のプロキシを壊すので採らない）。理由句`Connection established`の200をCONNECTの応答とみなすのは、あとに応答が続くときか、プロキシの応答の形（本文がない（`curl: (35) …`のようなcurlの失敗の行だけなら本文としない）、ヘッダが`Proxy-Agent`・`Via`・`Date`・`Connection`・`Keep-Alive`・`Proxy-Connection`・`Content-Length: 0`だけ）のときだけ（最後の応答の理由句を変えるだけでサイトの応答を消させない。プロキシ越しのCONNECTのあとでcurlが失敗したものは、サイトの応答にしない）。`-v`では、1xxと、`> CONNECT`への2xxの応答のあとを本文として読み飛ばさない（そのあとに本当のリクエストの`* SSL connection`・`> Origin`・`> Cookie`が続く）。407と、あとに応答が続く401も、その URL 自身の応答ではないので評価対象から除く（407を最初の応答にすると、T-04を誤って合格にし、A-01①を見逃す）。1xxとプロキシの応答（CONNECT・407）は、Set-Cookie・Clear-Site-Dataを見る項目でも使わない（入力モデルの「評価の単位」）。プロキシの応答しかないターゲットは警告する |
| `-v`の本文の中の`< HTTP/` | `-v`で本文も出力すると、本文に`< HTTP/1.1 200 OK`のような行（curlの出力を載せたページ）がありうる | 次の応答とみなすのは、前の応答のあとに次の応答が続きうる（転送・1xx・401・407）ときだけ。`#TARGET`ごとにCONNECTの状態を初期化する |
| 本文にくっついたマーカー | 改行のない本文（手で書いた`curl -i`のJSON）の直後に`#TARGET`が続く（`{"id":1}#TARGET url=…`） | JSON・HTMLの閉じ（`}`・`]`・`>`）の直後の`#TARGET url=`などで行を分ける（分けないと、次のターゲットが前の本文に吸い込まれて黙って消える）。`#TARGET url=`・`label=`は、空白・引用符以外のどの文字の直後でも分ける（`Unauthorized`のような平文の本文のあと。本文の文中の`… #TARGET url=`と、`set -x`の`+ echo '#TARGET …'`は分けない）。生成スクリプトも`#TARGET`の前に改行を出す |
| 進捗表示 | `-s`を付けずに`2>&1`にすると、curlの進捗表示が出る。遅い応答では、進捗表示とステータス行が同じ行になる | 見出しの行と数字の行（数字の欄と時刻の欄`--:--:--`）を読み飛ばし、応答の行の前にくっついた部分を取り除く。時刻の欄は curl の版で違う（`--:--:--`、`0:00:02`、curl 8.22 の`00:02`や空欄）。数字の欄の並び（%の欄は0〜100）で見分け、進捗表示だけの行は時刻の欄が1つ以上あるものだけを読み飛ばす（本文の数字の行を消さない）。時刻の欄が空欄の行（数字の欄のあいだに10個以上の空白）は、応答の本文の外のときだけ読み飛ばす（本文の桁をそろえた数値の表を消さない） |
| 大文字・小文字 | HTTP/2と3ではヘッダ名を小文字で送ることが求められる | 名前は小文字に正規化する |
| 重複ヘッダ | Set-Cookieは複数行。1行にカンマでつないだものは、`, 名前=`の前で1件ずつに分ける（Expiresの日付のカンマと、属性（`;`）のない値の中のカンマ（`prefs=lang=ja,tz=JST`）では分けない）。CSPが複数あればすべて適用される（あるポリシーにないディレクティブは、別のポリシーが指定し、そのポリシーに同じ指摘がなければH-04②・H-05①にしない。同じ緩いポリシーが2つあっても指摘する） | 名前ごとに配列で保持。Set-Cookieはカンマで結合しない。1つの応答で読むSet-Cookieは後の300個まで（ブラウザも1つのドメインに約180個までしか保存せず、古いものから捨てる。巨大なSet-Cookieの行で数万件の指摘を作らないため）。超えたら先のものを捨てて警告（too-many-cookies）を出す。`-i`・`-D`・`%{header_json}`・HARのどれも同じ |
| 折り返し（obs-fold） | 行頭が空白かタブの継続行（RFC 9112で非推奨） | 前の行の値に空白1つでつなぐ（報告はしない） |
| opensslの出力 | OpenSSL 1.1系と3系で形式が違う | 複数の正規表現を順に試す |

### HAR形式の取り込み

ブラウザの開発者ツールで書き出したHAR（HTTP Archive）ファイルを、curlの出力と同じターゲットの集まりに変換して評価します。ログイン前後・API・ログアウトの一連の通信をブラウザの操作だけで採取でき、横断ルール（C-09、C-12など）を手早く適用できます。

- **判別と結合**：HARはファイル読込で受け、拡張子が`.har`か、先頭（200文字以内）に`"log":`のキーがあるファイルをHARとして扱う（`log.entries`が配列でなければ、エントリのないHARとして読む）。テキストエリアの入力は`#TARGET`形式で解析し、両方から作ったターゲットを結合して評価する。
- **変換**：`log.entries`を、リダイレクトのホップをつないだチェーン（下の「リダイレクト」）ごとに1ターゲットにする。URLは`request.url`、応答は`response.status`、`response.httpVersion`、`response.headers`（nameとvalueの配列）から作る。HTTPバージョンは、ブラウザごとの表記（h2、HTTP/2.0など）を1.1・2・3に正規化する。名前が`:`で始まるHTTP/2の疑似ヘッダ（`:status`など）は除外する。1つのヘッダに複数の`Set-Cookie`を改行でつないで書き出すものがあるため、`Set-Cookie`は改行で1件ずつに分ける（分けないと2つ目以降のCookieを判定せず、証跡に生の値が出る）。本文は`response.content.text`のうちHTML・JSON・JS（JSONPのE-06、ソースマップの参照のE-13のため）・テキストとXML（`text/plain`・`text/xml`・`application/xml`・`application/…+xml`。スタックトレースやXMLのエラーのE-01、robots.txt・security.txtのE-04のため。`image/svg+xml`などは残さない）だけを先頭64K文字まで残す（`encoding: base64`ならデコード）。リクエスト側は、全ホップのリクエストからAuthorizationの有無とCookieの名前（値は持たない）だけを取り出す。ブラウザは解析用・同意用のCookieも送るので、機密応答の推定（`sentAuth`、第0章 0.3）には、Authorizationか、セッションCookieらしい名前（組織プロファイルの指定があればそれ）のCookieを送ったときだけを数える。Secure の Cookie は https のホップでしか送られないため、最初の http のリクエストだけでは分からない。
- **由来の記録**：HAR由来のターゲットには`meta.source = 'har'`と`meta.cmd = 'HAR'`を設定する。診断カバレッジの理由（HARに機密情報が含まれないなど）と、第8章の「実施コマンド」列に使う。除外したエントリの数（har-excluded）と、機密情報が除かれたHARの検出（har-sanitized）は、解析警告としても表示する。`#META`で受け付ける名前は`at`・`cmd`・`run`・`response_code`・`num_redirects`・`url_effective`・`http_version`だけで、`source`・`method`は受け付けない（curlの出力をHAR由来と取り違えないため。入力の名前をそのままプロパティにしない）。
- **リダイレクト**：HARではリダイレクトの各ホップが別のエントリになる。ブラウザが内部で作った転送（HSTS・HTTPS-Upgradesの`307 Internal Redirect`）は、サーバの応答ではないので取り込まず、件数を警告する。内部の転送とするのは、307で、ネットワークに出ていない（`serverIPAddress`がない）うえに、理由句が`Internal Redirect`か`Non-Authoritative-Reason`ヘッダがあるものだけ（理由句とヘッダはサーバも返せるので、それだけで除くと、診断対象のサーバがログインのPOSTやhttpからhttpsへの転送を判定から外せる）。`response.redirectURL`と次のエントリのURLでつなぎ、1つのターゲットの応答チェーンに組み直す。ブラウザはフラグメントを除いたURLでリクエストを記録するので、`Location`のフラグメント（`/app/#/home`）は除いて比べる。つなぐのは、ブラウザが転送する301・302・303・307・308だけ（304の`Location`ではつながない）。転送先のエントリは、URLに加えてメソッドでも探す（fetchの仕様のとおり、303はHEADならHEAD・ほかはGET、301・302はPOSTならGET・ほかは元と同じ、307・308は元と同じ。`GET /mypage`→302→`/login`の転送先に同じURLの`POST /login`をつながないため）。つなぐのは同じホスト名への転送だけで、別のホスト（IdP、apexからwwwなど）への転送先はつながない（つなぐと、対象外のホストの応答を、選んだホストのURLの結果として判定してしまう）。httpからhttpsに転送されたチェーンは、最後のhttpsのURLをターゲットのURLにする（HTTPSの応答が対象のH-01やCookieの項目を判定するため）。httpのホップは応答に残し、そこで発行したCookieも判定する。各応答にはそのホップのURLを持たせ、apexの「自身の応答」や、E-05・E-11・A-01の「そのURLの応答」には、最初のhttpsのホップを使う（`parser/target.ts`の`ownChain`。H-01・H-02のapexの見方は第1章の表のとおり）。`http`ラベルを付けたチェーンだけは、T-04のために転送元のhttpのURLのままにする。
- **応答のないエントリ**：`response.status`が0のエントリ（ブロック・キャンセルされた通信）は取り込まず、件数を解析警告（har-excluded）に出す。
- **304**：ブラウザがキャッシュを再検証した304の応答は、サーバがセキュリティヘッダを付け直さなくてよい（RFC 9110 15.4.5）ので、既定で除外し、件数を解析警告に出す（通常の応答として判定するとH-01①（高）などの誤検知になる）。開発者ツールで「キャッシュを無効にする」を選んで記録し直すよう案内する。一覧でラベルを選べば判定する。
- **対象ホストの選択**：解析の前に対象ホストを選ばせ、それ以外（解析タグ、CDN、外部APIなど）のエントリは既定で除外する。
- **ラベルの付与**：HARにはラベルがないため、取り込んだ後にエントリ一覧で付ける。一覧はリダイレクトを組み直した後のチェーン単位で表示し、ラベルはチェーン（1つのターゲット）に付ける。ツールは候補を示し、診断者が確定する。候補の例：パスワード入力欄のあるページのGET→`pre-login`、新しいセッションCookieを発行したPOSTか、パスが`login`・`signin`のPOST→`login`（セッションIDを再発行しない（C-09①の）ログインは新しいCookieを発行しないので、パスでも見る）、パスにlogoutを含む→`logout`、ほかは最初の応答が4xx・5xxなら`error-N`、それ以外は`har-N`（Nはチェーンの番号）。`sensitive`は送信側のCookie・Authorizationの有無で自動で決め、一覧で上書きできる。次の制約を設ける。
  - 予約ラベルは1つのエントリにだけ付けられる（横断ルールが比べる対象を一意にするため）。
  - `cors-*`ラベルは付けられない（ブラウザが送る正規のOriginを、R-01が「反射」と誤判定するため）。ほかにも、細工したリクエストを前提とするラベル（websocket、options、trace、method-override、open-redirect、host-inj、crlf、xff-spoof、probes、tls）は付けられない。テスト値を送っていないのに、ルールが「確認して問題なし」（.ok）を返してしまうため。HARで付けられるのは、一般、error-\*、http、apex、pre-login、login、logout、csp-sample-\* だけで、この許可リストはlabels.jsonに「HARで使えるか」の属性として持たせる。`sentOrigin`には、最後のホップのリクエストで送ったOriginを入れる（curlの`-v`と同じ。`cors-*`ラベルを付けられないのでR-01〜R-03の反射の判定には使われず、R-06などが「Originを送ったか」を見るのに使う）。
  - `after-logout`（旧Cookieでのアクセス）と`session-sample-*`はブラウザの通常の操作では生じないため、curl（C18）で採取する。
- **HARでは判定できない項目**：TLS（T-09〜T-11）、既知ファイル（E-03）、偽装OriginによるCORS確認（R-01〜R-03）、メソッド確認（T-01）、ヘッダインジェクション（T-07、T-08）など、細工したリクエストが必要な項目はHARには含まれない。これらは診断カバレッジで「入力不足」として示し、推奨コマンドで別に採取するよう案内する。
- **秘密情報の扱い**：HARには、ログイン時のパスワード（`request.postData`）、すべてのCookie、トークン、応答本文が入る。読み込みはWeb Worker内で行い、`request.postData`と不要な本文は読み込んだ直後に破棄し、残す値にもマスキングを適用する。JSONとして読めないときも、エラーの文言（誤りの前後の入力を含む）は画面に出さず、種類だけを示す。HARファイルは使用後に削除するよう画面で案内する（第0章 0.5と同じ扱い）。テスト用アカウントで採取する。
- **ブラウザによる違い**：ブラウザによっては、既定の書き出しでCookieやSet-Cookieなどの機密情報を除く（要確認事項）。CookieやSet-CookieがないHARでは、第2章の項目を「入力不足」とし、機密情報を含める書き出し方を画面で案内する。
- **サイズ**：HARは数十MBになることがあるため上限を50MBとし、必要な項目を取り出したら元のJSONは破棄する。
- **壊れたエントリ**：応答の`headers`が配列でない、`content.text`が文字列でないエントリは、そのヘッダ・本文を空として読み、取り込み全体を止めない。

## ツール設計2：ルールエンジン・集計・例外登録

ルールはチェックリストの項目IDと条件番号をそのまま使い、結果は重要度別の件数で示します。意図した設定は例外登録で抑制できます。

### ルールIDと定義の形

- **IDの形**：`<項目ID>.<条件番号>`で統一する（例：H-01の①は`H-01.1`、②は`H-01.2`）。合格は`H-01.ok`、判定不能は`H-01.na`。ルールは、評価したら必ず.okかfailを返し、判定できなければ.naを返す。空の配列は「このターゲットには適用外」（例：httpのターゲットに対するH-01）の意味にだけ使う。診断カバレッジは、この返り値で「判定済み」かどうかを決める。
- **本文を採取していない応答**：本文を見て判定する項目は、本文を採取していない（`-v`・`-D - -o /dev/null`、HARの本文なし）ときは、「反映されない」「参照なし」と合格にせず.na（理由「本文を採取していない」）を返す（合格にすると見逃しになり、カバレッジも水増しになる）。対象は、E-02・E-07〜E-10・E-12（2xxのHTML応答）、H-03（ヘッダのCSPがないHTML応答）、E-04（`robots.txt`・`security.txt`の2xx）、E-05①（`/actuator`・`/actuator/health`・`/actuator/info`の2xx）、E-06・E-13、T-01①（TRACEの200）、T-07②（2xx）、A-01①（2xx）、C-12①（`after-logout`の2xx）、C-09①（2xxの`login`）。HTMLでない応答や3xx・4xxの本文のない応答は適用外の空配列のまま。E-01・A-07は本文がなければ適用外（空配列）だが、本文を見るべき応答で採取していないもの（E-01はエラーの応答（4xx・5xx）と`error-*`のラベル、A-07はAPIの2xx）はna。本文のない応答（204・304、`Content-Length: 0`）は、採取していても本文がないので適用外のまま。HARで残す本文の形式は、ツール設計1「HAR形式の取り込み」のとおり。
- **ルールの書き方**：ルールはすべてTypeScriptの関数で書き、`rules/ruleset.ts`に登録する（条件の分岐が多いので、宣言的なJSONにせず、型と単体テストで守れる関数にする）。
- **適用範囲**：各ルールに`appliesTo`（`html`・`api`・`any`）を持たせる。API応答では、第0章 0.3のHTML向けの項目（H-03〜H-07、H-09、H-10、H-11、H-14。`engine/run.ts`の`HTML_ONLY_ITEMS`）の指摘の重要度を「情報」に下げる。
- **根拠の版管理**：各ルールに`basis`（根拠文書）を持たせる。ルールセット全体の版（`RULESET_VERSION`、例：`2026.11-v1.0.0`）を画面とエクスポートに出す（上げ方は「MVPとロードマップ」の版の付け方）。

### 集計

- **主な指標**：ターゲットごとと全体の、重要度別のfail件数（高・中・低・情報）。点数は作らない（判断の根拠8）。全体の件数は「項目×条件」（ルールID）で一意に数え、同じ指摘が複数ターゲットで出ても1件として、該当ターゲットを一覧で示す。ターゲットごとの件数は別に表示する。suppressedは件数に含めず、別に件数を表示する。

### CSPパーサとSet-Cookieパーサ

- **CSP**：Google `csp_evaluator`（npm、Apache-2.0、TypeScript）の`CspParser`と`CspEvaluator`を組み込む。自作するのは、複数CSPとReport-Onlyの区別、frame-ancestorsとXFOの総合評価（H-06）、非推奨ディレクティブの検出（H-07）だけ。
  - **振り分け**：csp_evaluatorの指摘を、チェックリストの条件に振り分ける（`rules/csp.ts`）。`SCRIPT_UNSAFE_INLINE`→H-04①、script系の`PLAIN_URL_SCHEMES`・`PLAIN_WILDCARD`・`SRC_HTTP`とscript-srcの`MISSING_DIRECTIVES`→H-04②、`SCRIPT_UNSAFE_EVAL`→H-04③、`SCRIPT_ALLOWLIST_BYPASS`（JSONP・AngularJSを置くホスト）→H-04④、`NONCE_LENGTH`・`IP_SOURCE`→H-04⑥、object-srcの問題と`OBJECT_ALLOWLIST_BYPASS`→H-05①（default-srcの指摘は、フォールバック先に振り分ける。script-srcがなければH-04、object-srcがなければH-05①。両方なければ両方）、csp_evaluatorが例外を出す値（`img-src data:image/svg+xml`など）→H-07④（そのポリシーがあればH-04は合格にせずna）、`DEPRECATED_DIRECTIVE`→H-07①、構文の検査（`MISSING_SEMICOLON`・`UNKNOWN_DIRECTIVE`・`INVALID_KEYWORD`・`NONCE_CHARSET`）→H-07④（csp_evaluatorが知らない仕様のディレクティブ（`fenced-frame-src`。`src/rules/csp.ts`の`NEW_DIRECTIVES`）は未知のディレクティブにしない）。
  - **使わない指摘**：「〜かもしれない」（`HIGH_MAYBE`・`MEDIUM_MAYBE`。`'self'`や未知のホストへの注意など）、Strict CSPの推奨、後方互換・Trusted Typesの指摘は、誤検知が多いため使わない。ただし`'unsafe-eval'`はcsp_evaluatorでは`MEDIUM_MAYBE`だが、H-04③（中）として扱う。
  - **自前で残す判定**：H-05②（base-uriがない。csp_evaluatorはnonceやhashを使う場合だけ指摘するが、チェックリストでは常に確認する）、H-07②③、H-06、H-03、H-04⑤（横断ルール）。
  - **ポリシーの区切り**：1つのヘッダ値の中のカンマはポリシーの区切り（CSP3の serialized-policy-list。プロキシが2つのヘッダを`a, b`にまとめた場合も同じ）。ヘッダ値をカンマで分けてから、ポリシーごとに評価する（`rules/util.ts`の`cspPolicies`。H-03〜H-07とH-04⑤で同じ）。分けないと、`…; base-uri 'none', frame-ancestors 'none'`の`frame-ancestors`を`base-uri`の値として読み、H-06①とH-07④を誤検知する。
- **Set-Cookie**：最初の`;`より前を`name=value`、残りを属性（名前は大文字小文字を区別しない）とする。値の長さ・文字種・推定エントロピーの上限を出し（C-07）、プレフィックスの条件を検証する（C-06）。

### ターゲット横断ルールと評価の順序

- **対象のサイトの応答だけを見る**：C-07②・C-09①のセッションCookieは、`-L`でたどった応答のうち対象のサイトのもの（C-01〜C-06と同じ）だけから取る。外部のIdPが発行したCookieを、アプリが再発行したものとみなさない。
- **C-09①の判定できない形**：`pre-login`で発行した（または送っただけの）主のセッションID（名前に`sess`・`sid`を含むもの）を`login`で再発行せず、ほかのCookieだけを発行したときのna（第2章の表）は、認証を新しいCookieで持つのか、ログイン前のIDのセッションに結び付けるのかが応答から分からないため。ログイン前のIDだけで認証後のページを取得できないかを手動で確かめるよう案内する。
- **C-07②の署名付きトークン**：`session-sample-*`の値がすべて同じJWT（またはFlaskの`.ペイロード.時刻.署名`の形、Djangoの署名が20文字以上の`ペイロード:時刻:署名`の形）で、採取の時刻（`#META at`）が分からないか60秒以内のときはna（同じ秒に同じ内容で署名すると同じ値になる。`#META at`は手元の時刻で、トークンの時刻はサーバのものなので、同じ秒かどうかでは比べない）。60秒より離れていれば②。`guest:1:admin`のような固定の値も②。
- **本文・API・転送の補足**：
  - HTMLのタグは、コメント（`<!-- … -->`）の中のものを読まない。ブラウザと同じく、`--!>`でも閉じ、`<!-->`・`<!--->`は空のコメントとする。閉じていない`<!--`は、コメントとして読み飛ばさない（読み飛ばすと、後ろのタグをすべて見逃す。`<head>`の終わりを探すときは、本文の終わりまでコメントとする）。`<script>`・`<style>`・`<textarea>`・`<title>`・`<xmp>`・`<iframe>`・`<noembed>`・`<noframes>`・`<noscript>`の中身と、ほかのタグの属性の値の中（`<div title="<!--">`）の`<!--`は、コメントの始まりではない。タグの終わりは、ブラウザの字句解析と同じく、引用符で囲んだ値の外の`>`（引用符が値を囲むのは、属性名と`=`のあとだけ。引用符のない値の中の`=`・引用符は普通の文字）。同じ名前の属性が2つあれば、ブラウザと同じく最初の値を使う。タグの名前のあとは空白・`/`・`>`だけを認める（`<form-field>`・`<img-slider>`のようなカスタム要素を`form`・`img`として読まない）。`<textarea>`・`<title>`・`<style>`・`<xmp>`・`<iframe>`・`<noembed>`・`<noframes>`の中のタグは要素にならないので、E-07・E-08・E-10・E-12とE-09の隠しフィールドでは数えない。`<script>`・`<template>`・`<noscript>`の中のタグは、書き出し（`document.write`）・複製・JavaScriptを切った表示で要素になるので数える（CSPのmeta（H-03）とH-09のmetaは、どちらの中のものも使わない）。E-09②の開発コメントも、同じ読み方でコメントを切り出す。
  - E-09の開発用コメントの証跡には、一致した語だけを出す（`pass Summer2024`は「pass」）。
  - E-08：空の`integrity=""`はintegrityなし。E-05：Spring Bootのヘルスのグループ（`/actuator/health/liveness`・`readiness`）で状態だけの応答は、既定の応答。
  - E-13：XSSI対策の前置き（`)]}'`の行）のあるソースマップも、取得できたものとする。
  - A-01①：エラーだけのJSONには、状態の番号だけのもの（`{"status":401,"message":"…"}`・`{"status":"fail"}`）も含める。
  - A-07①：キーの最後の部分を語に分け、`password`・`passwd`・`passphrase`を含むもの（`password_digest`・`hashedPassword`）と、`secret`・`api_key`・`secret_key`・`secret_access_key`などで終わるもの（`stripeSecretKey`）。最後の語が状態・設定のもの（`password_policy`・`password_updated_at`）と、`has`・`is`で始まるものは除く。
  - A-09②③：本文のない応答（204・304、Locationのある3xx、`Content-Length: 0`）はna（H-08と同じ）。
  - T-06：テスト値（`evil.example`。エンコードしたものを含む）を持ったまま、同じ入口（パスの最後の部分が同じ）へ転送したもの（ホスト名をそろえる転送、`/en/redirect`への書き換え）は、試した転送とせずna。T-07②：スキームのない`//evil.example`の反映も含める。
- **T-09・T-10の合意したバージョン・暗号**：`-v`の`SSL connection using`は、curlの`Issue another request to this URL`でたどったホストごとに分け、ターゲットのホストへの接続のものだけを使う（`-L`で移った外部のSSOのTLSを、対象のホストのものにしない。プロキシの`Connected to`ではホストを変えない）。
- **プロキシの407**：407はプロキシだけが返すので、あとに応答が続かなくても、サイトの応答として判定しない。
- **ラベル依存ルール**：特定のラベルが付いたターゲット1つを見るルール。H-15とC-12②は`logout`、T-04は`http`（apexのhttpも`label=http`で採取する）。
- **横断ルール**：複数ターゲットを比べるルール。C-07②は`session-sample-*`のセッションIDの共通接頭辞・連番性、C-09①は`pre-login`で発行されたIDと`login`のSet-Cookie、C-12①は`logout`と`after-logout`（`mypage`があれば、ログインできていたかも見る）、H-02③は一般ターゲット（www）のpreloadと`apex`のHSTS、H-04⑤のcsp-sample-\*同士のCSPのnonce、A-10は`error-*`のAPIのエラー応答どうし（2つ以上）の形式。ラベルが足りなければnaとし、画面で不足しているラベルを示す。
- **ルール間で共有する値**：C-01②③のホストのHSTSとE-12のホストのSameSiteは、ルールの実行前に全ターゲットの応答からホストごとに求める（`engine/run.ts`の`hostHstsMap`・`hostSameSiteMap`）。H-07③はE-07と同じ関数で混在コンテンツを見る。
- **評価の順序**：①ラベルと適用項目の対応表で項目を絞り込み→②ターゲット単位のルール→③ホスト単位のルール（ホストごとに集約）→④横断ルール。⑤条件単位の絞り込みと⑥API応答での引き下げは②の結果にだけ適用する（③④はターゲットを入力にし、ルールどうしは結果を参照しないので、⑤⑥の影響を受けない）。その後、⑦組織プロファイルで対象外にした項目の除外→⑧二重減点の除去→⑨組織プロファイルによる重要度の上書き→⑩例外の適用。除外を二重減点の除去より先に行うのは、除外した項目の代わりに数えている指摘を「数えない」扱いにしないため。実装は`engine/run.ts`（ツール設計4）。
- **ルールの例外**：ルールが例外を投げたら（診断対象の応答に細工したJWTのヘッダ（`alg`がオブジェクト）がある場合など）、判定全体を止めずに、そのルールだけをna（「ルールの実行中にエラーが発生した」）にする。止めると、ほかのすべての結果が消える。
- **二重減点の除去（DEDUPE）**：同じターゲットで、keep が fail のときは drop を数えない（`status`を`na`にし、`dedupedBy`にkeepを残す。診断カバレッジでは判定済みとして扱う）。keep もほかの組で数えないときは、数える指摘までたどって`dedupedBy`にする（C-10① → C-01① → C-06②）。

| keep | drop | 理由 |
| --- | --- | --- |
| A-09② | H-08① | API応答の nosniff なしは A-09② で数える |
| A-09③ | H-03①②③ | API応答の CSP なし（Report-Only だけ、効く指定がないものを含む）は A-09③ で数える |
| A-09① | H-13② | JSONをtext/htmlで返す件は A-09① で数える（第0章 0.2） |
| C-01①②③ | C-10①② | http から -L で https に転送したターゲットの、http のホップが発行した Secure のない Cookie は C-01 で数える（同じ Cookie のときだけ） |
| C-06② | C-01①②③ | Secure のない `__Host-`・`__Secure-` の Cookie は、どの主要なブラウザも拒否して保存しない（平文で送られない）ので、拒否される理由の C-06② で数える（同じ Cookie のときだけ） |
| C-01①②③ | C-03④ | Secure のない SameSite=None の Cookie は C-01 で数える（拒否するのは Chromium だけで、Safari・Firefox は保存して送る。同じ Cookie のときだけ） |
| C-10①② | C-03④ | http のターゲット（C-01 は判定しない）では、HTTP で発行した Secure のない SameSite=None の Cookie を C-10 で数える（同じ Cookie のときだけ） |
| C-06② | C-04①③ | Domain を付けた `__Host-` の Cookie（`__Secure-` は Domain を付けてよいので除く）は、どのブラウザも拒否して保存しない（サブドメインに送られない）ので C-06② で数える（同じ Cookie のときだけ） |
| R-01①・R-02①・R-03① | R-05① | プリフライトの応答（`cors-preflight`）で、許可外の Origin を資格情報付きで反射し、状態を変えるメソッドも許可したものは、重要度の高い R-01①〜R-03① で数える |
| R-05① | R-01②・R-02②・R-03②・R-04①②③ | プリフライトの応答（`cors-preflight`）の許可外の Origin の反射・`*`・`null` は、状態を変えるメソッドの許可（R-05①）で数える |
| R-01〜R-04 の指摘 | R-05① | 普通の応答（プリフライトでない）の Access-Control-Allow-Methods はブラウザが使わないので、許可外の Origin の許可は R-01〜R-04 で数える |

- **機密応答の判定**：第0章 0.3で決めた値を`RuleContext.sensitive`に入れる（分からないときの扱いも0.3）。

### 例外登録（抑制）

- 「意図した設定」を例外として登録できるようにする。登録項目は、ルールID、対象（ラベルまたはURLパターン）、理由、承認者、期限。
- 例外に該当した結果はステータスをsuppressedにし、重要度別の件数から除外する。エクスポートには理由付きで残す。
- 期限を過ぎた例外は自動で無効になり、結果がfailに戻る。
- 例外は`suppressions.json`としてインポート・エクスポートする。読み込むのは1000件まで（例外の数×指摘の数だけ照合するため）。`until`は実在する日付の`YYYY-MM-DD`の文字列で、期限なしは書かないか空にする（`null`も期限なし。`false`・`0`・`2026-13-45`はエラー）。`ruleId`は、チェックリストにある項目・条件のもの（組織プロファイルと同じ。`H-99`・`Z-99`と、項目にない条件番号（`H-01.9`・`H-01.0`）はエラー。綴りを誤った例外が黙って効かないことを防ぐ）。1件も読めなかったファイル（形式の違うもの）を読み込んだときは、登録済みの例外を残す（画面で登録しただけで書き出していない例外を消さない）。localStorageなどブラウザには保存しない（ツール設計3「ブラウザの保存領域」）。
- URLのパターン（`*`は任意の文字列）は、正規表現に変換せずに照合する（`*`の多いパターンでバックトラックが爆発し、画面が固まるため）。パターンは500文字までとする。
- 例外の対象が今の形式の突き合わせのキー（URLの部分が`urlKey`の出力そのもの。画面で登録した例外はこの形）か、今回の結果のどれかのキーと同じ文字列なら、キーの完全一致だけで照合する（画面で1つのターゲットに登録した`HAR GET https://a.example/*`の`*`は伏せたパスの部分で、ワイルドカードではない。今回のキーにあるかではなくキーの形で見分けるので、そのページを含まない回の入力でも同じ。以前の版のキーで今の形式と同じ形のものも完全一致だけになり、合わなければfailに戻る）。ただし、同じラベルが1つに減ってキーがラベルだけになった指摘には、「ラベル URL」の例外も当てる（キーに「 #2」が付いた同じラベル・URLの2つ目には当てない）。それ以外の`*`を含む対象（形式の違う以前の版のキー、手で書いた`HAR GET *`・`HAR GET https://a.example/admin*`）は、URLを持つキーの全体にワイルドカードとして照合する（`*`は`/`をまたいで任意の文字列に一致する。ラベルだけのキーには当てない。`*login*`が`login`ラベルの指摘を抑止しない）。対象が`*`だけの例外は、ラベルだけのキーを含むすべての指摘に当てる。「ラベル URL」の形の対象は、生のURLから作った突き合わせのキーのURL（`keyUrl`）と比べる（マスクしたURLでは、ASP.NETの`(S(…))`のような部分の形が変わるため）。URLのパターンの例外は、画面に出す（マスクした）URLのほかに、キーのURLとも照合する。指摘5000件×例外300件でも2秒以内に終わること（`tests/regression/review19.test.ts`）。

### 診断カバレッジ

チェックリストの全項目について、今回の入力で判定できたかどうかを一覧にします。結果が合格だけでも、判定していない項目が多ければ安全とは言えないため、「何を確認していないか」を明示します。

| 区分 | 条件 | 画面に示すもの |
| --- | --- | --- |
| 判定済み | その項目のFindingが1つ以上、pass・fail・suppressedになった | failの件数と重要度 |
| 入力不足 | すべてnaだった、または適用できるターゲットがなかった | 理由と、不足しているラベル・コマンド（例：「`tls`ラベルのターゲットがない。C11・C12を実行」） |
| 手動確認 | 手動確認項目（T-02、T-03、T-13、C-14、C-15、A-04〜A-06） | 第8章の様式への記録を促す |
| 未対応 | 今のルールセットではまだ実装していない | 実装予定のフェーズ（台帳の`phase`） |
| 対象外 | 組織プロファイルの`exclude`で判定しないとした項目 | 「組織プロファイルで対象外」 |

- **集計の単位**：項目ID単位で集計する（条件ごとの状態は持たない）。一部の条件だけが手動の項目（T-07①③、C-04②、H-11③）は、自動の条件で集計し、手動の条件は第8章の様式に記録する。
- **範囲外の項目**：カバレッジ表の下に、第7章の範囲を1文で示し、ZAP・Burp・コードレビューを案内する。
- **一部の条件が入力不足の項目**：ほかのラベルと比べる条件・ホスト単位の条件（C-09①、C-12①、C-07②、H-04⑤、H-02③、T-09①など）が入力不足でnaでも、同じ項目のほかの条件を判定していれば「判定済み」とする。ただし、指摘の有無にかかわらず理由の欄に「一部の条件（ほかのラベルと比べる条件、ホスト単位の条件）は入力不足」と、その理由を出す（`login`だけでC-09が「判定済み・0件」と出ると、①（高）を確かめたように見えるため）。機密でない応答だけで判定した項目（H-12）は、理由の欄に「機密応答では判定していない」と出す。
- **一部のターゲットが入力不足の項目**：ターゲットごとに判定する項目で、一部のターゲットがna（本文を採取していないページのE-07、`sensitive`のないページのH-12など）でも、ほかのターゲットで判定していれば「判定済み」とし、理由の欄に「一部のターゲット（n件）は入力不足」とnaの理由を出す（本文を採取したHTMLが1つあっても、本文のない機密のページを調べていないことが見えるように）。区分とカバレッジ率は変えない。ほかの項目に任せたna（「強制モードのCSPがない（H-03で判定）」など）と、二重計上の防止のnaは数えない。
- **カバレッジ率**：判定済みの項目数を、実装済みの自動判定項目の数（全項目から手動確認と未対応を除いた数）で割った値。全体で示し（ホストごとの率は今後の検討）、未対応の項目数は別に示す。率が高くても安全の保証ではないことを併記する。
- **入力不足の理由**：ラベルの不足、HTTPSかどうか不明（URLなし）、機密応答かどうか不明（`sensitive`なし）、HARに機密情報が含まれない、ok=errのプローブ、を区別して示す。理由はnaのFindingに持たせる（例：C-09.naの「必要なラベル: pre-login, login」）。
- **項目の台帳**：全項目の一覧（項目ID、項目名（日本語・英語）、章、手動かどうか、条件の数（第1〜6章の表の重要度の列の①②…の数。組織プロファイル・例外の条件番号の検証に使い、表と一致することをテストで確かめる）、実装フェーズ）を`engine/items.json`で、ルールセットと同じ版で管理する。必要なラベルは台帳に持たず、`labels.json`から実行時に作る（`engine/labels.ts`の`requiredLabels`）。実装済みの項目の集合は、ルールセットに登録したルールの項目IDから作る。
- **エクスポート**：MarkdownとJSONにカバレッジ表を含める。

### 組織プロファイル

組織ごとの基準を`profile.json`で読み込みます。ブラウザには保存しません。形は画面の「プロファイルのひな形」（`src/engine/profile.ts`の`profileTemplate`。READMEの例と同じ）で、各項目は次のとおりです。

- **APIの応答の情報の指摘**：APIの応答でHTML向けの項目の指摘を情報に下げたもの（第0章 0.3）は、プロファイルの重要度で上げない（ひな形の`"H-10": "low"`でAPIの情報の指摘を低に上げないため）。
- **severity**：項目ID（`H-10`）か条件（`H-14.1`）ごとの重要度（チェックリストにない項目（`H-99`）と、項目にない条件番号（`H-01.9`）・先頭が0の条件番号（`H-01.01`。`H-01.1`と照合されず効かない）はエラー。`exclude`も同じ）。条件の指定が項目の指定より優先する。変えた重要度には「*」を付け、元の重要度（`originalSeverity`）を残す。画面では、元の重要度を「低*（元：高）」のように文字で示し（マウスの説明（title）だけではキーボード・読み上げで分からない。「*」は読み上げない）、ターゲットごとの表とホスト単位・ターゲット横断の表（結果表には出さない）に「*」が出るときに凡例を出す（Markdownは表の下に凡例を出す）。
- **exclude**：判定しない項目。結果から除き、診断カバレッジでは「対象外」とする。
- **sessionCookieNames**：セッションCookieとして扱う名前。指定すると、名前と期限による推定より優先する。
- **sessionMaxAgeHours**：C-05で指摘する期限の基準（既定24時間）。数値だけを受け付ける（`true`・`"12"`はエラーにして既定値を使う）。1以上9600以下（`0.5`はエラー）。
- **trustedScriptOrigins**：自社の配信元（`https://cdn.example.com`、`cdn.example.com`、`*.example.com`、ポート付きの`cdn.example.com:8443`の形）。ポートを書かない登録はそのホストのどのポートにも、書いた登録はそのポートだけに当てはまる（URLにポートがなければスキームの既定のポート（httpsは443、httpは80）として比べるので、`cdn.example.com:443`の登録は`https://cdn.example.com/`に当たる）。ここからのscriptはE-08（第三者スクリプトのSRI）の対象外にする。
- 不正な値は読み込み時に指摘し、正しい部分だけを使う。配列にする項目を文字列などで書いたもの、`severity`をオブジェクト以外で書いたもの、知らない項目（綴りの誤りの`excludes`など）も指摘する（黙って既定値で判定しない）。エクスポートしたJSONにはプロファイルを含める。

### 前回との差分

以前にエクスポートしたJSONを読み込み、今回の結果と比べます。

- **突き合わせ**：指摘（failとsuppressed）を「ルールID×ターゲット×証跡のホスト名の一覧」のキーで突き合わせる。
  - **証跡のホスト名**：同じルール・ターゲットで別の配信元・読み込み先の指摘（E-08の配信元、E-07のタグ）は別に突き合わせ、直ったものを「解消」、増えたものを「新規」にする。証跡のほかの部分は画面のマスクで形が変わるので使わない（キーはマスクに依存しない）。同じホストの別のものは区別しない。ホスト名はサイトにまとめない（`ajax.googleapis.com`に`storage.googleapis.com`のスクリプトが増えたことや、`*.github.io`・`*.cloudfront.net`の別の持ち主の配信元を1つの「継続」にしないため）。そのため、A-01②の転送先が同じサイトの別のサーバ（`web-03`→`web-07`）に変わっただけでも「解消」と「新規」に分かれる（見逃すより安全なので、そのままにする）。
  - **ターゲット**：curlはラベル、HARは「HAR メソッド URL」（`targetKey`）で識別する（HARのラベルの番号は記録し直すと変わるため）。キーが重なるもの（curlの同じラベルで同じURL、HARでURLは違うがキーが同じもの）は、2つ目から` #2`を付ける。HARでURLまで同じもの（ポーリング）は、新しい番号を付けず、そのURLに前に付けたキー（` #2`を含む）を使う。`targetKey`のない以前のJSONはラベルで突き合わせる。
  - **URLのキー（`urlKey`）**：残してよい形だけを残す決まった形で作る（許可リスト。秘密らしい形を数え上げて伏せる作りでは、どんな形のトークンもキーに入らないとは言えない）。持つのは、スキーム・ホスト・パスと、並べ替えたクエリのパラメータの名前。パスの部分とパラメータの名前は、`-`・`_`・`.`・`~`で区切ったかけらのうち、英字の語（24文字まで。大文字・小文字のかたまりは4つまで、大文字だけは10文字まで。5文字以上のものは、画面の許可リストと同じく英字の語として読めるもの（`src/tokenShape.ts`の`wordLike`）だけ）、日本語などのASCII以外の文字の語（`お知らせ`・`採用情報`。24文字まで。大文字・小文字のかたまりは4つまで。長音`ー`も語の一部）、6桁までの数字、`v2`・`x64`のような短い語と数字だけを残し、それ以外は`*`にする（`AdminDashboard-*.js`）。英小文字だけの16文字以上の乱数（母音（`y`を含む）が4分の1未満か、英語でよく現れる2文字の並びにないものが35%以上。`src/tokenShape.ts`の`lowerToken`）も`*`にする。かけらを1つずつ見ると残る区切った番号・コード（カード番号・米国の社会保障番号の形、`QWER-TYUI-ZXCV-ASDF`・`K7QX-9MZP`のような同じ長さのかけらや`7Gk-p2Q-xZ81-m`のような長さのそろわない乱数のかけらの招待のコード）は、拡張子が付いても部分ごと`*`にする（画面の許可リストと同じ形。`digitRun`・`codeGroups`）。`.`・`~`で区切ったチャンクがトークンの形のもの（画面のマスクと同じ`secretPiece`と、数字のないbase64url。base64urlのトークン、UUID、JWTの各部分。かけらを1つずつ見ると、短い語と数字や区切りが残り、記録し直すたびにキーが変わる）は、英語の語（3文字以上の英小文字か先頭だけ大文字）と`v2`だけを残し、ほかのかけらと区切りは`*`にまとめる（`avatar_*.png`・`Product-Guide-*`。静的ファイルのビルドした名前は除く。番号・コードの検査はこれより先に行う）。10〜11桁の電話番号（`090-1234-5678`・`0312-34-5678`・`0120-123-456`・`555-123-4567`。国番号・`tel:`・括弧の付いた`+81-3-1234-5678`・`tel:090-…`・`(090)-…`も。`phoneRun`）もキーでは`*`にする（画面は電話番号を残す）。電話番号とコードは`.`で区切ったもの（`090.1234.5678`・`AB12.CD34.EF56`）も見る。パス引数（`;jsessionid=…`）とクエリの値は持たない（ページ送りの名前（`page`・`offset`など）の4桁までの数字と、並べ替え・表示の切り替えの名前（`sort`・`lang`など）の英字の語だけは残す。同じ名前が2回以上あれば、値がすべて同じときだけ残す）。ASP.NETのセッション`(S(…))`は`(*)`。相対のURLは先頭の`//`を1つにし、スキームのない`//ホスト/…`はホストを残す（もう一度かけても変わらないように）。トークンはキーに入れない（別のページが同じキーになることはある。英語の語をつないだ名前に見えるトークン（乱数のおよそ1万個に1個）と、トークンの中の英語の語に見えるかけら（base64urlの乱数の約0.4%）は残りうる）。
  - **マスクとの分離と性質**：キーは画面・エクスポートのマスク（`src/mask.ts`・`src/shownText.ts`）とは別のファイル（`src/engine/targetKey.ts`）で作り、マスクを読み込まない（マスクの一覧を変えても、以前の例外と前回の結果が黙って突き合わなくならないように）。ただし語・番号・コード・パスのトークンの形の判定（`src/tokenShape.ts`）は画面のマスク（`secretPiece`）と許可リストと共有するので、`tokenShape.ts`を変えるとキーの形も変わる（変わったキーの多くは、読み込むと以前の形式として知らせる。すでに`*`を含む部分がさらに伏せられた形（UUIDの`*-4821-*`、`sk_live_*`）は見分けられない）。キーが守ること（もう一度かけても変わらない、値を変えても変わらない、パスのトークンを含まない、パラメータ・ターゲットの順番で変わらない）は、性質のテスト（`tests/properties.test.ts`）で確かめる。
  - **以前の形式のキー**：読み込んだ例外ファイル・前回の結果のキーは、URLの部分にもう一度`urlKey`をかけて変わるものを以前の形式とみなし、突き合わない件数を知らせる（読み込むとルールセットの版の違いも知らせる）。例外の照合にも同じキーを使う（例外の照合は「例外登録（抑制）」と同じ）。
- **区分**：新規、解消、重要度の変化、例外登録、継続、再診断していない。同じ項目・ターゲットに今回のna（入力不足の条件）があれば、その項目は判定済みとせず、前回の指摘を「再診断していない」にする。前回のキーが「ラベル＋URL」なら、ラベルだけでは突き合わせず、今回の「ラベル＋URL」で比べる（同じラベルのターゲットが減ったとき、確かめていないターゲットの指摘を「解消」としないため）。機密でない応答だけで判定した合格（H-12の`limited`）は、機密応答の条件を確かめていないので判定済みに数えない。同じ項目・ターゲットに、前回の指摘より前の番号の条件の今回のfailがあれば、前回の指摘を「解消」にせず「再診断していない」にする（途中で返すルール（H-01は②で返して④を見ない）は、後の条件を確かめていないことがある。同じ条件の別の配信元（`cdn-a`→`cdn-b`）は「解消」のまま）。「再診断していない」は、前回の指摘のうち今回の入力で同じターゲット・項目を判定していないもの（採取していないのに「解消」と表示しないため）。「例外登録」は、今回 suppressed になった指摘（前回も suppressed なら変化なしとして出さない）。例外は直したことにならないので「解消」には数えない。前回 suppressed で今回 fail（例外の期限切れなど）は、既知の指摘として「継続」か「重要度の変化」にする。
- **警告**：前回と今回で、組織プロファイル（`severity`・`exclude`・`sessionCookieNames`・`sessionMaxAgeHours`・`trustedScriptOrigins`。`name`は除く）またはルールセットの版が違う場合（版の形が読めないものは「不明」として値を出さない）は、差分に設定やルールの変更が混ざるため警告する。どちらの警告も、画面とMarkdownのエクスポートの両方に出す。重要度の指定と配列の値は、順番の違いだけでは違うとみなさない（`src/engine/diff.ts`）。
- **読み込み時の検査**：前回の結果の各指摘は、`ruleId`（`H-01.1`の形）、`item`（`ruleId`と一致すること）、`severity`、`status`、`target`を確かめ、合わないものとチェックリストにない項目は除いて件数を表示する。条件番号と`ruleId`は作り直す（`H-01.01`は`H-01.1`として突き合わせる）。`title`は読まない（表示はチェックリストの項目名）。日時と版は`toJson`の形だけを受け付け、形の違う版は値を出さずに「不明」として警告する（ファイルに書かれた任意の文字列を画面に出さない）。前回の結果に含まれるプロファイルも、組織プロファイルと同じ検査を通す。手で編集したJSONや別のツールのJSONでも、表示が崩れないようにするため。
- **出力**：画面とMarkdownに差分の表を出す。

### ASVS 5.0・IPAとの対応

- **原典**：OWASP ASVSはGitHubのOWASP/ASVSリポジトリの`v5.0.0`タグの`5.0/en`（要件345件）、IPAは「安全なウェブサイトの作り方」改訂第7版（2021年3月、第4刷、IPAの公式ページのPDF）を読んで対応付けた。
- **持ち方**：対応は`src/engine/items.json`の各項目の`asvs`（要件ID）と`ipa`（項番）に持つ。ASVSの要件の文言はCC BY-SA 4.0のため取り込まず、要件IDとレベル（L1〜L3）だけを`src/engine/asvs-levels.json`に持つ（原典から機械的に作成）。第1〜6章の表の参考文献列は`items.json`と同じ内容にし、食い違いはテスト（`tests/standards.test.ts`）で検出する。
- **意味**：「関連する要件」であり、その要件を満たすかどうかの判定ではない。ツールの合格は、ASVSのその要件への適合を意味しない。
- **表記**：ASVSは、ASVSが推奨する`v<version>-<要件ID>`（例：`v5.0.0-3.4.1`）で引用する。画面とMarkdownの指摘の表では「ASVS 3.4.1」と略す（レベルは、画面ではツールチップ、Markdownでは診断カバレッジの表の「ASVS 5.0.0」の列に添える）。IPAは、第1章は「4-(iii)」「4-(iv)-a」、第2章は節番号と番号をつないで「2.3-1)」とする。
- **出す場所**：画面の項目名の横（指摘の一覧、差分、診断カバレッジ）、Markdown（指摘の項目名の横と、診断カバレッジの表の「ASVS 5.0.0」「IPA」列）、JSON（`standards`）。CSVは第8章の記録様式の列を変えないため出さない。
- **対応付けない項目**：ASVS 5.0・IPAに該当する要件がない項目（H-10、H-14、H-17、C-08、C-11、R-06〜R-08、T-12、E-04）は空にする。IPA 5-(x)は`X-XSS-Protection: 1; mode=block`とCSPの`reflected-xss`（廃止）を勧めており、H-17と向きが逆なので対応付けない（判断の根拠2）。
- **基準をASVSに合わせた点**：ASVS 5.0は、HSTSのmax-ageを1年以上（L2以上はincludeSubDomainsも）とし（3.4.1）、セッションIDに128bit以上のエントロピーを求める（7.2.3）。これに合わせ、H-01②の基準を1年、H-01④（includeSubDomainsがない、低）を置き、C-07①の基準を128bitとする。

### 英語UI

- **切り替え**：画面右上の切り替え、または`?lang=en`。ブラウザの言語が日本語以外なら英語で始める。切り替えのボタンの文言（English・日本語）は切り替え先の言語なので、ボタンに`lang`を付ける（WCAG 3.1.2）。画面を作り直したあとは、ボタンにフォーカスを戻す。コマンド生成器の入力・チェック・生成したスクリプト・開閉は、切り替えのあとも残す。
- **英語にする範囲**：画面の文言、項目名（`items.json`の`titleEn`）、ラベル名（`labels.json`の`nameEn`）、重要度・判定・区分、推奨対応、診断カバレッジの理由とコマンドの案内、Markdown。英語のMarkdownでは、全角の区切り（`：`・`、`・`（）`）を使わず、ASCIIの`: `・`, `・` (…)`にする。規格の欄は` — `のあとに、ASVSとIPAは`; `、同じ規格の番号は`, `で区切って書く（閉じ括弧で終わるIPAの項番`2.3-1)`が`))`にならないように）。
- **日本語のまま**：証跡（応答から取った値と短い説明）、CSV（第8章の記録様式）、解析警告、生成したスクリプト（コメントと終了時のメッセージ）。
- **管理**：画面の文言は`src/i18n.ts`の`ja`・`en`の両方に置く（足りないと型チェックで失敗する）。推奨対応・判定不能の理由・診断カバレッジの理由の英訳は`src/recommendationsEn.ts`、設定ファイル（例外・組織プロファイル・前回の結果）とコマンド生成器の入力のエラーの英訳は`src/messagesEn.ts`にまとめる。ルールの推奨対応を構文木から集めて英訳の漏れを検出するテスト（`tests/i18n.test.ts`）を置く。

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
| 0xelitesystem/http-header-analyzer、meduuv/security-headers-analyzer | 貼り付け型（ブラウザ内で完結） | ヘッダ解説、設定例の生成、「送信しない」設計 | どちらもMIT（2026-11-18に確認） |
| rfc-st/humble | CLI（Python）。URLを取得するほか、保存した生の応答ファイルも解析できる | 指紋になるヘッダの検出、非推奨・不正な値の検査、testssl.shとの連携 | MIT（2026-11-18に確認）。考え方の参考にとどめる |
| offseckit/headers | CLI（Python）。curl -sIの出力をパイプで受ける | CI向けのJSON出力 | MIT（2026-11-18に確認） |
| headerpulse | CLI（Python）。対象に自らアクセスする | ヘッダ・Cookie・CORSのOrigin反射を1回で確認する構成 | PyPIの版にはライセンスの記載がない。同じ説明のリポジトリ（HeaderPulse-CLI）はMIT |
| 貼り付け型のWebツール（jmrp.io、hidekazu-konishi.com、elysiatoolsなど） | ブラウザ内で完結（一部はURL取得の機能もある） | 1応答のヘッダの採点と解説。hidekazu-konishi.comは日本語 | ソースとライセンスは各サイトで確認 |

差別化のポイントは、複数ターゲット・`-v`・`-L`・openssl・プローブをまとめた1つの貼り付けを解析できること、API Top 10 2023に対応したルール、送信OriginとACAOの照合、日本語の解説とIPA・ISOG-Jへの対応付け、ログイン前後やログアウト後を比べるターゲット横断の判定、何を確認していないかを示す診断カバレッジ、ブラウザのHARの取り込みです。既存の貼り付け型ツールは、1つの応答のヘッダを採点するものがほとんどです。

### セキュリティとプライバシー

| 論点 | 方針 |
| --- | --- |
| 外部送信の禁止 | `fetch`、`XMLHttpRequest`、`WebSocket`、`sendBeacon`は使わない。分析タグやCDNもなし（すべて同梱）。メタCSPの`connect-src 'none'`で技術的にも止める |
| マスキングの対象 | 常に行う（切り替えはない）。画面・エクスポート（JSON・CSV・Markdown）に出す文字列は、次の2段で処理する。**①名前と形で伏せる**（`src/mask.ts`の`maskText`）：秘密らしい名前の値（URLのパラメータ、JSONの文字列の組、`password="…"`・`X-Auth-Token: …`のように名前を付けた値。URLのパラメータ・JSONのキーの名前は全角・ゼロ幅の文字・パーセントエンコードを戻してから照合する）と、形で分かる値（JWT、CSPのnonce、URLのユーザー情報（エンコードした形・スキームのない形を含む）、ASP.NETのCookieを使わないセッション、名前が一覧にないパラメータ・パスに置いたトークン、米国の社会保障番号とLuhnの検査に通るカード番号の形）を伏せる。生のヘッダ行（Authorization、Cookie、Set-Cookieなど）は出さず、証跡に出すSet-Cookieは値を伏せて既知の属性を残す。HTML本文のタグ（E-07〜E-10・E-12）は判定に使う属性の値だけを出し、ほかは「…」にする。**②最後に許可リストを通す**（`src/shownText.ts`の`showText`）：残してよい形の語（短い語・数字、語として読める英字（`src/tokenShape.ts`の`wordLike`）、暗号・プロトコルの名前、日時と単位、URLのホスト名、決まった最上位ドメインのドメイン名、CSP・SRIのハッシュ、伏せた印）だけを残し、それ以外は`…(N chars)`にする。名前の付いていないトークン（`ghp_…`・`AKIA…`・`xoxb-…`）は形を数え上げずにここで伏せる。かけらごとには残る区切った番号・コード（`4111-1111-1111-1111`・`K7QX-9MZP`・`K7QX.9MZP`・`7Gk-p2Q-xZ81-m`）は並びごと伏せる（10〜11桁の電話番号と、英小文字だけの`.`・`:`の並び（ホスト名・ファイル名）は残す）。スキームのない`//ホスト`は英小文字で決まった最上位ドメインのものだけを、ホスト名のあとに`@`（`%40`などのエンコードした形を含む）が続くものはユーザー名なので残さない。**性質**：①②は結果が変わらなくなるまで繰り返す（冪等）。コマンドの文字列は①の対象ではない（画面にコマンドは出さない）。証跡の抜粋はマスクしてから切り詰め、伏せた印の途中では切らず、語の途中で切ったかけらは残さない（`excerpt`）。CSVの「実施コマンド」「実施日時」は、伏せるのではなく許可リストで作る要約を出す（ツール設計4「エクスポートとテスト」の「実施コマンドの要約」）。Markdownのエクスポートでは、値の`<`・`>`を実体参照にし、記法の記号をエスケープし、裸のURL・`www.`・`@`の前にゼロ幅の空白を挟む（応答に書かれた画像の記法やURLが、レポートで外部から読み込まれたりリンクになったりしないように）。**既知の限界**：区切りのないキャメルケースの名前（`userPassword: …`）と全角・ゼロ幅の文字を含む名前を付けた値（URLのパラメータ・JSONのキーは伏せる）、名前の付いていない短い合言葉（`hunter2`）は残る。一様な乱数のトークンでも、語として読めるかけら（英小文字6〜9文字など）は残ることがある（名前の付いた値は①で伏せる）。生の空白で区切った番号・コード（`1234 5678 9012`・`K7QX 9MZP A2B4 C6D8`）と、`-`と`.`・`:`を混ぜたコードの一部も残る。**正本**：名前・形の一覧と規則の正本は`src/mask.ts`・`src/shownText.ts`・`src/tokenShape.ts`・`src/export/cmdSummary.ts`で、性質は`tests/masking.test.ts`・`tests/shown-text.test.ts`・`tests/properties.test.ts`で確かめる |
| マスキングの方法 | 値の長さで残す文字数を変える：8文字以下はすべて伏せる、9〜20文字は先頭2文字、21文字以上は先頭4文字。いずれも文字数を付記（例：`abcd…(64 chars)`）。エントロピー評価はマスク前の値でメモリ内だけで行う |
| プローブの中身 | `#PROBE`の`head`（採った先頭）は.envなどの秘密を含み得る（.envは64バイトだけ採る。4KBを採るweb.xmlの`<context-param>`のパスワードや、composer.jsonの`repositories`の認証付きのURLも、out.txtに残りうる。out.txtはCookieと同じく、読み込んだら削除する）。判定にだけ使い、画面とエクスポートには「一致したパターン名」（例：`git-head`、`dotenv`、`phpinfo`）だけを出す |
| 生データのエクスポート | 提供しない。エクスポートは常にマスク済み。生の出力は診断者の手元のファイルを社内の保管場所に置く（第8章） |
| ツール自身のCSP（meta） | `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src blob:; base-uri 'none'; form-action 'none'">`（`object-src`は`default-src 'none'`で禁止される）。あわせて`<meta name="referrer" content="no-referrer">`を入れる。これらは`<head>`の先頭（charsetより前）、どのスクリプトよりも前に置く。開発サーバには付けず、本番ビルド時だけViteプラグインで挿入する（理由は`csp.config.ts`）。CSSはTailwind CSS v4を@tailwindcss/viteでビルド時に静的ファイルとして生成し、実行時にstyle要素を注入するものは使わない |
| メタCSPの制約 | W3C CSP3では`frame-ancestors`、`report-uri`、`sandbox`、Report-Onlyはmetaで無効。GitHub Pagesは独自ヘッダを設定できない。クリックジャッキング対策はJSの`top !== self`による表示抑止で補う。厳密さが必要ならCloudflare Pagesなどヘッダを設定できるホストへ移す |
| XSS対策 | 入力由来の文字列は`textContent`か`createTextNode`で描画し、HTMLとして解釈させるAPIと`eval`系は使わない。ESLint（`no-restricted-properties`で`innerHTML`・`outerHTML`・`insertAdjacentHTML`・`document.write`・`document.writeln`・`setHTMLUnsafe`・`createContextualFragment`・`srcdoc`・`parseFromString`、`no-eval`・`no-implied-eval`・`no-new-func`）で機械的に止める。メタCSPの`require-trusted-types-for 'script'`は、今は採らない（主なブラウザの対応は確かめた。必要になれば改めて検討する） |
| Worker | HARの読み込み（`src/harWorker.ts`）と、判定（貼り付けとHARの解析、ルール、診断カバレッジ。`src/analyzeWorker.ts`が`src/engine/analyze.ts`を呼ぶ）はWeb Workerで行う（数万件のターゲットのHARでも画面を止めない。判定中は「判定しています」を表示し、判定し直したら前のWorkerを止めて古い結果を使わない）。画面の側は、ルール（`src/rules/`。`util.ts`を除く）とcsp\_evaluatorを読み込まない（版は`src/version.ts`に置く。同じコードを画面とWorkerの両方に入れない）。Viteの`?worker&inline`でblob: URLのWorkerとして作り、メタCSPに`worker-src blob:`を加える。別ファイルのWorkerには、そのファイルのHTTP応答のCSPが使われ、GitHub PagesはCSPヘッダを返さないため、生のHAR（Cookie・パスワード）を持つWorkerから通信できてしまう。blob: のWorkerはページのCSP（`connect-src 'none'`）を引き継ぐ（E2Eで確認） |
| ファイル読込・ReDoS | `File.text()`で読み込み、サイズ上限5MB（HARと前回の結果のJSONは50MB。大きなHARを判定した結果のJSONは5MBを超えるため。例外ファイルと組織プロファイルは5MB）。上限を超えた設定ファイルには、そのファイルの上限を示す。正規表現は線形時間のパターンに限る |
| ブラウザの保存領域 | localStorage・sessionStorage・IndexedDB・Cookieは使わない（何も保存しない）。共有PCに秘密情報が残るうえ、同じオリジン（`<組織名>.github.io`）の他のリポジトリのページから読めるため。例外ファイル・組織プロファイル・前回の結果は、毎回ファイルで読み込む |
| 公開先とオリジン | 専用の組織アカウントのリポジトリで管理し、`https://<組織名>.github.io/curl-sec-analyzer/`で公開する。個人アカウントの他のGitHub Pagesとはオリジンが分かれる。ただし同じ組織の他のPagesとはオリジンを共有するので、次を前提にする。①ブラウザの保存領域を使わない（上の行）。②他のページへの埋め込みを拒否する（同じ組織の他のページからの埋め込みも含む）。③同じ組織のPagesに、信頼できないコードや外部のスクリプトを読み込むページを置かない（同じオリジンのページは、このツールをウィンドウで開いて画面の内容を読めるため）。③を守れなくなったら、ツールごとに組織を分けるか、独自ドメイン（有料）を割り当てる |
| サプライチェーン | 依存は最小限。`package-lock.json`をコミットし、CIで依存の署名と既知の脆弱性を検査し、GitHub Actionsを固定する（ツール設計4「GitHub Actionsによるデプロイ」。手元では`npm run audit`）。Dependabotは`npm`と`github-actions`の両方を有効にし、公開直後のリリースを取り込まないよう待機期間（cooldown）を置く。公開リポジトリでは、CodeQLとdependency-reviewで、コード・ワークフローの脆弱性と新しく入る依存を検査する |
| ライセンス表記 | 同梱するOSS（csp\_evaluatorなど）のライセンス文を、`rollup-plugin-license`で`dist/THIRD_PARTY_LICENSES.txt`に出力し（JavaScriptのバンドルに入らないTailwind CSSは`vite.config.ts`で足す）、画面からリンクする。Viteはバンドル時にコメントを削除するため、別ファイルが必要 |
| 免責表示 | 画面の入力欄の上に、「自社管理または許可を得た対象のみ」「合格は安全性の保証ではない」「入力は外部送信されない」の3点を常時表示する |

### 非機能要件

| 項目 | 目標 |
| --- | --- |
| 対応ブラウザ | Chrome、Edge、Firefox、Safariの最新版 |
| アクセシビリティ | WCAG 2.1 AA。重要度を色だけでなく文字ラベルでも示す。キーボードだけで操作できる |
| 入力上限と性能 | 5MBまで。目安として1MBの入力を2秒以内で解析。HARは50MBまでで、必要な項目だけを取り出す。HARの目安は50MBを15秒以内とし、読み込み中は「読み込んでいます」を表示する |
| オフライン | 外部参照がないため、ページを開いたままならネットワークなしで動作する。再読込にはネットワークが必要（必要になればService Workerを検討） |
| 言語 | 日本語と英語（ツール設計2「英語UI」） |

### 画面設計

画面は「入力→HARのエントリ一覧→結果→ターゲット一覧→詳細→ホスト単位・ターゲット横断の判定→診断カバレッジ」の1ページ構成で、上から順に使います。下表は画面の上からの順です。何も入力していないときは、結果の欄に「①コマンドを作る→②自分の端末で実行する→③貼り付けて判定する」の手順を示し、コマンド生成器とサンプルへの入口を置きます。

| 領域 | 内容 | 操作 |
| --- | --- | --- |
| ヘッダ | ツール名、ツールとルールセットの版、免責表示（3点）、ライセンスへのリンク、言語の切り替え | — |
| 入力 | テキストエリア、ファイル読込（HARも可）、URL入力欄（`#TARGET`がない入力用）、設定ファイル（例外ファイル、組織プロファイル、前回の結果のJSON） | 「判定する」ボタン、入力のクリア、プロファイルのひな形の保存。判定できたら、生の出力（Cookieやトークンを含む）を入力欄から隠し、画面共有への注意を表示する（「入力を表示する」で戻す）。入力があるときにサンプルを入れる場合は確認する（読み込んだHARは外す。利用者のHARとダミーのサンプルを1つの結果にしない）。設定ファイルが1件も読めない・形式の違うものなら、読み込み済みの設定を使い続け、そのことを知らせる（前回の結果の検査はツール設計2「読み込み時の検査」）。例外を登録したり設定ファイルを読み込んだりしたら、表示中の結果の入力（入力欄・URL欄の値）で判定し直す。判定のあとに書き換えた入力欄は「判定する」を押すまで判定せず、そのことを状態のメッセージに添え、入力欄は隠さない（HARの一覧の選択は今のものを使う。組織プロファイルを読み込むとラベルの候補を作り直すため） |
| 状態の表示 | 入力の誤りや、判定のあとの件数（「N件のターゲットを判定しました。指摘（項目×条件）N件（うち重要度「高」N件）」。件数は結果表と同じく項目×条件で一意に数える）を、役割`status`の欄に出す。言語を切り替えたら、その言語で出し直す（件数だけでなく、入力がない・読み込みのエラーなどのメッセージも。メッセージは文言を作る関数で持つ）。結果欄は`aria-live`にしない（再描画のたびに数百行を読み上げるため） | — |
| HARのエントリ一覧 | 対象ホストの選択、エントリごとのURL・ステータス・ラベル候補・機密かどうか | ラベルの確定・変更、sensitiveの上書き、エントリの除外 |
| 重要度別の件数 | 重要度別のfail件数（項目×条件）。例外を当てた指摘の件数は、その下に別に出す（重要度別の件数には含めない） | — |
| エクスポート | Markdown、JSON、CSV、例外ファイル（`suppressions.json`） | ダウンロード |
| 解析の警告 | 不足している予約ラベル。解釈できなかった行数、ターゲットにならなかったブロック、URL不明のターゲット（URL入力欄の値がスキームのあるURLとして読めないものも）、ok=errのTLS・暗号プローブ（ターゲットごとに1つにまとめ、どのプローブかを書く）、1つの応答のSet-Cookieが300個を超えたもの、HARの除外件数と機密情報の欠落 | — |
| 前回との差分 | 前回の結果を読み込んだときだけ、変化ごとの件数、組織プロファイル・ルールセットの版が前回と違うことの警告、変化の一覧（新規・解消・重要度の変化・例外登録・再診断していない・継続） | — |
| 結果表 | 重要度（色＋文字）、項目IDと条件番号、短い説明、該当ターゲット（指摘だけ）。重要度順 | 章での絞り込み。重要度「情報」の指摘は既定で隠し、切り替えで表示する（件数は重要度別の件数に常に出す）。絞り込みと表示の切り替え（章・「情報」・全件の表示・診断カバレッジの区分）で描き直したあとは、操作した部品にフォーカスを戻す |
| ターゲット一覧 | ターゲットごとにラベル、URL、応答の種類（html・api・other）、機密かどうか、重要度別件数。URLが分からないターゲットは「URL不明」 | —（curlのターゲットの`kind`・`sensitive`は`#TARGET`で指定する。HARはエントリ一覧で`sensitive`を上書きできる） |
| 詳細 | 証跡（マスク済み）と推奨対応 | 「例外に登録」（理由・承認者・期限を入力。理由がないなどの誤りは役割`alert`の欄に出して読み上げ、理由の欄にフォーカスを移す。登録して判定し直したあとのフォーカスは、表の下の「フォーカス」のとおり）。ターゲットごとに折りたたみ、情報以外の指摘があるものだけを開く。指摘は、判定（指摘→例外→判定不能→合格）、重要度、項目IDの順に並べる。判定不能のうち、証跡と推奨対応が同じもの（本文を採取していないページのE-02・E-07〜E-10・E-12など）は1行にまとめ、項目の列に項目IDを並べる |
| ホスト単位・ターゲット横断の判定 | ターゲットに属さない指摘（T-09〜T-11・E-03のホスト単位の判定と、横断ルール）。「対象」の列（この表・指摘の一覧・差分の表・例外の登録のダイアログで同じ）は、今のターゲットのラベルはそのまま、ホスト単位の指摘のホスト名はURLの列と同じ出し方（URLの列で伏せるものだけを伏せる）、それ以外（前回の結果にだけある対象を含む）は許可リストを通して出す（`src/shownText.ts`の`showTarget`、`src/ui/dom.ts`の`targetText`） | 情報以外の指摘があるときだけ開く |
| 診断カバレッジ | 項目ごとの区分（判定済み・入力不足・手動確認・未対応・対象外）、カバレッジ率、入力不足の理由と不足しているラベル・コマンド。下に第7章の範囲外項目 | 区分での絞り込み、不足分のコマンドの表示（コマンド生成器と連携。生成器の入力の誤りと「コピーしました」は、生成器の中の役割`status`の欄に出して読み上げる）。既定では「入力不足」の項目だけを表示する |

- **フォーカス**：判定して結果を描き直したとき、描き直す前にフォーカスのあった部品が消えた・隠れた（例外に登録のボタン、空の画面の「サンプルで試す」、Ctrl+Enter で判定して隠した入力欄）ときだけ、結果の最初の見出しに移す（`focusResultsIfLost`）。描き直しで同じ部品にフォーカスを戻したとき（章の絞り込みなど）と、フォーカスが body にあったとき（Safari・macOS の Firefox はマウスで押したボタンにフォーカスしない）は移さない。

## ツール設計4：技術スタック・デプロイ・実装の対応

技術スタックはTypeScript＋Vite（フレームワークなし）＋Tailwind CSS v4＋Vitest＋Playwright（Node.js版）です。型付きのルール定義とVitestによるテストができ、外部CDNなしのバンドルにできるため、メタCSPと相性がよいからです。

- **UI**：フレームワークは使わず、素のTypeScriptでDOMを組み立てる1画面のSPAとする。描画の決まりはツール設計3のセキュリティの表。ルーティングは使わない。
- **CSS**：Tailwind CSS v4を`@tailwindcss/vite`で使い、ビルド時に静的CSSファイルを生成する（`src/styles.css`に`@import "tailwindcss";`）。SCSSは採用しない。ネストやカスタムプロパティなどSCSSの主要機能の多くは標準CSSで使え、CSSの方が転用性・汎用性・保守性が高いため。
- **テスト**：ユニットテストはVitest、E2EテストはPlaywrightのNode.js版（`@playwright/test`）。
- **CSPとの関係**：メタCSPは本番ビルド時だけ挿入する（Viteプラグインの`transformIndexHtml`。理由は`csp.config.ts`）。実行時に`<style>`を注入するTailwindのブラウザ版（`@tailwindcss/browser`）やCSS-in-JSは、`style-src 'self'`に抵触するため使わない。

### 構成

```
curl-sec-analyzer/
├─ index.html                 # UIの骨格（メタCSPは本番ビルドで挿入）
├─ run.sh                     # 簡易版の採取スクリプト（正式にはコマンド生成器を使う）
├─ src/
│  ├─ main.ts i18n.ts messagesEn.ts recommendationsEn.ts commands.ts mask.ts shownText.ts tokenShape.ts model.ts version.ts
│  │  harWorker.ts（HARの読み込み）analyzeWorker.ts（判定） sample.txt styles.css
│  ├─ ui/      state.ts dom.ts results.ts har.ts generator.ts dialog.ts
│  ├─ parser/  input.ts har.ts target.ts openssl.ts setCookie.ts
│  ├─ rules/   ruleset.ts util.ts jwt.ts headers.ts csp.ts cookies.ts cors.ts transport.ts hostRules.ts
│  │           exposure.ts html.ts api.ts cross.ts probes.ts（C13 のプローブの判定パターン）
│  ├─ engine/  analyze.ts run.ts labels.ts labels.json items.json asvs-levels.json standards.ts coverage.ts suppress.ts profile.ts diff.ts
│  │           summarize.ts targetKey.ts
│  └─ export/  markdown.ts json.ts csv.ts cmdSummary.ts
├─ scripts/screenshot.mjs     # README の画像と共有用の画像を撮り直す（npm run screenshot）
├─ scripts/capture-fixture.sh # tests/fixtures/generated_local.txt を、生成スクリプトをローカルのサーバに向けて実行して採り直す
├─ tests/                     # Vitest の単体テストと fixture。tests/regression/ はレビューの回ごとの回帰テスト
├─ e2e/                       # Playwright の E2E と axe-core のアクセシビリティ検査（本番ビルドに対して実行）
├─ docs/design.md             # 設計書（正本）。docs/history.md はレビューの経緯、docs/screenshot.png は README の画像
├─ .github/                   # workflows/（checks・ci・deploy・codeql・dependency-review）、dependabot.yml、ISSUE_TEMPLATE/、pull_request_template.md
├─ public/og.png              # 共有用の画像（npm run screenshot で撮り直す）
├─ SECURITY.md LICENSE README.md CONTRIBUTING.md CHANGELOG.md
├─ csp.config.ts             # このツール自身の CSP（vite.config.ts が本番ビルドに埋め込む）
└─ vite.config.ts eslint.config.js playwright.config.ts tsconfig.json .gitattributes .editorconfig .nvmrc
```

### GitHub Actionsによるデプロイ

Settings→PagesでSourceを「GitHub Actions」にし、「Enforce HTTPS」を有効にします（独自ドメインの場合はDNS設定とドメインの検証も行います）。ワークフローは`.github/workflows/`にあり、検査は`checks.yml`（再利用するワークフロー）にまとめ、Pull Requestの`ci.yml`と公開の`deploy.yml`の両方から呼ぶ（検査の内容がずれないようにするため）。

- **Pull Request（`ci.yml`）とmainへのpush（`deploy.yml`）**：`npm ci --ignore-scripts`→署名の検証と`npm audit`→`npm run lint`（tsc と ESLint）→単体テスト→本番ビルド→E2E（外部へのリクエストがないこと、マスキング、埋め込みの拒否、アクセシビリティなどを含む）。E2EはChromium・Firefox・WebKit（Safari）の3つで実行する（スマートフォンの画面幅の検査は、エミュレーションに対応しないFirefoxを除く）。
- **共有用の情報（OGP）**：`index.html`に説明とOGPを置く。共有用の画像の絶対URLは、ビルドのときに環境変数`SITE_URL`で渡す。CIでは、APIを呼ばずにリポジトリの情報から`https://<組織名>.github.io/<リポジトリ名>`を組み立てる（追加の権限が要らず、Pagesを有効にする前でも失敗しないため）。独自ドメインの場合は、リポジトリの変数`SITE_URL`で上書きする。画像には説明（`og:image:alt`）を付ける。画像は`npm run screenshot`で`public/og.png`も撮り直す。
- **main への push**：上記が通ったら、E2E まで通ったのと同じ`dist`を GitHub Pages に公開する（検査していないビルドを公開しない）。公開は1つずつ行い、実行中の公開は取り消さない。
- **権限**：どのワークフローも既定の権限を`{}`で無効にし、検査は`contents: read`だけ。公開のジョブだけに`pages: write`と`id-token: write`を与える（CodeQLの解析のジョブは結果の登録のために`security-events: write`・`actions: read`も持つ）。checkoutで認証情報を残さない（`persist-credentials: false`）。
- **SHA固定**：外部のActionはすべてコミットSHAで固定し、末尾に`# vX.Y.Z`のコメントを書く。更新はDependabotが行う。
- **CodeQL・dependency-review**：公開リポジトリのときだけ実行する（privateではGitHub Advanced Securityが必要なため、スキップする）。
- **ワークフローの検査**：`.github/`の下のYAMLが構文として読めることと、ワークフローの主要な設定（権限、SHA固定、認証情報を残さないこと、検査の順序、ブラウザ、`SITE_URL`）を単体テストで確かめる（`tests/workflows.test.ts`）。

### エクスポートとテスト

- **エクスポート**：Markdown（重要度順の表。前回の結果を読み込んでいれば差分の表、組織プロファイルの名前も含める）、JSON（Findingの配列、ツールとルールセットの版、生成日時、組織プロファイル、診断カバレッジ（`coverage`）、例外一覧、規格の対応表（`standards`。ASVS・IPA））、CSV（BOM付きUTF-8、第8章の列構成）。`Blob`と`URL.createObjectURL`で保存する。常にマスク済みで、生データは出力しない。CSVの「実施日時」「実施コマンド」は、指摘の元になったターゲットの`#META`から埋める（ホスト単位の判定は同じホストの`tls`・`probes`など、横断の判定は比べたラベルのターゲット。コマンドは、ターゲットごとの値を要約してから重複を除いてつなぎ、日時は文字列ではなく時刻として比べて最も新しいもの（`T`区切りと空白区切りが混ざっても））。
- **実施コマンドの要約**（`src/export/cmdSummary.ts`）：`#META cmd=`の値は利用者が書いたもの（`?access_token=`などを含むことがある）なので、秘密らしい場所を推し量って伏せるのではなく、残してよい形だけを残す（許可リスト。推し量る作りでは、どの漏れを直しても次の漏れが残る）。出す語は、コマンドのID（`C1`〜`C26`・`HAR`・`-`。`-`だけの値には数式の対策の`'`を付けない）、一覧にあるプログラム・オプション・ヘッダ・httpieの項目・環境変数の名前、シェルの区切り、HTTPのメソッド、opensslのサブコマンド、`timeout`の秒数、突き合わせのキーと同じ形のURL（`urlKey`）に限り、それ以外の語（値・ユーザー名・パスワード・ヘッダの値・知らない語）はすべて`****`にする（続く`****`は1つ。一覧と形の正本は`src/export/cmdSummary.ts`の冒頭）。
  - URLのユーザー情報は伏せる。URLの始まりからコマンドの値の終わりまでに`@`があるURLは、URL自身のユーザー情報の`@`が1つだけのときを除いて`****`にする（ユーザー情報の途中で切れたURLと見分けない。`?email=alice@example.com`・`/@alice`も）。`#META`の`cmd=`の値が引用符・空白で切れ、行のあとに`@`が残るときは、値の終わりに`@`を付けて要約する（`src/parser/input.ts`の`attrs`）。
  - 1つのコマンドは200文字まで（超えたら切って` …`を付ける）。実施日時はありうる日時（年は1900〜2099、各欄は範囲の中、秒の小数は3桁まで）だけを出し、ほかは`****`。
  - 要約はマスク（`src/mask.ts`）を読み込まない。出る語がどれも許可した形のどれかであること、値の置き場所の秘密が出ないこと、冪等、線形の時間は`tests/cmd-summary.test.ts`で確かめる。
- **テストが保証すること**：テストの流し方と期待結果の更新の手順は`CONTRIBUTING.md`に書く。
  - **パーサ**：fixtureのターゲット・応答（ゴールデンの期待結果の`responses=`）と、個々の形の例を確かめる。実際の curl と OpenSSL の出力（`generated_local.txt`は、今のコマンド生成器のスクリプトを curl 8.18.0・OpenSSL 3.5.5 でローカルのTLSサーバに対して実行したもの。`scripts/capture-fixture.sh`）も fixture にする。複数コマンドを続けて貼っても本文へ混入しないこと、`#`・` *  `・` >  `で始まる本文行が本文として残ること、空白を含むContent-Typeを`#PROBE`から読めること、複数ホストの結果をホスト単位で集約できること、HARの取り込み後のデータにリクエスト本文（postData）が残っていないことを確かめる。
  - **ルール**：条件ごとに、passとfailになる最小の入力を用意する。横断ルールは、予約ラベルが欠けたときにnaになることも確かめる。
  - **横断**：既知の秘密情報を入力のあらゆる場所に置き、どの出力（画面用のデータ、Markdown、JSON、CSV）にも現れないこと（`tests/masking.test.ts`）。推奨対応と判定不能の理由の英訳の漏れがないこと（ルールのソースコードの構文木から検出。`tests/i18n.test.ts`）。案内する「必要なラベル」で実際に判定されること（`tests/labels.test.ts`）。
  - **回帰**：判定の結果の全体（指摘・証跡・解析警告・突き合わせのキー・診断カバレッジ）を、コーパス（`tests/golden/cases/`と既存のfixture）について期待結果のファイルと比べる（ゴールデン。`tests/golden.test.ts`）。同じ応答を、改行の違う形と、curlの出力・HARの両方で入力し、判定が同じになること（同値性。`tests/equivalence.test.ts`）。
  - **アクセシビリティ**：axe-core（`@axe-core/playwright`）で、未入力・判定後・「情報」の表示・例外のダイアログ・コマンド生成器・英語UI・HARのエントリ一覧・ダークモード、スマートフォンの画面幅（390px）を検査し、軽微より重い違反がないこと（`e2e/a11y.spec.ts`）。スマートフォンの画面幅では、判定後にページが横にはみ出さないこと。表の枠は名前を持ち（`role="region"`と`aria-label`）、横にはみ出しているときだけフォーカスできる（`tabindex="0"`。画面幅や折りたたみの変化に合わせて判定し直す）。枠は`position: relative`にする（読み上げ用の非表示の文字が枠の外に出て、ページの幅を広げないように）。
  - **性質**（`tests/properties.test.ts`。fast-check）：作った入力の全体で確かめる。突き合わせのキー（もう一度かけても変わらない、値（クエリ・フラグメント・ユーザー情報・パス引数）とパスのトークンを差し替えても変わらずトークンを含まない、パラメータ・貼り付けたターゲットの順番で変わらない、マスクを読み込まない）、マスク（秘密の置き場所（パラメータ、JSON、ユーザー情報、パス、JWT、nonce、ASP.NETのセッション）にある乱数のトークンを、前後の文字を変えても出さない、もう一度かけても変わらない、切り詰めはマスクした文字列の先頭だけ）、実施コマンドの要約（`tests/cmd-summary.test.ts`。許可する形は実装とは別にテストに書く）、判定の結果（貼り付けたターゲットの順番を変えても指摘の集まりが変わらない）。見つけた反例は例のテスト（`tests/properties-cases.test.ts`・`tests/cmd-summary-cases.test.ts`）に残す。
  - **性能と耐性**（`tests/robustness.test.ts`。時間の上限を確かめるテストには`perf`のタグを付け、ほかのテストのあとに流す。`CONTRIBUTING.md`）：1MBの通常の出力の解析・判定時間（CIの差を見込んで上限6秒）。悪意のある入力（`*`の多い例外のURLパターン、閉じていないタグが大量にある本文）でも短時間で終わること。fast-checkで、curlの出力の行の部品を組み合わせた壊れた入力と、壊れたJSONの設定ファイル（例外、プロファイル、前回の結果、HAR）で例外を出さないこと。前回の結果・組織プロファイル・例外ファイルにおかしな値を入れても、Markdown・CSVに`undefined`などが出ないこと。前回の結果からは、差分で使う項目（ルールID・項目・ターゲット・キー・重要度・状態・証跡）だけを、型を確かめて取り出す。
  - **2乗の時間の見張り**（`tests/adversarial-perf.test.ts`）：個別の例ではなく形の組み合わせで見張る。よくある繰り返しの形（`<!--`・`ab.`・`a@`・`eyJ`・`-eyJ`・`%2B`・`#META `・ステータス行など約100種）を64KBずつ、HTMLとJSONの本文・CSP・Location・Set-Cookie・Serverのヘッダに置いて判定し、上限（判定4秒、差分・マスク・要約・キー1.5秒）に収まること。

### 実装の対応表

コードの詳細は設計書に写さず、ソースコードを正とします。設計書には方針・仕様・表だけを置きます。

| 設計書の節 | 実装 |
| --- | --- |
| 型（Target、Finding、Rule、Profile など） | `src/model.ts` |
| 入力モデル・パース（#TARGET、-i、-D -、-v、-L、header_json、openssl） | `src/parser/input.ts`、`src/parser/openssl.ts`、`src/parser/target.ts` |
| CSPパーサとSet-Cookieパーサ | `src/rules/csp.ts`、`src/parser/setCookie.ts` |
| HAR形式の取り込み | `src/parser/har.ts`、`src/harWorker.ts` |
| 入力から判定まで（画面はWeb Workerで実行） | `src/engine/analyze.ts`、`src/analyzeWorker.ts` |
| ラベルと適用する項目、必要なラベル | `src/engine/labels.json`、`src/engine/labels.ts` |
| ルール（第1〜6章） | `src/rules/`（登録は`ruleset.ts`、CSPの振り分けは`csp.ts`、横断ルールは`cross.ts`（A-10は`api.ts`）、ホスト単位は`hostRules.ts`） |
| 評価の順序、二重減点の除去 | `src/engine/run.ts` |
| 組織プロファイル、例外登録、差分 | `src/engine/profile.ts`、`src/engine/suppress.ts`、`src/engine/diff.ts` |
| 診断カバレッジ、集計 | `src/engine/coverage.ts`、`src/engine/items.json`、`src/engine/summarize.ts` |
| マスキング | `src/mask.ts`（名前と形で伏せる）、`src/shownText.ts`（画面・エクスポートに出す証跡とURLの許可リスト）、`src/tokenShape.ts`（英小文字のトークン・まれな2文字の並び・英字の語（`wordLike`）・区切った番号とコード（`digitRun`・`phoneRun`・`codeGroups`）・パスのトークン（`secretPiece`）の判定。マスク・画面の許可リスト・突き合わせのキー・ルールで共有） |
| プローブの判定パターン | `src/rules/probes.ts` |
| ASVS 5.0・IPAとの対応 | `src/engine/items.json`、`src/engine/asvs-levels.json`、`src/engine/standards.ts` |
| 差分・例外の突き合わせのキー | `src/engine/targetKey.ts` |
| CSVの実施コマンド・実施日時の要約 | `src/export/cmdSummary.ts` |
| コマンド生成器 | `src/commands.ts` |
| 画面、英語UI | `src/main.ts`（入口）、`src/ui/`（結果、HAR、コマンド生成器、例外のダイアログ、状態）、`src/i18n.ts`、`src/messagesEn.ts`、`src/recommendationsEn.ts` |
| エクスポート | `src/export/` |
| メタCSP、ライセンス一覧 | `csp.config.ts`（CSPの中身）、`vite.config.ts`（本番ビルドへの挿入、ライセンス一覧） |

## MVPとロードマップ

MVPでは、複数ターゲットの入力モデル、マスキング、例外登録、ルールセットの版管理までを入れ、実運用に耐える最小構成にしました。各フェーズで入れたものは次のとおりで、すべて実装済みです。

| フェーズ | 範囲 |
| --- | --- |
| MVP | `#TARGET`（`label`・`kind`・`sensitive`）・`#META`・`#PROBE`・`#TLSPROBE`による入力モデルと予約ラベル。`-i`、`-D -`、`-v`、`-L`のパーサ。URLとHTTPSの導出、API判定、機密応答の判定、ホスト単位の集約。H-07③を除くH系、C-01〜C-10・C-12・C-13、R-01〜R-07、T-04、T-05、T-07②、T-08、T-09、E-03、A-09と、横断ルール（C-07②・C-09・C-12①・H-02③・H-04⑤）。診断カバレッジ、例外登録、ルールセットの版と根拠、Markdown・JSONのエクスポート、メタCSP、免責表示、ライセンス表記、Actionsによるデプロイ |
| v0.2 | コマンド生成器（C1〜C26のうちC3を除くもの（C15はC5の`http`ターゲットで兼ねる）を`#TARGET`・`#META at=… cmd=…`付きで出力。WebSocketのパスを入れたときだけC16を出す。データを消しうる試験は作らない）。opensslパーサ（T-10②、T-11）と`#CIPHERPROBE`（C23。T-10①③）。C10（`header_json`）。H-07③、E-01・E-02・E-04〜E-13、T-01、T-06、T-12。CSVのエクスポート |
| v0.3 | A-01〜A-03、A-07、A-08、A-10、A-11、C-11、R-08、R-09。HAR形式の取り込み |
| v0.4 | 前回との差分、組織プロファイル、英語UI |
| v1.0 | ASVS 5.0とIPAの項番への対応付け（ツールの版1.0.0）。CLI版は作らない（判断の根拠14） |
| 手動確認（ツール対象外） | 手動確認の8項目と、自動の項目の手動の条件。扱いはツール設計1「ラベルと適用する項目」のとおり |

**版の付け方**：表の「v0.2」〜「v1.0」は機能の段階（マイルストーン）の名前で、ツールの版（`package.json`の`version`）とは別に扱う。v1.0の範囲を実装したので、ツールの版を1.0.0にした（それまでは0.x）。1.0.0からは、ツールの版をセマンティックバージョニングで付ける。

| 上げる桁 | 変更 |
| --- | --- |
| メジャー（2.0.0） | これまでの入力やファイルが使えなくなる変更：入力の形式（`#TARGET`などのマーカー、予約ラベル）、項目ID・条件番号、エクスポート（JSON）・例外ファイル・組織プロファイルの形式の互換を壊す変更 |
| マイナー（1.1.0） | 互換を保った追加：項目・条件・入力の形式・画面の機能の追加 |
| パッチ（1.0.1） | 誤判定・マスクの漏れ・画面の不具合の修正、文言の修正。重要度や条件を直す修正も、項目ID・条件番号を変えなければパッチ |

ルールセットの版（`RULESET_VERSION`）は`年.月-v<ツールの版>`の形で、判定の範囲や条件を変えたときに、そのときのツールの版に上げる。版を上げたら、`CHANGELOG.md`にその版の変更を書く。

## 判断の根拠・要確認事項・出典

主な設計判断は下記15点で、数値や版のうち未確認のものは「要確認事項」にまとめています。

### 判断の根拠

1. **HSTSのpreloadは既定で推奨しない**：hstspreload.orgがpreloadを既定で付けないよう求めているため。preloadなしは情報、条件を満たさないpreloadだけを低とする（H-02）。
2. **X-XSS-Protectionは「付いていると指摘」の向きで扱う**：古いObservatory CLIは未実装を減点していたが、現行のOWASPは`0`か送らないことを推奨している（H-17）。IPA「安全なウェブサイトの作り方」改訂第7版の5-(x)は`X-XSS-Protection: 1; mode=block`を勧めているが、主要なブラウザがXSSフィルタを廃止したため、本書はOWASPに従い、IPA 5-(x)をH-17に対応付けない。
3. **CSPの評価はcsp\_evaluatorを使う**：Apache-2.0で配布の制約が小さい。ObservatoryのコードはMPL-2.0の義務が生じるため、配点の考え方だけを参考にする。
4. **API応答には評価軸を切り替える**：OWASP REST Security CSが勧める`no-store`、`frame-ancestors 'none'`、`nosniff`、正しいContent-Typeを中心にし、HTML向けヘッダでは減点しない（第0章 0.3、A-09）。
5. **レート制限ヘッダは「兆候」としてだけ扱う**：IETFの`RateLimit`/`RateLimit-Policy`はまだInternet-Draftで仕様が変わっているため（A-04）。
6. **ライセンスはMIT**：短く、利用者にも貢献者にも分かりやすいため。依存パッケージのライセンス一覧はビルド時に生成し、画面から参照できるようにする。
7. **設計書の正本はリポジトリの`docs/design.md`**：実装と同じコミットで直せるため、設計と実装のずれが起きにくい。
8. **Observatory互換の点数は作らない**：主な指標は重要度別の件数とする。互換にするにはCSP・Cookie・CORS・Referrer-Policy・SRI・X-Content-Type-Options・X-Frame-Options・CORP・COOP・COEPのそれぞれをObservatoryの判定に対応付ける必要があり、特にCSPはObservatoryが独自の解析で結果を分けるので、csp\_evaluatorの結果から同じ結果を出すのは難しい。本家と同じ点数になることを確かめる手段がないまま「互換」と名乗ると、違う点数が出たときに誤解を招く。ソースはMPL-2.0で、流用できるのは考え方だけでもある。
9. **コマンド生成器はデータを消しうる試験を作らない**：チェックを付けたまま本番で実行する事故を防ぐため、DELETE は生成せず手順書に書くだけにする。メソッド上書き（T-03）の確認も、上書き先に副作用のない OPTIONS を使う。
10. **英語UIでは証跡・解析の警告・CSVを英訳しない**：証跡は応答から取った値と短い説明なので日本語のままとし、利用者が行動を決める推奨対応を優先した。CSV（第8章の記録様式）は日本語のまま。
11. **差分は、curlはラベル、HARはメソッドとURLで突き合わせる**：curlはラベルを診断者が付けるので安定している。HARはラベルの番号が記録し直すたびに変わるため（やり方はツール設計2「前回との差分」）。
12. **A-10（エラー形式）は`error-*`ラベルのAPIのエラー応答だけを比べる**：ブラウザ向けのHTMLのエラーページや、`unauth-*`の401などまで比べると、正しい設計でも「統一されていない」と出るため。HTMLのエラーページの情報露出はE-01で判定する。
13. **専用の組織アカウントで管理・公開する**：他のGitHub Pagesとオリジンを分けるため、専用の組織アカウントで公開する（ツール設計3「公開先とオリジン」）。
14. **CLI版は作らない**：ブラウザだけで使う運用のため。判定の部分（`src/parser`・`src/rules`・`src/engine`・`src/export`）は画面の部品に依存しないまま保ち（単体テストはNode.jsで実行している）、CIでの自動検査が必要になったときにCLIの入口を足せるようにしておく（具体的なCIの利用の予定が出るまでは作らない）。
15. **T-10はDHE＋AEADの暗号を合格のままにする**：Mozilla Server Side TLSは5.8でIntermediateからDHEを外した（6.0は前方秘匿性のあるECDHE＋AEADだけ）。一方、根拠にしているIPA「TLS暗号設定ガイドライン」はDHEのAEADの暗号を推奨の範囲に含める。DHEを指摘にすると多くのサーバで新しく指摘が出るため、IPAに合わせて合格とし、Mozillaとの差をここに書く。

### 要確認事項

- [ ] プローブの判定パターンを実際の応答で確認する（2026-11-19：git のHEAD・zip・package.json・ソースマップ・SPAのHTMLは実物で確認し、採る長さとパターンを直した（ツール設計1「プローブの判定パターン」）。phpinfo・server-status・web.xml・.svn/entries・composer.json・.DS\_Storeは、手元に実物を作る道具がなく、形式の仕様と典型的な例のまま）
- [x] HTTP/2・3のヘッダ名の大文字・小文字：公式の明言はないので、パーサは大文字・小文字の両方を受け付ける
- [x] `openssl s_client`の終了コードと出力：C12・C23は終了コードと`New, …, Cipher is`の行の両方で見る。`New`の行の版は暗号の最低の版なので、パーサは版をProtocolの行で読み、`New`の行はTLS 1.3のときだけ使う
- [x] ChromeのプリフライトMax-Ageの上限：7200秒（Safariは600秒、Firefoxは86400秒）。R-05②
- [x] curlの`-v`の行形式：`VERBOSE_HINT`はどの版でも検出できる。`SSL connection using`はOpenSSL系のバックエンドだけが出す（Windowsの標準のcurl（Schannel）・rustls・mbedTLSは出さない）ので、T-09①・T-10はC12・C23で判定する
- [x] 出典のURL：リンク切れと内容を確かめ、移転したものを直した
- [x] IPA・ASVSの項番：IPAは改訂第7版のPDFで確認し、ASVSは5.0.0の項番にした
- [x] C23の暗号名：OpenSSLの名前のまま。RC4-SHA・DES-CBC3-SHAは1.1.0以降の標準のビルドでok=err。DES-CBC-SHA・EXPORTの暗号は足さない
- [x] ブラウザのHARの書き出し：Chrome・Edge 130以降の既定はCookie・Authorization・Set-Cookieを除く（含めるには「with sensitive data」で書き出す）。Firefox・Safariは伏せずに書き出す。`har.ts`はどの形にも対応する

調べた内容の詳細と、レビューの指摘と対応の経緯は`docs/history.md`にまとめています。

### 出典

- [OWASP Secure Headers Project：Response Headers](https://secure-headers-project.owasp.org/response-headers/)（2026-11に移転）
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
- [Mozilla Server Side TLS の指針（JSON。v6.0）](https://ssl-config.mozilla.org/guidelines/latest.json)、[SSL Configuration Generator](https://ssl-config.mozilla.org/)（wikiの[Security/Server\_Side\_TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)は移転の案内だけになった）
- [IETF draft：RateLimit header fields](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers)、[RFC 9114（HTTP/3）](https://datatracker.ietf.org/doc/html/rfc9114)、[RFC 9116（security.txt）](https://www.rfc-editor.org/rfc/rfc9116)、[RFC 9457（Problem Details）](https://www.rfc-editor.org/rfc/rfc9457)
- [curl man page](https://curl.se/docs/manpage.html)、[everything curl：Verbose](https://everything.curl.dev/usingcurl/verbose/index.html)
- [GitHub Community Discussion #54257（PagesのHTTPヘッダ）](https://github.com/orgs/community/discussions/54257)
- [ISOG-J 活動成果](https://isog-j.org/activities/result.html)、[IPA「安全なウェブサイトの作り方」](https://www.ipa.go.jp/security/vuln/websecurity/about.html)
- [MDN Web Docs：HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)、[Chrome Lighthouse：Ensure CSP is effective against XSS attacks](https://developer.chrome.com/docs/lighthouse/best-practices/csp-xss/)
