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
- **機密応答の判定**：H-11①、H-12①②、R-04①、R-08①、R-09①、E-06①、E-12①は「機密応答かどうか」で判定が変わる。ツールは、①`#TARGET ... sensitive=1`または`sensitive=0`の明示、②明示がなければ送信側にAuthorizationか、セッションCookieらしい名前（第2章の推定。組織プロファイルの指定があればそれ）のCookieがある場合（`-v`の` >  `行とHARのリクエストで確認）は機密（`_ga`・`theme`のような解析用・設定用のCookieだけでは機密としない。curlとHARで同じ判定にする）、③どちらでもなければ「分からない」、の順で決める。分からないときは、機密応答を前提とする条件（①）を判定しない。H-11①・H-12①②・R-08①・R-09①・E-12①はnaにする。R-04とE-06は、`*`やJSONPがあること自体は確かなので、より弱い条件（R-04③・E-06②）として出し、根拠に「機密応答かどうか分からない」と書く。診断者は認証後ページと個人情報を含むAPIに`sensitive=1`を付ける。
- **静的リソースの扱い**：H-11①・H-12①②・R-04①・R-08①は、静的リソース（URLのパスの末尾の拡張子（クエリは見ない。`/api/me?avatar=me.png`は静的リソースではない）、またはContent-TypeがJS・CSS・画像・フォント・動画・音声・WebAssembly（拡張子は`.mp4`・`.webm`・`.mp3`・`.ogg`・`.wasm`・`.eot`なども））と、誰にでも同じ内容を返す公開ファイル（`robots.txt`、`sitemap*.xml`、`favicon.ico`、`ads.txt`、`humans.txt`、`security.txt`、`crossdomain.xml`、`manifest.json`、`*.webmanifest`、`/.well-known/`の下）を、`sensitive=1`を明示したときだけ機密応答として扱う。Cookieを送っただけ（上の②の推定）では機密としない。ブラウザは静的リソースや公開ファイルにもセッションCookieを送るため、長くキャッシュさせる静的リソースがすべてH-12①（高）になったり、CDNから`*`で配るJS・フォントがR-04①になったりするのを防ぐ。ただし`?callback=`・`?jsonp=`を持つURL（JSONP）は、Content-TypeがJSでも利用者ごとのデータを返すので静的リソースとしない（E-06は常に機密応答の判定に従う）。H-12は、静的リソースで`Cache-Control`がなければ③（情報）とする。
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
| H-01 | Strict-Transport-Security | C1（https）。HTTP応答のHSTSはブラウザが無視するため判定に使わない | `max-age=63072000; includeSubDomains` | ①ない・`max-age=0`（ブラウザにHSTSの記録を消させる指定） ②max-ageが31536000（1年）未満 ③構文を解釈できない ④includeSubDomainsがない（③は、RFC 6797 6.1のとおりに`;`で分けたディレクティブを読み、構文の誤り（カンマ区切り、`;`のない区切り）・同じディレクティブの重複・数字でないmax-ageのあるヘッダ。ブラウザはこのヘッダを無視する。C-01②③のホストのHSTSも同じ読み方） | SSLストリッピング、Cookieの盗聴 | ①高 ②中 ③高 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.1、IPA 2.3-1) |
| H-02 | HSTS preload | C1（label=apexのターゲットとwwwのターゲット）。apexは、apex自身の応答（転送の最初のホップ）で見る（`-L`やHARでwwwへの転送をたどった最後の応答はwwwのもの） | preloadを付けるならmax-age 31536000以上＋includeSubDomains。apexはhttpsの同一ホストに転送し、apex自身もHSTSを返す | ①preloadがあるのに条件不足 ②preloadなし（HSTSの構文が誤っていれば、ブラウザが無視するのでH-01③で判定し、H-02はna） ③preloadを付けているのにapexがHSTSを返さない（`max-age=0`も返さないのと同じ。preloadを付けたのがapexのドメイン（apex自身かそのサブドメイン）のときだけ。別のサイトのpreloadでは判定しない） | 登録拒否。登録後の取り消しに数か月かかる | ①低 ②情報 ③低 | hstspreload.org、ASVS 5.0.0 3.7.4 |
| H-03 | CSP（存在・強制） | C2（本文を含む採取。C1の`-D - -o /dev/null`では`<meta>`のCSPが分からないのでna）。`Content-Security-Policy`と`-Report-Only`を全件抽出 | 強制モードのCSPが1つ以上。HTMLの応答で、ヘッダがなく本文も採取していなければ（`-D - -o /dev/null`、`-v`）、metaのCSPがあるかが分からないのでna（JSONのAPIの応答は①を情報に下げ、A-09③として数える）。`<body>`の位置は、`<head>`の中のコメントとスクリプトの中の`<body>`を飛ばして探す。ヘッダがなくても、HTMLの`<head>`の中（`<body>`より前）の`<meta http-equiv="Content-Security-Policy">`のCSPがあれば、ブラウザは強制するので①②にしない（GitHub Pages・S3などヘッダを付けられない配信では普通の形）。H-04・H-05・H-07とH-04⑤（固定のnonce）もmetaのCSPで判定する。frame-ancestors・report-uri・sandboxはmetaでは効かないので除き、H-06はヘッダだけで見る | ①ない ②Report-Onlyのみ ③解析できない（ヘッダ値のどのポリシーにもディレクティブがない。カンマのあとのかけら（`report-uri`のURLの中のカンマ、`img-src 'self', data:`）だけが読めなくても、前のポリシーは効くので③にしない。読めないかけらは評価から除く） | XSSの影響が軽減されない | ①高 ②中 ③高 | OWASP CSP CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.3 |
| H-04 | CSP：script-src | csp\_evaluatorで解析。複数CSPはポリシーごとに評価（ただし、ほかのポリシーが同じ条件の指摘なしにスクリプトを制限していれば（`script-src`か`default-src`がある）、そのポリシーの①〜④・⑥は出さない。ブラウザはすべてのポリシーを満たすものだけを許すため） | nonceまたはhash＋`'strict-dynamic'` | ①`'unsafe-inline'`（nonce/hashなし） ②`*`、`https:`、`http:`、`data:` ③`'unsafe-eval'` ④JSONPを提供するホストを許可 ⑤nonceが応答ごとに変わらない（C24で同じURLを2回取得して比較） ⑥csp_evaluatorのその他の指摘（nonceが短い、IPアドレスでの許可、unsafe-hashes、スキームなしの指定） | XSSの回避 | ①高 ②高 ③中 ④中 ⑤高 ⑥中または情報（csp_evaluatorの重要度に従う） | Google CSP Evaluator、web.dev Strict CSP、ASVS 5.0.0 3.4.3 |
| H-05 | CSP：object-src・base-uri | 同上 | `object-src 'none'`、`base-uri 'none'`または`'self'` | ①object-srcもdefault-srcも未制限 ②base-uri未指定（default-srcにフォールバックしない） | プラグイン経由の実行、`<base>`注入 | ①中 ②中 | Chrome Lighthouse csp-xss、ASVS 5.0.0 3.4.3 |
| H-06 | クリックジャッキング対策（frame-ancestors・X-Frame-Options） | 同上＋XFOヘッダ | `frame-ancestors 'none'`または`'self'`。旧ブラウザ向けにXFO `DENY`/`SAMEORIGIN`を併用 | ①両方ない・XFOの値が不正（`ALLOWALL`や綴りの誤り。ブラウザは無視する） ②XFOが`ALLOW-FROM`のみ（モダンブラウザ非対応） ③frame-ancestorsがなくXFOのみ ④frame-ancestorsが広い（`*`、`https:`などのスキームだけ、`*.example.com`、ホストが`*`だけのもの（`https://*`・`*:443`・`https://*:*`）。XFOより優先されるので、XFOが`DENY`でも守れない。frame-ancestorsを指定したポリシーが複数あれば、すべてが広いときだけ④。1つでも狭いものがあれば、埋め込みはそれで制限される）。XFOはHTML Standardの手順で読む（すべての値をカンマで分けた小文字の集合。2つ以上で`deny`・`sameorigin`・`allowall`のどれかを含めば拒否、同じ値の繰り返しは1つ） | クリックジャッキング | ①中 ②中 ③情報 ④中 | MDN、OWASP Secure Headers、ASVS 5.0.0 3.4.6、IPA 9-(i)-a |
| H-07 | CSP：非推奨ディレクティブ・混在コンテンツ・構文 | 同上 | 報告は`report-to`。混在コンテンツがあるなら`upgrade-insecure-requests` | ①`block-all-mixed-content`、`referrer`、`plugin-types` ②`report-uri`のみ ③混在コンテンツ（E-07）があるのに`upgrade-insecure-requests`なし（httpのページは対象外。E-07と同じ） ④構文の誤り（不明なディレクティブ、キーワードの引用符、セミコロン、nonceの文字種。csp_evaluatorの構文検査） | 防御が効いていない | ①低 ②情報 ③低 ④低 | W3C CSP3、OWASP Secure Headers、ASVS 5.0.0 3.4.3, 3.4.7, 12.2.1 |
| H-08 | X-Content-Type-Options | C1 | `nosniff` | ①ない・値が不正（Fetch Standardのとおり、すべての値をカンマで分けた最初の値で見る。プロキシが付け足した`nosniff, nosniff`は合格。A-09②も同じ。本文のない204・304はna（H-11・H-12と同じ）。Locationのある3xxと`Content-Length: 0`の応答も、スニッフィングする本文がないのでna） | MIMEスニッフィングによるXSS | ①中 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.4 |
| H-09 | Referrer-Policy | C1 | `strict-origin-when-cross-origin`、`strict-origin`、`same-origin`、`no-referrer` | ①`unsafe-url` ②`no-referrer-when-downgrade`、`origin`、`origin-when-cross-origin` ③ない（現行ブラウザの既定はstrict-origin-when-cross-origin） ④不正な値 | URL内のトークンや個人情報の外部漏えい | ①中 ②低 ③情報 ④低 | OWASP HTTP Headers CS、MDN HTTP Observatory、ASVS 5.0.0 3.4.5 |
| H-10 | Permissions-Policy | C1 | 使わない機能を無効化（例：`camera=(), microphone=(), geolocation=()`） | ①ない ②旧`Feature-Policy`のみ | 埋め込まれた第三者による機能の悪用 | ①情報 ②低 | OWASP Secure Headers |
| H-11 | COOP・COEP・CORP | C1 | COOP `same-origin`。COEPは分離が必要なら`require-corp`または`credentialless`。CORP `same-origin`/`same-site` | ①機密応答（0.3）にCORPなし ②COOPなし（守りにならない値（CORPの`cross-origin`、COOPの`unsafe-none`）と、読めない値（知らない値・2つ以上の値）は、ないのと同じに扱う） ③分離が必要なのにCOEPなし（手動確認。ツールは判定しない）。機密応答かどうか分からず、守りになるCORP（`same-origin`・`same-site`）もなければ、①を判定していないので、COOPがあっても合格にせずna。値は大文字・小文字を区別する（`Same-Origin`はブラウザが読めない） | XS-Leaks、Spectre系攻撃 | ①低 ②情報 ③低 | OWASP HTTP Headers CS、ASVS 5.0.0 3.4.8, 3.5.8 |
| H-12 | Cache-Control | C1（認証後ページ、API、ログイン応答）。機密かどうかは0.3の判定に従う | 機密応答は`no-store`（本文のない応答（204・304）は対象外。H-11も同じ） | ①機密応答にno-storeがない（鮮度の指定（`max-age`・`s-maxage`・`public`・`Expires`）のない、経験的にキャッシュしてよいステータス（200・203・204・206・300・301・308・404・405・410・414・501）以外の応答（302・303・307、401・403・500など）はキャッシュされないのでna（`private`も保存を許す指定として数える）。未指定、`public`、`no-cache`のみ、Pragmaのみ） ②機密応答が`private`のみ ③静的リソースで未指定（静的リソースは、`sensitive=1`の明示がなければ機密応答としない。0.3）Locationのある3xxでは`private`を鮮度の指定に数えない（ASP.NETは既定ですべての応答に`private`を付けるので、`private`だけの302・303はna）。 | 共有PCやプロキシ、CDNに機密データが残る | ①高 ②中 ③情報 | OWASP HTTP Headers CS、REST Security CS、ASVS 5.0.0 14.3.2, 14.2.2 |
| H-13 | Content-Typeとcharset | C1 | HTMLは`text/html; charset=utf-8`、JSONは`application/json` | ①Content-Typeなし（本文が空の応答（`Content-Length: 0`の401・201など。HTTP/2でContent-Lengthがなく、本文のない201・202・401・403も）は対象外。別のサイトへの転送で終わるターゲット（`-L`でたどった転送先は対象の応答として判定しない）はnaとして示す） ②HTMLでcharsetなし（JSONを`text/html`で返す件はA-09①で判定） | 文字コードを利用したXSS、スニッフィング | ①中 ②中 | OWASP HTTP Headers CS、ASVS 5.0.0 4.1.1、IPA 5-(viii) |
| H-14 | X-Permitted-Cross-Domain-Policies | C1 | `none`（または`master-only`） | ①ない ②`all`など、ポリシーファイルによる読み込みを許す値 | PDFなどからのクロスドメイン読み込み | ①低 ②低 | OWASP Secure Headers（Active） |
| H-15 | Clear-Site-Data | C1（`label=logout`のターゲット） | `"cache", "cookies", "storage"` | ①ない（`logout`の応答が4xx・5xxのときはna） | 端末に情報が残る | ①情報 | OWASP Secure Headers、ASVS 5.0.0 14.3.1 |
| H-16 | 製品・バージョン・デバッグ情報の露出 | `Server`、`X-Powered-By`、`X-AspNet-Version`、`X-AspNetMvc-Version`、`X-Generator`、`Via`、`X-Runtime`、`X-Backend-Server`、`X-Debug-Token`、`X-Debug-Token-Link`、`Server-Timing` | 製品名・バージョン・内部ホスト名・内部処理の内訳を含まない（⑤の`Server-Timing`は、引用符の外のカンマで項目に分け、項目の名前だけを証跡に出す。`desc`の中のカンマで分けない） | ①バージョン番号が分かる（`X-Generator`は`Drupal 10`のような主な版だけでも①。`Server`・`X-Powered-By`は`AmazonS3`のような製品名の数字があるので`1.2`の形だけ。`Via`は、先頭のプロトコルの版（`1.1`・`HTTP/1.1`・`HTTPS/1.1`・`SPDY/3.1`）と区別するため、`Varnish/7.4`のような「名前/版」の形だけ。製品名だけの`Via`（`1.1 vegur`）は②にしない） ②製品名のみ（`X-Generator`なども含む） ③デバッグ系ヘッダ（プロファイラへのリンクなど） ④内部ホスト名・IP（ホスト名の最後が`.internal`・`.local`などのもの。`edge01.local.example-cdn.net`の`.local.`は公開のホスト名なので対象外） ⑤`Server-Timing`にDBや内部処理の名前・時間（CDNが付ける項目（Cloudflareの`cfL4`・`cfExtPri`、CloudFrontの`cdn-*`、Akamaiの`edge`・`origin`・`ak_p`、Fastly）だけなら対象外。証跡は項目の名前だけで、`desc`・`dur`の値は出さない（`desc`にSQLやメールアドレスを入れる実装がある）） | 既知の脆弱性を狙う手がかり、内部情報の露出 | ①低 ②情報 ③中 ④低 ⑤低 | OWASP WSTG、ISOG-J、ASVS 5.0.0 13.4.2, 13.4.6 |
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
| C-02 | HttpOnly | 同上 | セッションCookieに必須（OpenID Connectのセッション管理（check_session_iframe）のために仕様上JSから読むCookie（IdentityServerの`idsrv.session`、Keycloakの`KEYCLOAK_SESSION`）はセッションCookieとしない。解析用のCookie（Application Insightsの`ai_session`・`ai_user`、Adobeの`s_sess`、Brazeの`ab.storage.*`）と、名前がセッションらしくても値が真偽値・`0`・`1`のフラグ（`has_session=1`）もセッションCookieとしない（ほかの数字の値（`SESSIONID=1234`）はセッションIDとしてC-07で判定する）。0.3の機密応答の推定も同じ） | ①セッションCookieにない | XSSでのセッション窃取 | ①高 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.4、IPA 5-(ix) |
| C-03 | SameSite | 同上 | `Lax`または`Strict`。`None`ならSecure必須 | ①セッションCookieで未指定 ②値が不正 ③正当な理由のない`None` ④`None`でSecureなし（ブラウザが拒否し機能不全） | CSRF、クロスサイトでの漏えい | ①中 ②中 ③中 ④低 | OWASP Session Mgmt CS、MDN HTTP Observatory、ASVS 5.0.0 3.3.2 |
| C-04 | Domain・Path | 同上 | Domainは原則付けない。Pathは必要最小限 | ①`Domain=.example.com`など親ドメインへ拡大（CDN・WAFのCookie（`__cf_bm`など）はCDNがDomainを決めるので対象外。比べるのは、そのCookieを発行したホップのホスト（`-L`で転送した先のwwwが発行したCookieはwwwと比べる）） ②同じホストに複数アプリがあるのにPathが広い（手動確認。ツールは判定しない） ③Domainがホストと同じ（付けるとサブドメインにも送られる。空の`Domain=`はブラウザが無視するので対象外） | 侵害されたサブドメインや他アプリへの漏えい | ①中 ②低 ③低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.3 |
| C-05 | Expires・Max-Age | 同上 | セッションCookieは期限なしか、アプリのセッション有効期間以下 | ①セッションIDにセッション有効期間を超える期限（空や数字でない`Max-Age`はブラウザが無視し、`Expires`が効く） | 端末に残ったCookieの悪用 | ①中 | IPA 4-(vi) |
| C-06 | \_\_Host-・\_\_Secure-プレフィックス | Cookie名と属性 | セッションは`__Host-`（Secure、Domainなし、`Path=/`） | ①プレフィックスなし ②プレフィックスの条件を満たさない（ブラウザが拒否。プレフィックスは大文字小文字を区別しない（RFC 6265bis。今のChrome・Firefoxは`__host-sid`にも条件を求める）） | サブドメインからの上書き（Cookie Tossing） | ①情報 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 3.3.1, 3.3.3 |
| C-07 | セッションIDの長さ・推測可能性（文字種は、小文字と数字だけ・大文字と数字だけの値を36種で数える。62種で数えると、24文字の約124bitを約142bitとみなした）。ASP.NET Coreの分割したCookieの印（`.AspNetCore.Cookies=chunks-2`）は、値を比べるとき（C-07①②・C-09）は除く。属性の判定（C-01〜C-06）では、同じ応答に中身（`…C1`）があれば印は数えない（1つのCookieを2回指摘しない）。分割した中身の`…C1`・`C2`もセッションCookieとして扱う（oauth2-proxyの`_oauth2_proxy`・`_oauth2_proxy_1`も）。ただし①は、2つ目以降のかけら（`…C2`・`_oauth2_proxy_1`）を単独で判定しない（最後のかけらは端数の長さなので、約59bitのような誤検知になる）。JWT、Flask（itsdangerous）の圧縮したセッション（`.eJw…`で始まる「.ペイロード.時刻.署名」）、Djangoの署名付きのセッション（「ペイロード:時刻:署名」）は、同じアカウントではペイロードの大部分が共通になるので、署名の部分だけで比べる | ①は各値の長さと文字種。②は`session-sample-1`〜`N`の値を比較 | エントロピー128bit以上（ランダムな16進なら32文字以上） | ①推定128bit未満（時刻から作るUUIDは、乱数の部分だけで数える。v1・v2・v6は14bit、v7は74bit。v4は文字種で推定する） ②連番・時刻・ユーザーIDを含む、固定部分がある（JWTは、ヘッダとクレームが共通になるため署名の部分で比べる） | 総当たりや推測によるなりすまし | ①高 ②高 | OWASP Session Mgmt CS、ASVS 5.0.0 7.2.3、IPA 4-(i), 4-(v) |
| C-08 | 既定のCookie名 | Cookie名 | 汎用的な名前 | ①`PHPSESSID`、`JSESSIONID`、`ASP.NET_SessionId` | 技術スタックが分かる | ①情報 | OWASP Session Mgmt CS |
| C-09 | セッション固定化 | `pre-login`で発行・送信したIDと、`login`のSet-Cookieを比較（`-c`/`-b`でjarを引き継ぐ） | ログイン成功時にIDを再発行（2xx・3xxでもログインに失敗した応答はna：`?error`などのクエリへの転送、同じホストのログインらしいパス（`/login`・`/signin`など。認可コード・チケット（`?code=`・`?ticket=`）を持つSSOのコールバックは除く）への転送、`login`のURLのパス（末尾の`/`を除いて比べる。`login`のURLがトップ（`/`）ならクエリまで比べる）への転送、`pre-login`のチェーンの最後の応答（ログインのフォームの画面）のURLのパス（トップを除く）への転送、ログインらしいパスへ転送した先とlogin自身の応答のパスワード欄。SSOのコールバック（`?code=`・`?ticket=`）へ転送しただけでその先を採取していなければ、セッションはコールバックで発行されるのでna（`-L`で採取し直す）。`pre-login`の最初のURL（`/mypage`→`/login`の`/mypage`）とは比べない（ログインに成功して元のページへ戻る普通の流れを失敗とみなすため）。多要素認証の途中（`login`の転送先が`/two_factor`・`/mfa`・`/otp`・`/2fa`・`/totp`・`/webauthn`など。Fortifyの`/two-factor-challenge`、GitHubの`/sessions/two-factor/app`、Auth0の`/u/mfa-otp-challenge`、allauthの`/accounts/2fa/authenticate/`も含める。設定の画面の語（`setup`・`settings`・`reminder`・`backup`・`recovery`など）が続くもの（`/mfa/setup-reminder`・`/users/otp_settings`・`/2fa/backup-codes`）は含めない。メールの確認の案内（`/verify-email`・`/email/verify`）は、ログインが済んでいるので含めない）は、ログインが終わっていないのでna） | ①ログイン前後でIDが同じ（`login`で再発行されない。ログイン前のIDは、`pre-login`で発行したものと、`pre-login`で送ったもの（トップページで発行され、ログイン画面では送るだけ。ブラウザの普通の流れ）の両方を数える。送っただけの値は分からないので、`login`で新しいセッションCookieを発行したかで見る。`login`の応答が2xx・3xxでない（ログインに失敗した）ときはna） ②URLにセッションID（`;jsessionid=`など）多要素認証の2段階目かは、パスの最後の部分の拡張子を除いて見る（`/2fa.php`・`/Account/TwoFactor.aspx`もna）。ログインで新しいセッションIDを発行していれば、名前がセッションIDらしくない期限付きのCookie（`device_token`など。`sess`を含む名前と`sid`は除かない）をログイン前と同じ値で送り直しただけのものは固定化とみなさない。 | セッション固定化攻撃 | ①高 ②高 | ASVS 5.0.0 7.2.4, 14.2.1、IPA 4-(iv)-a, 4-(ii) |
| C-10 | HTTP応答でのCookie発行 | C15（`label=http`） | HTTP応答ではSet-Cookieしない（HTTPSへ転送するだけ）（`-L`でたどったhttpのホップすべてを見る） | ①HTTP応答でSecureなしのセッションCookieを発行 ②HTTP応答でその他のCookieを発行 | 平文区間での盗聴、Secure属性の確認だけでは見落とす | ①高 ②中 | ASVS 5.0.0 3.3.1, 12.2.1、IPA 4-(iii) |
| C-11 | Partitioned（CHIPS） | 第三者として埋め込まれるCookie | クロスサイト埋め込み用のCookieは`Partitioned` | ①`SameSite=None`の埋め込み用Cookieにない | サイト横断の追跡、将来のブラウザ制限での機能不全 | ①情報 | MDN |
| C-12 | ログアウト後のセッション無効化 | `after-logout`（ログアウト前の旧Cookieで認証後ページへアクセス） | 401、403、またはログイン画面への転送（200でもログインのフォーム（パスワード欄）を返したなら、セッションは使えていないので合格。`mypage`自身にパスワード欄があるときは使わない。②は、消したCookieがセッションCookieらしい名前のときだけ合格（`remember-me`だけを消すSpring Securityの既定のログアウトは②））（同じページ（末尾の`/`の違いだけ）への転送はたどって、その先で判定する。合格にするのは、401・403、ログイン画面・認証の入り口への転送（`/login`・`/signin`・Deviseの`/users/sign_in`・WordPressの`/wp-login.php`・OIDCの`…/openid-connect/auth`・`/authorize`・oauth2-proxyの`/oauth2/start`・Spring Securityの`/oauth2/authorization/<登録名>`、IdPの入り口（Googleの`/o/oauth2/v2/auth`、Shibbolethの`/idp/profile/SAML2/Redirect/SSO`、ADFSの`/adfs/ls`、SimpleSAMLphpの`SSOService.php`）、拡張子の付いた`/Account/Login.aspx`・`/login.php`・`.jsp`・`.do`など。トップ（`/`）への転送はログイン画面とみなさない（トップが利用者の画面を返すアプリがある）。`-L`でたどった転送は最後まで見て、途中の転送先がログイン画面か、先がログインのフォームか401・403でもよい）、ログインのフォーム（フォームごとに、inputのタグを1つずつ取り出して見る。パスワード欄が1つで、そのname・id・autocompleteにパスワードを決める欄の印（`new`・`confirm`・`retype`・`repeat`・`new-password`・`password_confirmation`など）がなく、name・idに`current`・`old`がある欄（アカウントの削除・メールアドレスの変更などの再認証の画面）は、nameに`current_password`・`old_password`があるもの（Deviseの再認証のフォーム`name="user[current_password]" autocomplete="current-password"`など）だけを除く（nameがちょうど`current-password`でautocompleteも`current-password`のもの（web.devが勧めるログイン画面）と、idだけが`currentPassword`のものは除かない。idの`old-password`・`old_password`は除く）（web.devが勧めるログイン画面は`id="current-password"`と`autocomplete="current-password"`）、ほかの入力欄かhiddenのユーザー名があるもの。パスワード欄だけのフォームは、`autocomplete="current-password"`で、送り先（action）がログインらしいもの（`/login`・`/signin`・`/session`など。`sudo`・`reauth`・`confirm`・`verify`を含むものは除く）だけ（ユーザー名を文字で表示した2段階目の画面。GitHubのsudoモードのような再認証の画面と分けるため））を200で返したときだけ。404・5xx・ほかのページへの転送はna。SPAの画面（`<div id="root">`とスクリプトだけで、文字がないか読み込み中の案内だけのHTML。Inertiaの`data-page`やNext.jsの`__NEXT_DATA__`のようにデータを持つものは除く）の200も、どのセッションでも同じものを返すのでna（A-01・E-05と同じ考え方）。②は、`Clear-Site-Data: "cookies"`でも合格。ログアウトの応答がセッションCookieを消さずに発行し直した（Laravelの`invalidate`・Railsの`reset_session`）ときは、新しい値か（期限を延ばしただけの同じ値か）が分からないので②をnaにし、古いセッションが使えないかは①で確かめる。WordPress（`wordpress_logged_in_…`）・Shibboleth（`_shibsession_…`）・oauth2-proxy（`_oauth2_proxy`）のCookieもセッションCookieとして扱う） | ①旧Cookieで認証後ページが200で返る ②ログアウト応答でCookieを削除しない（`logout`の応答が4xx・5xx（GETを受け付けないなど、ログアウトできていない）ときは①②ともna。`mypage`の応答が2xxでない（ログインできていない）ときは①をna）（`Max-Age=0`などがない）ログアウト後の2xxで、データのないJSON（値がすべて`null`・空のもの。`false`はログインの状態の名前（`authenticated`・`loggedIn`など）だけ。`{}`・`{"user":null}`）とGraphQLのエラーはna、GraphQLの認証の拒否（`UNAUTHENTICATED`など）は合格。利用者・状態のデータを埋め込んだ画面（インラインのスクリプトの代入・`JSON.parse(`・`application/json`のうち、`"user":`・`"email":`などの名前や、state・store・propsの名前への代入があるもの、`__NUXT`・`ng-state`、ルートの要素の`data-`・`:`・`v-bind:`の属性）は、中身のないSPAの画面とみなさず①。設定（`window.__ENV__ = {"API_URL":…}`・`dataLayer`）と構造化データ（`ld+json`）だけのものは殻のまま。SAMLの入り口（Entraの`/saml2`、Oktaの`/sso/saml`、Googleの`/o/saml2/idp`）への転送はログイン画面への転送。`-L`で別のサイト（IdP）へ転送した先のSet-Cookie・Clear-Site-Dataは、Cookieを消したかの判定に使わない（H-15も）。 | 盗まれたセッションがログアウト後も使える | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.4.1 |
| C-13 | Set-Cookieと共有キャッシュ | Set-Cookieを含む応答のCache-Control | Set-Cookieを含む応答は`private`または`no-store` | ①セッションCookieを含む応答が`public`または`s-maxage`付き（`no-store`か`private`もあれば共有キャッシュは保存しないので対象外） ②その他のCookieを含む応答が`public`（同じ） | CDNやプロキシ経由で他人にセッションが配られる | ①高 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 14.2.2 |
| C-14 | セッションタイムアウト | 認証後ページに、アプリの無操作タイムアウトより長くアクセスせずに置き、同じCookieで再アクセス（手動） | 無操作タイムアウトと絶対期限で失効する | ①無操作タイムアウトを過ぎても200で返る ②絶対期限を超えても使い続けられる | 盗まれたセッションの長期悪用 | ①中 ②低 | OWASP Session Mgmt CS、ASVS 5.0.0 7.3.1, 7.3.2 |
| C-15 | アカウントの列挙 | 存在するIDと存在しないIDでログインとパスワード再設定を試し、ステータス・本文・応答時間（-w '%{time\_total}'）を比べる（手動、検証環境） | どちらのIDでも同じステータス・同じメッセージを返す | ①ステータスや本文の違いでIDの存在が分かる ②応答時間の差でIDの存在が分かる | ユーザーIDの収集、パスワードリスト攻撃の効率化 | ①中 ②低 | OWASP Authentication CS、ASVS 5.0.0 6.3.8、IPA 2.5-3) |

- SameSite未指定時の扱いはブラウザで異なります（ChromeはLax扱い、FirefoxとSafariは挙動が違う）。「未指定＝安全」とも「未指定＝None」とも言えないため、明示を求めます。
- セッションCookieは、名前のパターンと期限がないことで推定します。名前は語（`-`・`_`・`.`とキャメルケースの境目）に分けて照合し、`sess`で始まる語（session、PHPSESSID、JSESSIONIDなど）か、sid・token・auth・jwt・loginの語があればセッションCookieとみなします（部分一致にすると sidebar_collapsed や oauth_state まで含めてしまうため）。CSRFトークンや設定用の名前（csrf・xsrf・consent と、ASP.NET の CSRF 対策の antiforgery・RequestVerificationToken を含むもの、区切り（- _ .）で分けた語が lang・locale・theme・ga・gid・pref… のもの）は除きます。負荷分散・WAFのCookie（`BIGipServer…`、`ARRAffinity…`、`AWSALB…`、`AWSELB…`、`TS01…`、`SERVERID`、`ROUTEID`、Kubernetesのingress-nginxの`INGRESSCOOKIE`、Google Cloudの`GCLB`）も、転送先のサーバの印で利用者ごとの秘密ではないため除きます（全員に同じ値を返すものがあり、C-07②の誤検知になる）。負荷分散のCookieは、CORSのリクエストでも同じサーバに届けるため仕組み上`SameSite=None`にする（`AWSALBCORS`、`ARRAffinitySameSite`）ので、C-03③にもしない。Azure Front Door（`ASLBSA`・`ASLBSACORS`）、Application Gateway（`ApplicationGatewayAffinity`）、Citrix ADC（`NSC_…`）、Traefik（`_TRAEFIK_BACKEND`）も負荷分散の印として除く。ただしALBの認証（OIDC・Cognito）のセッションCookie（`AWSELBAuthSessionCookie-…`）は、`AWSELB`で始まっても利用者ごとのセッションなので除かない。ASP.NETの認証のCookie（`.AspNetCore.Identity.Application`・`.AspNetCore.Cookies`・`.AspNetCore.Session`・`.ASPXAUTH`）は、名前の語にセッションらしい語がなく、「ログインしたままにする」では期限付きで発行するが、セッションCookieとみなす。WAF・CDN・ボット対策のCookie（Cloudflareの`__cf`で始まるもの（`__cf_bm`・`__cflb`・`__cfruid`など）・`cf_clearance`・`cf_ob_info`・`cf_use_ob`・`cf_chl_…`・`_cfuvid`、Impervaの`incap_ses_…`・`nlbi_…`・`visid_incap_…`、Akamaiの`ak_bmsc`・`bm_sv`・`bm_sz`・`bm_mi`・`_abck`）も、CDNが発行して属性を運営者が変えられないので、セッションCookieの推定から除き、C-03③・C-04①にしない。解析・チャット・決済などの外部サービスのCookie（Hotjarの`_hj…`、`intercom-session-…`、`AMP_TOKEN`、`__stripe_…`、`optimizely…`、Datadogの`_dd_s`、Bingの`_uet…`、Clarityの`_clck`・`_clsk`、HubSpotの`__hs…`、Segmentの`ajs_…`、Amplitude、Mixpanelの`mp_…`、`_fbp`、`_gcl_…`、）も、名前にsession・sid・tokenを含んでもログインの状態ではないので除く（HARで機密応答と推定し、公開ページをH-12①（高）にしないため）。推定が外れる場合は、ツールで手動指定します。
- `=`のないSet-Cookie（`Set-Cookie: <値>; Path=/`）は、名前が空で値だけを持つCookieとして扱います（RFC 6265bis 5.6。ChromeとFirefoxも同じ）。値が長く期限がなければセッションCookieと推定し、証跡では「（名前なし）=」に続けて値を伏せます（名前として読むと値が空になり、削除用とみなしてC-01・C-02の判定から外れ、C-12の証跡に値が出るため）。
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
| R-01 | Origin反射 | C6 | 許可リスト外のOriginにACAOを返さない（R-01は`Origin: null`を送った応答ではna、R-02は`Origin: null`を送った応答（送ったOriginが分からない`-i`では`cors-null`のラベル）だけで判定し、それ以外はna） | ①ACAOが送信Originを反射＋ACAC:true ②反射（ACACなし）（対象のURL自身のオリジン（スキーム・ホスト・ポートが同じ）を送った応答は、許可外のOriginを試していないのでna。httpのオリジン、サブドメイン、共用のホスティング（`*.herokuapp.com`、`*.github.io`）の隣のホストは、偽れるか他人のものでありうるので自サイトとしない） | 任意のサイトから認証付き応答を読まれる | ①高 ②中 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 3.4.2 |
| R-02 | null許可 | C7 | `null`を許可しない（`-v`でOriginを送っていなければna。R-01も同じ。CORSのミドルウェアの多くはOriginがあるときだけACAOを返すので、ACAOがないことは合格の根拠にならない） | ①`ACAO: null`＋ACAC:true ②`ACAO: null` | sandboxed iframeからの窃取 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-03 | 部分一致の不備 | `example.com.evil.net`、`evilexample.com`などをOriginに指定（`-v`必須。送ったOriginが見えない`-i`の`cors-partial`は、ACAOが似せたOriginならそれを送ったものとみなし、そうでなければna）。対象がサブドメイン（`api.example.com`）でも、そのドメイン（`example.com`）に似せたOriginはR-03で判定する（ドメインは最後の2つのラベル（`co.jp`などの国別の第2レベルなら3つ）の目安で、公開接尾辞の一覧は持たない。同じドメインのサブドメインは似せたものではなくR-01で判定する） | 完全一致で判定 | ①許可される＋ACAC:true ②許可される（ACACなし） | 同上 | ①高 ②中 | PortSwigger、ASVS 5.0.0 3.4.2 |
| R-04 | ワイルドカード | C6 | `*`は公開データのみ | ①機密応答（0.3）に`*` ②`*`＋ACAC:true（仕様上ブラウザが拒否。設定ミスの兆候） ③公開データに`*` | 公開すべきでないデータの露出 | ①中 ②低 ③情報 | MDN、MDN HTTP Observatory、ASVS 5.0.0 3.4.2 |
| R-05 | プリフライト応答 | C8 | Allow-Methods/Allow-Headersは必要最小限（許可外のOriginはR-01と同じく、送ったOrigin（自サイト以外）を反射したもの。送ったOriginが分からない`-i`では、テスト値のACAO） | ①許可外OriginにPUT・DELETEなど状態を変えるメソッドを許可（`Access-Control-Allow-Methods: *`も、ACAC:trueがなければすべてのメソッドの許可。ACAC:trueのときは「*」という名前のメソッドの意味なので対象外） ②`Access-Control-Max-Age`が極端に長い（Chromeは7200秒で打ち切り） | 他サイトからの状態変更、設定変更が反映されない | ①中 ②情報 | MDN、OWASP WSTG、ASVS 5.0.0 3.4.2, 4.1.4 |
| R-06 | Vary: Origin | C6 | ACAOを動的に返すなら`Vary: Origin`（`-v`かHARでOriginを送っていないのに返したACAOは、Originによらない固定の値なので適用外） | ①ない（カンマで区切った1つの値として`Origin`か`*`があるかで見る。`X-Origin-Id`のような名前の一部は対象外）送ったOriginが分からない（`-v`なし・`Origin`の指定なしで、HARでもない）ときの固定のACAOはna（Originによって変わる値かが分からない）。 | キャッシュ経由で別Origin向けの応答が配信される | ①低 | MDN |
| R-07 | Access-Control-Expose-Headers | C6 | 必要なヘッダのみ（レート制限の項目（`x-ratelimit-remaining-tokens`）と利用量の項目（`X-Tokens-Used`・`X-Total-Count`。`used`・`count`・`limit`は語として見る。`X-Account-Token`は対象）も対象外。除外はtokenを含む名前だけに使う） | ①認証トークンや内部ヘッダを公開（名前に token を含んでも、CSRF対策やページ送りのトークン（`X-CSRF-Token`、`X-Next-Page-Token`）は認証のトークンではないので対象外） ②`*` | クロスオリジンでのヘッダ情報の漏えい | ①中 ②低 | MDN |
| R-08 | Timing-Allow-Origin | C1（機密応答のターゲット） | 不要なら付けない。付けるなら限定 | ①機密応答（0.3）に`*` | タイミング情報の漏えい（XS-Leaks） | ①低 | MDN |
| R-09 | WebSocketのOrigin検証 | C16（握手の応答ステータスだけを見る。合格は401・403だけで、200・404などはWebSocketのエンドポイントではない可能性があるため判定不能とする。送ったOriginが対象と同じホスト（自サイト）なら、101は正しい動作で許可外のOriginを試していないため判定不能とする） | 許可外Originのハンドシェイクは403などで拒否（`-v`でOriginを送っていなければna。機密かどうかは0.3の判定に従い（`sensitive=0`の明示を優先）、`-v`でCookie・Authorizationを送っていなければ認証なし（②）、分からなければna） | ①Cookie認証のWebSocketが許可外Originで`101 Switching Protocols` ②認証なしのWebSocketが101 | クロスサイトWebSocketハイジャック（他サイトから利用者として通信される） | ①高 ②情報 | PortSwigger Web Security Academy、OWASP WSTG、ASVS 5.0.0 4.4.2 |

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
| T-01 | OPTIONS・TRACE | C9 | `Allow`は必要最小限。TRACEは405か501 | ①TRACEが200でリクエストを反射（200で本文を採取していなければna） ②不要な`PUT`、`DELETE`、`PROPFIND`がAllowにある | XST、攻撃対象の増加 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.4, 4.1.4、IPA 5-(ix) |
| T-02 | PUT・DELETE（静的パス） | `curl -sS -i -X PUT --data 'x' https://HOST/test.txt`（検証環境） | 401、403、405 | ①201または204で作成・削除できる | ファイルの改ざん・設置 | ①高 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-03 | メソッド上書き | C21。`X-HTTP-Method`、`X-Method-Override`も試す | 上書きヘッダを無視 | ①上書きでメソッド制御を迂回できる | アクセス制御の迂回 | ①中 | OWASP WSTG、ASVS 5.0.0 4.1.4 |
| T-04 | HTTP→HTTPSリダイレクト | C5（`label=http`のターゲットで実行） | 最初の応答で同じホストのhttpsへ301か308（ステータスが分からない応答（C10で`response_code`がない）はna） | ①転送せずHTTPでコンテンツを返す（4xxで断るのは、HTTPでコンテンツを返していないので合格。CloudFrontの「HTTPSのみ」、HTTPを拒否するAPIなど。5xxは設定が分からないのでna） ②最初の転送先がhttp ③別ホストへ転送（HSTSが効かない） ④302、303または307 | 中間者攻撃 | ①高 ②中 ③低 ④情報 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1, 4.1.2、IPA 2.3-1) |
| T-05 | リダイレクトチェーン | C5 | 最終的にhttpsで、ホップが少ない | ①途中にhttpが挟まる ②Locationに内部ホスト名やポート（診断したURL自身のホストとポート（`https://example.com:8443/`）への転送は対象外。別のホストへの転送は同じポートでも対象） | 中間者攻撃、内部情報の露出 | ①中 ②低 | MDN HTTP Observatory、ASVS 5.0.0 12.2.1 |
| T-06 | オープンリダイレクト | `?url=`、`next`、`returnTo`に`https://evil.example`を指定 | 外部ホストへのLocationを拒否（`Refresh: 0; url=https://evil.example/`も①。転送しなかった応答（200・404）は、転送先を検証しているかが分からないのでna）（ログイン画面・認証の入り口への転送（C-12と同じ一覧。テスト値を持ち越したかによらない。Spring・Devise・Laravelは保存したリクエストでログインのあとに戻る）と同じページ（パスとクエリが同じ）への転送は、転送先の検証を試していないのでna。ターゲットのURLが絶対URLでなくても、転送先を読んで判定する。ログイン画面以外への転送（`/home?blocked=…`、`/redirect?error=…`）は合格。C19の採取先（ログイン画面）が200を返すとnaになるので、`next=`で実際に転送するURLに置き換える） | ①`Location: https://evil.example`（転送先はブラウザと同じ読み方（WHATWG URL）で解釈する。`/\evil.example`・`https:\\evil.example/`・`///evil.example`も外部ホストへの転送。末尾のドットの付いた`evil.example.`も同じホスト。`evil.example.a.example`は外部ホストではない）SAMLの入り口（`/saml2`・`/sso/saml`・`/o/saml2/idp`）への転送も、ログイン画面への転送（na）。 | フィッシング、OAuthトークンの窃取 | ①中 | OWASP Unvalidated Redirects CS、ASVS 5.0.0 3.7.2、IPA 2.4-3) |
| T-07 | Host・X-Forwarded-Hostヘッダインジェクション | C14。①③はパスワード再設定に付けて実行し、届いたメールや再取得した応答を手動で確認（検証環境） | 偽装した値をLocation・本文・リンク生成に使わない | ①再設定メールなどのURLに反映 ②Locationや本文の絶対URLに反映（2xxで本文を採取していなければ、本文に反映したかが分からないのでna） ③キャッシュされた応答に反映 | 再設定リンクの乗っ取り、キャッシュポイズニング | ①高 ②中 ③高 | OWASP WSTG、PortSwigger Web Security Academy、ASVS 5.0.0 4.1.3 |
| T-08 | CRLFインジェクション | C20（検証環境） | 改行が応答ヘッダに入らない | ①応答に`Set-Cookie: crlf=1`など注入したヘッダが現れる | ヘッダ分割、Cookie注入、XSS | ①高 | OWASP WSTG、ASVS 5.0.0 1.2.1, 4.2.4、IPA 7-(i)-a, 7-(i)-b, 7-(ii) |
| T-09 | TLSバージョン。プローブがなく、合意したバージョン（C4）しかなければ、①はnaとして出す（②だけで判定済みとしない）。合意した`SSLv3`も① | ①はC12（プロトコルごとの接続可否）。C4の`* SSL connection using`行で旧バージョン（`TLSv1`・`TLSv1.1`・`SSLv3`）を合意した場合も、そのバージョンで接続できたので①。②もC4の同じ行。C4で分かるのは合意したバージョンだけで、TLS 1.2以上を合意しても旧バージョンを受け入れるかは分からない。TLS 1.3のプローブ（`#TLSPROBE v=tls1_3 ok=1`）で接続できたなら、合意が1.2なのはcurl側の事情なので②にしない。旧バージョンのプローブが拒否されても、そのホストにTLSで接続できたと分からない（1.2・1.3のプローブや弱くない暗号のプローブで接続できた、C4で合意した、opensslの出力に証明書がある、のどれもない）ときは、合格にせずna（プロキシ経由の環境では、curlはつながってもopensslはつながらず、すべてのプローブが失敗する。T-10も同じ） | TLS 1.2と1.3のみ（Mozilla Intermediate） | ①TLS 1.0・1.1・SSLv3で接続できる ②TLS 1.3非対応 | 暗号の弱化 | ①高 ②情報 | Mozilla Server Side TLS、OWASP TLS CS、ASVS 5.0.0 12.1.1、IPA 2.3-1) |
| T-10 | 暗号スイート・鍵。③は、AEADでも前方秘匿性のない静的RSAの鍵交換（`AES128-GCM-SHA256`など、ECDHE・DHEで始まらないもの）も含む | ①③は`openssl s_client -cipher`で個別に接続可否を確認（C23）。C4で合意した暗号（TLS 1.3以外）も①③で判定する。②はC11の証明書。C4で分かるのは合意した暗号だけ。合意した暗号（C4の`* SSL connection using`、C11のCipher）だけでは、弱い暗号を受け入れるか（①）も鍵・署名（②）も分からないので合格にせず、C23（暗号ごとの確認）かC11（証明書）があるときだけ合格にする。C23の弱い暗号がすべて拒否されても、そのホストにTLSで接続できたと分からなければna（T-09と同じ） | ECDHE＋AEAD（AES-GCM、ChaCha20-Poly1305）。ECDSA P-256かRSA 2048bit以上 | ①RC4、3DES、EXPORT、NULL、aNULLが通る ②RSA 2048bit未満（鍵の種類が出力にないOpenSSL 1.1・LibreSSLでは長さから推定。224・256・384・521bitは楕円曲線、253bitはEd25519、456bitはEd448とみなす。512bitはbrainpoolP512r1とRSAを区別できないのでRSAとする）、SHA-1署名（自己署名のルート証明書は除く。OpenSSL 3.5はEC鍵の長さを出さず`a:PKEY: EC, (prime256v1)`のように曲線の名前を出すので、名前から長さを引く） ③TLS 1.2以下でCBCや静的RSA鍵交換が通る | 既知の攻撃、前方秘匿性がない | ①高 ②高 ③中 | Mozilla Server Side TLS、ASVS 5.0.0 12.1.2 |
| T-11 | 証明書 | C11（同じホストのopensslの出力が複数あるときは、証明書の情報があるもの、採取した時刻（`#META at`）が新しいもの（時刻のないものは最後）、ラベルの順で選ぶ。T-10②も同じ順で、鍵・署名の分かる出力を選ぶ。入力の順番では選ばない） | `notAfter`まで30日以上。SANに対象ホスト。`Verify return code: 0 (ok)` | ①期限切れ・ホスト名不一致・チェーン不備・SANがない（今のブラウザはCNを見ない。SANがないかは、`-showcerts`の最初の証明書（PEM）にSANの拡張があるかで見る。PEMがない出力、切れたPEM（DERの長さが合わない、空行が入った）ではSANがあるか分からないので、今までどおりCNで比べる。x509の出力にSANの行があればSANはある。SANのIPアドレス（`IP Address:192.0.2.10`）も読み、IPアドレスで接続した証明書はそれで比べる。IPv6は書き方をそろえて比べる） ②期限まで30日以内 | サービス停止、中間者攻撃 | ①高 ②中 | OWASP TLS CS、ASVS 5.0.0 12.2.2 |
| T-12 | HTTP/2・HTTP/3 | `-w '%{http_version}'`、`alt-svc`ヘッダ。HTTP/3の確認は`--http3`対応のcurlが必要 | 任意 | ①HTTP/1.1のみ | — | ①情報 | RFC 9114 |
| T-13 | 送信元IPの偽装（X-Forwarded-Forなど） | C17。IP許可リストの管理画面や、レート制限（A-04）の試験時に`X-Forwarded-For`の値を変えて比べる（検証環境） | 信頼できるプロキシが付けた値だけを使う | ①偽装でIP許可リストを回避できる（403→200） ②偽装でレート制限がリセットされる ③偽装したIPが本文やログにそのまま反映 | アクセス制御や総当たり対策の回避、監査ログの改ざん | ①高 ②中 ③低 | OWASP WSTG、ASVS 5.0.0 4.1.3, 15.3.4 |

OpenSSL 3系は既定で古いプロトコルを拒否するため、T-09でTLS 1.0/1.1を試すときは`-cipher 'DEFAULT@SECLEVEL=0'`を付けます。付けないと、サーバが許可していても「接続不可」と誤判定します。手元のOpenSSLがそのプロトコル自体に対応していない場合、C12は ok=err を出し、ツールは判定不能（na）とします（T-10は、ok=errの暗号を「拒否」に数えず、合格の証跡に「手元のOpenSSLが非対応で試していない」と書く。OpenSSL 1.1以降はRC4・3DESを試せないため、naにはしない）。

診断対象のサーバは、ハンドシェイクのあとに任意のデータを送れ、`openssl s_client`はそれを標準出力に出します。そのため生成スクリプトは、次のように採取します（サーバが`unsupported protocol`・`DNS:…`・`notAfter=…`を書いて、T-09・T-10・T-11の判定を変えられないように）。
- C12・C23の接続可否：手元のopensslのエラー（`unknown option`・`no protocols available`・`no cipher match`）は標準エラーだけで見て`ok=err`にします。接続できたかは、終了コードが0で、出力を最初の`Verify return code:`の行（ハンドシェイクの要約の終わり。サーバのデータはこれより後にしか出ない）で切った中に`New, <版>, Cipher is <暗号>`の行があるかで見ます（版は、OpenSSL 1.1以降は暗号の最低の版を出す（TLS 1.0のAES128-SHAも`New, SSLv3, Cipher is AES128-SHA`）ので問わない。失敗した`New, (NONE), Cipher is (NONE)`は除く）。`unsupported protocol`は、サーバが別のバージョンを選んだ（そのバージョンを拒否した）ときにも出るので、拒否として扱います。
- C11の証明書：`s_client -showcerts`の出力を、同じく最初の`Verify return code:`の行で切って出します。`openssl x509`の出力は、最初の証明書から作るので、そのまま出します。
- 手で採取した出力（印のないもの）は切っていないので、サーバのデータが混ざりえます。

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
| E-01 | スタックトレース・デバッグ情報 | 不正なURL、型違いのID、壊れたJSONを送る | 汎用エラー、またはRFC 9457の問題詳細形式（資格情報を含む`jdbc:`は①だけで、②にはしない）（②のスタックトレースは、Java・Python・PHP・.NETに加え、Node.jsの`at 関数 (/パス:行:列)`と`node:internal`、Goの`goroutine N [running]`、Symfonyの例外も見る。Node.jsのフレームは、ファイル（`.js`・`.ts`など）か`node:`の行と列まであるもの（無名のフレーム`at /app/index.js:7:9`も）。無名のフレームは、行の始め・タグの直後・JSONの配列の要素や`stack`などの値の始めにあるもの、または同じ行の前に`Error`・`Exception`があるもの（文章の`Look at /src/app.js:10:5`は対象外）で、直前が引用符のもの（スクリプトの文字列`"at /static/js/chunk.js:1:20345"`）と、パスに引用符・カンマを含むもの（JSONの`{"tip":"look at /docs","entry":"main.js:1:2"}`）は対象外。JSONの文字列に入れたスタックトレース（Springの`"trace":"…\n\tat com.example…"`、エスケープしたPythonの`File \"/app/main.py\"`）は、エスケープを戻した本文でも照合する。PHPの`html_errors`の形（`<b>/app/index.php</b> on line <b>3</b>`）と`Stack trace: #0`、.NETのフレーム（行の始めの`at Npgsql.Internal.…(`）も見る。Railsの`/app/…/x.rb:12:in`、Pythonの`File "/app/main.py", line 41`の形も見る。`/app`は絶対パスの一覧には入れない（`serviceWorker.register("/app/sw.js")`のようなスクリプトのパスで誤検知するため）） | ①接続文字列（`Server=…;Password=…;`、資格情報を含む`jdbc:`（`//user:pass@`（ユーザー名とパスワードに`;`・`?`・`&`を含まないもの。`jdbc:sqlserver://db;user=svc@corp`はパスワードがないので対象外）、`?password=`・`;password=`、Oracleの`thin:user/pass@`）、`mongodb://user:pass@`。ユーザー名・パスワードに引用符・`/`・`@`を含まないもの（資格情報のない`mongodb://host/app`のあとのメールアドレスの`@`で誤検知しない））・AWSアクセスキー（HTMLの応答のAWSアクセスキーは、そのラベルでE-09を判定するときはE-09①で数える。同じ値を2回、高として数えない。`error-*`のようにE-09を判定しないラベルではE-01①で数える）。`Server=…;`の形は、キーを大文字小文字を区別して照合し、`Password`は`;`の直後のキーに限る（小文字のJSの`var host = …; var password = …;`には一致させない） ②スタックトレース（`Traceback`、`at java.`）、SQL文（`SQLSTATE`、語の境目からの`ORA-`。`FLORA-12345`のような品番は対象外）、資格情報のない`jdbc:`の接続文字列（証跡は`jdbc:mysql:`までで、接続先のホスト名は出さない）、絶対パス（URLのパスの一部（`https://cdn…/opt/app.js`、`src="/srv/main.js"`、`url(/srv/…)`）は対象外） ③フレームワーク既定のエラーページ（`Whitelabel Error Page`、Expressの既定のページ（タイトルがちょうど`Express`。`Example Express`のような普通のページは対象外）、Railsの既定の404・500のページと開発用の画面など。Jettyの`<title>Error 404 …</title>`は本文の`HTTP ERROR 404`か`Powered by Jetty`と合わせて見る。独自のエラーページのタイトルや、本文の「Ruby on Rails」の語は対象外）②の`Error`・`Exception`は小文字も見る（`Internal server error at /app/src/handler.js:10:5`）。nginxの既定のエラーページ（`<hr><center>nginx…</center>`）とApacheの`<address>Apache… Server at …</address>`は、エラーの応答（4xx・5xx）のときだけ③（同じ署名が既定の301・302の本文にもある）。 | 内部構造・秘密情報の露出 | ①高 ②中 ③低 | ISOG-J、ASVS 5.0.0 16.5.1, 13.4.2、IPA 1-(iii) |
| E-02 | ディレクトリリスティング | `curl -sS https://HOST/images/`（nginx・Apacheの`Index of /`、IISの`[To Parent Directory]`、Tomcatの`Directory Listing For`、Jettyの`Directory: /`、serve-indexの`<title>listing directory`） | 403か404 | ①`Index of /`など一覧が表示されるオブジェクトストレージの一覧（S3・GCSの`<ListBucketResult>`、Azure Blobの`<EnumerationResults>`。XMLの応答）も①。 | ファイルの列挙 | ①中 | ISOG-J、ASVS 5.0.0 13.4.3 |
| E-03 | 既知ファイル（/.git、/.envなど） | C13。先頭64バイトは判定にだけ使い、画面とエクスポートには「一致したパターン名」だけを出す | 404 | ①中身を取得できる（HTTP 2xxで、中身がパターンに一致する。/.git/HEADが`ref: refs/heads/`で始まる、/.envに`KEY=value`行、phpinfoの出力など） ②200だが中身が一致しない（どのパスにも200を返すSPAなど。判定保留）。コードが`000`（接続できなかった）のパスが1つでもあれば、ほかで①②がなくても合格にせずna（E-04②・E-13①も同じ）。パターンと項目の対応はツール設計1「プローブの判定パターン」。robots.txtとsecurity.txtは対象外（E-04で判定） | ソースコードや認証情報の漏えい | ①高 ②情報 | ISOG-J、OWASP WSTG、ASVS 5.0.0 13.4.1, 13.4.7、IPA 2.1-5) |
| E-04 | robots.txt・security.txt | C13では存在確認だけ。中身は本文を取得して確認：`curl -sS https://HOST/robots.txt` | robotsに機密パスを書かない。security.txtに`Contact:`と`Expires:` | ①robotsに機密パス（`Disallow: /admin-secret/`など。admin・secret・backup・private・internal・staging・dev・devel・test・testsite・config・manage・console・phpmyadminとその複数形を英字の語の境目で見る。adminはadministratorなどの続く語と、sys・my・web・db・site・superの接頭辞も含む。`/devices/`の`dev`、`/latest/`の`test`、`/badminton/`は対象外） ②security.txtがない・期限切れ（`Expires`が日時として読めないもの（`never`など）も含む）`/robots.txt`の本文がHTML（`<`で始まる。どのパスにも`index.html`を返すSPA）のときは、robots.txtなし（合格）。Content-Typeが`text/html`でも、本文がrobots.txtなら中身を見る。 | 隠しパスの露出、報告窓口がない | ①低 ②情報 | OWASP WSTG、RFC 9116 |
| E-05 | API仕様・管理機能 | `/swagger-ui/`、`/openapi.json`、`/v2/api-docs`、`/graphql`（introspection）、`/actuator`、`/actuator/env`。パスは`/`で区切った1つの部分として照合する（`/category/actuator-kits`のような普通のページには一致させない）。ステータスは、そのURL自身の応答（転送の最初のホップ）で見る（ログイン画面への転送先の200で①にしない）。ただし、同じホストで同じ機能のページへの転送（転送元のパスに`/`か`/index.html`を足しただけのもの。`/swagger-ui`→`/swagger-ui/index.html`、`/swagger-ui.html`→`/swagger-ui/index.html`）は転送先で見る（転送先を採取していなければna。`/actuator`→`/actuator/login`のようなログイン画面への転送は、今までどおり最初のホップで見る）。ステータスが分からない応答（`%{header_json}`だけで`response_code`がない）はna | 本番では無効、または認証の内側（HTMLの200は、その機能の画面と分かるとき（`<title>`のSwagger UI・ReDoc・RapiDoc・Scalar、`<div id="swagger-ui">`、`swagger-ui-bundle.js`、`<redoc>`、`<rapi-doc>`、`@scalar/api-reference`。本文の「Swagger UI」の語だけでは見ない）だけ②にする。actuatorとAPI仕様の本体はJSON・YAMLなので、HTMLの200はna。どのパスにも`index.html`を200で返すSPA（Netlify・Vercel・Firebase Hosting・S3＋CloudFront）で誤検知しないため） | ①管理機能・actuatorが未認証で使える（`/actuator/health`・`/actuator/info`の状態だけの応答（`{"status":"UP"}`）は、Spring Bootが既定で公開する死活監視の応答なので合格） ②API仕様が未認証で公開（①②とも、CookieかAuthorizationを送った応答（0.3の②の推定と同じ）の200は、未認証で使えるかが分からないのでna） ③GraphQL introspectionが有効（introspectionのクエリを送った応答だけで判定する。`__schema`があれば③、本文が introspection を拒否していれば合格、それ以外（`GET /graphql`の400「Must provide query string」や405など）はna。HTMLの応答は introspection の応答ではないので合格にしない。GraphiQLなどのIDEの画面が200で開ければ②（IDEのJSが introspection の語を含むため、拒否とみなしていた））Spring Boot actuatorの既定の応答（`/actuator/health`・`info`で`status`とKubernetesの`groups`だけのもの、`/actuator`の一覧でリンクが`self`・`health`・`health-path`・`info`だけのもの）は合格。 | 攻撃対象の全容が分かる、設定値の露出 | ①高 ②中 ③中 | OWASP API Top 10 2023（API9）、ISOG-J GraphQL診断ガイドライン、ASVS 5.0.0 13.4.5, 4.3.2 |
| E-06 | JSONP | `curl -sS -i 'https://HOST/api/x?callback=test123'` | JSONPに対応しない | ①機密応答（0.3）を`test123(...)`で返す（Expressの`res.jsonp`の形`/**/ typeof test123 === 'function' && test123(...)`も含む） ②公開データのJSONP（CSP回避の足がかりになる）（2xxで本文を採取していなければna） | クロスサイトでのデータ窃取、CSPの回避 | ①高 ②低 | Google CSP Evaluator、PortSwigger、ASVS 5.0.0 3.5.6, 3.5.7 |
| E-07 | HTML本文：混在コンテンツ | C2の本文 | 資源はすべてhttps | ①`http://`のscript・iframe・stylesheet ②`http://`のimgなど | 通信途中でのスクリプト差し替え | ①中 ②低 | MDN、ASVS 5.0.0 12.2.1、IPA 2.3-1) |
| E-08 | HTML本文：第三者スクリプトのSRI | C2の本文 | 外部CDNのscriptに`integrity`と`crossorigin` | ①外部オリジンのscriptにintegrityがない（外部かは、HTMLを返したページ（`-L`で転送したときは転送先）のホストと比べる。配信元ごとに1件にまとめる。組織プロファイルで自社の配信元とした所は対象外） | CDN侵害時のスクリプト改ざん | ①低 | MDN（Subresource Integrity）、ASVS 5.0.0 3.6.1 |
| E-09 | HTML本文：機密・内部情報 | C2の本文 | 本番HTMLに秘密情報や開発用コメントがない（OpenID Connectの`response_mode=form_post`の画面で、POSTするフォームのhiddenの`id_token`・`access_token`・`code`・`state`の値は、ブラウザに渡すのが仕事なので対象外）（除くのはそのinputのタグだけで、値をページ全体からは消さない） | ①APIキー・トークン・認証情報（代入の値はASCIIの英数字・記号のものだけ。日本語の文言は対象外。名前の前は語の境目（`forgot_password:`は対象外）。値がパス（`/users/password/new`）、URL、ドットでつないだ翻訳キー（`auth.password.label`）、テンプレート、英語の画面の文言、公開を前提にした値（A-07と同じ。Stripeの`pk_live_…`など）なら対象外。GoogleのAPIキー`AIza…`は、Maps・Firebaseなどブラウザから使う前提のキー（HTTPリファラーやAPIの制限で守る）なので対象外。伏せ字の値（`********`・`***`・`[REDACTED]`・Railsの`[FILTERED]`など。A-07も同じ）も対象外。JWTは、公開を前提にしたもの（ペイロードの`role`が`anon`。Supabaseのanon key）は対象外） ②内部URL（`db.prod.internal`のような複数のラベルのホスト名も含む。診断したURL自身のホスト（社内のポータルの自サイトへのリンク）は対象外）や開発コメント（`pass: …`・`pass=…`のような値の代入も見る。`TODO`・`FIXME`・`XXX`・`HACK`・`debug`・`staging`は大文字・小文字を区別し、前後が英字でないもの（`debug_mode`・`debugMode`・`staging_db`と、キャメルケースの途中の`isDebug`も）。`password`（複数形も。`pass`だけは「Tests pass」のような文に出るので見ない）・`パスワード`は、部品の説明（`<!-- Password field -->`、`password reset`、`パスワード欄`）を除く） ③`<meta name="generator">`のバージョン（`Drupal 10`のような主な版だけも含む）開発用コメントの語には、`pass`のあとに数字か、英字で始まり数字を含む語が続くもの（`admin/pass123`・`pass admin123`。`tests pass 100%`・`pass 2 of 3`は除く）も含める。Knockoutの制御のコメント（`<!-- ko if: … -->`・`<!-- /ko -->`）は開発用コメントとしない。ブラウザで使う前提のSDKの呼び出しの中の`apiKey`（Algoliaの`docsearch`・`algoliasearch`、Bugsnag・Sentry・Mixpanelなどの初期化）は①にしない。 | 秘密情報の漏えい、攻撃の手がかり | ①高 ②低 ③情報 | ISOG-J、ASVS 5.0.0 13.4.6 |
| E-10 | HTML本文：パスワードフォーム | C2の本文 | `action`がhttps、`method="post"` | ①送信先（action）が`http://` ②パスワードをGETで送信 | 平文送信、URL経由の漏えい | ①高 ②中 | OWASP Authentication CS、ASVS 5.0.0 12.2.1, 14.2.1、IPA 2.3-1) |
| E-11 | ダウンロード応答 | ファイル配信URLをC1で採取。①のアップロードしたファイルは、アップロード先らしいディレクトリ（uploads・files・attachments・media・download）の下で、最後がファイル名（拡張子付き）のURLで判断する（`/media/press-releases/`のような普通のページと、サーバ側で動くページ（`.php`・`.aspx`・`.jsp`・`.cgi`など）やディレクトリの`index.html`は対象外。ビルドしたファイル（Create React Appの`/static/media/logo.6ce24c58.svg`、Next.jsの`/_next/static/…`）も対象外。名前のハッシュだけでは除かない（`/uploads/avatar.5f3a9c2e.svg`、日付の`minutes.20241231.html`を見逃すため））。判定するのは、そのURLがファイルを返した応答（転送のない2xx）だけ（404のエラーページや、ログイン画面への転送先は対象外） | `Content-Disposition: attachment`、`nosniff`、正しいContent-Type（`/download/`の下の`.html`は、配布物を案内する普通のページなので①にしない。ただし、uploads・files・attachmentsも含むもの（Redmineの`/attachments/download/42/evil.html`）は①。CMSの配布物の置き場にも使う`media`（`/media/download/press.html`）は①にしない。旧式のフォント（`application/vnd.ms-fontobject`）とHLS・DASHのプレイリスト（`application/vnd.apple.mpegurl`・`dash+xml`）は②の対象外。ビルドの置き場（`/static/media/`・`/_next/static/`）の下でも、uploads・attachmentsの下（`/static/media/uploads/evil.html`）は①） | ①ユーザーがアップロードしたファイルを同一オリジンでinline・`text/html`などスクリプトを実行しうる種類（XHTML、SVG、XML）として配信 ②Content-Dispositionがない（画像・音声・動画、`+json`・`+xml`のAPI応答、Content-TypeがJSONのAPIの応答（パスがアップロード先らしい`/api/files/123.json`でも。`kind=api`の明示では除かない）と、ビルドしたCSS・JS・フォント（Drupalの`/sites/default/files/css/…`、Next.jsの`/_next/static/media/…`）は対象外） | アップロードファイル経由のXSS | ①高 ②低 | OWASP File Upload CS、ASVS 5.0.0 3.2.1, 5.4.1 |
| E-12 | HTML本文：CSRFトークンの有無 | C2の本文（認証後ページ） | 状態を変える`<form method="post">`に隠しトークンがある（実効性の確認は第7章の範囲外） | ①POSTフォームにトークンらしき項目がなく、SameSiteもLax/Strictでない（同じホストで見えたセッションCookieがすべてLax/Strictなら合格。セッションCookieが見えなければ①とする。機密応答かどうか分からなければna） | CSRFの可能性の兆候 | ①情報 | OWASP CSRF Prevention CS、ASVS 5.0.0 3.5.1、IPA 6-(i)-a |
| E-13 | ソースマップの露出 | 本番JSの応答ヘッダ（SourceMap、X-SourceMap）と本文末尾の //# sourceMappingURL= を確認し、示された .map のパスをC13のパス一覧に追加して実行する | 本番では .map を配信しないか、認証の内側に置く | ① .map を取得できる（HTTP 2xxで、中身がソースマップの形。元のソースコード（sourcesContent）を含むかは手動で確認） ② .map への参照（ヘッダ・コメント）がある（本文に埋め込んだソースマップ（`data:application/json;base64,…`）は、.map を配信しているのと同じなので、証跡と推奨を分ける（.map の取得は勧めない。中身は証跡に出さない）。JSの本文を採取していないとき、本文が先頭64KBで切れているとき（参照は末尾にあることが多い）は、参照がなくてもna） | ソースコードや内部APIの露出 | ①中 ②低 | OWASP WSTG、ASVS 5.0.0 13.4.7 |

## 第6章 WebAPI特有（OWASP API Security Top 10 2023）

APIでは、未認証アクセス、トークンの露出、過剰なデータ露出がcurl出力で判定できる主な「高」の項目です。A-04、A-05、A-06は負荷をかけるため、検証環境で少ない回数に限って実施します。

| ID | 項目 | 確認方法 | 推奨値・期待状態 | NG判定基準 | リスク・影響 | 重要度 | 参考文献 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | 未認証アクセス | `curl -sS -i https://HOST/api/me`（Authorizationなし。`label=unauth-*`。③はHTTPの応答のWWW-Authenticate。`-L`で転送をたどった場合は、URLがhttpのホップだけを見る（httpsに転送した先のBasicは対象外）。複数のチャレンジのどれにBasicがあってもよい） | 401＋`WWW-Authenticate`（例：`Bearer realm="api"`）（同じページ（末尾の`/`）への転送はたどった先のステータスで見る。転送先を採取していなければna。A-08・A-11も同じ） | ①200で保護データが返る（HTMLの画面の200は、どのパスにも同じ画面を返すSPAの可能性があり、ログインのフォームがあってもゲスト用のログイン欄と利用者のデータを並べる画面があるので、データを返したかが分からずna。HTMLの画面とみなすのは本文がタグで始まるものだけ（先頭の1KBに`<!doctype html>`・`<html`があるもの（PHPのNoticeの行のあとに続くHTMLも）か、`text/html`でタグで始まるもの。JSON・CSV・平文の本文はHTMLの画面としない。本文を採取していない`text/html`はna。本文がJSON（`{`・`[`で始まる）なら、HTMLの文字列を含んでもHTMLの画面としない。A-11も同じ）。データのないJSON（`{}`・`[]`・値がすべてnull。NextAuthの未認証の`/api/auth/session`）と、エラーだけを返したJSON（`{"success":false,"error":"Unauthorized"}`のように、エラーの項目かsuccess:falseがあり、ほかは`message`・`code`などの決まった名前と空の`data`だけのもの）はna。GraphQLの200で、`errors`があり`data`がnull（値がすべてnull）のものは、認証・認可の拒否（`UNAUTHENTICATED`・`FORBIDDEN`など）なら合格、それ以外のエラーはna） ②302でログイン画面へ転送（APIとして不適切） ③HTTPでBasic認証を受け付ける（①②の合格は401・403・405だけ。404（URLの誤りの可能性）・5xx（認証の前に落ちた可能性）・400などはna）データのないJSON（値がすべて`null`・空のもの。`false`はログインの状態の名前だけ。`{"authenticated":false,"user":null}`）はna。 | なりすまし、情報漏えい | ①高 ②低 ③高 | API2（Broken Authentication）、ASVS 5.0.0 8.2.1, 12.2.1、IPA 11-(i) |
| A-02 | トークンの露出 | URLのクエリ、本文、`Location`ヘッダ | トークンはAuthorizationヘッダだけで扱う | ①URLにトークン（`?access_token=`など。状態を伝える短い語（小文字の英字を`-`・`_`でつないだ16文字以下。`?session=expired`、`?auth=required`）と真偽値（`true`・`1`など）は除く。大文字を含む英字だけの値、長い値、6桁以上の数字だけの値（ワンタイムの番号）はトークンとする（5桁までの数字（講演の番号の`?session=12`）は対象外）） ②Locationや本文に長期トークン・他者のトークン（トークンを発行するエンドポイント（パスが`/token`で終わるもの。`/oauth/token`、`/connect/token`）は対象外） | ログやRefererからの漏えい | ①高 ②中 | API2、API8、ASVS 5.0.0 14.2.1、IPA 4-(ii) |
| A-03 | JWTの中身 | headerとpayloadをツール内でBase64デコード | `alg`が`none`でない。`exp`が短い。PIIを含まない（curlの`-v`の送信ヘッダと、HARのリクエストのAuthorization・Cookieで送ったJWTも見る）（HARでは、同じJWTを送ったエントリが多いので、最初に送ったエントリでだけ判定する） | ①`alg: none` ②`exp`がない ③個人情報を含むOpenID ConnectのIDトークン（`id_token`の欄・Cookieで返したもの、または`iss`・`aud`と`nonce`・`at_hash`があり`typ`が`Bearer`でないもの）は、仕様上ユーザーの属性を運ぶものなので③にしない（`azp`・`auth_time`はアクセストークンにもあるので見ない）。 | トークン偽造、無期限の再利用、情報漏えい | ①高 ②中 ③中 | API2、ASVS 5.0.0 9.1.2, 9.2.1 |
| A-04 | レート制限 | 同じリクエストを少数回連続で送る（検証環境） | 429＋`Retry-After`。`RateLimit`/`RateLimit-Policy`（IETF draft）か`X-RateLimit-*` | ①ログイン・OTPなど認証系で制限の兆候がない ②その他のエンドポイントで兆候がない | 総当たり、リソース枯渇 | ①中 ②情報 | API4、ASVS 5.0.0 2.4.1 |
| A-05 | ページングの上限 | `?limit=100000` | 上限で切り詰めるか400 | ①指定件数がそのまま返る | リソース枯渇、大量取得 | ①中 | API4、ASVS 5.0.0 15.2.2 |
| A-06 | リクエストサイズの上限 | 大きな本文を送る（検証環境） | 413 | ①上限なしで処理される | リソース枯渇 | ①低 | API4、ASVS 5.0.0 15.2.2 |
| A-07 | 過剰なデータ露出 | JSONのキーを確認 | 必要な項目だけ（証跡に出すキーの名前は、値をキーにしたもの（`sk-proj-…`、`glpat-…`、`-`・`_`で区切ったかけらが英大文字・小文字・数字を含む16文字以上のものなど）を`*`にする） | ①`password`、`passwordHash`、`secret`などのキーに、秘密情報らしい値（空白や日本語を含まない文字列。英語の画面の文言（`"password":"Password"`のように、キーと同じ語か、先頭だけ大文字の語をつないだもの）と、公開を前提にした値（Stripeの`client_secret`（`pi_…_secret_…`）と公開キー`pk_live_…`、Firebaseの設定のGoogle APIキー`AIza…`）、伏せ字の値（`********`・`***`・`[REDACTED]`・`[FILTERED]`・`<hidden>`）と、状態を表す決まった語（`set`・`configured`・`enabled`・`true`など。英小文字の語をすべて除くと英小文字だけのパスワードを見逃すので一覧で見る）は除く）がある。`salt`は②（内部属性） ②`isAdmin`、`internal_*`、`__`で始まるものなどの内部属性（GraphQLの`__typename`とMongooseの`__v`はライブラリが必ず付けるので対象外。判定は元のキーで行う。①②とも、証跡のキーの経路では、データの値をキーにしたもの（`{"users":{"alice@example.com":{…}}}`のメールアドレス、`sk_live_…`、AWSのアクセスキー、数字だけのIDや、数字を含む区切りのない16文字以上のID）を`*`にする） | 秘密情報の漏えい、攻撃の手がかり | ①高 ②中 | API3（BOPLA）、ASVS 5.0.0 8.2.3, 14.2.6 |
| A-08 | リクエストのContent-Type | `curl -sS -i -X POST -H 'Content-Type: text/plain' --data '{"a":1}' https://HOST/api/x`（`label=ctype`、検証環境） | 415（401・403・404は、Content-Typeを確かめる前に断られたのでna） | ①200で処理される | CSRFの単純リクエストを許す | ①中 | API8、ASVS 5.0.0 3.5.2 |
| A-09 | JSON応答のヘッダ | 応答ヘッダ | `application/json`、`nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` | ①`text/html`で返す ②nosniffがない ③CSPがない | ブラウザで開かれた場合のXSS | ①中 ②中 ③情報 | OWASP REST Security CS、API8、ASVS 5.0.0 4.1.1, 3.4.4, 3.4.3 |
| A-10 | エラー形式 | 400、404、500を発生させる（C25、`label=error-*`。HTMLのエラーページと`error-*`以外の応答、付け直したラベル（`error-api#2`）は比べない） | 統一形式（例：`application/problem+json`） | ①形式が統一されていない（内部情報の露出はE-01で判定） | クライアントの誤動作 | ①情報 | API8、RFC 9457、ASVS 5.0.0 16.5.1 |
| A-11 | メソッド制御・旧版 | `-X DELETE`や`-X PATCH`（`label=method-*`。データを消しうるため手動で、検証環境で行い、コマンド生成器では作らない）、`/api/v1/`、`/beta/`、`/internal/`（`label=old-*`） | 405＋`Allow`。廃止版は410か404（合格にするのは、メソッドが405・501、旧版が404・410のときだけ。401・403（認証の内側で動くかは分からない）・3xx（ログイン画面への転送など）・そのほかの4xx・5xxはna。A-08の401・403・404と同じ考え方） | ①想定外のメソッドが通る ②古い版が動いたまま（①②とも、HTMLの画面の200（SPAの`index.html`・ログイン画面）は、APIが処理したかが分からないのでna） | 権限外の操作、修正漏れの旧版経由の攻撃 | ①中 ②中 | API5（兆候）、API9、ASVS 5.0.0 4.1.4 |

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
- 「実施日時」と「実施コマンド」は、各ターゲットに`#META at=2026-10-13T10:00 cmd=C1`のように付けるとツールが転記します。付けない場合は空欄で出力します。コマンド生成器のID（`C1`など）以外の手で書いたコマンドは、プログラム・オプション・ヘッダの名前とURLの形だけを残し、値は`****`にして出します（秘密を出さないため。ツール設計3「マスキングの対象」）。
- `#META at`（HARは`startedDateTime`）は、期限の判定（証明書のnotAfter、CookieのExpires、security.txtのExpires）の基準にも使います。前に採取した出力を読み直しても、採取時の状態で判定するためです。ない場合は応答の`Date`ヘッダ（サーバが応答した時刻）を、それもなければ判定した時刻を使います。判定した時刻より5分以上先の`Date`は使いません（`Date`は診断対象のサーバが書くので、未来の時刻にしてCookieの期限を短く見せ、C-05①を合格にできたため）。例外の期限（until）は手元の日付で比べます。
- 再診断では同じコマンドを実行し、前回の結果と比べます（ツールの差分表示はv0.4）。

## ツール設計1：入力モデル・推奨コマンド・パース

ツールは対象にアクセスせず、`#TARGET`マーカーで区切られた複数コマンドの出力を、ターゲットごとに解析・評価します。

### 入力モデル

- **ターゲット**：`#TARGET url=https://HOST/PATH label=top kind=auto sensitive=1`の行から次の`#TARGET`行までを1ターゲットとする。`kind`は`html`、`api`、`auto`。`sensitive`は`1`か`0`で省略可（第0章 0.3）。`#TARGET`がない入力は「default」ターゲットを1つだけ持つ。
- **ラベルと適用範囲**：ラベルはターゲットの目的を表す（第0章 0.3）。ツールは下の対応表でターゲットごとに適用する項目を絞ってからルールを実行する。絞らないと、CORS確認やTRACEの応答にもCSPなどのヘッダ系ルールが当たり、指摘が重複したり的外れになったりする。予約・確認用ラベルが足りないとき、それを前提とする項目はnaになる。
- **評価の単位**：ヘッダ系ルールはターゲットごとの最終応答（1xx、CONNECT応答を除いた最後の応答。`-L`で別のサイトへ転送したときは、ターゲットのURLと同じサイト（登録ドメインの近似：最後の2つのラベル。`co.jp`のような2段の国別ドメインは3つ。apexから`www`への転送はたどる）の最後の応答（httpsのターゲットはhttpsのホップ）。転送先のIdPやほかのサイトの応答を対象の応答として判定しない）に、リダイレクト系ルールはチェーン全体に適用する。ホスト単位のルール（T-09〜T-11、E-03）は、ラベルに関係なく、URLから導いたホストごとに全ターゲットのデータを集約して1回だけ評価する。Locationのある3xxの本文は、ブラウザが表示しないのでHTMLの項目（ヘッダ・描画）を判定しない（nginxの301の本文でH-03①（高）などを出していた）。本文の秘密（E-09）は利用者に届くので判定する。Cookieの項目（C-01〜C-07・C-11・C-12②）とH-15は、ターゲットのURLと同じサイトの応答（URLの分からない応答を含む）だけを見る（`-L`で転送したIdPのCookieの属性を対象の指摘にし、IdPのCookieを消しただけのログアウトを合格にしていた）。
- **URLとHTTPS判定**：URLは「`#TARGET url=`→`#META url_effective=`→`-v`の`* Connected to ... port`行→画面のURL入力欄」の順で決める。どれもなければHTTPSかどうかは「不明」とし、HSTSなどのルールはnaにしてURLの入力を促す。C5（`http://`開始）は`#TARGET url=`と食い違わないよう、`label=http`の別ターゲットで実行する。
- **API判定（MVPから）**：`kind`の指定を優先し、`auto`なら最終応答のContent-Typeで判定する（第0章 0.3）。
- **マーカー**：`#TARGET`、`#META`、`#PROBE`、`#TLSPROBE`、v0.2で追加する#CIPHERPROBE、第40回で追加した`#BODY`の6種類だけをマーカーとして扱い、それ以外の`#`で始まる行（robots.txtや.envのコメントなど）は普通の本文として扱う。マーカー行は必ず直前の応答を閉じる。
- **採取の印（`run=`）**：コマンド生成器のスクリプト（と`run.sh`）は、実行ごとの乱数（16桁の16進数）を`run=`として全部のマーカー行に付ける。入力の最初の`#TARGET`の行（ほかの行ではない。本文の`#TARGET … run=…`で印を有効にさせない）に印があれば、同じ印のマーカー行だけをマーカーとし、印のないものや違う印のものは本文として読む。診断対象のサーバは印を知らないので、応答の本文に書いた`#TARGET label=login`・`#META at=`・`#PROBE`で、ターゲットを作ったり分けたりして判定を変えられない。印のない手書きの入力は、これまでどおり読む。印の違う`#TARGET`を本文として読んだときは、警告する（別の採取の出力を付け足したものは、別に判定する。`#BODY`のあとの本文の中のものも）。プロキシの応答（407・CONNECT）しかないターゲットも警告する。
- **本文の印（`#BODY`）**：コマンド生成器のスクリプトは、本文を取るコマンドを`-i`ではなく`-D "$hdr" -o "$body"`で採取し、ヘッダ、`#BODY run=…`の行、本文の順に出す（取る前に2つのファイルを空にし、curl が失敗したときに前のコマンドのヘッダ・本文を出さない）。`#BODY`のあとは、次のマーカーまで（本文は64KBで打ち切る）を、直前の応答（`-L`では最後のホップ）の本文としてそのまま読み、ステータス行・ヘッダ・openssl の出力・`-v`の行として読まない。`-i`の出力では本文と次の応答を見分けられず、本文を「HTTP/1.1 200 OK」と偽のヘッダで始めると、本物の応答を置き換えられたため。`#BODY`の前に読める応答がない（curl が失敗した、curl は受け付けるがこのツールは読まない小文字の`http/1.1`のステータス行など）ときは、本文を捨て、解析できない行として警告する（ふつうに読むと、本文の偽のステータス行が応答になる）。印のない手書きの入力では、どの`#BODY`の行もマーカーとして読む。手書きの`curl -i`の採取（`#BODY`のないもの）は、これまでどおり読み、本文の先頭のステータス行で偽装できる。
- **ラベルの形**：英数字・日本語などの文字と`_`・`.`・`*`・`-`・空白（前後を除く）の64文字まで。それ以外（引用符・波かっこを含むもの）は`invalid-label`にする（ラベルは画面・エクスポート・例外ファイルにそのまま出るため）。
- **同じラベル**：同じラベルのターゲットが複数あれば（貼り付けとHARの両方に`login`を付けた場合を含む）、2つ目以降を`top#2`のように付け直して別に判定し、解析警告（duplicate-label）を出す。適用する項目は元のラベル（`#2`を除いたもの）と同じにする（`label=http`をwwwとapexの2つで採取した場合も、2つ目でT-04・C-10を判定する）。横断の判定には最初のものだけを使う（`session-sample-*`・`csp-sample-*`のように接頭辞で集める横断ルールも、付け直したもの（`#2`）は比べない）。
- **`-v`のプレフィックス**：本文の読み取り中は` *  `、` >  `、` <  `で始まる行も本文として扱う。`-v`として解釈するのは、ターゲット内で`* Connected to`などの行を検出した場合（verboseモード）だけで、`-v`の出力では本文を解析しない。

### ラベルと適用する項目

ラベルは前方一致で判定し（`cors-*`など）、どれにも当てはまらなければ一般ターゲットとして扱います。診断カバレッジで案内する「必要なラベル」は、この対応表から実行時に作り（`engine/labels.ts`の`requiredLabels`）、横断ルールが必要とするラベル（C-07②、C-09①、C-12①、H-02③、H-04⑤、A-10）を足します。`csp-sample-*`はH-04⑤のためだけに案内します。ルールの中でラベルを確かめる場合も、この対応表と同じ範囲にそろえます。この一覧はengine/labels.json（ラベルの接頭辞と項目IDの配列）としてルールセットと同じ版で管理し、ツールとコマンド生成器で共有します。項目IDの後ろに条件を付けて絞ることもできます（例：T-05.2、E-04.1）。条件を付けた指定は、ルールを実行した後の結果（Finding）に適用します。手動確認項目のうち、T-03、T-07①③、T-13、A-04〜A-06は、対応するラベルのターゲットで取り込んだ応答（ステータスコードなど）を「手動確認」として表示するだけで、合否は判定しません。T-02、C-14、C-15はツールでは扱わず、第8章の様式に直接記録します。opensslの出力をまとめるtlsラベルのターゲットには、ホスト単位のルール（T-09〜T-11）だけを適用します。

| ラベル | 目的 | 適用する項目 |
| --- | --- | --- |
| 一般（下記以外。ラベルなしを含む） | 通常のページ・API | 第1章（H-15とH-02③を除く）、C-01〜C-06・C-08・C-11・C-13、R-04・R-06〜R-08、T-05②・T-12、E-01・E-02・E-04（②は、URLが`security.txt`のとき。2xxでない応答と、HTMLの画面（どのパスにもindex.htmlを返すSPA）は「security.txtがない」とする。`robots.txt`の2xxでない応答は「robots.txtなし」として合格）・E-05〜E-12・E-13②、第6章（A-01は③だけ。A-01①②は`unauth-*`、A-08は`ctype`、A-11は`method-*`・`old-*`、A-10は横断ルールで判定する。A-04〜A-06は手動確認） |
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
| C2 | ヘッダと本文 | `curl -sS -i "$T"` | ヘッダ、空行、本文。curl 8.10.0以降の正式名は`--show-headers`。コマンド生成器は、`-i`のコマンドを`-D "$hdr" -o "$body"`に置き換え、ヘッダ、`#BODY run=…`の行、本文、改行の順に出す（本文の印。最後の改行は、本文が改行で終わらないと、次の`#TARGET`の行が本文の続きになり、ターゲットが合わさるため） |
| C3 | HEAD（補助） | `curl -sS -I "$T"` | GETと結果が違うサーバがある |
| C4 | 詳細（推奨） | `curl -sS -v -o /dev/null "$T" 2>&1` | `>`送信、`<`受信、`*`情報。合意したTLSバージョンと暗号が分かる（T-09②、T-10③の一部） |
| C5 | リダイレクト追跡 | `curl -sS -L -D - -o /dev/null -w '\n#META response_code=%{response_code} num_redirects=%{num_redirects} url_effective=%{url_effective} http_version=%{http_version}\n' "http://HOST/"` | 複数のヘッダブロック＋`#META`行。`label=http`のターゲットで実行 |
| C6 | CORS反射 | `curl -sS -v -o /dev/null -H 'Origin: https://evil.example' "$T" 2>&1` | `> Origin:`で送信値を照合 |
| C7 | CORS null | C6のOriginを`null`にしたもの | 同上 |
| C8 | CORSプリフライト | 第3章のコマンド例 | Allow-Methods、Allow-Headers、Max-Age |
| C9 | メソッド | `curl -sS -i -X OPTIONS "$T"`、`curl -sS -i -X TRACE "$T"` | `Allow`ヘッダ、TRACEの反射 |
| C10 | ヘッダJSON（v0.2） | `curl -sS -o /dev/null -w '%{header_json}' "$T"` | ヘッダ名が小文字のJSON（curl 7.83以降）。パーサの対応はv0.2。ヘッダの形（名前がヘッダに使える文字、値が文字列の配列、`date`・`content-type`などよくあるヘッダを含む）でないJSON（`curl -s`で出力したAPIの本文など）は応答にせず、解析警告にする。ステータスは`#META response_code`から取り、JSONのあとに出したものも使う。ステータスが分からない応答では、ステータスで判定する項目（C-12①、A-01①②）をnaにする |
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
# サーバはハンドシェイクのあとに任意のデータを送れ、s_client はそれを標準出力に出す。データは最初の Verify return code: の行より後にしか
# 出ないので、そこで切る（切らないと、サーバが notAfter=・DNS:・a:PKEY: を書いて T-10・T-11 を変えられる）。x509 の出力は最初の証明書から作る
echo "#TARGET url=https://HOST/ label=tls"
openssl s_client -connect HOST:443 -servername HOST -showcerts </dev/null 2>&1 | sed '/^ *Verify return code:/q'
openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# C12: プロトコルごとの接続可否（OpenSSL 3系は SECLEVEL=0 が必要）
#   ok=1   : ハンドシェイク成功（終了コードが0で、要約の中に「New, <版>, Cipher is <暗号>」の行がある。版は問わない）
#   ok=0   : サーバが拒否（unsupported protocol を含む）
#   ok=err : 手元のOpenSSLがそのプロトコルに非対応（標準エラーの unknown option・no protocols available だけで見る）→ ツールでは na
tout=$(mktemp); terr=$(mktemp)
for v in tls1 tls1_1 tls1_2 tls1_3; do
  openssl s_client -connect HOST:443 -servername HOST -$v -cipher 'DEFAULT@SECLEVEL=0' </dev/null >"$tout" 2>"$terr"; rc=$?
  if grep -qiE 'unknown option|no protocols available' "$terr"; then r=err
  elif [ $rc -eq 0 ] && sed '/^ *Verify return code:/q' "$tout" | grep -qE '^New, [^(,][^,]*, Cipher is [^(]'; then r=1
  else r=0; fi
  printf '#TLSPROBE v=%s ok=%s\n' "$v" "$r"
done
```

```sh
# C23: 弱い暗号・鍵交換を個別に試す（T-10①③、v0.2）。TLS 1.2で確認する（C12 の tout・terr を使う）
#   ok=1   : その暗号で接続できた（サーバが受け入れる）
#   ok=0   : サーバが拒否
#   ok=err : 手元のOpenSSLがその暗号に非対応（OpenSSL 1.1以降の RC4・3DES）→ ツールでは「試していない」と書く
# RC4-SHA・DES-CBC3-SHA・NULL-SHA256 は T-10①、AES128-SHA（静的RSA＋CBC）・ECDHE-RSA-AES128-SHA（CBC）は T-10③
echo "#TARGET url=https://HOST/ label=tls"
for c in RC4-SHA DES-CBC3-SHA NULL-SHA256 AES128-SHA ECDHE-RSA-AES128-SHA; do
  openssl s_client -connect HOST:443 -servername HOST -tls1_2 -cipher "$c:@SECLEVEL=0" </dev/null >"$tout" 2>"$terr"; rc=$?
  if grep -qiE 'no cipher match|unknown option' "$terr"; then r=err
  elif [ $rc -eq 0 ] && sed '/^ *Verify return code:/q' "$tout" | grep -qE "^New, [^(,][^,]*, Cipher is $c\$"; then r=1
  else r=0; fi
  printf '#CIPHERPROBE c=%s ok=%s\n' "$c" "$r"
done
rm -f "$tout" "$terr"
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
| 改行 | HTTP/1.1のヘッダはCRLF。貼り付けでは混在する。Windowsのcurlの`-v`（`2>&1`）は受信ヘッダの行をCR CR LFで終える | 最初に、続くCRとLF（CR CR LFを含む）と単独のCRをLFに統一する（CR CR LFを2つの改行と読むと、受信ヘッダがすべて失われる）。CRの並びの先頭でだけLFを探す（LFの付かない長いCRの並びで、入力の長さの2乗の時間にしない）。ただし画面の入力欄（textarea）は、値を受け取った時点でCR CR LFを改行2つに変えるので（貼り付けもファイルの読み込みも入力欄を通る）、`-v`の受信ヘッダ（`< `の行）の途中の空行は無視し、`<`の行だけを終端とする。E2E（`e2e/app.spec.ts`）で入力欄を通して確かめる |
| マーカーの判定 | 本文にも`#`で始まる行（robots.txt、.env、設定ファイルのコメント）がある | `#TARGET`、`#META`、`#PROBE`、`#TLSPROBE`、#CIPHERPROBE、`#BODY`（単語境界付き）だけをマーカーとする |
| `-v`のプレフィックス | ` >  `送信、` <  `受信、` *  `情報、`{ [n bytes data]`本文。本文にも` *  `や` >  `で始まる行（箇条書きや引用）がある | verboseモードのターゲットで、かつ本文の読み取り中でないときだけ解釈する。verboseモードかは、curlの情報行（`* Connected to`・`* Trying`・`* SSL connection`など。プロキシを使うと最初の行になる`* Uses proxy env variable`も）で見分ける。` >  `行には送信したCookieやAuthorizationも含まれるためマスキング対象にする |
| `-v`のヘッダ終端 | 終端は` <  `だが、貼り付けで末尾の空白が落ちて`<`だけになることがある | `^<\s*$`を終端として扱い、その応答を閉じる（-vの出力では本文を解析せず、本文はC2で取る）。`-o /dev/null`がなく本文も出力した場合は、次の`< HTTP/`の行（`-L`の次の応答）までを読み飛ばす。本文の中の`HTTP/1.1 200 OK`や、`* `・`> `で始まる行を、応答・情報行・送信ヘッダとして読まないため |
| ブロック境界 | ステータス行`HTTP/(1.0・1.1・2・3) コード`。HTTP/2と3はreason phraseなし | ステータス行から空行までを1応答とする |
| 応答の閉じ忘れ | 本文の後に別コマンドの出力が続くと、本文に混入する | マーカー行とopensslの開始行（`CONNECTED(`、`depth=`、`subject=`、`notAfter=`など。OpenSSL 3.5が`CONNECTED(`の前に出す`Connecting to <アドレス>`も。次の行が`CONNECTED(`のときだけ）で応答を閉じる（`CONNECTED(`の行と、`Connecting to`の次の行が`CONNECTED(`のものは、応答の本文の中でも閉じる。同じターゲットでHTTPの応答に続けたopensslの出力を本文に入れないため。ただし生成スクリプトの出力（印のある入力）では、本文の中で閉じるのは`tls`のラベルだけ。診断対象のサーバが本文に`CONNECTED(n)`を書くと、そのあとの本文がopensslの出力になり、E-07〜E-09・E-12が消えたため）。本文は64KBで打ち切る。`#TARGET`・`#META`の値は引用符で囲んでもよい（`url="https://…"`）。`url=`がスキームのあるURLとして読めないときは警告する |
| `#PROBE`の属性 | Content-Typeは`text/html; charset=utf-8`のように空白を含む | `ct=`は行末に置き、`ct=`以降を行末まで値とする。`=`を含まない語は無視する |
| `-L`の複数応答 | すべてのホップのヘッダが順に出る | `responses[]`で保持し、`kind`（final・redirect・informational・connect）を付与。各ホップには、ターゲットのURLから`Location`をたどったURLを持たせる（HARと同じ）。`url=`がhttpで、`-L`で同じホストのhttpsに転送されたターゲットは、`http`ラベル以外ならHTTPSの応答として判定する（URLがhttpのままだと、H-・C-の項目がすべて黙って適用外になる）。httpのホップで発行したCookieも判定する |
| 1xx・CONNECT・認証のやり直し | 100 Continue、103 Early Hints、プロキシの`200 Connection established`、プロキシの認証要求`407`（`-x … -U`）、curlが認証し直す`401`（`--digest`・`--ntlm`・`--negotiate`・`--anyauth`） | 評価対象から除外。理由句が違うプロキシもあるため、本文のない2xxのあとに応答が続く場合もCONNECTの応答とみなす（`-i`の出力では、本文と次の応答を見分けられないので、本文が「HTTP/1.1 200 OK」と偽のヘッダで始まると、次の応答として読む。ヘッダの形でプロキシを見分ける作りは、ヘッダを足す本物のプロキシを壊すので採らない。生成スクリプトは、ヘッダと本文を分けて採取する）。`-v`では、1xxと、`> CONNECT`への2xxの応答のあとを本文として読み飛ばさない（そのあとに本当のリクエストの`* SSL connection`・`> Origin`・`> Cookie`が続く）。407と、あとに応答が続く401も、その URL 自身の応答ではないので評価対象から除く（407を最初の応答にすると、T-04が「HTTPを拒否」と合格にし、A-01①を見逃す） |
| `-v`の本文の中の`< HTTP/` | `-v`で本文も出力すると、本文に`< HTTP/1.1 200 OK`のような行（curlの出力を載せたページ）がありうる | 次の応答とみなすのは、前の応答のあとに次の応答が続きうる（転送・1xx・401・407）ときだけ。`#TARGET`ごとにCONNECTの状態を初期化する |
| 本文にくっついたマーカー | 改行のない本文（手で書いた`curl -i`のJSON）の直後に`#TARGET`が続く（`{"id":1}#TARGET url=…`） | JSON・HTMLの閉じ（`}`・`]`・`>`）の直後の`#TARGET url=`などで行を分ける（分けないと、次のターゲットが前の本文に吸い込まれて黙って消える）。`#TARGET url=`・`label=`は、空白・引用符以外のどの文字の直後でも分ける（`Unauthorized`のような平文の本文のあと。本文の文中の`… #TARGET url=`と、`set -x`の`+ echo '#TARGET …'`は分けない）。生成スクリプトも`#TARGET`の前に改行を出す |
| 進捗表示 | `-s`を付けずに`2>&1`にすると、curlの進捗表示が出る。遅い応答では、進捗表示とステータス行が同じ行になる | 見出しの行と数字の行（数字の欄と時刻の欄`--:--:--`）を読み飛ばし、応答の行の前にくっついた部分を取り除く。時刻の欄は curl の版で違う（`--:--:--`、`0:00:02`、curl 8.22 の`00:02`や空欄）。数字の欄の並び（%の欄は0〜100）で見分け、進捗表示だけの行は時刻の欄が1つ以上あるものだけを読み飛ばす（本文の数字の行を消さない）。時刻の欄が空欄の行（数字の欄のあいだに10個以上の空白）は、応答の本文の外のときだけ読み飛ばす（本文の桁をそろえた数値の表を消さない） |
| 大文字・小文字 | HTTP/2と3ではヘッダ名を小文字で送ることが求められる | 名前は小文字に正規化し、表示用に元の表記も残す |
| 重複ヘッダ | Set-Cookieは複数行。1行にカンマでつないだものは、`, 名前=`の前で1件ずつに分ける（Expiresの日付のカンマと、属性（`;`）のない値の中のカンマ（`prefs=lang=ja,tz=JST`）では分けない）。CSPが複数あればすべて適用される（あるポリシーにないディレクティブは、別のポリシーが指定し、そのポリシーに同じ指摘がなければH-04②・H-05①にしない。同じ緩いポリシーが2つあっても指摘する） | 名前ごとに配列で保持。Set-Cookieはカンマで結合しない |
| 折り返し（obs-fold） | 行頭が空白かタブの継続行（RFC 9112で非推奨） | 前の行に連結し、情報として報告 |
| opensslの出力 | OpenSSL 1.1系と3系で形式が違う | 複数の正規表現を順に試す |

### HAR形式の取り込み（v0.3）

ブラウザの開発者ツールで書き出したHAR（HTTP Archive）ファイルを、curlの出力と同じターゲットの集まりに変換して評価します。ログイン前後・API・ログアウトの一連の通信をブラウザの操作だけで採取でき、横断ルール（C-09、C-12など）を手早く適用できます。

- **判別と結合**：HARはファイル読込で受け、JSONとして解釈できて`log.entries`を持てばHARとして扱う。テキストエリアの入力はこれまでどおり`#TARGET`形式で解析し、両方から作ったターゲットを結合して評価する。
- **変換**：`log.entries`の1件を1ターゲットにする。URLは`request.url`、応答は`response.status`、`response.httpVersion`、`response.headers`（nameとvalueの配列）から作る。HTTPバージョンは、ブラウザごとの表記（h2、HTTP/2.0など）を1.1・2・3に正規化する。名前が`:`で始まるHTTP/2の疑似ヘッダ（`:status`など）は除外する。1つのヘッダに複数の`Set-Cookie`を改行でつないで書き出すものがあるため、`Set-Cookie`は改行で1件ずつに分ける（分けないと2つ目以降のCookieを判定せず、証跡に生の値が出る）。本文は`response.content.text`のうちHTMLとJSONだけを先頭64KBまで残す（`encoding: base64`ならデコード）。リクエスト側は、全ホップのリクエストからAuthorizationの有無とCookieの名前（値は持たない）だけを取り出す。ブラウザは解析用・同意用のCookieも送るので、機密応答の推定（`sentAuth`、第0章 0.3）には、Authorizationか、セッションCookieらしい名前（組織プロファイルの指定があればそれ）のCookieを送ったときだけを数える。Secure の Cookie は https のホップでしか送られないため、最初の http のリクエストだけでは分からない。
- **由来の記録**：HAR由来のターゲットには`meta.source = 'har'`と`meta.cmd = 'HAR'`を設定する。診断カバレッジの理由（HARに機密情報が含まれないなど）と、第8章の「実施コマンド」列に使う。除外したエントリの数（har-excluded）と、機密情報が除かれたHARの検出（har-sanitized）は、解析警告としても表示する。
- **リダイレクト**：HARではリダイレクトの各ホップが別のエントリになる。ブラウザが内部で作った転送（HSTS・HTTPS-Upgradesの`307 Internal Redirect`）は、サーバの応答ではないので取り込まず、件数を警告する。内部の転送とするのは、307で、ネットワークに出ていない（`serverIPAddress`がない）うえに、理由句が`Internal Redirect`か`Non-Authoritative-Reason`ヘッダがあるものだけ（理由句とヘッダはサーバも返せるので、それだけで除くと、診断対象のサーバがログインのPOSTやhttpからhttpsへの転送を判定から外せた）。`response.redirectURL`と次のエントリのURLでつなぎ、1つのターゲットの応答チェーンに組み直す。ブラウザはフラグメントを除いたURLでリクエストを記録するので、`Location`のフラグメント（`/app/#/home`）は除いて比べる。つなぐのは同じホスト名への転送だけで、別のホスト（IdP、apexからwwwなど）への転送先はつながない（つなぐと、対象外のホストの応答を、選んだホストのURLの結果として判定してしまう）。httpからhttpsに転送されたチェーンは、最後のhttpsのURLをターゲットのURLにする（HTTPSの応答が対象のH-01やCookieの項目を判定するため）。httpのホップは応答に残し、そこで発行したCookieも判定する。各応答にはそのホップのURLを持たせ、apexの「自身の応答」や、E-05・E-11・A-01の「そのURLの応答」には、最初のhttpsのホップを使う（`parser/target.ts`の`ownChain`）。`http`ラベルを付けたチェーンだけは、T-04のために転送元のhttpのURLのままにする。
- **304**：ブラウザがキャッシュを再検証した304の応答は、サーバがセキュリティヘッダを付け直さなくてよい（RFC 9110 15.4.5）ので、既定で除外し、件数を解析警告に出す（通常の応答として判定するとH-01①（高）などの誤検知になる）。開発者ツールで「キャッシュを無効にする」を選んで記録し直すよう案内する。一覧でラベルを選べば判定する。
- **対象ホストの選択**：解析の前に対象ホストを選ばせ、それ以外（解析タグ、CDN、外部APIなど）のエントリは既定で除外する。
- **ラベルの付与**：HARにはラベルがないため、取り込んだ後にエントリ一覧で付ける。一覧はリダイレクトを組み直した後のチェーン単位で表示し、ラベルはチェーン（1つのターゲット）に付ける。ツールは候補を示し、診断者が確定する。候補の例：パスワード入力欄のあるページのGET→`pre-login`、新しいセッションCookieを発行したPOSTか、パスが`login`・`signin`のPOST→`login`（セッションIDを再発行しない（C-09①の）ログインは新しいCookieを発行しないので、パスでも見る）、パスにlogoutを含む→`logout`。`sensitive`は送信側のCookie・Authorizationの有無で自動で決め、一覧で上書きできる。次の制約を設ける。
  - 予約ラベルは1つのエントリにだけ付けられる（横断ルールが比べる対象を一意にするため）。
  - `cors-*`ラベルは付けられない（ブラウザが送る正規のOriginを、R-01が「反射」と誤判定するため）。ほかにも、細工したリクエストを前提とするラベル（websocket、options、trace、method-override、open-redirect、host-inj、crlf、xff-spoof、probes、tls）は付けられない。テスト値を送っていないのに、ルールが「確認して問題なし」（.ok）を返してしまうため。HARで付けられるのは、一般、error-\*、http、apex、pre-login、login、logout、csp-sample-\* だけで、この許可リストはlabels.jsonに「HARで使えるか」の属性として持たせる。同じ理由で`sentOrigin`も設定しない。
  - `after-logout`（旧Cookieでのアクセス）と`session-sample-*`はブラウザの通常の操作では生じないため、curl（C18）で採取する。
- **HARでは判定できない項目**：TLS（T-09〜T-11）、既知ファイル（E-03）、偽装OriginによるCORS確認（R-01〜R-03）、メソッド確認（T-01）、ヘッダインジェクション（T-07、T-08）など、細工したリクエストが必要な項目はHARには含まれない。これらは診断カバレッジで「入力不足」として示し、推奨コマンドで別に採取するよう案内する。
- **秘密情報の扱い**：HARには、ログイン時のパスワード（`request.postData`）、すべてのCookie、トークン、応答本文が入る。読み込みはWeb Worker内で行い、`request.postData`と不要な本文は読み込んだ直後に破棄し、残す値にもマスキングを適用する。JSONとして読めないときも、エラーの文言（誤りの前後の入力を含む）は画面に出さず、種類だけを示す。HARファイルは使用後に削除するよう画面で案内する（第0章 0.5と同じ扱い）。テスト用アカウントで採取する。
- **ブラウザによる違い**：ブラウザによっては、既定の書き出しでCookieやSet-Cookieなどの機密情報を除く（要確認事項）。CookieやSet-CookieがないHARでは、第2章の項目を「入力不足」とし、機密情報を含める書き出し方を画面で案内する。
- **サイズ**：HARは数十MBになることがあるため上限を50MBとし、必要な項目を取り出したら元のJSONは破棄する。

## ツール設計2：ルールエンジン・スコアリング・例外登録

ルールはチェックリストの項目IDと条件番号をそのまま使い、結果は重要度別の件数で示します。意図した設定は例外登録で抑制できます。
- 壊れたエントリ（応答の`headers`が配列でない、`content.text`が文字列でない）は、そのヘッダ・本文を空として読み、取り込み全体を止めない。

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
  - **振り分け**：csp_evaluatorの指摘を、チェックリストの条件に振り分ける（`rules/csp.ts`）。`SCRIPT_UNSAFE_INLINE`→H-04①、script系の`PLAIN_URL_SCHEMES`・`PLAIN_WILDCARD`・`SRC_HTTP`・`WILDCARD_URL`とscript-srcの`MISSING_DIRECTIVES`→H-04②、`SCRIPT_UNSAFE_EVAL`→H-04③、`SCRIPT_ALLOWLIST_BYPASS`（JSONP・AngularJSを置くホスト）→H-04④、`NONCE_LENGTH`・`IP_SOURCE`・`SCRIPT_UNSAFE_HASHES`・`SRC_NO_PROTOCOL`→H-04⑥、object-srcの問題と`OBJECT_ALLOWLIST_BYPASS`→H-05①（default-srcの指摘は、フォールバック先に振り分ける。script-srcがなければH-04、object-srcがなければH-05①。両方なければ両方）、csp_evaluatorが例外を出す値（`img-src data:image/svg+xml`など）→H-07④（そのポリシーがあればH-04は合格にせずna）、`DEPRECATED_DIRECTIVE`→H-07①、構文の検査（`MISSING_SEMICOLON`・`UNKNOWN_DIRECTIVE`・`INVALID_KEYWORD`・`NONCE_CHARSET`）→H-07④（csp_evaluatorが知らない仕様のディレクティブ（`fenced-frame-src`・`webrtc`・`trusted-types`など）は未知のディレクティブにしない）。
  - **使わない指摘**：「〜かもしれない」（`HIGH_MAYBE`・`MEDIUM_MAYBE`。`'self'`や未知のホストへの注意など）、Strict CSPの推奨、後方互換・Trusted Typesの指摘は、誤検知が多いため使わない。ただし`'unsafe-eval'`はcsp_evaluatorでは`MEDIUM_MAYBE`だが、H-04③（中）として扱う。
  - **自前で残す判定**：H-05②（base-uriがない。csp_evaluatorはnonceやhashを使う場合だけ指摘するが、チェックリストでは常に確認する）、H-07②③、H-06、H-03、H-04⑤（横断ルール）。
  - **ポリシーの区切り**：1つのヘッダ値の中のカンマはポリシーの区切り（CSP3の serialized-policy-list。プロキシが2つのヘッダを`a, b`にまとめた場合も同じ）。ヘッダ値をカンマで分けてから、ポリシーごとに評価する（`rules/util.ts`の`cspPolicies`。H-03〜H-07とH-04⑤で同じ）。分けないと、`…; base-uri 'none', frame-ancestors 'none'`の`frame-ancestors`を`base-uri`の値として読み、H-06①とH-07④を誤検知する。
- **Set-Cookie**：最初の`;`より前を`name=value`、残りを属性（名前は大文字小文字を区別しない）とする。値の長さ・文字種・推定エントロピーの上限を出し（C-07）、プレフィックスの条件を検証する（C-06）。

### ターゲット横断ルールと評価の順序

- **対象のサイトの応答だけを見る**：C-07②・C-09①のセッションCookieは、`-L`でたどった応答のうち対象のサイトのもの（C-01〜C-06と同じ）だけから取る。外部のIdPが発行したCookieを、アプリが再発行したものとみなさない。
- **C-09①の判定できない形**：`pre-login`で発行した主のセッションID（名前に`sess`・`sid`を含むもの）を`login`で再発行せず、ほかのCookieだけを発行したときはna（認証を新しいCookieで持つのか、ログイン前のIDのセッションに結び付けるのかは、応答からは分からない。ログイン前のIDだけで認証後のページを取得できないかを手動で確かめる）。
- **C-07②の署名付きトークン**：`session-sample-*`の値がすべて同じJWT（またはFlaskの`.ペイロード.時刻.署名`の形、Djangoの署名が20文字以上の`ペイロード:時刻:署名`の形）で、採取の時刻（`#META at`）が分からないか60秒以内のときはna（同じ秒に同じ内容で署名すると同じ値になる。`#META at`は手元の時刻で、トークンの時刻はサーバのものなので、同じ秒かどうかでは比べない）。60秒より離れていれば②。`guest:1:admin`のような固定の値も②。
- **本文・API・転送の補足**：
  - HTMLのタグは、コメント（`<!-- … -->`）の中のものを読まない（閉じていないコメントは本文の終わりまで）。
  - E-09の開発用コメントの証跡には、一致した語だけを出す（`pass Summer2024`は「pass」）。E-01①のAWSのキーは、組織プロファイルでE-09を対象外にしたときはE-01で指摘する。
  - E-08：空の`integrity=""`はintegrityなし。E-05：Spring Bootのヘルスのグループ（`/actuator/health/liveness`・`readiness`）で状態だけの応答は、既定の応答。
  - E-04：`robots.txt`の3xxを`-L`なしで採取したものはna。`security.txt`のプローブは、先頭が`#`のコメントでもファイルとする。E-13：XSSI対策の前置き（`)]}'`の行）のあるソースマップも、取得できたものとする。
  - A-01①：本文のない2xx（204、`Content-Length: 0`）と、本文を採取していない2xxはna。エラーだけのJSONには、状態の番号だけのもの（`{"status":401,"message":"…"}`・`{"status":"fail"}`）も含める。
  - A-07①：キーの最後の部分を語に分け、`password`・`passwd`・`passphrase`を含むもの（`password_digest`・`hashedPassword`）と、`secret`・`api_key`・`secret_key`・`secret_access_key`などで終わるもの（`stripeSecretKey`）。最後の語が状態・設定のもの（`password_policy`・`password_updated_at`）と、`has`・`is`で始まるものは除く。
  - A-08：合格は415と、405以外の4xx。ログイン画面への転送（3xx）・5xx・405はna（Content-Typeを確かめるところまで届いたかが分からない）。A-09②③：本文のない応答（204・304、Locationのある3xx、`Content-Length: 0`）はna（H-08と同じ）。
  - T-06：テスト値（`evil.example`。エンコードしたものを含む）を持ったまま、同じ入口（パスの最後の部分が同じ）へ転送したもの（ホスト名をそろえる転送、`/en/redirect`への書き換え）は、試した転送とせずna。T-07②：スキームのない`//evil.example`の反映も含める。
- **T-09・T-10の合意したバージョン・暗号**：`-v`の`SSL connection using`は、curlの`Issue another request to this URL`でたどったホストごとに分け、ターゲットのホストへの接続のものだけを使う（`-L`で移った外部のSSOのTLSを、対象のホストのものにしない。プロキシの`Connected to`ではホストを変えない）。
- **プロキシの407**：407はプロキシだけが返すので、あとに応答が続かなくても、サイトの応答として判定しない。
- **ラベル依存ルール**：特定のラベルが付いたターゲット1つを見るルール。H-15とC-12②は`logout`、T-04は`http`（apexのhttpも`label=http`で採取する）。
- **横断ルール**：複数ターゲットを比べるルール。C-07②は`session-sample-*`のセッションIDの共通接頭辞・連番性、C-09①は`pre-login`で発行されたIDと`login`のSet-Cookie、C-12①は`logout`と`after-logout`、H-02③は一般ターゲット（www）のpreloadと`apex`のHSTS、H-04⑤のcsp-sample-\*同士のCSPのnonce。ラベルが足りなければnaとし、画面で不足しているラベルを示す。
- **ルール間の依存**：C-01②③は同じホストのH-01（HSTS）の結果を、H-07③は同じターゲットのE-07の結果を使う。ログイン関連ターゲットではH-01を実行しないため、HSTSの有無はホストごとに一般・`apex`ターゲットの結果から先に求めて参照する。依存先は各ルールの`dependsOn`に書く。
- **評価の順序**：①ラベルと適用項目の対応表で項目を絞り込み→②ターゲット単位のルール→③ホスト単位のルール（ホストごとに集約）→④横断ルール。②〜④の各スコープの中では`dependsOn`の順に実行する。その後、⑤条件単位の絞り込み（ターゲット単位のルールの結果に適用）→⑥API応答での重要度の引き下げ→⑦組織プロファイルで対象外にした項目の除外→⑧二重減点の除去→⑨組織プロファイルによる重要度の上書き→⑩例外の適用。除外を二重減点の除去より先に行うのは、除外した項目の代わりに数えている指摘を「数えない」扱いにしないため。実装は`engine/run.ts`（ツール設計4）。
- **ルールの例外**：ルールが例外を投げたら（診断対象の応答に細工したJWTのヘッダ（`alg`がオブジェクト）がある場合など）、判定全体を止めずに、そのルールだけをna（「ルールの実行中にエラーが発生した」）にする。止めると、ほかのすべての結果が消える。
- **本文を採取していない応答**：本文を見て判定するルール（E-06・E-13・T-01のTRACE・T-07）は、`-v`や`-o /dev/null`で採取して本文がなければ、「反映されない」「参照なし」と合格にせずnaにする（見逃しになり、カバレッジも水増しになる）。HARはHTML・JSONに加えてJSの本文も先頭64KBまで残す。
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
- 例外の対象が今の形式の突き合わせのキー（URLの部分が`urlKey`の出力そのもの。画面で登録した例外はこの形）か、今回の結果のどれかのキーと同じ文字列なら、キーの完全一致だけで照合する（画面で1つのターゲットに登録した`HAR GET https://a.example/*`の`*`は伏せたパスの部分で、ワイルドカードとして読むと`/login`・`/`の指摘まで抑止した。そのページを含まない回の入力でも同じことが起きたので、今回のキーにあるかではなく、キーの形で見分ける。以前の版のキーで今の形式と同じ形のものは、完全一致だけになり、合わなければfailに戻る）。それ以外の`*`を含む対象（形式の違う以前の版のキー、手で書いた`HAR GET *`・`HAR GET https://a.example/admin*`）は、今までどおりURLを持つキーの全体にワイルドカードとして照合する（ラベルだけのキーには当てない。`*login*`が`login`ラベルの指摘を抑止しない）。「ラベル URL」の形の対象は、生のURLから作った突き合わせのキーのURL（`keyUrl`）と比べる（マスクしたURLから作ると、ASP.NETの`(S(…))`のような部分の形が変わって外れた）。指摘5000件×例外300件でも2秒以内に終わること（`tests/review19.test.ts`）。

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
- **一部の条件が入力不足の項目**：ほかのラベルと比べる条件・ホスト単位の条件（C-09①、C-12①、C-07②、H-04⑤、H-02③、T-09①など）が入力不足でnaでも、同じ項目のほかの条件を判定していれば「判定済み」とする。ただし、指摘の有無にかかわらず理由の欄に「一部の条件（ほかのラベルと比べる条件、ホスト単位の条件）は入力不足」と、その理由を出す（`login`だけでC-09が「判定済み・0件」と出ると、①（高）を確かめたように見えるため）。
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
- 不正な値は読み込み時に指摘し、正しい部分だけを使う。配列にする項目を文字列などで書いたもの、`severity`をオブジェクト以外で書いたもの、知らない項目（綴りの誤りの`excludes`など）も指摘する（黙って既定値で判定しない）。エクスポートしたJSONにはプロファイルを含める。

### 前回との差分（v0.4）

以前にエクスポートしたJSONを読み込み、今回の結果と比べます。

- **突き合わせ**：指摘（fail）を「ルールID×ターゲット×証跡の形」で突き合わせる（証跡の形は、証跡に出てくるホスト名の一覧。同じルール・ターゲットで別の配信元・読み込み先の指摘（E-08の配信元、E-07のタグ）は別に突き合わせ、直ったものを「解消」、増えたものを「新規」にする。ホスト名だけを使うのは、証跡のほかの部分は画面のマスクで形が変わるため（キーはマスクに依存しない）。同じホストの別のものは区別しない）。ターゲットは、curlはラベル、HARは「HAR メソッド URL」（`targetKey`）で識別する（HARのラベルの番号は記録し直すと変わるため）。URLは、残してよい形だけを残す決まった形で作る（`urlKey`。許可リスト）。キーは画面・エクスポートのマスク（`src/mask.ts`）とは別のファイル（`src/engine/targetKey.ts`）で作り、マスクを読み込まない（マスクの一覧を変えるたびにキーが変わり、以前の例外と前回の結果が黙って突き合わなくなったため）。キーが守ること（もう一度かけても変わらない、値を変えても変わらない、パスのトークンを含まない、パラメータ・ターゲットの順番で変わらない）は、性質のテスト（`tests/properties.test.ts`）で確かめる：スキーム・ホスト・パスと、並べ替えたクエリのパラメータの名前。パスの部分とパラメータの名前は、`-`・`_`・`.`で区切ったかけらのうち、英字の語（24文字まで。大文字・小文字の入れ替わりは4回まで、大文字だけは10文字まで）、日本語などのASCII以外の文字の語（`お知らせ`・`採用情報`。24文字まで。大文字・小文字の入れ替わりは4回まで。長音`ー`も語の一部）、6桁までの数字、`v2`・`x64`のような短い語と数字だけを残し、それ以外は`*`にする（`AdminDashboard-*.js`）。パス引数（`;jsessionid=…`）とクエリの値は持たない（ページ送りの名前（`page`・`offset`など）の4桁までの数字と、並べ替え・表示の切り替えの名前（`sort`・`lang`など）の英字の語だけは残す。同じ名前が2回以上あれば、値がすべて同じときだけ残す）。ASP.NETのセッション`(S(…))`は`(*)`。相対のURLは先頭の`//`を1つにし、スキームのない`//ホスト/…`はホストを残す（もう一度かけても変わらないように）。秘密らしい形を数え上げて伏せる作り（v0.4.29・v0.4.30）は、`;jsessionid=`の値や小文字と数字だけのトークンを見分けられず、JSONのエクスポートと例外ファイルに出した。残す形を決めておけば、トークンがどんな形でもキーには入らない（別のページが同じキーになることはある）。キーが重なるもの（curlの同じラベルで同じURL、HARでURLは違うがキーが同じもの）は、2つ目から` #2`を付ける。HARでURLまで同じもの（ポーリング）には付けない。読み込んだ例外ファイル・前回の結果のキーは、URLの部分にもう一度`urlKey`をかけて変わるものを以前の形式とみなし、突き合わない件数を知らせる。`targetKey`のない以前のJSONはラベルで突き合わせる。例外の照合にも同じキーを使う。URLのパターンの例外は、画面に出す（マスクした）URLのほかに、キーのURLとも照合する（マスクの一覧を変えても、パターンが黙って外れないように）。v0.4.36でキーの形を変えた（ASCII以外の文字の語を残し、同じ名前のパラメータの値が違うものは名前だけにした）ので、以前の結果とは突き合わないことがある（読み込むとルールセットの版の違いを知らせる）。`*`を含む以前のキーの例外は、URLを持つ新しいキーの全体とも照合する（`*`は`/`で区切った1つの部分の中だけに一致させる。画面で1つのターゲットに登録したキーの`*`（伏せたパスの部分）が、同じホストのほかのページにも効いた。ラベルだけのキーとは`*`で照合しない）。同じラベルが1つに減ってキーがラベルだけになっても、「ラベル URL」で登録した例外は効く。英小文字だけの16文字以上で、母音（`y`を含む）が4分の1未満の部分（トークン）も`*`にする（12文字にすると`cryptography`・`strengthening`まで`*`にした）。
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
| マスキングの対象 | 常に行う（切り替えはない）。生のヘッダ行（Authorization、Cookie、Set-Cookieなど）は画面にもエクスポートにも出さない。証跡に出すSet-Cookieは値を伏せ、既知の属性（`Expires`・`Max-Age`・`Domain`・`Path`・`SameSite`・`Secure`・`HttpOnly`など）は残す。未知の属性の値と、既知の属性の値の中のカンマのあと（1行にまとめたSet-Cookieで分けられなかった、名前のない2つ目のCookie。`Expires`は日付の2つ目のカンマのあと）は伏せる。URL（ターゲット、Location、証跡）のパラメータは、検出（A-02・C-09②）に使う名前に加え、名前を`-`・`_`・`.`・角かっこ（`user[password]`）・キャメルケースの境目（`accessToken`）で区切った語に`token`・`secret`・`signature`・`credential`・`password`・`key`・`session`・`sid`・`code`などがあるものを伏せる（署名付きURLの`X-Amz-Security-Token`など）。`pass`・`pw`・`ticket`（CASのチケット）・`oauth_verifier`・`SAMLResponse`・`SAMLAssertion`・`client_assertion`（JWTでのクライアント認証）・`assertion`・`nonce`・`passcode`・`hash`と、名前全体が`pin`のものも伏せる（`pin_lat`は残す）。最後の語が`type`・`method`・`size`・`length`・`policy`・`timeout`・`ttl`・`alg`などの名前（`client_assertion_type`・`token_type`・`grant_type`・`code_challenge_method`・`key_size`・`max_password_length`）は種類や設定を表す公開の値なので伏せない（PKCEの方式のようなセキュリティ上意味のある値を読めるように）。Akamaiの署名トークン（`hdnts`・`hdnea`。`acl=/*`の値は持参人の資格情報）と`hmac`・`bearer`・`authentication`の語、httpie・xhの秘密らしい名前の項目（`password=…`・クエリの`api_key==…`。印はそのまま残す）とコロンのあとを引用符で囲んだヘッダの値（`Authorization:"Bearer …"`。curlでヘッダを消す`-H "Authorization:"`は値がないので、後ろを値として読まない）、`echo`・`printf`の引数や`<<<`でcurlに渡した本文の秘密らしい名前の値、コマンドの前の秘密らしい名前の環境変数の代入（`TOKEN=…_curl_…`。`export`・`env`・`set`・`declare -x`・PowerShellの`$env:`のあとのものも）、パラメータの値に入れたエンコードしたURLのパスワード（`https%3A%2F%2Falice%3A<パスワード>%40`）、名前が一覧にないパラメータの値のトークン（`?t=<トークン>`。パスに置いたトークンと同じ基準。公開の値を入れる決まった名前（`utm_*`・`gclid`・`list`・`id`・`title`・`q`など）の値は見ない）、名前全体が`mac`のものも伏せる（`mac_address`・`isMac`は残す）。`state`・`oauth_state`（OAuth）は、値が8文字未満か、16文字未満で英字の語のとき（`?state=open`・`state=California`のような一覧の絞り込み）は残し、それ以外は伏せる。語`code`は、ほかの語が`country`・`zip`・`promo`・`error`・`status`・`currency`などだけのとき（`country_code`・`error_code`）は伏せない（`code`だけと`auth_code`・`verification_code`・`otp_code`・`device_code`は伏せる）。語の末尾の数字は、`password`・`pass`・`pw`・`otp`・`token`・`secret`などのときだけ外して照合する（WordPressの`pass1`・`pass2`、`otp1`。`key1`・`code128`・`mac1`は例や品番にも使うので外さない）。`pw`で終わる名前（`userpw`）と`nonce`を含む名前（WordPressの`_wpnonce`）も伏せる。区切りのない1語の名前（`authtoken`・`secretkey`・`cftoken`・`sesskey`・`passphrase`など）は、`token`・`secret`・`passw`などを含むかでも見る（伏せすぎるほうを選ぶ）。名前はパーセントエンコードをデコードしてから照合し、区切り（`?`・`&`・`=`など）はエンコードした形（`%3F`・`%26`・`%3D`と二重エンコードの`%253D`など、JSのエスケープ、HTMLの文字参照`&amp;`・`&#61;`・`&#x3D;`など）も認める。HTML本文のタグの属性の値は、文字参照を戻してから判定・マスクする（`?next=%2Fcb%3Ftoken%3D…`のように、別のパラメータの値に入れたURLの中も伏せる）。証跡の抜粋は、マスクしてから切り詰める（切り詰めてからでは、途中で切れたJWTが一致しない）。伏せた値の印（`…(N chars)`）の途中では切らず、印にかかるときは印の終わりまで含める。マスク済みかどうかは、値が`…(N chars)`の形で終わるかで判断する（「…」を含むだけでは判断しない。URLの直後に続く日本語の文の「…」で、値を伏せずに残さないため）。値の長さに上限を付けずに最後まで伏せる（6KBのJWTなど）。パスの1つの部分が、英大文字・小文字・数字をすべて含む16文字以上、24文字以上の16進数（UUIDを含む）、または数字を含む32文字以上なら、パスに置いたトークン（`/password/reset/<トークン>`など）として伏せる。完全なURLだけでなく、`/`か`%2F`（二重エンコードを含む）のあとに続く部分ならどこでも見る（ただし`//`・`%2F%2F`の直後のホスト名は見ない。パスの途中の`//`・`///`（直前がパスの文字か`/`の`/reset//<トークン>`）の直後は見る。コロンをエンコードしたスキーム（`https%3A//`）の直後はホスト名なので見ない。長いホスト名やELBの名前まで伏せると、URLで登録した例外が一致せず、CORSの証跡のOriginも読めなくなる。相対パスの`<form action>`や`Location`、スキームのない`//cdn…`、別のパラメータの値`?next=/invite/…`、フラグメントのルート`#/reset/…`）。部分は`.`と`:`で分け、末尾の`=`（Base64の詰め物）を除いて判定する（`<トークン>.pdf`、`bot123:<トークン>`）。英字だけの短い語と`-`・`_`で始まるもの（`application-<ダイジェスト>.js`）は、その語を残して残りだけを伏せる（別のファイルを区別できるように）。ASP.NETのCookieを使わないセッション（`/(S(<セッションID>))/`、フォーム認証のチケット`/(F(…))/`、匿名IDの`A(…)`）の値も伏せる。ビルドしたファイルの名前（静的ファイルの拡張子が付き、英字の語を`-`・`_`でつなぎ、最後に12文字未満か20文字以下の16進数のハッシュを付けたもの。Viteの`AdminDashboard-Dk3x9Lq2.js`。語がtoken・reset・magic・login・shareなどのものは除く）は伏せない。パスの部分の中のBase64の`+`・`=`をエンコードしたもの（`%2B`・`%3D`）もトークンの一部として見る。英大文字・小文字・数字をすべて含むものと数字を含む32文字以上のものでも、英語の語と4桁までの数字をつないだ名前（`MyCompanyLogo2026Final.png`・`GettingStartedV2Guide`）は伏せない。名前とみなすのは、`-`・`_`で区切った部分ごとに、3文字までの語、4文字までの大文字の略語、4桁までの数字、12文字までで母音が4分の1以上あり子音が4つ・母音が3つ続かない語だけからなり、かたまりの平均が3.5文字以上（4文字までの部分は見ない）、小文字だけの語は1つまで、4文字以上の語が全体で3つ以上あるもの。`token`・`secret`・`session`・`pass`・`auth`・`key`などの語を含むものは名前とみなさない（乱数のトークンが名前とみなされるのは、16〜32文字で10万個に数個以下）。CSPのハッシュ（`'sha256-…'`）とSRI（`integrity="sha384-…"`）は、ハッシュの長さちょうど（SHA-256は44文字、SHA-384は64文字、SHA-512は88文字）で後ろにBase64の文字が続かないものだけ、`/`のあとをパスの部分と読まずにそのまま残す。小文字（または大文字）と数字だけの20文字以上の並び（base36・base32のトークン）も、数字と英字が4つ以上ずつあれば伏せる。数字のない、大文字・小文字が頻繁に入れ替わり、母音の少ない（3割未満）16文字以上の並びも伏せる。英小文字だけの16文字以上で、母音が4分の1未満の並び（`/reset/kqzvwxmplrtbnhjd`。英語の語をつないだ`internationalization`は残る）も伏せる（キャメルケースの`getUserByIdAndName`は残す）。英字の語で始まるトークンの語を残すのは、語らしい接頭辞（大文字・小文字の入れ替わりが少ない20文字以下）だけ。webpackの`[name].[contenthash].js`の16進数のハッシュ（語のあとに`.`でつないだもの）は、JS・CSS（`.chunk.js`・`.map`を含む）とフォント（`.woff2`など）だけ伏せない（名前全体が16進数のファイルと、画像の`avatar.<ハッシュ>.png`（アップロードしたファイルのランダムな名前のことがある）は伏せる）。`?`・`#`・`&`のあとの`=`のないトークン（`?<トークン>`、`#<トークン>`）も伏せる。パラメータの値は、前の引用符（`?token='…'`）を越えて、JSONの`\/`を含めて伏せる。`_csrf`・`xsrf`の値も伏せる。CSVの「実施コマンド」「実施日時」（手で書いた`#META cmd=`・`at=`）は、伏せるのではなく、残してよい形だけを残す要約を出す（`src/export/cmdSummary.ts`、第31回）：コマンドのID（`C1`〜`C26`・`HAR`・`-`。コマンド生成器とHARの取り込みが書くのはこれだけ）はそのまま。手で書いたコマンドは、一覧にあるプログラムの名前（パスは除く。`C:\Users\<名前>\…`の名前を出さない）、シェルの区切り（`|`・`;`・`&&`など）、オプションの名前（curl・wget・httpie・PowerShell・opensslごとの一覧にある長いオプションと、決まった文字だけの短いオプション。curlのまとめ書きはよく使う文字（`-sSLk`など）を4文字までと値を取る文字1つ。値を続けたものは`-u****`・`--user=****`（値を取る文字1つのときだけ。まとめ書きのあとに値を続けたもの（`-sSu…`）は`****`）。一覧にない名前は`****`。値の中の`_--secret`のかけらを名前として出さないため）、`-H`のあとのヘッダの名前（一覧にある名前と、`X-`・`Sec-`・`Accept-`・`Content-`などの接頭辞で始まるもの。`_`を含む名前は出さない）、httpieの項目の名前（一覧にあるヘッダ・パラメータの名前だけ。`Name:****`・`name==****`）、一覧にある環境変数の名前、HTTPのメソッド、opensslのサブコマンド、URLは突き合わせのキーの形（`urlKey`：パスのトークンは`*`。一部でも`*`になったパスの部分は全体を`*`。クエリは一覧にある名前だけを残し、ほかの名前は`*`、値は出さない。ユーザー情報は先に読んで捨てる（`svc_account:…@`の`_`で切らない。`_`で区切ったコマンドで`_`を含むユーザー情報は、次の引数（`_-`・`_Name:`・`_email=`・`_cv@`など）を越えて読んだものと見分けられないのでURLを`****`にする）。パスワードに`/`・`\`・`?`・`#`があるURLと、ホストに`.`のないURL（`localhost`とIPアドレスは除く）、URLの始まりからコマンドの値（`#META cmd=`の1つの値）の終わりまでに`@`があるURL（URL自身のユーザー情報の`@`が1つだけのものは除く。引用符・`\"`・`\ `・`・`・改行・閉じない引用符などでユーザー情報の途中で切れると、ユーザー名と数字のパスワードがホストとポートに見える。ユーザー情報の終わりの`@`はどこで切れてもURLのあとにあるので、切れ方ではなく`@`があるかだけを見る。`?email=alice@example.com`・`/@alice`のURLも`****`になる）は`****`）だけを残し、ほかの語（値・ユーザー名・パスワード・ヘッダの値・知らない語）はすべて`****`にする（続く`****`は1つ）。区切りは空白（空白を含まないコマンドでは空白と`_`。空白で区切ったコマンドでは、値の`Bearer_abc_-iLkvH…`のかけらを短いオプションとして出さないよう、`_`で区切らない）で、出力は空白でつなぐ。閉じていない引用符は区切りとして読み飛ばす。空白を含まないコマンド（`_`で区切ったもの）では、URLのパスの部分を`_`で終える（`_`で区切ったURLのあとの値をパスの続きとして読まないように。`/api/user_info`は`/api/user`と`****`になる）。1つのコマンドは200文字まで。実施日時はありうる日時（年は1900〜2099、月・日・時・分・秒・時差は範囲の中）だけを出し、ほかは`****`（秒の小数は3桁まで）。秘密らしい場所を推し量って伏せる作り（第30回までの`maskCommand`）は、第25回〜第30回で毎回、直前の回の修正が次の漏れを入れたのでやめた。要約はマスク（`src/mask.ts`）を読み込まない。パラメータの値でも印を値の一部として読み、伏せ済みとみなすのは値が「先頭の4文字までと印」（nonceを先に伏せた`nonce-Xk…(20 chars)`を含む）だけのときに限り、その値は印の終わりで終える（印で終わるだけで伏せ済みとみなすと、`?access_token=<トークン>_-L_-F_token=vi…(17 chars)`のトークンが残った）。URLのユーザー情報は、スキームの前が数字・`-`・`.`のもの（エンコードした引用符の直後の`%22https://user:pass@…`、`corp-egress-…-https://user:pass@…`）も伏せる。パラメータの値に入れたURLの中は深さ10まで見て、それより深いものも秘密の名前のパラメータは伏せる。マスクは、結果が変わらなくなるまで繰り返す（前の手順で伏せた結果が、後の手順の手がかりを変えることがあるため。冪等にする）。HTML本文のタグは、引用符で囲んだ属性の値の中の`>`で切らない。E-01③は、エラーページの`<title>Error 401 …</title>`の自由な文言を出さない。URLのユーザー情報は、スキームのない`//user:pass@host`も伏せる。JSONの文字列の組（`"password":"…"`）は、そのまま・エスケープした形（`\"password\":\"…\"`）・パーセントエンコードした形（`%22password%22%3A%22…%22`。二重エンコードと、コロンをエンコードしていないものを含む）のどれでも、名前がパラメータと同じ基準で秘密なら値を伏せる（パラメータの値に入れたJSON（`?data={"password":…}`）も含む）。数値の値は、ワンタイムの番号・パスワードらしい名前（`pin`・`otp`・`passcode`など）だけ伏せる（`"code":404`は残す）。ほかにJWT（`Bearer_eyJ…`・`access_token_eyJ…`のように語と`_`でつないだものと、JWEの5つの部分（鍵の部分が空の`dir`形式を含む）も伏せる）、CSPのnonce（閉じ引用符のない`'nonce-…`は長さを問わず伏せる。引用符のない`nonce-…`は、値が6文字以上で英大文字か数字を含むときだけ伏せる（`/posts/nonce-reuse-attacks-explained`のような普通の語は残す））、デバッグ用のヘッダ（`x-debug-token`・`x-debug-token-link`。H-16③）の値、URLのユーザー情報（`user:pass@`はパスワードを、ユーザー名だけの`<トークン>@`はユーザー名を伏せる。パスワードに`@`を含む場合も残さない）。HTML本文のタグを証跡に出すとき（E-07〜E-10・E-12）は、判定に使う属性（`src`・`href`・`action`・`data`・`rel`・`method`・`type`・`name`・`content`・`integrity`・`crossorigin`・`as`）の値だけを出し、ほかの属性（`data-api-key`・`nonce`など）は値を「…」にする。一覧の正本は`src/mask.ts`と`src/rules/html.ts`。Markdownのエクスポートでは、証跡などの値の`<`・`>`を実体参照にし、`|`・`[`・`]`・`!`・`` ` ``・`\`をエスケープし、改行を空白にする（診断対象の応答に書かれた画像の記法が、レポートを開いたときに外部から読み込まれないように。読み込んだ組織プロファイルの名前や前回の結果の日時も同じ扱い）英小文字だけの16文字以上の語で、母音（`y`を含む）が4分の1未満か、英語でよく現れる2文字の並びにないものが35%以上のものは、乱数のトークンとして伏せる（URLのパスの`/invite/qwrtzxkpmnbvcdfgh`など。乱数の16〜24文字の約98%。英語の語をつないだ`healthcheckstatus`・`internationalization`は24%以下なので残る。突き合わせのキーも同じ規則（`src/tokenShape.ts`）でかけらを除く）。ワンタイムコードの名前（`authcode`・`otpcode`・`smscode`・`mfacode`・`pincode`・`logincode`・`resetcode`・`verifycode`・`activationcode`・`confirmcode`・`emailcode`・`vcode`・`totp`・`otp…`）の値も伏せる（`zipcode`・`errorcode`は残す）。URL・JSONの外で名前を付けた値（`password="…"`・`{'password': '…'}`・`pass: …`・`X-Auth-Token: …`、PHPの`'password' => '…'`・`define('DB_PASSWORD', '…')`、XMLの`<password>…</password>`・`<add key="Password" value="…"/>`。名前の最後の語が`password`・`secret`・`token`・`api_key`などのもの。引用符で囲んだ値は閉じの引用符まで）も伏せる。**最後に許可リストを通す**（`src/shownText.ts`の`showText`。証跡とターゲットのURL）：上の伏せ方のあとの文字列から英数字の語を取り出し、残してよい形の語だけを残して、それ以外は`…(N chars)`にする。`-`・`_`・`+`でつないだ並び（`glpat-…`・`sk_live_…`）はまとめて見て、残せないかけらがあれば、そこから並びの終わりまでを伏せる（それより前は英字の語のかけらだけを残す）。残すのは、4文字までの語、10桁までの数字、語として読める英字（小文字・12文字までの大文字。キャメルケースは部分に分け、2文字の部分は`By`・`Id`・`Of`などの語か略語、部分は4つまで（すべて3文字以上の語なら7つまで）。部分の中のまれな2文字の並びが多いものは乱数として残さない）、語と短い数字をつないだもの（`oauth2`・`app01`・`sha1WithRSAEncryption`・`1024bit`）、暗号・プロトコルの名前に数字を付けたもの（`sha256`・`AES128`・`TLSv1`・`secp256r1`・`X25519`）、日時と単位、URLのホスト名（ユーザー情報のあとか、ユーザー情報のないURLの`//`の直後だけ。ユーザー名に置いたトークンはホスト名として残さない）、決まった最上位ドメインの英小文字のドメイン名（スキームのないCSPのホスト）、CSP・SRIのハッシュ、伏せた印。名前の付いていないトークン（本文の`ghp_…`・`AKIA…`・`sk_live_…`・Slackの`xoxb-…`）は形を数え上げずに伏せる。パーセントエンコードした`+`・`/`・`=`も並びの区切りとして読み、数字だけのかけらが3つ以上で12桁以上の並び（カード番号の形）はまとめて伏せる。英大文字だけの7文字以上と英小文字だけの7〜9文字も、まれな2文字の並びで見る。一様な乱数のトークンのうち8文字のかけらが残るのは、base62・16進数で0.01%以下、URL-safeで約0.2%、GitLabの形（`glpat-`の後ろ）で約0.2%、英数字10〜15文字で約0.6%、標準のBase64（`+`・`/`を含む）で約5%、パーセントエンコードしたBase64で約6%、英大文字10文字で約12%、英小文字6〜9文字で約8%（語として読めてしまう並び。名前の付いた値は、名前で伏せる上の規則に頼る）。パラメータの名前は、全角の英数字を半角にし、ゼロ幅の文字・ソフトハイフンと末尾の`+`・空白を除いてから照合する（`password+=`）。`pswd`・`psw`・`mdp`・`pin_number`も伏せる。全角の名前のパラメータの値（`?ｐａｓｓｗｏｒｄ=…`）は、パラメータとして見つけられないので残る。名前の付いていない短い合言葉（`hunter2`）は形では見分けられないので、名前で伏せる上の規則に頼る。 |
| マスキングの方法 | 値の長さで残す文字数を変える：8文字以下はすべて伏せる、9〜20文字は先頭2文字、21文字以上は先頭4文字。いずれも文字数を付記（例：`abcd…(64 chars)`）。Set-Cookieは値だけ伏せて属性は残す。エントロピー評価はマスク前の値でメモリ内だけで行う |
| プローブの中身 | `#PROBE`の`head`（先頭64バイト）は.envなどの秘密を含み得る。判定にだけ使い、画面とエクスポートには「一致したパターン名」（例：`git-head`、`dotenv`、`phpinfo`）だけを出す |
| 生データのエクスポート | 提供しない。エクスポートは常にマスク済み。生の出力は診断者の手元のファイルを社内の保管場所に置く（第8章） |
| ツール自身のCSP（meta） | `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src blob:; base-uri 'none'; form-action 'none'">`（`object-src`は`default-src 'none'`で禁止される）。あわせて`<meta name="referrer" content="no-referrer">`を入れる。これらは`<head>`の先頭（charsetより前）、どのスクリプトよりも前に置く。開発サーバはCSSをstyle要素で注入するため、メタCSPは本番ビルド時だけViteプラグインで挿入する。CSSはTailwind CSS v4を@tailwindcss/viteでビルド時に静的ファイルとして生成し、実行時にstyle要素を注入するものは使わない |
| メタCSPの制約 | W3C CSP3では`frame-ancestors`、`report-uri`、`sandbox`、Report-Onlyはmetaで無効。GitHub Pagesは独自ヘッダを設定できない。クリックジャッキング対策はJSの`top !== self`による表示抑止で補う。厳密さが必要ならCloudflare Pagesなどヘッダを設定できるホストへ移す |
| XSS対策 | 入力由来の文字列は`textContent`か`createTextNode`で描画し、`innerHTML`、`insertAdjacentHTML`、`eval`、`new Function`は禁止。ESLint（`no-restricted-properties`で`innerHTML`・`outerHTML`・`insertAdjacentHTML`・`document.write`、`no-eval`・`no-implied-eval`・`no-new-func`）で機械的に止める。可能ならメタCSPに`require-trusted-types-for 'script'`（ブラウザ対応は要確認） |
| Worker | HARの解析はWeb Workerで行う（curlの貼り付けはメインスレッドで解析する）。Viteの`?worker&inline`でblob: URLのWorkerとして作り、メタCSPに`worker-src blob:`を加える。別ファイルのWorkerには、そのファイルのHTTP応答のCSPが使われ、GitHub PagesはCSPヘッダを返さないため、生のHAR（Cookie・パスワード）を持つWorkerから通信できてしまう。blob: のWorkerはページのCSP（`connect-src 'none'`）を引き継ぐ（E2Eで確認） |
| ファイル読込・ReDoS | `FileReader.readAsText`でサイズ上限5MB（HARと前回の結果のJSONは50MB。大きなHARを判定した結果のJSONは5MBを超えるため。例外ファイルと組織プロファイルは5MB）。正規表現は線形時間のパターンに限る |
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
| 状態の表示 | 入力の誤りや、判定のあとの件数（「N件のターゲットを判定しました。指摘（項目×条件）N件（うち重要度「高」N件）」。件数は結果表と同じく項目×条件で一意に数える）を、役割`status`の欄に出す。言語を切り替えたら、その言語で出し直す（件数だけでなく、入力がない・読み込みのエラーなどのメッセージも。メッセージは文言を作る関数で持つ）。結果欄は`aria-live`にしない（再描画のたびに数百行を読み上げるため） | — |
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

- **エクスポート**：Markdown（重要度順の表。前回の結果を読み込んでいれば差分の表、組織プロファイルの名前も含める）、JSON（Findingの配列、ツールとルールセットの版、生成日時、組織プロファイル、例外一覧）、CSV（BOM付きUTF-8、第8章の列構成）。`Blob`と`URL.createObjectURL`で保存する。常にマスク済みで、生データは出力しない。CSVの「実施日時」「実施コマンド」は、指摘の元になったターゲットの`#META`から埋める（ホスト単位の判定は同じホストの`tls`・`probes`など、横断の判定は比べたラベルのターゲット。コマンドは重複を除いてつなぎ、日時は最も新しいもの）。`#META`の値は利用者が書いたもの（コマンドに`?access_token=`などを含むことがある）なので、マスク（拒否リスト）ではなく、残してよい形だけを残す要約にする（`src/export/cmdSummary.ts`。許可リスト）：コマンドはプログラム名、既知のオプションの名前と決まった形の値、URLのスキーム・ホスト・パスの語だけを残し、ほかは`****`にする。`sudo`・`timeout`・`env`・`time`・`nohup`などの前置きのコマンドのあとのコマンドも読む（数字は`timeout`の秒数だけ残す）。URLのユーザー情報は伏せる。URLの始まりからコマンドの値の終わりまでに`@`があるURLは、URL自身のユーザー情報の`@`が1つだけのときを除いて`****`にする（`?email=alice@example.com`・`/@alice`も。ユーザー情報の途中で切れたURLと見分けない）。コマンドは、ターゲットごとの値を要約してから重複を除いてつなぐ（別のターゲットのコマンドの`@`でURLを伏せない）。`#META`の`cmd=`の値が引用符・空白で切れ、行のあとに`@`が残るとき（`cmd="curl 'https://first.last:'"$PASS"'@host/'"`）は、値の終わりに`@`を付けて要約する（`src/parser/input.ts`の`attrs`）。値が`-`だけのものはそのまま出す（数式の対策の`'`を付けない）。日時は文字列ではなく時刻として比べて、最も新しいものを選ぶ（`T`区切りと空白区切りが混ざっても）。
- **パーサのテスト**：fixtureごとにターゲット数、応答数、最終ステータス、Set-Cookie件数を検証する。実際の curl 8.5.0 と OpenSSL 3.0.13 の出力（ローカルのTLSサーバに対してコマンド生成器のスクリプトを実行したもの）も fixture にする。複数コマンドを続けて貼っても本文へ混入しないこと、`#`で始まる本文行や` *  `・` >  `で始まる本文行が本文として残ること、空白を含むContent-Typeを`#PROBE`から正しく読めること、複数ホストの結果をホスト単位で集約できることを確認する。HARでは、取り込み後のデータにリクエスト本文（postData。パスワードを含む）が残っていないことも確認する。
- **ルールのテスト**：条件ごとに、passとfailになる最小の入力を用意する。横断ルールは、予約ラベルが欠けたときにnaになることも確認する。
- **横断的なテスト**：既知の秘密情報を入力のあらゆる場所に置き、どの出力（画面用のデータ、Markdown、JSON、CSV）にも現れないことを確かめる（`tests/masking.test.ts`）。推奨対応と判定不能の理由の英訳の漏れを、ルールのソースコードの構文木から検出する（`tests/i18n.test.ts`）。案内する「必要なラベル」で実際に判定されることを確かめる（`tests/labels.test.ts`）。
- **回帰テスト**：判定の結果の全体（指摘・証跡・解析警告・突き合わせのキー・診断カバレッジ）を、コーパス（`tests/golden/cases/`と既存のfixture）について期待結果のファイルと比べる（ゴールデン。`tests/golden.test.ts`）。同じ応答を、改行の違う形と、curlの出力・HARの両方で入力し、判定が同じになることも確かめる（同値性。`tests/equivalence.test.ts`）。期待結果は「今の結果」で、判定を変えたら書き直して差分をレビューする（CONTRIBUTING.md）。過去の退行（第16回のCR CR LF、第17回のHARの最初のリクエストだけを見るもの、第18回の静的リソースなど）をソースに戻すと、これらのテストが失敗することを確かめた。
- **アクセシビリティ**：axe-core（`@axe-core/playwright`）で、未入力・判定後・「情報」の表示・例外のダイアログ・コマンド生成器・英語UI・HARのエントリ一覧・ダークモード、スマートフォンの画面幅（390px）を検査し、軽微より重い違反がないことを確かめる（`e2e/a11y.spec.ts`）。スマートフォンの画面幅では、判定後にページが横にはみ出さないことも確かめる。表の枠は名前を持ち（`role="region"`と`aria-label`）、横にはみ出しているときだけフォーカスできる（`tabindex="0"`。画面幅や折りたたみの変化に合わせて判定し直す）。枠は`position: relative`にする（読み上げ用の非表示の文字が枠の外に出て、ページ全体の幅を広げた不具合があったため）。
- **性質のテスト**（`tests/properties.test.ts`。fast-check）：例ではなく、作った入力の全体で確かめる。突き合わせのキー（もう一度かけても変わらない、値（クエリ・フラグメント・ユーザー情報・パス引数）とパスのトークンを差し替えても変わらずトークンを含まない、パラメータ・貼り付けたターゲットの順番で変わらない、マスクを読み込まない）、マスク（秘密の置き場所（パラメータ、JSON、ユーザー情報、パス、JWT、nonce、ASP.NETのセッション）にある乱数のトークンを、前後の文字を変えても出さない、もう一度かけても変わらない、切り詰めはマスクした文字列の先頭だけ）、`#META cmd=`の実施コマンドの要約（`tests/cmd-summary.test.ts`。値の置き場所の乱数の秘密を、オプションの順番・区切り（空白・`_`）・プログラムの書き方を変えても出さない、出る語はどれも許可した形のどれか（許可する形は実装とは別にテストに書く。任意の文字列の入力でも）、もう一度かけても変わらない、長い入力でも線形の時間）、判定の結果（貼り付けたターゲットの順番を変えても指摘の集まりが変わらない）。回数は既定で数百回、手元では環境変数`FC_RUNS`で倍にして探す。見つけた反例は例のテスト（`tests/t7-keys.test.ts`など）に残す。
- **性能と耐性**（`tests/robustness.test.ts`）：1MBの通常の出力の解析・判定時間（計測値は約0.5秒。CIの差を見込んで上限6秒で検査）。悪意のある入力（`*`の多い例外のURLパターン、閉じていないタグが大量にある本文）でも短時間で終わること。fast-checkで、curlの出力の行の部品を組み合わせた壊れた入力と、壊れたJSONの設定ファイル（例外、プロファイル、前回の結果、HAR）で例外を出さないこと。fast-checkは導入時に、例外ファイルの`[null]`で落ちる不具合を見つけた。前回の結果・組織プロファイル・例外ファイルにおかしな値を入れて組み合わせても、Markdown・CSVに`undefined`などが出ないことも確かめる。前回の結果からは、差分で使う項目（ルールID・項目・ターゲット・キー・重要度・状態・題名・証跡）だけを、型を確かめて取り出す。
- **2乗の時間の見張り**（`tests/adversarial-perf.test.ts`）：よくある繰り返しの形（`<!--`・`ab.`・`a@`・`eyJ`・`%2B`・`#META `・ステータス行など約50種）を64KBずつ、HTMLとJSONの本文・CSP・Location・Set-Cookie・Serverのヘッダに置いて判定し、上限（判定4秒、差分・マスク・要約・キー1.5秒）に収まることを確かめる。第37回〜第39回の修正が毎回どこかに2乗の時間の処理を入れたので、個別の例ではなく形の組み合わせで見張る（第39回の版では11種が16〜105秒かかった）。重いので、ほかのテストが終わってから別に流す（`vite.config.ts`の`projects`。同時に流すと、時間を測るほかのテストが上限を超えた）。

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
| マスキング、プローブの判定パターン | `src/mask.ts`（名前と形で伏せる）、`src/shownText.ts`（画面・エクスポートに出す証跡とURLの許可リスト）、`src/tokenShape.ts`（英小文字のトークンとまれな2文字の並びの判定。突き合わせのキーと共有） |
| 差分・例外の突き合わせのキー | `src/engine/targetKey.ts` |
| CSVの実施コマンド・実施日時の要約 | `src/export/cmdSummary.ts` |
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
