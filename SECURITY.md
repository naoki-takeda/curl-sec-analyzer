# セキュリティポリシー / Security policy

## このツールの脆弱性を報告する

curl-sec-analyzer 自体の脆弱性（マスキングの漏れ、XSS、外部への通信が発生する、など）を見つけた場合は、**公開の Issue には書かず**、GitHub の「Report a vulnerability」（Security タブ → Advisories）から非公開で報告してください。内容を確認し、修正とあわせて公開します。

報告に含めてほしいもの：

- 再現手順と、影響（どの情報が、どこに出るか）
- 再現用の入力。**実在のシステムの出力は使わず、値をダミーに置き換えたもの**にしてください

## 診断結果や curl の出力を共有するときの注意

- curl の `-v` の出力、HAR、`login.txt`、Cookie の jar には、パスワード・Cookie・トークンがそのまま入っています。**Issue・Pull Request・チャットに貼らないでください。**
- 誤検知や見落としを報告するときは、ツールの「保存（マスク済み）」で出力した Markdown か JSON を使い、URL やホスト名も必要に応じて伏せてください。
- マスク済みの診断結果にも、未修正の脆弱性の情報が含まれます。公開の場に出す前に、対象システムの管理者の了承を得てください。

## Reporting a vulnerability in this tool

Please do not open a public issue. Use GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab). Never include raw curl output, HAR files or credentials from real systems; replace values with dummies.
