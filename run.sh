#!/usr/bin/env bash
# run.sh：curl の出力を #TARGET 形式でまとめて out.txt に書き出す（設計書「推奨コマンド」）
# 使い方：HOST を書き換えて bash run.sh。out.txt をツールで読み込んだら削除する（rm -f out.txt jar.txt）
# 簡易版。ログインの流れや CORS・TLS を含む推奨コマンドは、ツールの「コマンドを作る」で生成する
set -u
umask 077                         # out.txt と jar.txt を本人だけが読めるようにする（設計書 0.5）
rm -f out.txt                     # umask は新しく作るファイルにだけ効くので、前からある out.txt は消してから作る
HOST=${HOST:-www.example.com}
H=https://$HOST
# 実行ごとの印。ツールは最初の #TARGET と同じ印のマーカー行だけを読む（応答の本文に書かれた #TARGET を読まないため）
RUN=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

# t <label> <url> <sensitive(1/0/空)> <curlの引数...>
t() { local label=$1 url=$2 s=$3; shift 3
  echo "#TARGET url=$url label=$label${s:+ sensitive=$s} run=$RUN"
  echo "#META at=$(date +%Y-%m-%dT%H:%M:%S) run=$RUN"
  curl -q -sS --connect-timeout 10 --max-time 30 "$@" "$url" 2>&1; echo; }   # -q：~/.curlrc を読まない（最初の引数）

{
  t top          "$H/"            ""  -v -o /dev/null
  t http         "http://${HOST%:*}/" "" -L -D - -o /dev/null   # ポートを除く（http は 80 番）
  t notfound     "$H/no-such-page-csa404" "" -D - -o /dev/null
  t cors-reflect "$H/"            ""  -v -o /dev/null -H 'Origin: https://evil.example'
  # 認証後のページ（Cookie は jar.txt から渡す。jar.txt はブラウザやログイン手順で用意し、chmod 600 にする）
  # t mypage     "$H/mypage"      1   -v -o /dev/null -b jar.txt
} > out.txt
echo "out.txt に書き出しました。ツールで読み込んだら削除してください：rm -f out.txt" >&2
