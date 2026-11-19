#!/usr/bin/env bash
# tests/fixtures/generated_local.txt を採り直す（Linux・WSL で実行する。OpenSSL を使う curl と python3 が要る。Windows の標準の curl（Schannel）は
# -v に TLS の版と暗号を出さないので使わない）。
#
# 使い方：コマンド生成器でホスト名 www.example.com、apex example.com、静的リソース /assets/app.js、検証環境の試験ありで作ったスクリプトを
# gen.sh として保存し、bash scripts/capture-fixture.sh gen.sh tests/fixtures/generated_local.txt を実行する。
#
# 診断対象の代わりに、openssl s_server -WWW のローカルの HTTPS サーバ（127.0.0.1 の空いているポートだけで待ち受ける。www.example.com・
# example.com の自己署名の証明書）に向けて実行する。curl には -k（自己署名）・--connect-to（どのホストもそのポートへ）・--max-time 3
# （s_server -WWW は POST などに応答しないので長く待たない）を付け、openssl s_client の接続先もそのポートにする。外部には接続しない：
# gen.sh のホストが www.example.com・example.com でなければ止め（openssl のラッパーが置き換えるのはこの2つだけ）、サーバがこのスクリプトの
# s_server として応答することを確かめてから実行する（同じポートのほかのサービスに、ログインの POST や検証環境の試験を送らない）。
# login.txt は秘密の値の代わりに CANARY を含むダミーの値（s_server -WWW は POST に応答しないので、今の採取では out.txt に入らない）
set -eu
GEN=$(realpath "$1"); OUT=$(realpath -m "$2")
for h in $(grep -oE "#TARGET url=https?://[^/ '\"]+" "$GEN" | sed -E 's|.*://||' | sort -u); do
  case $h in www.example.com|example.com) ;; *) echo "gen.sh のホスト $h は www.example.com・example.com ではありません" >&2; exit 1 ;; esac
done
W=$(mktemp -d /tmp/csa-capture.XXXXXX)
SERVER=''
# 後始末は set -e でも最後まで行う（s_server がすでに終わっていて kill が失敗しても、一時ディレクトリ（鍵・login.txt・jar.txt）を消す）
trap 'if [ -n "$SERVER" ]; then kill "$SERVER" 2>/dev/null || true; fi; rm -rf "$W"' EXIT
mkdir -p "$W/www" "$W/run" "$W/bin"
cd "$W"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 20 -subj '/CN=www.example.com' \
  -addext 'subjectAltName=DNS:www.example.com,DNS:example.com' 2>/dev/null
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
REAL_CURL=$(command -v curl); REAL_OPENSSL=$(command -v openssl)
cat > bin/curl <<EOF
#!/usr/bin/env bash
# -q は最初の引数でないと効かないので、先頭に残す
first=\$1; shift
exec "$REAL_CURL" "\$first" -k --connect-to ::127.0.0.1:$PORT "\$@" --max-time 3
EOF
cat > bin/openssl <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do case \$a in www.example.com:443|example.com:443) args+=(127.0.0.1:$PORT) ;; *) args+=("\$a") ;; esac; done
exec "$REAL_OPENSSL" "\${args[@]}"
EOF
chmod +x bin/curl bin/openssl
( cd www && exec "$REAL_OPENSSL" s_server -accept "127.0.0.1:$PORT" -cert ../cert.pem -key ../key.pem -WWW -quiet ) >/dev/null 2>&1 &
SERVER=$!
# このスクリプトの s_server が応答するまで待つ（-WWW は、ないファイルに「Error opening」の平文を返す）。起動しなければ止める
ok=''
for _ in $(seq 50); do
  kill -0 "$SERVER" 2>/dev/null || break
  if "$REAL_CURL" -sk --max-time 2 "https://127.0.0.1:$PORT/csa-capture-check" | grep -q "Error opening 'csa-capture-check'"; then ok=1; break; fi
  sleep 0.2
done
[ -n "$ok" ] || { echo "ローカルの s_server（127.0.0.1:$PORT）が起動しませんでした" >&2; exit 1; }
cd run
cp "$GEN" gen.sh
printf 'user=t&pass=CANARY1' > login.txt; chmod 600 login.txt
PATH="$W/bin:$PATH" bash gen.sh 2>/dev/null || true
cp out.txt "$OUT"
echo "wrote $(wc -l < out.txt) lines to $OUT"
