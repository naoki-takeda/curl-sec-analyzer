#!/usr/bin/env bash
# tests/fixtures/generated_local.txt を採り直す（Linux・WSL で実行する。OpenSSL を使う curl が要る。Windows の標準の curl（Schannel）は
# -v に TLS の版と暗号を出さないので使わない）。
#
# 使い方：コマンド生成器でホスト名 www.example.com、apex example.com、静的リソース /assets/app.js、検証環境の試験ありで作ったスクリプトを
# gen.sh として保存し、bash scripts/capture-fixture.sh gen.sh tests/fixtures/generated_local.txt を実行する。
#
# 診断対象の代わりに、openssl s_server -WWW のローカルの HTTPS サーバ（127.0.0.1:8443、www.example.com・example.com の自己署名の証明書）に
# 向けて実行する。curl には -k（自己署名）・--connect-to（どのホストも 127.0.0.1:8443 へ）・--max-time 3（s_server -WWW は POST などに
# 応答しないので長く待たない）を付け、openssl s_client の接続先も 127.0.0.1:8443 にする。外部には接続しない。
# login.txt は秘密の値の代わりに CANARY を含むダミーの値（ゴールデンのテストが、画面・エクスポートに出ないことを確かめる）
set -eu
GEN=$(realpath "$1"); OUT=$(realpath -m "$2")
W=$(mktemp -d /tmp/csa-capture.XXXXXX)
mkdir -p "$W/www" "$W/run" "$W/bin"
cd "$W"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 20 -subj '/CN=www.example.com' \
  -addext 'subjectAltName=DNS:www.example.com,DNS:example.com' 2>/dev/null
REAL_CURL=$(command -v curl); REAL_OPENSSL=$(command -v openssl)
cat > bin/curl <<EOF
#!/usr/bin/env bash
# -q は最初の引数でないと効かないので、先頭に残す
first=\$1; shift
exec "$REAL_CURL" "\$first" -k --connect-to ::127.0.0.1:8443 "\$@" --max-time 3
EOF
cat > bin/openssl <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do case \$a in www.example.com:443|example.com:443) args+=(127.0.0.1:8443) ;; *) args+=("\$a") ;; esac; done
exec "$REAL_OPENSSL" "\${args[@]}"
EOF
chmod +x bin/curl bin/openssl
( cd www && exec "$REAL_OPENSSL" s_server -accept 8443 -cert ../cert.pem -key ../key.pem -WWW -quiet ) >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$W"' EXIT
sleep 1
cd run
cp "$GEN" gen.sh
printf 'user=t&pass=CANARY1' > login.txt; chmod 600 login.txt
PATH="$W/bin:$PATH" bash gen.sh 2>/dev/null || true
cp out.txt "$OUT"
echo "wrote $(wc -l < out.txt) lines to $OUT"
