// parser/openssl.ts：openssl s_client（-showcerts）と openssl x509 -noout の出力から、T-10②・T-11 に使う値を取り出す
export interface TlsInfo {
  protocol?: string; cipher?: string;
  verifyCode?: number; verifyText?: string;
  notAfter?: Date; notBefore?: Date;
  subjectCN?: string; sans: string[];
  keyType?: string; keyBits?: number;      // リーフ証明書の公開鍵
  sigalgs: string[];                       // チェーンの署名アルゴリズム（リーフから順に）
  certs: { subject: string; issuer?: string }[];   // -showcerts のチェーン（リーフから順に）。自己署名（ルート）の判定に使う
  chainDepth: number;
  noPeerCert: boolean;                     // 「no peer certificate available」（ハンドシェイクに失敗し、証明書を受け取っていない）
  /**
   * リーフ証明書に SAN の拡張があるか。分からなければ undefined。-showcerts の最初の PEM に SAN の OID（2.5.29.17）があるかで見る。
   * PEM がなければ、SAN の行があれば true、なければ undefined（x509 を -ext subjectAltName なしで実行した出力と区別できないため、false にしない）
   */
  sanExtension?: boolean;
}

/**
 * DER の中に SAN の拡張の OID（06 03 55 1D 11）があるか。PEM を読めないか、途中で切れている（外側の SEQUENCE の長さと
 * 合わない）なら undefined。切れた PEM で「SAN がない」とすると、T-11①（高）の誤検知になる
 */
function pemHasSan(b64: string): boolean | undefined {
  let der: string;
  try { der = atob(b64); } catch { return undefined; }
  if (der.includes('\x06\x03\x55\x1d\x11')) return true;
  if (der.charCodeAt(0) !== 0x30 || der.length < 2) return undefined;
  const b1 = der.charCodeAt(1); let len = b1, head = 2;
  if (b1 & 0x80) { const n = b1 & 0x7f; if (n < 1 || n > 3) return undefined; len = 0; for (let i = 0; i < n; i++) len = len * 256 + der.charCodeAt(2 + i); head = 2 + n; }
  return head + len === der.length ? false : undefined;
}

/** 証明書の情報が1つでもあるか。ハンドシェイクに失敗した出力では false（T-11 は na にする） */
export const hasCertificate = (i: TlsInfo) => !i.noPeerCert && !!(i.notAfter || i.sans.length || i.subjectCN || i.chainDepth);

/** OpenSSL 3.5 が長さの代わりに出す曲線の名前と、その鍵の長さ（T-10② は長さで RSA と EC を見分けるので、EC だと分かれば十分） */
const CURVE_BITS: Record<string, number> = { prime256v1: 256, secp256r1: 256, secp384r1: 384, secp521r1: 521, secp224r1: 224, x25519: 253, ed25519: 253, x448: 456, ed448: 456,
  brainpoolp256r1: 256, brainpoolp384r1: 384, brainpoolp512r1: 512 };

const date = (s: string) => { const d = new Date(s.replace(/\s+/g, ' ').trim()); return Number.isNaN(d.getTime()) ? undefined : d; };

export function parseOpenssl(lines: string[]): TlsInfo | undefined {
  if (!lines.length) return undefined;
  const info: TlsInfo = { sans: [], sigalgs: [], certs: [], chainDepth: 0, noPeerCert: false };
  let sanNext = false, sanLine = false;
  // -showcerts の最初の証明書（リーフ）の PEM。見るのは最初の PEM だけで、途中に空行などが入って切れたら使わない
  // （次の PEM は中間 CA の証明書で、それを「リーフ」として SAN がないと判定してしまうため）
  let pem: string[] | undefined, firstPem: string | undefined, pemSeen = false;
  let cur = -1;                            // 直前の「N s:」の証明書の番号（a: の行をその証明書に対応させる）
  let afterSummary = false;                // s_client のハンドシェイクの要約（最初の Verify return code:）のあと
  let noCipher = false;                    // ハンドシェイクに失敗したセッション（Cipher : 0000・Cipher is (NONE)）
  for (const raw of lines) {
    const l = raw.trim();
    if (pem) {
      if (l === '-----END CERTIFICATE-----') { firstPem = pem.join(''); pem = undefined; continue; }
      if (/^[A-Za-z0-9+/=]+$/.test(l)) { pem.push(l); continue; }
      pem = undefined;                     // 切れた PEM は使わない
    }
    if (l === '-----BEGIN CERTIFICATE-----') { if (!pemSeen) { pemSeen = true; pem = []; } continue; }
    // IP アドレスの SAN（IP Address:192.0.2.10）も読む（読まないと、IP アドレスで接続する証明書を、ブラウザが見ない CN で比べてホスト名不一致にした）
    if (sanNext) { for (const m of l.matchAll(/(?:DNS|IP Address):([^,\s]+)/g)) info.sans.push(m[1].toLowerCase()); sanNext = false; continue; }   // push(...) に広げない（長い行でスタックがあふれる）
    let m: RegExpMatchArray | null;
    if ((m = l.match(/^Protocol\s*:\s*(\S+)/))) info.protocol ??= m[1];
    // 「New, <版>, Cipher is <暗号>」の版は、その暗号を使える最小の版で、合意した版ではない（TLS 1.2 の接続で New, SSLv3, Cipher is AES128-SHA、
    // New, TLSv1.0, Cipher is ECDHE-RSA-AES128-SHA と出る）。版として使うのは TLS 1.3 の暗号（TLS 1.3 でしか使えない）のときだけで、
    // それ以外は Protocol の行で読む（OpenSSL 1.1.1・3.0 は TLS 1.3 の接続で Protocol の行を出さない）
    else if ((m = l.match(/^New, (TLSv[\d.]+|SSLv3), Cipher is (\S+)/))) { if (m[1] === 'TLSv1.3') info.protocol ??= m[1]; info.cipher ??= m[2]; }
    // 失敗したハンドシェイクの「Cipher : 0000」「Cipher : (NONE)」は暗号ではない（0000 を合意した暗号として T-10 の証跡に出した）
    else if ((m = l.match(/^Cipher\s*:\s*(\S+)/))) { if (/^(?:0+|\(NONE\))$/i.test(m[1])) noCipher = true; else info.cipher ??= m[1]; }
    else if (/^New, \(NONE\), Cipher is \(NONE\)/.test(l)) noCipher = true;
    else if ((m = l.match(/^Verify return code:\s*(\d+)\s*\((.*)\)/))) { info.verifyCode ??= Number(m[1]); info.verifyText ??= m[2]; afterSummary = true; }
    // notAfter・SAN は、後ろのもの（x509 の出力。s_client のあとに実行する）を使う。s_client のあとにサーバが送ったデータ（手で採取した、切っていない
    // 出力）は x509 の出力より前に出るので、後ろのものが本物になる
    else if ((m = l.match(/^notAfter=(.+)$/))) info.notAfter = date(m[1]);
    else if ((m = l.match(/^notBefore=(.+)$/))) info.notBefore = date(m[1]);
    else if ((m = l.match(/^subject=.*?CN\s*=\s*([^,/]+)/))) info.subjectCN ??= m[1].trim().toLowerCase();
    // SAN は最後の X509v3 Subject Alternative Name: の行のものだけ（前のものを足し続けると、サーバが送った「DNS:victim.example」でホスト名の不一致を隠せた）
    else if (/^X509v3 Subject Alternative Name:/.test(l)) { sanNext = true; sanLine = true; info.sans = []; }
    else if (afterSummary) continue;
    // ここから下（証明書のチェーン・鍵）は、s_client のハンドシェイクの要約（最初の Verify return code: まで）の中にだけ出る。それより後ろの同じ形の行は、
    // サーバがハンドシェイクのあとに送ったデータ（a:PKEY: で鍵の長さと署名を上書きし、T-10②（高）を合格にできた）
    else if ((m = l.match(/^v:NotBefore: (.+?); NotAfter: (.+)$/)) && info.chainDepth === 1) { info.notBefore ??= date(m[1]); info.notAfter ??= date(m[2]); }
    else if ((m = l.match(/^(\d+) s:(.*)$/))) { cur = Number(m[1]); info.chainDepth = Math.max(info.chainDepth, cur + 1); info.certs[cur] = { subject: m[2].trim() }; }
    else if ((m = l.match(/^i:(.*)$/)) && info.certs.length) info.certs[info.certs.length - 1].issuer = m[1].trim();
    else if (/no peer certificate available/i.test(l)) info.noPeerCert = true;
    // OpenSSL 3 の -showcerts。鍵の種類には id-ecPublicKey・RSASSA-PSS のようにハイフンを含むものがある。
    // OpenSSL 3.5 は EC 鍵の長さを出さず、曲線の名前を出す（a:PKEY: EC, (prime256v1); sigalg: …）。読めないと署名がずれ、ルートの SHA-1 を T-10② にした。
    // 署名は証明書の番号の位置に入れる（読めない行があっても、ルート証明書の判定（T-10②）がずれないように）
    else if ((m = l.match(/^a:PKEY: ([\w-]+), (?:(\d+) \(bit\)|\(([\w-]+)\)); sigalg: (\S+)/))) {
      const i = cur >= 0 ? cur : info.sigalgs.length;
      if (i === 0) { info.keyType = m[1]; info.keyBits = m[2] ? Number(m[2]) : CURVE_BITS[m[3].toLowerCase()]; }
      info.sigalgs[i] = m[4];
    }
    else if ((m = l.match(/^Server public key is (\d+) bit/))) info.keyBits ??= Number(m[1]);
  }
  // 暗号を合意しなかったセッションの「Protocol : TLSv1.2」は、試みた版で、合意した版ではない
  if (noCipher && !info.cipher) info.protocol = undefined;
  // x509 -ext subjectAltName の出力に SAN の行があれば、PEM によらず SAN はある
  info.sanExtension = sanLine || info.sans.length ? true : firstPem ? pemHasSan(firstPem) : undefined;
  return info;
}

/** 証明書の名前（ワイルドカード対応）がホスト名に一致するか */
export function nameMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase(), h = host.toLowerCase();
  if (p === h) return true;
  // IPv6 のアドレス（SAN の IP Address:2001:DB8:0:0:0:0:0:1 と、URL のホスト [2001:db8::1]）は、書き方をそろえて比べる
  if (p.includes(':') && h.includes(':')) { const v6 = (a: string) => { try { return new URL(`http://[${a.replace(/^\[|\]$/g, '')}]/`).hostname; } catch { return a; } }; return v6(p) === v6(h); }
  if (!p.startsWith('*.')) return false;
  const rest = p.slice(2);
  return h.endsWith(`.${rest}`) && !h.slice(0, -rest.length - 1).includes('.');
}
