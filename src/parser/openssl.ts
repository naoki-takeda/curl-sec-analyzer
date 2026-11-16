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
}

/** 証明書の情報が1つでもあるか。ハンドシェイクに失敗した出力では false（T-11 は na にする） */
export const hasCertificate = (i: TlsInfo) => !i.noPeerCert && !!(i.notAfter || i.sans.length || i.subjectCN || i.chainDepth);

const date = (s: string) => { const d = new Date(s.replace(/\s+/g, ' ').trim()); return Number.isNaN(d.getTime()) ? undefined : d; };

export function parseOpenssl(lines: string[]): TlsInfo | undefined {
  if (!lines.length) return undefined;
  const info: TlsInfo = { sans: [], sigalgs: [], certs: [], chainDepth: 0, noPeerCert: false };
  let sanNext = false;
  let cur = -1;                            // 直前の「N s:」の証明書の番号（a: の行をその証明書に対応させる）
  for (const raw of lines) {
    const l = raw.trim();
    if (sanNext) { info.sans.push(...[...l.matchAll(/DNS:([^,\s]+)/g)].map(m => m[1].toLowerCase())); sanNext = false; continue; }
    let m: RegExpMatchArray | null;
    if ((m = l.match(/^Protocol\s*:\s*(\S+)/))) info.protocol ??= m[1];
    else if ((m = l.match(/^New, (TLSv[\d.]+|SSLv3), Cipher is (\S+)/))) { info.protocol ??= m[1]; info.cipher ??= m[2]; }
    else if ((m = l.match(/^Cipher\s*:\s*(\S+)/))) info.cipher ??= m[1];
    else if ((m = l.match(/^Verify return code:\s*(\d+)\s*\((.*)\)/))) { info.verifyCode ??= Number(m[1]); info.verifyText ??= m[2]; }
    else if ((m = l.match(/^notAfter=(.+)$/))) info.notAfter = date(m[1]);
    else if ((m = l.match(/^notBefore=(.+)$/))) info.notBefore = date(m[1]);
    else if ((m = l.match(/^v:NotBefore: (.+?); NotAfter: (.+)$/)) && info.chainDepth === 1) { info.notBefore ??= date(m[1]); info.notAfter ??= date(m[2]); }
    else if ((m = l.match(/^subject=.*?CN\s*=\s*([^,/]+)/))) info.subjectCN ??= m[1].trim().toLowerCase();
    else if (/^X509v3 Subject Alternative Name:/.test(l)) sanNext = true;
    else if ((m = l.match(/^(\d+) s:(.*)$/))) { cur = Number(m[1]); info.chainDepth = Math.max(info.chainDepth, cur + 1); info.certs[cur] = { subject: m[2].trim() }; }
    else if ((m = l.match(/^i:(.*)$/)) && info.certs.length) info.certs[info.certs.length - 1].issuer = m[1].trim();
    else if (/no peer certificate available/i.test(l)) info.noPeerCert = true;
    // OpenSSL 3 の -showcerts。鍵の種類には id-ecPublicKey・RSASSA-PSS のようにハイフンを含むものがある。
    // 署名は証明書の番号の位置に入れる（読めない行があっても、ルート証明書の判定（T-10②）がずれないように）
    else if ((m = l.match(/^a:PKEY: ([\w-]+), (\d+) \(bit\); sigalg: (\S+)/))) {
      const i = cur >= 0 ? cur : info.sigalgs.length;
      if (i === 0) { info.keyType = m[1]; info.keyBits = Number(m[2]); }
      info.sigalgs[i] = m[3];
    }
    else if ((m = l.match(/^Server public key is (\d+) bit/))) info.keyBits ??= Number(m[1]);
  }
  return info;
}

/** 証明書の名前（ワイルドカード対応）がホスト名に一致するか */
export function nameMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase(), h = host.toLowerCase();
  if (p === h) return true;
  if (!p.startsWith('*.')) return false;
  const rest = p.slice(2);
  return h.endsWith(`.${rest}`) && !h.slice(0, -rest.length - 1).includes('.');
}
