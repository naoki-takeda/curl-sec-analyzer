// rules/hostRules.ts：ホスト単位のルール（T-09〜T-11、E-03）。同じホストの全ターゲットをまとめて判定する
import type { Finding, Rule, Severity, Status, Target } from '../model';
import { HTML_PROBE_PATHS, htmlProbe, probePattern } from './probes';
import { hasCertificate, nameMatches, parseOpenssl, type TlsInfo } from '../parser/openssl';
import { hostnameOf } from '../parser/target';
import { PROBE_UNREACHED_REC, cf } from './util';

const hf = (rule: Rule, host: string, cond: number | 'ok' | 'na', severity: Severity, status: Status, evidence: string, recommendation: string) =>
  cf(rule, host, cond, severity, status, evidence, recommendation, host);

/** 旧バージョン（TLS 1.1 以前）。-v の「SSL connection using SSLv3」も */
const OLD = /^(ssl3|sslv3|tls1(?:\.0)?|tls1\.1|tls1_1|tls1_0|tlsv1(?:\.0)?|tlsv1\.1)$/i;
const isOld = (v: string) => OLD.test(v.replace(/\s/g, ''));
/**
 * そのホストに TLS で接続できたと分かるか：新しいバージョン（1.2・1.3）か弱くない暗号のプローブで接続できた、curl -v で合意した、
 * openssl の出力に証明書がある。プロキシ経由の環境では curl はつながっても openssl（s_client）はつながらず、すべてのプローブが失敗する。
 * そのとき「旧バージョン・弱い暗号は拒否された」と合格にすると、高の条件を確かめずに合格にする
 */
const reachedTls = (ts: Target[], negotiated: number): boolean => negotiated > 0
  || ts.some(t => t.tlsProbes.some(p => p.result === 'accepted' && !isOld(p.version)) || t.cipherProbes.some(p => p.result === 'accepted'))
  || opensslCaptures(ts).some(c => hasCertificate(c.info));
const UNREACHED_TLS_REC = 'openssl が対象に届く環境（プロキシを通さない端末、-proxy の指定）で C12・C23 を実行し直す';
/**
 * ターゲットの -v の情報行のうち、そのホストへの接続のもの。-L で別のホスト（外部の SSO、apex から www）に移ると、そのホストの
 * 「SSL connection using」の行も同じターゲットに入る。-L で次のリクエストに移るときの curl の「Issue another request to this URL: '…'」で、
 * どのホストへの接続かをたどる（外部の SSO の TLS 1.1 を対象のホストの T-09① にしない）。「Connected to」はプロキシへの接続でも
 * 出るので使わない（プロキシ経由の採取で、対象のホストの TLS を失う）
 */
function ownInfo(t: Target, host: string): string[] {
  const want = hostnameOf(`https://${host}`); let cur = want; const out: string[] = [];
  for (const l of t.info) {
    const m = l.match(/^Issue another request to this URL: '([^']+)'/);
    if (m) cur = hostnameOf(m[1]) ?? cur;              // 読めない URL なら、いまのホストのまま
    if (cur === want) out.push(l);
  }
  return out;
}
export const tlsVersion: Rule = { id: 'T-09', title: 'TLSバージョン', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'IPA TLS暗号設定ガイドライン'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const probes = ts.flatMap(t => t.tlsProbes);
      // OpenSSL は TLS 1.0 を「TLSv1」と出す
      const negotiated = ts.flatMap(t => ownInfo(t, host)).map(l => l.match(/SSL connection using (TLSv1(?:\.\d)?|SSLv3)\b/)?.[1]).filter((v): v is string => !!v);
      if (!probes.length && !negotiated.length) continue;         // TLSの情報がないホストは適用外
      const oldProbes = probes.filter(p => isOld(p.version));
      // 同じバージョンのプローブが2回あっても（サンプルと採取を一緒に入れたとき）、証跡には1回だけ書く
      const accepted = oldProbes.filter(p => p.result === 'accepted');
      const errored = oldProbes.filter(p => p.result === 'error');
      // C4 で旧バージョンを合意した場合も、そのバージョンで接続できたので①にする（②の「TLS 1.3 非対応」だけにしない）
      const oldNegotiated = [...new Set(negotiated.filter(isOld))];
      if (accepted.length || oldNegotiated.length) out.push(hf(tlsVersion, host, 1, 'high', 'fail',
        [accepted.length ? `接続できた旧バージョン: ${[...new Set(accepted.map(p => p.version))].join(', ')}` : '', oldNegotiated.length ? `合意したバージョン: ${oldNegotiated.join(', ')}` : ''].filter(Boolean).join('、'),
        'TLS 1.2 と 1.3 だけを有効にする'));
      // 旧バージョンの一部が ok=err（手元の OpenSSL が非対応）なら、そのバージョンは試していないので合格にしない（設計書：ok=err は na。
      // tls1=err・tls1_1=0 では TLS 1.0 を確かめていない）
      else if (oldProbes.some(p => p.result === 'rejected') && errored.length)
        out.push(hf(tlsVersion, host, 'na', 'info', 'na', `旧バージョンの一部の接続可否が分からない（手元のOpenSSLが非対応: ${[...new Set(errored.map(p => p.version))].join(', ')}）`, '旧バージョンに対応した環境で C12 を実行する'));
      else if (oldProbes.some(p => p.result === 'rejected'))
        out.push(reachedTls(ts, negotiated.length) ? hf(tlsVersion, host, 'ok', 'info', 'pass', '旧バージョンは拒否された', '')
          : hf(tlsVersion, host, 'na', 'info', 'na', 'どのバージョンでも接続できなかった（旧バージョンを拒否したのか、openssl が対象に届かないのかが分からない）', UNREACHED_TLS_REC));
      else if (errored.length) out.push(hf(tlsVersion, host, 'na', 'info', 'na', '旧バージョンの接続可否が分からない（手元のOpenSSLが非対応）', '旧バージョンに対応した環境で C12 を実行する'));
      else if (probes.length) out.push(hf(tlsVersion, host, 'na', 'info', 'na', '旧バージョンの接続可否が分からない（旧バージョン（tls1・tls1_1）の #TLSPROBE がない）', 'C12（プロトコルごとの接続の確認）を採取する'));
      // プローブがなく、合意したバージョン（-v）が新しいだけなら、旧バージョンを受け入れるか（①）は分からない。② だけで「判定済み」と数えないよう、①は na として出す
      else out.push(hf(tlsVersion, host, 'na', 'info', 'na', '旧バージョンの接続可否が分からない（#TLSPROBE がない。合意したバージョンだけでは分からない）', 'C12（プロトコルごとの接続の確認）を採取する'));
      // TLS 1.3 のプローブ（#TLSPROBE v=tls1_3）で接続できたなら、合意が 1.2 なのは curl 側の事情（古い OpenSSL など）。②にしない
      const tls13 = probes.some(p => p.result === 'accepted' && /1[._]?3$/.test(p.version.replace(/\s/g, '')));
      if (negotiated.length && !negotiated.includes('TLSv1.3') && !tls13) out.push(hf(tlsVersion, host, 2, 'info', 'fail', `合意したバージョン: ${[...new Set(negotiated)].join(', ')}`, 'TLS 1.3 を有効にする（curl 側が 1.3 に対応しているかも確認）'));
    }
    return out;
  } };

export const knownFiles: Rule = { id: 'E-03', title: '既知ファイル（/.git、/.envなど）', appliesTo: 'any', scope: 'host',
  basis: ['OWASP WSTG-CONF-04', 'IPA'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const probes = ts.flatMap(t => t.probes);
      if (!probes.length) continue;
      const own = probes.filter(p => !/\/(robots|security)\.txt$/.test(p.path) && !/\.map$/.test(p.path));   // E-04・E-13 の対象は除く
      let fails = 0, html = 0;
      for (const p of own) {
        const hit = probePattern(p.path, p.headB64, p.code);
        if (hit?.item === 'E-03') { fails++; out.push(hf(knownFiles, host, 1, 'high', 'fail', `${p.path}（HTTP ${p.code}、一致したパターン: ${hit.name}）`, 'Webサーバの公開ディレクトリから削除するか、アクセスを拒否する')); }
        // HTML でない形式のファイルのパスに HTML の画面が返ったら、そのファイルではない（SPA の index.html、共通のエラー画面）
        else if (p.code === 200 && !HTML_PROBE_PATHS.test(p.path) && htmlProbe(p.headB64)) html++;
        else if (p.code === 200) { fails++; out.push(hf(knownFiles, host, 2, 'info', 'fail', `${p.path}（HTTP 200、中身はパターンに一致しない。どのパスにも200を返す可能性）`, '中身を手動で確認する')); }
      }
      // コード 000 は接続できなかった（タイムアウト・名前解決の失敗など）ことを示し、ファイルがないことは分からない。1件でもあれば合格にしない
      const unreached = own.filter(p => !p.code).length;
      if (!fails && unreached) out.push(hf(knownFiles, host, 'na', 'info', 'na', `${own.length}件のうち${unreached}件は接続できなかった（HTTP 000）`, PROBE_UNREACHED_REC));
      else if (!fails && own.length) out.push(hf(knownFiles, host, 'ok', 'info', 'pass', `${own.length}件のパスはいずれも取得できなかった${html ? `（うち${html}件は HTML の画面が返った。どのパスにも同じ画面を返す SPA など）` : ''}`, ''));
    }
    return out;
  } };

// 弱い暗号（①）。単一 DES（DES-CBC-SHA、IANA 名の _DES_）、EXP1024-… の輸出用、RC2、IANA 名の匿名の鍵交換（TLS_DH_anon_…・
// TLS_ECDH_anon_…）も含める（設計書は EXPORT・aNULL を①に置く）
const WEAK = /RC4|RC2|DES-CBC|_DES_|3DES|EXPORT|EXP-|EXP1024|NULL|ADH|AECDH|_anon_|MD5/i;
const AEAD = /GCM|CHACHA20|CCM|^TLS_AES/i;
// 前方秘匿性のある鍵交換（ECDHE・DHE）か、TLS 1.3 の暗号。AES128-GCM-SHA256 のような静的 RSA の鍵交換は、GCM でも③
const FORWARD_SECRET = /^(?:ECDHE|DHE|EDH|TLS_AES|TLS_CHACHA20|TLS_ECDHE|TLS_DHE)/i;
const modern = (c: string) => AEAD.test(c) && FORWARD_SECRET.test(c);
const T10_REC = 'C23（暗号ごとの接続の確認）と C11（証明書の取得）を採取する';
/**
 * 同じホストの openssl の出力（tls のターゲットなど）が複数あるときの順番。ターゲットの順番で T-10・T-11 の結果が変わらないよう、入力の順番に
 * よらず決める：証明書の情報があるもの → 採取した時刻（#META at）が新しいもの（時刻のないものは最後。capturedAt は時刻がなければ判定した
 * 時刻を返すので使わない） → ラベルの順
 */
function opensslCaptures(ts: Target[]): { t: Target; info: TlsInfo }[] {
  const at = (t: Target) => { const v = t.meta.at ? Date.parse(t.meta.at) : NaN; return Number.isNaN(v) ? -Infinity : v; };
  return ts.filter(t => t.openssl.length).map(t => ({ t, info: parseOpenssl(t.openssl), at: at(t) }))
    .filter((c): c is { t: Target; info: TlsInfo; at: number } => !!c.info)
    .sort((a, b) => Number(hasCertificate(b.info)) - Number(hasCertificate(a.info)) || (b.at === a.at ? 0 : b.at > a.at ? 1 : -1)
      || (a.t.label < b.t.label ? -1 : a.t.label > b.t.label ? 1 : 0));
}
export const cipherSuites: Rule = { id: 'T-10', title: '暗号スイート・鍵', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'IPA TLS暗号設定ガイドライン'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const probes = ts.flatMap(t => t.cipherProbes);
      // 鍵・署名の分かる出力を使う（x509 -noout だけの出力より、s_client -showcerts の出力）
      const caps = opensslCaptures(ts);
      const info = (caps.find(c => c.info.keyBits || c.info.sigalgs.length) ?? caps[0])?.info;
      const negotiated = ts.flatMap(t => ownInfo(t, host)).map(l => l.match(/SSL connection using (TLSv[\d.]+) \/ (\S+)/)).filter((m): m is RegExpMatchArray => !!m);
      if (!probes.length && !info && !negotiated.length) continue;
      const before = out.length;
      for (const p of probes.filter(p => p.result === 'accepted')) {
        if (WEAK.test(p.cipher)) out.push(hf(cipherSuites, host, 1, 'high', 'fail', `接続できた弱い暗号: ${p.cipher}`, 'RC4・3DES・NULL・EXPORT などを無効にする'));
        else if (!modern(p.cipher)) out.push(hf(cipherSuites, host, 3, 'medium', 'fail', `TLS 1.2で接続できたCBC・静的RSAの暗号: ${p.cipher}`, 'TLS 1.2 では ECDHE＋AEAD（AES-GCM、ChaCha20-Poly1305）だけにする'));
      }
      // 合意した暗号：TLS 1.3 以外（1.2 以下）で、弱い暗号なら①、CBC・静的RSAなら③（旧バージョンで合意した CBC も合格にしない）
      for (const [, ver, c] of negotiated) {
        if (ver === 'TLSv1.3') continue;
        if (WEAK.test(c)) out.push(hf(cipherSuites, host, 1, 'high', 'fail', `合意した弱い暗号: ${ver} / ${c}`, 'RC4・3DES・NULL・EXPORT などを無効にする'));
        else if (!modern(c)) out.push(hf(cipherSuites, host, 3, 'medium', 'fail', `合意した暗号: ${ver} / ${c}`, 'ECDHE＋AEAD の暗号を優先する'));
      }
      // ②鍵：OpenSSL 1.1・LibreSSL は「Server public key is N bit」だけで種類を出さない。256・384・521bit は楕円曲線、
      // 224bit は P-224、253bit は Ed25519、456bit は Ed448、それ以外は RSA とみなす（512bit は brainpoolP512r1 と RSA 512bit を区別できないので RSA とする）
      const ec = info?.keyType ? /^id-ec|^EC|ED25519|ED448/i.test(info.keyType) : [224, 253, 256, 384, 456, 521].includes(info?.keyBits ?? 0);
      if (info?.keyBits && !ec && info.keyBits < 2048) out.push(hf(cipherSuites, host, 2, 'high', 'fail', `RSA ${info.keyBits}bit${info.keyType ? '' : '（鍵の種類は長さから推定）'}`, 'RSA 2048bit 以上か ECDSA P-256 の鍵にする'));
      // ②署名：自己署名の証明書（ルート）の署名は対象外。チェーンの subject・issuer がなければ、2つ目以降の最後の証明書をルートとみなす
      const isRoot = (i: number) => (info?.certs[i]?.issuer ? info.certs[i].issuer === info.certs[i].subject : i > 0 && i === (info?.sigalgs.length ?? 0) - 1);
      const sha1 = info?.sigalgs.find((a, i) => /sha1/i.test(a) && !isRoot(i));
      if (sha1) out.push(hf(cipherSuites, host, 2, 'high', 'fail', `署名アルゴリズム: ${sha1}`, 'SHA-256 以上で署名した証明書にする'));
      if (out.length === before) {
        const errs = probes.filter(p => p.result === 'error').length;
        // 合格にするのは、何かを実際に確かめたときだけ（ハンドシェイクに失敗した openssl の出力だけでは判定できない）。
        // 合意した暗号（curl -v の * SSL connection、openssl の Cipher）だけでは、弱い暗号を受け入れるか（①）も鍵・署名（②）も分からないので合格にしない
        const checked = probes.length > errs || !!info?.keyBits || !!info?.sigalgs.length;
        const onlyNegotiated = !checked && (negotiated.length > 0 || !!info?.cipher);
        out.push(probes.length && errs === probes.length
          ? hf(cipherSuites, host, 'na', 'info', 'na', '手元のOpenSSLが試した暗号に対応していない', '弱い暗号に対応した環境で C23 を実行する')
          : probes.length && !reachedTls(ts, negotiated.length)
          ? hf(cipherSuites, host, 'na', 'info', 'na', 'どの暗号でも接続できなかった（弱い暗号を拒否したのか、openssl が対象に届かないのかが分からない）', UNREACHED_TLS_REC)
          : onlyNegotiated ? hf(cipherSuites, host, 'na', 'info', 'na', `合意した暗号（${[...new Set([...negotiated.map(m => `${m[1]} / ${m[2]}`), info?.cipher].filter(Boolean))].join(', ')}）だけでは、弱い暗号を受け入れるか・鍵と署名は分からない`, T10_REC)
          : !checked ? hf(cipherSuites, host, 'na', 'info', 'na', '暗号・鍵の情報がない（ハンドシェイクに失敗した可能性）', 'C11 の出力にエラーがないか確認して採取し直す')
          : hf(cipherSuites, host, 'ok', 'info', 'pass', [info?.cipher && `暗号: ${info.cipher}`, info?.keyBits && `鍵: ${info.keyType ?? ''} ${info.keyBits}bit`, probes.length > errs && `弱い暗号${probes.length - errs}種は拒否`,
            // ok=err（手元の OpenSSL が非対応。OpenSSL 1.1 以降は RC4・3DES を試せない）の暗号は、拒否に数えず、試していないと書く。
            // err は手元の openssl の標準エラーだけから作るので、サーバは作れない
            errs && `${[...new Set(probes.filter(p => p.result === 'error').map(p => p.cipher))].join(', ')} は手元のOpenSSLが非対応で試していない`].filter(Boolean).join(' / ') || '問題なし', ''));
      }
    }
    return out;
  } };

const DAY_MS = 86400e3;
/** #META at の日時の形（2026-11-01、2026-11-01T10:00:00、2026-11-01 10:00、末尾の Z・+09:00） */
const AT_SHOWN = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?(?=\s|$)/;
export const certificate: Rule = { id: 'T-11', title: '証明書', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'CA/Browser Forum Baseline Requirements'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const cap = opensslCaptures(ts)[0];
      if (!cap) continue;
      const { t: src, info } = cap;
      if (!hasCertificate(info)) { out.push(hf(certificate, host, 'na', 'info', 'na', '証明書の情報がない（ハンドシェイクに失敗した可能性）', 'C11 の出力にエラーがないか確認して採取し直す')); continue; }
      // 期限は採取した時刻（#META at）を基準にする。古い出力を読み直しても、採取時の状態で判定する。#META at がない・読めなければ判定した時刻
      // （応答の Date は使わない（capturedAt は使わない）。Date は診断対象のサーバが書くので、過去の Date（CDN のキャッシュの古い応答を含む）で、
      // 期限の近い・切れた証明書を合格にできてしまう。Cookie の期限（C-05）とは逆に、過去の基準が甘い向きになる）
      const at = Date.parse(src.meta.at ?? ''); const now = Number.isNaN(at) ? Date.now() : at;
      // 証跡には、読めた日時の形の部分だけを、書いてあるとおりに出す（日時のあとに書いた文字（認証情報など）を出さない。形を変えると、
      // 日付だけの値やタイムゾーン付きの値が、見る人の時刻でずれる）
      const atShown = src.meta.at?.trim().match(AT_SHOWN)?.[0];
      const asOf = atShown && !Number.isNaN(Date.parse(atShown)) ? `、${atShown} 時点` : '';
      const before = out.length;
      const hostname = host.replace(/:\d+$/, '');
      if (info.notAfter && info.notAfter.getTime() < now) out.push(hf(certificate, host, 1, 'high', 'fail', `期限切れ（notAfter: ${info.notAfter.toISOString().slice(0, 10)}${asOf}）`, '証明書を更新する（自動更新を設定する）'));
      else if (info.notAfter && info.notAfter.getTime() - now < 30 * DAY_MS) out.push(hf(certificate, host, 2, 'medium', 'fail', `期限まで${Math.ceil((info.notAfter.getTime() - now) / DAY_MS)}日（notAfter: ${info.notAfter.toISOString().slice(0, 10)}${asOf}）`, '証明書を更新する（自動更新を確認する）'));
      // 今のブラウザは CN を見ず、SAN だけでホスト名を確かめる（Chrome 58 以降）。SAN の拡張がないと分かる証明書は、CN が一致しても①。
      // SAN があるかが分からない出力（s_client だけで x509 -ext subjectAltName がない）では、CN で比べる
      if (info.sanExtension === false && info.subjectCN)
        out.push(hf(certificate, host, 1, 'high', 'fail', `SAN がない（CN: ${info.subjectCN}。ブラウザは CN を見ない）`, '対象ホストをSANに含む証明書にする'));
      const names = info.sans.length ? info.sans : info.subjectCN && info.sanExtension !== false ? [info.subjectCN] : [];
      if (names.length && !names.some(n => nameMatches(n, hostname))) out.push(hf(certificate, host, 1, 'high', 'fail', `ホスト名不一致（${hostname} / 証明書: ${names.join(', ')}）`, '対象ホストをSANに含む証明書にする'));
      if (info.verifyCode !== undefined && info.verifyCode !== 0) out.push(hf(certificate, host, 1, 'high', 'fail', `Verify return code: ${info.verifyCode}（${info.verifyText}）`, '信頼できるCAの証明書と、中間証明書を含むチェーンを設定する'));
      if (out.length === before) out.push(hf(certificate, host, 'ok', 'info', 'pass', `notAfter: ${info.notAfter?.toISOString().slice(0, 10) ?? '不明'} / SAN: ${names.join(', ') || '不明'}`, ''));
    }
    return out;
  } };
