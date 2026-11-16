// rules/hostRules.ts：ホスト単位のルール（T-09〜T-11、E-03）。同じホストの全ターゲットをまとめて判定する
import type { Finding, Rule, Severity, Status } from '../model';
import { probePattern } from '../mask';
import { hasCertificate, nameMatches, parseOpenssl } from '../parser/openssl';
import { capturedAt } from '../parser/target';
import { PROBE_UNREACHED_REC } from './util';

const hf = (rule: Rule, host: string, cond: number | 'ok' | 'na', severity: Severity, status: Status, evidence: string, recommendation: string): Finding =>
  ({ ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined, title: rule.title, severity, status,
     target: host, host, evidence, recommendation, references: rule.basis, score: 0 });

const OLD = /^(ssl3|tls1(?:\.0)?|tls1\.1|tls1_1|tls1_0|tlsv1(?:\.0)?|tlsv1\.1)$/i;
export const tlsVersion: Rule = { id: 'T-09', title: 'TLSバージョン', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'IPA TLS暗号設定ガイドライン'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const probes = ts.flatMap(t => t.tlsProbes);
      // OpenSSL は TLS 1.0 を「TLSv1」と出す
      const negotiated = ts.flatMap(t => t.info).map(l => l.match(/SSL connection using (TLSv1(?:\.\d)?|SSLv3)\b/)?.[1]).filter((v): v is string => !!v);
      if (!probes.length && !negotiated.length) continue;         // TLSの情報がないホストは適用外
      const accepted = probes.filter(p => p.result === 'accepted' && OLD.test(p.version.replace(/\s/g, '')));
      // C4 で旧バージョンを合意した場合も、そのバージョンで接続できたので①にする（②の「TLS 1.3 非対応」だけにしない）
      const oldNegotiated = [...new Set(negotiated.filter(v => OLD.test(v)))];
      if (accepted.length || oldNegotiated.length) out.push(hf(tlsVersion, host, 1, 'high', 'fail',
        [accepted.length ? `接続できた旧バージョン: ${accepted.map(p => p.version).join(', ')}` : '', oldNegotiated.length ? `合意したバージョン: ${oldNegotiated.join(', ')}` : ''].filter(Boolean).join('、'),
        'TLS 1.2 と 1.3 だけを有効にする'));
      else if (probes.some(p => OLD.test(p.version.replace(/\s/g, '')) && p.result === 'rejected')) out.push(hf(tlsVersion, host, 'ok', 'info', 'pass', '旧バージョンは拒否された', ''));
      else if (probes.length) out.push(hf(tlsVersion, host, 'na', 'info', 'na', '旧バージョンの接続可否が分からない（手元のOpenSSLが非対応）', '旧バージョンに対応した環境で C12 を実行する'));
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
      let fails = 0;
      for (const p of own) {
        const hit = probePattern(p.path, p.headB64, p.code);
        if (hit?.item === 'E-03') { fails++; out.push(hf(knownFiles, host, 1, 'high', 'fail', `${p.path}（HTTP ${p.code}、一致したパターン: ${hit.name}）`, 'Webサーバの公開ディレクトリから削除するか、アクセスを拒否する')); }
        else if (p.code === 200) { fails++; out.push(hf(knownFiles, host, 2, 'info', 'fail', `${p.path}（HTTP 200、中身はパターンに一致しない。どのパスにも200を返す可能性）`, '中身を手動で確認する')); }
      }
      // コード 000 は接続できなかった（タイムアウト・名前解決の失敗など）ことを示し、ファイルがないことは分からない。1件でもあれば合格にしない
      const unreached = own.filter(p => !p.code).length;
      if (!fails && unreached) out.push(hf(knownFiles, host, 'na', 'info', 'na', `${own.length}件のうち${unreached}件は接続できなかった（HTTP 000）`, PROBE_UNREACHED_REC));
      else if (!fails && own.length) out.push(hf(knownFiles, host, 'ok', 'info', 'pass', `${own.length}件のパスはいずれも取得できなかった`, ''));
    }
    return out;
  } };

// ---- 以下 v0.2 で追加（T-10、T-11） ----
const WEAK = /RC4|DES-CBC3|3DES|EXPORT|EXP-|NULL|aNULL|ADH|AECDH|MD5/i;
const AEAD = /GCM|CHACHA20|CCM|^TLS_AES/i;
export const cipherSuites: Rule = { id: 'T-10', title: '暗号スイート・鍵', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'IPA TLS暗号設定ガイドライン'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const probes = ts.flatMap(t => t.cipherProbes);
      const info = ts.map(t => parseOpenssl(t.openssl)).find(Boolean);
      const negotiated = ts.flatMap(t => t.info).map(l => l.match(/SSL connection using (TLSv[\d.]+) \/ (\S+)/)).filter((m): m is RegExpMatchArray => !!m);
      if (!probes.length && !info && !negotiated.length) continue;
      const before = out.length;
      for (const p of probes.filter(p => p.result === 'accepted')) {
        if (WEAK.test(p.cipher)) out.push(hf(cipherSuites, host, 1, 'high', 'fail', `接続できた弱い暗号: ${p.cipher}`, 'RC4・3DES・NULL・EXPORT などを無効にする'));
        else if (!AEAD.test(p.cipher)) out.push(hf(cipherSuites, host, 3, 'medium', 'fail', `TLS 1.2で接続できたCBC・静的RSAの暗号: ${p.cipher}`, 'TLS 1.2 では ECDHE＋AEAD（AES-GCM、ChaCha20-Poly1305）だけにする'));
      }
      // 合意した暗号：TLS 1.3 以外（1.2 以下）で、弱い暗号なら①、CBC・静的RSAなら③（旧バージョンで合意した CBC も合格にしない）
      for (const [, ver, c] of negotiated) {
        if (ver === 'TLSv1.3') continue;
        if (WEAK.test(c)) out.push(hf(cipherSuites, host, 1, 'high', 'fail', `合意した弱い暗号: ${ver} / ${c}`, 'RC4・3DES・NULL・EXPORT などを無効にする'));
        else if (!AEAD.test(c)) out.push(hf(cipherSuites, host, 3, 'medium', 'fail', `合意した暗号: ${ver} / ${c}`, 'ECDHE＋AEAD の暗号を優先する'));
      }
      // ②鍵：OpenSSL 1.1・LibreSSL は「Server public key is N bit」だけで種類を出さない。256・384・521bit は楕円曲線、
      // 224bit は P-224、253bit は Ed25519、456bit は Ed448、それ以外は RSA とみなす（512bit は brainpoolP512r1 と RSA 512bit を区別できないので RSA とする）
      const ec = info?.keyType ? /^id-ec|^EC|ED25519|ED448/i.test(info.keyType) : [224, 253, 256, 384, 456, 521].includes(info?.keyBits ?? 0);
      if (info?.keyBits && !ec && info.keyBits < 2048) out.push(hf(cipherSuites, host, 2, 'high', 'fail', `RSA ${info.keyBits}bit${info.keyType ? '' : '（鍵の種類は長さから推定）'}`, 'RSA 2048bit 以上か ECDSA P-256 の鍵にする'));
      // ②署名：自己署名の証明書（ルート）の署名は対象外。チェーンの subject・issuer がなければ、従来どおり2つ目以降の最後の証明書をルートとみなす
      const isRoot = (i: number) => (info?.certs[i]?.issuer ? info.certs[i].issuer === info.certs[i].subject : i > 0 && i === (info?.sigalgs.length ?? 0) - 1);
      const sha1 = info?.sigalgs.find((a, i) => /sha1/i.test(a) && !isRoot(i));
      if (sha1) out.push(hf(cipherSuites, host, 2, 'high', 'fail', `署名アルゴリズム: ${sha1}`, 'SHA-256 以上で署名した証明書にする'));
      if (out.length === before) {
        const errs = probes.filter(p => p.result === 'error').length;
        // 合格にするのは、何かを実際に確かめたときだけ（ハンドシェイクに失敗した openssl の出力だけでは判定できない）
        const checked = probes.length > errs || negotiated.length > 0 || !!info?.cipher || !!info?.keyBits || !!info?.sigalgs.length;
        out.push(probes.length && errs === probes.length
          ? hf(cipherSuites, host, 'na', 'info', 'na', '手元のOpenSSLが試した暗号に対応していない', '弱い暗号に対応した環境で C23 を実行する')
          : !checked ? hf(cipherSuites, host, 'na', 'info', 'na', '暗号・鍵の情報がない（ハンドシェイクに失敗した可能性）', 'C11 の出力にエラーがないか確認して採取し直す')
          : hf(cipherSuites, host, 'ok', 'info', 'pass', [info?.cipher && `暗号: ${info.cipher}`, info?.keyBits && `鍵: ${info.keyType ?? ''} ${info.keyBits}bit`, probes.length && `弱い暗号${probes.length}種は拒否`].filter(Boolean).join(' / ') || '問題なし', ''));
      }
    }
    return out;
  } };

const DAY_MS = 86400e3;
export const certificate: Rule = { id: 'T-11', title: '証明書', appliesTo: 'any', scope: 'host',
  basis: ['Mozilla Server Side TLS', 'CA/Browser Forum Baseline Requirements'],
  runCross(x) {
    const out: Finding[] = [];
    for (const [host, ts] of x.byHost()) {
      const src = ts.find(t => t.openssl.length);
      const info = src && parseOpenssl(src.openssl);
      if (!src || !info) continue;
      if (!hasCertificate(info)) { out.push(hf(certificate, host, 'na', 'info', 'na', '証明書の情報がない（ハンドシェイクに失敗した可能性）', 'C11 の出力にエラーがないか確認して採取し直す')); continue; }
      // 期限は採取した時刻（#META at）を基準にする。古い出力を読み直しても、採取時の状態で判定する
      const now = capturedAt(src);
      const asOf = src.meta.at ? `、${src.meta.at} 時点` : '';
      const before = out.length;
      const hostname = host.replace(/:\d+$/, '');
      if (info.notAfter && info.notAfter.getTime() < now) out.push(hf(certificate, host, 1, 'high', 'fail', `期限切れ（notAfter: ${info.notAfter.toISOString().slice(0, 10)}${asOf}）`, '証明書を更新する（自動更新を設定する）'));
      else if (info.notAfter && info.notAfter.getTime() - now < 30 * DAY_MS) out.push(hf(certificate, host, 2, 'medium', 'fail', `期限まで${Math.ceil((info.notAfter.getTime() - now) / DAY_MS)}日（notAfter: ${info.notAfter.toISOString().slice(0, 10)}${asOf}）`, '証明書を更新する（自動更新を確認する）'));
      const names = info.sans.length ? info.sans : info.subjectCN ? [info.subjectCN] : [];
      if (names.length && !names.some(n => nameMatches(n, hostname))) out.push(hf(certificate, host, 1, 'high', 'fail', `ホスト名不一致（${hostname} / 証明書: ${names.join(', ')}）`, '対象ホストをSANに含む証明書にする'));
      if (info.verifyCode !== undefined && info.verifyCode !== 0) out.push(hf(certificate, host, 1, 'high', 'fail', `Verify return code: ${info.verifyCode}（${info.verifyText}）`, '信頼できるCAの証明書と、中間証明書を含むチェーンを設定する'));
      if (out.length === before) out.push(hf(certificate, host, 'ok', 'info', 'pass', `notAfter: ${info.notAfter?.toISOString().slice(0, 10) ?? '不明'} / SAN: ${names.join(', ') || '不明'}`, ''));
    }
    return out;
  } };
