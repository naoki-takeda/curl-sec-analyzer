// parser/input.ts：#TARGET 形式の貼り付けを解析する（-i、-D -、-v、-L、#META、#PROBE、#TLSPROBE、#CIPHERPROBE）
import type { HttpResponse, ParseResult, ParseWarning, Target } from '../model';
import { assignHopUrls, uniqueLabels } from './target';
import { cookieNames, sentAuthOf, splitSetCookie } from './setCookie';

const STATUS_RE = /^HTTP\/(1\.0|1\.1|2|3)(?:\.0)?\s+(\d{3})(?:\s+(.*))?$/;
const MARKER_RE = /^#(TARGET|META|PROBE|TLSPROBE|CIPHERPROBE)\b(.*)$/;   // 既知のマーカーだけ。他の # 行は本文
const OPENSSL_START = /^(CONNECTED\(|depth=|Certificate chain|subject=|issuer=|notBefore=|notAfter=)/;
// -v の出力の手がかり。今の curl は「*   Trying」（空白が3つ）や「* Established connection to」とも出すので、空白の数を問わない
const VERBOSE_HINT = /^\*\s+(Connected to|Established connection to|Trying|SSL connection|ALPN|Host )/;
const BODY_LIMIT = 64 * 1024;
// 改行のない本文（手で書いた curl -i の JSON・HTML）の直後にくっついたマーカー（{"id":1}#TARGET url=…）。分けないと、次のターゲットが
// 前の本文に吸い込まれて黙って消える。本文がたまたま「}#TARGET url=」を含むことはまずないので、JSON・HTML の閉じの直後だけを分ける
const STUCK_MARKER = /([}\]>])(#(?:TARGET|META)[ \t]+(?:url|label|at|cmd|response_code)=)/g;
// curl の進捗表示（-s を付けない実行で 2>&1 にしたもの）。見出しの行と数字の行は読み飛ばし、応答の行の前にくっついた部分は取り除く
// （遅い応答では、進捗表示とステータス行が同じ行に出て、ターゲットごと失われる）。時刻の欄（--:--:-- か 0:00:01）を手がかりにする
// 数字の行は欄が12個（% Total % Received % Xferd Dload Upload Total Spent Left Speed）。8個以上の数字の欄と時刻の欄を条件にし、
// 本文の日時の行（2026-11-01 12:00:00）を読み飛ばさないようにする
// 欄の並び：% Total、Total、% Received、Received、% Xferd、Xferd、Dload、Upload、時刻の欄（0〜3個）、Speed。
// 時刻の欄は curl の版で違う（--:--:--、0:00:02、curl 8.22 の 00:02、空欄）ので、あってもなくてもよい。% の欄は 0〜100
const PCT = String.raw`(?:100|\d{1,2})`, NUM = String.raw`[\d.]+[kMGTP]?`;
const METER = String.raw`^\s*${PCT}\s+${NUM}\s+${PCT}\s+${NUM}\s+${PCT}\s+${NUM}\s+${NUM}\s+${NUM}(?:\s+(?:--:--:--|\d+:\d\d(?::\d\d)?))*\s+${NUM}\s*`;
// 進捗表示だけの行は、時刻の欄が1つ以上あるものだけ（本文の「1 2 3 4 5 6 7 8 9」のような数字の行を読み飛ばさない）。
// 応答の行の前にくっついたもの（METER_PREFIX）は、直後がステータス行・送受信の行なので、時刻の欄がなくてもよい
const METER_LINE = new RegExp(String.raw`^\s*(?:% Total\s+% Received|Dload\s+Upload\s+Total)|^(?=.*\d:\d\d)${METER.slice(1)}$`);
const METER_PREFIX = new RegExp(String.raw`${METER}(?=(?:< )?HTTP\/[\d.]+ \d{3}|[<>*] )`);

// key=value を解析。ct= 以降は行末まで1つの値（空白を含むContent-Type対策）
export function attrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const ct = s.match(/(?:^|\s)ct=(.*)$/);
  if (ct) { out.ct = ct[1].trim(); s = s.slice(0, ct.index); }
  for (const kv of s.trim().split(/\s+/)) {
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return out;
}

const newTarget = (a: Record<string, string>): Target => ({
  label: a.label ?? 'default', url: a.url, kind: (['html', 'api'].includes(a.kind) ? a.kind : 'auto') as Target['kind'],
  sensitive: a.sensitive === '1' ? true : a.sensitive === '0' ? false : undefined,
  verbose: false, responses: [], sentAuth: false, sentTokens: [], info: [], meta: {}, probes: [], tlsProbes: [], cipherProbes: [], openssl: [],
});
const hasData = (t: Target) =>
  t.responses.length + t.probes.length + t.tlsProbes.length + t.cipherProbes.length + t.openssl.length > 0;
/** この応答のあとに次の応答が続きうるか（転送・1xx・認証のやり直し）。200 の本文の中のステータス行らしき行では分けない */
const nextHopAfter = (status: number) => status < 200 || (status >= 300 && status < 400) || status === 401 || status === 407;
const probeResult = (ok?: string): 'accepted' | 'rejected' | 'error' => (ok === '1' ? 'accepted' : ok === 'err' ? 'error' : 'rejected');

export function parseInput(input: string): ParseResult {
  const targets: Target[] = [];
  let t = newTarget({});
  let cur: HttpResponse | null = null, inHeaders = false, last = '', inOpenssl = false;
  let unparsed = 0; const emptyTargets: string[] = [];
  let json: string[] | null = null;                   // C10（%{header_json}）の読み取り中
  let jsonBytes = 0;
  let vBody = false;                                  // -v の受信ヘッダの終端（< の空行）のあと。次の「< HTTP/」の行までは本文として読み飛ばす
  let connectReq = false;                             // -v で「> CONNECT」を送った（プロキシのトンネル）。その応答のあとは本文がない
  const close = () => { if (cur) t.responses.push(cur); cur = null; inHeaders = false; last = ''; };
  const inBody = () => cur !== null && !inHeaders;
  const flush = () => { if (hasData(t)) targets.push(t); else if (t.label !== 'default') emptyTargets.push(t.label); };

  // 改行をそろえる。Windows の curl の -v（2>&1）は受信ヘッダの行を CR CR LF で終えるため、CR がいくつ続いても1つの改行にする
  // （CR CR LF を CR LF と CR に分けて読むと、受信ヘッダの各行のあとに空行ができ、ヘッダがすべて失われる）
  for (let line of input.replace(/\r+\n|\r/g, '\n').replace(STUCK_MARKER, '$1\n$2').split('\n')) {
    if (METER_LINE.test(line)) continue;
    line = line.replace(METER_PREFIX, '');
    const mk = line.match(MARKER_RE);
    if (mk) {                                          // マーカー行は必ず応答を閉じる
      close(); inOpenssl = false; vBody = false; if (json) { unparsed += json.length; json = null; }
      const [, tag, rest] = mk; const a = attrs(rest);
      if (tag === 'TARGET') { flush(); t = newTarget(a); }
      else if (tag === 'META') {
        Object.assign(t.meta, a);
        // %{header_json} のあとに出した response_code（-w '%{header_json}' のあとの #META）も、その応答のステータスにする
        if (a.response_code) for (const r of t.responses) if (r.status === 0 && r.reason === 'header_json') r.status = Number(a.response_code) || 0;
      }
      else if (tag === 'PROBE') t.probes.push({ path: a.path ?? '', code: +a.code, size: +a.size, contentType: a.ct ?? '', headB64: a.head ?? '' });
      else if (tag === 'CIPHERPROBE') t.cipherProbes.push({ cipher: a.c ?? '', result: probeResult(a.ok) });
      else t.tlsProbes.push({ version: a.v ?? '', result: probeResult(a.ok) });
      continue;
    }
    // -v で本文も出力した（-o /dev/null のない）場合、本文の行（ドキュメントの例の「HTTP/1.1 200 OK」、「* 」「> 」で始まる行など）を
    // 応答・情報行・送信ヘッダとして読まない。-L の次の応答は、curl が「< HTTP/」の形で出す
    // -L や認証のやり直しで curl が次のリクエストを送るときの印（「* Issue another request」、「> GET /x HTTP/1.1」の要求行）でも終える。
    // 終えないと、2つ目のホップの TLS（* SSL connection）や送信した Origin・Cookie を失う。本文の「* SSL connection …」だけの行では終えない
    if (t.verbose && vBody) {
      if (/^< HTTP\//.test(line) || /^\* Issue another request/.test(line) || /^> [A-Z]+ \S+ HTTP\/[\d.]+\s*$/.test(line)) vBody = false;
      else continue;
    }
    if (!inBody() && OPENSSL_START.test(line)) { close(); inOpenssl = true; }
    if (inOpenssl && !STATUS_RE.test(line) && !/^[*<>] /.test(line)) { t.openssl.push(line); continue; }
    inOpenssl = false;
    if (!inBody() && VERBOSE_HINT.test(line)) t.verbose = true;
    if (t.verbose && !inBody()) {                      // -v の解釈は verbose ターゲットのヘッダ部だけ
      // 受信ヘッダ（< の行）の途中の空行は無視する。終端は「<」の行で、空行ではない。
      // Windows の curl は受信ヘッダの行を CR CR LF で終え、画面の入力欄（textarea）はそれを改行2つ（空行）に変えるため、
      // 空行で閉じると受信ヘッダがすべて失われる（パーサの CR CR LF の扱いは、入力欄を通ると効かない）
      if (cur && inHeaders && !line.trim()) continue;
      if (line.startsWith('* ')) { t.info.push(line.slice(2)); continue; }
      if (line.startsWith('> ')) {
        const h = line.slice(2);
        if (/^CONNECT /i.test(h)) connectReq = true;
        const o = h.match(/^origin:\s*(.*)$/i); if (o) t.sentOrigin = o[1].trim();
        const ck = h.match(/^cookie:\s*(.*)$/i), au = /^authorization:/i.test(h);
        if (ck) t.sentCookieNames = [...new Set([...(t.sentCookieNames ?? []), ...cookieNames(ck[1])])];
        if (au) t.sentAuthorization = true;
        if (ck || au) { t.sentAuth = sentAuthOf(!!t.sentAuthorization, t.sentCookieNames ?? []); for (const tok of h.match(/\beyJ[\w-]+\.[\w-]+\.[\w-]*/g) ?? []) t.sentTokens.push(tok); }
        continue;
      }
      if (/^>\s*$/.test(line)) continue;               // 送信ヘッダの終端
      if (/^<\s*$/.test(line)) {
        // 1xx と、プロキシの CONNECT への応答（トンネル）のあとには本文がなく、本当のリクエスト（* SSL connection、> Cookie、> Origin）が続く。
        // そこを本文として読み飛ばすと、送信した Origin・Cookie や合意した TLS を失う
        const r = cur as HttpResponse | null;          // close() が書き換えるので、型の絞り込みに頼らない
        const st = r?.status ?? 0;
        const tunnel = st >= 200 && st < 300 && (connectReq || /connection established/i.test(r?.reason ?? ''));
        close(); vBody = st >= 200 && !tunnel; if (tunnel) connectReq = false;
        continue;
      }  // 受信ヘッダの終端。-v では本文を解析しない
      if (line.startsWith('< ')) line = line.slice(2);
      else if (/^[{}] \[/.test(line)) continue;
    }
    const sm = line.match(STATUS_RE);
    if (sm && !inBody()) { close(); cur = { httpVersion: sm[1], status: +sm[2], reason: sm[3], headers: new Map(), rawNames: [], kind: 'final' }; inHeaders = true; continue; }
    // 本文の直前の行が空行かは、本文の末尾だけを見る（本文全体を split すると、本文の中のステータス行らしい行ごとに64KBを分けることになり、入力の長さの2乗の時間がかかる）
    if (sm && inBody() && (cur!.body === undefined || nextHopAfter(cur!.status)) && /^\s*$/.test(lastLine(cur!.body ?? ''))) {   // -L で次のホップが続く場合
      close(); cur = { httpVersion: sm[1], status: +sm[2], reason: sm[3], headers: new Map(), rawNames: [], kind: 'final' }; inHeaders = true; continue;
    }
    // C10：ヘッダ名が小文字のJSON。-v の本文や、応答のあとの本文（{"items":[...]} など）は対象にしない
    if (!cur && !t.verbose && (json || (!t.responses.length && /^\s*\{\s*"[\w-]+"\s*:\s*\[/.test(line)))) {
      if (!json) { json = []; jsonBytes = 0; }
      json.push(line); jsonBytes += line.length;
      // JSON のオブジェクトは } で終わるので、そこまでは読み直さない（行ごとに全体をつないで解析すると、入力の長さの2乗の時間がかかる）
      // 上限は先に見る（} で終わる行が続くと、行ごとに全体をつないで解析し直し、入力の長さの2乗の時間がかかる）
      const r = jsonBytes > BODY_LIMIT ? null : /\}\s*$/.test(line) ? headerJson(json.join('\n'), t.meta.response_code) : undefined;
      // null：JSON としては読めたが、ヘッダの形ではない（curl -s で出力した API の本文など）。応答にせず、解析できない行として警告する
      if (r) { t.responses.push(r); json = null; } else if (r === null || json.length > 500) { unparsed += json.length; json = null; }
      continue;
    }
    if (!cur) { if (line.trim()) unparsed++; continue; }
    if (!inHeaders) {                                  // 本文は先頭64KBまで。1行が長い本文（圧縮したHTMLなど）も途中で切る
      const room = BODY_LIMIT - (cur.body?.length ?? 0);
      if (room > 0) cur.body = (cur.body ?? '') + (line.length < room ? `${line}\n` : line.slice(0, room));
      continue;
    }
    if (line.trim() === '') { inHeaders = false; continue; }
    if (/^[ \t]/.test(line) && last) { const v = cur.headers.get(last)!; v[v.length - 1] = `${v[v.length - 1]} ${line.trim()}`.trim(); continue; }  // obs-fold
    const i = line.indexOf(':'); if (i <= 0) continue;
    const raw = line.slice(0, i).trim(); last = raw.toLowerCase(); cur.rawNames.push(raw);
    const val = line.slice(i + 1).trim();
    // 値を push(...) に広げない（5MB の Set-Cookie の行で、引数が多すぎてスタックがあふれ、解析全体が止まった）
    const list = cur.headers.get(last) ?? cur.headers.set(last, []).get(last)!;
    for (const x of last === 'set-cookie' ? splitSetCookie(val) : [val]) list.push(x);
  }
  close(); flush();
  for (const tg of targets) tg.responses.forEach((r, i) => {
    // CONNECT（プロキシ）の応答：理由句が「Connection established」のもの。理由句が違っても、本文のない 2xx のあとに応答が続くなら、それはプロキシの応答
    const proxyReply = r.status >= 200 && r.status < 300 && i < tg.responses.length - 1 && !r.body?.trim() && r.reason !== 'header_json';
    // プロキシの認証要求（407）と、curl が認証し直した 401 のあとには、同じリクエストの応答が続く。その URL 自身の応答ではないので、
    // 最初の応答（T-04・A-01・C-09・C-12 などが見るステータス）にしない。プロキシの 407 を最初の応答にすると、T-04 が「HTTP を拒否」と合格にする
    const retried = i < tg.responses.length - 1;
    if (r.status > 0 && r.status < 200) r.kind = 'informational';
    else if ((r.status === 200 && /connection established/i.test(r.reason ?? '')) || proxyReply || (r.status === 407 && retried)) r.kind = 'connect';
    else if (r.status === 401 && retried) r.kind = 'challenge';
    else if (r.status >= 300 && r.status < 400 && r.headers.has('location')) r.kind = 'redirect';
    if (r.body !== undefined && !r.body.trim()) r.body = undefined;
  });
  for (const tg of targets) assignHopUrls(tg);
  const dup = uniqueLabels(targets);
  return { targets, warnings: [...dup, ...collectWarnings(targets, unparsed, emptyTargets)] };
}

// %{header_json} にほぼ必ずある応答ヘッダ。どれもない JSON（{"tags":["a"]} など）はヘッダとみなさない
const TYPICAL_HEADER = /^(?:date|content-type|content-length|server|cache-control|set-cookie|strict-transport-security|vary|etag|last-modified|location|expires|age|via|connection|transfer-encoding)$/;
/**
 * curl -w '%{header_json}' の出力。ステータスは #META response_code（C5の -w）から取る。なければ0（不明。あとの #META で補う）。
 * undefined：まだ JSON として読めない（続きの行を待つ）。
 * null：JSON だがヘッダの形ではない（名前がヘッダに使える文字、値が文字列の配列、よくあるヘッダを含む、のどれかを満たさない）
 */
function headerJson(text: string, code?: string): HttpResponse | null | undefined {
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return undefined; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const entries = Object.entries(obj as Record<string, unknown>);
  const isHeaders = entries.some(([k]) => TYPICAL_HEADER.test(k.toLowerCase()))
    && entries.every(([k, v]) => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(k) && Array.isArray(v) && v.every(x => typeof x === 'string'));
  if (!isHeaders) return null;
  const headers = new Map<string, string[]>();
  for (const [k, v] of entries)
    headers.set(k.toLowerCase(), k.toLowerCase() === 'set-cookie' ? (v as string[]).flatMap(splitSetCookie) : (v as string[]));
  return { httpVersion: '', status: Number(code) || 0, reason: 'header_json', headers, rawNames: [...headers.keys()], kind: 'final' };
}

/** 本文の最後の行（本文は「行 + 改行」でつなぐので、最後の改行の前の行。body.split('\n').at(-2) と同じ）。改行がなければ空 */
function lastLine(body: string): string {
  const e = body.lastIndexOf('\n');
  return e < 0 ? '' : body.slice(body.lastIndexOf('\n', e - 1) + 1, e);
}

function collectWarnings(targets: Target[], unparsed: number, emptyTargets: string[]): ParseWarning[] {
  const w: ParseWarning[] = [];
  if (unparsed) w.push({ kind: 'unparsed-lines', detail: `どのターゲットにも属さない行が${unparsed}行ありました（HTTPのステータス行より前の行など）` });
  for (const l of emptyTargets) w.push({ kind: 'orphan-block', detail: `#TARGET label=${l} にデータがありません` });
  for (const t of targets) if (!t.url && !t.meta.url_effective)
    w.push({ kind: 'unknown-url', label: t.label, detail: `ターゲット「${t.label}」のURLが分かりません。HTTPSかどうかを使う項目は判定できません（#TARGET に url= を付けてください）` });
  for (const t of targets) for (const p of [...t.tlsProbes, ...t.cipherProbes]) if (p.result === 'error')
    w.push({ kind: 'tls-probe-error', detail: `ターゲット「${t.label}」：手元のOpenSSLが対応していないプローブがあります（判定不能）` });
  return w;
}
