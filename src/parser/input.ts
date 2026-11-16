// parser/input.ts：#TARGET 形式の貼り付けを解析する（-i、-D -、-v、-L、#META、#PROBE、#TLSPROBE、#CIPHERPROBE）
import type { HttpResponse, ParseResult, ParseWarning, Target } from '../model';
import { uniqueLabels } from './target';

const STATUS_RE = /^HTTP\/(1\.0|1\.1|2|3)(?:\.0)?\s+(\d{3})(?:\s+(.*))?$/;
const MARKER_RE = /^#(TARGET|META|PROBE|TLSPROBE|CIPHERPROBE)\b(.*)$/;   // 既知のマーカーだけ。他の # 行は本文
const OPENSSL_START = /^(CONNECTED\(|depth=|Certificate chain|subject=|issuer=|notBefore=|notAfter=)/;
const VERBOSE_HINT = /^\* (Connected to|Trying|SSL connection|ALPN|Host )/;
const BODY_LIMIT = 64 * 1024;

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
  const close = () => { if (cur) t.responses.push(cur); cur = null; inHeaders = false; last = ''; };
  const inBody = () => cur !== null && !inHeaders;
  const flush = () => { if (hasData(t)) targets.push(t); else if (t.label !== 'default') emptyTargets.push(t.label); };

  for (let line of input.replace(/\r\n?/g, '\n').split('\n')) {
    const mk = line.match(MARKER_RE);
    if (mk) {                                          // マーカー行は必ず応答を閉じる
      close(); inOpenssl = false; if (json) { unparsed += json.length; json = null; }
      const [, tag, rest] = mk; const a = attrs(rest);
      if (tag === 'TARGET') { flush(); t = newTarget(a); }
      else if (tag === 'META') Object.assign(t.meta, a);
      else if (tag === 'PROBE') t.probes.push({ path: a.path ?? '', code: +a.code, size: +a.size, contentType: a.ct ?? '', headB64: a.head ?? '' });
      else if (tag === 'CIPHERPROBE') t.cipherProbes.push({ cipher: a.c ?? '', result: probeResult(a.ok) });
      else t.tlsProbes.push({ version: a.v ?? '', result: probeResult(a.ok) });
      continue;
    }
    if (!inBody() && OPENSSL_START.test(line)) { close(); inOpenssl = true; }
    if (inOpenssl && !STATUS_RE.test(line) && !/^[*<>] /.test(line)) { t.openssl.push(line); continue; }
    inOpenssl = false;
    if (!inBody() && VERBOSE_HINT.test(line)) t.verbose = true;
    if (t.verbose && !inBody()) {                      // -v の解釈は verbose ターゲットのヘッダ部だけ
      if (line.startsWith('* ')) { t.info.push(line.slice(2)); continue; }
      if (line.startsWith('> ')) {
        const h = line.slice(2);
        const o = h.match(/^origin:\s*(.*)$/i); if (o) t.sentOrigin = o[1].trim();
        if (/^(cookie|authorization):/i.test(h)) { t.sentAuth = true; t.sentTokens.push(...(h.match(/\beyJ[\w-]+\.[\w-]+\.[\w-]*/g) ?? [])); }
        continue;
      }
      if (/^>\s*$/.test(line)) continue;               // 送信ヘッダの終端
      if (/^<\s*$/.test(line)) { close(); continue; }  // 受信ヘッダの終端。-v では本文を解析しない
      if (line.startsWith('< ')) line = line.slice(2);
      else if (/^[{}] \[/.test(line)) continue;
    }
    const sm = line.match(STATUS_RE);
    if (sm && !inBody()) { close(); cur = { httpVersion: sm[1], status: +sm[2], reason: sm[3], headers: new Map(), rawNames: [], kind: 'final' }; inHeaders = true; continue; }
    if (sm && inBody() && /^\s*$/.test(cur!.body?.split('\n').at(-2) ?? '') && (cur!.body === undefined || nextHopAfter(cur!.status))) {   // -L で次のホップが続く場合
      close(); cur = { httpVersion: sm[1], status: +sm[2], reason: sm[3], headers: new Map(), rawNames: [], kind: 'final' }; inHeaders = true; continue;
    }
    // C10：ヘッダ名が小文字のJSON。-v の本文や、応答のあとの本文（{"items":[...]} など）は対象にしない
    if (!cur && !t.verbose && (json || (!t.responses.length && /^\s*\{\s*"[\w-]+"\s*:\s*\[/.test(line)))) {
      json = [...(json ?? []), line];
      const r = headerJson(json.join('\n'), t.meta.response_code);
      if (r) { t.responses.push(r); json = null; } else if (json.length > 500) { unparsed += json.length; json = null; }
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
    (cur.headers.get(last) ?? cur.headers.set(last, []).get(last)!).push(line.slice(i + 1).trim());
  }
  close(); flush();
  for (const tg of targets) for (const r of tg.responses) {
    if (r.status > 0 && r.status < 200) r.kind = 'informational';
    else if (r.status === 200 && /connection established/i.test(r.reason ?? '')) r.kind = 'connect';
    else if (r.status >= 300 && r.status < 400 && r.headers.has('location')) r.kind = 'redirect';
    if (r.body !== undefined && !r.body.trim()) r.body = undefined;
  }
  const dup = uniqueLabels(targets);
  return { targets, warnings: [...dup, ...collectWarnings(targets, unparsed, emptyTargets)] };
}

/** curl -w '%{header_json}' の出力。ステータスは #META response_code（C5の -w）から取る。なければ0（不明） */
function headerJson(text: string, code?: string): HttpResponse | undefined {
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return undefined; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return undefined;
  const headers = new Map<string, string[]>();
  for (const [k, v] of Object.entries(obj as Record<string, unknown>))
    headers.set(k.toLowerCase(), (Array.isArray(v) ? v : [v]).map(String));
  return { httpVersion: '', status: Number(code) || 0, reason: 'header_json', headers, rawNames: [...headers.keys()], kind: 'final' };
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
