// parser/har.ts：HAR（HTTP Archive）の取り込み（v0.3。ツール設計1「HAR形式の取り込み」）
// - request.postData（ログインのパスワードなど）は読まない。本文は HTML と JSON の先頭64KBだけ残す
// - リダイレクトの各ホップを1本のチェーンにまとめ、ラベルはチェーン（1つのターゲット）に付ける
import type { HttpResponse, ParseWarning, Target } from '../model';
import { looksLikeSession, parseSetCookie } from './setCookie';
import { allowedForHar } from '../engine/labels';
import { baseLabel } from './target';

const BODY_LIMIT = 64 * 1024;
export const HAR_MAX_BYTES = 50 * 1024 * 1024;

interface HarHeader { name: string; value: string; }
interface HarEntry {
  startedDateTime?: string;
  request: { method: string; url: string; httpVersion?: string; headers?: HarHeader[] };
  response: { status: number; statusText?: string; httpVersion?: string; headers?: HarHeader[]; redirectURL?: string;
              content?: { mimeType?: string; text?: string; encoding?: string } };
}

/** 取り込み後のチェーン（画面のエントリ一覧の1行）。秘密情報は持たない */
export interface HarChain {
  id: number; url: string; method: string; host: string; status: number; hops: number;
  finalUrl?: string;                // 最後のホップのURL（http から https に転送されたチェーンの判定に使う）
  responses: HttpResponse[]; sentAuth: boolean; at?: string;
  suggested: string; label: string; sensitive?: boolean; excluded: boolean;
}
export interface HarImport { chains: HarChain[]; hosts: string[]; sanitized: boolean; total: number; failed: number; }   // failed：応答のない（status 0）エントリの数

export const isHar = (text: string) => /^\s*\{[\s\S]{0,200}"log"\s*:/.test(text);

/** HTTPのバージョン表記（h2、HTTP/2.0、http/1.1 など）を 1.1・2・3 にそろえる */
export function normalizeVersion(v?: string): string {
  const s = (v ?? '').toLowerCase();
  if (/h3|http\/3/.test(s)) return '3';
  if (/h2|http\/2/.test(s)) return '2';
  if (/1\.0/.test(s)) return '1.0';
  return s ? '1.1' : '';
}

function toResponse(e: HarEntry): HttpResponse {
  const headers = new Map<string, string[]>(); const rawNames: string[] = [];
  for (const h of e.response.headers ?? []) {
    if (!h?.name || h.name.startsWith(':')) continue;               // HTTP/2 の疑似ヘッダは除外
    const k = h.name.toLowerCase(); rawNames.push(h.name);
    // 1つのヘッダに複数の Set-Cookie を改行でつないで書き出すものがある。1件ずつに分けないと、2つ目以降の Cookie を判定せず、
    // 証跡（値は先頭の name=value だけをマスクする）に生の値が出てしまう
    const vals = k === 'set-cookie' ? String(h.value ?? '').split(/\r?\n/).filter(v => v.trim()) : [String(h.value ?? '')];
    (headers.get(k) ?? headers.set(k, []).get(k)!).push(...vals);
  }
  if (e.response.redirectURL && !headers.has('location') && e.response.status >= 300 && e.response.status < 400) headers.set('location', [e.response.redirectURL]);
  let body: string | undefined;
  const c = e.response.content;
  if (c?.text && /html|json/i.test(c.mimeType ?? '')) {
    try { body = c.encoding === 'base64' ? new TextDecoder().decode(Uint8Array.from(atob(c.text.slice(0, BODY_LIMIT * 2)), x => x.charCodeAt(0))) : c.text; } catch { body = undefined; }
    body = body?.slice(0, BODY_LIMIT);
  }
  const status = e.response.status;
  return { httpVersion: normalizeVersion(e.response.httpVersion), status, reason: e.response.statusText, headers, rawNames, body,
           kind: status >= 300 && status < 400 && headers.has('location') ? 'redirect' : 'final' };
}

const hostOfUrl = (u: string) => { try { return new URL(u).host; } catch { return ''; } };

/** HAR の JSON を読み、チェーンにまとめる。request.postData はここで捨てる */
export function importHar(text: string): HarImport {
  const har = JSON.parse(text) as { log?: { entries?: HarEntry[] } };
  const all = (har.log?.entries ?? []).filter(e => e?.request?.url && e.response && /^https?:/i.test(e.request.url));
  // status 0 は、ブロック・キャンセル・CORSの失敗などで応答がなかったエントリ。ヘッダがないので判定に使うと誤検知になる
  const entries = all.filter(e => Number(e.response.status) > 0);
  const used = new Set<number>(); const chains: HarChain[] = [];
  let anyCookie = false;
  entries.forEach((e, i) => {
    if (used.has(i)) return;
    used.add(i);
    const hops = [e];
    let cur = e;
    while (cur.response.status >= 300 && cur.response.status < 400) {          // Location の先のエントリをつなぐ
      const loc = cur.response.redirectURL || cur.response.headers?.find(h => h.name.toLowerCase() === 'location')?.value;
      if (!loc) break;
      let next: string; try { next = new URL(loc, cur.request.url).href; } catch { break; }
      const j = entries.findIndex((x, k) => k > entries.indexOf(cur) && !used.has(k) && x.request.url === next);
      if (j < 0) break;
      used.add(j); cur = entries[j]; hops.push(cur);
    }
    const reqH = (e.request.headers ?? []).map(h => h.name.toLowerCase());
    const sentAuth = reqH.includes('cookie') || reqH.includes('authorization');
    if (sentAuth || hops.some(h => (h.response.headers ?? []).some(x => x.name.toLowerCase() === 'set-cookie'))) anyCookie = true;
    chains.push({ id: chains.length, url: e.request.url, finalUrl: cur.request.url, method: e.request.method, host: hostOfUrl(e.request.url),
      status: cur.response.status, hops: hops.length, responses: hops.map(toResponse), sentAuth, at: e.startedDateTime,
      suggested: '', label: '', sensitive: undefined, excluded: false });
  });
  suggestLabels(chains);
  const hosts = [...new Set(chains.map(c => c.host))];
  return { chains, hosts, sanitized: chains.length > 0 && !anyCookie, total: entries.length, failed: all.length - entries.length };
}

/**
 * ラベルの候補。予約ラベルは1つのチェーンにだけ付ける。
 * セッションCookieの推定は組織プロファイルの sessionCookieNames に従うので、プロファイルを読んだら withProfile の中で呼び直す。
 * keepUserLabels：画面で選び直したラベル（候補と違うもの）は変えず、それが予約ラベルなら他のチェーンの候補に使わない
 */
export function suggestLabels(chains: HarChain[], keepUserLabels = false): void {
  const kept = new Set(keepUserLabels ? chains.filter(c => c.label && c.label !== c.suggested).map(c => c.id) : []);
  const taken = new Set(chains.filter(c => kept.has(c.id)).map(c => c.label));
  const take = (c: HarChain, l: string) => { if (!taken.has(l)) { taken.add(l); c.suggested = l; } };
  for (const c of chains) {
    c.suggested = '';
    const path = (() => { try { return new URL(c.url).pathname; } catch { return ''; } })();
    const first = c.responses[0];
    const at = c.at ? Date.parse(c.at) : NaN; const now = Number.isNaN(at) ? Date.now() : at;   // 期限は記録した時刻で比べる
    const setsSession = c.responses.some(r => (r.headers.get('set-cookie') ?? []).map(v => parseSetCookie(v)).some(x => looksLikeSession(x, now)));
    if (/logout|signout|sign-out|log-out/i.test(path)) take(c, 'logout');
    else if (c.method === 'POST' && setsSession) take(c, 'login');
    else if (c.method === 'GET' && /type\s*=\s*["']?password/i.test(c.responses.at(-1)?.body ?? '')) take(c, 'pre-login');
    else if (first && first.status >= 400) c.suggested = `error-${c.id + 1}`;
    if (!c.suggested) c.suggested = `har-${c.id + 1}`;
    if (!kept.has(c.id)) c.label = c.suggested;
  }
}

/** 画面で確定したチェーンをターゲットにする */
export function harTargets(imp: HarImport, selectedHosts: Set<string>): { targets: Target[]; warnings: ParseWarning[] } {
  const targets: Target[] = []; const warnings: ParseWarning[] = [];
  let excluded = 0;
  for (const c of imp.chains) {
    if (c.excluded || !selectedHosts.has(c.host)) { excluded++; continue; }
    const label = allowedForHar(c.label) ? c.label : `har-${c.id + 1}`;
    // http から https に転送されたチェーンは、最後の https の応答を、その URL で判定する（H-01・Cookie の項目は HTTPS の応答が対象）。
    // 最初の http の URL のままだと、HTTPS の項目がすべて適用外になる。http ラベル（T-04）だけは、転送元の http の URL で判定する
    const upgraded = /^http:/i.test(c.url) && /^https:/i.test(c.finalUrl ?? '');
    const url = upgraded && baseLabel(label) !== 'http' ? c.finalUrl! : c.url;
    targets.push({ label, url, kind: 'auto', sensitive: c.sensitive, verbose: false,   // 画面で明示したときだけ。Cookie を送っただけの推定は isSensitive が sentAuth から行う
      responses: c.responses, sentAuth: c.sentAuth, sentTokens: [], info: [],
      meta: { source: 'har', cmd: 'HAR', method: c.method, ...(c.at ? { at: c.at } : {}) }, probes: [], tlsProbes: [], cipherProbes: [], openssl: [] });
  }
  if (imp.failed) warnings.push({ kind: 'har-excluded', detail: `HAR：応答のない（status 0）エントリが${imp.failed}件あり、判定に使いませんでした（ブロック・キャンセルされた通信など）` });
  if (excluded) warnings.push({ kind: 'har-excluded', detail: `HAR：${excluded}件のエントリ（対象外のホスト、または除外したもの）を判定に使いませんでした` });
  if (imp.sanitized) warnings.push({ kind: 'har-sanitized', detail: 'HAR：Cookie・Set-Cookie が含まれていません。機密情報を除いた形式で書き出された可能性があります。第2章（Cookie）の項目は判定できません' });
  return { targets, warnings };
}

/** HARで付けられるラベル（画面の選択肢） */
export const HAR_LABEL_CHOICES = ['pre-login', 'login', 'logout', 'http', 'apex', 'csp-sample-1', 'csp-sample-2'];
