// parser/har.ts：HAR（HTTP Archive）の取り込み（ツール設計1「HAR形式の取り込み」）
// - request.postData（ログインのパスワードなど）は読まない。本文は HTML・JSON・JS・テキスト・XML の先頭64K文字だけ残す
// - リダイレクトの各ホップを1本のチェーンにまとめ、ラベルはチェーン（1つのターゲット）に付ける
import type { HttpResponse, ParseWarning, Target } from '../model';
import { autoAuthScheme, cookieNames, JWT_IN_TEXT, looksLikeSession, parseSetCookie, sentAuthOf, splitSetCookie } from './setCookie';
import { allowedForHar } from '../engine/labels';
import { baseLabel, BODY_LIMIT, cookieCapWarnings, isRedirectWithLocation, LOGOUT_WORD, pushCookies } from './target';

/** パスワード欄らしい文字（ラベルの候補の推定用。判定は rules/html.ts の hasPasswordField でタグを読む。画面の側はルールを読み込まないので文字で見る） */
const PASSWORD_TEXT = /type\s*=\s*["']?password/i;

export const HAR_MAX_BYTES = 50 * 1024 * 1024;

interface HarHeader { name: string; value: string; }
interface HarEntry {
  startedDateTime?: string;
  serverIPAddress?: unknown;
  request: { method: string; url: string; httpVersion?: string; headers?: HarHeader[] };
  response: { status: number; statusText?: string; httpVersion?: string; headers?: HarHeader[]; redirectURL?: string;
              content?: { mimeType?: string; text?: string; encoding?: string } };
}

/**
 * 取り込み後のチェーン（画面のエントリ一覧の1行）。送った Cookie は名前だけを持つ。送った JWT（sentTokens）と応答（Set-Cookie・本文）は
 * 判定に使うので持つが、画面には出さない（URL は showText を通す）
 */
export interface HarChain {
  id: number; url: string; method: string; host: string; status: number; hops: number;
  finalUrl?: string;                // 最後のホップのURL（http から https に転送されたチェーンの判定に使う）
  responses: HttpResponse[];        // 各応答の url はそのホップのリクエストのURL（parser/target.ts の ownChain が使う）
  sentAuth: boolean;                // 一覧の表示用の推定（Authorization か、セッションCookieらしい名前の Cookie を送った）
  sentAuthorization: boolean; sentCookieNames: string[];   // 全ホップのリクエストで送った Authorization の有無と Cookie の名前（値は持たない）
  sentAutoAuth?: boolean;           // ブラウザが自動で送る方式（Basic など）の Authorization を送った
  sentOrigin?: string;              // 最後のホップのリクエストで送った Origin（R-06：Origin を送らずに返した ACAO は固定の値。curl の -v と同じ）
  sentTokens: string[];             // Authorization・Cookie で送った JWT。A-03 のデコードにだけ使い、画面・エクスポートには出さない（curl の -v と同じ）
  at?: string;
  suggested: string; label: string; sensitive?: boolean; excluded: boolean;
}
export interface HarImport { chains: HarChain[]; hosts: string[]; sanitized: boolean; failed: number; internal?: number; }   // failed：応答のない（status 0 など）エントリの数

export const isHar = (text: string) => /^\s*\{[\s\S]{0,200}"log"\s*:/.test(text);

/** HTTPのバージョン表記（h2、HTTP/2.0、http/1.1 など）を 1.1・2・3 にそろえる */
export function normalizeVersion(v?: unknown): string {
  // 文字列でない値（"httpVersion": 2）も文字列にして読む（例外で HAR 全体を読めなくしない）
  const s = (typeof v === 'string' ? v : v == null ? '' : String(v)).toLowerCase();
  if (/h3|http\/3/.test(s)) return '3';
  if (/h2|http\/2/.test(s)) return '2';
  if (/1\.0/.test(s)) return '1.0';
  return s ? '1.1' : '';
}

function toResponse(e: HarEntry): HttpResponse {
  const headers = new Map<string, string[]>(); let dropped = 0;
  for (const h of named(e.response.headers)) {
    if (h.name.startsWith(':')) continue;               // HTTP/2 の疑似ヘッダは除外
    const k = h.name.toLowerCase();
    // 1つのヘッダに複数の Set-Cookie を改行でつないで書き出すものがあるので、1件ずつに分ける（2つ目以降の Cookie も判定し、
    // 証跡（値は先頭の name=value だけをマスクする）に生の値を出さない）
    const vals = k === 'set-cookie' ? String(h.value ?? '').split(/\r?\n/).flatMap(splitSetCookie) : [String(h.value ?? '')];
    const list = headers.get(k) ?? headers.set(k, []).get(k)!;
    if (k === 'set-cookie') dropped += pushCookies(list, vals); else for (const x of vals) list.push(x);   // push(...) に広げない（長い Set-Cookie でスタックがあふれる）
  }
  // redirectURL は文字列のときだけ使う（壊れた HAR のオブジェクトをヘッダの値にすると、ルールが例外を投げる）
  if (typeof e.response.redirectURL === 'string' && e.response.redirectURL && !headers.has('location') && e.response.status >= 300 && e.response.status < 400) headers.set('location', [e.response.redirectURL]);
  let body: string | undefined;
  const c = e.response.content;
  // JS も残す（JSONP の E-06、ソースマップの参照の E-13 が本文で判定する）。テキストと XML も残す（text/plain のスタックトレース・S3 の XML の
  // エラーの E-01、robots.txt・security.txt の E-04。捨てると「本文を採取していない」の na になり、採り直しても直らない）。XML は text/xml と
  // application/…+xml・application/xml だけ（image/svg+xml や Office の文書（application/vnd.openxmlformats-…）のバイナリは残さない）。
  // 本文が文字列でないもの（content.text: 12345）は読まない
  if (typeof c?.text === 'string' && c.text && /html|json|javascript|ecmascript|^\s*text\/(?:plain|xml)\b|^\s*application\/(?:[\w.-]+\+)?xml\b/i.test(String(c.mimeType ?? ''))) {
    // base64 は4文字で3バイト。日本語の3バイトの文字でも、64K文字まで読めるだけ取る
    try { body = c.encoding === 'base64' ? new TextDecoder().decode(Uint8Array.from(atob(c.text.slice(0, BODY_LIMIT * 4)), x => x.charCodeAt(0))) : c.text; } catch { body = undefined; }
    body = body?.slice(0, BODY_LIMIT);
  }
  const r: HttpResponse = { httpVersion: normalizeVersion(e.response.httpVersion), status: e.response.status, reason: e.response.statusText, headers, body,
    kind: 'final', ...(dropped ? { droppedCookies: dropped } : {}) };
  if (isRedirectWithLocation(r)) r.kind = 'redirect';
  return r;
}

const withoutHash = (u: string) => { const i = u.indexOf('#'); return i >= 0 ? u.slice(0, i) : u; };
/** 名前のあるヘッダだけ（配列でない headers、名前のない要素・null を含む HAR でも TypeError にしない） */
const named = (hs: (HarHeader | null | undefined)[] | undefined): HarHeader[] => (Array.isArray(hs) ? hs : []).filter((h): h is HarHeader => typeof h?.name === 'string');
/** Authorization・Cookie のリクエストヘッダにある JWT（A-03 が curl の -v と同じく送った JWT もデコードできるように） */
const jwtsIn = (hs: HarHeader[]) => [...new Set(hs.filter(h => /^(?:authorization|cookie)$/i.test(h.name)).flatMap(h => String(h.value ?? '').match(JWT_IN_TEXT) ?? []))];
const hostOfUrl = (u: string) => { try { return new URL(u).host; } catch { return ''; } };
/** 突き合わせ用の URL（フラグメントを除き、URL として読み直した形） */
const normalizedUrl = (u: string) => { try { const x = new URL(u); x.hash = ''; return x.href; } catch { return withoutHash(u); } };

/** HAR の JSON を読み、チェーンにまとめる。request.postData はここで捨てる */
export function importHar(text: string): HarImport {
  const har = JSON.parse(text) as { log?: { entries?: unknown } } | null;
  // 型の違う値は、例外で HAR 全体を読めなくしないよう、ここでそろえる（entries がオブジェクト、url が配列、startedDateTime が数値など）。
  // url は文字列のものだけ（配列も文字列にすると /^https?:/ を通り、画面で例外になる）
  const raw = har?.log?.entries;
  const all = (Array.isArray(raw) ? raw as HarEntry[] : []).filter(e => typeof e?.request?.url === 'string' && e.response && /^https?:/i.test(e.request.url));
  for (const e of all) {
    if (e.request.method !== undefined && typeof e.request.method !== 'string') e.request.method = String(e.request.method);
    if (e.startedDateTime !== undefined && typeof e.startedDateTime !== 'string') e.startedDateTime = undefined;
  }
  // status 0 は、ブロック・キャンセル・CORSの失敗などで応答がなかったエントリ。ヘッダがないので判定に使うと誤検知になる
  // ブラウザが内部で作った転送（HSTS・HTTPS-Upgrades の 307 Internal Redirect。Non-Authoritative-Reason ヘッダが付く）も、サーバの応答では
  // ないので除く（http で接続していないのに T-04・C-10 を判定しない）。
  // 印（理由句・ヘッダ）はサーバも返せるので、307 で、ネットワークに出ていない（serverIPAddress がない）ものだけを内部の転送とする
  // （印だけで除くと、診断対象のサーバがログインの POST や http から https への転送を判定から外せる）
  const internal = (e: HarEntry) => e.response.status === 307 && !String(e.serverIPAddress ?? '').trim()
    && (/internal redirect/i.test(e.response.statusText ?? '') || named(e.response.headers).some(h => /^non-authoritative-reason$/i.test(h.name)));
  // 状態コードは数値にそろえる（文字列の "304" を書き出すツールがある。304 の除外や === 401 などの比べ方を効かせるため）
  // 応答がオブジェクトでないエントリ（"response": 1）は、書き換えずに除く（書き換えると例外になる）
  const entries: HarEntry[] = []; let internalCount = 0;
  for (const e of all) {
    if (typeof e.response !== 'object') continue;
    const st = Number(e.response.status); e.response.status = Number.isInteger(st) ? st : 0;
    if (e.response.status <= 0) continue;
    if (internal(e)) internalCount++; else entries.push(e);
  }
  const used = new Set<number>(); const chains: HarChain[] = [];
  // 転送先のエントリを「メソッド URL」から引く表（エントリごとに全体を探すと、転送先のない 302 が多い HAR で入力の長さの2乗の時間がかかる）。
  // URL は、引くときと同じく URL として読み直した形（new URL().href）にする（https://a.example:443/、エンコードしていない /日本 でも連なりを切らない）。
  // メソッドもキーに入れる（メソッドの違うエントリを転送のたびになめ直さない）
  const methodOf = (x: { request: { method?: unknown } }) => String(x.request.method ?? 'GET').toUpperCase();
  const byUrl = new Map<string, number[]>();
  entries.forEach((x, k) => { const u = `${methodOf(x)} ${normalizedUrl(x.request.url)}`; (byUrl.get(u) ?? byUrl.set(u, []).get(u)!).push(k); });
  // キーごとの一覧（エントリの番号の昇順）から、from より後の最初の使っていないエントリを引く。from より後の位置は二分探索で求め、使い済みの
  // エントリは「次の候補の位置」をたどって飛ばす（経路を縮める。同じ URL へ転送する 3xx が多い HAR でも2乗の時間にしない）。
  // 使い済みは増えるだけなので、飛ばしてよい
  const skip = new Map<string, Int32Array>();
  const nextOf = (key: string, from: number): number => {
    const list = byUrl.get(key); if (!list) return -1;
    let nx = skip.get(key);
    if (!nx) { nx = Int32Array.from({ length: list.length + 1 }, (_, k) => k); skip.set(key, nx); }
    let lo = 0, hi = list.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid] > from) hi = mid; else lo = mid + 1; }
    let r = lo;
    while (r < list.length) {
      if (nx[r] !== r) r = nx[r];
      else if (used.has(list[r])) { nx[r] = r + 1; r++; }
      else break;
    }
    for (let k = lo; k < r && nx[k] !== r;) { const n = nx[k] === k ? k + 1 : nx[k]; nx[k] = r; k = n; }
    return r < list.length ? list[r] : -1;
  };
  /**
   * 転送先のメソッド（fetch の仕様）：303 は HEAD なら HEAD、ほかは GET。301・302 は POST なら GET、ほかは元と同じ。307・308 は元と同じ。
   * メソッドも合わせてつなぐ（GET /mypage → 302 /login の転送先に、同じ URL の POST /login をつなげてログインの候補を消さない）
   */
  const nextEntry = (href: string, from: number, status: number, m0: string): number => {
    const m = status === 303 ? (m0 === 'HEAD' ? 'HEAD' : 'GET') : (status === 301 || status === 302) && m0 === 'POST' ? 'GET' : m0;
    return nextOf(`${m} ${href}`, from);
  };
  let anyCookie = false;
  entries.forEach((e, i) => {
    if (used.has(i)) return;
    used.add(i);
    const hops = [e];
    let cur = e, ci = i;
    // Location の先のエントリをつなぐ。ブラウザが転送するのは 301・302・303・307・308 だけ（304 などの Location はたどらない）
    while ([301, 302, 303, 307, 308].includes(cur.response.status)) {
      const loc = (typeof cur.response.redirectURL === 'string' ? cur.response.redirectURL : '') || named(cur.response.headers).find(h => h.name.toLowerCase() === 'location')?.value;
      if (!loc) break;
      let next: URL; try { next = new URL(loc, cur.request.url); } catch { break; }
      next.hash = '';   // ブラウザはフラグメントを除いた URL でリクエストを記録する（Location: /app/#/home → GET /app/）
      // 別のホスト（IdP、apex から www など）への転送先はつながない。つなぐと、対象外のホストの応答を、選んだホストのURLの結果として判定してしまう。
      // 同じホストの http から https への転送はつなぐ
      if (next.hostname !== new URL(cur.request.url).hostname) break;
      const j = nextEntry(next.href, ci, cur.response.status, methodOf(cur));
      if (j < 0) break;
      used.add(j); cur = entries[j]; ci = j; hops.push(cur);
    }
    // 送った認証情報は全ホップのリクエストから見る。Secure の Cookie は https のホップでしか送らないため、最初の http のリクエストだけでは分からない
    const reqHeaders = hops.flatMap(h => named(h.request.headers));
    const sentAuthorization = reqHeaders.some(h => h.name.toLowerCase() === 'authorization');
    const sentAutoAuth = reqHeaders.some(h => h.name.toLowerCase() === 'authorization' && autoAuthScheme(String(h.value ?? '')));
    const sentCookieNames = [...new Set(reqHeaders.filter(h => h.name.toLowerCase() === 'cookie').flatMap(h => cookieNames(String(h.value ?? ''))))];
    const sentAuth = sentAuthOf(sentAuthorization, sentCookieNames);
    if (sentAuthorization || sentCookieNames.length || hops.some(h => named(h.response.headers).some(x => x.name.toLowerCase() === 'set-cookie'))) anyCookie = true;
    chains.push({ id: chains.length, url: e.request.url, finalUrl: cur.request.url, method: methodOf(e), host: hostOfUrl(e.request.url),
      status: cur.response.status, hops: hops.length, responses: hops.map(h => ({ ...toResponse(h), url: h.request.url })),
      sentAuth, sentAuthorization, sentAutoAuth, sentCookieNames, sentTokens: jwtsIn(reqHeaders), at: e.startedDateTime,
      sentOrigin: named(cur.request.headers).find(h => h.name.toLowerCase() === 'origin')?.value?.toString().trim() || undefined,
      // 304（ブラウザのキャッシュの再検証）は、サーバがセキュリティヘッダを付け直さなくてよい応答（RFC 9110 15.4.5）。
      // 通常の応答として判定すると H-01①（高）などの誤検知になるので、既定で除外する（画面でラベルを選べば判定する）
      suggested: '', label: '', sensitive: undefined, excluded: cur.response.status === 304 });
  });
  suggestLabels(chains);
  const hosts = [...new Set(chains.map(c => c.host))];
  return { chains, hosts, sanitized: chains.length > 0 && !anyCookie, failed: all.length - entries.length - internalCount, internal: internalCount };
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
    c.sentAuth = sentAuthOf(c.sentAuthorization, c.sentCookieNames);   // 一覧の「自動（はい）」もプロファイルのセッションCookieの名前で作り直す
    const path = (() => { try { return new URL(c.url).pathname; } catch { return ''; } })();
    const first = c.responses[0];
    const at = c.at ? Date.parse(c.at) : NaN; const now = Number.isNaN(at) ? Date.now() : at;   // 期限は記録した時刻で比べる
    const setsSession = c.responses.some(r => (r.headers.get('set-cookie') ?? []).map(v => parseSetCookie(v)).some(x => looksLikeSession(x, now)));
    if (LOGOUT_WORD.test(path)) take(c, 'logout');
    // セッションIDを再発行しない（C-09①の）ログインは新しいCookieを発行しないので、パスが login・signin の POST も login の候補にする
    else if (c.method === 'POST' && (setsSession || /log-?in|sign-?in/i.test(path))) take(c, 'login');
    else if (c.method === 'GET' && PASSWORD_TEXT.test(c.responses.at(-1)?.body ?? '')) take(c, 'pre-login');
    else if (first && first.status >= 400) c.suggested = `error-${c.id + 1}`;
    if (!c.suggested) c.suggested = `har-${c.id + 1}`;
    if (!kept.has(c.id)) c.label = c.suggested;
  }
}


/** 既定で選ぶ対象ホスト：チェーンのいちばん多いホスト（画面の初期値。回帰テストも同じものを使う） */
export function defaultHarHosts(imp: HarImport): Set<string> {
  const count = new Map<string, number>(); for (const c of imp.chains) count.set(c.host, (count.get(c.host) ?? 0) + 1);
  const main = [...count].sort((a, b) => b[1] - a[1])[0]?.[0];
  return new Set(main ? [main] : []);
}

/** 画面で確定したチェーンをターゲットにする */
export function harTargets(imp: HarImport, selectedHosts: Set<string>): { targets: Target[]; warnings: ParseWarning[] } {
  const targets: Target[] = []; const warnings: ParseWarning[] = [];
  // 送った JWT は、最初に送ったターゲットにだけ持たせる（SPA の HAR では同じ Bearer の JWT を数百の XHR で送るので、ターゲットごとに A-03 を出すと
  // 同じ指摘が数百倍になる。curl の -v では、同じ JWT を送るターゲットを1つずつ採取するので、これは HAR だけ）
  const tokensSeen = new Set<string>();
  let excluded = 0, revalidated = 0;
  for (const c of imp.chains) {
    if (c.excluded && c.status === 304 && selectedHosts.has(c.host)) { revalidated++; continue; }
    if (c.excluded || !selectedHosts.has(c.host)) { excluded++; continue; }
    const label = allowedForHar(c.label) ? c.label : `har-${c.id + 1}`;
    // http から https に転送されたチェーンは、最後の https の応答を、その URL で判定する（H-01・Cookie の項目は HTTPS の応答が対象）。
    // 最初の http の URL のままだと、HTTPS の項目がすべて適用外になる。http ラベル（T-04）だけは、転送元の http の URL で判定する
    const upgraded = /^http:/i.test(c.url) && /^https:/i.test(c.finalUrl ?? '');
    const https = upgraded && baseLabel(label) !== 'http';
    const url = https ? c.finalUrl! : c.url;
    // http のホップは応答に残す（そこで発行した Cookie も判定する）。apex の「自身の応答」は、各応答の url から最初の https のホップを選ぶ
    // （parser/target.ts の ownChain）
    targets.push({ label, url, kind: 'auto', sensitive: c.sensitive, verbose: false,   // 画面で明示したときだけ。Cookie を送っただけの推定は isSensitive が sentAuth から行う
      // 送った認証情報の推定（sentAuth）は、runAll が組織プロファイルのセッションCookieの名前で作り直す
      responses: c.responses, sentAuth: c.sentAuth, sentAuthorization: c.sentAuthorization, sentAutoAuth: c.sentAutoAuth, sentOrigin: c.sentOrigin, sentCookieNames: c.sentCookieNames, sentTokens: c.sentTokens.filter(tok => !tokensSeen.has(tok) && !!tokensSeen.add(tok)), info: [],
      meta: { source: 'har', cmd: 'HAR', method: c.method, ...(c.at ? { at: c.at } : {}) }, probes: [], tlsProbes: [], cipherProbes: [], openssl: [] });
  }
  if (imp.failed) warnings.push({ kind: 'har-excluded', detail: `HAR：応答のない（status 0）エントリが${imp.failed}件あり、判定に使いませんでした（ブロック・キャンセルされた通信など）` });
  if (imp.internal) warnings.push({ kind: 'har-excluded', detail: `HAR：ブラウザの内部の転送（HSTS などの 307 Internal Redirect）のエントリが${imp.internal}件あり、判定に使いませんでした` });
  if (revalidated) warnings.push({ kind: 'har-excluded', detail: `HAR：304（キャッシュの再検証）のエントリが${revalidated}件あり、判定に使いませんでした。開発者ツールで「キャッシュを無効にする」を選んで記録し直すと判定できます` });
  if (excluded) warnings.push({ kind: 'har-excluded', detail: `HAR：${excluded}件のエントリ（対象外のホスト、または除外したもの）を判定に使いませんでした` });
  warnings.push(...cookieCapWarnings(targets));
  if (imp.sanitized) warnings.push({ kind: 'har-sanitized', detail: 'HAR：Cookie・Set-Cookie が含まれていません。機密情報を除いた形式で書き出された可能性があります。第2章（Cookie）の項目は判定できません' });
  return { targets, warnings };
}
