import type { HttpResponse, ParseWarning, ResponseKind, Target } from '../model';

/** 付け直したラベル（http#2 など）の元のラベル。ラベル対応表やラベルで判定を変えるルールは、この元のラベルで判定する */
export const baseLabel = (label: string) => label.replace(/#\d+$/, '');

/**
 * 同じラベルのターゲットを分ける（2つ目以降を「top#2」などにする）。適用する項目は元のラベルと同じ（baseLabel）。
 * 結果の表示・二重計上の除去・差分・例外はラベルで突き合わせるため、同じラベルのままだと別の応答の指摘が混ざる。
 * 横断ルール（pre-login と login の比較など）は最初のものだけを使う。curl の貼り付けと HAR を合わせたあとにも呼ぶ
 */
export function uniqueLabels(targets: Target[]): ParseWarning[] {
  const used = new Set(targets.map(t => t.label)); const seen = new Set<string>(); const renamed = new Map<string, string[]>();
  const next = new Map<string, number>();            // ラベルごとの次の番号（毎回 2 から探すと、同じラベルが多いときに件数の2乗の時間がかかる）
  for (const t of targets) {
    if (!seen.has(t.label)) { seen.add(t.label); continue; }
    let n = next.get(t.label) ?? 2; while (used.has(`${t.label}#${n}`)) n++;
    next.set(t.label, n + 1);
    const to = `${t.label}#${n}`;
    const list = renamed.get(t.label); if (list) list.push(to); else renamed.set(t.label, [to]);   // 配列をコピーしない
    used.add(to); seen.add(to); t.label = to;
  }
  return [...renamed].map(([l, tos]) => ({ kind: 'duplicate-label', detail:
    `ラベル「${l}」のターゲットが${tos.length + 1}つあります。2つ目以降は ${tos.join('、')} として別に判定しました（横断の判定には最初のものだけを使います）` }));
}

/** Location のある 3xx（ブラウザは本文を表示せずに転送先へ移る） */
export const isRedirectWithLocation = (r?: HttpResponse): boolean => !!r && r.status >= 300 && r.status < 400 && r.headers.has('location');

/** その URL の応答のホップか（1xx、プロキシの応答（CONNECT・407）、curl が認証し直した 401 を除く） */
export const isHop = (x: HttpResponse) => x.kind !== 'informational' && x.kind !== 'connect' && x.kind !== 'challenge';

/**
 * 判定に使う応答：-L なら、ターゲットの URL と同じホストの最後のホップ。別のホスト（IdP、legacy.example.net）へ転送した先の応答は、
 * 対象の URL の応答として判定しない（転送先の HSTS のなさで、対象を H-01①（高）にした。HAR の取り込みも別のホストの転送先をつながない）。
 * 同じホストのホップがない（URL が分からない）ときは最後のホップ
 */
export const finalResponse = (t: Target): HttpResponse | undefined => {
  const c = t.responses.filter(isHop);
  const host = hostnameOf(t.url);
  if (!host) return c.at(-1);
  // 同じサイト（登録ドメイン。apex と www、example.co.jp の下のホスト）への転送はたどる（curl -L で apex から www へ転送する普通の形を、
  // 301 で判定して H-01①（高）などの誤検知にした）。https のターゲットは https のホップだけ（途中で http に落とした転送の応答は対象の応答ではない）
  const site = siteOf(host); const https = /^https:/i.test(t.url ?? '');
  return c.filter(r => { const h = hostnameOf(r.url); return !r.url || (!!h && siteOf(h) === site && (!https || /^https:/i.test(r.url))); }).at(-1) ?? c.at(-1);
};
const hostnameOf = (u?: string) => { try { return u ? new URL(u).hostname.toLowerCase() : undefined; } catch { return undefined; } };
/**
 * ターゲットの URL と同じサイトの応答（URL の分からない応答を含む）。-L で別のサイト（IdP の login.microsoftonline.com）へ転送した先の Set-Cookie・
 * Clear-Site-Data を、対象の Cookie として判定しない（C-01〜C-07・C-11・C-12②・H-15。IdP の Cookie の属性を対象の指摘にし、IdP の Cookie を
 * 消しただけのログアウトを合格にした）。http の同じサイトのホップは含める（C-10 が見る）
 */
export const siteResponses = (t: Target): HttpResponse[] => {
  const host = hostnameOf(t.url);
  if (!host) return t.responses;
  const site = siteOf(host);
  return t.responses.filter(r => { const h = hostnameOf(r.url); return !r.url || !h || siteOf(h) === site; });
};
/** 登録ドメインの近似（最後の2つのラベル。co.jp・com.au のような2段の国別ドメインは3つ）。IP アドレスはそのまま */
const siteOf = (h: string): string => {
  if (/^[\d.]+$|:/.test(h)) return h;
  const l = h.split('.');
  return l.slice(l.length >= 3 && /^[a-z]{2}$/.test(l.at(-1)!) && /^(?:co|ne|or|ac|go|ed|lg|gr|ad|com|net|org|gov|edu)$/.test(l.at(-2)!) ? -3 : -2).join('.');
};

export const chainOf = (t: Target): HttpResponse[] => t.responses.filter(isHop);

/**
 * curl の出力の各ホップに、そのリクエストの URL を付ける（HAR は取り込みで付ける）。ターゲットの URL から Location をたどる。
 * -L で http から同じホストの https に転送されたかを、isHttps と ownChain が判定するのに使う
 */
export function assignHopUrls(t: Target): void {
  let cur = t.url;
  for (const r of chainOf(t)) {
    if (!cur) return;
    r.url ??= cur;
    if (r.kind !== 'redirect') return;
    try { const n = new URL(r.headers.get('location')![0], cur); n.hash = ''; cur = n.href; } catch { return; }
  }
}

/**
 * http の URL で採取し、-L で同じサイトの https に転送された（最後のホップが https）。http ラベル（T-04）以外は、HTTPS の応答として判定する。
 * URL が http のままだと、H-・C- の項目がすべて黙って適用外になる（HAR では取り込みでターゲットの URL を https にしている）
 */
const upgradedToHttps = (t: Target): boolean => {
  if (baseLabel(t.label) === 'http' || !/^http:/i.test(t.url ?? '')) return false;
  const last = chainOf(t).at(-1)?.url;
  // 同じサイト（apex と www）の https への転送も含める（finalResponse と同じ。http://example.com → https://www.example.com のよくある形で、
  // H-・C- の項目が黙って適用外になった）
  try { return !!last && new URL(last).protocol === 'https:' && siteOf(new URL(last).hostname.toLowerCase()) === siteOf(new URL(t.url!).hostname.toLowerCase()); } catch { return false; }
};

/**
 * そのターゲットの URL 自身の応答から始まるチェーン。http から https に転送されたチェーン（HAR はターゲットの URL を https にする。
 * curl は upgradedToHttps）は、最初の https のホップから始める（apex の「自身の応答」や、E-05・E-11 の「そのURLの応答」に http の転送を使わないため）
 */
const trimPath = (p: string) => (p.length > 1 ? p.replace(/\/+$/, '') : p);
/** 転送先が同じページ（同じホストで、パスが末尾の / の違いだけ）か。Django の APPEND_SLASH、FastAPI の redirect_slashes、Apache の DirectorySlash など */
export function sameDocument(r: HttpResponse, base?: string): boolean {
  try {
    const from = new URL(r.url ?? base ?? ''), to = new URL(r.headers.get('location')?.[0] ?? '', from);
    // クエリも同じもの（/login?next=… から /login、/redirect?url=… から /redirect?error=… は別のページへの転送）
    return to.host === from.host && trimPath(to.pathname) === trimPath(from.pathname) && to.search === from.search;
  } catch { return false; }
}

/**
 * その URL の応答のうち、同じページへの転送をたどった先（A-01・A-08・A-11 のステータス、C-12①）。
 * 末尾の / への 307 のあとの 200 を、転送の 307 で判定しないため。転送先を採取していない（-L なし）ときは unfollowed
 */
export function sameDocumentHop(t: Target): { hop?: HttpResponse; unfollowed: boolean } {
  const c = ownChain(t); let i = 0;
  while (c[i]?.kind === 'redirect' && sameDocument(c[i], t.url)) { if (!c[i + 1]) return { hop: c[i], unfollowed: true }; i++; }
  return { hop: c[i], unfollowed: false };
}

export function ownChain(t: Target): HttpResponse[] {
  const c = chainOf(t);
  if (!/^https:/i.test(t.url ?? '') && !upgradedToHttps(t)) return c;
  const i = c.findIndex(r => /^https:/i.test(r.url ?? ''));
  return i > 0 ? c.slice(i) : c;
}

export function isHttps(t: Target): boolean | undefined {
  const u = t.url ?? t.meta.url_effective;
  if (u) return /^https:\/\//i.test(u) || upgradedToHttps(t);   // スキームは大文字小文字を区別しない（HTTPS://…）
  if (t.info.some(l => /SSL connection using|ALPN:/.test(l))) return true;
  if (t.info.some(l => /^(?:Connected to|Established connection to) .* port 80\b/.test(l))) return false;   // 今の curl は Established connection to とも出す
  return undefined;
}

export function responseKind(t: Target, r?: HttpResponse): ResponseKind {
  if (t.kind !== 'auto') return t.kind;
  const ct = r?.headers.get('content-type')?.[0]?.toLowerCase() ?? '';
  if (/^application\/(?:[\w.-]+\+)?json\b/.test(ct)) return 'api';
  if (ct.startsWith('text/html')) return 'html';
  return 'other';
}

// 第0章 0.3：明示 > 送信側のCookie/Authorization > 不明
export const isSensitive = (t: Target): boolean | undefined => t.sensitive ?? (t.sentAuth ? true : undefined);

/**
 * 期限（Cookie の Expires、証明書の notAfter など）を比べる基準の時刻。採取した時刻（#META at、HAR の startedDateTime）があればそれを使う。
 * 判定した時刻を使うと、前に採取した出力を読み直したときに、採取時には有効だった期限を「切れている」と判定してしまうため。
 * #META at がなければ、応答の Date ヘッダ（サーバが応答した時刻）を使う。どちらもなければ判定した時刻
 */
export function capturedAt(t: Target): number {
  const at = t.meta.at ? Date.parse(t.meta.at) : NaN;   // 「2026-11-12T10:00:00」（タイムゾーンなし）は手元の時刻として読む
  if (!Number.isNaN(at)) return at;
  // 未来の Date（時計のずれの5分より先）は使わない。Date は診断対象のサーバが書くので、Date: 2030 として、Expires=2031 の Cookie の期限を短く
  // 見せ、C-05①（中）を合格にできた（1日まで認めると、C-05 の既定の基準の24時間と同じ幅で期限を短く見せられた）。過去の Date は、前に採取した
  // 出力を読み直したときの正しい基準（期限を長く見せる向きにはならない）
  const now = Date.now();
  for (const r of t.responses) {
    const d = Date.parse(r.headers.get('date')?.[0] ?? '');
    if (!Number.isNaN(d) && d <= now + 5 * 60e3) return d;
  }
  return now;
}

export function hostOf(t: Target): string | undefined {
  const u = t.url ?? t.meta.url_effective;
  try { return u ? new URL(u).host : undefined; } catch { return undefined; }
}

/** そのURL自身の最初の応答のステータス（分からなければ0） */
export const firstStatus = (t: Target): number => ownChain(t)[0]?.status ?? 0;
/**
 * ログアウトの応答が失敗（4xx・5xx）しているか。GET の /logout に 405 を返すアプリなどでは、ログアウトしていないので、
 * C-12（ログアウト後の無効化・Cookie の削除）と H-15 を判定しない
 */
export const logoutFailed = (t: Target): boolean => firstStatus(t) >= 400;
