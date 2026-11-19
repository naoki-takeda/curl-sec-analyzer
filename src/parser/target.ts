// parser/target.ts：ターゲットの共通の処理（ラベル・判定に使う応答のホップ・HTTPS か・機密か・採取時刻・Set-Cookie の上限）
import type { HttpResponse, ParseWarning, ResponseKind, Target } from '../model';
import { looksLikeSessionName } from './setCookie';

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
 * 判定に使う応答：-L なら、ターゲットの URL と同じサイトの最後のホップ。別のサイト（IdP、legacy.example.net）へ転送した先の応答は、
 * 対象の URL の応答として判定しない（転送先の HSTS のなさで対象を H-01①（高）にしない。HAR の取り込みも別のホストの転送先をつながない）。
 * 同じサイトのホップがない（URL が分からない）ときは最後のホップ
 */
export const finalResponse = (t: Target): HttpResponse | undefined => {
  const c = t.responses.filter(isHop);
  const host = hostnameOf(t.url);
  if (!host) return c.at(-1);
  // 同じサイト（登録ドメイン。apex と www、example.co.jp の下のホスト）への転送はたどる（curl -L で apex から www へ転送する普通の形を、
  // 301 で判定しない）。https のターゲットは https のホップだけ（途中で http に落とした転送の応答は対象の応答ではない）
  const site = siteOf(host); const https = /^https:/i.test(t.url ?? '');
  return c.filter(r => { const h = hostnameOf(r.url); return !r.url || (!!h && siteOf(h) === site && (!https || /^https:/i.test(r.url))); }).at(-1) ?? c.at(-1);
};
const hostnameOf = (u?: string) => { try { return u ? new URL(u).hostname.toLowerCase() : undefined; } catch { return undefined; } };
/**
 * ターゲットの URL と同じサイトの応答（URL の分からない応答を含む）。-L で別のサイト（IdP の login.microsoftonline.com）へ転送した先の Set-Cookie・
 * Clear-Site-Data を、対象の Cookie として判定しない（C-01〜C-07・C-11・C-12②・H-15。IdP の Cookie の属性を対象の指摘にせず、IdP の Cookie を
 * 消しただけのログアウトを合格にしない）。http の同じサイトのホップは含める（C-10 が見る）
 */
export const siteResponses = (t: Target): HttpResponse[] => {
  // 1xx（103 Early Hints など）とプロキシの応答（CONNECT・407）は除く。ブラウザは 1xx の Set-Cookie・Clear-Site-Data を使わない
  // （103 で C-09・C-12②・H-15 を合格にさせない）。プロキシの応答はサイトの応答ではない
  const rs = t.responses.filter(r => r.kind !== 'informational' && r.kind !== 'connect');
  const host = hostnameOf(t.url);
  if (!host) return rs;
  const site = siteOf(host);
  return rs.filter(r => { const h = hostnameOf(r.url); return !r.url || !h || siteOf(h) === site; });
};
/**
 * 1つの応答で読む Set-Cookie の上限。ブラウザも1つのドメインに約180個までしか保存しない。上限がないと、5MB の Set-Cookie の行で
 * Cookie の項目ごとに数万件の指摘を作り、判定に数十秒かかる。超えた分は警告で知らせる
 */
export const MAX_SET_COOKIES = 300;
/**
 * Set-Cookie の値を一覧に足す。上限を超えたら古いもの（先のもの）を捨てて、後のものを残す（ブラウザも古いものから追い出す。
 * 先のものを残すと、後ろに置いた Secure なしのセッションCookie を判定しない）。捨てた数を返す
 */
export const pushCookies = (list: string[], vals: string[]): number => {
  let dropped = 0;
  for (const x of vals) list.push(x);   // push(...) に広げない（長い Set-Cookie でスタックがあふれる）
  if (list.length > MAX_SET_COOKIES) { dropped = list.length - MAX_SET_COOKIES; list.splice(0, dropped); }
  return dropped;
};
/** 上限を超えた Set-Cookie のあるターゲットの警告 */
export const cookieCapWarnings = (targets: Target[]): ParseWarning[] => targets.flatMap(t => {
  const n = t.responses.reduce((a, r) => a + (r.droppedCookies ?? 0), 0);
  return n ? [{ kind: 'too-many-cookies' as const, label: t.label, detail: `ターゲット「${t.label}」：1つの応答の Set-Cookie が${MAX_SET_COOKIES}個を超えたので、先の${n}個を判定に使いませんでした（ブラウザも1つのドメインに約180個までしか保存せず、古いものから捨てます）` }] : [];
});
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
  // 同じサイト（apex と www）の https への転送も含める（finalResponse と同じ。http://example.com → https://www.example.com のよくある形）
  try { return !!last && new URL(last).protocol === 'https:' && siteOf(new URL(last).hostname.toLowerCase()) === siteOf(new URL(t.url!).hostname.toLowerCase()); } catch { return false; }
};

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

/**
 * そのターゲットの URL 自身の応答から始まるチェーン。http から https に転送されたチェーン（HAR はターゲットの URL を https にする。
 * curl は upgradedToHttps）は、最初の https のホップから始める（apex の「自身の応答」や、E-05・E-11 の「そのURLの応答」に http の転送を使わないため）
 */
export function ownChain(t: Target): HttpResponse[] {
  const c = chainOf(t);
  if (!/^https:/i.test(t.url ?? '') && !upgradedToHttps(t)) return c;
  const i = c.findIndex(r => /^https:/i.test(r.url ?? ''));
  return i > 0 ? c.slice(i) : c;
}

export function isHttps(t: Target): boolean | undefined {
  const u = t.url ?? t.meta.url_effective;
  if (u) return /^https:\/\//i.test(u) || upgradedToHttps(t);   // スキームは大文字小文字を区別しない（HTTPS://…）
  // ALPN の行は、curl 7.83 より前は「ALPN, server accepted to use h2」、以降は「ALPN: server accepted h2」。Windows の Schannel 版の curl は
  // 「SSL connection using」の行を出さないので、ALPN の行が HTTPS の手がかりになる
  if (t.info.some(l => /SSL connection using|ALPN[:,]/.test(l))) return true;
  if (t.info.some(l => /^(?:Connected to|Established connection to) .* port 80\b/.test(l))) return false;   // 今の curl は Established connection to とも出す
  return undefined;
}

export function responseKind(t: Target, r?: HttpResponse): ResponseKind {
  if (t.kind !== 'auto') return t.kind;
  const ct = r?.headers.get('content-type')?.[0]?.toLowerCase() ?? '';
  if (/^application\/(?:[\w.-]+\+)?json\b/.test(ct)) return 'api';
  // XHTML（application/xhtml+xml）もブラウザが描画する HTML の画面。Content-Type のない応答は、ブラウザが本文から HTML と推測するので、
  // 本文が HTML の始まりのものは HTML とする（other にすると、H-03①（高）・H-06 などの HTML の項目を na も出さずに飛ばす）
  if (ct.startsWith('text/html') || /^application\/xhtml\+xml\b/.test(ct)) return 'html';
  if (!ct && /^\s*(?:<!doctype html|<html)\b/i.test(r?.body ?? '')) return 'html';
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
  // 未来の Date（時計のずれの5分より先）は使わない。Date は診断対象のサーバが書くので、未来の Date で Cookie の期限を短く見せて
  // C-05①（中）を合格にさせない。過去の Date は、前に採取した出力を読み直したときの正しい基準（期限を長く見せる向きにはならない）
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
export const logoutFailed = (t: Target): boolean => {
  const s = firstStatus(t);
  return s >= 400 || (s >= 200 && s < 300 && logoutConfirmPage(t));
};
const LOGOUT_WORD = /log[-_ ]?out|sign[-_ ]?out|log[-_ ]?off|ログアウト|サインアウト/i;
/**
 * ログアウトの確認画面（GET では「ログアウトしますか」のフォームを返すだけで、POST でログアウトする作り。ASP.NET Core Identity の既定の画面、
 * Spring Security の既定のログアウトの確認画面）。ログアウトしていないので、C-12①（高）と H-15 を判定しない。次のすべてに当たるもの：
 * - セッションCookie らしい名前の Cookie を消しも発行し直しもせず、Clear-Site-Data もない（AWSALB のような毎回の Cookie は見ない）
 * - 本文に、送信先（action）に logout・signout・logoff の語がある POST のフォームがあり、その中にログアウトのボタンの文言がある
 *   （action のないフォームや購読のフォームを置くだけで本物のログアウトの C-12① を na に隠せないよう、送信先と文言の両方を見る）
 * - パスワード欄（ログアウトのあとのログインの画面）と、ASP.NET WebForms の __VIEWSTATE（ページ全体を囲むフォーム）がない
 * タグは indexOf で切り出して線形の時間で読む（正規表現の先読みで読むと、<form の繰り返しで3乗の時間がかかる）
 */
function logoutConfirmPage(t: Target): boolean {
  const chain = ownChain(t);
  if (chain.some(r => r.headers.has('clear-site-data') || (r.headers.get('set-cookie') ?? []).some(c => looksLikeSessionName(c.split('=')[0].trim())))) return false;
  const body = (finalResponse(t)?.body ?? '').slice(0, 65536);
  if (/type\s*=\s*["']?password/i.test(body) || /__VIEWSTATE/i.test(body)) return false;
  const low = body.toLowerCase();
  for (let i = low.indexOf('<form'), n = 0; i >= 0 && n < 50; i = low.indexOf('<form', i + 5), n++) {
    const end = low.indexOf('>', i); if (end < 0 || end - i > 2000) continue;
    const tag = low.slice(i, end);
    const method = tag.match(/\bmethod\s*=\s*["']?(\w+)/)?.[1];
    const action = tag.match(/\baction\s*=\s*["']?([^"'\s>]*)/)?.[1] ?? '';
    if (method !== 'post' || !LOGOUT_WORD.test(action)) continue;
    const close = low.indexOf('</form', end);
    const inner = body.slice(end + 1, close < 0 ? end + 4000 : Math.min(close, end + 4000));
    if (LOGOUT_WORD.test(inner.replace(/<[^>]{0,500}>/g, ' ')) || /value\s*=\s*["'][^"']{0,40}(?:log\s*out|sign\s*out|ログアウト)/i.test(inner)) return true;
  }
  return false;
}
