// parser/setCookie.ts：Set-Cookie の解析とセッションCookieの推定
export interface SetCookie { name: string; value: string; attrs: Map<string, string | true>; raw: string; }

export function parseSetCookie(raw: string): SetCookie {
  const [nv = '', ...rest] = raw.split(';');
  const i = nv.indexOf('=');
  const name = (i >= 0 ? nv.slice(0, i) : nv).trim();
  const value = i >= 0 ? nv.slice(i + 1).trim() : '';
  const attrs = new Map<string, string | true>();
  for (const a of rest) {
    const j = a.indexOf('=');
    const k = (j >= 0 ? a.slice(0, j) : a).trim().toLowerCase();
    if (k) attrs.set(k, j >= 0 ? a.slice(j + 1).trim() : true);
  }
  return { name, value, attrs, raw };
}

/**
 * 1つのヘッダ値にカンマでつないだ複数の Set-Cookie を1件ずつに分ける（プロキシやフレームワークがまとめる場合がある）。
 * 分けるのは「, 名前=」の前だけで、Expires の日付（Expires=Wed, 21 Oct 2026 …）のカンマでは分けない。
 * 分けないと2つ目以降の Cookie を判定せず、証跡（値は先頭の name=value だけをマスクする）に生の値が出る
 */
export const splitSetCookie = (v: string): string[] =>
  v.split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/).map(s => s.trim()).filter(Boolean);

/** 削除用のSet-Cookie（空の値、Max-Age<=0、過去のExpires）は判定対象にしない */
export function isDeletion(c: SetCookie, now = Date.now()): boolean {
  if (c.value === '' || c.value === '""') return true;
  const ma = c.attrs.get('max-age');
  if (typeof ma === 'string' && /^-?\d+$/.test(ma.trim()) && Number(ma) <= 0) return true;   // 空や数字でない Max-Age は無視する（RFC 6265 5.2.2）
  const ex = c.attrs.get('expires');
  return typeof ex === 'string' && Date.parse(ex) < now;
}

// 設計書：セッションCookieは、名前のパターンと期限がないことで推定する。
// 名前を語（- _ . とキャメルケースの境目）に分けて照合する。部分一致だと sidebar_collapsed（sid）・considered・oauth_state（auth）まで含めてしまう。
// sess で始まる語（session、sessionid、PHPSESSID、JSESSIONID、Drupal の SSESS…）と、sid・token・auth などの語
const SESSION_WORD = /^(?:(?:j|php|s)?sess\w*|sid|token|auth|jwt|login|aspxauth)$/i;
const SESSION_NAME = { test: (name: string) => name.replace(/([a-z\d])([A-Z])/g, '$1_$2').split(/[-_.]+/).some(w => SESSION_WORD.test(w)) };
/** 組織プロファイルで変えられる設定（engine/profile.ts の withProfile が実行中だけ差し替える） */
export const sessionConfig = { names: [] as string[], maxAgeHours: 24 };

// CSRFトークンや設定用のCookie。csrf・xsrf・consent は名前のどこにあってもよい（csrftoken、CookieConsent）。
// それ以外は区切り（- _ .）で分けた語として一致させる。部分一致だと sso_gateway_sid（_ga）や golang_session（lang）まで外れてしまう
const NOT_SESSION = /csrf|xsrf|consent/i;
// 負荷分散・WAF の Cookie（転送先のサーバの印）。期限がなく値が長いため推定ではセッションCookieに見えるが、利用者ごとの秘密ではない。
// セッションCookieとして扱うと、全員に同じ値を返す ARRAffinity などで C-07②（同じ値）や C-01①・C-02①（高）の誤検知になる
const LOAD_BALANCER = /^(?:BIGipServer|ARRAffinity|AWSALB|AWSELB|TS01[0-9a-f]{6}|SERVERID$|ROUTEID$)/i;
const NOT_SESSION_WORD = /^(?:lang|language|locale|theme|ga|gid|pref\w*)$/i;
export const notSessionName = (name: string) => NOT_SESSION.test(name) || LOAD_BALANCER.test(name) || name.split(/[-_.]+/).some(w => NOT_SESSION_WORD.test(w));

/** now：削除用かどうか（過去の Expires）を判定する時刻。ルールからは採取時刻（RuleContext.now）を渡す */
export function looksLikeSession(c: SetCookie, now = Date.now()): boolean {
  if (isDeletion(c, now)) return false;
  if (sessionConfig.names.length) return sessionConfig.names.some(n => n.toLowerCase() === c.name.toLowerCase());   // 指定があれば推定しない
  if (notSessionName(c.name)) return false;
  const persistent = c.attrs.has('expires') || c.attrs.has('max-age');
  return SESSION_NAME.test(c.name) || (!persistent && c.value.length >= 20);
}
