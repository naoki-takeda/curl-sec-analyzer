// parser/setCookie.ts：Set-Cookie の解析とセッションCookieの推定
export interface SetCookie { name: string; value: string; attrs: Map<string, string | true>; raw: string; }

/**
 * 本文・ヘッダの中の JWT（A-03 のデコード用に送った JWT を集める）。直前が英数字・ハイフンでないところから（\b にすると「-eyJ」の繰り返しで
 * 2乗の時間になる）。g フラグなので String.prototype.match だけで使う（exec・test は lastIndex が残る）
 */
export const JWT_IN_TEXT = /(?<![\w-])eyJ[\w-]+\.[\w-]+\.[\w-]*/g;

/**
 * 「=」のない Set-Cookie（set-cookie: <値>; Path=/）は、名前が空で値だけを持つ Cookie（RFC 6265bis 5.6、Chrome・Firefox もこう扱う）。
 * 名前として読むと値が空になり、削除用とみなして C-01・C-02 の判定から外れ、C-12 の証跡に生の値が出る
 */
export function parseSetCookie(raw: string): SetCookie {
  const [nv = '', ...rest] = raw.split(';');
  const i = nv.indexOf('=');
  const name = i >= 0 ? nv.slice(0, i).trim() : '';
  const value = (i >= 0 ? nv.slice(i + 1) : nv).trim();
  const attrs = new Map<string, string | true>();
  for (const a of rest) {
    const j = a.indexOf('=');
    const k = (j >= 0 ? a.slice(0, j) : a).trim().toLowerCase();
    const v = j >= 0 ? a.slice(j + 1).trim() : true;
    // ブラウザが無視する属性は、前の正しい値を上書きしない（RFC 6265 5.2.1〜5.2.3：数字でない Max-Age、日付として読めない Expires、
    // 空の Domain）。例：Max-Age=0; Max-Age=abc は削除、Domain=a.com; Domain= は Domain=a.com
    if (k === 'max-age' && (typeof v !== 'string' || !/^-?\d+$/.test(v))) continue;
    if (k === 'expires' && (typeof v !== 'string' || Number.isNaN(cookieDate(v)))) continue;
    if (k === 'domain' && (typeof v !== 'string' || !v)) continue;
    if (k) attrs.set(k, v);
  }
  return { name, value, attrs, raw };
}

/**
 * 1つのヘッダ値にカンマでつないだ複数の Set-Cookie を1件ずつに分ける（プロキシやフレームワークがまとめる場合がある）。
 * 分けるのは「, 名前=」の前だけで、Expires の日付（Expires=Wed, 21 Oct 2026 …）のカンマでは分けない。
 * 分けないと2つ目以降の Cookie を判定せず、証跡（値は先頭の name=value だけをマスクする）に生の値が出る。
 * 値の中のカンマ（prefs=lang=ja,tz=JST）では分けない：分けるのは、前のかけらがすでに属性（; Path=/ など）を持つときだけ。
 * 分けなかった場合も、値はカンマのあとまでまとめてマスクされる
 */
export function splitSetCookie(v: string): string[] {
  const out: string[] = [];
  // 前のかけらが属性（;）を持つかは真偽値で持つ（伸びていくかけらに毎回 includes をかけると、'a=b,' の繰り返しで2乗の時間がかかる）
  let lastHasAttr = false;
  for (const part of v.split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/)) {
    if (out.length && !lastHasAttr) out[out.length - 1] += `,${part}`; else out.push(part);
    lastHasAttr = part.includes(';');
  }
  return out.map(s => s.trim()).filter(Boolean);
}

/** 削除用のSet-Cookie（空の値、Max-Age<=0、過去のExpires）は判定対象にしない */
export function isDeletion(c: SetCookie, now = Date.now()): boolean {
  if (c.value === '' || c.value === '""') return true;
  const ma = c.attrs.get('max-age');
  // Max-Age は Expires より優先する（RFC 6265 5.3 の手順3。Max-Age=3600 と過去の Expires の Cookie は生きている）。読めない Max-Age は parseSetCookie が捨てる
  if (typeof ma === 'string') return Number(ma) <= 0;
  const ex = c.attrs.get('expires');
  return typeof ex === 'string' && cookieDate(ex) < now;
}

const COOKIE_DELIM = /[\t\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+/;
const COOKIE_MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
/**
 * Cookie の Expires の日時（読めなければ NaN）。RFC 6265 5.1.1 の手順で読む：区切りで語に分け、時刻（hh:mm:ss）・日・月の名前・年を
 * 順に探し、どれかが欠けるか範囲の外なら読めない（ブラウザは Expires を無視し、セッションCookieとして扱う）。2桁の年は 70〜99 を 19xx、
 * 0〜69 を 20xx にする。Date.parse は使わない（Expires=0・-1 を過去の日時と、Expires=2099 を日時と読んでしまう）
 */
export function cookieDate(s: string): number {
  let time: number[] | undefined, day: number | undefined, month: number | undefined, year: number | undefined;
  for (const tok of s.split(COOKIE_DELIM)) {
    if (!tok) continue;
    let m: RegExpMatchArray | null;
    if (!time && (m = tok.match(/^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D|$)/))) time = [Number(m[1]), Number(m[2]), Number(m[3])];
    else if (day === undefined && (m = tok.match(/^(\d{1,2})(?:\D|$)/))) day = Number(m[1]);
    else if (month === undefined && COOKIE_MONTHS.includes(tok.slice(0, 3).toLowerCase())) month = COOKIE_MONTHS.indexOf(tok.slice(0, 3).toLowerCase());
    else if (year === undefined && (m = tok.match(/^(\d{2,4})(?:\D|$)/))) year = Number(m[1]);
  }
  if (!time || day === undefined || month === undefined || year === undefined) return NaN;
  if (year >= 70 && year <= 99) year += 1900; else if (year >= 0 && year <= 69) year += 2000;
  if (day < 1 || day > 31 || year < 1601 || time[0] > 23 || time[1] > 59 || time[2] > 59) return NaN;
  const d = new Date(Date.UTC(year, month, day, time[0], time[1], time[2]));
  return d.getUTCDate() === day ? d.getTime() : NaN;   // 2月30日のような実在しない日は読めない
}

// 設計書：セッションCookieは、名前のパターンと期限がないことで推定する。
// 名前を語（- _ . とキャメルケースの境目）に分けて照合する。部分一致だと sidebar_collapsed（sid）・considered・oauth_state（auth）まで含めてしまう。
// sess で始まる語（session、sessionid、PHPSESSID、JSESSIONID、Drupal の SSESS…）と、sid・token・auth などの語
const SESSION_WORD = /^(?:(?:j|php|s)?sess\w*|sid|token|auth|jwt|login|aspxauth)$/i;
// ASP.NET の認証の Cookie。名前の語（AspNetCore・Identity・Application）にはセッションらしい語がなく、「ログインしたままにする」では期限付きで
// 発行するので、推定ではセッションCookieに見えない。4KB を超えて分割したもの（.AspNetCore.Identity.ApplicationC1・C2）も同じ。
// WordPress のログインの Cookie（wordpress_sec_<hash>・wordpress_logged_in_<hash>）と Shibboleth のセッション（_shibsession_<id>）も、
// 名前の語にセッションらしい語がないので、ここで挙げる
const AUTH_COOKIE = /^(?:\.(?:AspNetCore\.(?:Identity\.Application|Cookies|Session)(?:C\d+)?|ASPXAUTH|AspNet\.ApplicationCookie)|wordpress_(?:sec|logged_in)_\w+|_shibsession_\w+|_oauth2_proxy(?:_\d+)?)$/i;   // _oauth2_proxy は oauth2-proxy（大きいものは _oauth2_proxy_0・_1 に分ける）
/** 名前の語（- _ . とキャメルケースの境目で分ける。sessionExpiry → session・expiry） */
const wordsOfName = (name: string) => name.replace(/([a-z\d])([A-Z])/g, '$1_$2').split(/[-_.]+/).filter(Boolean);
const sessionName = (name: string) => AUTH_COOKIE.test(name) || wordsOfName(name).some(w => SESSION_WORD.test(w));
/** 組織プロファイルで変えられる設定（engine/profile.ts の withProfile が実行中だけ差し替える） */
export const sessionConfig = { names: [] as string[], maxAgeHours: 24 };

// CSRFトークンや設定用のCookie。csrf・xsrf・consent は名前のどこにあってもよい（csrftoken、CookieConsent）。
// それ以外は区切り（- _ .）で分けた語として一致させる。部分一致だと sso_gateway_sid（_ga）や golang_session（lang）まで外れてしまう
// ASP.NET の CSRF 対策（.AspNetCore.Antiforgery.*、__RequestVerificationToken）も同じ。後者は語 Token でセッションらしく見えてしまう
// OpenID Connect のセッション管理（check_session_iframe）のために、仕様上 JS から読む Cookie（IdentityServer の idsrv.session、
// Keycloak の KEYCLOAK_SESSION）は、値を盗まれても認証には使えないのでセッションCookie としない（HttpOnly がなくても C-02①（高）にしない）
const NOT_SESSION = /csrf|xsrf|consent|antiforgery|requestverificationtoken|^idsrv\.session$|^KEYCLOAK_SESSION(?:_LEGACY)?$/i;
// 解析・チャット・決済などの外部サービスの Cookie。名前に session・sid・token を含むが、ログインの状態ではない。
// HAR で送っただけで機密応答と推定すると、robots.txt などの公開ページまで H-12①（高）になる。
// Azure Application Insights の ai_session・ai_user、Adobe Analytics の s_sess、Braze の ab.storage.* も解析用
const THIRD_PARTY = /^(?:_hj|intercom-|AMP_TOKEN$|__stripe_|optimizely|_dd_s$|_uet|_clck$|_clsk$|__hs|hubspot|ajs_|amplitude|mp_|_fbp$|_gcl_|ai_(?:session|user|authUser)$|s_sess$|s_pers$|ab\.storage\.)/i;
// 負荷分散・WAF の Cookie（転送先のサーバの印）。期限がなく値が長いため推定ではセッションCookieに見えるが、利用者ごとの秘密ではない。
// セッションCookieとして扱うと、全員に同じ値を返す ARRAffinity などで C-07②（同じ値）や C-01①・C-02①（高）の誤検知になる。
// Kubernetes の ingress-nginx（INGRESSCOOKIE）、Google Cloud（GCLB）、Azure Front Door（ASLBSA・ASLBSACORS）、Application Gateway
// （ApplicationGatewayAffinity）、Citrix ADC（NSC_…）、Traefik の既定の名前も負荷分散の印。
// AWSELB で始まっても、ALB の認証（OIDC・Cognito）のセッションCookie（AWSELBAuthSessionCookie-0）は利用者ごとのセッションなので除かない
const LOAD_BALANCER = /^(?:BIGipServer|ARRAffinity|AWSALB|AWSELB(?!Auth)|TS01[0-9a-f]{6}|SERVERID$|ROUTEID$|INGRESSCOOKIE$|GCLB$|ASLBSA|ApplicationGatewayAffinity|NSC_|_TRAEFIK_BACKEND$|route$)/i;   // route は nginx-sticky-module-ng の既定の名前
// セッションIDではない語：言語・テーマ・解析（ga・gid）・設定（pref…）と、期限・時刻を表す語（grafana_session_expiry・session_timeout・
// token_expires_at。画面の JS が読む期限の Cookie で、HttpOnly がなくても C-02①・C-07①②（高）にしない）
const NOT_SESSION_WORD = /^(?:lang|language|locale|theme|ga|gid|pref\w*|expiry|expires?|expired|expiration|timeout|ttl|timestamp)$/i;
// WAF・CDN・ボット対策の Cookie（Cloudflare、Imperva、Akamai）。CDN が発行し、属性（Domain・SameSite・Secure）は運営者が変えられない。
// 期限がなく値が長いものは、推定ではセッションCookieに見える（Imperva の incap_ses_* で C-01①・C-02①（高）の誤検知になる）
// Cloudflare は __cf で始まる名前（__cf_bm、__cflb、__cfruid、__cfwaitingroom）と cf_clearance・cf_ob_info・cf_use_ob・cf_chl_…・_cfuvid
const WAF_CDN = /^(?:__cf|cf_(?:clearance|ob_info|use_ob|chl_)|_cfuvid$|incap_ses_|nlbi_|visid_incap_|ak_bmsc$|bm_sv$|bm_sz$|bm_mi$|_abck$)/i;
const TIME_WORD = /^(?:last|at|time|ts|date|since|until|updated|created|when)$/i;
/**
 * 主のセッションIDらしい名前：sess を含むもの（JSESSIONID・PHPSESSID・laravel_session）と、語として sid で終わるもの（sid・__Host-sid・
 * Express の connect.sid）。C-09 で「再発行したか」を必ず比べる Cookie
 */
export const MAIN_SESSION = /sess|(?:^|[^a-z0-9])sid$/i;
export const notSessionName = (name: string) => NOT_SESSION.test(name) || LOAD_BALANCER.test(name) || WAF_CDN.test(name) || THIRD_PARTY.test(name) || wordsOfName(name).some(w => NOT_SESSION_WORD.test(w));
/**
 * 負荷分散・WAF・CDN の Cookie か。AWSALBCORS・ARRAffinitySameSite・__cf_bm は仕組み上 SameSite=None で、__cf_bm などは Domain を親ドメインにする。
 * 運営者が属性を選べないので、C-03③・C-04① にしない
 */
export const isInfraCookie = (name: string) => LOAD_BALANCER.test(name) || WAF_CDN.test(name);

/**
 * 名前だけでセッションCookieらしいか（リクエストの Cookie ヘッダには期限も属性もないため、名前で推定する）。
 * 組織プロファイルで名前の指定があれば、それだけを使う
 */
export const looksLikeSessionName = (name: string): boolean =>
  sessionConfig.names.length ? sessionConfig.names.some(n => n.toLowerCase() === name.toLowerCase()) : !notSessionName(name) && sessionName(name);

/**
 * Cookie・Authorization を送ったか（機密応答の推定、第0章 0.3②）。ブラウザや curl の Cookie ジャーは解析用・同意用の Cookie（_ga、theme）も送るので、
 * Authorization か、セッションCookieらしい名前（組織プロファイルの指定があればそれ）の Cookie を送ったときだけ数える。curl と HAR で同じ判定にする
 */
export const sentAuthOf = (authorization: boolean, cookieNames: string[]) => authorization || cookieNames.some(looksLikeSessionName);
/** ブラウザが自動で送る（クロスサイトのリクエストにも付く）認証の方式か。Authorization の値の最初の語で見る */
export const autoAuthScheme = (authorization: string) => /^\s*(?:basic|digest|negotiate|ntlm)\b/i.test(authorization);
/** リクエストの Cookie ヘッダの値から名前だけを取り出す */
export const cookieNames = (v: string) => v.split(';').map(c => c.split('=')[0].trim()).filter(Boolean);

/**
 * ASP.NET Core の Cookie の分割の印（.AspNetCore.Cookies=chunks-2。中身は …C1・C2 にある）。セッションCookie の属性の判定（C-01〜C-06）には
 * 含めるが、セッションIDの値として比べるとき（C-07①②・C-09）は除く（約48bit・同じ値の誤検知になる）。
 * セッションCookie の推定からは外さない（外すと、分割した Cookie 全体がセッションCookie とみなされなくなる）
 */
export const isChunkMarker = (c: SetCookie) => /^chunks-\d+$/.test(c.value);
/**
 * 分割した Cookie の2つ目以降のかけら（ASP.NET Core の …C2・C3、oauth2-proxy の _oauth2_proxy_1）。最後のかけらは端数の長さなので、
 * 単独でエントロピーを推定すると C-07①（高）の誤検知になる。値は最初のかけら（…C1・_0）で見る
 */
export const isChunkPiece = (c: SetCookie) => /^\..*C(?:[2-9]|\d{2,})$/.test(c.name) ? AUTH_COOKIE.test(c.name) : /^_oauth2_proxy_[1-9]\d*$/.test(c.name);

/**
 * 値が URL（https://…、エンコードした https%3A%2F%2F…）か、戻り先らしい名前（url・redirect・return・callback・next・dest・path）の
 * エンコードした / で始まるパス（returnUrl=%2Fmypage）か。生の「/」と、名前によらない「%2F」で始まる値は、Base64 のセッションID
 * （/u5G…、Rails の _app_session=%2Fx9Y…（Base64 を URL エンコードしたもの））と見分けられないので含めない
 */
const urlValue = (name: string, v: string): boolean => /^"?https?(?::\/\/|%3A%2F%2F)/i.test(v)
  || (/^"?%2F/i.test(v) && /url|redirect|return|callback|next|dest|path/i.test(name));
/** Set-Cookie がセッションCookieらしいか。now：削除用かどうか（過去の Expires）を判定する時刻。ルールからは採取時刻（RuleContext.now）を渡す */
export function looksLikeSession(c: SetCookie, now = Date.now()): boolean {
  if (isDeletion(c, now)) return false;
  if (sessionConfig.names.length) return sessionConfig.names.some(n => n.toLowerCase() === c.name.toLowerCase());   // 指定があれば推定しない
  if (notSessionName(c.name)) return false;
  // 値が URL・パスのもの（NextAuth の __Secure-next-auth.callback-url=https%3A%2F%2F…、戻り先の returnUrl=%2Fmypage）は、名前に auth・session を
  // 含んでもセッションIDではない（ログインで同じ値を送り直しても C-09①（高）に、サンプルごとに同じ値でも C-07②（高）にしない）
  if (urlValue(c.name, c.value)) return false;
  const persistent = c.attrs.has('expires') || c.attrs.has('max-age');
  // 名前で推定しても、値が真偽値・0・1 のもの（has_session=1、session_active=true）はフラグで、セッションIDではない（ほかの数字の値（SESSIONID=1234）は
  // セッションIDとして C-07 で判定する）。
  // 値が Unix 時刻（1で始まる10桁の秒か13桁のミリ秒。2001〜2033年）で、名前に sess・sid がなく時刻の語（last・at・time など）があるもの
  // （last_login=1731900000）も、時刻でセッションIDではない。時刻の語のない auth=1000000001 は、連番のトークンとして C-07 で判定する
  if (sessionName(c.name)) return !/^(?:true|false|yes|no|on|off|[01])$/i.test(c.value) && !(/^1\d{9}(?:\d{3})?$/.test(c.value) && !MAIN_SESSION.test(c.name) && wordsOfName(c.name).some(w => TIME_WORD.test(w)));
  return !persistent && c.value.length >= 20;
}
