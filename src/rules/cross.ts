// rules/cross.ts：ターゲット横断ルール（C-07②、C-09①、C-12①、H-02③、H-04⑤）
import type { Finding, Rule, Severity, Status, Target } from '../model';
import { capturedAt, chainOf, finalResponse, firstStatus, hostOf, isHop, isHttps, logoutFailed, ownChain, sameDocument, siteResponses } from '../parser/target';
import { isChunkMarker, isDeletion, looksLikeSession, looksLikeSessionName, notSessionName, parseSetCookie } from '../parser/setCookie';
import { maskValue } from '../mask';
import { LOGIN_FAILED_REC, LOGOUT_FAILED_REC, NO_BODY_REC, errorJson, graphqlError, hstsDirective, noDataJson, parseCsp, parseHsts, splitPolicies } from './util';
import { LOGIN_PATH, loginForm, metaCspFromHtml } from './html';

const cf = (rule: Rule, target: string, cond: number | 'ok' | 'na', severity: Severity, status: Status, evidence: string, recommendation: string): Finding =>
  ({ ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined, title: rule.title, severity, status,
     target, evidence, recommendation, references: rule.basis });
const na = (rule: Rule, target: string, need: string) => [cf(rule, target, 'na', 'info', 'na', '', `必要なラベル: ${need}`)];

// 対象のサイトの応答だけを見る（C-01〜C-07 と同じ siteResponses）。-L でたどった外部の IdP の Cookie（idp_session）を、アプリが
// セッションIDを再発行したものとみなし、C-09① を合格にした
const sessionCookies = (t?: Target) => { const now = t ? capturedAt(t) : Date.now(); return (t ? siteResponses(t) : []).flatMap(r => r.headers.get('set-cookie') ?? [])
  .map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, now) && looksLikeSession(c, now) && !isChunkMarker(c)); };   // 値を比べるので、分割の印は除く

/**
 * 2xx・3xx でもログインに失敗した応答。Spring Security の失敗時の転送（302 Location: /login?error）、ログイン画面への転送、
 * パスワード欄のある画面を 200 で返し直すもの（Django、ASP.NET Identity、WordPress）。失敗ならセッションIDを再発行しないのは当然なので C-09① にしない
 */
// 失敗とみなす転送先：?error などのクエリ、ログインらしいパス（/login・/signin など）、login の URL のパス、pre-login の URL のパス（トップ（/）を除く）。
// パスは末尾の / を除いて比べ、クエリは比べない（/login?next=%2Fhome から /login への転送は失敗）。ただし login の URL のパスがトップ（/）の
// ときは、クエリで画面を切り替えるアプリ（/?_task=login と /?_task=mail）なので、クエリまで比べる。
// pre-login の URL のパスがトップ（/）のときは比べない（HAR では pre-login がトップになることが多く、成功してトップに転送されたのを失敗とみなした）。
// パスワード欄は、login 自身の応答と、ログインらしいパスへ転送したときの最後の応答で見る（-L でたどったアカウント画面のパスワード変更の欄で、
// 成功を失敗とみなさない）
// ログイン画面・認証の入り口のパス：/login・/signin・Devise の /users/sign_in・WordPress の /wp-login.php・OIDC の …/openid-connect/auth・
// /authorize・oauth2-proxy の /oauth2/start・SAML の /saml/login
// 拡張子の付いたログイン画面（ASP.NET の /Account/Login.aspx、/login.php・.jsp・.do）と、Spring Security の /oauth2/authorization/<登録名> も含める
// IdP の入り口（Google の /o/oauth2/v2/auth、Shibboleth の /idp/profile/SAML2/Redirect/SSO、ADFS の /adfs/ls/、SimpleSAMLphp の SSOService.php）も含める。
// T-06 と共有する（rules/html.ts の LOGIN_PATH。T-06 だけ狭い一覧を持っていて、/login.php・/oauth2/authorization/x への転送を合格にした）
const PASSWORD_FIELD = /type\s*=\s*["']?password/i;
/** SPA の画面：ルートの要素（root・app・__next・__nuxt）とスクリプトがあり、スクリプト・スタイル・タグを除いた文字がないか、読み込み中の案内だけの HTML */
// ページのデータを属性やスクリプトに入れたもの（Inertia の data-page、Next.js の __NEXT_DATA__、__INITIAL_STATE__・__NUXT__・__APOLLO_STATE__）は、
// サーバが利用者のデータを返しているので殻としない。文字は、ないか「Loading…」「読み込み中」だけのとき（<noscript> の案内を除く）に限る
// （文字数で見ると、短いサーバ描画のマイページ（マイページ 山田太郎様のご注文）まで殻とみなした）
const spaShell = (b: string): boolean => /<div\b[^>]{0,200}\bid\s*=\s*["']?(?:root|app|__next|__nuxt|q-app)\b/i.test(b) && /<script\b/i.test(b)
  // 状態の名前（__NUXT_DATA__・ng-state・window.Laravel・window.__USER__ など）は一覧で追いきれないので、形で見る：インラインのスクリプトに中身が
  // あり、オブジェクト・配列・JSON を代入・読み込むもの、type="application/json" のスクリプト、ルートの要素の id・class 以外の属性（data-user・
  // Vue の :user）があれば、データを持つ画面として殻としない
  && !/\bdata-page\s*=|__NEXT_DATA__|__INITIAL_STATE__|__NUXT|__APOLLO_STATE__|__PRELOADED_STATE__|\bng-state\b/.test(b)
  && !inlineData(b) && !ROOT_ATTR.test(b)
  && /^(?:loading|読み込み中|ロード中)?[.…]*$/i.test(visibleText(b.replace(/<noscript\b[\s\S]{0,2000}?<\/noscript>/gi, '')));
/** ルートの要素（root・app・__next・__nuxt・q-app）の、データを入れる属性（data-user・:user・v-bind:user。data-v-・data-testid・data-reactroot は除く） */
const ROOT_ATTR = /<div\b(?=[^>]{0,200}\bid\s*=\s*["']?(?:root|app|__next|__nuxt|q-app)\b)[^>]{0,200}\s(?:data-(?!v-|testid\b|reactroot\b)[\w-]+|:[\w-]+|v-bind:[\w-]+)\s*=/i;
/** 利用者・状態のデータらしい中身（"user":・"email":・"currentUser":、state・store・props の名前への代入）。設定（window.__ENV__ = {"API_URL":…}・dataLayer = []）は除く */
const STATE_DATA = /["']?\b(?:user(?:name|_?id)?|current_?user|email|account|profile|customer|member|viewer|me|session|auth(?:enticated|_?user)?|props|state|store)\b["']?\s*:|\b\w*(?:state|store|user|props|session)\w*\s*=\s*(?:[{[]|JSON\.parse)/i;
/**
 * インラインのスクリプト（src のないもの）に、利用者・状態のデータがあるか（先頭の 64KB で、閉じタグまで）：type="application/json" のスクリプト、
 * オブジェクト・配列の代入、JSON.parse のうち、中身が STATE_DATA に当てはまるもの。ld+json（構造化データ）と設定だけのものはデータとしない
 */
/**
 * STATE_DATA に当たった名前のうち、値が null・false・空でないものがあるか（window.Laravel = {"csrfToken":…,"user":null} は、サーバが利用者を
 * 持っていないことを示すので、データとしない。データとみなして C-12①（高）にした。第49回）
 */
/** STATE_DATA の1つ目の選択肢（"user": のような名前） */
const STATE_KEY = /["']?\b(?:user(?:name|_?id)?|current_?user|email|account|profile|customer|member|viewer|me|session|auth(?:enticated|_?user)?)\b["']?\s*:/;
/** 値が null・false・空 */
const EMPTY_VALUE = /^(?:null|false|undefined|""|''|\[\s*\]|\{\s*\})(?![\w$])/;
function stateData(body: string): boolean {
  const re = new RegExp(STATE_DATA.source, 'gi');
  for (let m = re.exec(body), n = 0; m && n < 200; m = re.exec(body), n++) {
    const rest = body.slice(m.index + m[0].length, m.index + m[0].length + 20).trimStart();
    const opened = m[0].trimEnd().slice(-1);
    if (opened === '{' || opened === '[') {
      // 代入の { [ の中（2000文字まで）に利用者のデータらしい名前があれば、その値で見る（Redux・Vuex の SSR の __INITIAL_STATE__ = {"user":null}。
      // { のあとが空でないだけでデータとすると、利用者のいない殻を C-12①（高）にした。束のレビュー）。名前がなければ、空でないものをデータとする
      const inner = body.slice(m.index + m[0].length, m.index + m[0].length + 2000);
      const keys = [...inner.matchAll(new RegExp(STATE_KEY.source, 'gi'))].slice(0, 50);
      if (keys.length ? keys.some(k => !EMPTY_VALUE.test(inner.slice(k.index! + k[0].length, k.index! + k[0].length + 20).trimStart())) : !/^[}\]]/.test(rest)) return true;
      continue;
    }
    if (/^JSON\.parse/i.test(m[0].slice(-10)) || !EMPTY_VALUE.test(rest)) return true;
    if (m[0].length === 0) re.lastIndex++;
  }
  return false;
}
/** パスワード欄のあるフォームの送信先が、ログインらしいパス（LOGIN_PATH）か、送信先がない（同じ URL に送る）か（タグは indexOf で線形に読む） */
function loginFormAction(b: string): boolean {
  const low = b.slice(0, 65536).toLowerCase();
  for (let i = low.indexOf('<form'), n = 0; i >= 0 && n < 50; i = low.indexOf('<form', i + 5), n++) {
    const end = low.indexOf('>', i); if (end < 0 || end - i > 2000) continue;
    const close = low.indexOf('</form', end);
    if (!/type\s*=\s*["']?password/.test(low.slice(end, close < 0 ? end + 8000 : Math.min(close, end + 8000)))) continue;
    const action = low.slice(i, end).match(/(?<![\w-])action\s*=\s*["']?([^"'\s>]*)/)?.[1];   // data-action には当てない
    if (!action) return true;
    try {
      const path = new URL(action, 'https://x.invalid/').pathname.replace(/\/+$/, '');
      // ログインの語を途中に含むパス（/login/password・/users/sign_in・/session）も含める
      if (LOGIN_PATH.test(path) || /(?:^|\/)(?:log-?in|sign-?in|sign_in|sessions?|authenticate|auth|j_(?:spring_)?security_check)(?:[/.]|$)/i.test(path) || path === '') return true;
    } catch { /* 読めない送信先 */ }
  }
  return false;
}
function inlineData(b: string): boolean {
  const s = b.slice(0, 65536), low = s.toLowerCase();
  for (let i = low.indexOf('<script'); i >= 0; i = low.indexOf('<script', i + 7)) {
    const tagEnd = low.indexOf('>', i); if (tagEnd < 0) return false;
    const tag = low.slice(i, tagEnd);
    if (/\bsrc\s*=/.test(tag)) continue;
    const end = low.indexOf('</script', tagEnd); const body = s.slice(tagEnd + 1, end < 0 ? s.length : end);
    if ((/type\s*=\s*["']?application\/json/.test(tag) || /=\s*[{[]|JSON\.parse\s*\(/.test(body)) && stateData(body)) return true;
    if (end < 0) return false;
  }
  return false;
}
/** タグ・スクリプト・スタイルの外の、空白を除いた文字（40 文字まで）。正規表現で除くと、閉じない <script の続く本文で2乗の時間がかかるので、1回の走査で集める */
function visibleText(b: string): string {
  const s = b.slice(0, 65536), low = s.toLowerCase(); let out = '';
  for (let i = 0; i < s.length && out.length < 40;) {
    if (s[i] === '<') {
      const close = low.startsWith('<script', i) ? '</script' : low.startsWith('<style', i) ? '</style' : '>';
      const e = low.indexOf(close, i + 1);
      if (e < 0) break;
      // 閉じタグ（</script>・</style>）は、その「>」まで飛ばす
      const end = close === '>' ? e + 1 : low.indexOf('>', e + close.length) + 1;
      if (end <= 0) break;
      i = end; continue;
    }
    if (!/\s/.test(s[i])) out += s[i];
    i++;
  }
  return out;
}
const MFA_REC = '2段階目（ワンタイムの番号の入力など）まで済ませた応答を login として採取する';
/** login の最初の応答が、多要素認証の2段階目の画面（/two_factor、/mfa、/otp、/2fa、/webauthn）への転送か。/verify-email のようなメールの確認の案内は、ログインが済んでいるので含めない */
function mfaStep(login: Target): string | undefined {
  const first = ownChain(login)[0];
  const loc = first && first.status >= 300 && first.status < 400 ? first.headers.get('location')?.[0] : undefined;
  if (!loc) return undefined;
  let p: string; try { p = new URL(loc, login.url ?? 'https://x.invalid/').pathname; } catch { return undefined; }
  // 最後の部分が2段階目の画面の名前（/mfa、/two_factor_authentication、/2fa）か、2段階目の入力の画面（/two_factor/verify、/mfa/challenge）のときだけ。
  // パスのどこかに mfa・otp があるだけ（/mfa/setup-reminder、/users/otp_settings。ログインが済んだあとの設定の画面）は含めない
  // 各部分の拡張子は外して見る（/2fa.php・/Account/TwoFactor.aspx・/two_factor.html を見逃し、①（高）の誤検知にした）
  const segs = p.replace(/\/+$/, '').split('/').map(x => x.replace(/\.[A-Za-z0-9]{1,5}$/, ''));
  // 2段階目の画面の名前（two-factor-challenge・mfa-otp-challenge のように語が続くものも）。設定の画面の語（setup・settings・reminder・backup・
  // recovery など）が続くものと、その下の部分（/2fa/backup-codes）は除く（除外の一覧で見る。完全一致にすると、Fortify の /two-factor-challenge・
  // GitHub の /sessions/two-factor/app・allauth の /accounts/2fa/authenticate/ を見逃した）
  const settings = /^(?:set-?up|settings?|reminder|recovery|backup|enroll|enable|disable|manage|info|configure|config|preferences)/i;
  const step = (x: string) => { const m = x.match(/^(?:two[-_]?factor|2fa|mfa|otp|totp|webauthn|second[-_]?factor)(?:[-_](.+))?$/i); return !!m && !(m[1] && settings.test(m[1])); };
  const at = segs.findIndex(step);
  return at >= 0 && segs.slice(at + 1).every(x => !settings.test(x)) ? p : undefined;
}
const trimSlash = (p: string) => (p.length > 1 ? p.replace(/\/+$/, '') : p);
function loginRejected(login: Target, pre: Target): string | undefined {
  const first = ownChain(login)[0];
  if (!first) return undefined;
  const loc = first.status >= 300 && first.status < 400 ? first.headers.get('location')?.[0] : undefined;
  if (loc) {
    let to: URL | undefined, self: URL | undefined, before: URL | undefined;
    try { to = new URL(loc, login.url ?? 'https://x.invalid/'); } catch { /* 解釈できない */ }
    try { self = login.url ? new URL(login.url) : undefined; } catch { /* なし */ }
    // pre-login の URL は、そのチェーンの最後の応答（ログインのフォームの画面）の URL。最初の URL（/mypage → 302 /login の /mypage）と比べると、
    // ログインに成功して元のページ（/mypage）に戻る普通の流れを「戻された」とみなした
    const preUrl = ownChain(pre).at(-1)?.url ?? pre.url;
    try { before = preUrl ? new URL(preUrl) : undefined; } catch { /* なし */ }
    if (to) {
      const path = trimSlash(to.pathname);
      const backToSelf = self && (trimSlash(self.pathname) === '/' ? path === '/' && to.search === self.search : path === trimSlash(self.pathname));
      const backToPre = before && trimSlash(before.pathname) !== '/' && path === trimSlash(before.pathname);
      // ログインらしいパスは、同じホストで、認可コード・チケットを持たないものだけ（SSO のコールバック /sso/login?code=… はログインの成功）
      const loginLike = LOGIN_PATH.test(path) && (!self || to.host === self.host) && !/[?&](?:code|ticket|SAMLart|state)=/i.test(to.search);
      if (/[?&](?:error|failed|fail|login_error|authfailed)(?:[=&]|$)/i.test(to.search) || loginLike || backToSelf || backToPre) {
        const fin = finalResponse(login);
        return fin && fin !== first && fin.status >= 200 && fin.status < 300 && PASSWORD_FIELD.test(fin.body ?? '')
          ? `HTTP ${first.status} でログイン画面に戻され、パスワード欄のある画面を返した` : `HTTP ${first.status} でログイン画面に戻された`;
      }
    }
  }
  if (first.status >= 200 && first.status < 300 && PASSWORD_FIELD.test(first.body ?? '')) return `HTTP ${first.status} でパスワード欄のある画面を返した`;
  // JSON の API のログインが、200 でエラーだけの JSON（{"success":false,"error":"invalid_credentials"}）を返した（①（高）にした。第48回）
  if (first.status >= 200 && first.status < 300 && errorJson(first.body)) return `HTTP ${first.status} でエラーの JSON を返した`;
  return undefined;
}

/** 暗号化した Cookie の値：Laravel（base64 の {"iv":…,"value":…,"mac":…}。URL エンコードしたものを含む）と ASP.NET Core の Data Protection（CfDJ8） */
const encryptedCookie = (v: string) => /^(?:eyJpdiI6|CfDJ8)/.test(v);
const ENCRYPTED_REC = 'ログイン前の Cookie だけを送って、ログイン後のページを取得できないか手動で確認する';
export const sessionFixation: Rule = { id: 'C-09', title: 'セッション固定化', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP Session Mgmt CS'],
  runCross(x) {
    const pre = x.byLabel('pre-login'), login = x.byLabel('login');
    if (!pre || !login) return na(sessionFixation, 'pre-login/login', 'pre-login, login');
    const beforeC = sessionCookies(pre), afterC = sessionCookies(login);
    const before = beforeC.map(c => `${c.name}=${c.value}`);
    // 新しい値のセッションCookie を1つでも発行し、同じ値で送り直したのが期限付きの Cookie（device_token・remember の類）だけなら、再発行している
    // （名前の推定でセッションCookie とみなした長期の Cookie を同じ値で送り直しただけで、①（高）にした）
    const fresh = afterC.some(c => !before.includes(`${c.name}=${c.value}`));
    // 名前がセッションらしい Cookie を新しい値にしたか（visitor_ref だけが新しく、主のセッションCookie（APPCTX）を同じ値で送り直したログインを、
    // 期限のない名前のない Cookie を除いて合格にした。束のレビュー）
    const freshSession = afterC.some(c => looksLikeSessionName(c.name) && !before.includes(`${c.name}=${c.value}`));
    // 期限のない Cookie でも、名前がセッションらしくないもの（visitor_ref）は除く（同じ値で送り直しただけで①（高）にした。第49回）。
    // 除くのは、名前がセッションIDらしくないもの（sessionid・JSESSIONID・laravel_session・sid は、期限付きでも主のセッションIDなので比べる。
    // 除くと、期限付きの sessionid を再発行せずに auth_token を足しただけのログインを合格にした）
    const after = afterC.filter(c => !(fresh && !/sess|^sid$/i.test(c.name) && before.includes(`${c.name}=${c.value}`) && (c.attrs.has('expires') || c.attrs.has('max-age') || (freshSession && !looksLikeSessionName(c.name))))).map(c => `${c.name}=${c.value}`);
    // ログインに失敗した応答（403 など）では、セッションIDを再発行しないのは当然なので判定しない
    const ls = firstStatus(login);
    if (ls && !(ls >= 200 && ls < 400)) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `ログインに失敗している（HTTP ${ls}）`, LOGIN_FAILED_REC)];
    const rejected = loginRejected(login, pre);
    if (rejected) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `ログインに失敗している（${rejected}）`, LOGIN_FAILED_REC)];
    // 多要素認証の途中（2段階目の画面への転送）は、ログインが終わっていない。セッションIDの再発行は、ふつう2段階目のあとに行う
    const mfa = mfaStep(login);
    if (mfa) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `多要素認証の途中（${mfa} への転送）。ログインが終わっていない`, MFA_REC)];
    // ログイン前のセッションIDは、pre-login で発行したものに加え、pre-login で送ったもの（トップページで発行され、ログイン画面では送るだけ。
    // ブラウザの普通の流れで、HAR ではほぼこの形になる）も数える。送っただけの値は分からないので、login で新しいセッションCookieを発行したかで見る
    const sent = (pre.sentCookieNames ?? []).filter(looksLikeSessionName);
    if (!before.length && !sent.length) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', 'ログイン前にセッションCookieが発行されていない', 'ログイン前にCookieを発行するページで pre-login を採取する')];
    // SSO のコールバック（Location に ?code=・?ticket=）へ転送しただけで、その先を採取していない（-L なし）なら、セッションはコールバックで発行される
    // ので、再発行したかは分からない
    const lc = ownChain(login);
    // login の応答がない（プロキシの CONNECT のあとで curl が失敗した）なら、ログインしたかが分からない（応答がないまま①（高）にした。束のレビュー）
    if (!lc.length) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', 'login の応答がない', LOGIN_FAILED_REC)];
    if (!after.length && lc.length === 1 && /[?&](?:code|ticket|SAMLart)=/i.test(lc[0].headers.get('location')?.[0] ?? ''))
      return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `HTTP ${lc[0].status}（SSO のコールバックへの転送。その先を採取していない）`, '-L を付けて、転送先まで採取し直す')];
    const reused = !after.length || after.some(a => before.includes(a));
    // 2xx のログインで本文を採取していない（-v -o /dev/null、HAR の本文なし）なら、パスワード欄のある画面を返し直す失敗（loginRejected）と
    // 成功を見分けられない。失敗ならセッションIDを再発行しないのは当然なので、①（高）にせず na にする（3xx は Location で見分けるので判定する）
    if (reused && lc[0] && lc[0].status >= 200 && lc[0].status < 300 && !lc[0].body?.trim())
      return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `login 応答が HTTP ${lc[0].status}（本文を採取していないので、ログインに成功したかは分からない）`, NO_BODY_REC)];
    if (reused)
      return [cf(sessionFixation, 'pre-login/login', 1, 'high', 'fail', 'login 応答でセッションIDが再発行されていない', 'ログイン成功時にセッションIDを再発行する')];
    // pre-login で発行した主のセッションID（名前に sess・sid を含むもの）を、login で新しい値にせず、別の Cookie（auth_token・
    // ASP.NET Core の .AspNetCore.Identity.Application）だけを発行した。認証を新しい Cookie で持つなら固定化はないが、ログイン前の ID の
    // セッションに認証を結び付けるなら固定化になる。どちらかは応答からは分からないので、合格にしない（新しい Cookie があるだけで合格にした）
    const renewed = new Set(afterC.filter(c => !before.includes(`${c.name}=${c.value}`)).map(c => c.name));
    // 値を変えたセッションCookie が、すべて暗号化した Cookie（Laravel の EncryptCookies・ASP.NET Core の Data Protection）で、ログイン前にも
    // 同じ名前があった：暗号化した値は応答ごとに変わるので、セッションIDを再発行したかは値から分からない（regenerate() を忘れた固定化のある
    // Laravel のアプリを合格にした。第50回）
    const changed = afterC.filter(c => !before.includes(`${c.name}=${c.value}`));
    if (changed.length && changed.every(c => encryptedCookie(c.value) && (beforeC.some(b => b.name === c.name && encryptedCookie(b.value)) || (pre.sentCookieNames ?? []).includes(c.name))))
      return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', 'セッションCookie が暗号化した値（応答ごとに値が変わる）なので、セッションIDを再発行したかは値から分からない', ENCRYPTED_REC)];
    // pre-login で送っただけの主のセッションID（-v・HAR の > Cookie: JSESSIONID=…。ブラウザの普通の流れ）も数える（発行した場合だけを数え、
    // 送っただけの JSESSIONID を再発行せず auth_token だけを発行したログインを合格にした。第49回）
    // 送っただけの名前は、解析用・負荷分散などのセッションCookie でない名前を除く（Hotjar の _hjSession_123・ai_session を数え、C-09 を na に
    // した。第50回）。looksLikeSessionName で絞ると、classic ASP の ASPSESSIONIDxxxx も外して合格にした（束のレビュー）
    const kept = [...new Set([...beforeC.map(c => c.name), ...(pre.sentCookieNames ?? []).filter(n => !notSessionName(n))].filter(n => /sess|^sid$/i.test(n) && !renewed.has(n)))];
    if (kept.length)
      return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `login 応答で ${kept.join(', ')} を再発行せず、ほかの Cookie（${[...renewed].join(', ')}）を発行した。どちらで認証しているかは分からない`,
        `ログイン後に、ログイン前の ${kept.join('・')} だけを送って認証後のページを取得できないか、手動で確認する`)];
    return [cf(sessionFixation, 'pre-login/login', 'ok', 'info', 'pass', 'ログイン時にセッションIDを再発行している', '')];
  } };

/** 2つ以上のセッションIDを比べ、固定部分や連番がないかを見る */
// Flask（itsdangerous）の圧縮したセッション（.eJw… で始まる「.ペイロード.時刻.署名」）も、同じアカウントではペイロードの大部分が共通になる。
// JWT と同じく署名の部分だけで比べる（全体で比べると「先頭57文字が共通」と C-07②（高）の誤検知になる）
// Django の署名付きのセッション（django.contrib.sessions.backends.signed_cookies。「ペイロード:時刻:署名」で、圧縮したものは . で始まる）も同じ
const JWT_VALUE = /^(?:eyJ[\w-]*\.[\w-]*|\.[\w-]+\.[\w-]+)\.([\w-]*)$|^\.?[\w-]+:[\w-]+:([\w-]+)$/;
export function predictable(raw: string[]): string | undefined {
  // JWT は、同じアカウントで発行するとヘッダとクレーム（iat・exp まで）の大部分が共通になる。乱数性は署名の部分だけで比べる。
  // 署名がない（alg:none）JWT は A-03① で判定する
  const jwt = raw.every(v => JWT_VALUE.test(v));
  const sig = (v: string) => { const m = v.match(JWT_VALUE)!; return m[1] ?? m[2] ?? ''; };
  if (jwt && raw.some(v => !sig(v))) return undefined;
  const ids = jwt ? raw.map(sig) : raw;
  if (new Set(ids).size < ids.length) return '同じ値が繰り返し発行された';
  let prefix = 0;
  while (ids.every(v => v[prefix] !== undefined && v[prefix] === ids[0][prefix])) prefix++;
  const minLen = Math.min(...ids.map(v => v.length));
  if (prefix >= Math.max(4, minLen / 2)) return `先頭${prefix}文字が共通`;
  if (ids.every(v => /^\d+$/.test(v))) {
    const n = ids.map(Number).sort((a, b) => a - b);
    if (n.every((v, i) => i === 0 || v - n[i - 1] < 1000)) return '数値の連番に近い';
  }
  return undefined;
}
export const sessionPredictable: Rule = { id: 'C-07', title: 'セッションIDの長さ・推測可能性', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP Session Mgmt CS'],
  runCross(x) {
    const samples = x.withPrefix('session-sample-');
    if (samples.length < 2) return na(sessionPredictable, 'session-sample-*', 'session-sample-1, session-sample-2（2つ以上）');
    const byName = new Map<string, string[]>();
    // サンプルごとに、名前ごとの値は1つ（最後のもの）にする。同じ応答に同じ Set-Cookie が2つある場合や、-L の転送で同じ Cookie を
    // 再び送る場合に、1つのサンプルの値を2回数えて「同じ値が繰り返し発行された」にしないため
    for (const t of samples) {
      const last = new Map(sessionCookies(t).map(c => [c.name, c.value]));
      for (const [name, value] of last) byName.set(name, [...(byName.get(name) ?? []), value]);
    }
    const out: Finding[] = [];
    for (const [rawName, vals] of byName) {
      if (vals.length < 2) continue;
      const name = rawName || '（名前なし）';   // 値だけの Set-Cookie（rules/cookies.ts の cookieName と同じ表示）
      // 署名付きのトークン（JWT・Flask・Django）がすべて同じ値なのは、同じ秒に同じ内容で署名したため（HS256 は同じ入力から同じ署名になる）。
      // 署名の鍵がなければ作れないので、推測できる（②（高））とはしない
      // 採取の時刻（#META at）が分かり、60秒より離れているときは②（時刻を見ずに na にすると、15分おきに採取した同じ JWT も「同じ秒」とした）。
      // #META at は手元の時刻で、トークンの iat はサーバの時刻なので、同じ秒かどうかでは比べない（秒をまたいだ採取を②（高）にした）。
      // 署名付きの形は、JWT・itsdangerous と、署名が20文字以上の Django の形（固定の値 guest:1:admin は署名付きではない）
      const times = samples.map(t => (t.meta.at ? Date.parse(t.meta.at.replace(' ', 'T')) : NaN));
      const far = times.every(v => !Number.isNaN(v)) && Math.max(...times) - Math.min(...times) > 60e3;
      if (new Set(vals).size === 1 && !far && /^(?:(?:eyJ[\w-]*\.[\w-]*|\.[\w-]+\.[\w-]+)\.[\w-]+|\.?[\w-]+:[\w-]+:[\w-]{20,})$/.test(vals[0])) {
        out.push(cf(sessionPredictable, 'session-sample-*', 'na', 'info', 'na', `${name}：署名付きのトークンが同じ値（同じ秒に同じ内容で署名した可能性）`, '秒をまたいで session-sample を採取し直す'));
        continue;
      }
      // 暗号化した Cookie（Laravel・ASP.NET Core）は、値が暗号文なので、中のセッションIDの推測可能性は値から分からない（暗号文を比べて合格にした。第50回）
      if (vals.every(encryptedCookie)) {
        out.push(cf(sessionPredictable, 'session-sample-*', 'na', 'info', 'na', `${name}：暗号化した Cookie なので、セッションIDの推測可能性は値から分からない`, 'サーバ側のセッションIDの作り方（フレームワークの既定の乱数か）を確認する'));
        continue;
      }
      const why = predictable(vals);
      out.push(why ? cf(sessionPredictable, 'session-sample-*', 2, 'high', 'fail', `${name}：${why}（${vals.map(maskValue).join(' / ')}）`, '暗号論的に安全な乱数でセッションIDを生成する')
                   : cf(sessionPredictable, 'session-sample-*', 'ok', 'info', 'pass', `${name}：${vals.length}件に共通部分・連番なし`, ''));
    }
    return out.length ? out : [cf(sessionPredictable, 'session-sample-*', 'na', 'info', 'na', '比較できるセッションCookieがない', '同じ名前のセッションCookieを2回以上採取する')];
  } };

export const logoutInvalidation: Rule = { id: 'C-12', title: 'ログアウト後のセッション無効化', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP Session Mgmt CS'],
  runCross(x) {
    const lo = x.byLabel('logout'), after = x.byLabel('after-logout');
    if (!lo || !after) return na(logoutInvalidation, 'logout/after-logout', 'logout, after-logout');
    const f = finalResponse(after);
    if (!f) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', '応答がない', '')];
    // ログアウトが失敗した（GET の /logout に 405 など）なら、旧Cookieが使えても当然なので①にしない。
    // ログイン後のページ（mypage）が 2xx でないなら、そもそもセッションがなく、旧Cookieが使えないのも当然なので合格にしない
    if (logoutFailed(lo)) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `ログアウトの応答が HTTP ${firstStatus(lo)}（ログアウトできていない）`, LOGOUT_FAILED_REC)];
    const mp = x.byLabel('mypage'), ms = mp ? firstStatus(mp) : 0;
    if (ms && !(ms >= 200 && ms < 300)) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `ログイン後のページ（mypage）が HTTP ${ms}（ログインできていない）`, LOGIN_FAILED_REC)];
    const first = after.responses.find(isHop)!;
    // ステータスが分からない応答（%{header_json} だけで #META response_code がない）は判定しない（第0章 0.2）
    if (!first.status) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', 'ステータスが分からない', '-w に #META response_code=%{response_code} を加えて採取する')];
    // 同じページ（末尾の / の違いだけ）への転送はたどって、その先で判定する（Django の APPEND_SLASH、Next.js の trailingSlash、Apache の DirectorySlash）。
    // 最初の応答が 2xx でなければすべて合格にすると、301 のあとに旧Cookieで mypage が 200 になるのを見逃した
    const chain = after.responses.filter(isHop);
    let i = 0;
    while (chain[i]?.kind === 'redirect' && sameDocument(chain[i], after.url)) {
      if (!chain[i + 1]) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `HTTP ${chain[i].status}（同じページへの転送。転送先を採取していない）`, '-L を付けて、転送先まで採取し直す')];
      i++;
    }
    const r = chain[i];
    const ev = `旧Cookieでの認証後ページが HTTP ${r.status}${i ? `（同じページへの転送のあと）` : ''}`;
    if (r.status >= 200 && r.status < 300) {
      // 旧Cookieで 200 でも、ログインのフォームを返したなら、セッションは使えていない（転送せずにその場でログイン画面を出すアプリ）。
      // ログインのフォームは、パスワード欄が1つで、ユーザー名・メールの欄があり、パスワード変更の欄（new_password など）がないもの。
      // ログイン後のページ（mypage）自身にパスワード欄があるときは、見分けられないので使わない
      const mpBody = mp ? finalResponse(mp)?.body ?? '' : '';
      // ログイン後のページ（mypage）がないときは、パスワード欄のフォームの送信先がログインらしいパス（または送信先なし）のときだけログイン画面とする
      // （メールアドレスの変更などで再入力を求めるアカウント画面（action="/account/email"）を「ログイン画面」として合格にした。第49回）
      if (loginForm(r.body ?? '') && !mp && !loginFormAction(r.body ?? '')) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（パスワード欄のある画面。送信先がログインらしいパスでなく、ログイン後のページ（mypage）もないので、ログイン画面かは分からない）`, 'ログイン後のデータを返すページを label=mypage として採取する')];
      if (loginForm(r.body ?? '') && !PASSWORD_FIELD.test(mpBody)) return [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', `${ev} でログイン画面（パスワード欄）を返した`, '')];
      // SPA の画面（<div id="root"> とスクリプトだけで、文字のない HTML）は、どのセッションでも同じものを返すので、旧Cookie が使えたかは分からない
      // （A-01・A-11・E-05 の HTML の画面と同じ考え方）
      // データのない JSON（{}・{"user":null}）と GraphQL の認証の拒否は、旧Cookie でデータを返していない（A-01 と同じ判定）。SPA の殻の推奨に従って
      // API の URL を after-logout にすると、未認証の /api/auth/session の {} を①（高）にした
      const gql = graphqlError(r.body);
      if (gql === 'denied') return [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', `${ev}（GraphQL の認証エラー。データは null）`, '')];
      if (gql || noDataJson(r.body)) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（データのない JSON。旧Cookie が使えたかは分からない）`, 'ログイン後のデータを返す API の URL を after-logout として採取し直す')];
      // 本文を採取していない（-D - -o /dev/null、HAR の本文なし）と、ログインのフォーム・SPA の殻・データのない JSON を見分けられない。
      // 生成スクリプトの出力でいつもこの形になり、①（高）にした（C-09① の本文のないログインと同じ。第48回）
      if (!r.body?.trim()) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（本文を採取していないので、旧Cookie が使えたかは分からない）`, NO_BODY_REC)];
      if (spaShell(r.body ?? '')) return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（SPA の画面。旧Cookie が使えたかは分からない）`, 'ログイン後のデータを返す API の URL を after-logout として採取し直す')];
      return [cf(logoutInvalidation, 'after-logout', 1, 'high', 'fail', ev, 'ログアウト時にサーバ側のセッションを破棄する')];
    }
    // 合格にするのは、断られた（401・403）か、ログイン画面へ転送されたときだけ。404・5xx やほかのページへの転送は、セッションが無効かが分からない
    if (r.status === 401 || r.status === 403) return [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', ev, '')];
    if (r.status >= 300 && r.status < 400) {
      const loginUrl = x.byLabel('login')?.url; let loginPath: string | undefined;
      try { loginPath = loginUrl ? trimSlash(new URL(loginUrl).pathname) : undefined; } catch { /* なし */ }
      // ログイン画面・認証の入り口への転送か。トップ（/）への転送はログイン画面とみなさない（トップが利用者の画面を返すアプリ（/dashboard → /）では、
      // 旧Cookie が使えても / へ転送する。-L でたどった先がログインのフォームか 401・403 なら合格）
      const loginRedirect = (h: typeof r): string | undefined => {
        let to: URL | undefined; try { to = new URL(h.headers.get('location')?.[0] ?? '', h.url ?? after.url ?? 'https://x.invalid/'); } catch { return undefined; }
        const p = trimSlash(to.pathname);
        return LOGIN_PATH.test(p) || (loginPath && loginPath !== '/' && p === loginPath) ? to.pathname : undefined;
      };
      // -L でたどった転送は最後まで見る（/oauth2/authorization/x → IdP の …/openid-connect/auth のように、入り口の転送が続くもの）
      for (let k = i; k < chain.length; k++) {
        const h = chain[k];
        if (h.status >= 300 && h.status < 400) {
          const to = loginRedirect(h);
          if (to) return [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', `${ev} → ${to}（ログイン画面へ転送）`, '')];
          continue;
        }
        // 転送の先で断られた・ログインのフォームを返したなら合格
        if (h.status === 401 || h.status === 403 || (h.status >= 200 && h.status < 300 && loginForm(h.body ?? '')))
          return [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', `${ev} → HTTP ${h.status}（ログイン画面・認証が必要）`, '')];
        break;
      }
      return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（転送先がログイン画面か分からない）`, '転送先まで（-L）採取し直す')];
    }
    return [cf(logoutInvalidation, 'after-logout', 'na', 'info', 'na', `${ev}（セッションが無効になったかは分からない）`, '')];
  } };

export const apexHsts: Rule = { id: 'H-02', title: 'HSTS preload', appliesTo: 'any', scope: 'cross',
  basis: ['hstspreload.org'],
  runCross(x) {
    const preloads = x.targets.filter(t => isHttps(t) && hstsDirective(finalResponse(t)?.headers.get('strict-transport-security')?.[0], 'preload'));
    if (!preloads.length) return [];                           // preload を付けていなければ適用外
    const apex = x.byLabel('apex');
    if (!apex) return na(apexHsts, 'apex', 'apex（https://apexドメイン/）');
    // preload を付けたのが apex のドメイン（apex 自身かそのサブドメイン）のときだけ比べる。別のサイト（b.example の www）の preload で、
    // a.example の apex を③にしない
    const ah = hostOf(apex)?.replace(/:\d+$/, '').toLowerCase();
    const related = (t: Target) => { const h = hostOf(t)?.replace(/:\d+$/, '').toLowerCase(); return !ah || !h || h === ah || h.endsWith(`.${ah}`); };
    const preload = preloads.find(related);
    if (!preload) return [];
    // apex 自身の応答（転送の最初のホップ）で見る。-L や HAR で www への転送をたどった最後の応答は www のもの
    // max-age=0 は HSTS を解除する指定なので、返していないのと同じ（H-01①と同じ）
    // apex 自身の https の応答で見る。http で採取して https の apex に転送したもの（http://a.example → https://a.example → www）は、その https の
    // ホップ。https の apex の応答がなければ、HSTS を返すかは分からない（「HSTSを返さない」とは言わない。http の応答の HSTS はブラウザが無視する）
    const httpsHop = /^https:/i.test(apex.url ?? '') ? ownChain(apex)[0]
      : chainOf(apex).find(r => { try { const u = new URL(r.url ?? ''); return u.protocol === 'https:' && u.hostname.toLowerCase() === ah; } catch { return false; } });
    if (!httpsHop && isHttps(apex) !== undefined) return [cf(apexHsts, 'apex', 'na', 'info', 'na', 'apex の https の応答がない（http の応答の HSTS はブラウザが無視する）', 'apex の https の URL（https://apexドメイン/）で採取する')];
    const v = (httpsHop ?? ownChain(apex)[0])?.headers.get('strict-transport-security')?.[0];
    return v && parseHsts(v).maxAge > 0 ? [cf(apexHsts, 'apex', 'ok', 'info', 'pass', `apex: ${v}`, '')]
             : [cf(apexHsts, 'apex', 3, 'low', 'fail', `${preload.label} は preload を付けているが、apex がHSTSを返さない`, 'apex ドメインもHSTS（includeSubDomains; preload）を返す')];
  } };

// ヘッダの CSP と、HTML の <head> の <meta> の CSP（H-04 と同じ。meta の CSP の nonce が固定でも⑤）。スクリプトに効くディレクティブ
// （<script> の要素に効くもの）の nonce だけ。どのディレクティブでも最初の nonce を
// 比べると、style-src の固定の nonce で⑤（高）を出し、script-src の固定の nonce を見逃した
// <script> の要素に効くのは、CSP3 のとおり script-src-elem、なければ script-src、なければ default-src（script-src があるときの default-src の
// nonce は、スクリプトには効かない）。'nonce-' の部分は大文字・小文字を区別しない（値は区別する）
const nonceOf = (t: Target) => new Set([...splitPolicies(finalResponse(t)?.headers.get('content-security-policy') ?? []), ...metaCspFromHtml(finalResponse(t)?.body ?? '')]
  .flatMap(v => { const d = parseCsp(v); return d.get('script-src-elem') ?? d.get('script-src') ?? d.get('default-src') ?? []; })
  .map(v => v.match(/^'nonce-([^']+)'$/i)?.[1]).filter((v): v is string => !!v));
export const fixedNonce: Rule = { id: 'H-04', title: 'CSP：script-src', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP CSP CS', 'Google csp_evaluator'],
  runCross(x) {
    const samples = x.withPrefix('csp-sample-');
    if (samples.length < 2) return na(fixedNonce, 'csp-sample-*', 'csp-sample-1, csp-sample-2（同じURLを2回取得）');
    const nonces = samples.map(nonceOf);
    if (nonces.some(n => !n.size)) return [cf(fixedNonce, 'csp-sample-*', 'na', 'info', 'na', 'CSPのスクリプトのディレクティブにnonceがない', '')];
    // 2つ以上の応答に現れた nonce（同じ応答の中で同じ nonce を繰り返すのは固定ではない）
    const seen = new Set<string>();
    const fixed = nonces.flatMap(n => { const dup = [...n].filter(v => seen.has(v)); n.forEach(v => seen.add(v)); return dup; });
    return fixed.length
      ? [cf(fixedNonce, 'csp-sample-*', 5, 'high', 'fail', `応答ごとに同じnonce（${maskValue(fixed[0])}）`, 'nonce は応答ごとに新しい乱数で生成する')]
      : [cf(fixedNonce, 'csp-sample-*', 'ok', 'info', 'pass', `${nonces.length}件の応答のnonceはすべて異なる`, '')];
  } };

export const CROSS_RULES: Rule[] = [sessionFixation, sessionPredictable, logoutInvalidation, apexHsts, fixedNonce];
