// rules/cross.ts：ターゲット横断ルール（C-07②、C-09①、C-12①、H-02③、H-04⑤）
import type { Finding, Rule, Severity, Status, Target } from '../model';
import { capturedAt, finalResponse, firstStatus, isHop, isHttps, logoutFailed, ownChain } from '../parser/target';
import { isDeletion, looksLikeSession, looksLikeSessionName, parseSetCookie } from '../parser/setCookie';
import { maskValue } from '../mask';
import { LOGIN_FAILED_REC, LOGOUT_FAILED_REC, hstsDirective, parseCsp } from './util';

const cf = (rule: Rule, target: string, cond: number | 'ok' | 'na', severity: Severity, status: Status, evidence: string, recommendation: string): Finding =>
  ({ ruleId: `${rule.id}.${cond}`, item: rule.id, condition: typeof cond === 'number' ? cond : undefined, title: rule.title, severity, status,
     target, evidence, recommendation, references: rule.basis, score: 0 });
const na = (rule: Rule, target: string, need: string) => [cf(rule, target, 'na', 'info', 'na', '', `必要なラベル: ${need}`)];

const sessionCookies = (t?: Target) => { const now = t ? capturedAt(t) : Date.now(); return (t?.responses ?? []).flatMap(r => r.headers.get('set-cookie') ?? [])
  .map(raw => parseSetCookie(raw)).filter(c => !isDeletion(c, now) && looksLikeSession(c, now)); };

export const sessionFixation: Rule = { id: 'C-09', title: 'セッション固定化', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP Session Mgmt CS'],
  runCross(x) {
    const pre = x.byLabel('pre-login'), login = x.byLabel('login');
    if (!pre || !login) return na(sessionFixation, 'pre-login/login', 'pre-login, login');
    const before = sessionCookies(pre).map(c => `${c.name}=${c.value}`);
    const after = sessionCookies(login).map(c => `${c.name}=${c.value}`);
    // ログインに失敗した応答（403 など）では、セッションIDを再発行しないのは当然なので判定しない
    const ls = firstStatus(login);
    if (ls && !(ls >= 200 && ls < 400)) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', `ログインに失敗している（HTTP ${ls}）`, LOGIN_FAILED_REC)];
    // ログイン前のセッションIDは、pre-login で発行したものに加え、pre-login で送ったもの（トップページで発行され、ログイン画面では送るだけ。
    // ブラウザの普通の流れで、HAR ではほぼこの形になる）も数える。送っただけの値は分からないので、login で新しいセッションCookieを発行したかで見る
    const sent = (pre.sentCookieNames ?? []).filter(looksLikeSessionName);
    if (!before.length && !sent.length) return [cf(sessionFixation, 'pre-login/login', 'na', 'info', 'na', 'ログイン前にセッションCookieが発行されていない', 'ログイン前にCookieを発行するページで pre-login を採取する')];
    if (!after.length || after.some(a => before.includes(a)))
      return [cf(sessionFixation, 'pre-login/login', 1, 'high', 'fail', 'login 応答でセッションIDが再発行されていない', 'ログイン成功時にセッションIDを再発行する')];
    return [cf(sessionFixation, 'pre-login/login', 'ok', 'info', 'pass', 'ログイン時にセッションIDを再発行している', '')];
  } };

/** 2つ以上のセッションIDを比べ、固定部分や連番がないかを見る */
const JWT_VALUE = /^eyJ[\w-]*\.[\w-]*\.([\w-]*)$/;
export function predictable(raw: string[]): string | undefined {
  // JWT は、同じアカウントで発行するとヘッダとクレーム（iat・exp まで）の大部分が共通になる。乱数性は署名の部分だけで比べる。
  // 署名がない（alg:none）JWT は A-03① で判定する
  const jwt = raw.every(v => JWT_VALUE.test(v));
  if (jwt && raw.some(v => !v.match(JWT_VALUE)![1])) return undefined;
  const ids = jwt ? raw.map(v => v.match(JWT_VALUE)![1]) : raw;
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
    for (const [name, vals] of byName) {
      if (vals.length < 2) continue;
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
    return first.status >= 200 && first.status < 300
      ? [cf(logoutInvalidation, 'after-logout', 1, 'high', 'fail', `旧Cookieでの認証後ページが HTTP ${first.status}`, 'ログアウト時にサーバ側のセッションを破棄する')]
      : [cf(logoutInvalidation, 'after-logout', 'ok', 'info', 'pass', `旧Cookieでの認証後ページが HTTP ${first.status}`, '')];
  } };

export const apexHsts: Rule = { id: 'H-02', title: 'HSTS preload', appliesTo: 'any', scope: 'cross',
  basis: ['hstspreload.org'],
  runCross(x) {
    const preload = x.targets.find(t => isHttps(t) && hstsDirective(finalResponse(t)?.headers.get('strict-transport-security')?.[0], 'preload'));
    if (!preload) return [];                                   // preload を付けていなければ適用外
    const apex = x.byLabel('apex');
    if (!apex) return na(apexHsts, 'apex', 'apex（https://apexドメイン/）');
    // apex 自身の応答（転送の最初のホップ）で見る。-L や HAR で www への転送をたどった最後の応答は www のもの
    const v = ownChain(apex)[0]?.headers.get('strict-transport-security')?.[0];
    return v ? [cf(apexHsts, 'apex', 'ok', 'info', 'pass', `apex: ${v}`, '')]
             : [cf(apexHsts, 'apex', 3, 'low', 'fail', `${preload.label} は preload を付けているが、apex がHSTSを返さない`, 'apex ドメインもHSTS（includeSubDomains; preload）を返す')];
  } };

const nonceOf = (t: Target) => (finalResponse(t)?.headers.get('content-security-policy') ?? [])
  .flatMap(v => [...parseCsp(v).values()].flat()).map(v => v.match(/^'nonce-([^']+)'$/)?.[1]).filter((v): v is string => !!v);
export const fixedNonce: Rule = { id: 'H-04', title: 'CSP：script-src', appliesTo: 'any', scope: 'cross',
  basis: ['OWASP CSP CS', 'Google csp_evaluator'],
  runCross(x) {
    const samples = x.withPrefix('csp-sample-');
    if (samples.length < 2) return na(fixedNonce, 'csp-sample-*', 'csp-sample-1, csp-sample-2（同じURLを2回取得）');
    const nonces = samples.map(nonceOf);
    if (nonces.some(n => !n.length)) return [cf(fixedNonce, 'csp-sample-*', 'na', 'info', 'na', 'CSPにnonceがない', '')];
    const firsts = nonces.map(n => n[0]);
    return new Set(firsts).size < firsts.length
      ? [cf(fixedNonce, 'csp-sample-*', 5, 'high', 'fail', `応答ごとに同じnonce（${maskValue(firsts[0])}）`, 'nonce は応答ごとに新しい乱数で生成する')]
      : [cf(fixedNonce, 'csp-sample-*', 'ok', 'info', 'pass', `${firsts.length}件のnonceはすべて異なる`, '')];
  } };

export const CROSS_RULES: Rule[] = [sessionFixation, sessionPredictable, logoutInvalidation, apexHsts, fixedNonce];
