import { describe, expect, it } from 'vitest';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { applyProfile, parseProfile, profileTemplate } from '../src/engine/profile';
import { diff, diffSummary, parseBaseline } from '../src/engine/diff';
import { coverage, ITEMS } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { looksLikeSession, parseSetCookie } from '../src/parser/setCookie';
import { toMarkdown } from '../src/export/markdown';
import { toJson } from '../src/export/json';
import { evaluate, sampleText } from './helpers';

const t = (label: string, url: string, head: string, extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n`;

describe('組織プロファイル', () => {
  it('ひな形を読み込め、不正な値を指摘する', () => {
    expect(parseProfile(profileTemplate()).errors).toEqual([]);
    const { profile, errors } = parseProfile(JSON.stringify({ name: 'x', severity: { 'H-10': 'critical', 'bad': 'low' }, exclude: ['H-17', 'oops'], sessionMaxAgeHours: -1 }));
    expect(errors.length).toBe(4);
    expect(profile?.exclude).toEqual(['H-17']);
  });
  it('重要度の上書き（条件の指定が優先）と、対象外の項目', () => {
    const { profile } = parseProfile(JSON.stringify({ name: 'org', severity: { 'H-01': 'low', 'H-01.1': 'medium' }, exclude: ['H-17'] }));
    const fs = runAll(parseInput(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html\nx-xss-protection: 1')).targets, { profile });
    const h01 = fs.find(f => f.ruleId === 'H-01.1')!;
    expect([h01.severity, h01.originalSeverity]).toEqual(['medium', 'high']);
    expect(fs.some(f => f.item === 'H-17')).toBe(false);
    expect(coverage(fs, IMPLEMENTED, ITEMS, profile!.exclude).find(c => c.item === 'H-17')?.status).toBe('excluded');
    expect(applyProfile(fs, undefined)).toBe(fs);
  });
  it('セッションCookieの名前と期限の基準を指定でき、実行後は元に戻る', () => {
    const { profile } = parseProfile(JSON.stringify({ name: 'org', sessionCookieNames: ['APPS'], sessionMaxAgeHours: 1 }));
    const input = t('login', 'https://a.example/login', 'HTTP/2 200\ncontent-type: text/html\nset-cookie: APPS=abcdefghijklmnopqrstuvwxyz012345; Max-Age=7200; Secure; HttpOnly; SameSite=Lax\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz012345; Secure; HttpOnly; SameSite=Lax');
    const fs = runAll(parseInput(input).targets, { profile });
    expect(fs.find(f => f.ruleId === 'C-05.1')?.evidence).toContain('APPS=');
    expect(fs.some(f => f.ruleId === 'C-06.1' && f.evidence.startsWith('sid='))).toBe(false);   // sid はセッション扱いしない
    expect(looksLikeSession(parseSetCookie('sid=abcdefghijklmnopqrstuvwxyz012345'))).toBe(true);   // 実行後は既定の推定に戻る
  });
});

describe('前回との差分', () => {
  it('新規・解消・重要度の変化・再診断していない・継続を分ける', () => {
    const before = evaluate(sampleText()).findings;
    const fixed = sampleText().replace('< server: nginx/1.24.0\n', '').replace(/#TARGET url=https:\/\/www\.example\.com\/ label=tls[\s\S]*$/, '');
    const after = evaluate(fixed + t('top2', 'https://www.example.com/x', 'HTTP/2 200\ncontent-type: text/html')).findings;
    const rows = diff(before, after);
    const by = (k: string) => rows.filter(r => r.kind === k).map(r => `${r.ruleId}@${r.target}`);
    expect(by('resolved')).toContain('H-16.1@top');
    expect(by('not-rechecked')).toContain('T-09.1@www.example.com');
    expect(by('new').some(x => x.endsWith('@top2'))).toBe(true);
    expect(by('continuing')).toContain('R-01.1@cors-reflect');
    const s = diffSummary(rows);
    expect(s.resolved).toBeGreaterThan(0);
  });
  it('例外を登録した指摘は「解消」ではなく「例外登録」、例外が外れた指摘は「継続」', () => {
    const before = evaluate(sampleText()).findings;
    const f = before.find(x => x.ruleId === 'R-01.1')!;
    const sup = [{ ruleId: f.ruleId, target: f.target, reason: '検証中', approver: '', until: '' }];
    const after = runAll(parseInput(sampleText()).targets, { suppressions: sup });
    const k = (rows: ReturnType<typeof diff>) => rows.filter(r => r.ruleId === 'R-01.1' && r.target === f.target).map(r => r.kind);
    expect(k(diff(before, after))).toEqual(['suppressed']);
    expect(k(diff(after, after))).toEqual([]);                 // 例外のまま変化なし
    expect(k(diff(after, before))).toEqual(['continuing']);    // 期限切れなどで fail に戻った
    expect(diffSummary(diff(before, after)).resolved).toBe(0);
  });
  it('Markdown は証跡のHTMLタグを実体参照にする', () => {
    const fs = evaluate(t('top', 'https://www.example.com/', 'HTTP/2 200\ncontent-type: text/html\n\n<img src="http://cdn.example/a.png">')).findings;
    const md = toMarkdown(fs, coverage(fs, IMPLEMENTED), []);
    // 裸の URL はゼロ幅の空白（&#8203;）で自動リンクにしない（第42回）
    expect(md).toContain('&lt;img src="http&#8203;://cdn.example/a.png"&gt;');
    expect(md).not.toMatch(/<img/i);
  });
  it('エクスポートしたJSONを前回の結果として読み込める', () => {
    const fs = evaluate(sampleText()).findings;
    const { baseline } = parseBaseline(toJson(fs, coverage(fs, IMPLEMENTED), []));
    expect(baseline?.findings.length).toBe(fs.length);
    expect(parseBaseline('{"a":1}').error).toBeDefined();
  });
  it('Markdown に差分とプロファイルを含める', () => {
    const fs = evaluate(sampleText()).findings;
    const md = toMarkdown(fs, coverage(fs, IMPLEMENTED), [], new Date('2026-11-11T00:00:00Z'), { profile: parseProfile(profileTemplate()).profile, diff: { rows: diff(fs, []), baselineAt: '2026-11-01' } });
    expect(md).toContain('## 前回との差分');
    expect(md).toContain('組織名・プロファイル名');
  });
});

describe('差分の突き合わせ（HAR）とプロファイルの違い', () => {
  it('HAR はラベルの番号が変わっても、メソッドとURLで同じターゲットとして突き合わせる', async () => {
    const { importHar, harTargets } = await import('../src/parser/har');
    const { readFileSync } = await import('node:fs');
    const har = readFileSync(new URL('./fixtures/har_chrome.har', import.meta.url), 'utf8');
    const a = importHar(har); const before = runAll(harTargets(a, new Set(['www.example.com'])).targets);
    const b = importHar(har); b.chains.forEach(c => { if (c.label.startsWith('har-')) c.label = `har-${c.id + 100}`; });
    const after = runAll(harTargets(b, new Set(['www.example.com'])).targets);
    const s = diffSummary(diff(before, after));
    expect([s.new, s.resolved, s['not-rechecked']]).toEqual([0, 0, 0]);
  });
  it('プロファイルが違えば警告する', async () => {
    const { profileDiffers } = await import('../src/engine/diff');
    expect(profileDiffers(undefined, undefined)).toBe(false);
    expect(profileDiffers(undefined, parseProfile(JSON.stringify({ name: 'a', severity: { 'H-10': 'low' } })).profile)).toBe(true);
    expect(profileDiffers(parseProfile(JSON.stringify({ name: 'a' })).profile, parseProfile(JSON.stringify({ name: 'b' })).profile)).toBe(false);   // 名前だけの違いは無視
  });
});

describe('プロファイルの除外と二重計上の除去の順番（A-2）', () => {
  it('A-09 を対象外にしても、API応答の nosniff なしは H-08 で数える', () => {
    const { profile } = parseProfile(JSON.stringify({ name: 'org', exclude: ['A-09'] }));
    const fs = runAll(parseInput(t('top', 'https://a.example/api', 'HTTP/2 200\ncontent-type: application/json\n\n{}')).targets, { profile });
    expect(fs.filter(f => f.status === 'fail').map(f => f.ruleId)).toContain('H-08.1');
    expect(fs.some(f => f.item === 'A-09')).toBe(false);
  });
});

describe('HARの例外（A-4）', () => {
  it('HAR のターゲットは「HAR メソッド URL」で登録した例外が、ラベルの番号が変わっても効く', async () => {
    const { importHar, harTargets } = await import('../src/parser/har');
    const { readFileSync } = await import('node:fs');
    const har = readFileSync(new URL('./fixtures/har_chrome.har', import.meta.url), 'utf8');
    const first = runAll(harTargets(importHar(har), new Set(['www.example.com'])).targets);
    const f = first.find(x => x.status === 'fail' && x.targetKey?.startsWith('HAR GET') && x.targetKey.endsWith('/api/me'))!;
    const sup = [{ ruleId: f.ruleId, target: f.targetKey!, reason: 'テスト', approver: '', until: '' }];
    const b = importHar(har); b.chains.forEach(c => { if (c.label.startsWith('har-')) c.label = `har-${c.id + 100}`; });
    const again = runAll(harTargets(b, new Set(['www.example.com'])).targets, { suppressions: sup });
    expect(again.find(x => x.ruleId === f.ruleId && x.targetKey === f.targetKey)?.status).toBe('suppressed');
  });
});

describe('ルールセットの版（A-6）', () => {
  it('エクスポートしたJSONからルールセットの版を読む', () => {
    const fs = evaluate(sampleText()).findings;
    expect(parseBaseline(toJson(fs, coverage(fs, IMPLEMENTED), [])).baseline?.rulesetVersion).toMatch(/^2026\./);
  });
});

describe('E-08：配信元ごとのまとめと、自社の配信元（R-1）', () => {
  const html = '<script src="https://cdn.example.net/a.js"></script><script src="https://cdn.example.net/b.js"></script><script src="https://other.example.org/c.js" integrity="sha384-x" crossorigin="anonymous"></script><script src="https://assets.example.com/d.js"></script>';
  const input = t('top', 'https://www.example.com/', `HTTP/2 200\ncontent-type: text/html\n\n${html}`);
  it('同じ配信元の script は1件にまとめ、件数を証跡に書く', () => {
    const e08 = evaluate(input).findings.filter(f => f.item === 'E-08' && f.status === 'fail');
    expect(e08.map(f => f.evidence.split('（')[0])).toEqual(['https://cdn.example.net', 'https://assets.example.com']);
    expect(e08[0].evidence).toContain('integrity なし 2件／2件');
  });
  it('組織プロファイルの trustedScriptOrigins は対象外（オリジン・ホスト名・*.ドメインで指定できる）', () => {
    const { profile, errors } = parseProfile(JSON.stringify({ name: 'org', trustedScriptOrigins: ['https://cdn.example.net', '*.example.com'] }));
    expect(errors).toEqual([]);
    const e08 = runAll(parseInput(input).targets, { profile }).filter(f => f.item === 'E-08');
    expect(e08.map(f => f.ruleId)).toEqual(['E-08.ok']);
    expect(parseProfile(JSON.stringify({ name: 'x', trustedScriptOrigins: ['javascript:alert(1)'] })).errors.length).toBe(1);
  });
});

describe('W-1・W-2', () => {
  it('R-09：101 は指摘、401・403 は合格、それ以外（200・404）は判定不能', () => {
    const ws = (head: string) => evaluate(t('websocket', 'https://a.example/ws', head, 'sensitive=1')).ids('websocket');
    expect(ws('HTTP/1.1 101 Switching Protocols\nUpgrade: websocket')).toContain('R-09.1');
    expect(ws('HTTP/1.1 403 Forbidden')).toContain('R-09.ok');
    expect(ws('HTTP/1.1 200 OK\ncontent-type: text/plain')).toContain('R-09.na');
    expect(ws('HTTP/1.1 404 Not Found')).toContain('R-09.na');
  });
  it('CSV：ホスト単位・横断の判定にも、元になったターゲットの実施日時・実施コマンドを入れる', async () => {
    const { toCsv } = await import('../src/export/csv');
    const input = [
      '#TARGET url=https://www.example.com/ label=top', '#META at=2026-11-11T10:00:00 cmd=C4', 'HTTP/2 200', 'content-type: text/html', '',
      '#TARGET url=https://www.example.com/login label=pre-login', '#META at=2026-11-11T10:01:00 cmd=C18', 'HTTP/2 200', 'set-cookie: SESSIONID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/', '',
      '#TARGET url=https://www.example.com/login label=login', '#META at=2026-11-11T10:02:00 cmd=C18', 'HTTP/2 302', 'location: /', 'set-cookie: SESSIONID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/', '',
      '#TARGET url=https://www.example.com/ label=tls', '#META at=2026-11-11T10:03:00 cmd=C11・C12・C23', 'subject=CN = www.example.com', 'notAfter=Jan  1 00:00:00 2020 GMT', '',
    ].join('\n');
    const r = evaluate(input);
    const rows = toCsv(r.findings, r.targets).split('\r\n');
    expect(rows.find(x => x.startsWith('C-09,pre-login/login'))).toContain(',2026-11-11T10:02:00,C18,');
    expect(rows.find(x => x.startsWith('T-11,www.example.com'))).toContain(',2026-11-11T10:03:00,C11・C12・C23,');
  });
});

describe('レビュー指摘の修正（低優先度）', () => {
  it('生成スクリプトはプローブの一時ファイルを mktemp で作る', async () => {
    const { generateScript } = await import('../src/commands');
    const s = generateScript({ host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/assets/app.js', dangerous: false });
    expect(s).toContain('probe=$(mktemp)');
    expect(s).not.toContain('/tmp/probe');
  });
  it('証明書・Cookie の期限は採取時刻（#META at）で判定する', () => {
    const tls = (meta: string) => evaluate(`#TARGET url=https://www.example.com/ label=tls\n${meta}\nsubject=CN = www.example.com\nnotAfter=Jun  1 00:00:00 2020 GMT\n`).findings.filter(f => f.item === 'T-11').map(f => f.ruleId);
    expect(tls('#META at=2020-01-01T00:00:00')).toEqual(['T-11.ok']);
    expect(tls('')).toEqual(['T-11.1']);
    const cookie = (meta: string) => evaluate(t('login', 'https://a.example/login', `HTTP/2 200\ncontent-type: text/html\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz012345; Expires=Wed, 01 Jul 2020 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax`, '') .replace('\nHTTP', `\n${meta}\nHTTP`)).ids('login');
    expect(cookie('#META at=2020-06-01T00:00:00')).toContain('C-05.1');           // 採取時には30日先の期限
    expect(cookie('#META x=1').some(id => id.startsWith('C-05'))).toBe(false);   // 採取時刻がなければ今の時刻で、削除用として扱う
  });
  it('例外の期限は手元の日付で比べる', async () => {
    const { isActive, localDate } = await import('../src/engine/suppress');
    expect(localDate(new Date(2026, 10, 13, 1, 0))).toBe('2026-11-13');
    expect(isActive({ ruleId: 'H-01', target: 'top', reason: 'x', approver: '', until: localDate() })).toBe(true);
  });
  it('同じラベルのターゲットは分けて判定し、警告する', () => {
    const r = evaluate(t('top', 'https://a.example/', 'HTTP/2 200\ncontent-type: text/html') + t('top', 'https://a.example/x', 'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains'));
    expect(r.targets.map(x => x.label)).toEqual(['top', 'top#2']);
    expect(r.warnings.some(w => w.kind === 'duplicate-label')).toBe(true);
    expect(r.ids('top')).toContain('H-01.1');
    expect(r.ids('top#2')).toContain('H-01.ok');
  });
  it('セッションCookieの推定から外す名前は、区切った語で判定する', async () => {
    const { notSessionName } = await import('../src/parser/setCookie');
    for (const n of ['XSRF-TOKEN', 'csrftoken', '_ga_ABC123', '_gid', 'django_language', 'user_prefs', 'NEXT_LOCALE', 'CookieConsent']) expect(notSessionName(n), n).toBe(true);
    for (const n of ['sso_gateway_sid', 'golang_session', 'slang_sid', 'sid']) expect(notSessionName(n), n).toBe(false);
  });
  it('HAR のラベル候補は組織プロファイルのセッションCookieの名前に従い、選び直したラベルは残す', async () => {
    const { suggestLabels } = await import('../src/parser/har');
    const { withProfile } = await import('../src/engine/profile');
    const chain = (id: number, method: string, cookie?: string) => ({ id, url: `https://a.example/p${id}`, method, host: 'a.example', status: 200, hops: 1, sentAuth: false, sentAuthorization: false, sentCookieNames: [] as string[], sentTokens: [] as string[],
      responses: [{ httpVersion: '2', status: 200, headers: new Map(cookie ? [['set-cookie', [cookie]]] : []), rawNames: [], kind: 'final' as const }],
      suggested: '', label: '', sensitive: undefined, excluded: false });
    const chains = [chain(0, 'POST', 'APPX=abc; Max-Age=3600; Secure'), chain(1, 'GET')];
    suggestLabels(chains);
    expect(chains[0].label).toBe('har-1');                       // 既定の推定ではセッションCookieではない
    const { profile } = parseProfile(JSON.stringify({ name: 'org', sessionCookieNames: ['APPX'] }));
    withProfile(profile, () => suggestLabels(chains, true));
    expect(chains[0].label).toBe('login');
    chains[0].label = 'har-1'; chains[1].label = 'login';         // 画面で選び直した
    withProfile(profile, () => suggestLabels(chains, true));
    expect(chains.map(c => c.label)).toEqual(['har-1', 'login']);
  });
});
