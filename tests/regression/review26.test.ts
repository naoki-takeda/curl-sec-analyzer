// 第42回（第41回のレビューの重要度「低」の指摘）
import { describe, expect, it } from 'vitest';
import { generateScript } from '../../src/commands';
import { importHar } from '../../src/parser/har';
import { parseOpenssl } from '../../src/parser/openssl';
import { parseInput } from '../../src/parser/input';
import { isDeletion, parseSetCookie } from '../../src/parser/setCookie';
import { isTrustedOrigin, parseProfile } from '../../src/engine/profile';
import { MAX_SUPPRESSIONS, parseSuppressions } from '../../src/engine/suppress';
import { EXACT } from '../../src/recommendationsEn';
import { messageEn } from '../../src/messagesEn';
import { showText } from '../../src/shownText';
import { toMarkdown } from '../../src/export/markdown';
import { validPermissionsPolicy } from '../../src/rules/headers';
import { readFileSync } from 'node:fs';
import { evaluate } from '../helpers';

const OPTS = { host: 'app.example.com:8443', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false };

describe('生成スクリプト', () => {
  const s = generateScript(OPTS);
  it('ポート付きのホストでも、http の採取は 80 番、部分一致の Origin は正しい origin にする', () => {
    expect(s).toContain("'http://app.example.com/'");
    expect(s).not.toContain('http://app.example.com:8443');
    expect(s).toContain("'Origin: https://app.example.com.evil.net'");
    expect(s).toContain("-connect 'app.example.com:8443' -servername 'app.example.com'");
  });
  it('前からある出力ファイルを消してから作る（umask は新しいファイルにだけ効く）', () => {
    expect(s).toMatch(/^umask 077\nrm -f out\.txt old\.txt jar\.txt s1\.txt s2\.txt s3\.txt$/m);
  });
  it('証明書の SAN は見出しと値の2行だけを取り、期限は SAN の前に出す（SAN の改行で notAfter を偽装させない）', () => {
    const line = s.split('\n').find(l => l.startsWith('if [ -n "$cert" ]'))!;
    expect(line).toBe(`if [ -n "$cert" ]; then printf '%s\\n' "$cert" | openssl x509 -noout -subject -issuer -dates; printf '%s\\n' "$cert" | openssl x509 -noout -ext subjectAltName | tr -d '\\r' | head -n 2; fi`);
  });
  it('run.sh：sh（dash）でも止まらない、~/.curlrc を読まない、http はポートを除く', () => {
    const r = readFileSync(new URL('../../run.sh', import.meta.url), 'utf8');
    expect(r).not.toContain('$RANDOM');
    expect(r).toContain('curl -q -sS --connect-timeout 10 --max-time 30 "$@"');
    expect(r).toContain('"http://${HOST%:*}/"');
    expect(r).toMatch(/^rm -f out\.txt/m);
  });
});

describe('パーサ', () => {
  it('T-11：#META at のない採取では、サーバの過去の Date を証明書の期限の基準にしない', () => {
    const soon = new Date(Date.now() + 10 * 86400e3).toUTCString().replace(/^\w+, (\d+) (\w+) (\d+) ([\d:]+) GMT$/, '$2 $1 $4 $3 GMT');
    const input = `#TARGET url=https://www.example.com/ label=tls\nHTTP/2 200\ndate: Mon, 01 Jan 2001 00:00:00 GMT\n\nCONNECTED(00000003)\nsubject=CN = www.example.com\nnotAfter=${soon}\n`;
    expect(evaluate(input).findings.filter(f => f.item === 'T-11').map(f => f.ruleId)).toContain('T-11.2');
  });
  it('HAR：文字列でない値で、取り込み全体を失敗させない', () => {
    const entry = (over: object) => ({ startedDateTime: '2026-11-01T00:00:00Z', request: { method: 'GET', url: 'https://www.example.com/', headers: [] },
      response: { status: 200, httpVersion: 'h2', headers: [] }, ...over });
    expect(() => importHar(JSON.stringify({ log: { entries: [entry({ response: { status: 200, httpVersion: 2, headers: [] } })] } }))).not.toThrow();
    expect(importHar(JSON.stringify({ log: { entries: {} } })).chains).toEqual([]);
    expect(importHar('null').chains).toEqual([]);
    expect(importHar(JSON.stringify({ log: { entries: [entry({ request: { method: 'GET', url: ['https://www.example.com/'], headers: [] } })] } })).chains).toEqual([]);
    const c = importHar(JSON.stringify({ log: { entries: [entry({ startedDateTime: 1731830400000 })] } })).chains;
    expect(c).toHaveLength(1);
    expect(c[0].at).toBeUndefined();
  });
  it('openssl：失敗したハンドシェイクの Cipher : 0000 を暗号として読まない', () => {
    const info = parseOpenssl(['CONNECTED(00000003)', 'no peer certificate available', 'New, (NONE), Cipher is (NONE)', 'SSL-Session:', '    Protocol  : TLSv1.2', '    Cipher    : 0000'])!;
    expect(info.cipher).toBeUndefined();
    expect(info.protocol).toBeUndefined();
    const ok = parseOpenssl(['New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', 'SSL-Session:', '    Protocol  : TLSv1.3', '    Cipher    : TLS_AES_256_GCM_SHA384'])!;
    expect([ok.protocol, ok.cipher]).toEqual(['TLSv1.3', 'TLS_AES_256_GCM_SHA384']);
  });
  it('#TARGET の書き間違い・受け付けない値を知らせる', () => {
    const w = (line: string) => parseInput(`${line}\nHTTP/2 200\n\n`).warnings.filter(x => x.kind === 'invalid-attr').map(x => x.detail).join('\n');
    expect(w('#TARGET url=https://a.example/ lable=login')).toContain('lable=');
    expect(w('#TARGET url=https://a.example/ label=login/x')).toContain('invalid-label');
    expect(w('#TARGET url=https://a.example/ label=top kind=xml')).toContain('kind=');
    expect(w('#TARGET url=https://a.example/ label=top kind=API sensitive=1 run=0123456789abcdef')).toBe('');
    expect(parseInput('#TARGET url=https://a.example/ label=top kind=API\nHTTP/2 200\n\n').targets[0].kind).toBe('api');
  });
  it('Set-Cookie：ブラウザが無視する後ろの属性で、前の正しい値を上書きしない', () => {
    expect(isDeletion(parseSetCookie('sid=abc; Max-Age=0; Max-Age=abc'))).toBe(true);
    expect(parseSetCookie('sid=abc; Domain=a.example; Domain=').attrs.get('domain')).toBe('a.example');
    expect(parseSetCookie('sid=abc; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Expires=never').attrs.get('expires')).toBe('Wed, 21 Oct 2099 07:28:00 GMT');
    expect(parseSetCookie('sid=abc; Max-Age=60; Max-Age=0').attrs.get('max-age')).toBe('0');   // 正しい値どうしは後ろが勝つ
  });
});

describe('設定ファイル', () => {
  it('組織プロファイル：型の違う時間、存在しない項目を受け付けない', () => {
    for (const v of [true, '12', [12]]) {
      const r = parseProfile(JSON.stringify({ sessionMaxAgeHours: v }));
      expect(r.errors.length, JSON.stringify(v)).toBe(1);
      expect(r.profile!.sessionMaxAgeHours).toBe(24);
    }
    expect(parseProfile(JSON.stringify({ sessionMaxAgeHours: 12 })).profile!.sessionMaxAgeHours).toBe(12);
    expect(parseProfile(JSON.stringify({ severity: { 'H-99': 'low', 'H-10': 'low', 'H-14.1': 'info' } })).errors).toEqual(['severity：「H-99」は項目IDではありません']);
    expect(parseProfile(JSON.stringify({ exclude: ['H-99'] })).errors).toHaveLength(1);
  });
  it('自社の配信元：ポートを書かない登録はどのポートにも、書いた登録はそのポートだけに当たる', () => {
    const u = (s: string) => new URL(s);
    expect(isTrustedOrigin(u('https://cdn.example.com:8443/a.js'), ['*.example.com'])).toBe(true);
    expect(isTrustedOrigin(u('https://cdn.example.com/a.js'), ['https://cdn.example.com:443'])).toBe(true);
    expect(isTrustedOrigin(u('https://cdn.example.com:8443/a.js'), ['https://cdn.example.com:443'])).toBe(false);
    expect(isTrustedOrigin(u('https://cdn.example.com:8443/a.js'), ['cdn.example.com:8443'])).toBe(true);
    expect(isTrustedOrigin(u('https://evil.example/a.js'), ['*.example.com', 'cdn.example.com'])).toBe(false);
    expect(isTrustedOrigin(u('http://cdn.example.com/a.js'), ['https://cdn.example.com'])).toBe(false);
  });
  it('例外ファイル：until は実在する日付の文字列だけ。件数に上限がある', () => {
    const one = (until: unknown) => parseSuppressions(JSON.stringify([{ ruleId: 'H-01', target: 'top', reason: 'r', until }]));
    for (const v of [false, 0, '2026-13-45', '2026-02-30', 20261231]) expect(one(v).errors, JSON.stringify(v)).toHaveLength(1);
    for (const v of [undefined, null, '', '2028-02-29']) expect(one(v).errors, JSON.stringify(v)).toEqual([]);
    const many = parseSuppressions(JSON.stringify(Array.from({ length: MAX_SUPPRESSIONS + 5 }, () => ({ ruleId: 'H-01', target: 'top', reason: 'r' }))));
    expect(many.list).toHaveLength(MAX_SUPPRESSIONS);
    expect(many.errors).toHaveLength(1);
    expect(messageEn(many.errors[0])).not.toMatch(/[ぁ-んァ-ヶ一-龠]/);
  });
});

describe('マスキングとエクスポート', () => {
  it('C-09 の推奨対応に、入力の Cookie の名前をそのまま出さない', () => {
    const name = 'SESSqkzvwxmplrtbnhgfdsa9f3k2';
    const input = `#TARGET url=https://a.example/login label=pre-login\nHTTP/2 200\nset-cookie: ${name}=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; Secure; HttpOnly\n\n`
      + '#TARGET url=https://a.example/login label=login\nHTTP/2 302\nlocation: /home\nset-cookie: auth_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; Path=/; Secure; HttpOnly\n\n';
    const c09 = evaluate(input).findings.filter(f => f.item === 'C-09');
    expect(c09.length).toBeGreaterThan(0);
    for (const f of c09) expect(`${f.evidence} ${f.recommendation}`).not.toContain(name);
  });
  it('決まった推奨対応の文言は、許可リストを通しても変わらない', () => {
    expect(Object.keys(EXACT).filter(k => showText(k) !== k)).toEqual([]);
  });
  it('パーセントエンコードしたバイナリの並びは伏せ、エンコードした日本語は残す', () => {
    expect(showText('https://app.example.com/cb?d=%8F%1A%C3%77%E2%99%10%AB%CD%EF%01%23')).not.toContain('%8F%1A');
    const ja = 'https://www.example.com/%E3%81%8A%E7%9F%A5%E3%82%89%E3%81%9B';   // お知らせ
    expect(showText(ja)).toBe(ja);
    expect(showText('https://www.example.com/a%2F%2F%2F%2Fb')).toBe('https://www.example.com/a%2F%2F%2F%2Fb');
    const masked = showText('?q=%71%6B%7A%76%77%78%6D%70%6C%72');   // 英小文字の乱数をエンコードしたもの
    expect(masked).toContain('…(');
    expect(showText(masked)).toBe(masked);
  });
  it('Markdown：診断対象が返した URL を自動リンクにしない', () => {
    const fs = evaluate('#TARGET url=https://a.example/r?next=https://evil.example label=open-redirect\nHTTP/2 302\nlocation: https://evil.example/login\n\n').findings;
    const md = toMarkdown(fs, [], []);
    expect(md).toContain('https&#8203;://evil.example/login');
    expect(md).not.toMatch(/(?<!&#8203;)https:\/\/evil\.example/);
  });
});

describe('判定ルール', () => {
  const logout = (csd: string) => evaluate(`#TARGET url=https://a.example/logout label=logout\nHTTP/2 302\nlocation: /\nclear-site-data: ${csd}\n\n`).ids('logout').filter(i => i.startsWith('H-15'));
  it('H-15：引用符のない Clear-Site-Data は、ないのと同じ', () => {
    expect(logout('cookies, storage')).toEqual(['H-15.1']);
    expect(logout('"cookies", "storage"')).toEqual(['H-15.ok']);
    expect(logout('"*"')).toEqual(['H-15.ok']);
  });
  it('H-10：Structured Field として読めない Permissions-Policy は、ないのと同じ', () => {
    for (const v of ["camera 'none'; microphone 'none'", 'Camera=()', 'camera=(self', 'camera=()) ']) expect(validPermissionsPolicy(v), v).toBe(false);
    for (const v of ['camera=(), microphone=(), geolocation=()', 'geolocation=(self "https://a.example")', 'fullscreen=*', 'camera=();report-to=main', 'interest-cohort=()', 'sync-xhr=?0'])
      expect(validPermissionsPolicy(v), v).toBe(true);
    const ids = evaluate("#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\npermissions-policy: camera 'none'\n\n<html></html>\n").ids('top');
    expect(ids).toContain('H-10.1');
  });
});
