// 前回との差分・組織プロファイル・例外の照合（engine/diff.ts・profile.ts・suppress.ts）
import { describe, expect, it } from 'vitest';
import { diff } from '../src/engine/diff';
import { isCurrentKey, legacyHarKey } from '../src/engine/targetKey';
import { parseProfile } from '../src/engine/profile';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { AT, evaluate } from './helpers';

const top = (host: string, hsts: boolean) => `#TARGET url=https://${host}/ label=top\n${AT}\nHTTP/2 200\ncontent-type: text/html\n${hsts ? 'strict-transport-security: max-age=63072000; includeSubDomains\n' : ''}\n<p>x</p>\n`;
const kinds = (rows: ReturnType<typeof diff>, ruleId: string) => rows.filter(r => r.ruleId === ruleId).map(r => r.kind);

describe('差分の突き合わせ', () => {
  it('同じラベルのターゲットが2つから1つに減ったとき、確かめていないターゲットの指摘を「解消」にしない', () => {
    const before = evaluate(top('a.example', false) + top('b.example', true)).findings;
    const after = evaluate(top('b.example', true)).findings;
    const rows = diff(before, after);
    // a.example の H-01①（HSTS なし）は今回確かめていない
    expect(kinds(rows, 'H-01.1')).toEqual(['not-rechecked']);
    // b.example の変わっていない指摘は、新規にならない
    expect(rows.filter(r => r.kind === 'new')).toEqual([]);
  });
  it('同じ項目の別の条件を判定しただけで、確かめていない条件の指摘を「解消」にしない', () => {
    const tls = (lines: string) => `#TARGET url=https://www.example.com/ label=top\n${AT}\n${lines}\n`;
    const before = evaluate(`#TARGET url=https://www.example.com/ label=tls\n${AT}\n#TLSPROBE v=tls1 ok=1\n#TLSPROBE v=tls1_2 ok=1\n`).findings;
    const after = evaluate(tls('* Connected to www.example.com (192.0.2.1) port 443\n* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256\n> GET / HTTP/2\n>\n< HTTP/2 200\n<')).findings;
    expect(before.some(f => f.ruleId === 'T-09.1')).toBe(true);
    expect(kinds(diff(before, after), 'T-09.1')).toEqual(['not-rechecked']);
  });
});

describe('組織プロファイルの重要度', () => {
  it('API の応答で情報に下げた HTML 向けの指摘を、プロファイルの重要度で上げない', () => {
    const { profile } = parseProfile(JSON.stringify({ name: 'p', severity: { 'H-10': 'low' } }));
    const input = `#TARGET url=https://www.example.com/api/me label=api sensitive=1\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n{"id":1}\n`;
    const fs = runAll(parseInput(input).targets, { profile });
    const h10 = fs.filter(f => f.item === 'H-10' && f.status === 'fail');
    expect(h10.length).toBeGreaterThan(0);
    expect(h10.every(f => f.severity === 'info' && !f.originalSeverity)).toBe(true);
  });
});

describe('ラベルの *', () => {
  it('label=* は受け付けない（例外の照合で任意の文字列の意味になるため）', () => {
    const r = parseInput(`#TARGET url=https://www.example.com/ label=*\nHTTP/2 200\n\n`);
    expect(r.targets[0].label).toBe('invalid-label');
    expect(r.warnings.map(w => w.kind)).toContain('invalid-attr');
  });
});

describe('空白を含むラベルの差分', () => {
  const page = (host: string) => `#TARGET url=https://${host}/ label="top page"\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n`;
  it('同じラベル（空白を含む）のターゲットが増えても、変わらない指摘を「解消」にしない', () => {
    const rows = diff(evaluate(page('a.example')).findings, evaluate(page('a.example') + page('b.example')).findings);
    expect(rows.filter(r => r.ruleId === 'H-01.1').map(r => r.kind).sort()).toEqual(['continuing', 'new']);
  });
});

describe('差分と Markdown', () => {
  it('機密でない応答だけの合格（limited）で、前回の H-12①（高）を「解消」にしない', () => {
    const page = (s: string) => `#TARGET url=https://www.example.com/mypage label=mypage ${s}\n${AT}\nHTTP/2 200\ncontent-type: text/html\ncache-control: max-age=600\n\n<p>x</p>\n`;
    const rows = diff(evaluate(page('sensitive=1')).findings, evaluate(page('sensitive=0')).findings);
    expect(rows.filter(r => r.ruleId === 'H-12.1').map(r => r.kind)).toEqual(['not-rechecked']);
  });
  it('途中で返すルールで、確かめていない別の条件の前回の指摘を「解消」にしない（同じ条件の別の配信元は「解消」のまま）', () => {
    const page = (hsts: string) => `#TARGET url=https://www.example.com/ label=top\n${AT}\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: ${hsts}\n\n<p>x</p>\n`;
    const rows = diff(evaluate(page('max-age=31536000')).findings, evaluate(page('max-age=86400')).findings);
    expect(rows.filter(r => r.ruleId === 'H-01.4').map(r => r.kind)).toEqual(['not-rechecked']);
  });
  it('前回と組織プロファイルが違う警告を、Markdown にも出す', async () => {
    const { toMarkdown } = await import('../src/export/markdown');
    const md = toMarkdown([], [], [], new Date(), { diff: { rows: [], baselineAt: '2026-11-01', profileWarning: '前回と今回で組織プロファイルが違います。' } });
    expect(md).toContain('> 前回と今回で組織プロファイルが違います。');
  });
});

describe('プロファイルの比べ方・例外ファイル・時間の下限・英語の Markdown', () => {
  it('重要度のキーの順番だけが違うプロファイルは、違うとしない', async () => {
    const { profileDiffers } = await import('../src/engine/diff');
    const a = parseProfile('{"severity":{"H-10":"low","H-14.1":"info"}}').profile!, b = parseProfile('{"severity":{"H-14.1":"info","H-10":"low"}}').profile!;
    expect(profileDiffers(a, b)).toBe(false);
    expect(profileDiffers(a, parseProfile('{"severity":{"H-10":"medium"}}').profile!)).toBe(true);
  });
  it('例外ファイルの存在しない項目ID（H-99・Z-99）はエラーにする', async () => {
    const { parseSuppressions } = await import('../src/engine/suppress');
    const r = parseSuppressions(JSON.stringify([{ ruleId: 'H-99', target: 'top', reason: 'x' }, { ruleId: 'Z-99.1', target: 'top', reason: 'x' }, { ruleId: 'H-01.1', target: 'top', reason: 'x' }]));
    expect(r.list.map(s => s.ruleId)).toEqual(['H-01.1']);
    expect(r.errors).toHaveLength(2);
  });
  it('sessionMaxAgeHours は1以上（0.5 はエラーにして既定の24時間）', () => {
    const r = parseProfile('{"sessionMaxAgeHours":0.5}');
    expect(r.errors).toHaveLength(1);
    expect(r.profile?.sessionMaxAgeHours).toBe(24);
  });
  it('英語の Markdown に全角の区切り文字を残さない', async () => {
    const { setLang } = await import('../src/i18n');
    const { toMarkdown } = await import('../src/export/markdown');
    const { coverage } = await import('../src/engine/coverage');
    const { IMPLEMENTED } = await import('../src/rules/ruleset');
    const before = evaluate('#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n').findings;
    const r = evaluate('#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=1\n\n<p>x</p>\n');
    // 言語の切り替えは <html lang> も書き換えるので、テストでは document の代わりを置く
    const g = globalThis as { document?: unknown }; const had = 'document' in g;
    if (!had) g.document = { documentElement: {} };
    setLang('en');
    try {
      const md = toMarkdown(r.findings, coverage(r.findings, IMPLEMENTED), [], new Date('2026-11-01T00:00:00Z'), { diff: { rows: diff(before, r.findings), baselineAt: '2026-10-01' } });
      const head = md.split('## Findings')[0];
      expect(head).not.toMatch(/[：、（）]/);
      expect(md).toMatch(/^- Generated: 2026/m);
    } finally { setLang('ja'); if (!had) delete g.document; }
  });
  it('例外ファイルの存在しない項目IDのエラーも英訳する', async () => {
    const { messageEn } = await import('../src/messagesEn');
    expect(messageEn('1件目：ruleId「H-99」は項目IDではありません')).toBe('Entry 1: ruleId "H-99" is not a check ID');
  });
});

describe('空白を含むラベルの例外の照合', () => {
  it('空白を含むラベルの「ラベル URL」のキーで登録した例外は、伏せた部分の * で別のページを抑止しない', async () => {
    const { matches } = await import('../src/engine/suppress');
    const { isCurrentKey } = await import('../src/engine/targetKey');
    expect(isCurrentKey('top page https://a.example/files/*')).toBe(isCurrentKey('toppage https://a.example/files/*'));
    const s = { ruleId: 'H-01.1', target: 'top page https://a.example/files/*', reason: 'x' };
    const f = { item: 'H-01', ruleId: 'H-01.1', target: 'top page', targetKey: 'top page https://a.example/files/admin-console', url: 'https://a.example/files/admin-console' } as never;
    expect(matches(s as never, f, new Set())).toBe(false);
  });
});

describe('以前の形式のキーの見分け方', () => {
  it('空白を含むラベルのキーも、URL の部分で以前の形式かを見分ける', () => {
    expect(legacyHarKey('top page https://a.example/x?token=1')).toBe(true);
    expect(legacyHarKey('top page https://a.example/')).toBe(false);
    expect(isCurrentKey('top page https://a.example/ #2')).toBe(true);
  });
});

describe('存在しない条件番号', () => {
  it('組織プロファイルの重要度は、項目にない条件番号（H-01.9・H-01.0）をエラーにし、ある条件番号は受け付ける', () => {
    const r = parseProfile(JSON.stringify({ severity: { 'H-01.9': 'low', 'H-01.0': 'low', 'H-01.4': 'info', 'H-04.6': 'low' } }));
    expect(r.errors).toEqual(['severity：「H-01.9」は条件番号がH-01にありません（1〜4）', 'severity：「H-01.0」は条件番号がH-01にありません（1〜4）']);
    expect(r.profile?.severity).toEqual({ 'H-01.4': 'info', 'H-04.6': 'low' });
  });
  it('例外ファイルも、項目にない条件番号をエラーにする', async () => {
    const { parseSuppressions } = await import('../src/engine/suppress');
    const r = parseSuppressions(JSON.stringify([{ ruleId: 'H-08.2', target: 'top', reason: 'x' }, { ruleId: 'H-08.1', target: 'top', reason: 'x' }]));
    expect(r.errors).toEqual(['1件目：ruleId「H-08.2」は条件番号がH-08にありません（1〜1）']);
    expect(r.list.map(s => s.ruleId)).toEqual(['H-08.1']);
  });
  it('条件番号のエラーも英訳する', async () => {
    const { messageEn } = await import('../src/messagesEn');
    expect(messageEn('1件目：ruleId「H-08.2」は条件番号がH-08にありません（1〜1）')).toBe('Entry 1: ruleId "H-08.2" is not a condition of H-08 (1 to 1)');
    expect(messageEn('severity：「H-01.9」は条件番号がH-01にありません（1〜4）')).toBe('severity: "H-01.9" is not a condition of H-01 (1 to 4)');
  });
});

describe('組織プロファイルの読み込み', () => {
  it('プロファイルの項目があるかを返す（既定の値と同じ値と、誤りが混ざっていても、プロファイルのファイルとみなす）', () => {
    expect(parseProfile('{"sessionMaxAgeHours":24,"exclude":"T-12"}').recognized).toBe(true);
    expect(parseProfile('{"suppressions":[]}').recognized).toBe(false);
  });
  it('name が文字列でなければ知らせる', () => {
    expect(parseProfile('{"name":1}').errors).toEqual(['name は文字列にしてください']);
  });
});
