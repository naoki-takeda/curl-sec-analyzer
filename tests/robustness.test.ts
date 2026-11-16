// 性能と、悪意のある入力・壊れた入力への耐性（時間の制限は、CIの遅いマシンでも落ちないよう目標より余裕を持たせる）
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { readFileSync } from 'node:fs';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { applySuppressions, parseSuppressions, wildcardMatch } from '../src/engine/suppress';
import { importHar } from '../src/parser/har';
import { parseProfile } from '../src/engine/profile';
import { parseBaseline } from '../src/engine/diff';

const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const page = (body: string) => `#TARGET url=https://a.example/ label=top\nHTTP/2 200\ncontent-type: text/html\n\n${body}\n`;

describe('性能（設計書の非機能要件）', () => {
  it('1MBの通常の出力を解析・判定できる（目標2秒。CIの差を見込んで6秒を上限にする）', () => {
    const one = readFileSync(new URL('./fixtures/generated_local.txt', import.meta.url), 'utf8');
    const big = one.repeat(Math.ceil(1_000_000 / one.length));
    expect(ms(() => runAll(parseInput(big).targets))).toBeLessThan(6000);
  }, 15_000);   // 上限の6秒を測れるよう、テストのタイムアウト（既定5秒）を延ばす
});

describe('悪意のある入力（Q-1・Q-2）', () => {
  it('例外ファイルの * の多いパターンでも、照合がすぐ終わる（ReDoS）', () => {
    const f = { ruleId: 'H-01.1', item: 'H-01', title: '', severity: 'high', status: 'fail', target: 'x', url: `https://a.example/${'a'.repeat(2000)}`, evidence: '', recommendation: '', references: [], score: 0 } as never;
    const sup = [{ ruleId: 'H-01', target: `${'*a'.repeat(200)}*b`, reason: 'r', approver: '', until: '' }];
    expect(ms(() => applySuppressions([f], sup))).toBeLessThan(500);
    expect(parseSuppressions(JSON.stringify([{ ruleId: 'H-01', target: '*'.repeat(501), reason: 'r' }])).errors[0]).toContain('長すぎ');
  });
  it('wildcardMatch は正規表現の照合と同じ結果になる', () => {
    expect(wildcardMatch('https://a.example/*', 'https://a.example/x/y')).toBe(true);
    expect(wildcardMatch('*/admin/*', 'https://a.example/admin/x')).toBe(true);
    expect(wildcardMatch('https://a.example/*', 'https://b.example/')).toBe(false);
    expect(wildcardMatch('a*b*c', 'axxbyyc')).toBe(true);
    expect(wildcardMatch('a*b*c', 'axxbyy')).toBe(false);
    fc.assert(fc.property(fc.stringMatching(/^[ab*]{0,8}$/), fc.stringMatching(/^[ab]{0,12}$/), (p, s) => {
      const re = new RegExp(`^${p.split('*').join('.*')}$`);   // 短い入力どうしなので正規表現でも安全
      return wildcardMatch(p, s) === re.test(s);
    }), { numRuns: 2000 });
  });
  it('閉じていないタグが大量にある本文でも、判定がすぐ終わる', () => {
    expect(ms(() => runAll(parseInput(page('<script '.repeat(8000))).targets))).toBeLessThan(1500);
    expect(ms(() => runAll(parseInput(page('<form method="post"><input type=password '.repeat(1500))).targets))).toBeLessThan(1500);
  });
});

describe('壊れた入力でも例外を出さない（fast-check）', () => {
  // curl の出力に現れる行の部品を組み合わせて、壊れた入力を作る
  const line = fc.oneof(
    fc.constantFrom('HTTP/2 200', 'HTTP/1.1 301 Moved', 'HTTP/1.1 100 Continue', '#TARGET url=https://a.example/ label=top', '#TARGET label=login sensitive=1',
      '#META at=x cmd=C4', '#PROBE path=/.env code=200 size=1 head=QUJD ct=text/plain', '#TLSPROBE v=tls1 ok=1', '#CIPHERPROBE c=RC4-SHA ok=err',
      '* Connected to a.example (192.0.2.1) port 443', '> Origin: https://evil.example', '> Cookie: sid=1', '< HTTP/2 200', '<', '>', '',
      'set-cookie: sid=abc; Secure; SameSite=None', "content-security-policy: script-src 'nonce-a' *; object-src", 'location: //evil.example',
      'strict-transport-security: max-age=-1', 'content-type: application/json', '{"a":[', 'notAfter=garbage', 'Verify return code: x'),
    fc.string({ maxLength: 40 }));
  it('どんな組み合わせでも parseInput と runAll は例外を出さない', () => {
    fc.assert(fc.property(fc.array(line, { maxLength: 60 }), lines => {
      const r = parseInput(lines.join('\n'));
      runAll(r.targets);
    }), { numRuns: 300 });
  });
  it('設定ファイル（例外・プロファイル・前回の結果・HAR）の壊れたJSONでも例外を出さない', () => {
    fc.assert(fc.property(fc.json(), j => {
      parseSuppressions(j); parseProfile(j); parseBaseline(j);
      try { importHar(j); } catch (e) { if (!(e instanceof Error)) throw e; }   // HAR は読めなければ Error を投げ、画面がメッセージを出す
    }), { numRuns: 300 });
  });
});

describe('設定ファイルの組み合わせ（V-1）', () => {
  it('おかしな前回の結果・プロファイル・例外を組み合わせても、出力に undefined などが出ない', async () => {
    const { diff } = await import('../src/engine/diff');
    const { coverage } = await import('../src/engine/coverage');
    const { IMPLEMENTED } = await import('../src/rules/ruleset');
    const { toMarkdown } = await import('../src/export/markdown');
    const { toCsv } = await import('../src/export/csv');
    const { targets } = parseInput(readFileSync(new URL('../src/sample.txt', import.meta.url), 'utf8'));
    const anyVal = fc.oneof(fc.string(), fc.integer(), fc.constant(undefined), fc.constant(null), fc.array(fc.string(), { maxLength: 2 }));
    const finding = fc.record({ ruleId: fc.oneof(fc.constantFrom('H-01.1', 'C-09.1', 'H-01.ok', 'X'), anyVal), target: fc.oneof(fc.constantFrom('top', 'login'), anyVal),
      status: fc.oneof(fc.constantFrom('fail', 'pass', 'na'), anyVal), severity: fc.oneof(fc.constantFrom('high', 'low'), anyVal), item: fc.oneof(fc.constant('H-01'), anyVal),
      condition: anyVal, title: anyVal, targetKey: anyVal }, { requiredKeys: [] });
    fc.assert(fc.property(fc.array(finding, { maxLength: 8 }), fc.oneof(fc.json(), fc.constant('{"exclude":5,"severity":"x"}')), fc.json(), (fs, pj, sj) => {
      const b = parseBaseline(JSON.stringify({ generatedAt: 'x', rulesetVersion: 'y', findings: fs, profile: JSON.parse(pj) }));
      const { profile } = parseProfile(pj);
      const { list } = parseSuppressions(sj);
      const now = runAll(targets, { profile, suppressions: list });
      const rows = diff(b.baseline!.findings, now);
      const out = toMarkdown(now, coverage(now, IMPLEMENTED), list, new Date(), { profile, diff: { rows, baselineAt: 'x' } }) + toCsv(now, targets);
      expect(out).not.toMatch(/undefined|NaN|\[object Object\]/);
    }), { numRuns: 300 });
  }, 30_000);   // 300通りの組み合わせを試すため、並列で実行して重いときは既定の5秒を超えることがある
  it('形式が合わない指摘は除き、その件数を返す', () => {
    const r = parseBaseline(JSON.stringify({ findings: [
      { ruleId: 'H-01.1', item: 'H-01', target: 'top', status: 'fail', severity: 'high' },
      { ruleId: 'H-01.1', target: 'top', status: 'fail' },                                 // severity なし
      { ruleId: 'H-01.1', item: 'C-01', target: 'top', status: 'fail', severity: 'high' },  // ruleId と item が食い違う
      { ruleId: 'bad', target: 'top', status: 'fail', severity: 'high' }, null, 5] }));
    expect(r.baseline?.findings.map(f => [f.ruleId, f.item, f.condition])).toEqual([['H-01.1', 'H-01', 1]]);
    expect(r.skipped).toBe(5);
  });
});
