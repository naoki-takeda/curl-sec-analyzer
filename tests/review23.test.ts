// 23回目のレビュー（リポジトリ全体を新しい目で見直したもの）で見つかった不具合の再現テスト。小さな束に分けて直す（第40回）
import { describe, expect, it } from 'vitest';
import { diff, parseBaseline } from '../src/engine/diff';
import { tags } from '../src/rules/html';
import { toJson } from '../src/export/json';
import type { Finding } from '../src/model';
import { evaluate } from './helpers';

const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
const f = (evidence: unknown) => ({ ruleId: 'E-08.1', item: 'E-08', condition: 1, title: 'SRI', severity: 'low', status: 'fail', target: 'page', targetKey: 'page', evidence, recommendation: '', references: [], score: 0 } as Finding);

describe('束2 2乗の時間と、壊れた前回の結果', () => {
  it('閉じのない <!-- の繰り返しでも、タグの読み取りは本文の長さに比例する', () => {
    expect(ms(() => tags('<!--'.repeat(16384), ['script', 'iframe', 'link', 'img', 'form']))).toBeLessThan(200);
    expect(ms(() => tags('<!-- x'.repeat(11000), ['script']))).toBeLessThan(200);
  });
  it('閉じた <!-- --> の中のタグはこれまでどおり読まない（確認用）', () => {
    expect(tags('<!-- <script src="https://x.example/a.js"></script> --><script src="https://y.example/b.js"></script>', ['script']).map(t => t.attrs.get('src'))).toEqual(['https://y.example/b.js']);
  });
  it('差分のキー：長い英数字とドットの並びの証跡でも速い', () => {
    const ev = 'ab.'.repeat(30000);
    expect(ms(() => diff([f(ev)], [f(ev)]))).toBeLessThan(500);
  });
  it('差分のキー：ホスト名の違いで別の指摘、同じホストは継続（確認用）', () => {
    expect(diff([f('https://cdn-a.example（integrity なし）')], [f('https://cdn-b.example（integrity なし）')]).map(r => r.kind).sort()).toEqual(['new', 'resolved']);
    expect(diff([f('https://cdn-a.example（integrity なし 1件）')], [f('https://cdn-a.example（integrity なし 2件）')]).map(r => r.kind)).toEqual(['continuing']);
  });
  it('前回の結果の evidence が文字列でなくても、差分は例外にならない', () => {
    const { baseline } = parseBaseline(JSON.stringify({ findings: [{ ...f('x'), evidence: 1 }, { ...f('x'), evidence: { a: 1 }, ruleId: 'E-08.2' }] }));
    expect(baseline?.findings).toHaveLength(2);
    expect(() => diff(baseline!.findings, [f('https://cdn-a.example')])).not.toThrow();
  });
  it('大きな CSP の証跡（4KB を超える）でも、自分のエクスポートとの差分は継続（証跡を切らない）', () => {
    const csp = `default-src ${Array.from({ length: 200 }, (_, i) => `https://cdn${i}.example.com`).join(' ')}`;
    const r = evaluate(`#TARGET url=https://a.example/ label=page\n#META at=2026-11-01T10:00:00\nHTTP/2 200\ncontent-type: text/html\ncontent-security-policy-report-only: ${csp}\n\n<p>x</p>\n`);
    const { baseline } = parseBaseline(toJson(r.findings, [], []));
    expect(diff(baseline!.findings, r.findings).every(x => x.kind === 'continuing')).toBe(true);
  });
  it('前回の結果からは、差分で使う項目だけを取り出す', () => {
    const { baseline } = parseBaseline(JSON.stringify({ findings: [{ ...f('x'), suppressedBy: { reason: 'r' }, dedupedBy: 'A-09.2', extra: 'y' }] }));
    const b = baseline!.findings[0] as Finding & { extra?: unknown };
    expect(b.suppressedBy).toBeUndefined();
    expect(b.dedupedBy).toBeUndefined();
    expect(b.extra).toBeUndefined();
  });
});
