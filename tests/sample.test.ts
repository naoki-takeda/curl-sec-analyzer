import { describe, expect, it } from 'vitest';
import { countBySeverity, overall } from '../src/engine/summarize';
import { coverage, coverageRate } from '../src/engine/coverage';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toMarkdown } from '../src/export/markdown';
import { evaluate, sampleText } from './helpers';

describe('サンプル入力の通し確認（MVP）', () => {
  const { findings } = evaluate(sampleText());

  it('ターゲット単位・ホスト単位・横断の指摘がそろう', () => {
    const ids = overall(findings).map(r => r.ruleId);
    expect(ids).toEqual(expect.arrayContaining([
      'C-01.1', 'C-09.1', 'C-12.1', 'C-12.2', 'H-02.3', 'H-04.1', 'H-15.1', 'R-01.1', 'T-04.4', 'T-09.1', 'E-03.1', 'E-03.2']));
    expect(countBySeverity(overall(findings)).high).toBeGreaterThanOrEqual(6);
  });

  it('ラベル対応表どおりに項目を絞る（cors-* には第1章を適用しない、http に H-01 を適用しない）', () => {
    expect(findings.some(f => f.target === 'cors-reflect' && f.item.startsWith('H-'))).toBe(false);
    expect(findings.some(f => f.target === 'http' && f.item === 'H-01')).toBe(false);
    expect(findings.some(f => f.target === 'logout' && f.item === 'H-15')).toBe(true);
  });

  it('どの証跡にも生のトークンやCookie値が出ない', () => {
    const all = JSON.stringify(findings) + toMarkdown(findings, coverage(findings, IMPLEMENTED), []);
    expect(all).not.toContain('8f3c2a91d0b74e6fa1c55d3e9b2f7a40');
    expect(all).not.toContain('eyJzdWIiOiJ0ZXN0In0');
    expect(all).not.toContain('cmVmOiByZWZzL2hlYWRzL21haW4K');   // プローブの中身（パターン名だけを出す）
  });

  it('診断カバレッジ：入力がない項目は理由付きで「入力不足」、未実装は「未対応」', () => {
    const cov = coverage(findings, IMPLEMENTED);
    const by = (id: string) => cov.find(c => c.item === id)!;
    expect(by('H-01').status).toBe('evaluated');
    expect(by('C-07').status).toBe('evaluated');                 // ①は判定済み（②は session-sample-* が必要）
    expect(by('R-03').status).toBe('missing-input');
    expect(by('R-03').reasons.join()).toContain('cors-');
    expect(by('T-08').status).toBe('missing-input');
    expect(by('A-01').status).toBe('missing-input');   // unauth-* が必要
    expect(cov.filter(c => c.status === 'not-implemented')).toEqual([]);   // v0.3 で手動以外の全項目を実装
    expect(by('C-15').status).toBe('manual');
    const r = coverageRate(cov);
    expect(r.evaluated).toBeGreaterThan(20);
    expect(r.denominator).toBe(IMPLEMENTED.size);
  });
});
