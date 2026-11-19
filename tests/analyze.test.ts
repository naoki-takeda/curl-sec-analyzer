// 入力から判定まで（engine/analyze.ts。画面は Web Worker の中でこれを呼ぶ）
import { describe, expect, it } from 'vitest';
import { analyzeInput } from '../src/engine/analyze';
import { sampleText } from './helpers';

const req = (text: string, url = '') => ({ text, url, suppressions: [] });

describe('analyzeInput', () => {
  it('サンプルを判定し、ターゲット・警告・指摘を返す', () => {
    const r = analyzeInput(req(sampleText()));
    expect(r.targets.length).toBeGreaterThan(5);
    expect(r.findings.some(f => f.status === 'fail')).toBe(true);
  });
  it('#TARGET のない入力は URL 欄の値で補い、「url= を付けて」の警告は出さない', () => {
    const r = analyzeInput(req('HTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n', 'https://a.example/'));
    expect(r.targets[0].url).toBe('https://a.example/');
    expect(r.warnings.filter(w => w.kind === 'unknown-url')).toEqual([]);
    expect(r.findings.map(f => f.ruleId)).toContain('H-01.1');
  });
  it('URL 欄の値がスキームのない URL なら警告する', () => {
    const r = analyzeInput(req('HTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n', 'www.example.com'));
    expect(r.warnings.find(w => w.kind === 'unknown-url')?.detail).toContain('URL 欄の値を URL として読めません');
  });
  it('応答がなければ、ターゲットも指摘も返さない', () => {
    expect(analyzeInput(req('hello'))).toEqual({ targets: [], warnings: [], findings: [], cov: [] });
  });
  it('結果は Worker から送れる（構造化複製できる）', () => {
    const r = analyzeInput(req(sampleText()));
    expect(structuredClone(r).findings).toEqual(r.findings);
  });
});
