import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ITEMS, coverage } from '../src/engine/coverage';
import { asvsLevel, asvsRef, standardsOf, standardsShort } from '../src/engine/standards';
import { IMPLEMENTED } from '../src/rules/ruleset';
import { toMarkdown } from '../src/export/markdown';
import { toJson } from '../src/export/json';
import { evaluate, sampleText } from './helpers';

describe('ASVS 5.0・IPA との対応（v1.0）', () => {
  it('すべての項目が対応の配列を持ち、ASVS の要件IDは原典にあるもの（レベル付き）だけ', () => {
    for (const it of ITEMS) {
      expect(Array.isArray(it.asvs) && Array.isArray(it.ipa), it.id).toBe(true);
      for (const a of it.asvs) {
        expect(a, it.id).toMatch(/^\d+\.\d+\.\d+$/);
        expect(asvsLevel(a), `${it.id} ${a}`).toBeGreaterThanOrEqual(1);
      }
      // 第1章は 4-(iii)・4-(iv)-a、第2章は 2.3-1) の形
      for (const p of it.ipa) expect(p, it.id).toMatch(/^(?:\d+-\((?:i|ii|iii|iv|v|vi|vii|viii|ix|x)\)(?:-[a-c])?|2\.[1-7]-\d\))$/);
    }
  });
  it('代表的な項目の対応', () => {
    expect(standardsOf('H-01')).toEqual({ asvs: ['3.4.1'], ipa: ['2.3-1)'] });
    expect(standardsOf('C-01').ipa).toEqual(['4-(iii)']);
    expect(standardsOf('C-09').ipa).toContain('4-(iv)-a');
    expect(asvsRef('3.4.1')).toBe('v5.0.0-3.4.1 (L1)');
    expect(standardsShort('H-06')).toBe('ASVS 3.4.6・IPA 9-(i)-a');
    // IPA 5-(x) は X-XSS-Protection の有効化を勧めており、H-17 と向きが逆なので対応付けない（設計書の判断の根拠2）
    expect(standardsOf('H-17').ipa).toEqual([]);
  });
  it('設計書（第1〜6章の表の参考文献列）と items.json の対応が一致する', () => {
    const doc = readFileSync(new URL('../docs/design.md', import.meta.url), 'utf8');
    // 項目IDで始まる行は後ろの章（ラベル対応表など）にもあるので、最初に出てくる行（第1〜6章の表）だけを使う
    const rows = new Map<string, string>();
    for (const m of doc.matchAll(/^\| ([HCRTEA]-\d\d) \| .* \| ([^|]*) \|\r?$/gm)) if (!rows.has(m[1])) rows.set(m[1], m[2].trim());
    for (const it of ITEMS) {
      const refs = rows.get(it.id);
      expect(refs, it.id).toBeDefined();
      const asvs = refs!.match(/ASVS 5\.0\.0 ([\d., ]+?)(?:、|$)/)?.[1].split(', ') ?? [];
      const ipa = refs!.match(/IPA ((?:\d[^、]*))(?:、|$)/)?.[1].split(', ') ?? [];
      expect({ asvs, ipa }, it.id).toEqual({ asvs: it.asvs, ipa: it.ipa });
    }
  });
  it('Markdown と JSON に対応を出す', () => {
    const fs = evaluate(sampleText()).findings;
    const cov = coverage(fs, IMPLEMENTED);
    const md = toMarkdown(fs, cov, []);
    expect(md).toContain('| ASVS 5.0.0 | IPA |');
    expect(md).toMatch(/\| H-01 \|.*\| 3\.4\.1 \(L1\) \| 2\.3-1\) \|/);
    const json = JSON.parse(toJson(fs, cov, []));
    expect(json.standards.asvs.version).toBe('5.0.0');
    expect(json.standards.items['C-07'].asvs).toEqual(['7.2.3']);
  });
});

describe('ASVS 5.0 に合わせた既定の基準', () => {
  const login = (cookie: string) => evaluate(`#TARGET url=https://a.example/login label=login\nHTTP/2 200\ncontent-type: text/html\nset-cookie: ${cookie}; Secure; HttpOnly; SameSite=Lax; Path=/\n`).ids('login');
  it('C-07①：セッションIDは128bit以上（7.2.3）。16進16文字（64bit）は不足、32文字（128bit）は合格', () => {
    expect(login('sid=0123456789abcdef')).toContain('C-07.1');
    expect(login('sid=0123456789abcdef0123456789abcdef')).not.toContain('C-07.1');
  });
});
