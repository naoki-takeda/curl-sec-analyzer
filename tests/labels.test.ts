// 診断カバレッジで案内する「必要なラベル」が、ルールの実際の判定範囲と一致することを確かめる
import { describe, expect, it } from 'vitest';
import { RESERVED_HINTS, requiredLabels } from '../src/engine/labels';
import { ITEMS } from '../src/engine/coverage';
import { evaluate } from './helpers';

describe('必要なラベル', () => {
  it('ラベルで判定範囲を絞るルールは、そのラベルだけを案内する', () => {
    expect(requiredLabels('A-08')).toEqual(['ctype']);
    expect(requiredLabels('A-11')).toEqual(['method-*', 'old-*']);
    expect(requiredLabels('H-15')).toEqual(['logout']);
    expect(requiredLabels('A-10')).toEqual(['error-*（APIのエラー応答を2つ以上）']);
    expect(requiredLabels('C-07')).toContain('session-sample-*（2つ以上）');
    expect(requiredLabels('A-01')).toEqual(['（一般）', 'http', 'unauth-*']);   // 一般と http は③（HTTPでのBasic認証）だけ
  });
  it('csp-sample-* は H-04 だけに案内し、どの項目でも重複しない', () => {
    for (const it of ITEMS) {
      const r = requiredLabels(it.id);
      expect(new Set(r).size).toBe(r.length);
      if (it.id !== 'H-04') expect(r.some(x => x.startsWith('csp-sample-'))).toBe(false);
    }
  });
  it('案内したラベルで実際に判定される（代表例）', () => {
    const t = (label: string, url: string, head: string) => evaluate(`#TARGET url=${url} label=${label}\n${head}\n\n`).ids(label);
    expect(t('ctype', 'https://a.example/api', 'HTTP/2 415')).toContain('A-08.ok');
    expect(t('top', 'https://a.example/api', 'HTTP/2 415').some(i => i.startsWith('A-08'))).toBe(false);
    expect(t('logout', 'https://a.example/logout', 'HTTP/2 302\nlocation: /')).toContain('H-15.1');
    expect(t('http', 'http://a.example/admin', 'HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm="x"')).toContain('A-01.3');   // B：HTTPでのBasic認証
  });
});

describe('予約ラベルの組の案内', () => {
  it('横断ルールの2つのラベルの組（C-09・C-12）から、両方向の組を作る', () => {
    expect([...RESERVED_HINTS].sort()).toEqual([['after-logout', 'logout', 'C-12'], ['login', 'pre-login', 'C-09'], ['logout', 'after-logout', 'C-12'], ['pre-login', 'login', 'C-09']]);
  });
});
