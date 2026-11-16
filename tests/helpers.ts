import { readFileSync } from 'node:fs';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';

export const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
export const sampleText = () => readFileSync(new URL('../src/sample.txt', import.meta.url), 'utf8');

/** 入力を解析・評価し、「ターゲット:ルールID」の一覧を返す（テストで比較しやすくするため） */
export function evaluate(input: string) {
  const { targets, warnings } = parseInput(input);
  const findings = runAll(targets);
  return { targets, warnings, findings, ids: (label: string) => findings.filter(f => f.target === label).map(f => f.ruleId).sort() };
}

/** 1つの応答だけのターゲットを組み立てる */
export const target = (url: string, head: string, extra = '') => `#TARGET url=${url} label=t ${extra}\n${head.trim()}\n`;
