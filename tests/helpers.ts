import { readFileSync } from 'node:fs';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import type { CommandOptions } from '../src/commands';

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

/** 採取時刻（#META at=。期限の判定が判定した日で変わらないよう固定する）と、生成スクリプトの実行ごとの印 */
export const AT = '#META at=2026-11-01T10:00:00';
export const RUN = '0123456789abcdef';

/** コマンド生成器の標準の入力 */
export const GEN_OPTS: CommandOptions = { host: 'www.example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', dangerous: false };

/** 項目 item の指摘のルールID（target を渡せば、そのターゲットのものだけ） */
export const itemIds = (input: string, item: string, target?: string) =>
  evaluate(input).findings.filter(f => f.item === item && (target === undefined || f.target === target)).map(f => f.ruleId);

/** fast-check の実行回数の倍率（環境変数 FC_RUNS で増やす） */
export const FC_MULT = Number(process.env.FC_RUNS) || 1;

/** 秘密 t の8文字の窓が out に1つでもあれば、その窓を返す */
export const leaks = (out: string, t: string) => { for (let i = 0; i + 8 <= t.length; i++) if (out.includes(t.slice(i, i + 8))) return t.slice(i, i + 8); return undefined; };

/** f の実行にかかった時間（ミリ秒） */
export const ms = (f: () => unknown) => { const t = performance.now(); f(); return performance.now() - t; };
