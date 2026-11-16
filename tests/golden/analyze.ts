// 回帰テスト（ゴールデン・同値性）が使う、画面と同じ判定の流れ（src/main.ts の analyzeUnsafe と同じ順番）と、結果を比べやすい文字列にする関数
import type { Coverage, Finding, ParseWarning, Target } from '../../src/model';
import { coverage, ITEMS } from '../../src/engine/coverage';
import { runAll } from '../../src/engine/run';
import { maskText } from '../../src/mask';
import { defaultHarHosts, harTargets, importHar } from '../../src/parser/har';
import { parseInput } from '../../src/parser/input';
import { uniqueLabels } from '../../src/parser/target';
import { IMPLEMENTED } from '../../src/rules/ruleset';

export interface Analysis { targets: Target[]; warnings: ParseWarning[]; findings: Finding[]; cov: Coverage[]; }

/**
 * curl の貼り付けと HAR を、画面と同じ順番で判定する。HAR の対象ホストは画面の初期値と同じ（チェーンのいちばん多いホスト。defaultHarHosts）。
 * harLabels：HAR のチェーンに付けるラベル（チェーンの最初の URL → ラベル）。画面でラベルを選び直すのと同じ
 */
export function analyze(curl: string, har?: string, harLabels: Record<string, string> = {}): Analysis {
  const parsed = curl.trim() ? parseInput(curl) : { targets: [], warnings: [] };
  let fromHar: { targets: Target[]; warnings: ParseWarning[] } = { targets: [], warnings: [] };
  if (har) {
    const imp = importHar(har);
    for (const c of imp.chains) if (harLabels[c.url]) c.label = harLabels[c.url];
    fromHar = harTargets(imp, defaultHarHosts(imp));
  }
  const targets = [...parsed.targets, ...fromHar.targets];
  const merged = uniqueLabels(targets);
  const findings = runAll(targets);
  return { targets, warnings: [...parsed.warnings, ...fromHar.warnings, ...merged], findings, cov: coverage(findings, IMPLEMENTED, ITEMS) };
}

const one = (s: string | undefined) => (s ?? '').replace(/\r?\n/g, '⏎');
/** 1件の指摘を1行にする（証跡まで含める。証跡の変化も、マスクの漏れや表示の退行として見えるように） */
export const findingLine = (f: Finding) =>
  [f.target, f.ruleId, f.severity, f.status, one(f.evidence), f.dedupedBy ? `dedupedBy=${f.dedupedBy}` : ''].filter((x, i) => i < 5 || x).join(' | ');

/**
 * 判定の結果を、比べやすい文字列にする。指摘はターゲット・ルールID・証跡の順に並べる（ルールの登録順を変えても差が出ないように）。
 * ターゲットの突き合わせのキー（targetKey）、解析警告、診断カバレッジも含める（キーの変化・カバレッジの水増しも退行として見えるように）
 */
export function render(a: Analysis): string {
  const keys = new Map(a.findings.filter(f => f.targetKey).map(f => [f.target, f.targetKey!]));
  // URL は画面と同じくマスクしたもの（生の URL はトークンを含みうる）
  const lines = ['## targets', ...a.targets.map(t => `${t.label} | ${t.url ? maskText(t.url) : '(URLなし)'} | key=${keys.get(t.label) ?? '-'} | responses=${t.responses.length}`),
    '', '## warnings', ...a.warnings.map(w => `${w.kind} | ${one(w.detail)}`),
    '', '## findings', ...a.findings.map(findingLine).sort(),
    '', '## coverage', ...a.cov.map(c => `${c.item} | ${c.status} | fails=${c.fails}${c.reasons.length ? ` | ${one(c.reasons.join(' / '))}` : ''}`)];
  return `${lines.join('\n')}\n`;
}
