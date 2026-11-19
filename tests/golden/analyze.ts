// テスト（ゴールデン・同値性ほか）が使う、画面と同じ判定の流れ（Worker が呼ぶ engine/analyze.ts の analyzeInput）と、結果を比べやすい文字列にする関数
import type { Finding } from '../../src/model';
import { type AnalyzeResult, analyzeInput } from '../../src/engine/analyze';
import { maskText } from '../../src/mask';
import { defaultHarHosts, importHar } from '../../src/parser/har';

/**
 * curl の貼り付けと HAR を、画面と同じ流れで判定する。HAR の対象ホストは画面の初期値と同じ（チェーンのいちばん多いホスト。defaultHarHosts）。
 * harLabels：HAR のチェーンに付けるラベル（チェーンの最初の URL → ラベル）。画面でラベルを選び直すのと同じ
 */
export function analyze(curl: string, har?: string, harLabels: Record<string, string> = {}): AnalyzeResult {
  let imp;
  if (har) {
    imp = importHar(har);
    for (const c of imp.chains) if (harLabels[c.url]) c.label = harLabels[c.url];
  }
  return analyzeInput({ text: curl, url: '', har: imp ? { imp, hosts: defaultHarHosts(imp) } : undefined, suppressions: [] });
}

const one = (s: string | undefined) => (s ?? '').replace(/\r?\n/g, '⏎');
/** 1件の指摘を1行にする（証跡まで含める。証跡の変化も、マスクの漏れや表示の退行として見えるように） */
export const findingLine = (f: Finding) =>
  [f.target, f.ruleId, f.severity, f.status, one(f.evidence), f.dedupedBy ? `dedupedBy=${f.dedupedBy}` : ''].filter((x, i) => i < 5 || x).join(' | ');

/**
 * 判定の結果を、比べやすい文字列にする。指摘はターゲット・ルールID・証跡の順に並べる（ルールの登録順を変えても差が出ないように）。
 * ターゲットの突き合わせのキー（targetKey）、解析警告、診断カバレッジも含める（キーの変化・カバレッジの水増しも退行として見えるように）
 */
export function render(a: AnalyzeResult): string {
  const keys = new Map(a.findings.filter(f => f.targetKey).map(f => [f.target, f.targetKey!]));
  // URL は maskText でマスクしたもの（生の URL はトークンを含みうる。画面はさらに showText を通す）
  const lines = ['## targets', ...a.targets.map(t => `${t.label} | ${t.url ? maskText(t.url) : '(URLなし)'} | key=${keys.get(t.label) ?? '-'} | responses=${t.responses.length}`),
    '', '## warnings', ...a.warnings.map(w => `${w.kind} | ${one(w.detail)}`),
    '', '## findings', ...a.findings.map(findingLine).sort(),
    '', '## coverage', ...a.cov.map(c => `${c.item} | ${c.status} | fails=${c.fails}${c.reasons.length ? ` | ${one(c.reasons.join(' / '))}` : ''}`)];
  return `${lines.join('\n')}\n`;
}
