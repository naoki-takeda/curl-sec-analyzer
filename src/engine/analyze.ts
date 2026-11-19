// engine/analyze.ts：入力（貼り付け・HAR・URL 欄）から判定までを行う。画面は Web Worker（analyzeWorker.ts）の中でこれを呼ぶ
// （数万件のターゲットの HAR でも画面を止めない）。DOM に依存しないので、単体テストでも同じものを使う
import type { Coverage, Finding, ParseWarning, Profile, Suppression, Target } from '../model';
import { parseInput } from '../parser/input';
import { type HarImport, harTargets } from '../parser/har';
import { HAS_SCHEME, assignHopUrls, uniqueLabels } from '../parser/target';
import { runAll } from './run';
import { coverage, ITEMS } from './coverage';
import { IMPLEMENTED } from '../rules/ruleset';

export interface AnalyzeRequest {
  text: string;                     // 貼り付けた curl・openssl の出力
  url: string;                      // URL 欄の値（#TARGET のない入力の default ターゲットの URL）
  har?: { imp: HarImport; hosts: Set<string> };
  suppressions: Suppression[];
  profile?: Profile;
}
/** cov：診断カバレッジ（組織プロファイルの対象外を含む。実装済みの項目はルールセットから作るので、ルールを持つ Worker の側で計算する） */
export interface AnalyzeResult { targets: Target[]; warnings: ParseWarning[]; findings: Finding[]; cov: Coverage[]; }

/** 入力を解析して判定する。ターゲットが1つもなければ findings は空 */
export function analyzeInput(req: AnalyzeRequest): AnalyzeResult {
  const parsed = req.text.trim() ? parseInput(req.text) : { targets: [], warnings: [] };
  const fromHar = req.har ? harTargets(req.har.imp, req.har.hosts) : { targets: [], warnings: [] };
  const targets = [...parsed.targets, ...fromHar.targets];
  const merged = uniqueLabels(targets);                       // 貼り付けと HAR で同じラベル（login など）を付けた場合
  const u = req.url.trim();
  // URL 欄で補ったターゲットにも、各ホップの URL を付け直す（-L で http から https に転送されたかを判定するため。parseInput の中では URL が分からない）
  let filled = false;
  if (u) for (const t of targets) if (!t.url && t.label === 'default') { t.url = u; assignHopUrls(t); filled = true; }
  if (!targets.length) return { targets, warnings: [], findings: [], cov: [] };
  // URL 欄の値がスキームのある URL でなければ（www.example.com）、#TARGET の url= と同じく警告する（HTTPS かどうかを使う項目
  // （H-01①・C-01① など）が、警告なしに判定されなくなるのを防ぐ）
  // パーサの「url= を付けてください」は、URL 欄で補ったターゲットには出さない（URL 欄の誤りは、URL 欄の警告として1つだけ出す）。
  // url= を書いた default のターゲット（#TARGET url=www.example.com）は補わないので、その url= の警告は残す。
  // 文言はほかの解析の警告と同じく日本語に固定する（判定した時点の言語で作ると、言語を切り替えたあとも古い言語のまま残る）
  const warnings = [...parsed.warnings, ...fromHar.warnings, ...merged].filter(w => !(filled && w.kind === 'unknown-url' && w.label === 'default'));   // URL欄で補ったのは default だけ
  if (filled && !HAS_SCHEME.test(u)) warnings.push({ kind: 'unknown-url', label: 'default', detail: 'URL 欄の値を URL として読めません。HTTPSかどうかを使う項目は判定できません（https:// から書いてください）' });
  const findings = runAll(targets, { suppressions: req.suppressions, profile: req.profile });
  return { targets, warnings, findings, cov: coverage(findings, IMPLEMENTED, ITEMS, req.profile?.exclude) };
}
