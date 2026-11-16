// export/csv.ts：第8章の記録様式（BOM付きUTF-8）
import type { Finding, Target } from '../model';
import { SEVERITY_LABEL, circled } from '../engine/summarize';
import { summarizeAt, summarizeCommand } from './cmdSummary';
import { hostOf } from '../parser/target';

// BOM はエスケープで書かない（見えない文字のまま書くと、エディタや整形で消えても気づかない）
const BOM = String.fromCharCode(0xfeff);
const COLS = ['項目ID', '対象（ラベル・URL）', '実施日時', '実施コマンド', '判定', '該当条件', '重要度', '証跡（マスク済み）', '対応方針', '例外理由・期限', '再診断日'];
const esc = (v: string) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
// 表計算ソフトが数式として解釈しないようにする（CSVインジェクション対策）
// コマンドの ID の「-」（コマンド生成器が書く cmd=-）だけのものは、数式にならないのでそのまま出す
const noFormula = (v: string) => (v !== '-' && /^[=+\-@\t\r]/.test(v) ? `'${v}` : v);

// ホスト単位の判定で、元になるターゲットのラベル（ホストの全ターゲットではなく、そのための採取に絞る）
const HOST_SOURCES: Record<string, string[]> = { 'T-09': ['tls', 'top'], 'T-10': ['tls'], 'T-11': ['tls'], 'E-03': ['probes'] };

/** ラベルとホストからターゲットを引く索引（指摘ごとに全ターゲットを探すと、指摘の数 × ターゲットの数の時間がかかる） */
interface MetaIndex { byLabel: Map<string, Target[]>; byHost: Map<string, Target[]>; targets: Target[]; memo: Map<string, { at: string; cmd: string }> }
function indexTargets(targets: Target[]): MetaIndex {
  const byLabel = new Map<string, Target[]>(), byHost = new Map<string, Target[]>();
  const add = (m: Map<string, Target[]>, k: string | undefined, t: Target) => {
    if (k === undefined) return;
    const list = m.get(k);
    if (list) list.push(t); else m.set(k, [t]);
  };
  for (const t of targets) { add(byLabel, t.label, t); add(byHost, hostOf(t), t); }
  return { byLabel, byHost, targets, memo: new Map() };
}

/**
 * 指摘の元になったターゲットの #META（実施日時・実施コマンド）。
 * ターゲット単位の指摘はそのターゲット、ホスト単位はそのホストの tls・probes など、横断（pre-login/login、session-sample-* など）は比べたラベルのターゲット。
 * 複数あれば、コマンドは重複を除いて「・」でつなぎ、日時は最も新しいものにする。
 * #META の値は利用者が書いたもの（コマンドに Authorization や ?access_token= を含むことがある）なので、残してよい形だけを残す要約にする（export/cmdSummary.ts）
 */
function sourceMeta(f: Finding, ix: MetaIndex): { at: string; cmd: string } {
  const key = `${f.item}\u0000${f.target}`;
  const hit = ix.memo.get(key);
  if (hit) return hit;
  let src = ix.byLabel.get(f.target) ?? [];
  if (!src.length) {
    const onHost = ix.byHost.get(f.target) ?? [];
    if (onHost.length) {
      const want = HOST_SOURCES[f.item];
      const picked = want ? onHost.filter(t => want.includes(t.label)) : [];
      src = picked.length ? picked : onHost;
    } else {
      const parts = f.target.split('/').map(p => p.trim()).filter(Boolean);
      src = ix.targets.filter(t => parts.some(p => (p.endsWith('*') ? t.label.startsWith(p.slice(0, -1)) : t.label === p)));
    }
  }
  const cmds = [...new Set(src.flatMap(t => (t.meta.cmd ?? '').split('・')).filter(Boolean))];
  // 最も新しい日時は、時刻として比べる（文字列で並べると、T 区切りと空白区切りが混ざったとき、時刻に関係なく T 区切りを選んだ）
  const at = src.map(t => t.meta.at ?? '').filter(Boolean).sort((a, b) => (Date.parse(a.replace(' ', 'T')) || 0) - (Date.parse(b.replace(' ', 'T')) || 0) || (a < b ? -1 : a > b ? 1 : 0)).at(-1) ?? '';
  // 実施日時と実施コマンドは、残してよい形だけを残す（export/cmdSummary.ts。手で書いた #META の値の秘密を出さない）
  const out = { at: summarizeAt(at), cmd: summarizeCommand(cmds.join('・')) };
  ix.memo.set(key, out);
  return out;
}

export function toCsv(fs: Finding[], targets: Target[]): string {
  const ix = indexTargets(targets);
  const rows = fs.filter(f => f.status === 'fail' || f.status === 'suppressed').map(f => {
    const m = sourceMeta(f, ix);
    return [
      f.item, f.url ? `${f.target}（${f.url}）` : f.target, m.at, m.cmd,
      f.status === 'suppressed' ? 'suppressed' : 'fail', circled(f.condition), SEVERITY_LABEL[f.severity], f.evidence, f.recommendation,
      f.suppressedBy ? `${f.suppressedBy.reason}（${f.suppressedBy.until || '期限なし'}）` : '', '',
    ];
  });
  return BOM + [COLS, ...rows].map(r => r.map(v => esc(noFormula(String(v)))).join(',')).join('\r\n') + '\r\n';
}
