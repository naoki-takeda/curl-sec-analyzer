// export/csv.ts：第8章の記録様式（BOM付きUTF-8）
import type { Finding, Target } from '../model';
import { SEVERITY_LABEL, circled } from '../engine/summarize';
import { hostOf } from '../parser/target';

const COLS = ['項目ID', '対象（ラベル・URL）', '実施日時', '実施コマンド', '判定', '該当条件', '重要度', '証跡（マスク済み）', '対応方針', '例外理由・期限', '再診断日'];
const esc = (v: string) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
// 表計算ソフトが数式として解釈しないようにする（CSVインジェクション対策）
const noFormula = (v: string) => (/^[=+\-@\t\r]/.test(v) ? `'${v}` : v);

// ホスト単位の判定で、元になるターゲットのラベル（ホストの全ターゲットではなく、そのための採取に絞る）
const HOST_SOURCES: Record<string, string[]> = { 'T-09': ['tls', 'top'], 'T-10': ['tls'], 'T-11': ['tls'], 'E-03': ['probes'] };

/**
 * 指摘の元になったターゲットの #META（実施日時・実施コマンド）。
 * ターゲット単位の指摘はそのターゲット、ホスト単位はそのホストの tls・probes など、横断（pre-login/login、session-sample-* など）は比べたラベルのターゲット。
 * 複数あれば、コマンドは重複を除いて「・」でつなぎ、日時は最も新しいものにする
 */
export function sourceMeta(f: Finding, targets: Target[]): { at: string; cmd: string } {
  let src = targets.filter(t => t.label === f.target);
  if (!src.length) {
    const onHost = targets.filter(t => hostOf(t) === f.target);
    if (onHost.length) {
      const want = HOST_SOURCES[f.item];
      const picked = want ? onHost.filter(t => want.includes(t.label)) : [];
      src = picked.length ? picked : onHost;
    } else {
      const parts = f.target.split('/').map(p => p.trim()).filter(Boolean);
      src = targets.filter(t => parts.some(p => (p.endsWith('*') ? t.label.startsWith(p.slice(0, -1)) : t.label === p)));
    }
  }
  const cmds = [...new Set(src.flatMap(t => (t.meta.cmd ?? '').split('・')).filter(Boolean))];
  const at = src.map(t => t.meta.at ?? '').filter(Boolean).sort().at(-1) ?? '';
  return { at, cmd: cmds.join('・') };
}

export function toCsv(fs: Finding[], targets: Target[]): string {
  const rows = fs.filter(f => f.status === 'fail' || f.status === 'suppressed').map(f => [
    f.item, f.url ? `${f.target}（${f.url}）` : f.target, sourceMeta(f, targets).at, sourceMeta(f, targets).cmd,
    f.status === 'suppressed' ? 'suppressed' : 'fail', circled(f.condition), SEVERITY_LABEL[f.severity], f.evidence, f.recommendation,
    f.suppressedBy ? `${f.suppressedBy.reason}（${f.suppressedBy.until || '期限なし'}）` : '', '',
  ]);
  return '\ufeff' + [COLS, ...rows].map(r => r.map(v => esc(noFormula(String(v)))).join(',')).join('\r\n') + '\r\n';
}
