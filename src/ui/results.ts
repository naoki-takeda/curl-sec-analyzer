// ui/results.ts：判定結果の描画（重要度別の件数、指摘の一覧、ターゲットごとの結果、差分、診断カバレッジ）
import type { Coverage, Finding, Severity, Target } from '../model';
import { finalResponse, isSensitive, responseKind } from '../parser/target';
import { coverageRate } from '../engine/coverage';
import { localDate } from '../engine/suppress';
import { labelRow, RESERVED_HINTS } from '../engine/labels';
import { type DiffRow, diffSummary, profileDiffers } from '../engine/diff';
import { SEVERITIES, circled, countBySeverity, mergeNa, overall } from '../engine/summarize';
import { RULESET_VERSION } from '../version';
import { toMarkdown } from '../export/markdown';
import { suppressionsJson, toJson } from '../export/json';
import { toCsv } from '../export/csv';
import { ITEM_COMMANDS, ITEM_COMMANDS_EN } from '../commands';
import { hstsDirective } from '../rules/util';
import { covLabel, diffLabel, getLang, listSep, sevLabel, statusLabel, tr } from '../i18n';
import { showText } from '../shownText';
import { recommendationEn } from '../recommendationsEn';
import { BTN, type Child, LINK, PRIMARY, SEV_BORDER, SEV_TEXT, button, chapterOf, disclosure, download, el, focusable, focusedKey, options, restoreFocus, sevCell, table, td, titleCell } from './dom';
import { actions, refs, state } from './state';
import { openSuppressDialog } from './dialog';

const commandsFor = (item: string) => (getLang() === 'en' ? ITEM_COMMANDS_EN[item] : ITEM_COMMANDS[item]);
const rec = (s: string) => (getLang() === 'en' ? recommendationEn(s) : s);

// ---- 結果の描画 ----
export function renderEmpty() {
  const T = tr();
  refs.results.replaceChildren(el('div', 'rounded-md border border-dashed border-line p-6 text-muted',
    el('p', 'font-bold text-ink', T.emptyTitle),
    el('ol', 'mt-3 list-decimal space-y-1 pl-5 text-ink', ...T.emptySteps.map(x => el('li', '', x))),
    el('div', 'mt-4 flex flex-wrap gap-2', button(T.openGenerator, PRIMARY, actions.openGenerator), button(T.trySample, BTN, actions.loadSample)),
    el('p', 'mt-4 text-sm', T.emptyHave),
    el('p', 'mt-2 text-sm', T.emptyHint)));
}
export function render() {
  if (!state.last) return;
  const T = tr();
  const { targets, warnings, findings, cov } = state.last;
  const rows = overall(findings);
  const byTarget = groupByTarget(findings);   // ターゲットごとに全指摘を絞り込み直すと、ターゲット数×指摘数になる（数千件で数秒）
  const hints = missingLabelHints(targets);
  // 絞り込み・表示の切り替えの部品は描き直すので、操作した部品にフォーカスを戻す
  const focusKey = focusedKey();
  // 章で絞り込んだ行（見出しの件数と「情報」の件数を、表の行数と合わせる）
  const chapterRows = rows.filter(r => !state.view.chapter || chapterOf(r.item) === state.view.chapter);
  const parts: Child[] = [
    ledger(countBySeverity(rows)),
    // 例外を当てた指摘の件数（重要度別の件数には含めないので、ワイルドカードの例外で高が消えたことに画面から気づけるように）
    findings.some(f => f.status === 'suppressed') ? el('p', 'mt-2 text-sm text-muted', T.suppressedCount(new Set(findings.filter(f => f.status === 'suppressed').map(f => f.ruleId)).size)) : null,
    exportBar(),
    warnings.length || hints.length ? warningList([...warnings.map(w => w.detail), ...hints]) : null,
    state.last.diff ? diffBlock(state.last.diff) : null,
    // 件数は、章で絞り込んだ表の行数と合わせる
    heading(T.findings, findingsCount(chapterRows), el('span', 'flex flex-wrap items-center gap-3', infoToggle(chapterRows.filter(r => r.severity === 'info').length), chapterFilter())),
    rows.length ? overallTable(chapterRows) : el('p', 'text-muted', T.noFindings),
    heading(T.perTarget, T.count(targets.length), focusable(button(state.view.showAll ? T.showFails : T.showAll, LINK, () => { state.view.showAll = !state.view.showAll; render(); }), 'show-all')),
    targetSummary(targets, byTarget),
    ...targets.map(t => targetBlock(t, byTarget.get(t.label) ?? [])),
    crossBlock(findings, targets),
    coverageBlock(cov),
  ];
  refs.results.replaceChildren(...parts.filter((p): p is Node => p instanceof Node));
  restoreFocus(refs.results, focusKey);
}
/** 指摘の件数。「情報」を隠しているときは、表の行数と合うように内訳を添える */
function findingsCount(rows: ReturnType<typeof overall>) {
  const info = rows.filter(r => r.severity === 'info').length;
  return !state.view.showInfo && info ? tr().countHidden(rows.length, info) : tr().count(rows.length);
}

function infoToggle(n: number) {
  if (!n) return null;
  return focusable(button(state.view.showInfo ? tr().hideInfo : tr().showInfo(n), LINK, () => { state.view.showInfo = !state.view.showInfo; render(); }), 'show-info');
}
function heading(text: string, aside?: string, right?: Node) {
  return el('div', 'mt-8 mb-2 flex flex-wrap items-baseline gap-x-3 gap-y-1',
    el('h2', 'text-lg font-bold', text), aside ? el('span', 'num text-muted', aside) : null, right ? el('span', 'ml-auto', right) : null);
}
function ledger(c: Record<Severity, number>) {
  const T = tr();
  const wrap = el('div', 'grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4',
    ...SEVERITIES.map(s => el('div', `border-l-[6px] ${SEV_BORDER[s]} bg-surface px-4 py-3`,
      el('div', `num text-4xl font-bold leading-none ${c[s] ? SEV_TEXT[s] : 'text-muted'}`, String(c[s])),
      el('div', 'mt-1 text-sm text-muted', T.severity(sevLabel(s))))));
  wrap.setAttribute('role', 'group'); wrap.setAttribute('aria-label', SEVERITIES.map(s => `${T.severity(sevLabel(s))} ${c[s]}`).join(', '));
  return wrap;
}
function exportBar() {
  const T = tr(); const stamp = localDate();
  return el('div', 'mt-3 flex flex-wrap items-center gap-2 text-sm',
    el('span', 'text-muted', T.save),
    // 結果のファイルは、その結果を判定したときの設定で書く（判定のあとに読み込んだ設定と混ぜない）。判定中は押せない（main.ts の setBusy）
    exportButton('Markdown', () => { const L = state.last!; const b = L.settings.baseline;
      return download(`sec-report-${stamp}.md`, 'text/markdown', toMarkdown(L.findings, L.cov, L.settings.suppressions, new Date(),
        { profile: L.settings.profile, diff: L.diff && b ? { rows: L.diff, baselineAt: b.generatedAt, ...diffWarnings() } : undefined })); }),
    exportButton('JSON', () => { const L = state.last!; download(`sec-report-${stamp}.json`, 'application/json', toJson(L.findings, L.cov, L.settings.suppressions, new Date(), L.settings.profile)); }),
    exportButton(T.csv, () => download(`sec-report-${stamp}.csv`, 'text/csv', toCsv(state.last!.findings, state.last!.targets))),
    button(T.suppressionsFile, BTN, () => download('suppressions.json', 'application/json', suppressionsJson(state.suppressions))));
}
/** 結果のファイルの保存ボタン。判定中（actions.isAnalyzing）は押せないようにする（data-export で main.ts の setBusy が切り替える） */
function exportButton(label: string, save: () => void) {
  const b = button(label, BTN, () => { if (state.last && !actions.isAnalyzing()) save(); });
  b.dataset.export = '1'; b.disabled = actions.isAnalyzing();
  return b;
}
function missingLabelHints(targets: Target[]): string[] {
  const T = tr(); const has = (l: string) => targets.some(t => t.label === l);
  const out = RESERVED_HINTS.filter(([a, b]) => has(a) && !has(b)).map(([a, b, item]) => T.missingPair(a, b, item));
  if (targets.some(t => hstsDirective(finalResponse(t)?.headers.get('strict-transport-security')?.[0], 'preload')) && !has('apex')) out.push(T.preloadNoApex);
  return out;
}
function warningList(ws: string[]) {
  return el('div', 'mt-4 rounded-md border border-sev-medium/50 bg-surface p-3 text-sm',
    el('p', 'font-bold', tr().warnings), el('ul', 'mt-1 list-disc pl-5', ...ws.map(w => el('li', '', w))));
}
function chapterFilter() {
  const T = tr();
  const sel = options(el('select', 'rounded-md border border-line bg-surface px-2 py-1 text-sm'),
    [['0', T.allChapters], ...T.chapters.map((c, i): [string, string] => [String(i + 1), T.chapter(i + 1, c)])], String(state.view.chapter));
  sel.setAttribute('aria-label', T.filterChapter);
  focusable(sel, 'chapter');
  sel.addEventListener('change', () => { state.view.chapter = Number(sel.value); render(); });
  return sel;
}
/** 章で絞り込んだ行の表。「情報」を隠して行が残らないときは、章に指摘がないとは書かない（見出しに隠した件数を出している） */
function overallTable(chapterRows: ReturnType<typeof overall>) {
  const T = tr();
  const rows = chapterRows.filter(r => state.view.showInfo || r.severity !== 'info');
  if (!rows.length) return el('p', 'text-muted', chapterRows.length ? T.nothingToShow : T.noFindingsInChapter);
  return table(T.tables.findings, [T.cols.severity, T.cols.item, T.cols.title, T.cols.targets], rows.map(r =>
    el('tr', '', sevCell(r.severity), td('whitespace-nowrap num', `${r.item}${circled(r.condition)}`), titleCell(r.item, r.title), td('', r.targets.join(', ')))));
}
/** 指摘をターゲット（ラベル）ごとにまとめる */
function groupByTarget(fs: Finding[]): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>();
  for (const f of fs) { const a = m.get(f.target); if (a) a.push(f); else m.set(f.target, [f]); }
  return m;
}
function targetSummary(targets: Target[], byTarget: Map<string, Finding[]>) {
  const T = tr();
  return table(T.tables.targets, [T.cols.label, T.cols.url, T.cols.kind, T.cols.sensitive, ...SEVERITIES.map(sevLabel)], targets.map(t => {
    const f = finalResponse(t); const s = isSensitive(t);
    const fails = (byTarget.get(t.label) ?? []).filter(x => x.status === 'fail');
    return el('tr', '',
      td('whitespace-nowrap font-bold', t.label), td('break-all text-muted', t.url ? showText(t.url) : T.urlUnknown),
      td('whitespace-nowrap', getLang() === 'en' ? `${T.kinds[responseKind(t, f)]} (${labelRow(t.label).nameEn})` : `${T.kinds[responseKind(t, f)]}（${labelRow(t.label).name}）`),
      td('whitespace-nowrap', s === undefined ? T.unknown : s ? T.yes : T.no),
      ...SEVERITIES.map(sv => { const n = fails.filter(x => x.severity === sv).length; return td(`num ${n ? SEV_TEXT[sv] + ' font-bold' : 'text-muted'}`, String(n)); }));
  }));
}
const STATUS_ORDER = ['fail', 'suppressed', 'na', 'pass'];
/** 指摘を先に、重要度の高い順、項目IDの順に並べる */
const byImportance = (a: Finding, b: Finding) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status)
  || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.ruleId.localeCompare(b.ruleId);
/** withTarget：対象（ホスト・ラベルの組）の列を出す（ホスト単位・横断の表で、どのホストの指摘かが分かるように） */
function findingsTable(fs: Finding[], label: string, withTarget = false) {
  const T = tr();
  const shown = mergeNa(fs.filter(f => state.view.showAll || (f.status === 'fail' && (state.view.showInfo || f.severity !== 'info'))).sort(byImportance));
  if (!shown.length) return el('p', 'mt-1 text-sm text-muted', T.nothingToShow);
  return table(label, [T.cols.severity, T.cols.item, ...(withTarget ? [T.cols.target] : []), T.cols.status, T.cols.evidence, T.cols.recommendation, ''], shown.map(x =>
    el('tr', '', x.status === 'fail' ? sevCell(x.severity, x.originalSeverity) : td('text-muted', '—'),
      td('whitespace-nowrap num', x.items ? x.items.join(getLang() === 'en' ? ', ' : '・') : `${x.item}${circled(x.condition)}`),
      withTarget ? td('break-all', showText(x.target)) : null,
      td(`whitespace-nowrap ${x.status === 'pass' ? 'text-ok' : x.status === 'fail' ? '' : 'text-muted'}`, statusLabel(x.status)),
      td('font-mono text-[12px] break-all', x.evidence || '—'),
      td('', x.status === 'suppressed' ? T.suppressedNote(x.suppressedBy!.reason, x.suppressedBy!.approver, x.suppressedBy!.until) : rec(x.recommendation) || '—'),
      td('whitespace-nowrap', x.status === 'fail' ? button(T.addSuppression, LINK, () => openSuppressDialog(x)) : null))));
}
/** 重要度別の件数の小さな表示（折りたたみの見出し用） */
function counts(fs: Finding[]) {
  const fails = fs.filter(x => x.status === 'fail');
  return el('span', 'ml-auto flex gap-3 text-sm', ...SEVERITIES.map(sv => {
    const n = fails.filter(x => x.severity === sv).length;
    return el('span', `num ${n ? SEV_TEXT[sv] + ' font-bold' : 'text-muted'}`, `${sevLabel(sv)} ${n}`);
  }));
}
function targetBlock(t: Target, fs: Finding[]) {
  const T = tr(); const f = finalResponse(t);
  const d = el('details', 'mt-3 rounded-md border border-line bg-surface',
    el('summary', 'summary-custom flex cursor-pointer flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2',
      disclosure(), el('span', 'font-bold', t.label),
      el('span', 'text-sm text-muted break-all', `${t.url ? showText(t.url) : T.urlUnknown} / ${f ? `HTTP ${f.status}` : T.noResp}`), counts(fs)),
    el('div', 'border-t border-line p-2', findingsTable(fs, T.tables.target(t.label))));
  d.open = state.view.showAll || fs.some(x => x.status === 'fail' && x.severity !== 'info');   // 情報以外の指摘があるものだけ開く
  return d;
}
function crossBlock(findings: Finding[], targets: Target[]) {
  const labels = new Set(targets.map(t => t.label));
  const fs = findings.filter(f => !labels.has(f.target));
  if (!fs.length) return null;
  const d = el('details', 'mt-3 rounded-md border border-line bg-surface',
    el('summary', 'summary-custom flex cursor-pointer flex-wrap items-baseline gap-x-3 px-3 py-2', disclosure(), el('span', 'font-bold', tr().crossTitle), counts(fs)),
    el('div', 'border-t border-line p-2', findingsTable(fs, tr().crossTitle, true)));
  d.open = state.view.showAll || fs.some(x => x.status === 'fail' && x.severity !== 'info');
  return d;
}
/** 前回との差分の警告（ルールセットの版・組織プロファイルの違い）。画面と Markdown で同じものを出す */
function diffWarnings(): { rulesetWarning?: string; profileWarning?: string } {
  const s = state.last?.settings; const b = s?.baseline; const T = tr();
  return { rulesetWarning: b?.rulesetVersion && b.rulesetVersion !== RULESET_VERSION ? T.diffRulesetWarning(b.rulesetVersion, RULESET_VERSION) : undefined,
           profileWarning: profileDiffers(b?.profile, s?.profile) ? T.diffProfileWarning : undefined };
}
function diffBlock(rows: DiffRow[]) {
  const T = tr(); const s = diffSummary(rows); const w = diffWarnings();
  const shown = rows.filter(r => r.kind !== 'continuing');
  return el('section', '',
    heading(T.diff, state.last?.settings.baseline?.generatedAt),
    el('p', 'mb-2 text-sm', T.diffSummary(s.new, s.resolved, s['severity-changed'], s.suppressed, s['not-rechecked'], s.continuing)),
    ...[w.profileWarning, w.rulesetWarning].map(x => (x ? el('p', 'mb-2 text-sm text-sev-medium', x) : null)),
    shown.length ? table(T.tables.diff, [T.cols.change, T.cols.severity, T.cols.item, T.cols.title, T.cols.target], shown.map(r =>
      el('tr', '', td(`whitespace-nowrap font-bold ${r.kind === 'new' ? 'text-sev-high' : r.kind === 'resolved' ? 'text-ok' : 'text-muted'}`, diffLabel(r.kind)),
        td(`whitespace-nowrap ${SEV_TEXT[r.severity]}`, sevLabel(r.severity), r.before ? (getLang() === 'en' ? ` (was ${sevLabel(r.before)})` : `（← ${sevLabel(r.before)}）`) : ''),
        td('whitespace-nowrap num', `${r.item}${circled(r.condition)}`), titleCell(r.item, r.title), td('', r.target)))) : null,
    el('p', 'mt-2 text-sm text-muted', T.diffNote));
}
function coverageBlock(cov: Coverage[]) {
  const T = tr(); const r = coverageRate(cov);
  const sel = options(el('select', 'rounded-md border border-line bg-surface px-2 py-1 text-sm'),
    [['all', T.allCategories], ...(['evaluated', 'missing-input', 'manual', 'not-implemented', 'excluded'] as const).map((k): [string, string] => [k, covLabel(k)])], state.view.covFilter);
  sel.setAttribute('aria-label', T.filterCategory);
  focusable(sel, 'cov-filter');
  sel.addEventListener('change', () => { state.view.covFilter = sel.value; render(); });
  const rows = cov.filter(c => state.view.covFilter === 'all' || c.status === state.view.covFilter);
  return el('section', '',
    heading(T.coverage, T.coverageRate(r.evaluated, r.denominator, r.notImplemented, cov.filter(c => c.status === 'manual').length), sel),
    el('p', 'mb-2 text-sm text-muted', T.coverageNote),
    table(T.tables.coverage, [T.cols.item, T.cols.title, T.cols.category, T.cols.reason], rows.map(c =>
      el('tr', '', td('whitespace-nowrap num', c.item), titleCell(c.item, c.title),
        td(`whitespace-nowrap ${c.status === 'evaluated' ? (c.fails ? 'text-sev-medium' : 'text-ok') : 'text-muted'}`, covLabel(c.status), c.status === 'evaluated' && c.fails ? ` (${c.fails})` : ''),
        td('text-muted', c.status === 'manual' ? T.manualNote
          : c.status === 'missing-input' && commandsFor(c.item) ? (getLang() === 'en' ? `${c.reasons.map(rec).join(listSep())} (${T.command}: ${commandsFor(c.item)})` : `${c.reasons.map(rec).join(listSep())}（${T.command}：${commandsFor(c.item)}）`)
          : c.reasons.map(rec).join(listSep()))))),
    el('p', 'mt-3 text-sm text-muted', T.outOfScope));
}
