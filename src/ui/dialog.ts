// ui/dialog.ts：例外の登録ダイアログ
import type { Finding } from '../model';
import { circled } from '../engine/summarize';
import { localDate } from '../engine/suppress';
import { itemTitle, tr } from '../i18n';
import { BTN, button, el, labelFor, options, targetNames, targetText } from './dom';
import { actions, refs, state } from './state';

// ---- 例外の登録 ----
export function openSuppressDialog(f: Finding) {
  const T = tr().dlg;
  const field = (id: string, label: string, i: HTMLInputElement) => { i.id = id; i.className = 'mt-1 w-full rounded-md border border-line bg-paper px-3 py-2'; return el('div', 'mt-3', labelFor(id, label), i); };
  const reason = el('input'); const approver = el('input'); const until = el('input'); until.type = 'date';
  until.value = localDate(new Date(Date.now() + 90 * 86400e3)); until.min = localDate();
  const scope = options(el('select', 'mt-1 w-full rounded-md border border-line bg-paper px-3 py-2'),
    [[f.ruleId, T.onlyCond(`${f.item}${circled(f.condition)}`)], [f.item, T.wholeItem(f.item)]], f.ruleId);
  scope.id = 'sup-scope';
  const err = el('p', 'mt-2 min-h-5 text-sm text-sev-high');
  err.setAttribute('role', 'alert');   // 入力の誤りを読み上げる（WCAG 4.1.3）
  const save = button(T.save, 'rounded-md bg-primary px-4 py-2 font-bold text-primary-ink', () => {
    if (!reason.value.trim()) { err.textContent = T.needReason; reason.focus(); return; }
    // 過去の期限の例外は、登録してもすぐに無効になる（指摘が残ることが、閉じた設定の欄の「期限切れ」でしか分からない）
    if (until.value && until.value < localDate()) { err.textContent = T.pastUntil; until.focus(); return; }
    state.suppressions = [...state.suppressions, { ruleId: scope.value, target: f.targetKey ?? f.target, reason: reason.value.trim(), approver: approver.value.trim(), until: until.value }];
    refs.dialog.close(); actions.renderSettings();
    // 例外に登録したボタンは描き直しで消えるので、判定し直して描いたときに結果の最初の見出しにフォーカスを移す（main.ts の show・ui/dom.ts の focusResultsIfLost）
    actions.analyze('result');
  });
  refs.dialog.replaceChildren(el('div', 'p-5',
    Object.assign(el('h2', 'text-lg font-bold', T.title), { id: 'sup-title' }),
    el('p', 'mt-1 text-sm text-muted', T.note(`${f.item}${circled(f.condition)} ${itemTitle(f.item, f.title)}`, targetText(f.target, targetNames(state.last?.targets ?? [], state.last?.findings ?? [])))),
    el('div', 'mt-3', labelFor('sup-scope', T.scope), scope),
    field('sup-reason', T.reason, reason), field('sup-approver', T.approver, approver), field('sup-until', T.until, until), err,
    el('div', 'mt-4 flex justify-end gap-2', button(T.cancel, BTN, () => refs.dialog.close()), save)));
  // 見出しをダイアログの名前にする（読み上げで、何のダイアログかが分かるように。WCAG 4.1.2）
  refs.dialog.setAttribute('aria-labelledby', 'sup-title');
  refs.dialog.showModal(); reason.focus();
}
