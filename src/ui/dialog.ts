// ui/dialog.ts：例外の登録ダイアログ
import type { Finding } from '../model';
import { circled } from '../engine/summarize';
import { localDate } from '../engine/suppress';
import { itemTitle, tr } from '../i18n';
import { BTN, button, el, labelFor, options } from './dom';
import { actions, refs, state } from './state';

// ---- 例外の登録 ----
export function openSuppressDialog(f: Finding) {
  const T = tr().dlg;
  const field = (id: string, label: string, i: HTMLInputElement) => { i.id = id; i.className = 'mt-1 w-full rounded-md border border-line bg-paper px-3 py-2'; return el('div', 'mt-3', labelFor(id, label), i); };
  const reason = el('input'); const approver = el('input'); const until = el('input'); until.type = 'date';
  until.value = localDate(new Date(Date.now() + 90 * 86400e3));
  const scope = options(el('select', 'mt-1 w-full rounded-md border border-line bg-paper px-3 py-2'),
    [[f.ruleId, T.onlyCond(`${f.item}${circled(f.condition)}`)], [f.item, T.wholeItem(f.item)]], f.ruleId);
  scope.id = 'sup-scope';
  const err = el('p', 'mt-2 min-h-5 text-sm text-sev-high');
  const save = button(T.save, 'rounded-md bg-primary px-4 py-2 font-bold text-primary-ink', () => {
    if (!reason.value.trim()) { err.textContent = T.needReason; return; }
    state.suppressions = [...state.suppressions, { ruleId: scope.value, target: f.targetKey ?? f.target, reason: reason.value.trim(), approver: approver.value.trim(), until: until.value }];
    refs.dialog.close(); actions.renderSettings(); actions.analyze();
  });
  refs.dialog.replaceChildren(el('div', 'p-5',
    Object.assign(el('h2', 'text-lg font-bold', T.title), { id: 'sup-title' }),
    el('p', 'mt-1 text-sm text-muted', T.note(`${f.item}${circled(f.condition)} ${itemTitle(f.item, f.title)}`, f.target)),
    el('div', 'mt-3', labelFor('sup-scope', T.scope), scope),
    field('sup-reason', T.reason, reason), field('sup-approver', T.approver, approver), field('sup-until', T.until, until), err,
    el('div', 'mt-4 flex justify-end gap-2', button(T.cancel, BTN, () => refs.dialog.close()), save)));
  // 見出しをダイアログの名前にする（読み上げで、何のダイアログかが分かるように。第48回）
  refs.dialog.setAttribute('aria-labelledby', 'sup-title');
  refs.dialog.showModal(); reason.focus();
}
