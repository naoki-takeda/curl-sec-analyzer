// ui/generator.ts：コマンド生成器の画面
import { type CommandOptions, generateScript, validate } from '../commands';
import { getLang, tr } from '../i18n';
import { joinMessages } from '../messagesEn';
import { BTN, button, download, el, labelFor } from './dom';

// 入力と生成したスクリプトは、画面を作り直しても（言語を切り替えても）残す
const draft = { values: new Map<string, string>(), danger: false, output: '', open: false };
export function commandGenerator() {
  const T = tr().gen;
  const fields: [keyof CommandOptions, string][] = [['host', 'www.example.com'], ['apex', 'example.com'], ['apiPath', '/api/me'],
    ['loginPath', '/login'], ['mypagePath', '/mypage'], ['logoutPath', '/logout'], ['staticPath', '/assets/app.js'], ['wsPath', '/ws']];
  const inputs = new Map<string, HTMLInputElement>();
  const grid = el('div', 'grid gap-x-3 gap-y-2 sm:grid-cols-2');
  for (const [k, ph] of fields) {
    const i = el('input', 'mt-1 w-full rounded-md border border-line bg-surface px-3 py-2 font-mono text-[13px]'); i.id = `gen-${k}`; i.placeholder = ph;
    if (k !== 'host' && k !== 'apex' && k !== 'wsPath') i.value = ph;   // 任意の項目は空のまま
    if (draft.values.has(k)) i.value = draft.values.get(k)!;
    i.addEventListener('input', () => { draft.values.set(k, i.value); });
    inputs.set(k, i); grid.append(el('div', '', labelFor(i.id, T.fields[k]), i));
  }
  const danger = el('input'); danger.type = 'checkbox'; danger.id = 'gen-danger'; danger.checked = draft.danger;
  danger.addEventListener('change', () => { draft.danger = danger.checked; });
  const out = el('textarea', 'mt-3 hidden h-64 w-full rounded-md border border-line bg-surface p-3 font-mono text-[12px]'); out.readOnly = true; out.wrap = 'off';
  out.setAttribute('aria-label', T.output);
  const err = el('p', 'mt-2 min-h-5 text-sm text-sev-high');
  err.setAttribute('role', 'status');   // 入力の誤りと「コピーしました」を読み上げる（WCAG 4.1.3）
  const actions = el('div', 'mt-2 hidden flex-wrap gap-2',
    button(T.copy, BTN, async () => { try { await navigator.clipboard.writeText(out.value); err.textContent = T.copied; } catch { out.select(); err.textContent = T.copyFailed; } }),
    button(T.saveSh, BTN, () => download('csa-collect.sh', 'text/x-shellscript', out.value)));
  const gen = button(T.make, 'rounded-md bg-primary px-4 py-2 font-bold text-primary-ink hover:opacity-90', () => {
    const v = (k: string) => inputs.get(k)!.value.trim();
    const o: CommandOptions = { host: v('host'), apex: v('apex') || undefined, apiPath: v('apiPath'), loginPath: v('loginPath'),
      mypagePath: v('mypagePath'), logoutPath: v('logoutPath'), staticPath: v('staticPath'), wsPath: v('wsPath') || undefined, dangerous: danger.checked };
    const errors = validate(o);
    err.textContent = getLang() === 'en' ? joinMessages(errors, 'en') : errors.join('。');
    if (errors.length) { out.classList.add('hidden'); actions.classList.add('hidden'); draft.output = ''; return; }
    out.value = draft.output = generateScript(o); out.classList.remove('hidden'); actions.classList.remove('hidden'); actions.classList.add('flex');
  });
  const d = el('details', 'mt-4 rounded-md border border-line bg-surface p-4',
    el('summary', 'cursor-pointer font-bold', T.title),
    el('p', 'mt-2 text-sm text-muted', T.note),
    el('div', 'mt-3', grid), el('div', 'mt-3 flex items-center gap-2', danger, labelFor('gen-danger', T.danger, 'text-sm')),
    el('div', 'mt-3', gen), err, out, actions);
  d.id = 'generator';
  if (draft.output) { out.value = draft.output; out.classList.remove('hidden'); actions.classList.remove('hidden'); actions.classList.add('flex'); }
  d.open = draft.open; d.addEventListener('toggle', () => { draft.open = d.open; });
  return d;
}
