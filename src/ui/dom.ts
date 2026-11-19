// ui/dom.ts：DOM の組み立て。描画はすべて textContent で行い、innerHTML は使わない（ESLint でも禁止）
import type { Severity } from '../model';
import { itemTitle, sevLabel, tr } from '../i18n';
import { API_TOP10, asvsRef, standardsOf, standardsShort } from '../engine/standards';

export type Child = Node | string | null | undefined | false;
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls = '', ...children: Child[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const c of children) if (c !== null && c !== undefined && c !== false) e.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return e;
}
export const button = (text: string, cls: string, onClick: () => void) => { const b = el('button', cls, text); b.type = 'button'; b.addEventListener('click', onClick); return b; };
export const link = (href: string, text: string) => { const a = el('a', 'text-primary underline underline-offset-4', text); a.href = href; a.target = '_blank'; a.rel = 'noopener'; return a; };
export const labelFor = (id: string, text: string, cls = 'block text-sm') => { const l = el('label', cls, text); l.htmlFor = id; return l; };
export const options = (sel: HTMLSelectElement, list: [string, string][], value: string) => { for (const [v, t] of list) { const o = el('option', '', t); o.value = v; sel.append(o); } sel.value = value; return sel; };
export const fileInput = (accept: string, onFile: (f: File) => void) => {
  const i = el('input', 'hidden'); i.type = 'file'; i.accept = accept;
  i.addEventListener('change', () => { const f = i.files?.[0]; i.value = ''; if (f) onFile(f); });
  return i;
};
export const BTN = 'rounded-md border border-line bg-surface px-4 py-2 hover:border-primary';
export const PRIMARY = 'rounded-md bg-primary px-5 py-2 font-bold text-primary-ink hover:opacity-90';
export const LINK = 'text-sm text-primary underline underline-offset-4';
export const SEV_TEXT: Record<Severity, string> = { high: 'text-sev-high', medium: 'text-sev-medium', low: 'text-sev-low', info: 'text-sev-info' };
export const SEV_BORDER: Record<Severity, string> = { high: 'border-sev-high', medium: 'border-sev-medium', low: 'border-sev-low', info: 'border-sev-info' };
export const chapterOf = (item: string) => 'HCRTEA'.indexOf(item[0]) + 1;
export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * 表。狭い画面では横にスクロールするので、そのときだけ枠にフォーカスを当てられるようにし（キーボードで横スクロールできる）、名前を付ける。
 * 枠は position: relative にする。読み上げ用の非表示の文字（sr-only、position: absolute）が枠の外に出て、ページ全体の幅を広げないため
 */
export function table(label: string, head: string[], body: HTMLTableRowElement[]) {
  const wrap = el('div', 'relative overflow-x-auto rounded-md border border-line bg-surface',
    el('table', 'w-full border-collapse text-sm',
      // 見出しが空の列（操作のボタンなど）にも、読み上げ用の名前を付ける
      el('thead', 'bg-paper text-left text-muted', el('tr', '', ...head.map(h => el('th', 'px-3 py-2 font-normal whitespace-nowrap', h || el('span', 'sr-only', tr().cols.actions))))),
      el('tbody', '', ...body)));
  wrap.setAttribute('role', 'region');
  wrap.setAttribute('aria-label', label);
  // 横にはみ出しているときだけ Tab で止まるようにする（はみ出していない表まで止まると、移動が煩わしい）。画面幅や折りたたみが変わったら判定し直す
  const update = () => { if (wrap.scrollWidth > wrap.clientWidth + 1) wrap.tabIndex = 0; else wrap.removeAttribute('tabindex'); };
  new ResizeObserver(update).observe(wrap);
  return wrap;
}
export const td = (cls: string, ...c: Child[]) => el('td', `border-t border-line px-3 py-2 align-top ${cls}`, ...c);
export const sevCell = (s: Severity, from?: Severity) => {
  const c = td(`whitespace-nowrap font-bold ${SEV_TEXT[s]}`, sevLabel(s), from ? '*' : '');
  if (from) c.title = tr().profileChanged(sevLabel(from));
  return c;
};
/** 項目名に、関連する基準（OWASP API Top 10、ASVS 5.0、IPA）を小さく添える。ASVS のレベルは title（ツールチップ）で示す */
export function titleCell(item: string, fallback: string) {
  const s = standardsOf(item); const short = standardsShort(item);
  const std = short ? el('span', 'ml-2 text-xs text-muted', short) : null;
  if (std && s.asvs.length) std.title = s.asvs.map(asvsRef).join('\n');
  return td('', itemTitle(item, fallback), API_TOP10[item] ? el('span', 'ml-2 text-xs text-muted', `OWASP ${API_TOP10[item]}`) : null, std);
}
export function download(name: string, type: string, body: string) {
  const a = el('a'); a.href = URL.createObjectURL(new Blob([body], { type })); a.download = name;
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/** 折りたたみ（details）の見出しの先頭に付ける開閉の目印。summary を flex にするとブラウザの三角が消えるため自前で付ける */
export const disclosure = () => { const s = el('span', 'disclosure inline-block w-4 shrink-0 text-muted'); s.setAttribute('aria-hidden', 'true'); return s; };
