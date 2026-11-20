// ui/har.ts：HARの読み込み（Web Worker）と、エントリ一覧の画面
import { HAR_MAX_BYTES, type HarChain, type HarImport, defaultHarHosts, suggestLabels } from '../parser/har';
import { HAR_LABEL_CHOICES } from '../engine/labels';
import { withProfile } from '../engine/profile';
import { type HarFailure, tr } from '../i18n';
import { showTarget, showText } from '../shownText';
import { BTN, button, el, focusable, focusedKey, labelFor, options, restoreFocus, table, td } from './dom';
import HarWorker from '../harWorker.ts?worker&inline';
import { type Message, actions, refs, state } from './state';
import { renderEmpty } from './results';

const say = (m?: Message) => actions.say(m);

// 読み込みの世代。読み込み中に別の HAR を読んだり、消去・HARを外す・サンプルを入れるを押したりしたら、前の読み込みの結果は使わない
let harLoad = 0; let harWorker: Worker | undefined;
export const cancelHarLoad = () => { harLoad++; harWorker?.terminate(); harWorker = undefined; };
/** HAR を読み込んでいる途中か（読み込み中のファイルは、まだ state.har に入っていない） */
export const isHarLoading = () => !!harWorker;
/** HAR の案内（読み込み中・読み込み済み）。HAR がなければ undefined */
export const harNotice = (): Message | undefined => {
  const h = state.har;
  return harWorker ? () => tr().har.loading : h ? () => tr().har.loaded(h.name, h.imp.chains.length) : undefined;
};

export function loadHar(f: File) {
  // 前の読み込みは、新しいファイルが大きすぎても止める（置き換えたつもりの前の HAR を、あとから入れない）
  cancelHarLoad();
  if (f.size > HAR_MAX_BYTES) { say(() => tr().har.tooLarge(HAR_MAX_BYTES / 1024 / 1024)); return; }
  say(() => tr().har.loading);
  // Worker は blob: URL で作る（ページの CSP を引き継ぐため。csp.config.ts）。作れない・送れない・結果を受け取れないときも失敗と知らせる
  let w: Worker;
  try { w = new HarWorker(); } catch { say(() => tr().har.failed('worker')); return; }
  harWorker = w; const gen = harLoad;
  const done = () => { w.terminate(); if (harWorker === w) harWorker = undefined; };
  const failed = (e: HarFailure) => { done(); if (gen === harLoad) say(() => tr().har.failed(e)); };
  w.onmessage = (e: MessageEvent<{ ok: boolean; result?: HarImport; error?: string }>) => {
    done();
    if (gen !== harLoad) return;                     // 古い読み込みの結果
    if (!e.data.ok || !e.data.result) { const err = e.data.error === 'JSON' ? 'json' : 'format'; say(() => tr().har.failed(err)); return; }
    const imp = e.data.result;
    // 読み込み中に出た設定ファイルのエラーは、読み込みの案内のあとに残す（案内で上書きしない）
    const prev = actions.message(); const pending = prev && prev() !== tr().har.loading ? prev : undefined;
    // Worker の中では組織プロファイルが分からないため、プロファイルがあればセッションCookieの名前を反映して候補を作り直す
    if (state.profile) withProfile(state.profile, () => suggestLabels(imp.chains));
    state.har = { imp, hosts: defaultHarHosts(imp), name: f.name };
    renderHar(); say();
    // 別の HAR に入れ替えたとき、前の HAR の判定結果を残さない。判定中（初回を含む）なら、読み込んだ HAR も入れて判定し直す
    if (state.last || actions.isAnalyzing()) actions.analyze();
    // 判定し直したときは、判定のメッセージ（判定中・エラー）を残す
    if (!refs.message.textContent) say(pending ? () => `${tr().har.loaded(f.name, imp.chains.length)} ${pending()}` : () => tr().har.loaded(f.name, imp.chains.length));
  };
  w.onerror = w.onmessageerror = () => failed('worker');
  f.text().then(t => { try { w.postMessage(t); } catch { failed('worker'); } }, () => failed('read'));
}
/**
 * HAR を外す。判定結果に HAR のターゲットが残らないよう、貼り付けがあれば判定し直し、なければ結果を消す。押したボタンは消えるので、
 * フォーカスは「ファイルを開く」に移す（body に落とさない。WCAG 2.4.3）
 */
function removeHar() {
  const was = actions.isAnalyzing();
  cancelHarLoad(); actions.cancelAnalysis(); state.har = null; renderHar(); say();
  document.querySelector<HTMLButtonElement>('#open-file')?.focus();
  if (!state.last && !was) return;
  if (refs.input.value.trim()) actions.analyze();
  else { state.last = null; renderEmpty(); }
}

/**
 * 一覧に出す URL（マスク済み）。チェーンごとに一度だけ作る（描き直すたびに全行の URL をマスクし直すと、長い URL の多い HAR で遅い）
 */
const shownUrls = new WeakMap<HarChain, string>();
/**
 * 予約ラベルを移したエントリと、元のラベル。移したエントリがそのラベルを外したら戻す（Chromium は閉じた select を矢印で動かすたびに change を出す
 * ので、選択肢を見て回るだけで、login・logout のエントリのラベルを失わないため）
 */
const moved = new Map<HarChain, { by: HarChain; label: string }>();
/** 前に描いた HAR（別の HAR を読んだら、一覧は開いて先頭から表示する） */
let shownImp: HarImport | undefined;
const shownUrl = (c: HarChain) => { let v = shownUrls.get(c); if (v === undefined) { v = showText(c.url); shownUrls.set(c, v); } return v; };
export function renderHar() {
  if (!state.har) { refs.harBox.replaceChildren(); return; }
  // 一覧は描き直すので、操作した部品のフォーカス・表のスクロール位置・開閉を戻す（チェックボックス・ラベルの選択を変えても、フォーカスを
  // body に落とさず、表を先頭に戻さない。WCAG 2.4.3）
  const focusKey = focusedKey();
  const T = tr().har; const { imp, hosts } = state.har;
  const same = shownImp === imp; shownImp = imp; if (!same) moved.clear();
  const prevScroll = same ? refs.harBox.querySelector<HTMLElement>('[data-scroll="har"]')?.scrollTop ?? 0 : 0;
  const prevOpen = same ? refs.harBox.querySelector('details')?.open : undefined;
  // ホスト名は URL の列と同じ出し方にする（URL の列で伏せるカード番号のラベルのホスト名を、ここでそのまま出さない）
  const hostBoxes = imp.hosts.map(h => {
    const cb = el('input'); cb.type = 'checkbox'; cb.checked = hosts.has(h); cb.id = `har-host-${h}`; focusable(cb, `har-host-${h}`);
    cb.addEventListener('change', () => { if (cb.checked) hosts.add(h); else hosts.delete(h); renderHar(); });
    return el('span', 'mr-4 inline-flex items-center gap-1', cb, labelFor(cb.id, `${showTarget(h, h)} (${imp.chains.filter(c => c.host === h).length})`, 'text-sm'));
  });
  const rows = imp.chains.filter(c => hosts.has(c.host)).map(c => {
    const base = c.suggested.startsWith('har-') || c.suggested.startsWith('error-') ? c.suggested : `har-${c.id + 1}`;
    const sel = options(el('select', 'rounded-md border border-line bg-paper px-2 py-1 text-sm'),
      // har-N は、予約ラベルをほかのエントリに移したときの戻り先なので、いつも選択肢に入れる（候補が error-N のエントリでも空欄にしない）
      [...new Set([base, `har-${c.id + 1}`, `error-${c.id + 1}`, ...HAR_LABEL_CHOICES, c.label])].map((v): [string, string] => [v, v]).concat([['__exclude', T.exclude]]),
      c.excluded ? '__exclude' : c.label);
    sel.setAttribute('aria-label', T.labelFor(c.method, shownUrl(c))); focusable(sel, `har-label-${c.id}`);   // 読み上げ用の名前も、画面の表示と同じくマスクする
    sel.addEventListener('change', () => {
      // このエントリが前に予約ラベルを移していたら、そのエントリのラベルを戻す（ほかのラベルに変えていなければ）
      for (const [o, v] of moved) if (v.by === c) { if (o.label === `har-${o.id + 1}` && !imp.chains.some(x => x !== o && x !== c && x.label === v.label)) o.label = v.label; moved.delete(o); }
      if (sel.value === '__exclude') { c.excluded = true; renderHar(); return; }
      c.excluded = false;
      if (HAR_LABEL_CHOICES.includes(sel.value)) for (const o of imp.chains) if (o !== c && o.label === sel.value) { moved.set(o, { by: c, label: o.label }); o.label = `har-${o.id + 1}`; }   // 予約ラベルは1件だけ
      c.label = sel.value; renderHar();
    });
    const sens = options(el('select', 'rounded-md border border-line bg-paper px-2 py-1 text-sm'),
      [['auto', T.auto(c.sentAuth)], ['1', tr().yes], ['0', tr().no]], c.sensitive === undefined ? 'auto' : c.sensitive ? '1' : '0');
    sens.setAttribute('aria-label', T.sensFor(shownUrl(c))); focusable(sens, `har-sens-${c.id}`);
    sens.addEventListener('change', () => { c.sensitive = sens.value === 'auto' ? undefined : sens.value === '1'; });
    return el('tr', '', td('whitespace-nowrap', c.method), td('break-all font-mono text-[12px]', shownUrl(c)),
      td('num whitespace-nowrap', `${c.status}${c.hops > 1 ? T.hops(c.hops) : ''}`), td('', sel), td('', sens));
  });
  const scroller = el('div', 'mt-3 max-h-96 overflow-auto', table(tr().tables.har, [T.method, tr().cols.url, T.status, tr().cols.label, tr().cols.sensitive], rows));
  scroller.dataset.scroll = 'har';
  const box = el('details', 'mt-4 rounded-md border border-line bg-surface p-4',
    el('summary', 'cursor-pointer font-bold', T.title(state.har.name)),
    el('p', 'mt-2 text-sm text-muted', T.note),
    imp.sanitized ? el('p', 'mt-2 text-sm text-sev-medium', T.sanitized) : null,
    el('div', 'mt-3', el('span', 'mr-2 text-sm text-muted', T.hosts), ...hostBoxes),
    scroller,
    el('div', 'mt-3', button(T.remove, BTN, removeHar)));
  box.open = prevOpen ?? true;
  refs.harBox.replaceChildren(box);
  scroller.scrollTop = prevScroll;
  restoreFocus(box, focusKey);
}
