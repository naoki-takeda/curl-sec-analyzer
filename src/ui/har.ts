// ui/har.ts：HARの読み込み（Web Worker）と、エントリ一覧の画面
import { HAR_LABEL_CHOICES, HAR_MAX_BYTES, type HarChain, type HarImport, defaultHarHosts, suggestLabels } from '../parser/har';
import { withProfile } from '../engine/profile';
import { tr } from '../i18n';
import { showText } from '../shownText';
import { BTN, button, el, labelFor, options, table, td } from './dom';
import HarWorker from '../worker.ts?worker&inline';
import { type Message, actions, refs, state } from './state';
import { renderEmpty } from './results';

// メッセージは文言を作る関数で渡す（言語を切り替えたら、その言語で出し直すため。main.ts の say）
const say = (m: Message) => actions.say(m);

// 読み込みの世代。読み込み中に別の HAR を読んだり、消去・HARを外すを押したりしたら、前の読み込みの結果は使わない
let harLoad = 0; let harWorker: Worker | undefined;
export const cancelHarLoad = () => { harLoad++; harWorker?.terminate(); harWorker = undefined; };

export function loadHar(f: File) {
  if (f.size > HAR_MAX_BYTES) { say(() => tr().har.tooLarge); return; }
  say(() => tr().har.loading);
  // Worker は blob: URL で作る（?worker&inline）。別ファイルの Worker には、そのファイルの HTTP 応答の CSP が使われ、
  // GitHub Pages は CSP ヘッダを返さないため、生の HAR（Cookie・パスワード）を持つ Worker から通信できてしまう。
  // blob: の Worker はページの CSP（connect-src 'none'）を引き継ぐ。メタCSPの worker-src blob: で許可する
  cancelHarLoad(); const w = new HarWorker(); harWorker = w; const gen = harLoad;
  const done = () => { w.terminate(); if (harWorker === w) harWorker = undefined; };
  w.onmessage = (e: MessageEvent<{ ok: boolean; result?: HarImport; error?: string }>) => {
    done();
    if (gen !== harLoad) return;                     // 古い読み込みの結果
    if (!e.data.ok || !e.data.result) { const err = e.data.error; say(() => { const t = tr().har; return t.failed(err === 'JSON' ? t.invalidJson : err ?? '?'); }); return; }
    const imp = e.data.result;
    // Worker の中では組織プロファイルが分からないため、プロファイルがあればセッションCookieの名前を反映して候補を作り直す
    if (state.profile) withProfile(state.profile, () => suggestLabels(imp.chains));
    state.har = { imp, hosts: defaultHarHosts(imp), name: f.name };
    renderHar(); say('');
    // 別の HAR に入れ替えたとき、前の HAR の判定結果を残さない。判定中（初回を含む）なら、読み込んだ HAR も入れて判定し直す
    if (state.last || actions.isAnalyzing()) actions.analyze();
    if (!refs.message.textContent) say(() => tr().har.loaded(f.name, imp.chains.length));   // 判定し直したときは、判定のメッセージ（判定中・エラー）を残す
  };
  w.onerror = () => { done(); if (gen === harLoad) say(() => tr().har.failed('worker')); };
  f.text().then(t => w.postMessage(t), () => { done(); if (gen === harLoad) say(() => tr().har.failed('read')); });
}
/** HAR を外す。判定結果に HAR のターゲットが残らないよう、貼り付けがあれば判定し直し、なければ結果を消す */
function removeHar() {
  const was = actions.isAnalyzing();
  cancelHarLoad(); actions.cancelAnalysis(); state.har = null; renderHar(); say('');
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
  const focusKey = (document.activeElement as HTMLElement | null)?.dataset?.focus;
  const T = tr().har; const { imp, hosts } = state.har;
  const same = shownImp === imp; shownImp = imp; if (!same) moved.clear();
  const prevScroll = same ? refs.harBox.querySelector<HTMLElement>('[data-scroll="har"]')?.scrollTop ?? 0 : 0;
  const prevOpen = same ? refs.harBox.querySelector('details')?.open : undefined;
  const hostBoxes = imp.hosts.map(h => {
    const cb = el('input'); cb.type = 'checkbox'; cb.checked = hosts.has(h); cb.id = `har-host-${h}`; cb.dataset.focus = `har-host-${h}`;
    cb.addEventListener('change', () => { if (cb.checked) hosts.add(h); else hosts.delete(h); renderHar(); });
    return el('span', 'mr-4 inline-flex items-center gap-1', cb, labelFor(cb.id, `${h} (${imp.chains.filter(c => c.host === h).length})`, 'text-sm'));
  });
  const rows = imp.chains.filter(c => hosts.has(c.host)).map(c => {
    const base = c.suggested.startsWith('har-') || c.suggested.startsWith('error-') ? c.suggested : `har-${c.id + 1}`;
    const sel = options(el('select', 'rounded-md border border-line bg-paper px-2 py-1 text-sm'),
      // har-N は、予約ラベルをほかのエントリに移したときの戻り先なので、いつも選択肢に入れる（候補が error-N のエントリでも空欄にしない）
      [...new Set([base, `har-${c.id + 1}`, `error-${c.id + 1}`, ...HAR_LABEL_CHOICES, c.label])].map((v): [string, string] => [v, v]).concat([['__exclude', T.exclude]]),
      c.excluded ? '__exclude' : c.label);
    sel.setAttribute('aria-label', T.labelFor(c.method, shownUrl(c))); sel.dataset.focus = `har-label-${c.id}`;   // 読み上げ用の名前も、画面の表示と同じくマスクする
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
    sens.setAttribute('aria-label', T.sensFor(shownUrl(c))); sens.dataset.focus = `har-sens-${c.id}`;
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
  if (focusKey) box.querySelector<HTMLElement>(`[data-focus="${CSS.escape(focusKey)}"]`)?.focus();
}
