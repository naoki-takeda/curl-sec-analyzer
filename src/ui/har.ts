// ui/har.ts：HARの読み込み（Web Worker）と、エントリ一覧の画面
import { HAR_LABEL_CHOICES, HAR_MAX_BYTES, type HarImport, defaultHarHosts, suggestLabels } from '../parser/har';
import { withProfile } from '../engine/profile';
import { tr } from '../i18n';
import { maskText } from '../mask';
import { BTN, button, el, labelFor, options, table, td } from './dom';
import HarWorker from '../worker.ts?worker&inline';
import { type Message, actions, refs, state } from './state';
import { renderEmpty } from './results';

// メッセージは文言を作る関数で渡す（言語を切り替えたら、その言語で出し直すため。main.ts の say）
const say = (m: Message) => actions.say(m);

// ---- HAR（v0.3） ----
// 読み込みの世代。読み込み中に別の HAR を読んだり、消去・HARを外すを押したりしたら、前の読み込みの結果は使わない
let harLoad = 0;
export const cancelHarLoad = () => { harLoad++; };

export function loadHar(f: File) {
  if (f.size > HAR_MAX_BYTES) { say(() => tr().har.tooLarge); return; }
  say(() => tr().har.loading);
  // Worker は blob: URL で作る（?worker&inline）。別ファイルの Worker には、そのファイルの HTTP 応答の CSP が使われ、
  // GitHub Pages は CSP ヘッダを返さないため、生の HAR（Cookie・パスワード）を持つ Worker から通信できてしまう。
  // blob: の Worker はページの CSP（connect-src 'none'）を引き継ぐ。メタCSPの worker-src blob: で許可する
  const w = new HarWorker(); const gen = ++harLoad;
  w.onmessage = (e: MessageEvent<{ ok: boolean; result?: HarImport; error?: string }>) => {
    w.terminate();
    if (gen !== harLoad) return;                     // 古い読み込みの結果
    if (!e.data.ok || !e.data.result) { const err = e.data.error; say(() => { const t = tr().har; return t.failed(err === 'JSON' ? t.invalidJson : err ?? '?'); }); return; }
    const imp = e.data.result;
    // Worker の中では組織プロファイルが分からないため、プロファイルがあればセッションCookieの名前を反映して候補を作り直す
    if (state.profile) withProfile(state.profile, () => suggestLabels(imp.chains));
    state.har = { imp, hosts: defaultHarHosts(imp), name: f.name };
    renderHar(); say('');
    if (state.last) actions.analyze();              // 別の HAR に入れ替えたとき、前の HAR の判定結果を残さない
    if (!refs.message.textContent) say(() => tr().har.loaded(f.name, imp.chains.length));   // 判定し直してエラーが出たら、そちらを残す
  };
  w.onerror = () => { w.terminate(); if (gen === harLoad) say(() => tr().har.failed('worker')); };
  f.text().then(t => w.postMessage(t));
}
/** HAR を外す。判定結果に HAR のターゲットが残らないよう、貼り付けがあれば判定し直し、なければ結果を消す */
function removeHar() {
  cancelHarLoad(); state.har = null; renderHar(); say('');
  if (!state.last) return;
  if (refs.input.value.trim()) actions.analyze();
  else { state.last = null; renderEmpty(); }
}

export function renderHar() {
  if (!state.har) { refs.harBox.replaceChildren(); return; }
  const T = tr().har; const { imp, hosts } = state.har;
  const hostBoxes = imp.hosts.map(h => {
    const cb = el('input'); cb.type = 'checkbox'; cb.checked = hosts.has(h); cb.id = `har-host-${h}`;
    cb.addEventListener('change', () => { if (cb.checked) hosts.add(h); else hosts.delete(h); renderHar(); });
    return el('span', 'mr-4 inline-flex items-center gap-1', cb, labelFor(cb.id, `${h} (${imp.chains.filter(c => c.host === h).length})`, 'text-sm'));
  });
  const rows = imp.chains.filter(c => hosts.has(c.host)).map(c => {
    const base = c.suggested.startsWith('har-') || c.suggested.startsWith('error-') ? c.suggested : `har-${c.id + 1}`;
    const sel = options(el('select', 'rounded-md border border-line bg-paper px-2 py-1 text-sm'),
      [...new Set([base, `error-${c.id + 1}`, ...HAR_LABEL_CHOICES])].map((v): [string, string] => [v, v]).concat([['__exclude', T.exclude]]),
      c.excluded ? '__exclude' : c.label);
    sel.setAttribute('aria-label', T.labelFor(c.method, maskText(c.url)));   // 読み上げ用の名前も、画面の表示と同じくマスクする
    sel.addEventListener('change', () => {
      if (sel.value === '__exclude') { c.excluded = true; return; }
      c.excluded = false;
      if (HAR_LABEL_CHOICES.includes(sel.value)) for (const o of imp.chains) if (o !== c && o.label === sel.value) o.label = `har-${o.id + 1}`;   // 予約ラベルは1件だけ
      c.label = sel.value; renderHar();
    });
    const sens = options(el('select', 'rounded-md border border-line bg-paper px-2 py-1 text-sm'),
      [['auto', T.auto(c.sentAuth)], ['1', tr().yes], ['0', tr().no]], c.sensitive === undefined ? 'auto' : c.sensitive ? '1' : '0');
    sens.setAttribute('aria-label', T.sensFor(maskText(c.url)));
    sens.addEventListener('change', () => { c.sensitive = sens.value === 'auto' ? undefined : sens.value === '1'; });
    return el('tr', '', td('whitespace-nowrap', c.method), td('break-all font-mono text-[12px]', maskText(c.url)),
      td('num whitespace-nowrap', `${c.status}${c.hops > 1 ? T.hops(c.hops) : ''}`), td('', sel), td('', sens));
  });
  const box = el('details', 'mt-4 rounded-md border border-line bg-surface p-4',
    el('summary', 'cursor-pointer font-bold', T.title(state.har.name)),
    el('p', 'mt-2 text-sm text-muted', T.note),
    imp.sanitized ? el('p', 'mt-2 text-sm text-sev-medium', T.sanitized) : null,
    el('div', 'mt-3', el('span', 'mr-2 text-sm text-muted', T.hosts), ...hostBoxes),
    el('div', 'mt-3 max-h-96 overflow-auto', table(tr().tables.har, [T.method, tr().cols.url, T.status, tr().cols.label, tr().cols.sensitive], rows)),
    el('div', 'mt-3', button(T.remove, BTN, removeHar)));
  box.open = true;
  refs.harBox.replaceChildren(box);
}
