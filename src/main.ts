// main.ts：画面の入口（ツール設計3「画面設計」）。描画の部品は ui/ の下にある
import './styles.css';
import { HAR_MAX_BYTES, isHar, suggestLabels } from './parser/har';
import type { AnalyzeRequest, AnalyzeResult } from './engine/analyze';
import AnalyzeWorker from './analyzeWorker.ts?worker&inline';
import { countBySeverity, overall } from './engine/summarize';
import { isActive, parseSuppressions } from './engine/suppress';
import { parseProfile, profileTemplate, withProfile } from './engine/profile';
import { diff, parseBaseline } from './engine/diff';
import { legacyHarKey } from './engine/targetKey';
import { RULESET_VERSION, TOOL_VERSION } from './version';
import { type Lang, getLang, setLang, tr } from './i18n';
import sample from './sample';
import { BTN, LINK, PRIMARY, button, download, el, fileInput as hidden, labelFor, link, reducedMotion } from './ui/dom';
import { type Message, actions, refs, state } from './ui/state';
import { render, renderEmpty } from './ui/results';
import { cancelHarLoad, loadHar, renderHar } from './ui/har';
import { commandGenerator } from './ui/generator';
import { joinMessages } from './messagesEn';

const MAX_BYTES = 5 * 1024 * 1024;
const app = document.querySelector<HTMLDivElement>('#app')!;
refs.dialog = el('dialog', 'm-auto w-[min(32rem,92vw)] rounded-md border border-line bg-surface p-0 text-ink backdrop:bg-black/40');
Object.assign(actions, { analyze, cancelAnalysis, isAnalyzing: () => !!analyzing, say, renderSettings, openGenerator, loadSample });

// ?lang= は ja・en（en-US などは en）だけを受け付ける。それ以外はブラウザの言語で決める（不明な値だと文言の表が引けず、判定で止まる）
const qLang = new URLSearchParams(location.search).get('lang')?.toLowerCase() ?? '';
setLang(/^(ja|en)(-|$)/.test(qLang) ? qLang.slice(0, 2) as Lang : (navigator.language.toLowerCase().startsWith('ja') ? 'ja' : 'en'));
// 他のサイトに埋め込まれたときは、入力欄を出さない（クリックジャッキング対策。メタCSPでは frame-ancestors が効かないため。ツール設計3）
if (window.top !== window.self) {
  const open = el('a', 'text-primary underline underline-offset-4', getLang() === 'en' ? 'Open this tool directly' : 'このツールを直接開く');
  open.href = location.href; open.target = '_blank'; open.rel = 'noopener noreferrer';
  app.replaceChildren(el('div', 'p-6',
    el('p', 'font-bold', getLang() === 'en' ? 'This tool cannot be used inside another site.' : 'このツールは、他のサイトに埋め込んだ状態では使えません。'),
    el('p', 'mt-2 text-sm', getLang() === 'en' ? 'To protect what you paste, open it in its own tab.' : '貼り付ける内容を守るため、単独のタブで開いてください。'), el('p', 'mt-2', open)));
} else {
  buildShell();
}

// ---- 画面の骨格 ----
function buildShell() {
  const T = tr();
  refs.input = el('textarea', 'block w-full h-[22rem] lg:h-[calc(100vh-26rem)] min-h-64 resize-y rounded-md border border-line bg-surface p-3 font-mono text-[13px] leading-relaxed text-ink');
  refs.input.id = 'input'; refs.input.spellcheck = false; refs.input.autocomplete = 'off'; refs.input.wrap = 'off'; refs.input.value = state.draft.input;
  refs.input.placeholder = '#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\n…';
  refs.input.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyze(); });
  refs.input.addEventListener('input', inputChanged);
  refs.urlInput = el('input', 'w-full rounded-md border border-line bg-surface px-3 py-2 font-mono text-[13px]');
  refs.urlInput.id = 'url'; refs.urlInput.type = 'url'; refs.urlInput.placeholder = 'https://www.example.com/'; refs.urlInput.value = state.draft.url;
  refs.urlInput.addEventListener('input', inputChanged);
  refs.message = el('p', 'min-h-6 text-sm text-sev-medium', state.draft.message); refs.message.setAttribute('role', 'status');
  // 結果欄は aria-live にしない（再描画のたびに数百行を読み上げてしまう）。判定の結果は、件数だけを役割 status の欄（refs.message）で知らせる
  refs.results = el('section', 'min-w-0'); refs.results.setAttribute('aria-label', getLang() === 'en' ? 'Results' : '判定結果');
  refs.harBox = el('div', '');
  refs.settingsStatus = el('ul', 'mt-2 space-y-0.5 text-sm text-muted');
  refs.inputNote = el('div', 'hidden rounded-md border border-line bg-surface p-3 text-sm text-muted');
  refs.inputToggle = button('', LINK, () => { state.view.inputHidden = !state.view.inputHidden; applyInputVisibility(); if (!state.view.inputHidden) refs.input.focus(); });
  refs.genDetails = commandGenerator();

  const fileIn = hidden('.txt,.log,.har,text/plain,application/json', openFile);
  // 設定ファイル（例外・組織プロファイル）も、貼り付けと同じ大きさまでにする（大きなファイルで画面を止めない）
  const supIn = hidden('.json,application/json', async f => {
    if (f.size > MAX_BYTES) { say(() => tr().settingsTooLarge(MAX_BYTES / 1024 / 1024)); return; }
    const { list, errors } = parseSuppressions(await f.text());
    // 1件も読めなかった（形式の違うファイル）ときは、登録済みの例外を残す（画面で登録しただけの例外を消さない）
    if (list.length || !errors.length) state.suppressions = list;
    // * を含むものは、以前の形式のキーでもパターンとして照合する（engine/suppress.ts の matches）ので、登録し直しを促さない
    const legacy = list.filter(s => !s.target.includes('*') && legacyHarKey(s.target)).length;
    refresh(() => { const t = tr(); return errors.length ? t.readErrors(t.suppressionsFile, joinMessages(errors, getLang())) : legacy ? t.legacyHarKeys(legacy) : ''; });
  });
  const profIn = hidden('.json,application/json', async f => {
    if (f.size > MAX_BYTES) { say(() => tr().settingsTooLarge(MAX_BYTES / 1024 / 1024)); return; }
    const { profile: p, errors } = parseProfile(await f.text());
    // 形式の違うファイル（どの設定も読めず、エラーがある）では、読み込み済みのプロファイルを残す（既定の設定に置き換えない。例外ファイルと同じ）
    const known = p && (Object.keys(p.severity).length || p.exclude.length || p.sessionCookieNames.length || p.trustedScriptOrigins.length || p.name || p.sessionMaxAgeHours !== 24);
    const kept = !!state.profile && !(p && (known || !errors.length));
    if (p && !kept) state.profile = p;
    // 読み込み済みのHARのラベル候補も、プロファイルのセッションCookieの名前で作り直す（画面で選び直したラベルは残す）。残したプロファイルでは作り直さない
    // （判定に使うプロファイルと食い違わないため）
    if (p && !kept && state.har) { const chains = state.har.imp.chains; withProfile(p, () => suggestLabels(chains, true)); renderHar(); }
    // 残したときは、そのことを知らせる（「既定の24時間を使います」などのエラーの文言だけでは、古いプロファイルを使い続けることが分からない）
    refresh(() => { const t = tr(); return errors.length ? t.readErrors(t.loadProfile, joinMessages(errors, getLang())) + (kept ? t.profileKept : '') : ''; });
  });
  const baseIn = hidden('.json,application/json', async f => {
    // 前回の結果は HAR と同じ上限（大きな HAR を判定した結果の JSON は 5MB を超えるので、貼り付けと同じ上限では自分のエクスポートを読めない）
    if (f.size > HAR_MAX_BYTES) { say(() => tr().settingsTooLarge(HAR_MAX_BYTES / 1024 / 1024)); return; }
    const { baseline: b, error, skipped } = parseBaseline(await f.text());
    if (b) state.baseline = b;
    const legacy = b ? b.findings.filter(x => legacyHarKey(x.targetKey)).length : 0;
    refresh(() => { const t = tr(); return error ? joinMessages([error], getLang()) : skipped ? t.baselineSkipped(skipped) : legacy ? t.legacyHarKeys(legacy) : ''; });
  });

  app.replaceChildren(
    el('div', 'mx-auto max-w-[1400px] px-4 py-6 lg:px-8',
      el('header', 'mb-6 border-b border-line pb-4',
        el('div', 'flex flex-wrap items-baseline gap-x-4',
          el('h1', 'text-2xl font-bold tracking-tight', 'curl-sec-analyzer'),
          el('span', 'num text-sm text-muted', T.versions(TOOL_VERSION, RULESET_VERSION)),
          // ボタンの文言（English・日本語）は切り替え先の言語なので lang を付ける（WCAG 3.1.2）。作り直したあとはボタンにフォーカスを戻す（WCAG 2.4.3）
          Object.assign(button(T.langSwitch, `${LINK} ml-auto`, () => { keepDraft(); const m = current; setLang(getLang() === 'ja' ? 'en' : 'ja'); buildShell(); setBusy(!!analyzing); if (m) say(m);
            document.querySelector<HTMLButtonElement>('#lang-switch')?.focus(); }), { id: 'lang-switch', lang: getLang() === 'ja' ? 'en' : 'ja' })),
        el('p', 'mt-1 text-muted', T.tagline),
        el('ul', 'mt-2 list-disc pl-5 text-sm text-muted', el('li', '', T.notice1), el('li', '', T.notice2), el('li', '', T.notice3),
          T.englishNote ? el('li', '', T.englishNote) : null),
        el('p', 'mt-2 flex gap-4 text-sm', link('./LICENSE.txt', T.license), link('./THIRD_PARTY_LICENSES.txt', T.thirdParty))),
      el('main', 'grid gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]',
        el('section', 'min-w-0',
          el('div', 'mb-2 flex items-baseline justify-between gap-2', labelFor('input', T.inputLabel, 'block font-bold'), refs.inputToggle),
          refs.inputNote, refs.input,
          labelFor('url', T.urlLabel, 'mt-3 mb-1 block text-sm text-muted'), refs.urlInput,
          el('div', 'mt-3 flex flex-wrap items-center gap-2',
            button(T.analyze, PRIMARY, analyze),
            button(T.openFile, BTN, () => fileIn.click()),
            button(T.sample, BTN, loadSample),
            button(T.clear, 'rounded-md px-3 py-2 text-muted underline-offset-4 hover:underline', () => { refs.input.value = ''; cancelAnalysis(); cancelHarLoad(); state.har = null; renderHar(); say(''); state.last = null; state.view.inputHidden = false; applyInputVisibility(); renderEmpty(); refs.input.focus(); }),
            fileIn, supIn, profIn, baseIn),
          refs.message,
          refs.genDetails,
          refs.harBox,
          el('details', 'mt-4 rounded-md border border-line bg-surface p-4',
            el('summary', 'cursor-pointer font-bold', T.settings),
            el('div', 'mt-3 flex flex-wrap gap-2',
              button(T.loadSuppressions, BTN, () => supIn.click()),
              button(T.loadProfile, BTN, () => profIn.click()),
              button(T.loadBaseline, BTN, () => baseIn.click()),
              button(T.profileTemplate, LINK, () => download('profile.json', 'application/json', profileTemplate()))),
            refs.settingsStatus),
          el('p', 'mt-3 text-sm text-muted', T.maskNote)),
        refs.results)),
    refs.dialog);
  renderSettings(); renderHar(); applyInputVisibility();
  if (state.last) render(); else renderEmpty();
}
function keepDraft() { state.draft = { input: refs.input.value, url: refs.urlInput.value, message: refs.message.textContent ?? '' }; }
// 状態のメッセージ（件数、入力がない、読み込みのエラーなど）は、文言を作る関数で受け取る。言語を切り替えたら、その言語で出し直す
// （文字列のまま残すと、英語の画面に日本語のメッセージが残る）
let current: (() => string) | undefined;
function say(m: Message) { current = typeof m === 'function' ? m : undefined; refs.message.textContent = typeof m === 'function' ? m() : m; }
function saySummary(s: [number, number, number]) { say(() => tr().analyzed(...s)); }
/** 設定を読み込んだあとに判定し直す。読み込みのエラーは判定のあとに表示する（analyze は最初に表示を消すため、先に出すと消えてしまう） */
async function refresh(msg: () => string = () => '') {
  renderSettings();
  const again = !!(state.last || state.har || analyzing);
  if (again) await analyze();
  if (msg() || !again) say(msg);
}
function renderSettings() {
  const T = tr();
  const active = state.suppressions.filter(s => isActive(s)).length;
  refs.settingsStatus.replaceChildren(
    el('li', '', state.suppressions.length ? T.suppressionsStatus(state.suppressions.length, active) : T.noSuppressions),
    el('li', '', state.profile ? T.profileStatus(state.profile.name) : T.noProfile),
    el('li', '', state.baseline ? T.baselineStatus(state.baseline.generatedAt) : T.noBaseline));
}
/** 判定後は、生の出力（Cookieやトークンを含む）を入力欄に見せたままにしない */
function applyInputVisibility() {
  const T = tr(); const has = refs.input.value.trim().length > 0;
  const hide = state.view.inputHidden && has;
  refs.input.classList.toggle('hidden', hide);
  refs.inputNote.classList.toggle('hidden', !hide);
  refs.inputNote.textContent = hide ? T.inputHidden(refs.input.value.split('\n').length) : '';
  refs.inputToggle.classList.toggle('hidden', !has);
  refs.inputToggle.textContent = hide ? T.showInput : T.hideInput;
}
function loadSample() {
  if (refs.input.value.trim() && refs.input.value !== sample && !confirm(tr().confirmReplace)) return;
  refs.input.value = sample; analyze();
}
function openGenerator() {
  refs.genDetails.open = true;
  refs.genDetails.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  refs.genDetails.querySelector<HTMLInputElement>('input')?.focus({ preventScroll: true });
}
async function openFile(f: File) {
  if (/\.har$/i.test(f.name) || isHar(await f.slice(0, 400).text())) { loadHar(f); return; }
  if (f.size > MAX_BYTES) { say(() => tr().fileTooLarge); return; }
  refs.input.value = await f.text(); analyze();
}
// 判定の世代と、判定中の Worker・その Promise の解決。判定し直したり、消去・HAR を外すを押したりしたら、前の Worker を止め、前の結果は
// 使わない（古い結果で新しい入力の表示を上書きしない）。止めた判定の Promise も解決する（待っている呼び出し側を止めたままにしない）
let analyzeGen = 0; let analyzing: { worker: Worker; settle: (shown: boolean) => void; text: string; url: string } | undefined;
/** 判定中の Worker を止める（結果は使わない） */
function cancelAnalysis() {
  analyzeGen++;
  const a = analyzing; analyzing = undefined;
  if (a) { a.worker.terminate(); a.settle(false); }
  setBusy(false);
}
/** 判定中は結果欄を aria-busy にし、結果のファイルの保存を止める（判定のあとに読み込んだ設定と古い結果を混ぜて出力しない） */
function setBusy(b: boolean) {
  refs.results.setAttribute('aria-busy', String(b));
  for (const x of refs.results.querySelectorAll<HTMLButtonElement>('[data-export]')) x.disabled = b;
}
/** 判定中に入力・URL 欄を直したら、その判定を止める（結果が届いたときに、直す前の入力の結果を出して入力欄を隠さない） */
function inputChanged() {
  if (!analyzing || (refs.input.value === analyzing.text && refs.urlInput.value === analyzing.url)) return;
  cancelAnalysis(); say(() => tr().analysisCancelled);
}
/**
 * 入力を判定して表示する。判定は Web Worker で行う（数万件のターゲットの HAR などで画面を止めない）。Worker は HAR の読み込みと同じく
 * blob: URL で作る（ページの CSP の connect-src 'none' を引き継ぐ。ui/har.ts）。表示まで終わったら解決する（判定のあとに出すメッセージのため）。
 * 解決する値は、この判定の結果を表示したか（止められた・置き換わった・判定できなかったときは false。描き直した結果にフォーカスを移すため）
 */
function analyze(): Promise<boolean> {
  say('');
  const text = refs.input.value;
  const fail = (m: () => string) => { cancelAnalysis(); say(m); state.last = null; renderEmpty(); };
  if (!text.trim() && !state.har) { fail(() => tr().emptyInput); return Promise.resolve(false); }
  // 判定できなかったときは前の結果を消す（残すと、言語の切り替えなどで別の入力の結果が表示・出力される）
  if (new Blob([text]).size > MAX_BYTES) { fail(() => tr().tooLarge); return Promise.resolve(false); }
  const req: AnalyzeRequest = { text, url: refs.urlInput.value, har: state.har ? { imp: state.har.imp, hosts: state.har.hosts } : undefined,
    suppressions: state.suppressions, profile: state.profile };
  const settings = { suppressions: state.suppressions, profile: state.profile, baseline: state.baseline };
  cancelAnalysis();
  const w = new AnalyzeWorker(); const gen = analyzeGen;
  say(() => tr().analyzing); setBusy(true);
  return new Promise<boolean>(resolve => {
    analyzing = { worker: w, settle: resolve, text, url: req.url };
    const done = () => { w.terminate(); if (analyzing?.worker === w) { analyzing = undefined; setBusy(false); } };
    w.onmessage = (e: MessageEvent<{ ok: boolean; result?: AnalyzeResult }>) => {
      done();
      if (gen !== analyzeGen) { resolve(false); return; }   // 古い判定の結果
      // 判定の途中の例外（想定外の入力）で、前の入力の結果を表示・出力したままにしない
      let shown = false;
      if (!e.data.ok || !e.data.result) fail(() => tr().analysisFailed);
      else { try { show(e.data.result, text, settings); shown = true; } catch { fail(() => tr().analysisFailed); } }
      resolve(shown);                                   // 表示まで終わってから解決する
    };
    w.onerror = () => { done(); if (gen === analyzeGen) fail(() => tr().analysisFailed); resolve(false); };
    w.postMessage(req);
  });
}
/** 判定の結果を表示する */
function show({ targets, warnings, findings, cov }: AnalyzeResult, text: string, settings: NonNullable<typeof state.last>['settings']) {
  if (!targets.length) { say(() => tr().noResponse); state.last = null; renderEmpty(); return; }
  state.last = { targets, warnings, findings, cov, settings, diff: settings.baseline ? diff(settings.baseline.findings, findings) : undefined };
  if (text.trim()) state.view.inputHidden = true;            // 判定できたら、生の出力を隠す
  applyInputVisibility();
  render();
  // 件数は画面の集計（項目×条件で一意に数える。ui/results.ts と同じ）に合わせる。ターゲットごとの指摘を数えると、画面と違う数を読み上げる
  const rows = overall(findings);
  saySummary([targets.length, rows.length, countBySeverity(rows).high]);
  if (matchMedia('(max-width: 1023px)').matches)
    refs.results.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth' });
}
