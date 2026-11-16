// main.ts：画面の入口（ツール設計3「画面設計」）。描画の部品は ui/ の下にある
import './styles.css';
import { parseInput } from './parser/input';
import { harTargets, isHar, suggestLabels } from './parser/har';
import { assignHopUrls, uniqueLabels } from './parser/target';
import { runAll } from './engine/run';
import { countBySeverity, overall } from './engine/summarize';
import { coverage, ITEMS } from './engine/coverage';
import { isActive, parseSuppressions } from './engine/suppress';
import { parseProfile, profileTemplate, withProfile } from './engine/profile';
import { diff, parseBaseline } from './engine/diff';
import { IMPLEMENTED, RULESET_VERSION, TOOL_VERSION } from './rules/ruleset';
import { type Lang, getLang, setLang, tr } from './i18n';
import sample from './sample';
import { BTN, LINK, PRIMARY, button, download, el, fileInput as hidden, labelFor, link, reducedMotion } from './ui/dom';
import { actions, refs, state } from './ui/state';
import { render, renderEmpty } from './ui/results';
import { cancelHarLoad, loadHar, renderHar } from './ui/har';
import { commandGenerator } from './ui/generator';
import { joinMessages } from './messagesEn';

const MAX_BYTES = 5 * 1024 * 1024;
const app = document.querySelector<HTMLDivElement>('#app')!;
refs.dialog = el('dialog', 'm-auto w-[min(32rem,92vw)] rounded-md border border-line bg-surface p-0 text-ink backdrop:bg-black/40');
Object.assign(actions, { analyze, say, renderSettings, openGenerator, loadSample });

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
// ---- 画面の骨格 ----
function buildShell() {
  const T = tr();
  refs.input = el('textarea', 'block w-full h-[22rem] lg:h-[calc(100vh-26rem)] min-h-64 resize-y rounded-md border border-line bg-surface p-3 font-mono text-[13px] leading-relaxed text-ink');
  refs.input.id = 'input'; refs.input.spellcheck = false; refs.input.autocomplete = 'off'; refs.input.wrap = 'off'; refs.input.value = state.draft.input;
  refs.input.placeholder = '#TARGET url=https://www.example.com/ label=top\nHTTP/2 200\ncontent-type: text/html\n…';
  refs.input.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyze(); });
  refs.urlInput = el('input', 'w-full rounded-md border border-line bg-surface px-3 py-2 font-mono text-[13px]');
  refs.urlInput.id = 'url'; refs.urlInput.type = 'url'; refs.urlInput.placeholder = 'https://www.example.com/'; refs.urlInput.value = state.draft.url;
  refs.message = el('p', 'min-h-6 text-sm text-sev-medium', state.draft.message); refs.message.setAttribute('role', 'status');
  // 結果欄は aria-live にしない（再描画のたびに数百行を読み上げてしまう）。判定の結果は、件数だけを役割 status の欄（refs.message）で知らせる
  refs.results = el('section', 'min-w-0'); refs.results.setAttribute('aria-label', getLang() === 'en' ? 'Results' : '判定結果');
  refs.harBox = el('div', '');
  refs.settingsStatus = el('ul', 'mt-2 space-y-0.5 text-sm text-muted');
  refs.inputNote = el('div', 'hidden rounded-md border border-line bg-surface p-3 text-sm text-muted');
  refs.inputToggle = button('', LINK, () => { state.view.inputHidden = !state.view.inputHidden; applyInputVisibility(); if (!state.view.inputHidden) refs.input.focus(); });
  refs.genDetails = commandGenerator();

  const fileIn = hidden('.txt,.log,.har,text/plain,application/json', openFile);
  const supIn = hidden('.json,application/json', async f => {
    const { list, errors } = parseSuppressions(await f.text());
    state.suppressions = list; refresh(errors.length ? T.readErrors(T.suppressionsFile, joinMessages(errors, getLang())) : '');
  });
  const profIn = hidden('.json,application/json', async f => {
    const { profile: p, errors } = parseProfile(await f.text());
    if (p) state.profile = p;
    // 読み込み済みのHARのラベル候補も、プロファイルのセッションCookieの名前で作り直す（画面で選び直したラベルは残す）
    if (p && state.har) { const chains = state.har.imp.chains; withProfile(p, () => suggestLabels(chains, true)); renderHar(); }
    refresh(errors.length ? T.readErrors(T.loadProfile, joinMessages(errors, getLang())) : '');
  });
  const baseIn = hidden('.json,application/json', async f => {
    const { baseline: b, error, skipped } = parseBaseline(await f.text());
    if (b) state.baseline = b; refresh(error ? joinMessages([error], getLang()) : skipped ? T.baselineSkipped(skipped) : '');
  });

  app.replaceChildren(
    el('div', 'mx-auto max-w-[1400px] px-4 py-6 lg:px-8',
      el('header', 'mb-6 border-b border-line pb-4',
        el('div', 'flex flex-wrap items-baseline gap-x-4',
          el('h1', 'text-2xl font-bold tracking-tight', 'curl-sec-analyzer'),
          el('span', 'num text-sm text-muted', T.versions(TOOL_VERSION, RULESET_VERSION)),
          button(T.langSwitch, `${LINK} ml-auto`, () => { keepDraft(); const s = summary; setLang(getLang() === 'ja' ? 'en' : 'ja'); buildShell(); if (s) saySummary(s); })),
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
            button(T.clear, 'rounded-md px-3 py-2 text-muted underline-offset-4 hover:underline', () => { refs.input.value = ''; cancelHarLoad(); state.har = null; renderHar(); say(''); state.last = null; state.view.inputHidden = false; applyInputVisibility(); renderEmpty(); refs.input.focus(); }),
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
// 判定のあとの件数。言語を切り替えたら、その言語で出し直す（文字列のまま残すと、英語の画面に日本語の件数が残る）
let summary: [number, number, number] | undefined;
function say(m: string) { refs.message.textContent = m; summary = undefined; }
function saySummary(s: [number, number, number]) { say(tr().analyzed(...s)); summary = s; }
/** 設定を読み込んだあとに判定し直す。読み込みのエラーは判定のあとに表示する（analyze は最初に表示を消すため、先に出すと消えてしまう） */
function refresh(msg = '') {
  renderSettings();
  const again = !!(state.last || state.har);
  if (again) analyze();
  if (msg || !again) say(msg);
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
  const T = tr();
  if (/\.har$/i.test(f.name) || isHar(await f.slice(0, 400).text())) { loadHar(f); return; }
  if (f.size > MAX_BYTES) { say(T.fileTooLarge); return; }
  refs.input.value = await f.text(); analyze();
}
function analyze() {
  // 判定の途中の例外（想定外の入力）で、前の入力の結果を表示・出力したままにしない
  try { analyzeUnsafe(); }
  catch { say(tr().analysisFailed); state.last = null; renderEmpty(); }
}
function analyzeUnsafe() {
  const T = tr();
  say('');
  const text = refs.input.value;
  if (!text.trim() && !state.har) { say(T.emptyInput); state.last = null; renderEmpty(); return; }
  // 判定できなかったときは前の結果を消す（残すと、言語の切り替えなどで別の入力の結果が表示・出力される）
  if (new Blob([text]).size > MAX_BYTES) { say(T.tooLarge); state.last = null; renderEmpty(); return; }
  const parsed = text.trim() ? parseInput(text) : { targets: [], warnings: [] };
  const fromHar = state.har ? withProfile(state.profile, () => harTargets(state.har!.imp, state.har!.hosts)) : { targets: [], warnings: [] };
  const targets = [...parsed.targets, ...fromHar.targets];
  const merged = uniqueLabels(targets);                       // 貼り付けと HAR で同じラベル（login など）を付けた場合
  const u = refs.urlInput.value.trim();
  // URL 欄で補ったターゲットにも、各ホップの URL を付け直す（-L で http から https に転送されたかを判定するため。parseInput の中では URL が分からない）
  if (u) for (const t of targets) if (!t.url && t.label === 'default') { t.url = u; assignHopUrls(t); }
  if (!targets.length) { say(T.noResponse); state.last = null; renderEmpty(); return; }
  const warnings = [...parsed.warnings, ...fromHar.warnings, ...merged].filter(w => !(u && w.kind === 'unknown-url' && w.label === 'default'));   // URL欄で補ったのは default だけ
  const findings = runAll(targets, { suppressions: state.suppressions, profile: state.profile });
  state.last = { targets, warnings, findings, cov: coverage(findings, IMPLEMENTED, ITEMS, state.profile?.exclude), diff: state.baseline ? diff(state.baseline.findings, findings) : undefined };
  if (text.trim()) state.view.inputHidden = true;            // 判定できたら、生の出力を隠す
  applyInputVisibility();
  render();
  // 件数は画面の集計（項目×条件で一意に数える。ui/results.ts と同じ）に合わせる。ターゲットごとの指摘を数えると、画面と違う数を読み上げる
  const rows = overall(findings);
  saySummary([targets.length, rows.length, countBySeverity(rows).high]);
  if (matchMedia('(max-width: 1023px)').matches)
    refs.results.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth' });
}
