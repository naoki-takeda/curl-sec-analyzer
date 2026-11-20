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
import sample from './sample.txt?raw';   // 「サンプルを入れる」の入力例（値はすべてダミー。192.0.2.0/24 は文書用のアドレス）
import { BTN, LINK, PRIMARY, button, download, el, fileInput as hidden, focusResultsIfLost, labelFor, link, reducedMotion } from './ui/dom';
import { type AnalyzeSource, type AnalyzedInput, type Message, actions, refs, state } from './ui/state';
import { render, renderEmpty } from './ui/results';
import { cancelHarLoad, harNotice, isHarLoading, keepHarView, loadHar, renderHar, setPendingSettings } from './ui/har';
import { currentMessage, joined, say } from './ui/message';
import { commandGenerator } from './ui/generator';
import { joinMessages } from './messagesEn';

const MAX_MB = 5; const MAX_BYTES = MAX_MB * 1024 * 1024;
const app = document.querySelector<HTMLDivElement>('#app')!;
refs.dialog = el('dialog', 'm-auto w-[min(32rem,92vw)] rounded-md border border-line bg-surface p-0 text-ink backdrop:bg-black/40');
Object.assign(actions, { analyze, cancelAnalysis, isAnalyzing: () => !!analyzing, renderSettings, openGenerator, loadSample });

// ?lang= は ja・en（en-US などは en）だけを受け付け、それ以外の値はブラウザの言語で決める
const qLang = new URLSearchParams(location.search).get('lang')?.toLowerCase() ?? '';
setLang(/^(ja|en)(-|$)/.test(qLang) ? qLang.slice(0, 2) as Lang : (navigator.language.toLowerCase().startsWith('ja') ? 'ja' : 'en'));
// ほかのページ（同じ組織の Pages を含む）に埋め込まれたときは、入力欄を出さない（クリックジャッキング対策。メタCSPでは frame-ancestors が効かないため。ツール設計3）
if (window.top !== window.self) {
  const T = tr().framed;
  app.replaceChildren(el('div', 'p-6', el('p', 'font-bold', T.title), el('p', 'mt-2 text-sm', T.note), el('p', 'mt-2', link(location.href, T.open))));
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
  refs.message = el('p', 'min-h-6 text-sm text-sev-medium'); refs.message.setAttribute('role', 'status');
  // 結果欄は aria-live にしない（再描画のたびに数百行を読み上げてしまう）。判定の結果は、件数だけを役割 status の欄（refs.message）で知らせる
  refs.results = el('section', 'min-w-0'); refs.results.setAttribute('aria-label', T.resultsLabel);
  refs.harBox = el('div', '');
  refs.settingsStatus = el('ul', 'mt-2 space-y-0.5 text-sm text-muted');
  refs.inputNote = el('div', 'hidden rounded-md border border-line bg-surface p-3 text-sm text-muted');
  // 入力欄が空なら隠さない（空の入力欄ではボタンを出さないが、念のため）
  refs.inputToggle = button('', LINK, () => { state.view.inputHidden = !state.view.inputHidden && /\S/.test(refs.input.value); applyInputVisibility(); if (!state.view.inputHidden) refs.input.focus(); });
  refs.genDetails = commandGenerator();

  const fileIn = hidden('.txt,.log,.har,text/plain,application/json', openFile);
  // 設定ファイル（例外・組織プロファイル）も、貼り付けと同じ大きさまでにする（大きなファイルで画面を止めない）
  const supIn = hidden('.json,application/json', async f => {
    const text = await readSettings(f, MAX_BYTES); if (text === undefined) return;
    const { list, errors } = parseSuppressions(text);
    // 1件も読めなかった（形式の違うファイル）ときは、登録済みの例外を残す（画面で登録しただけの例外を消さない）
    if (list.length || !errors.length) state.suppressions = list;
    // 手で書いたパターン（* が語に続く admin*）は、以前の形式のキーでもパターンとして照合する（engine/suppress.ts の matches）ので、登録し直しを
    // 促さない。画面で登録したキーの * は区切りのあいだの部分だけ（/f/*/x）で、形の変わったキーはパターンとしても合わないので知らせる
    const legacy = list.filter(s => !/[\w%]\*|\*[\w%]/.test(s.target) && legacyHarKey(s.target)).length;
    // 1件も読めなかったときは「一部」と書かない。登録済みの例外を残したことも知らせる（組織プロファイルの profileKept と同じ）
    refresh(() => { const t = tr(); const e = joinMessages(errors);
      return errors.length ? (list.length ? t.readErrors(t.suppressionsName, e) : t.readFailed(t.suppressionsName, e) + (state.suppressions.length ? t.suppressionsKept : '')) : legacy ? t.legacyHarKeys(legacy) : ''; });
  });
  const profIn = hidden('.json,application/json', async f => {
    const text = await readSettings(f, MAX_BYTES); if (text === undefined) return;
    const { profile: p, errors, recognized } = parseProfile(text);
    // 読めない・形式の違うファイル（組織プロファイルの項目がなく、エラーがある）は使わない（名前のない既定の設定のプロファイルにしない）。
    // 読み込み済みのプロファイルは残す（例外ファイルと同じ）
    const loaded = p && (recognized || !errors.length) ? p : undefined;
    if (loaded) state.profile = loaded;
    // 読み込み済みのHARのラベル候補も、プロファイルのセッションCookieの名前で作り直す（画面で選び直したラベルは残す）
    if (loaded && state.har) { const chains = state.har.imp.chains; withProfile(loaded, () => suggestLabels(chains, true)); renderHar(); }
    // 残したときは、そのことを知らせる（「既定の24時間を使います」などのエラーの文言だけでは、古いプロファイルを使い続けることが分からない）
    const kept = !loaded && !!state.profile;
    refresh(() => { const t = tr(); const e = joinMessages(errors);
      return errors.length ? (loaded ? t.readErrors(t.profileName, e) : t.readFailed(t.profileName, e)) + (kept ? t.profileKept : '') : ''; });
  });
  const baseIn = hidden('.json,application/json', async f => {
    // 前回の結果は HAR と同じ上限（大きな HAR を判定した結果の JSON は 5MB を超えるので、貼り付けと同じ上限では自分のエクスポートを読めない）
    const text = await readSettings(f, HAR_MAX_BYTES); if (text === undefined) return;
    const { baseline: b, error, skipped } = parseBaseline(text);
    // 指摘がどれも形式の違うファイルは使わない（0件の前回の結果にすると、差分がすべて「新規」になる）。読み込み済みの前回の結果は残す
    const loaded = b && (b.findings.length || !skipped) ? b : undefined;
    if (loaded) state.baseline = loaded;
    const kept = !loaded && !!state.baseline;
    const legacy = loaded ? loaded.findings.filter(x => legacyHarKey(x.targetKey)).length : 0;
    refresh(() => { const t = tr();
      return (error ? t.baselineError(joinMessages([error])) : !loaded ? t.baselineInvalid(skipped) : skipped ? t.baselineSkipped(skipped) : legacy ? t.legacyHarKeys(legacy) : '')
        + (kept ? t.baselineKept : ''); });
  });

  app.replaceChildren(
    el('div', 'mx-auto max-w-[1400px] px-4 py-6 lg:px-8',
      el('header', 'mb-6 border-b border-line pb-4',
        el('div', 'flex flex-wrap items-baseline gap-x-4',
          el('h1', 'text-2xl font-bold tracking-tight', 'curl-sec-analyzer'),
          el('span', 'num text-sm text-muted', T.versions(TOOL_VERSION, RULESET_VERSION)),
          // ボタンの文言（English・日本語）は切り替え先の言語なので lang を付ける（WCAG 3.1.2）。作り直したあとはボタンにフォーカスを戻す（WCAG 2.4.3）
          Object.assign(button(T.langSwitch, `${LINK} ml-auto`, () => {
            // 作り直す前に、入力・メッセージ・HAR の一覧と設定の欄の開閉を覚え、作り直したあとに戻す
            keepDraft(); keepHarView(); const m = currentMessage(); const settingsOpen = document.querySelector<HTMLDetailsElement>('#settings-box')?.open;
            setLang(getLang() === 'ja' ? 'en' : 'ja'); buildShell(); setBusy(!!analyzing); if (m) say(m);
            const sb = document.querySelector<HTMLDetailsElement>('#settings-box'); if (sb && settingsOpen) sb.open = true;
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
            button(T.analyze, PRIMARY, () => analyze()),
            Object.assign(button(T.openFile, BTN, () => fileIn.click()), { id: 'open-file' }),
            button(T.sample, BTN, loadSample),
            button(T.clear, 'rounded-md px-3 py-2 text-muted underline-offset-4 hover:underline', clearAll),
            // 隠したファイルの入力には id を付ける（E2E が並びの順番ではなく id で選ぶ）
            Object.assign(fileIn, { id: 'file-in' }), Object.assign(supIn, { id: 'sup-in' }), Object.assign(profIn, { id: 'prof-in' }), Object.assign(baseIn, { id: 'base-in' })),
          refs.message,
          refs.genDetails,
          refs.harBox,
          Object.assign(el('details', 'mt-4 rounded-md border border-line bg-surface p-4',
            el('summary', 'cursor-pointer font-bold', T.settings),
            el('div', 'mt-3 flex flex-wrap gap-2',
              button(T.loadSuppressions, BTN, () => supIn.click()),
              button(T.loadProfile, BTN, () => profIn.click()),
              button(T.loadBaseline, BTN, () => baseIn.click()),
              button(T.profileTemplate, LINK, () => download('profile.json', 'application/json', profileTemplate()))),
            refs.settingsStatus), { id: 'settings-box' }),
          el('p', 'mt-3 text-sm text-muted', T.maskNote)),
        refs.results)),
    refs.dialog);
  renderSettings(); renderHar(); applyInputVisibility();
  if (state.last) render(); else renderEmpty();
}
/** 設定ファイルを読む。上限を超えたら、そのファイルの上限を知らせて undefined を返す */
async function readSettings(f: File, limit: number): Promise<string | undefined> {
  if (f.size > limit) { say(() => tr().settingsTooLarge(limit / 1024 / 1024)); return undefined; }
  return readText(f);
}
/** ファイルを読む。読めない（選んだあとに書き換わった・消えた）ときは知らせて undefined を返す */
async function readText(f: Blob): Promise<string | undefined> {
  try { return await f.text(); } catch { say(() => tr().fileUnreadable); return undefined; }
}
/** 入力（URL 欄を含む）・HAR・結果を消す（設定ファイルは残す。URL 欄を残すと、次に貼った別のサイトの出力を前の URL で判定する） */
function clearAll() {
  openGen++; refs.input.value = ''; refs.urlInput.value = ''; cancelAnalysis(); cancelHarLoad(); state.har = null; renderHar(); say();
  state.last = null; state.view.inputHidden = false; applyInputVisibility(); renderEmpty(); refs.input.focus();
}
function keepDraft() { state.draft = { input: refs.input.value, url: refs.urlInput.value }; }
/**
 * 設定を読み込んだあとに判定し直す。読み込みのエラーは判定のあとに表示する（analyze は最初に表示を消すため、先に出すと消えてしまう）。
 * 判定の結果を表示できなかった（失敗・中止・置き換わった）ときは、判定のメッセージを消さずに読み込みのエラーを後ろに足す
 */
async function refresh(msg: Message) {
  renderSettings();
  // HAR の読み込み中は、読み込みの案内・判定し直しのあとにも出せるよう、この知らせを HAR の読み込みに預ける（新しい設定ファイルで置き換える）
  if (isHarLoading()) setPendingSettings(msg() ? msg : undefined);
  // 判定する前の HAR は判定しない（ホストとラベルを確かめてから「判定する」を押す）。読み込みのエラーがなければ HAR の案内（読み込み中・読み込み済み）
  // を出し直す（前の設定ファイルのエラーを残さない）
  if (!(state.last || analyzing)) { say(msg() ? msg : harNotice()); return; }
  const shown = await analyze('result');
  if (!msg()) return;
  const prev = currentMessage();
  // 表示できたら読み込みのメッセージに置き換える。書き換えた入力欄をまだ判定していないことは残す
  const note = shown && formNotAnalyzed;
  say(shown || !prev ? (note ? () => msg() + tr().formNotAnalyzed : msg) : joined(prev, msg));
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
  const T = tr(); const has = /\S/.test(refs.input.value);
  const hide = state.view.inputHidden && has;
  refs.input.classList.toggle('hidden', hide);
  refs.inputNote.classList.toggle('hidden', !hide);
  refs.inputNote.textContent = hide ? T.inputHidden(refs.input.value.replace(/\n$/, '').split('\n').length) : '';   // 末尾の改行は行に数えない
  refs.inputToggle.classList.toggle('hidden', !has);
  refs.inputToggle.textContent = hide ? T.showInput : T.hideInput;
}
function loadSample() {
  // 読み込んだ（読み込み中の）HAR は外す（利用者の HAR とダミーのサンプルを1つの結果にしない）。貼り付けた内容も置き換えるなら、両方を確かめる
  const har = !!state.har || isHarLoading(); const typed = !!refs.input.value.trim() && refs.input.value !== sample;
  if ((har || typed) && !confirm(har ? (typed ? tr().confirmDropHarAndInput : tr().confirmDropHar) : tr().confirmReplace)) return;
  openGen++; cancelHarLoad();   // 読み込み中のテキストファイル・HAR を、あとからサンプルに混ぜない
  if (state.har) { state.har = null; renderHar(); }
  refs.input.value = sample; state.view.inputHidden = false; applyInputVisibility(); analyze();
}
function openGenerator() {
  refs.genDetails.open = true;
  refs.genDetails.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  refs.genDetails.querySelector<HTMLInputElement>('input')?.focus({ preventScroll: true });
}
// 開いたファイルの世代。読み込みを待つあいだに消去・別のファイルを開いたら、前のファイルの中身を入力欄に入れない
let openGen = 0;
async function openFile(f: File) {
  const gen = ++openGen;
  const head = /\.har$/i.test(f.name) ? '' : await readText(f.slice(0, 400));
  if (head === undefined || gen !== openGen) return;
  if (/\.har$/i.test(f.name) || isHar(head)) { loadHar(f); return; }
  if (f.size > MAX_BYTES) { say(() => tr().fileTooLarge(MAX_MB)); return; }
  const text = await readText(f); if (text === undefined || gen !== openGen) return;
  // 新しい入力は、判定できるまで隠さない（貼り付けたときと同じ。隠したままだと、前の入力の行数の説明が残る）
  refs.input.value = text; state.view.inputHidden = false; applyInputVisibility(); analyze();
}
// 判定の世代と、判定中の Worker・その Promise の解決。判定し直したり、消去・HAR を外すを押したりしたら、前の Worker を止め、前の結果は
// 使わない（古い結果で新しい入力の表示を上書きしない）。止めた判定の Promise も解決する（待っている呼び出し側を止めたままにしない）
let analyzeGen = 0; let analyzing: { worker: Worker; settle: (shown: boolean) => void; text: string; url: string; source: AnalyzeSource } | undefined;
// 最後に表示した結果が、表示中の結果の入力で判定し直したもので、入力欄がその入力と違ったか（入力欄の変更をまだ判定していない）
let formNotAnalyzed = false;
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
/**
 * 判定中に入力・URL 欄を直したら、その判定を止める（結果が届いたときに、直す前の入力の結果を出して入力欄を隠さない）。
 * 表示中の結果の入力で判定し直しているときは止めない（入力欄を判定しているのではなく、入力欄も隠さない）
 */
function inputChanged() {
  applyInputVisibility();   // 入力欄を空にしたら「入力を隠す」を消す
  if (!analyzing || analyzing.source === 'result' || (refs.input.value === analyzing.text && refs.urlInput.value === analyzing.url)) return;
  cancelAnalysis(); say(() => tr().analysisCancelled);
}
/**
 * 入力を判定して表示する。判定は Web Worker で行う（数万件のターゲットの HAR などで画面を止めない。blob: URL で作る理由は csp.config.ts）。
 * 表示まで終わったら解決する（判定のあとに出すメッセージのため）。解決する値は、この判定の結果を表示したか（止められた・置き換わった・
 * 判定できなかった・応答がなかったときは false。描き直した結果にフォーカスを移すため）。
 * source が result なら、表示中の結果（判定中ならその判定）の入力を判定し直す（ui/state.ts の AnalyzeSource）。結果も判定中のものもなければ入力欄
 */
function analyze(source: AnalyzeSource = 'form'): Promise<boolean> {
  say();
  const base: AnalyzedInput | undefined = source === 'result' ? (analyzing ?? state.last?.input) : undefined;
  const input: AnalyzedInput = base ? { text: base.text, url: base.url } : { text: refs.input.value, url: refs.urlInput.value };
  // 判定中の判定を引き継ぐときは、その判定の種類も引き継ぐ（「判定する」の判定中に設定を読み込んでも、入力欄の判定として生の出力を隠し、
  // 判定中に入力欄を直したら止める）
  const fromResult = source === 'result' && (analyzing ? analyzing.source === 'result' : !!state.last);
  const { text } = input;
  const fail = (m: () => string) => { cancelAnalysis(); say(m); state.last = null; renderEmpty(); };
  // 入力欄が空で HAR を読み込んでいる途中なら、入力がないとは言わずに読み込み中と知らせる（結果は消さない）
  if (!text.trim() && !state.har && isHarLoading()) { say(() => tr().har.loading); return Promise.resolve(false); }
  if (!text.trim() && !state.har) { fail(() => tr().emptyInput); return Promise.resolve(false); }
  // 判定できなかったときは前の結果を消す（残すと、言語の切り替えなどで別の入力の結果が表示・出力される）
  if (new Blob([text]).size > MAX_BYTES) { fail(() => tr().tooLarge(MAX_MB)); return Promise.resolve(false); }
  const req: AnalyzeRequest = { text, url: input.url, har: state.har ? { imp: state.har.imp, hosts: state.har.hosts } : undefined,
    suppressions: state.suppressions, profile: state.profile };
  const settings = { suppressions: state.suppressions, profile: state.profile, baseline: state.baseline };
  cancelAnalysis();
  // Worker を作れない・送れない・結果を受け取れない（ブラウザの設定、メモリ不足、ツールの不具合）ときは、入力の形式の問題（判定の途中の例外。
  // Worker が {ok:false} で返す）とは分けて知らせる。作れないときは、Vite の包みが data: URL で作り直し、それを CSP が止めると onerror になる
  let w: Worker;
  try { w = new AnalyzeWorker(); } catch { fail(() => tr().workerFailed); return Promise.resolve(false); }
  const gen = analyzeGen;
  say(() => tr().analyzing); setBusy(true);
  return new Promise<boolean>(resolve => {
    analyzing = { worker: w, settle: resolve, text, url: input.url, source: fromResult ? 'result' : 'form' };
    const done = () => { w.terminate(); if (analyzing?.worker === w) { analyzing = undefined; setBusy(false); } };
    const broken = () => { done(); if (gen === analyzeGen) fail(() => tr().workerFailed); resolve(false); };
    w.onmessage = (e: MessageEvent<{ ok: boolean; result?: AnalyzeResult }>) => {
      done();
      if (gen !== analyzeGen) { resolve(false); return; }   // 古い判定の結果
      // 判定の途中の例外（想定外の入力）で、前の入力の結果を表示・出力したままにしない
      let shown = false;
      if (!e.data.ok || !e.data.result) fail(() => tr().analysisFailed);
      else { try { shown = show(e.data.result, input, settings, fromResult); } catch { fail(() => tr().analysisFailed); } }
      resolve(shown);                                   // 表示まで終わってから解決する
    };
    w.onerror = w.onmessageerror = broken;
    try { w.postMessage(req); } catch { broken(); }
  });
}
/**
 * 判定の結果を表示する。応答が1つもなければ結果を消して false を返す。fromResult は、表示中の結果の入力で判定し直したか
 */
function show({ targets, warnings, findings, cov }: AnalyzeResult, input: AnalyzedInput, settings: NonNullable<typeof state.last>['settings'], fromResult: boolean): boolean {
  // HAR だけで判定して、対象ホスト・除外ですべてのエントリを外したときは、curl のオプションではなく HAR の選択を案内する
  const harOnly = !!state.har && !input.text.trim();
  if (!targets.length) { say(() => harOnly ? tr().harNoEntries : tr().noResponse); state.last = null; renderEmpty(); return false; }
  state.last = { targets, warnings, findings, cov, settings, input, diff: settings.baseline ? diff(settings.baseline.findings, findings) : undefined };
  // 表示中の結果の入力で判定し直したとき、判定のあとに書き換えた入力欄は、まだ判定していない
  formNotAnalyzed = fromResult && (refs.input.value !== input.text || refs.urlInput.value !== input.url);
  // 判定できたら、生の出力を隠す。書き換えた入力欄は隠さない（書き換えている途中の入力欄を隠さない）
  if (input.text.trim() && !formNotAnalyzed) state.view.inputHidden = true;
  const focused = document.activeElement;
  applyInputVisibility();
  render(); focusResultsIfLost(refs.results, focused);
  // 件数は画面の集計（項目×条件で一意に数える。ui/results.ts と同じ）に合わせる。ターゲットごとの指摘を数えると、画面と違う数を読み上げる
  const rows = overall(findings); const high = countBySeverity(rows).high;
  const note = formNotAnalyzed;
  say(() => tr().analyzed(targets.length, rows.length, high) + (note ? tr().formNotAnalyzed : ''));
  // 1列の画面では結果欄までスクロールする。設定ファイル・例外の登録での判定し直しでは、読み込みの知らせ（入力欄の下）を画面の外に出さない
  if (!fromResult && matchMedia('(max-width: 1023px)').matches)
    refs.results.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth' });
  return true;
}
