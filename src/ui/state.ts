// ui/state.ts：画面の状態（どれもブラウザには保存しない）と、画面の部品への参照、モジュールをまたぐ操作
import type { Coverage, Finding, ParseWarning, Profile, Suppression, Target } from '../model';
import type { HarImport } from '../parser/har';
import type { Baseline, DiffRow } from '../engine/diff';

/** 判定した入力欄・URL 欄の値 */
export interface AnalyzedInput { text: string; url: string; }
/**
 * 判定する入力。form は入力欄（「判定する」・ファイル・サンプル・HAR の入れ替え）。result は表示中の結果（判定中ならその判定）の入力で、
 * 例外・組織プロファイル・前回の結果を変えて判定し直すときに使う（設定だけを変えたのに、判定のあとに書き換えた入力欄の結果に入れ替えない）
 */
export type AnalyzeSource = 'form' | 'result';

export const state = {
  suppressions: [] as Suppression[],
  profile: undefined as Profile | undefined,
  baseline: undefined as Baseline | undefined,
  har: null as { imp: HarImport; hosts: Set<string>; name: string } | null,
  // settings：その結果を判定したときの例外・組織プロファイル・前回の結果（判定のあとに読み込んだ設定と、古い結果を混ぜて出力しない）
  // input：その結果を判定したときの入力欄・URL 欄の値（設定を変えて判定し直すときは、判定のあとに書き換えた入力欄ではなく、これを使う）
  last: null as { targets: Target[]; warnings: ParseWarning[]; findings: Finding[]; cov: Coverage[]; diff?: DiffRow[];
    settings: { suppressions: Suppression[]; profile?: Profile; baseline?: Baseline }; input: AnalyzedInput } | null,
  view: { showAll: false, showInfo: false, inputHidden: false, chapter: 0, covFilter: 'missing-input' },
  draft: { input: '', url: '' },
};

/** main.ts が作る画面の部品（dialog 以外は buildShell で作り直す） */
export const refs = {} as {
  input: HTMLTextAreaElement; inputNote: HTMLDivElement; inputToggle: HTMLButtonElement; genDetails: HTMLDetailsElement;
  urlInput: HTMLInputElement; message: HTMLParagraphElement; results: HTMLElement; harBox: HTMLDivElement;
  settingsStatus: HTMLUListElement; dialog: HTMLDialogElement;
};

/** 状態のメッセージ。文言を作る関数で持ち、言語を切り替えたらその言語で出し直す */
export type Message = () => string;

/** 循環する依存を避けるため、main.ts が登録する操作 */
export const actions = {
  analyze: (_source?: AnalyzeSource): Promise<boolean> => Promise.resolve(false), cancelAnalysis: () => {}, isAnalyzing: (): boolean => false, renderSettings: () => {}, openGenerator: () => {}, loadSample: () => {},
};
