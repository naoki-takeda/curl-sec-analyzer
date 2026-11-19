// ui/state.ts：画面の状態（どれもブラウザには保存しない）と、画面の部品への参照、モジュールをまたぐ操作
import type { Coverage, Finding, ParseWarning, Profile, Suppression, Target } from '../model';
import type { HarImport } from '../parser/har';
import type { Baseline, DiffRow } from '../engine/diff';

export const state = {
  suppressions: [] as Suppression[],
  profile: undefined as Profile | undefined,
  baseline: undefined as Baseline | undefined,
  har: null as { imp: HarImport; hosts: Set<string>; name: string } | null,
  // settings：その結果を判定したときの例外・組織プロファイル・前回の結果（判定のあとに読み込んだ設定と、古い結果を混ぜて出力しない）
  last: null as { targets: Target[]; warnings: ParseWarning[]; findings: Finding[]; cov: Coverage[]; diff?: DiffRow[];
    settings: { suppressions: Suppression[]; profile?: Profile; baseline?: Baseline } } | null,
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
  analyze: (): Promise<boolean> => Promise.resolve(false), cancelAnalysis: () => {}, isAnalyzing: (): boolean => false, say: (_m?: Message) => {}, renderSettings: () => {}, openGenerator: () => {}, loadSample: () => {},
};
