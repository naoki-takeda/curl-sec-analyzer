// e2e/helpers.ts：E2E で共有する待ち方と、Web Worker の差し替え
import { type Page, expect } from '@playwright/test';

/** 判定は Web Worker で行うので、件数のメッセージが出る（描き直しが終わる）まで待つ */
export async function analyzed(page: Page) {
  await expect(page.getByRole('status')).toHaveText(/件のターゲットを判定しました|Analyzed \d+ target/);
}

/**
 * Worker を差し替える。window.workerMode が 'real' なら本物、'throw' ならコンストラクタの例外、'error' ならあとから error を出す。
 * 'hang' は結果を返さない（判定中の状態を確かめるため）。
 * Vite の ?worker&inline の包みは、blob: で作れないと data: URL で作り直すので、'throw' はどちらの試みでも例外にする
 */
export async function fakeWorker(page: Page) {
  await page.addInitScript(() => {
    const Real = window.Worker; const w = window as unknown as { Worker: unknown; workerMode: string };
    w.workerMode = 'real';
    w.Worker = class {
      onerror: ((e: Event) => void) | null = null; onmessage: unknown = null; onmessageerror: unknown = null;
      constructor(url: string | URL, o?: WorkerOptions) {
        if (w.workerMode === 'real') return new Real(url, o) as never;
        if (w.workerMode === 'throw') throw new Error('blocked');
        if (w.workerMode === 'hang') return;
        setTimeout(() => this.onerror?.(new Event('error')), 50);
      }
      postMessage() {} terminate() {} addEventListener() {} removeEventListener() {}
    };
  });
}
export const setWorkerMode = (page: Page, mode: 'real' | 'throw' | 'error' | 'hang') =>
  page.evaluate(m => { (window as unknown as { workerMode: string }).workerMode = m; }, mode);
