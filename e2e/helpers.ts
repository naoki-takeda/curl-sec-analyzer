// e2e/helpers.ts：E2E で共有する待ち方と、Web Worker の差し替え
import { type Page, expect } from '@playwright/test';

/** 判定は Web Worker で行うので、件数のメッセージが出る（描き直しが終わる）まで待つ */
export async function analyzed(page: Page) {
  await expect(page.getByRole('status')).toHaveText(/件のターゲットを判定しました|Analyzed \d+ target/);
}

/**
 * Worker を差し替える。window.workerMode が 'real' なら本物、'throw' ならコンストラクタの例外、'error' ならあとから error を出す。
 * 'hang' は結果を返さない（判定中の状態を確かめるため）。'hold' は本物の Worker の結果をためておき、releaseWorkers で届ける（止めた Worker の結果は
 * 届けない。読み込み中・判定中に別の操作をしたあとで、前の結果が使われないことを確かめるため）。
 * Vite の ?worker&inline の包みは、blob: で作れないと data: URL で作り直すので、'throw' はどちらの試みでも例外にする
 */
export async function fakeWorker(page: Page) {
  await page.addInitScript(() => {
    const Real = window.Worker; const w = window as unknown as { Worker: unknown; workerMode: string; held: (() => void)[]; releaseWorkers: () => void };
    w.workerMode = 'real'; w.held = [];
    w.releaseWorkers = () => { const h = w.held; w.held = []; for (const f of h) f(); };
    w.Worker = class {
      onerror: ((e: Event) => void) | null = null; onmessage: ((e: MessageEvent) => void) | null = null; onmessageerror: unknown = null;
      real?: Worker; dead = false;
      constructor(url: string | URL, o?: WorkerOptions) {
        if (w.workerMode === 'real') return new Real(url, o) as never;
        if (w.workerMode === 'throw') throw new Error('blocked');
        if (w.workerMode === 'hang') return;
        if (w.workerMode === 'hold') {
          this.real = new Real(url, o);
          this.real.onmessage = e => { w.held.push(() => { if (!this.dead) this.onmessage?.(e); }); };
          return;
        }
        setTimeout(() => this.onerror?.(new Event('error')), 50);
      }
      postMessage(m: unknown) { this.real?.postMessage(m); }
      terminate() { this.dead = true; this.real?.terminate(); }
      addEventListener() {} removeEventListener() {}
    };
  });
}
export const setWorkerMode = (page: Page, mode: 'real' | 'throw' | 'error' | 'hang' | 'hold') =>
  page.evaluate(m => { (window as unknown as { workerMode: string }).workerMode = m; }, mode);
/** 'hold' でためた Worker の結果の数と、それを届けること */
export const heldWorkers = (page: Page) => page.evaluate(() => (window as unknown as { held: unknown[] }).held.length);
export const releaseWorkers = (page: Page) => page.evaluate(() => { (window as unknown as { releaseWorkers: () => void }).releaseWorkers(); });
