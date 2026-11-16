// worker.ts：HARの読み込みを Web Worker で行う（大きなファイルで画面を止めない。postData は読まずに捨てる）
import { importHar } from './parser/har';

self.onmessage = (e: MessageEvent<string>) => {
  try { (self as unknown as Worker).postMessage({ ok: true, result: importHar(e.data) }); }
  catch (err) { (self as unknown as Worker).postMessage({ ok: false, error: err instanceof Error ? err.message : String(err) }); }
};
