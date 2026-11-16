// worker.ts：HARの読み込みを Web Worker で行う（大きなファイルで画面を止めない。postData は読まずに捨てる）
import { importHar } from './parser/har';

self.onmessage = (e: MessageEvent<string>) => {
  try { (self as unknown as Worker).postMessage({ ok: true, result: importHar(e.data) }); }
  // エラーの文言（err.message）は返さない。JSON.parse のメッセージには、誤りの前後の入力（Cookie・パスワードなど）が入るため。
  // 返すのは入力を含まない種類だけ（JSON の誤り、またはエラーの種類名）
  catch (err) { (self as unknown as Worker).postMessage({ ok: false, error: err instanceof SyntaxError ? 'JSON' : err instanceof Error ? err.name : 'error' }); }
};
