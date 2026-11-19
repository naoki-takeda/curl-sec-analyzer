// analyzeWorker.ts：判定（engine/analyze.ts）を Web Worker で行う（数万件のターゲットの HAR などで画面を止めない）
import { type AnalyzeRequest, analyzeInput } from './engine/analyze';

self.onmessage = (e: MessageEvent<AnalyzeRequest>) => {
  try { (self as unknown as Worker).postMessage({ ok: true, result: analyzeInput(e.data) }); }
  // エラーの文言（err.message）は返さない。入力の一部（Cookie・パスワードなど）を含みうるため。画面は決まった文言で知らせる
  catch { (self as unknown as Worker).postMessage({ ok: false }); }
};
