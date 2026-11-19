// scripts/screenshot.mjs：README の画像（docs/screenshot.png）と共有用の画像（public/og.png）を撮り直す。リリースのたびに実行する
//   npm run screenshot   （先に本番ビルドを行い、vite preview で開いたページを撮る）
// インストール済みの Chromium を使う場合は PW_CHROMIUM にパスを指定する（通常は npx playwright install chromium）
import { preview } from 'vite';
import { chromium } from '@playwright/test';

const server = await preview({ preview: { port: 4179, strictPort: true }, logLevel: 'warn' });
const browser = await chromium.launch(process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {});
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 }, locale: 'ja-JP', colorScheme: 'light' });
  await page.goto('http://localhost:4179/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  // 見出しで待つ（状態の欄の件数の文にも「指摘（項目×条件）」が入り、getByText では2か所に当たるため）
  await page.getByRole('heading', { name: '指摘（項目×条件）' }).waitFor();
  await page.screenshot({ path: 'docs/screenshot.png' });
  await page.screenshot({ path: 'public/og.png' });      // 共有用の画像（OGP）。ビルドで dist/og.png になる
  console.log('docs/screenshot.png と public/og.png を更新しました');
} finally {
  await browser.close();
  await new Promise(r => server.httpServer.close(r));
}
