import { defineConfig, devices } from '@playwright/test';

// 本番ビルド（メタCSPあり）に対して実行する。先に npm run build を済ませておく
export default defineConfig({
  testDir: 'e2e',
  use: { baseURL: 'http://localhost:4173/', locale: 'ja-JP' },
  webServer: { command: 'npx vite preview --port 4173 --strictPort', url: 'http://localhost:4173/', reuseExistingServer: !process.env.CI },
  // CI では Chromium・Firefox・WebKit（Safari）のすべてで実行する（npx playwright install --with-deps）。
  // PW_CHROMIUM：インストール済みの Chromium だけで実行する場合に、その実行ファイルのパスを指定する
  projects: process.env.PW_CHROMIUM
    ? [{ name: 'chromium', use: { ...devices['Desktop Chrome'], launchOptions: { executablePath: process.env.PW_CHROMIUM } } }]
    : [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
        { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
        { name: 'webkit', use: { ...devices['Desktop Safari'] } },
      ],
});
