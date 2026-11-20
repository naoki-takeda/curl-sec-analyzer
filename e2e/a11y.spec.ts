// アクセシビリティの自動検査（axe-core）。ベストプラクティスを含む全ルールで、軽微（minor）より重い違反がないことを確かめる
import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { analyzed } from './helpers';

async function check(page: Page, name: string) {
  const r = await new AxeBuilder({ page }).analyze();
  const bad = r.violations.filter(v => v.impact !== 'minor')
    .map(v => `${name}: ${v.id}（${v.impact}）${v.help} → ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`);
  expect(bad).toEqual([]);
}

test('未入力・判定後・例外のダイアログ・コマンド生成器', async ({ page }) => {
  await page.goto('/');
  await check(page, '未入力');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await check(page, '判定後');
  await page.getByRole('region', { name: '判定結果' }).getByRole('button', { name: /「情報」の\d+件も表示/ }).click();
  await check(page, '「情報」を表示');
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await check(page, '例外のダイアログ');
  await page.getByRole('button', { name: 'やめる' }).click();
  await page.getByText('コマンドを作る（推奨コマンド C1〜C26）').click();
  await check(page, 'コマンド生成器');
});

test('英語UIとHARのエントリ一覧', async ({ page }) => {
  await page.goto('/?lang=en');
  await page.getByRole('button', { name: 'Load sample' }).click();
  await analyzed(page);
  await check(page, '英語UI');
  await page.goto('/');
  await page.locator('#file-in').setInputFiles('tests/fixtures/har_chrome.har');
  await expect(page.getByText('HARのエントリ一覧（har_chrome.har）')).toBeVisible();
  await check(page, 'HARのエントリ一覧');
});

test('ダークモード', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await check(page, 'ダークモード');
});

test.describe('スマートフォンの画面幅（390px）', () => {
  test.skip(({ browserName }) => browserName === 'firefox', 'Firefox は isMobile のエミュレーションに対応していない');
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  test('判定後もページが横にはみ出さず、横スクロールする表をキーボードで操作できる', async ({ page }) => {
    const pageWidth = () => page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    await page.goto('/');
    await page.getByRole('button', { name: 'サンプルを入れる' }).click();
    await analyzed(page);
    let [sw, cw] = await pageWidth();
    expect(sw).toBeLessThanOrEqual(cw);
    await check(page, 'スマートフォン：判定後');
    await page.getByRole('button', { name: /合格・判定不能/ }).click();
    [sw, cw] = await pageWidth();
    expect(sw).toBeLessThanOrEqual(cw);
    await check(page, 'スマートフォン：すべて表示');
    // 横にはみ出している表の枠にはフォーカスでき、名前が付いている
    await expect(page.getByRole('region', { name: 'ターゲット「top」の判定' })).toHaveAttribute('tabindex', '0');
  });
});

test('パソコンの画面幅では、はみ出していない表の枠に Tab で止まらない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await expect(page.getByRole('region', { name: '指摘の一覧' })).not.toHaveAttribute('tabindex', /.*/);
});
