import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { analyzed, fakeWorker, setWorkerMode } from './helpers';

test('サンプルを判定でき、外部へのリクエストが発生しない', async ({ page }) => {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('request', r => { const u = r.url(); if (!u.startsWith('http://localhost:4173/') && !u.startsWith('data:') && !u.startsWith('blob:')) external.push(u); });
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

  await page.goto('/');
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveAttribute('content', /connect-src 'none'/);

  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByText('指摘（項目×条件）')).toBeVisible();
  await expect(results.getByRole('cell', { name: 'C-09①' }).first()).toBeVisible();
  await expect(results.getByText('診断カバレッジ')).toBeVisible();

  // 生のCookie値・トークン・プローブの中身が画面に出ていない
  const text = await page.locator('#app').innerText();
  expect(text).not.toContain('8f3c2a91d0b74e6fa1c55d3e9b2f7a40');
  expect(text).not.toContain('eyJzdWIiOiJ0ZXN0In0');

  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});

test('例外に登録すると「例外」になり、Markdown を保存できる', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  // 判定は Web Worker で行うので、結果が出てから数える
  await expect(page.getByRole('button', { name: '例外に登録' }).first()).toBeVisible();
  const before = await page.getByRole('button', { name: '例外に登録' }).count();
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await page.getByLabel('理由（必須）').fill('検証環境のため');
  await page.getByRole('button', { name: '登録する' }).click();
  await page.getByText('設定ファイル').click();
  await expect(page.getByText(/例外 1件（有効 1件/)).toBeVisible();
  // 登録すると判定し直す（Worker）ので、表示が変わるまで待つ
  await expect.poll(() => page.getByRole('button', { name: '例外に登録' }).count()).toBeLessThan(before);

  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Markdown' }).click()]);
  expect(dl.suggestedFilename()).toMatch(/\.md$/);
});

test('コマンド生成器：ホスト名を入れると #TARGET 付きのコマンドを作り、不正な入力は拒否する', async ({ page }) => {
  await page.goto('/');
  await page.getByText('コマンドを作る（推奨コマンド C1〜C26）').click();
  await page.getByLabel('ホスト名').fill('www.example.com;id');
  await page.getByRole('button', { name: 'コマンドを作る', exact: true }).click();
  await expect(page.getByText(/ホスト名は英数字/)).toBeVisible();
  await page.getByLabel('ホスト名').fill('www.example.com');
  await page.getByRole('button', { name: 'コマンドを作る', exact: true }).click();
  await expect(page.getByLabel('生成したコマンド')).toHaveValue(/#TARGET url=https:\/\/www\.example\.com\/login label=pre-login/);
});

test('HAR を読み込み、パスワードを画面に出さずに判定する', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
  await expect(page.getByText('HARのエントリ一覧（har_chrome.har）')).toBeVisible();
  await expect(page.getByRole('combobox', { name: /POST https:\/\/www\.example\.com\/login のラベル/ })).toHaveValue('login');
  await page.getByRole('button', { name: '判定する' }).click();
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByRole('cell', { name: 'C-09①' }).first()).toBeVisible();
  await expect(results.getByText('OWASP API3:2023').first()).toBeVisible();
  expect(await page.locator('#app').innerText()).not.toContain('SuperSecretPassw0rd');
});

test('英語UIに切り替えられ、前回の結果との差分を表示する', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'JSON' }).click()]);
  const path = await dl.path();
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.getByRole('heading', { name: 'Findings (check × condition)' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Session fixation' }).first()).toBeVisible();
  await page.getByText('Settings files').click();
  await page.locator('input[type=file]').nth(3).setInputFiles(path!);
  await expect(page.getByRole('heading', { name: 'Changes since previous results' })).toBeVisible();
  await expect(page.getByText(/0 new, 0 resolved/)).toBeVisible();
});

test('ライセンスと第三者のライセンスを参照できる', async ({ page, request }) => {
  await page.goto('/');
  await expect(page.getByRole('link', { name: 'ライセンス（MIT）' })).toHaveAttribute('href', './LICENSE.txt');
  expect((await (await request.get('/LICENSE.txt')).text())).toContain('MIT License');
  expect((await (await request.get('/THIRD_PARTY_LICENSES.txt')).text())).toContain('tailwindcss');
});

test('英語UIでは推奨対応も英語で表示する', async ({ page }) => {
  await page.goto('/?lang=en');
  await page.getByRole('button', { name: 'Load sample' }).click();
  await expect(page.getByText('Issue a new session ID when login succeeds').first()).toBeVisible();
});

test('他のサイトに埋め込まれたときは、入力欄を出さない（クリックジャッキング対策）', async ({ page }) => {
  await page.setContent('<iframe src="http://localhost:4173/" width="900" height="600"></iframe>');
  const frame = page.frameLocator('iframe');
  await expect(frame.getByText('他のサイトに埋め込んだ状態では使えません')).toBeVisible();
  await expect(frame.locator('textarea')).toHaveCount(0);
});

test('画面の改善：最初の手順の案内、入力欄を隠す、「情報」の折りたたみ、ターゲットの折りたたみ', async ({ page }) => {
  await page.goto('/');
  // 未入力のときは3つの手順を示し、そこからコマンド生成器を開ける
  await expect(page.getByRole('listitem').filter({ hasText: '自分の端末でスクリプトを実行' })).toBeVisible();
  await page.getByRole('region', { name: '判定結果' }).getByRole('button', { name: 'コマンドの生成へ' }).click();
  await expect(page.getByLabel('ホスト名')).toBeFocused();

  // 判定後は生の出力を隠し、注意を表示する。「入力を表示する」で戻せる
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await expect(page.locator('#input')).toBeHidden();
  await expect(page.getByText(/貼り付けた出力（\d+行）は隠しています/)).toBeVisible();
  await page.getByRole('button', { name: '入力を表示する' }).click();
  await expect(page.locator('#input')).toBeVisible();

  // 「情報」の指摘は既定で隠し、切り替えで表示する
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByRole('cell', { name: 'T-04④' })).toHaveCount(0);
  await results.getByRole('button', { name: /「情報」の\d+件も表示/ }).click();
  await expect(results.getByRole('cell', { name: 'T-04④' }).first()).toBeVisible();

  // 情報以外の指摘がないターゲット（probes）は閉じ、指摘があるターゲット（login）は開いている
  await expect(results.locator('details', { hasText: 'login' }).filter({ hasText: 'https://www.example.com/login /' }).first()).toHaveAttribute('open', '');
  expect(await results.locator('details', { has: page.locator('summary span.font-bold', { hasText: /^probes$/ }) }).getAttribute('open')).toBeNull();
});

// ---- 不具合の再現 ----
test('HAR の Worker も含め、ページから作る Worker は外部へ通信できない（blob: Worker はページの CSP を引き継ぐ）', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveAttribute('content', /worker-src blob:/);
  // no-cors にする（CORS の失敗でも reject されるので、CSP が効いていなくても 'blocked' になり、何も確かめられない）。
  // 送られたリクエストも見る
  const sent: string[] = [];
  page.on('request', r => { if (r.url().startsWith('https://example.com/')) sent.push(r.url()); });
  const result = await page.evaluate(() => new Promise<string>(resolve => {
    const src = "fetch('https://example.com/', { mode: 'no-cors' }).then(() => postMessage('sent'), () => postMessage('blocked'))";
    const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
    w.onmessage = e => resolve(String(e.data)); w.onerror = () => resolve('error');
  }));
  expect(result).toBe('blocked');
  expect(sent).toEqual([]);
});

test('?lang= に ja・en 以外を指定しても判定できる（en-US は英語）', async ({ page }) => {
  for (const [q, button, heading] of [['en-US', 'Load sample', 'Findings (check × condition)'], ['fr', 'サンプルを入れる', '指摘（項目×条件）']]) {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`/?lang=${q}`);
    await page.getByRole('button', { name: button }).click();
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();   // 状態の欄（件数の読み上げ）にも同じ語があるので、見出しで探す
    expect(errors).toEqual([]);
  }
});

test('判定のあとに読み込んだ設定ファイルのエラーが消えない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.locator('input[type=file]').nth(1).setInputFiles({ name: 'suppressions.json', mimeType: 'application/json', buffer: Buffer.from('{not json') });
  await expect(page.getByRole('status')).toHaveText(/例外ファイルを読み込めませんでした：JSONとして読めません。/);
});

test('HAR の一覧の読み上げ名でもトークンをマスクし、HAR を外すと結果からも消える', async ({ page }) => {
  const har = JSON.parse(readFileSync('tests/fixtures/har_chrome.har', 'utf8'));
  for (const e of har.log.entries) if (e.request.url === 'https://www.example.com/mypage') e.request.url += '?access_token=SECRETTOKENVALUE1234567890abcdef';
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles({ name: 'tok.har', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(har)) });
  await expect(page.getByText('HARのエントリ一覧（tok.har）')).toBeVisible();
  expect(await page.locator('[aria-label*="SECRETTOKENVALUE"]').count()).toBe(0);
  expect(await page.locator('[aria-label*="access_token="]').count()).toBeGreaterThan(0);
  await page.getByRole('button', { name: '判定する' }).click();
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByRole('cell', { name: 'C-09①' }).first()).toBeVisible();
  await page.getByRole('button', { name: 'HARを外す' }).click();
  await expect(results.getByRole('cell', { name: 'C-09①' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'JSON' })).toHaveCount(0);
});

test('判定できなかった入力のあとに言語を切り替えても、前の結果を出さない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await expect(page.getByRole('button', { name: 'JSON' })).toBeVisible();
  await page.getByRole('button', { name: '入力を表示する' }).click();
  await page.locator('textarea').first().fill('hello world');
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(page.getByRole('status')).toHaveText(/HTTPの応答が見つかりませんでした/);
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.getByRole('button', { name: 'JSON' })).toHaveCount(0);
});

test('英語UIでは、コマンド生成器の入力エラーも英語で出す', async ({ page }) => {
  await page.goto('/?lang=en');
  await page.locator('#generator summary').click();
  await page.locator('#gen-host').fill('www.example.com;id');
  await page.getByRole('button', { name: 'Build commands', exact: true }).click();
  await expect(page.getByText(/Use only letters, digits, hyphens and dots in the host name/)).toBeVisible();
});

// Windows の curl の -v（2>&1）は受信ヘッダの行を CR CR LF で終える。画面の入力欄（textarea）は値を受け取った時点でそれを改行2つに変えるので、
// パーサに文字列を直接渡す単体テストでは確かめられない。貼り付けとファイルの読み込みの両方が入力欄を通る
test('Windows の curl の -v（CR CR LF）を入力欄に入れても、受信ヘッダを失わない', async ({ page }) => {
  await page.goto('/');
  const lines = ['#TARGET url=https://a.example/api label=cors-reflect sensitive=1', '* Connected to a.example (192.0.2.1) port 443', '> GET /api HTTP/1.1', '> Origin: https://evil.example', '>',
    '< HTTP/1.1 200 OK', '< Content-Type: application/json', '< Access-Control-Allow-Origin: https://evil.example', '< Access-Control-Allow-Credentials: true', '<'];
  const cr = String.fromCharCode(13);
  const text = lines.map(l => (l.startsWith('<') ? `${l}${cr}${cr}` : l)).join('\n') + '\n';
  // 実際のファイルの読み込みと同じく、入力欄の value に入れる（fill はキー入力の扱いが違うため使わない）
  await page.locator('#input').evaluate((el, v) => { (el as HTMLTextAreaElement).value = v; }, text);
  expect(await page.locator('#input').evaluate(el => (el as HTMLTextAreaElement).value.includes('\n\n'))).toBe(true);   // 入力欄が改行を変えたことの確認
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(page.getByRole('region', { name: '判定結果' }).getByRole('cell', { name: 'R-01①' }).first()).toBeVisible();
});

// 結果欄全体を aria-live にすると、再描画（判定・絞り込み・折りたたみ）のたびに数百行を読み上げる。件数だけを status で知らせる
test('判定の結果は件数だけを読み上げ、結果欄は aria-live にしない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByText('指摘（項目×条件）')).toBeVisible();
  await expect(results).not.toHaveAttribute('aria-live', /.*/);
  await expect(page.getByRole('status')).toHaveText(/件のターゲットを判定しました。指摘（項目×条件）\d+件（うち重要度「高」\d+件）/);
});

// URL 欄の値はパーサのあとで入るので、-L の各ホップの URL を付け直さないと、http から https に転送された応答の H-・C- が黙って抜ける
test('URL 欄で補った http の URL でも、-L で https に転送されたら HTTPS の応答として判定する', async ({ page }) => {
  await page.goto('/');
  await page.locator('#input').fill('HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.com/\n\nHTTP/2 200\ncontent-type: text/html\n\n<html></html>\n');
  await page.getByLabel('#TARGET がない入力のURL（任意）').fill('http://www.example.com/');
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(page.getByRole('region', { name: '判定結果' }).getByRole('cell', { name: 'H-01①' }).first()).toBeVisible();
});

test('読み上げる件数は画面の件数と同じで、言語を切り替えるとその言語で出し直す', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const status = page.getByRole('status');
  await expect(status).toHaveText(/指摘（項目×条件）\d+件/);
  const n = (await status.innerText()).match(/指摘（項目×条件）(\d+)件/)![1];
  await expect(page.getByRole('region', { name: '判定結果' }).getByText(new RegExp(`^${n}件`))).toBeVisible();
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.getByRole('status')).toHaveText(new RegExp(`: ${n} findings?, [0-9]+ high`));
});

test('件数以外の状態のメッセージも、言語を切り替えるとその言語で出し直す', async ({ page }) => {
  await page.goto('/?lang=ja');
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(page.getByRole('status')).toHaveText('curlの出力を貼り付けてから「判定する」を押してください。');
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.getByRole('status')).toHaveText('Paste curl output, then select Analyze.');
  await page.getByRole('button', { name: '日本語' }).click();
  await expect(page.getByRole('status')).toHaveText('curlの出力を貼り付けてから「判定する」を押してください。');
});

test('URL 欄にスキームのない URL を入れると警告する', async ({ page }) => {
  await page.goto('/');
  await page.locator('#input').fill('HTTP/2 200\ncontent-type: text/html\nset-cookie: SESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/\n\n<html></html>\n');
  await page.getByLabel('#TARGET がない入力のURL（任意）').fill('www.example.com');
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(page.getByText(/URL 欄の値を URL として読めません/)).toBeVisible();
});

test('言語を切り替えても、コマンド生成器の入力と生成したスクリプトを残す', async ({ page }) => {
  await page.goto('/');
  await page.getByText('コマンドを作る（推奨コマンド C1〜C26）').click();
  await page.getByLabel('ホスト名').fill('www.example.com');
  await page.getByRole('button', { name: 'コマンドを作る', exact: true }).click();
  await page.getByRole('button', { name: 'English' }).click();
  await expect(page.locator('#gen-host')).toHaveValue('www.example.com');
  await expect(page.locator('textarea[readonly]').first()).toHaveValue(/label=pre-login/);
});

test('章の絞り込みを変えてもフォーカスを失わず、例外の理由のエラーを読み上げる', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const sel = page.locator('select[data-focus="chapter"]');
  await sel.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('select[data-focus="chapter"]')).toBeFocused();
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await page.getByRole('button', { name: '登録する' }).click();
  await expect(page.getByRole('alert')).toHaveText(/理由/);
});

test('形式の違うファイルを例外ファイルとして読んでも、登録済みの例外を消さない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await page.getByLabel('理由（必須）').fill('検証環境のため');
  await page.getByRole('button', { name: '登録する' }).click();
  await page.locator('input[type=file]').nth(1).setInputFiles({ name: 'suppressions.json', mimeType: 'application/json', buffer: Buffer.from('{not json') });
  await page.getByText('設定ファイル').click();
  await expect(page.getByText(/例外 1件（有効 1件/)).toBeVisible();
});

test('HAR の一覧で操作してもフォーカスを失わない', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
  const sel = page.locator('select[data-focus^="har-label-"]').first();
  await expect(sel).toBeVisible();
  await sel.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('select[data-focus^="har-label-"]').first()).toBeFocused();
});

test('ホストが2つあるとき、ホスト単位の表に対象の列を出す', async ({ page }) => {
  await page.goto('/');
  await page.locator('#input').fill(['#TARGET url=https://www.example.com/ label=tls', '#TLSPROBE v=tls1 ok=1', '#TARGET url=https://api.example.com/ label=tls2', '#TLSPROBE v=tls1 ok=1', ''].join('\n'));
  await page.getByRole('button', { name: '判定する' }).click();
  const cross = page.getByRole('region', { name: 'ホスト単位・ターゲット横断の判定' });
  await expect(cross.getByRole('columnheader', { name: 'ターゲット' })).toBeVisible();
  await expect(cross.getByText('www.example.com', { exact: false }).first()).toBeVisible();
});

test('HAR のラベルを矢印で見て回っても、ほかのエントリの予約ラベルを失わない', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
  const labels = async () => page.locator('select[data-focus^="har-label-"]').evaluateAll(els => els.map(e => (e as HTMLSelectElement).value));
  await expect(page.locator('select[data-focus^="har-label-"]').first()).toBeVisible();
  const before = await labels();
  await page.locator('select[data-focus^="har-label-"]').first().focus();
  for (const k of ['ArrowDown', 'ArrowDown', 'ArrowUp', 'ArrowUp']) await page.keyboard.press(k);
  expect(await labels()).toEqual(before);
});

test('判定は Web Worker で行い、判定中に消去したら前の入力の結果を出さない', async ({ page }) => {
  await page.goto('/');
  await page.locator('#input').fill(readFileSync('src/sample.txt', 'utf8'));
  // 判定する・消去を同じタスクの中で押す（Worker の結果が届く前に消去する）
  await page.evaluate(() => {
    const b = (name: string) => [...document.querySelectorAll('button')].find(x => x.textContent === name)!;
    b('判定する').click(); b('消去').click();
  });
  // 消去しなかった場合に結果が届く時間より長く待つ（遅い環境も見込む）
  await page.waitForTimeout(3000);
  const results = page.getByRole('region', { name: '判定結果' });
  await expect(results.getByText('指摘（項目×条件）')).toHaveCount(0);
  await expect(page.locator('#input')).toHaveValue('');
});

test('例外に登録したあと、判定し直した結果の見出しにフォーカスを移す', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await page.getByLabel('理由（必須）').fill('検証環境のため');
  await page.getByRole('button', { name: '登録する' }).click();
  // 登録すると同期的に「判定しています…」になるので、件数のメッセージを待てば、Worker の結果で描き直したあと
  await analyzed(page);
  await expect(page.locator('#app h2:focus')).toHaveCount(1);
  expect(await page.evaluate(() => document.activeElement?.tagName)).toBe('H2');
});

test('判定中は結果のファイルを保存できず、判定中に入力を直すと判定を止める', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await expect(page.locator('[data-export]').first()).toBeEnabled();
  // 判定するを押した同じタスクの中で見る（Worker の結果が届く前）
  const busy = await page.evaluate(() => {
    [...document.querySelectorAll('button')].find(x => x.textContent === '判定する')!.click();
    return [...document.querySelectorAll<HTMLButtonElement>('[data-export]')].every(b => b.disabled) && document.querySelector('[aria-label="判定結果"]')?.getAttribute('aria-busy') === 'true';
  });
  expect(busy).toBe(true);
  await analyzed(page);
  await expect(page.locator('[data-export]').first()).toBeEnabled();
  // 入力を表示して直し、判定するを押した同じタスクの中で入力を変える
  await page.getByRole('button', { name: '入力を表示' }).click();
  await page.evaluate(() => {
    const input = document.querySelector<HTMLTextAreaElement>('#input')!;
    [...document.querySelectorAll('button')].find(x => x.textContent === '判定する')!.click();
    input.value += '\n'; input.dispatchEvent(new Event('input'));
  });
  await expect(page.getByRole('status')).toHaveText(/判定を止めました/);
  await page.waitForTimeout(2000);
  await expect(page.locator('#input')).toBeVisible();
  await expect(page.getByRole('status')).toHaveText(/判定を止めました/);
});

test('Web Worker を作れない・Worker がエラーになるブラウザでは、判定できないことを知らせ、結果を残さない', async ({ page }) => {
  await fakeWorker(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  const status = page.getByRole('status'); const shown = page.getByRole('region', { name: '判定結果' }).getByText('指摘（項目×条件）');
  await analyzed(page);
  await setWorkerMode(page, 'throw');                              // コンストラクタの例外
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(status).toHaveText(/判定を始められなかったか/);
  await expect(shown).toHaveCount(0);
  await setWorkerMode(page, 'error');                              // あとから来るエラー（blob: の Worker を止める設定など）
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(status).toHaveText(/判定を始められなかったか/);
  await expect(shown).toHaveCount(0);
  await expect(page.locator('[aria-label="判定結果"]')).toHaveAttribute('aria-busy', 'false');
});

test('HAR の Worker を作れない・Worker がエラーになるときは、読み込めないと知らせる', async ({ page }) => {
  await fakeWorker(page);
  await page.goto('/');
  const status = page.getByRole('status');
  for (const mode of ['throw', 'error'] as const) {
    await setWorkerMode(page, mode);
    await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
    await expect(status).toHaveText(/^HARを読み込めませんでした。ブラウザが Web Worker を使えない/);
  }
  await expect(page.getByText('HARのエントリ一覧')).toHaveCount(0);
});

test('HAR を外すと、フォーカスを「ファイルを開く」に移す', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
  await page.getByRole('button', { name: 'HARを外す' }).click();
  await expect(page.getByRole('button', { name: 'ファイルを開く' })).toBeFocused();
});

test('判定する前の HAR は、設定ファイルを読み込んでも判定しない（ホストとラベルを確かめてから判定する）', async ({ page }) => {
  await page.goto('/');
  await page.locator('input[type=file]').first().setInputFiles('tests/fixtures/har_chrome.har');
  const status = page.getByRole('status');
  await expect(status).toHaveText(/件のリクエストを読み込みました/);
  await page.locator('input[type=file]').nth(2).setInputFiles({ name: 'profile.json', mimeType: 'application/json', buffer: Buffer.from('{"name":"x"}') });
  await expect(page.getByText('組織プロファイル：x')).toBeAttached();   // 設定の欄は閉じている
  await expect(status).toHaveText(/件のリクエストを読み込みました/);
  await expect(page.getByRole('heading', { name: /指摘/ })).toHaveCount(0);
});

test('例外の登録・設定ファイルの読み込みで判定し直すときは、表示中の結果の入力を使い、入力欄の変更は「判定する」まで判定しない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  const status = page.getByRole('status');
  await expect(status).toHaveText(/^11件のターゲット/);
  // 判定のあとに入力欄を書き換える（まだ「判定する」は押さない）
  await page.getByRole('button', { name: '入力を表示する' }).click();
  const other = '#TARGET url=https://other.example/ label=top\nHTTP/2 200\ncontent-type: text/html\n\n<html></html>';
  await page.locator('#input').fill(other);
  // 例外を登録すると、表示中の結果（サンプル）の入力で判定し直し、書き換えたことを知らせる。入力欄は隠さない
  await page.getByRole('button', { name: '例外に登録' }).first().click();
  await page.getByLabel('理由（必須）').fill('検証環境のため');
  await page.getByRole('button', { name: '登録する' }).click();
  await analyzed(page);
  await expect(status).toHaveText(/^11件のターゲット.*入力欄の変更/);
  await expect(page.locator('#input')).toBeVisible();
  await expect(page.locator('#input')).toHaveValue(other);
  // 入力欄を空にしてから例外のない例外ファイルを読み込んでも、表示中の結果を消さずに判定し直す（登録した例外が外れるまで待つ）
  const suppressed = page.getByText(/例外を当てた指摘/);
  await expect(suppressed).toHaveCount(1);
  await page.locator('#input').fill('');
  await page.locator('input[type=file]').nth(1).setInputFiles({ name: 'suppressions.json', mimeType: 'application/json', buffer: Buffer.from('[]') });
  await expect(suppressed).toHaveCount(0);
  await analyzed(page);
  await expect(status).toHaveText(/^11件のターゲット.*入力欄の変更/);
  await expect(page.locator('#input')).toBeVisible();
  // 読み込みのエラーを出すときも、入力欄の変更をまだ判定していないことを残す
  await page.locator('input[type=file]').nth(1).setInputFiles({ name: 'suppressions.json', mimeType: 'application/json', buffer: Buffer.from('{not json') });
  await expect(status).toHaveText(/JSONとして読めません.*入力欄の変更/);
  // 「判定する」で、入力欄の内容を判定する
  await page.locator('#input').fill(other);
  await page.getByRole('button', { name: '判定する' }).click();
  await expect(status).toHaveText(/^1件のターゲット/);
  await expect(status).not.toHaveText(/入力欄の変更/);
});

test('「判定する」の判定中に設定ファイルを読み込むと、その判定を入力欄の判定として引き継ぎ、入力欄を直したら止める', async ({ page }) => {
  await fakeWorker(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.getByRole('button', { name: '入力を表示する' }).click();
  // 結果を返さない Worker で「判定する」を押し、その判定中に例外ファイルを読み込む（判定中の判定の入力で判定し直す）
  await setWorkerMode(page, 'hang');
  await page.getByRole('button', { name: '判定する' }).click();
  await page.locator('input[type=file]').nth(1).setInputFiles({ name: 'suppressions.json', mimeType: 'application/json', buffer: Buffer.from('[]') });
  await page.getByText('設定ファイル').click();
  await expect(page.getByText('例外の登録はありません')).toBeVisible();
  await expect(page.getByRole('status')).toHaveText('判定しています…');
  // 引き継いだ判定も入力欄の判定なので、入力欄を直したら止める（直す前の入力の結果を出して入力欄を隠さない）
  await page.locator('#input').press('End');
  await page.locator('#input').pressSequentially('x');
  await expect(page.getByRole('status')).toHaveText(/判定を止めました/);
});

test('組織プロファイルで重要度を変えた指摘の「*」の意味を、凡例と読み上げで示す', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  const legend = page.getByText('「*」は、組織プロファイルで重要度を変えた指摘です');
  await expect(legend).toHaveCount(0);
  await page.locator('input[type=file]').nth(2).setInputFiles({ name: 'profile.json', mimeType: 'application/json', buffer: Buffer.from('{"name":"t","severity":{"C-01.1":"low"}}') });
  await expect(legend).toBeVisible();
  // 元の重要度は文字で出す（title だけではキーボード・読み上げで分からない）。「*」は読み上げない
  await expect(page.getByRole('cell', { name: /^低（元：高）$/ }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: /^低（元：高）$/ }).first()).toHaveText('低*（元：高）');
});

test('入力欄で Ctrl+Enter を押して判定すると、隠した入力欄から結果の見出しにフォーカスを移す', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.getByRole('button', { name: '入力を表示する' }).click();
  await page.locator('#input').press('Control+Enter');
  await analyzed(page);
  await expect(page.locator('#input')).toBeHidden();
  expect(await page.evaluate(() => document.activeElement?.tagName)).toBe('H2');
});

test('組織プロファイルの読み込みのエラーは、ボタンの文言ではなくファイルの名前で知らせ、1件も読めなければ「一部」と書かない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.locator('input[type=file]').nth(2).setInputFiles({ name: 'profile.json', mimeType: 'application/json', buffer: Buffer.from('{not json') });
  await expect(page.getByRole('status')).toHaveText(/^組織プロファイルを読み込めませんでした：JSONとして読めません。/);
});

test('解析の警告に出す #TARGET の読めない名前も、許可リストを通す', async ({ page }) => {
  const token = 'dXNlcjpwYXNzd29yZA';
  await page.goto('/');
  await page.locator('#input').fill(`#TARGET url=https://www.example.com/ label=api Authorization: Basic ${token}==\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n`);
  await page.getByRole('button', { name: '判定する' }).click();
  await analyzed(page);
  await expect(page.getByText(/#TARGET の指定を読めませんでした/)).toBeVisible();
  expect(await page.locator('#app').innerText()).not.toContain(token);
});

test('前回の結果の読み込みのエラーは、どのファイルかを示して文を閉じる', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.locator('input[type=file]').nth(3).setInputFiles({ name: 'baseline.json', mimeType: 'application/json', buffer: Buffer.from('{not json') });
  await expect(page.getByRole('status')).toHaveText(/^前回の結果を読み込めませんでした：.+。$/);
});

test('判定を待つあいだに章の絞り込みへ移したフォーカスは、結果を描き直しても見出しに奪わない', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'サンプルを入れる' }).click();
  await analyzed(page);
  await page.getByRole('button', { name: '入力を表示する' }).click();
  // 判定する を押して、結果が届く前に章の絞り込みへフォーカスを移す
  await page.evaluate(() => {
    [...document.querySelectorAll('button')].find(b => b.textContent === '判定する')!.click();
    document.querySelector<HTMLSelectElement>('select[data-focus="chapter"]')!.focus();
  });
  await analyzed(page);
  expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.focus)).toBe('chapter');
});
