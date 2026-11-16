// ゴールデンテスト（入力と期待結果の組）：コーパスの入力を画面と同じ流れで判定し、結果の全体（指摘・証跡・解析警告・突き合わせのキー・
// カバレッジ）を tests/golden/expected/ のファイルと比べる。判定を変えると、変わった行がテストの失敗として出る。
//
// - 意図した変更なら `npx vitest run tests/golden.test.ts -u` で期待結果を書き直し、その差分をレビューする（CONTRIBUTING.md）。
//   意図しない行が変わっていたら退行。今までの「修正の前後で同じ入力を比べる」レビューを、毎回機械的に行うためのもの
// - 期待結果は「正しい結果」ではなく「今の結果」。誤りと分かっている行は、直したときに書き直す
// - 時刻は固定する（Cookie・証明書の期限を、採取時刻のない入力では判定した時刻で比べるため）
import { readFileSync, readdirSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { toCsv } from '../src/export/csv';
import { toJson } from '../src/export/json';
import { toMarkdown } from '../src/export/markdown';
import { analyze, render } from './golden/analyze';

const NOW = new Date('2026-11-01T12:00:00Z');
const casesDir = new URL('./golden/cases/', import.meta.url);
const read = (u: URL) => readFileSync(u, 'utf8');

/** コーパス：golden/cases の入力と、ほかのテストや画面のサンプルで使っている実際に近い入力 */
const CASES: { name: string; url: URL }[] = [
  ...readdirSync(casesDir).sort().map(f => ({ name: f, url: new URL(f, casesDir) })),
  { name: 'sample.txt', url: new URL('../src/sample.txt', import.meta.url) },
  ...['generated_local.txt', 'multi_setcookie.txt', 'body_hash_comments.txt', 'openssl_tls13.txt', 'har_chrome.har', 'har_sanitized.har']
    .map(f => ({ name: `fixtures-${f}`, url: new URL(`./fixtures/${f}`, import.meta.url) })),
];
const run = (c: { name: string; url: URL }) => (/\.har$/.test(c.name) ? analyze('', read(c.url)) : analyze(read(c.url)));

/**
 * 画面・エクスポートに出てはいけない値。コーパスの秘密の値には「CANARY」を入れてある（maskValue が残す先頭の4文字より後ろ）。
 * CANARY を Base64 にしたもの（JWT の署名の部分）も見る
 */
const SECRETS = [/CANARY/, /Q0FOQVJZ/, /c2lnQ0FO/];

beforeAll(() => { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(NOW); });
afterAll(() => { vi.useRealTimers(); });

describe('ゴールデン：判定の結果が期待結果と同じ', () => {
  for (const c of CASES) it(c.name, async () => {
    await expect(render(run(c))).toMatchFileSnapshot(`./golden/expected/${c.name}.out`);
  });
});

describe('ゴールデン：秘密の値が画面・エクスポートに出ない', () => {
  for (const c of CASES) it(c.name, () => {
    const a = run(c);
    const shown = [render(a), JSON.stringify(a.findings), toMarkdown(a.findings, a.cov, [], NOW), toCsv(a.findings, a.targets), toJson(a.findings, a.cov, [], NOW)].join('\n');
    for (const re of SECRETS) expect(shown.match(re)?.[0], `${re}`).toBeUndefined();
  });
});

it('期待結果のファイルは、コーパスの入力と1対1（入力がないまま残った期待結果を、黙って通さない）', () => {
  const expected = readdirSync(new URL('./golden/expected/', import.meta.url)).filter(f => f.endsWith('.out')).sort();
  expect(expected).toEqual(CASES.map(c => `${c.name}.out`).sort());
});

it('コーパスの各ファイルに、少なくとも1つのターゲットがある（読み込めないファイルを黙って比べない）', () => {
  for (const c of CASES) expect(run(c).targets.length, c.name).toBeGreaterThan(0);
});
