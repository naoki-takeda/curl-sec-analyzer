import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';
import license from 'rollup-plugin-license';
import { readFileSync } from 'node:fs';
// Vite の設定の読み込みに対応するため、ローカルの TypeScript には拡張子を付ける
import { CSP } from './csp.config.ts';

// 本番ビルドのときだけメタCSPを挿入する。指定の中身と、開発サーバに付けない理由は csp.config.ts にある
const metaCsp = (): Plugin => ({
  name: 'meta-csp',
  apply: 'build',
  transformIndexHtml: () => [
    { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP }, injectTo: 'head-prepend' },
    { tag: 'meta', attrs: { name: 'referrer', content: 'no-referrer' }, injectTo: 'head-prepend' },
  ],
});

// 共有用の画像の説明（読み上げを使う人に、画像の内容を伝える）
const OG_ALT = 'サンプルを判定した画面。重要度別の件数と、項目×条件ごとの指摘の一覧';

// 共有用の画像の絶対URL（OGP は絶対URLが必要）。CI で公開先のURL（SITE_URL）が分かるときだけ入れる
const ogp = (): Plugin => ({
  name: 'ogp-url',
  apply: 'build',
  transformIndexHtml() {
    const site = process.env.SITE_URL?.replace(/\/$/, '');
    if (!site) return [];
    return [
      { tag: 'meta', attrs: { property: 'og:url', content: `${site}/` }, injectTo: 'head' },
      { tag: 'meta', attrs: { property: 'og:image', content: `${site}/og.png` }, injectTo: 'head' },
      { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' }, injectTo: 'head' },
      { tag: 'meta', attrs: { property: 'og:image:alt', content: OG_ALT }, injectTo: 'head' },
      { tag: 'meta', attrs: { name: 'twitter:image:alt', content: OG_ALT }, injectTo: 'head' },
    ];
  },
});

// 本番ビルドに LICENSE.txt（このツール）を入れる（THIRD_PARTY_LICENSES.txt は下の rollup-plugin-license が作る）
const licenseFiles = (): Plugin => ({
  name: 'license-files',
  apply: 'build',
  generateBundle() { this.emitFile({ type: 'asset', fileName: 'LICENSE.txt', source: readFileSync('LICENSE', 'utf8') }); },
});

export default defineConfig({
  base: './',   // GitHub Pages のサブパスでも独自ドメインでも動くように相対パスにする
  plugins: [tailwindcss(), metaCsp(), ogp(), licenseFiles(),
    license({ thirdParty: { includePrivate: false, output: { file: 'dist/THIRD_PARTY_LICENSES.txt',
      template: deps => ['curl-sec-analyzer に含まれる第三者のソフトウェア / Third-party software bundled in curl-sec-analyzer', '',
        ...deps.map(d => `${d.name}@${d.version}（${d.license ?? 'unknown'}）\n${d.licenseText ?? ''}`),
        // CSS は Tailwind CSS がビルド時に生成する（preflight などを含む）。JavaScript のバンドルには含まれないため手で記載する
        `tailwindcss（MIT）\n${readFileSync('node_modules/tailwindcss/LICENSE', 'utf8')}`].join('\n\n') } } })],
  build: { target: 'es2022', sourcemap: false },
  // タイムゾーンを固定する。#META at= はタイムゾーンを持たず手元の時刻として読むので、CI（UTC）と手元（JST）で期限の時間が変わる。
  // ゴールデンテストの期待結果は JST で作ってある。perf のタグの使い方は CONTRIBUTING.md
  test: { environment: 'node', env: { TZ: 'Asia/Tokyo' }, include: ['tests/**/*.test.ts'],
    tags: [{ name: 'perf', description: '時間の上限を確かめるテスト（npm test では、ほかのテストのあとに、ファイルを並べずに流す）' }] },
});
