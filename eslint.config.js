// ESLint の設定。セキュリティの設計（innerHTML を使わない、eval を使わない）をルールでも強制する
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

const NO_HTML = 'textContent・createTextNode・el() で描画する（ツール設計3：innerHTML 禁止）';

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/', 'test-results/', 'playwright-report/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      'no-restricted-properties': ['error',
        { property: 'innerHTML', message: NO_HTML }, { property: 'outerHTML', message: NO_HTML },
        { property: 'insertAdjacentHTML', message: NO_HTML }, { object: 'document', property: 'write', message: NO_HTML },
        { property: 'setHTMLUnsafe', message: NO_HTML }, { property: 'createContextualFragment', message: NO_HTML }, { property: 'srcdoc', message: NO_HTML },
        { property: 'parseFromString', message: NO_HTML }],
      'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
);
