import { describe, expect, it } from 'vitest';
import { CSP, CSP_DIRECTIVES } from '../csp.config.ts';

// このツール自身の CSP（csp.config.ts）を、気付かないうちに緩めないための検査。
// 緩める必要がある場合は、この検査も変えて、プルリクエストに理由を書く
describe('このツール自身の CSP', () => {
  it('外部への通信を禁止し、既定はすべて拒否する', () => {
    expect(CSP_DIRECTIVES['default-src']).toBe("'none'");
    expect(CSP_DIRECTIVES['connect-src']).toBe("'none'");
    expect(CSP_DIRECTIVES['form-action']).toBe("'none'");
    expect(CSP_DIRECTIVES['base-uri']).toBe("'none'");
  });

  it('スクリプトは同じオリジンのファイルだけ、Worker は blob: だけ', () => {
    expect(CSP_DIRECTIVES['script-src']).toBe("'self'");
    expect(CSP_DIRECTIVES['worker-src']).toBe('blob:');
  });

  it("'unsafe-*'・ワイルドカード・http(s): の許可を含まない", () => {
    expect(CSP).not.toMatch(/'unsafe-|\*|https?:/);
  });

  it('指定を「; 」でつないだ1行になる', () => {
    expect(CSP.split('; ')).toHaveLength(Object.keys(CSP_DIRECTIVES).length);
    expect(CSP).toContain("connect-src 'none'");
  });
});
