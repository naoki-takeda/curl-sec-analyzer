import { describe, expect, it } from 'vitest';
import { maskText, maskValue } from '../src/mask';
import { cookieEvidence } from '../src/rules/cookies';
import { parseSetCookie } from '../src/parser/setCookie';

describe('mask', () => {
  it('値の長さに応じて先頭だけ残す', () => {
    expect(maskValue('abc')).toBe('…(3 chars)');
    expect(maskValue('0123456789abcdef')).toBe('01…(16 chars)');
  });
  it('Cookie・クエリ・JWT・URLの認証情報を隠す', () => {
    expect(cookieEvidence(parseSetCookie('sid=1234567890123; Secure'))).toBe('sid=12…(13 chars); Secure');
    expect(maskText('https://a.example/cb?code=SECRETCODE123&x=1')).toBe('https://a.example/cb?code=SE…(13 chars)&x=1');
    expect(maskText('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln')).not.toContain('eyJzdWIi');
    expect(maskText('https://user:pass@a.example/')).toBe('https://user:****@a.example/');
  });
});
