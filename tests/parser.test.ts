import { describe, expect, it } from 'vitest';
import { attrs, parseInput } from '../src/parser/input';
import { finalResponse, isHttps } from '../src/parser/target';
import { fixture, sampleText } from './helpers';

describe('parseInput', () => {
  it('#TARGET ごとにターゲットを分け、url・label・sensitive を読む', () => {
    const { targets } = parseInput(sampleText());
    expect(targets.map(t => t.label)).toEqual(['top', 'http', 'apex', 'pre-login', 'login', 'mypage', 'cors-reflect', 'logout', 'after-logout', 'probes', 'tls']);
    expect(targets.find(t => t.label === 'mypage')!.sensitive).toBe(true);
    expect(targets[0].sensitive).toBeUndefined();
    expect(targets.find(t => t.label === 'probes')!.probes[0]).toMatchObject({ path: '/.git/HEAD', code: 200, contentType: 'text/plain' });
    expect(targets.find(t => t.label === 'tls')!.tlsProbes.map(p => p.result)).toEqual(['rejected', 'accepted', 'accepted', 'accepted']);
  });

  it('-v の出力から送信ヘッダ（Origin・Authorization）と接続情報を読む', () => {
    const { targets } = parseInput(sampleText());
    const top = targets[0], api = targets.find(t => t.label === 'cors-reflect')!;
    expect(top.verbose).toBe(true);
    expect(top.sentAuth).toBe(false);
    expect(top.info.some(l => l.startsWith('ALPN'))).toBe(true);
    expect(api.sentOrigin).toBe('https://evil.example');
    expect(api.sentAuth).toBe(true);
    expect(finalResponse(top)?.headers.get('strict-transport-security')).toEqual(['max-age=31536000; includeSubDomains; preload']);
  });

  it('-L の複数ホップを1つのターゲットの応答チェーンにする', () => {
    const http = parseInput(sampleText()).targets[1];
    expect(http.responses.map(r => [r.status, r.kind])).toEqual([[302, 'redirect'], [200, 'final']]);
    expect(isHttps(http)).toBe(false);
  });

  it('既知のマーカー以外の # 行は本文として扱い、obs-fold をつなぐ', () => {
    const { targets, warnings } = parseInput(fixture('body_hash_comments.txt'));
    expect(targets).toHaveLength(1);
    const r = finalResponse(targets[0])!;
    expect(r.headers.get('x-long')).toEqual(['continued value']);
    expect(r.body).toContain('# これは本文の行');
    expect(r.body).toContain('#TARGETS も本文');
    expect(warnings).toEqual([]);
  });

  it('ct= は行末まで1つの値として読む', () => {
    expect(attrs(' path=/x code=200 ct=text/html; charset=utf-8')).toEqual({ path: '/x', code: '200', ct: 'text/html; charset=utf-8' });
  });

  it('解析警告：属さない行、データのない #TARGET、URL不明', () => {
    const { warnings } = parseInput('garbage line\n#TARGET label=empty\n#TARGET label=nourl\nHTTP/1.1 200 OK\nA: b\n');
    expect(warnings.map(w => w.kind)).toEqual(['unparsed-lines', 'orphan-block', 'unknown-url']);
  });

  it('CRLF の改行も読める', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/\r\nHTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n');
    expect(finalResponse(targets[0])?.headers.get('x-content-type-options')).toEqual(['nosniff']);
  });
});
