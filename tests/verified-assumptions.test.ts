// 要確認事項の確認（2026-11-18）で分かった、プローブのパターン・openssl の出力・curl の -v の前提の違い
import { describe, expect, it } from 'vitest';
import { probePattern } from '../src/rules/probes';
import { parseOpenssl } from '../src/parser/openssl';
import { isHttps } from '../src/parser/target';
import { recommendationEn } from '../src/recommendationsEn';
import { evaluate } from './helpers';

// 先頭64バイトだけを渡す（C13 と同じ）
const hit = (path: string, head: string) => probePattern(path, btoa(head.slice(0, 64)), 200)?.name;

describe('プローブ：一般的なキーだけの JSON では一致させない（誤検知）', () => {
  it('どのパスにも同じ JSON を返す API は、package.json・composer.json・ソースマップにならない', () => {
    for (const body of ['{"name":"api","version":"1.0.0","status":"ok"}', '{"type":"about:blank","title":"Not Found"}', '{"description":"service","license":"MIT"}']) {
      expect(hit('/package.json', body), body).toBeUndefined();
      expect(hit('/composer.json', body), body).toBeUndefined();
    }
    expect(hit('/assets/app.js.map', '{"version":"2.1.0","name":"api"}')).toBeUndefined();
    expect(hit('/assets/app.js.map', '{"file":"app.js","status":"ok"}')).toBeUndefined();
  });
  it('本物の package.json・composer.json・ソースマップには一致する', () => {
    expect(hit('/package.json', '{\n  "name": "my-app",\n  "version": "0.1.0",\n  "private": true,\n  "scripts": {}')).toBe('package-json');
    expect(hit('/package.json', '{\n  "name": "@acme/web",\n  "version": "2.0.0"')).toBe('package-json');
    expect(hit('/package.json', '{"dependencies":{"react":"^19.0.0"}}')).toBe('package-json');
    expect(hit('/composer.json', '{\n    "name": "laravel/laravel",\n    "type": "project"')).toBe('composer-json');
    expect(hit('/composer.json', '{"require":{"php":"^8.2"}}')).toBe('composer-json');
    expect(hit('/assets/app.js.map', '{"version":3,"file":"app.js","sources":["../src/a.ts"]')).toBe('source-map');
    expect(hit('/assets/app.js.map', `)]}'\n{"version":3,"sources":[]}`)).toBe('source-map');
  });
  it('特有のキーが先頭64バイトより後ろにある package.json は一致しない（E-03② の判定保留になる）', () => {
    expect(hit('/package.json', '{\n  "name": "lodash",\n  "version": "4.17.21",\n  "description": "Lodash modular utilities.",\n  "main": "lodash.js"')).toBeUndefined();
  });
});

describe('プローブ：見逃していた本物のファイル', () => {
  it('detached HEAD（コミットの ID だけ）の .git/HEAD', () => {
    expect(hit('/.git/HEAD', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n')).toBe('git-head');
    expect(hit('/.git/HEAD', `${'0123456789abcdef'.repeat(4)}\n`)).toBe('git-head');
    expect(hit('/.git/HEAD', 'ref: refs/heads/main\n')).toBe('git-head');
    expect(hit('/.git/HEAD', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 extra\n')).toBeUndefined();
  });
  it('export を付けた .env と、= の前後に空白のある .env', () => {
    expect(hit('/.env', 'export APP_KEY=base64:xxxx\n')).toBe('dotenv');
    expect(hit('/.env', 'APP_KEY = xxxx\n')).toBe('dotenv');
    expect(hit('/.env', '<!DOCTYPE html>\n<html lang="ja">')).toBeUndefined();
  });
  it('Canonical・Policy などで始まる security.txt', () => {
    expect(hit('/.well-known/security.txt', 'Canonical: https://example.com/.well-known/security.txt\n')).toBe('security-txt');
    expect(hit('/.well-known/security.txt', 'policy: https://example.com/disclosure\n')).toBe('security-txt');
    expect(hit('/.well-known/security.txt', '<!doctype html><title>Not found</title>')).toBeUndefined();
  });
});

describe('openssl：「New, <版>, Cipher is」の版は合意した版として読まない', () => {
  it('TLS 1.2 の接続の New, SSLv3, Cipher is AES128-SHA は、Protocol の行の版を使う', () => {
    const info = parseOpenssl(['CONNECTED(00000003)', 'New, SSLv3, Cipher is AES128-SHA', 'Protocol: TLSv1.2', 'Verify return code: 0 (ok)'])!;
    expect(info.protocol).toBe('TLSv1.2');
    expect(info.cipher).toBe('AES128-SHA');
  });
  it('Protocol の行がない TLS 1.3（OpenSSL 1.1.1・3.0）は、New の行の TLSv1.3 を使う', () => {
    const info = parseOpenssl(['CONNECTED(00000003)', 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384', 'Verify return code: 0 (ok)'])!;
    expect(info.protocol).toBe('TLSv1.3');
  });
  it('Protocol の行がなく、New の版が TLS 1.3 でなければ、版は分からない', () => {
    const info = parseOpenssl(['CONNECTED(00000003)', 'New, TLSv1.0, Cipher is ECDHE-RSA-AES128-SHA', 'Verify return code: 0 (ok)'])!;
    expect(info.protocol).toBeUndefined();
    expect(info.cipher).toBe('ECDHE-RSA-AES128-SHA');
  });
});

describe('curl の -v：7.83 より前の ALPN の行と、Schannel 版の curl', () => {
  it('URL のないターゲットで「ALPN, server accepted to use h2」を HTTPS の手がかりにする', () => {
    const r = evaluate('#TARGET label=top\n* Connected to a.example (192.0.2.1) port 443 (#0)\n* ALPN, server accepted to use h2\n> GET / HTTP/2\n>\n< HTTP/2 200\n<\n');
    expect(isHttps(r.targets[0])).toBe(true);
  });
  it('Schannel 版の curl 8.16 以降の行（SSL connection の行なし）でも -v として読む', () => {
    const r = evaluate('#TARGET url=https://a.example/ label=top\n* Host a.example:443 was resolved.\n*   Trying 192.0.2.1:443...\n* ALPN: curl offers h2,http/1.1\n* ALPN: server accepted h2\n* Established connection to a.example (192.0.2.1 port 443) from 192.0.2.9 port 50000\n> GET / HTTP/2\n>\n< HTTP/2 200\n< content-type: text/html\n<\n');
    expect(r.targets[0].verbose).toBe(true);
    expect(r.targets[0].responses.some(x => x.status === 200)).toBe(true);
  });
});

describe('R-05②：Safari のプリフライトの上限', () => {
  it('推奨対応に Safari の600秒を書き、英訳がある', () => {
    const r = evaluate('#TARGET url=https://a.example/api label=cors-preflight\nHTTP/2 204\naccess-control-allow-origin: https://app.example\naccess-control-allow-methods: GET\naccess-control-max-age: 86400\n\n');
    const f = r.findings.find(x => x.ruleId === 'R-05.2')!;
    expect(f.recommendation).toContain('Safariは600秒');
    expect(recommendationEn(f.recommendation)).toContain('Safari at 600 seconds');
  });
});
