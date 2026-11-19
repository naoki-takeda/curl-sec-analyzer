// C13 のプローブ（#PROBE）の判定パターンと、採る先頭の長さ（src/rules/probes.ts・src/commands.ts）
import { describe, expect, it } from 'vitest';
import { HTML_PROBE_PATHS, htmlProbe, probePattern } from '../src/rules/probes';
import { generateScript } from '../src/commands';
import { GEN_OPTS, evaluate } from './helpers';

const b64 = (s: string, n = 64) => Buffer.from(s, 'latin1').subarray(0, n).toString('base64');

describe('実物の形の先頭', () => {
  it('git の HEAD（ブランチ・detached・SHA-256 の detached・bare）', () => {
    // git 2.x の git init・git checkout --detach で作った HEAD の中身
    for (const s of ['ref: refs/heads/main\n', 'ref: refs/heads/master\n', `${'a1'.repeat(20)}\n`, `${'8e'.repeat(32)}\n`])
      expect(probePattern('/.git/HEAD', b64(s), 200)?.name, s).toBe('git-head');
  });
  it('zip は中身のあるもの（PK 03 04）だけ。空の zip（PK 05 06）は一致しない', () => {
    expect(probePattern('/backup.zip', b64('PK\x03\x04\x14\x00\x00\x00\x08\x00'), 200)?.name).toBe('backup');
    expect(probePattern('/backup.zip', b64('PK\x05\x06\x00\x00\x00\x00'), 200)).toBeUndefined();
  });
  it('npm init の package.json は、64バイトでは一致せず、4KB なら一致する', () => {
    const pkg = '{\n  "name": "my-shop-frontend",\n  "version": "1.0.0",\n  "description": "",\n  "main": "index.js",\n  "scripts": {\n    "test": "echo"\n  }\n}\n';
    expect(probePattern('/package.json', b64(pkg), 200)).toBeUndefined();
    expect(probePattern('/package.json', b64(pkg, 4096), 200)?.name).toBe('package-json');
  });
  it('phpinfo の title は CSS のあと（php-src の php_info_print_html_head の順）なので、4KB なら一致する', () => {
    const php = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">\n<html xmlns="http://www.w3.org/1999/xhtml"><head>\n<style type="text/css">\n${'body {background-color: #fff; color: #222; font-family: sans-serif;}\n'.repeat(18)}</style>\n<title>PHP 8.4.1 - phpinfo()</title>`;
    expect(probePattern('/phpinfo.php', b64(php), 200)).toBeUndefined();
    expect(probePattern('/phpinfo.php', b64(php, 4096), 200)?.name).toBe('phpinfo');
  });
  it('Apache の server-status は、1KB なら見出しが入る', () => {
    const st = '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n<html><head>\n<title>Apache Status</title>\n</head><body>\n<h1>Apache Server Status for localhost (via 127.0.0.1)</h1>\n';
    expect(probePattern('/server-status', b64(st), 200)).toBeUndefined();
    expect(probePattern('/server-status', b64(st, 1024), 200)?.name).toBe('server-status');
  });
  it('使用許諾のコメントで始まる web.xml は、4KB なら <web-app> が入る', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<!--\n${'  Licensed to the Apache Software Foundation (ASF) under one or more\n'.repeat(14)}-->\n<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee" version="6.0">`;
    expect(probePattern('/WEB-INF/web.xml', b64(xml), 200)).toBeUndefined();
    expect(probePattern('/WEB-INF/web.xml', b64(xml, 4096), 200)?.name).toBe('web-xml');
    expect(htmlProbe(b64(xml))).toBe(false);
  });
});

describe('HTML の画面が返ったプローブ', () => {
  const page = '<!doctype html>\n<html lang="ja">\n  <head>\n    <meta charset="UTF-8">';
  const probes = (lines: string[]) => evaluate(['#TARGET url=https://www.example.com/ label=probes', ...lines, ''].join('\n')).findings.filter(f => f.item === 'E-03');
  it('HTML でない形式のファイルのパスに HTML が返ったら、そのファイルではない（SPA の index.html）', () => {
    const fs = probes(['/.git/HEAD', '/.env', '/backup.zip', '/package.json'].map(p => `#PROBE path=${p} head=${b64(page)} code=200 size=2220 ct=text/html`));
    expect(fs.map(f => f.ruleId)).toEqual(['E-03.ok']);
    expect(fs[0].evidence).toContain('うち4件は HTML の画面が返った');
  });
  it('BOM と空白のあとの <html も HTML とみなす', () => {
    expect(htmlProbe(b64('\xEF\xBB\xBF\n  <html><head>'))).toBe(true);
    expect(htmlProbe(b64('<?xml version="1.0"?><web-app>'))).toBe(false);
  });
  it('phpinfo・server-status は本物も HTML なので、パターンに一致しなければ今までどおり②', () => {
    expect(HTML_PROBE_PATHS.test('/phpinfo.php') && HTML_PROBE_PATHS.test('/server-status')).toBe(true);
    expect(probes([`#PROBE path=/phpinfo.php head=${b64(page)} code=200 size=2220 ct=text/html`]).map(f => f.ruleId)).toEqual(['E-03.2']);
  });
  it('HTML でもパターンにも一致しない 200 は、今までどおり②', () => {
    expect(probes([`#PROBE path=/.env head=${b64('hello world\n')} code=200 size=12 ct=text/plain`]).map(f => f.ruleId)).toEqual(['E-03.2']);
  });
});

describe('生成スクリプトの C13', () => {
  it('目印が後ろにあるテキストの形式は4KB、server-status は1KB、ほかは64バイトを採る', () => {
    const s = generateScript(GEN_OPTS);
    expect(s).toContain('case $p in /phpinfo.php|/WEB-INF/web.xml|/package.json|/composer.json|/.well-known/security.txt) n=4096 ;; /server-status) n=1024 ;; *) n=64 ;; esac');
    expect(s).toContain('head -c "$n" "$probe"');
  });
});

describe('長く採った先頭で、ほかの応答の中の語・要素に一致しない', () => {
  it('SPA の HTML の中のカスタム要素 <web-app> を web.xml としない', () => {
    const spa = `<!doctype html>\n<html><head><title>App</title></head><body>${' '.repeat(500)}<web-app></web-app></body></html>`;
    expect(probePattern('/WEB-INF/web.xml', b64(spa, 4096), 200)).toBeUndefined();
    // 本文の途中の <web-app>（HTML でない応答）も、先頭に固定するので一致しない
    expect(probePattern('/WEB-INF/web.xml', b64(`Not Found\n<web-app>`, 4096), 200)).toBeUndefined();
    expect(probePattern('/WEB-INF/web.xml', b64('<?xml version="1.0"?>\n<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN">', 4096), 200)?.name).toBe('web-xml');
  });
  it('package.json・composer.json は最上位のキーだけを見る（API の入れ子の main・repositories に一致しない）', () => {
    const api = '{"status":"ok","data":{"page":{"title":"x","main":{"id":1}},"repositories":[]}}';
    expect(probePattern('/package.json', b64(api, 4096), 200)).toBeUndefined();
    expect(probePattern('/composer.json', b64(api, 4096), 200)).toBeUndefined();
    expect(probePattern('/package.json', b64('{"name":"x","description":"a \\"main\\": b","private":true}', 4096), 200)?.name).toBe('package-json');
    expect(probePattern('/package.json', b64('{"version":"1","name":"@acme/web"}', 4096), 200)?.name).toBe('package-json');
    expect(probePattern('/composer.json', b64('{\n    "name": "acme/shop",\n    "type": "project"', 4096), 200)?.name).toBe('composer-json');
  });
  it('phpinfo・server-status は出力の決まった形だけ（記事の「Requires PHP Version 8.1」に一致しない）', () => {
    const article = '<!doctype html><html><body><p>Requires PHP Version 8.1 and Apache Server Status page.</p>';
    expect(probePattern('/phpinfo.php', b64(article, 4096), 200)).toBeUndefined();
    expect(probePattern('/server-status', b64(article, 1024), 200)).toBeUndefined();
    expect(probePattern('/phpinfo.php', b64('phpinfo()\nPHP Version => 8.3.6\n', 4096), 200)?.name).toBe('phpinfo');
    expect(probePattern('/server-status', b64('<html><head>\n<title>Apache Status</title>\n</head><body>\n<dt>Server Version: Apache/2.4.62 (Unix)</dt>', 1024), 200)?.name).toBe('server-status');
  });
  it('HTML の画面の中の「Contact:」の行を security.txt としない', () => {
    expect(probePattern('/.well-known/security.txt', b64('<!doctype html><html><body>\nContact: support@example.com\n', 4096), 200)).toBeUndefined();
  });
  it('閉じないコメント・括弧の多い先頭でも、すぐ終わる', { tags: ['perf'] }, () => {
    const t = performance.now();
    for (const s of ['<!--'.repeat(1024), `<?xml?>${'<!-- -->'.repeat(500)}x`, `{${'"a":{'.repeat(800)}`, `{${'"\\\\'.repeat(1000)}`, `{${'"a":"'.repeat(800)}`])
      for (const p of ['/WEB-INF/web.xml', '/package.json', '/composer.json']) probePattern(p, b64(s, 4096), 200);
    expect(performance.now() - t).toBeLessThan(200);
  });
});

describe('汎用の語のキー・web.xml の処理命令と名前空間', () => {
  it('main・module・exports・bin は、name か version と組のときだけ package.json とする', () => {
    expect(probePattern('/package.json', b64('{"module":"auth","error":"not found"}', 4096), 200)).toBeUndefined();
    expect(probePattern('/package.json', b64('{"name":"x","version":"1.0.0","main":"index.js"}', 4096), 200)?.name).toBe('package-json');
  });
  it('XML 宣言のほかの処理命令のあとと、名前空間の接頭辞の <j:web-app> も web.xml とする', () => {
    expect(probePattern('/WEB-INF/web.xml', b64('<?xml version="1.0"?>\n<?xml-stylesheet type="text/xsl" href="a.xsl"?>\n<web-app>', 4096), 200)?.name).toBe('web-xml');
    expect(probePattern('/WEB-INF/web.xml', b64('<?xml version="1.0"?>\n<j:web-app xmlns:j="https://jakarta.ee/xml/ns/jakartaee">', 4096), 200)?.name).toBe('web-xml');
  });
});
