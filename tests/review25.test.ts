// 第41回（24回目の新鮮な目でのレビュー：領域ごとの4人のレビュアー）の重要度「中」の指摘
import { describe, expect, it } from 'vitest';
import { urlKey } from '../src/engine/targetKey';
import { showText } from '../src/shownText';
import { summarizeCommand } from '../src/export/cmdSummary';
import { toJson } from '../src/export/json';
import { generateScript } from '../src/commands';
import { refreshTarget } from '../src/rules/transport';
import { evaluate } from './helpers';

const t = (label: string, url: string, head: string, body = '', extra = '') => `#TARGET url=${url} label=${label} ${extra}\n${head.trim()}\n\n${body}\n`;
const ids = (input: string, item: string) => evaluate(input).findings.filter(f => f.item === item).map(f => f.ruleId);
const HTML = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8';

describe('1 突き合わせのキーは、画面で伏せるパスのトークンを残さない（JSON・CSV の実施コマンド・例外ファイル）', () => {
  const TOKEN = 'qkzvwxmplrtbnhg';   // 英小文字15文字（lowerToken の16文字に届かない）
  it('英小文字15文字までの乱数を * にする', () => {
    expect(urlKey(`https://www.example.com/reset/${TOKEN}`)).toBe('https://www.example.com/reset/*');
    expect(urlKey('https://www.example.com/invite/Xkqzvwxmplrtbnhgfdsa')).toBe('https://www.example.com/invite/*');
    expect(summarizeCommand(`curl_-sI_https://www.example.com/reset/${TOKEN}`)).not.toContain(TOKEN);
    const { findings } = evaluate(`#TARGET url=https://www.example.com/reset/${TOKEN} label=reset\nHTTP/2 200\ncontent-type: text/html\n\n`);
    expect(toJson(findings, [], [])).not.toContain(TOKEN);
  });
  it('ふつうの語のパスは残す（キーを変えない）', () => {
    for (const p of ['/settings', '/dashboard', '/products/checkout', '/account/AdminDashboard', '/API/v2/users', '/お知らせ'])
      expect(urlKey(`https://www.example.com${p}`)).toBe(`https://www.example.com${p}`);
  });
  it('キーに残るパスの語は、画面の許可リストでも残る（一様な乱数の英字）', () => {
    let seed = 20261118;
    const rand = () => { seed = (seed + 0x6D2B79F5) | 0; let x = Math.imul(seed ^ (seed >>> 15), 1 | seed); x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x; return ((x ^ (x >>> 14)) >>> 0) / 4294967296; };
    const gen = (alpha: string, n: number) => Array.from({ length: n }, () => alpha[Math.floor(rand() * alpha.length)]).join('');
    for (const alpha of ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'])
      for (let i = 0; i < 2000; i++) {
        const w = gen(alpha, 5 + (i % 20));
        if (urlKey(`https://a.example/x/${w}`).endsWith(`/${w}`)) expect(showText(`https://a.example/x/${w}`), w).toContain(w);
      }
  });
  it('キーは冪等のまま', () => {
    for (const u of [`https://www.example.com/reset/${TOKEN}`, 'https://www.example.com/settings/profile', 'https://www.example.com/invite/Xkqzvwxmplrtbnhgfdsa?page=2'])
      expect(urlKey(urlKey(u))).toBe(urlKey(u));
  });
});

describe('2・3・9 生成スクリプトの curl', () => {
  const s = generateScript({ host: 'www.example.com', apex: 'example.com', apiPath: '/api/me', loginPath: '/login', mypagePath: '/mypage', logoutPath: '/logout', staticPath: '/app.js', wsPath: '/ws', dangerous: true });
  const curls = s.split('\n').filter(l => /\bcurl\s/.test(l) && !/^\s*#/.test(l) && !/^echo /.test(l.trim()));
  it('すべての curl が最初の引数で ~/.curlrc を読まない（-q）、時間の上限を持つ', () => {
    expect(curls.length).toBeGreaterThan(20);
    for (const l of curls) {
      for (const m of l.matchAll(/\bcurl (\S+)/g)) expect(m[1], l).toBe('-q');
      expect(l, l).toMatch(/--max-time \d+/);
      expect(l, l).toMatch(/--connect-timeout \d+/);
    }
  });
  it('WebSocket（C16）は HTTP/1.1 でハンドシェイクする（HTTP/2 では Upgrade を送らない）', () => {
    expect(s.split('\n').find(l => l.includes('Upgrade: websocket'))).toContain('--http1.1');
  });
  it('一時ファイルを、止められたときも消す（trap）', () => {
    expect(s).toMatch(/^trap 'rm -f "\$hdr" "\$body" \$\{probe:\+"\$probe"\} \$\{tout:\+"\$tout"\} \$\{terr:\+"\$terr"\}' EXIT$/m);
    expect(s).toMatch(/^trap 'exit 130' INT TERM HUP$/m);
    // trap は一時ファイルを作った直後、出力の { より前
    expect(s.indexOf('trap ')).toBeLessThan(s.indexOf('\n{\n'));
    expect(s.indexOf('hdr=$(mktemp)')).toBeLessThan(s.indexOf('trap '));
  });
});

describe('4 http の URL を同じサイトの https（www）に転送したものは HTTPS のターゲットとして判定する', () => {
  const chain = (to: string) => `#TARGET url=http://example.com/ label=top\nHTTP/1.1 301 Moved Permanently\nlocation: ${to}\n\nHTTP/2 200\ncontent-type: text/html\nset-cookie: sid=abcdefghijklmnopqrstuvwxyz0123; Path=/\n\n`;
  it('apex → www の https', () => {
    const r = evaluate(chain('https://www.example.com/'));
    expect(r.ids('top')).toContain('H-01.1');
    expect(r.ids('top')).toContain('C-01.1');
  });
  it('別のサイトの https への転送は、これまでどおり HTTPS のターゲットにしない', () => {
    expect(evaluate(chain('https://other.example/')).ids('top')).not.toContain('H-01.1');
  });
});

describe('5 H-05②：base-uri の * とスキームだけの指定は、ないのと同じ', () => {
  const csp = (v: string) => t('top', 'https://a.example/', `${HTML}\ncontent-security-policy: ${v}`, '<html></html>');
  it('①にするもの', () => {
    for (const b of ['*', 'https:', 'data: https:', "'self' https:"])
      expect(ids(csp(`default-src 'self'; object-src 'none'; base-uri ${b}`), 'H-05'), b).toEqual(['H-05.2']);
  });
  it('合格にするもの', () => {
    for (const b of ["'none'", "'self'", 'https://a.example', ''])
      expect(ids(csp(`default-src 'self'; object-src 'none'; base-uri ${b}`), 'H-05'), b).toEqual(['H-05.ok']);
    // ポリシーは重ねて効く：制限する base-uri のあるポリシーが1つあればよい
    const two = `${HTML}\ncontent-security-policy: default-src 'self'; object-src 'none'; base-uri *\ncontent-security-policy: base-uri 'none'`;
    expect(ids(t('top', 'https://a.example/', two, '<html></html>'), 'H-05')).toEqual(['H-05.ok']);
  });
});

describe('6 T-06：Refresh ヘッダ', () => {
  it('転送先の読み方（HTML Standard）', () => {
    expect(refreshTarget('0; url=https://evil.example/')).toBe('https://evil.example/');
    expect(refreshTarget('0; https://evil.example/')).toBe('https://evil.example/');
    expect(refreshTarget('0,https://evil.example/')).toBe('https://evil.example/');
    expect(refreshTarget("0; URL='https://evil.example/a b'")).toBe('https://evil.example/a b');
    expect(refreshTarget('5')).toBeUndefined();
    expect(refreshTarget('5;')).toBeUndefined();
    expect(refreshTarget('x; url=https://evil.example/')).toBeUndefined();
  });
  const r = (refresh: string) => ids(t('open-redirect', 'https://a.example/r?next=https://evil.example', `HTTP/2 200\ncontent-type: text/html\nrefresh: ${refresh}`), 'T-06');
  it('url= のない外部への転送を①にする', () => {
    expect(r('0; https://evil.example/')).toEqual(['T-06.1']);
    expect(r('0; url=https://evil.example/')).toEqual(['T-06.1']);
  });
  it('読み込み直し・同じページへの Refresh では、転送を試したとしない', () => {
    expect(r('5')).toEqual(['T-06.na']);
    expect(r('5; url=https://a.example/r?next=https://evil.example')).toEqual(['T-06.na']);
  });
  it('別のページへの Refresh は、これまでどおり合格', () => {
    expect(r('0; url=/home')).toEqual(['T-06.ok']);
  });
});

describe('7 E-11①：Content-Disposition は種類（最初のトークン）で見る', () => {
  const up = (cd: string) => ids(t('top', 'https://a.example/uploads/attachment.html', `HTTP/2 200\ncontent-type: text/html\ncontent-disposition: ${cd}`), 'E-11');
  it('inline でファイル名に attachment を含むものを①にする', () => {
    expect(up('inline; filename="attachment.html"')).toEqual(['E-11.1']);
    expect(up('inline; filename=attachment.html')).toEqual(['E-11.1']);
  });
  it('attachment は①にしない', () => {
    for (const cd of ['attachment; filename="x.html"', 'Attachment', ' attachment ;filename=x.html']) expect(up(cd), cd).not.toContain('E-11.1');
  });
});

describe('8 E-10①：送信先はページの URL を基準に読む', () => {
  const page = (url: string, action: string) => evaluate(t('top', url, HTML, `<form action="${action}" method="post"><input type="password" name="p"></form>`)).ids('top');
  it('http のページの相対・空・スキームのない送信先を①にする', () => {
    for (const a of ['/login', '', 'login', '//a.example/login']) expect(page('http://a.example/login', a), a).toContain('E-10.1');
  });
  it('https のページの相対の送信先、https:// の送信先は①にしない', () => {
    expect(page('https://a.example/login', '/login')).not.toContain('E-10.1');
    expect(page('http://a.example/login', 'https://a.example/login')).not.toContain('E-10.1');
    expect(page('https://a.example/login', 'http://a.example/login')).toContain('E-10.1');
  });
});
