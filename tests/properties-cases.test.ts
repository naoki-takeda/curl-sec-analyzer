// 性質のテスト（tests/properties.test.ts）が見つけた、突き合わせのキーとマスクの誤りの再現テスト。
// 性質のテストは入力を毎回作り直すので、見つけた反例はここに例として残す
import { describe, expect, it } from 'vitest';
import { maskText } from '../src/mask';
import { targetKeys, urlKey } from '../src/engine/targetKey';
import { parseInput } from '../src/parser/input';

const TOKEN = 'Xk9pQ2mZ7vR4tL8nW3bY';

describe('突き合わせのキー', () => {
  it('同じ名前のパラメータの値の順番で、キーが変わらない', () => {
    expect(urlKey('https://a.example/x?sort=1&q=1&sort=ja')).toBe(urlKey('https://a.example/x?sort=ja&q=1&sort=1'));
    expect(urlKey('https://a.example/x?sort=asc&sort=asc')).toBe('https://a.example/x?sort=asc');
    expect(urlKey('https://a.example/x?page=1&page=2')).toBe('https://a.example/x?page');
  });

  it('URL として読めないもののキー（*）は、もう一度かけても変わらない', () => {
    expect(urlKey('//')).toBe('*');
    expect(urlKey('*')).toBe('*');
  });

  it('相対のパスの先頭の「//」は1つにし、スキームのない「//ホスト/…」はホストを残す（もう一度かけても変わらない）', () => {
    for (const [u, k] of [['/.//b', '/b'], ['/a/..//b', '/b'], ['.//b', '/b'], ['//cdn.example/x', '//cdn.example/x']]) {
      expect(urlKey(u)).toBe(k);
      expect(urlKey(k)).toBe(k);
    }
  });

  it('ターゲットのキーは、マスクを使わずに作る（engine/targetKey.ts）', () => {
    const { targets } = parseInput(`#TARGET url=https://a.example/reset/${TOKEN}?token=${TOKEN} label=top\nHTTP/1.1 200 OK\n\n`
      + `#TARGET url=https://a.example/ label=top\nHTTP/1.1 200 OK\n\n`);
    const keys = targetKeys(targets);
    expect(keys).toEqual(['top https://a.example/reset/*?token', 'top https://a.example/']);
    for (const k of keys) expect(k).not.toContain(TOKEN.slice(0, 8));
  });
});

describe('画面のマスク', () => {
  it('エンコードした URL のホスト名をユーザー情報として伏せない', () => {
    for (const s of ['?next=https%3A//a.example%2Fcb%3Fe=bob@example.com', '/a%20//bob@example.com']) expect(maskText(s)).toBe(s);
  });

  it('nonce を先に伏せたパラメータの値を、伏せ直さない', () => {
    expect(maskText(`?code=nonce-${TOKEN}`)).toBe('?code=nonce-Xk…(20 chars)');
    expect(maskText(`?token='nonce-${TOKEN}'`)).toBe("?token='nonce-Xk…(20 chars)'");
  });

  it('エンコードした引用符・= の直後の URL（%22https://…）のパスワードも伏せる', () => {
    expect(maskText(`%22https://alice:${TOKEN}@a.example/`)).toBe('%22https://alice:****@a.example/');
    expect(maskText(`?u=%3Dhttps://alice:${TOKEN}@a.example/`)).not.toContain(TOKEN.slice(0, 8));
    // 「-」でつないだ32文字を超える語の直後のスキーム
    expect(maskText(`proxy=corp-egress-gateway-primary-region-https://svc:${TOKEN}@internal.example/`)).toContain('https://svc:****@internal.example/');
  });

  it('伏せ済みの値は、先頭の4文字までと印だけのものに限る（印で終わるだけの値は伏せる）', () => {
    expect(maskText('?token=abcd…(40 chars)')).toBe('?token=abcd…(40 chars)');
    expect(maskText(`?token=${TOKEN}_x=vi…(17 chars)`)).not.toContain(TOKEN.slice(0, 8));
  });
});

describe('突き合わせのキーのクエリの値', () => {
  it('並べ替え・表示の名前でも、乱数の形の値はキーに残さない', () => {
    const k = urlKey('https://a.example/?sort=QwErTyUiOpAsDfGhJkLz&view=xkqzvwmplrtbnhgf&mode=sk_live_abcdEFG&lang=ja&order=created_at');
    for (const v of ['QwErTyUiOpAsDfGhJkLz', 'xkqzvwmplrtbnhgf', 'sk_live_abcdEFG']) expect(k).not.toContain(v);
    expect(k).toContain('lang=ja'); expect(k).toContain('order=created_at');
  });
});
