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

describe('突き合わせのキーの区切った番号とコード', () => {
  it('カード番号・社会保障番号の形・招待のコードは、かけらごとに残さない（画面の許可リストと同じ形）', () => {
    for (const [path, code] of [['/card/4111-1111-1111-1111', '4111'], ['/u/123-45-6789', '6789'], ['/invite/QWER-TYUI-ZXCV-ASDF', 'ZXCV'],
      ['/invite/123456-654321-111111', '654321'], ['/r/ab12_cd34_ef56_gh78', 'cd34'], ['/invite/K7QX-9MZP', '9MZP']] as const) {
      const k = urlKey(`https://a.example${path}`);
      expect(k).not.toContain(code); expect(urlKey(k)).toBe(k);
    }
  });
  it('日付・版・語のパスは残す', () => {
    for (const p of ['/news/2026-11-19', '/docs/2026-annual-report-v2', '/api/v1/user-list', '/cipher/ECDHE-RSA-AES-GCM']) expect(urlKey(`https://a.example${p}`)).toBe(`https://a.example${p}`);
  });
});

describe('#META の内部の印', () => {
  it('入力の #META の source=・method= は受け付けない（HAR のターゲットのキーにしない）', () => {
    const [t] = parseInput('#TARGET url=https://a.example/api label=t\n#META source=har method=Bearer_secret\nHTTP/2 200\n\n').targets;
    expect(t.meta.source).toBeUndefined(); expect(t.meta.method).toBeUndefined();
    expect(targetKeys([t])[0]).toBe('t');
  });
});

describe('突き合わせのキーの番号とコード（第70回）', () => {
  it('拡張子の付いた社会保障番号の形は残さず、版・IP アドレス・語と数字の組は残す', () => {
    expect(urlKey('https://a.example/x/123-45-6789.pdf')).not.toContain('6789');
    for (const p of ['/download/10.0.19045.3803/setup.exe', '/ip/192.168.100.200', '/f/x86-x64', '/f/md5-rc4'])
      expect(urlKey(`https://a.example${p}`)).toBe(`https://a.example${p}`);
  });
  it('「HAR 」で始まるラベルは使えない（HAR のターゲットのキーにしない）', () => {
    const { targets } = parseInput('#TARGET url=https://a.example/x label="HAR GET"\nHTTP/2 200\n\n#TARGET url=https://a.example/y label="HAR GET"\nHTTP/2 200\n\n');
    expect(targets.every(t => t.label.startsWith('invalid-label'))).toBe(true);
    expect(targetKeys(targets).some(k => k.startsWith('HAR '))).toBe(false);
  });
});

describe('突き合わせのキーの電話番号と、長さのそろわないコード', () => {
  it('10〜11桁の電話番号（拡張子が付いても）と、長さのそろわない乱数のかけらのコードは残さない', () => {
    for (const [path, code] of [['/u/090-1234-5678', '5678'], ['/u/090-1234-5678.vcf', '1234'], ['/t/03-1234-5678', '5678'], ['/c/0120-123-456', '0120'],
      ['/u/555-123-4567', '4567'], ['/u/+81-90-1234-5678', '5678'], ['/i/7Gk-p2Q-xZ81-m', 'xZ81']] as const) {
      const k = urlKey(`https://a.example${path}`);
      expect(k, path).not.toContain(code); expect(urlKey(k)).toBe(k);
    }
  });
  it('日付に番号を付けたもの・語と数字の組・画像の大きさは残す', () => {
    for (const p of ['/news/2026-11-19-01', '/img/1920-1080', '/f/s3-ap-northeast-1', '/f/x86-x64-v2'])
      expect(urlKey(`https://a.example${p}`), p).toBe(`https://a.example${p}`);
  });
});

describe('突き合わせのキーの . で区切った電話番号・コードと、ほかの電話番号の形', () => {
  it('. で区切ったもの・拡張子が2つのもの・前に語の付いたもの・0 で始まるほかの区切り方の電話番号は残さない', () => {
    for (const [path, code] of [['/u/090.1234.5678', '5678'], ['/u/555.123.4567', '4567'], ['/i/AB12.CD34.EF56.GH78', 'CD34'], ['/u/090-1234-5678.vcf.gz', '5678'],
      ['/u/090-1234-5678.profile.json', '5678'], ['/u/tel090-1234-5678', '5678'], ['/u/0312-34-5678', '5678'], ['/u/01267-2-3456', '3456'], ['/u/01-23-45-67-89', '67-89'],
      ['/i/QWER-TYUI-ZXCV-ASDF.png', 'ZXCV'],
      // 国番号・tel:・括弧・内線の付いたもの
      ['/u/+81-3-1234-5678', '1234'], ['/u/81-3-1234-5678', '1234'], ['/u/+33-1-23-45-67-89', '67-89'], ['/call/tel:090-1234-5678', '1234'],
      ['/u/(090)-1234-5678', '1234'], ['/u/090-1234-5678x', '1234'], ['/u/+1-555-123-4567', '4567']] as const) {
      const k = urlKey(`https://a.example${path}`);
      expect(k, path).not.toContain(code); expect(urlKey(k)).toBe(k);
    }
  });
  it('IP アドレス・版・ファイル名・略語は変えない', () => {
    for (const p of ['/ip/192.168.100.200', '/ip/10.1.100.200', '/ip/010.123.123.123', '/v/2026.11.20', '/v/v1.28.3', '/img/1920-1080-60', '/download/120.0.6099.109/x.exe', '/download/10.0.19045.3803/x.exe', '/docs/user-guide-v2', '/js/jquery-3.6.0.min.js'])
      expect(urlKey(`https://a.example${p}`), p).toBe(`https://a.example${p}`);
  });
});
