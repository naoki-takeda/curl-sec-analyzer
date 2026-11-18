// 前回との差分・組織プロファイル・例外の照合（engine/diff.ts・profile.ts・suppress.ts）。第48回のレビューで見つかったもの
import { describe, expect, it } from 'vitest';
import { diff } from '../src/engine/diff';
import { parseProfile } from '../src/engine/profile';
import { parseInput } from '../src/parser/input';
import { runAll } from '../src/engine/run';
import { evaluate } from './helpers';

const AT = '#META at=2026-11-01T10:00:00';
const top = (host: string, hsts: boolean) => `#TARGET url=https://${host}/ label=top\n${AT}\nHTTP/2 200\ncontent-type: text/html\n${hsts ? 'strict-transport-security: max-age=63072000; includeSubDomains\n' : ''}\n<p>x</p>\n`;
const kinds = (rows: ReturnType<typeof diff>, ruleId: string) => rows.filter(r => r.ruleId === ruleId).map(r => r.kind);

describe('第48回：差分の突き合わせ', () => {
  it('同じラベルのターゲットが2つから1つに減ったとき、確かめていないターゲットの指摘を「解消」にしない', () => {
    const before = evaluate(top('a.example', false) + top('b.example', true)).findings;
    const after = evaluate(top('b.example', true)).findings;
    const rows = diff(before, after);
    // a.example の H-01①（HSTS なし）は今回確かめていない
    expect(kinds(rows, 'H-01.1')).toEqual(['not-rechecked']);
    // b.example の変わっていない指摘は、新規にならない
    expect(rows.filter(r => r.kind === 'new')).toEqual([]);
  });
  it('同じ項目の別の条件を判定しただけで、確かめていない条件の指摘を「解消」にしない', () => {
    const tls = (lines: string) => `#TARGET url=https://www.example.com/ label=top\n${AT}\n${lines}\n`;
    const before = evaluate(`#TARGET url=https://www.example.com/ label=tls\n${AT}\n#TLSPROBE v=tls1 ok=1\n#TLSPROBE v=tls1_2 ok=1\n`).findings;
    const after = evaluate(tls('* Connected to www.example.com (192.0.2.1) port 443\n* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256\n> GET / HTTP/2\n>\n< HTTP/2 200\n<')).findings;
    expect(before.some(f => f.ruleId === 'T-09.1')).toBe(true);
    expect(kinds(diff(before, after), 'T-09.1')).toEqual(['not-rechecked']);
  });
});

describe('第48回：組織プロファイルの重要度', () => {
  it('API の応答で情報に下げた HTML 向けの指摘を、プロファイルの重要度で上げない', () => {
    const { profile } = parseProfile(JSON.stringify({ name: 'p', severity: { 'H-10': 'low' } }));
    const input = `#TARGET url=https://www.example.com/api/me label=api sensitive=1\n${AT}\nHTTP/2 200\ncontent-type: application/json\n\n{"id":1}\n`;
    const fs = runAll(parseInput(input).targets, { profile });
    const h10 = fs.filter(f => f.item === 'H-10' && f.status === 'fail');
    expect(h10.length).toBeGreaterThan(0);
    expect(h10.every(f => f.severity === 'info' && !f.originalSeverity)).toBe(true);
  });
});

describe('第48回：ラベルの *', () => {
  it('label=* は受け付けない（例外の照合で任意の文字列の意味になるため）', () => {
    const r = parseInput(`#TARGET url=https://www.example.com/ label=*\nHTTP/2 200\n\n`);
    expect(r.targets[0].label).toBe('invalid-label');
    expect(r.warnings.map(w => w.kind)).toContain('invalid-attr');
  });
});

describe('第48回（束3〜5のレビュー）：空白を含むラベルの差分', () => {
  const page = (host: string) => `#TARGET url=https://${host}/ label="top page"\n${AT}\nHTTP/2 200\ncontent-type: text/html\n\n<p>x</p>\n`;
  it('同じラベル（空白を含む）のターゲットが増えても、変わらない指摘を「解消」にしない', () => {
    const rows = diff(evaluate(page('a.example')).findings, evaluate(page('a.example') + page('b.example')).findings);
    expect(rows.filter(r => r.ruleId === 'H-01.1').map(r => r.kind).sort()).toEqual(['continuing', 'new']);
  });
});
