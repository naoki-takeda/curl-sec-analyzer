// ルールが返す日本語の推奨対応に、英訳の漏れがないかを確かめる（TypeScript の構文木から文言を集める）
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import ts from 'typescript';
import { hasEnglish, recommendationEn } from '../src/recommendationsEn';
import { evaluate, sampleText } from './helpers';

/** 判定不能（na）で推奨対応が空のときは、証跡が診断カバレッジの理由になる。その証跡も集める */
function naReasons(): string[] {
  const dir = new URL('../src/rules/', import.meta.url);
  const out = new Set<string>();
  for (const f of readdirSync(dir).filter(x => x.endsWith('.ts'))) {
    const src = ts.createSourceFile(f, readFileSync(new URL(f, dir), 'utf8'), ts.ScriptTarget.Latest, true);
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && ['mk', 'hf', 'cf'].includes(n.expression.getText())) {
        const a = n.arguments;
        if (a[2]?.getText() === "'na'" && a[6] && ts.isStringLiteralLike(a[6]) && a[6].text === '' && a[5] && ts.isStringLiteralLike(a[5])) out.add(a[5].text);
      }
      ts.forEachChild(n, visit);
    };
    visit(src);
  }
  return [...out].filter(s => /[ぁ-んァ-ヶ一-龠]/.test(s));
}

function literals(): string[] {
  const dir = new URL('../src/rules/', import.meta.url);
  const out = new Set<string>();
  for (const f of readdirSync(dir).filter(x => x.endsWith('.ts'))) {
    const src = ts.createSourceFile(f, readFileSync(new URL(f, dir), 'utf8'), ts.ScriptTarget.Latest, true);
    const visit = (n: ts.Node): void => {
      // mk・hf・cf の7番目の引数、recommendation プロパティ、rec 変数
      if (ts.isCallExpression(n) && ['mk', 'hf', 'cf'].includes(n.expression.getText()) && n.arguments[6] && ts.isStringLiteralLike(n.arguments[6])) out.add(n.arguments[6].text);
      if (ts.isPropertyAssignment(n) && n.name.getText() === 'recommendation' && ts.isStringLiteralLike(n.initializer)) out.add(n.initializer.text);
      if (ts.isVariableDeclaration(n) && n.name.getText() === 'rec' && n.initializer && ts.isStringLiteralLike(n.initializer)) out.add(n.initializer.text);
      // 推奨対応の表（CSP_REC など、名前が _REC で終わるオブジェクト）
      if (ts.isVariableDeclaration(n) && /_REC$/.test(n.name.getText()) && n.initializer && ts.isObjectLiteralExpression(n.initializer))
        for (const p of n.initializer.properties) if (ts.isPropertyAssignment(p) && ts.isStringLiteralLike(p.initializer)) out.add(p.initializer.text);
      ts.forEachChild(n, visit);
    };
    visit(src);
  }
  return [...out].filter(s => /[ぁ-んァ-ヶ一-龠]/.test(s));
}

describe('推奨対応の英訳', () => {
  it('判定不能の理由（推奨対応が空のときの証跡）も、すべて英訳がある', () => {
    expect(naReasons().filter(s => !hasEnglish(s))).toEqual([]);
  });
  it('ルールの日本語の推奨対応は、すべて英訳がある', () => {
    const missing = literals().filter(s => !hasEnglish(s));
    expect(missing).toEqual([]);
  });
  it('実際の判定結果（テンプレートで作る文言を含む）も英訳できる', () => {
    const recs = evaluate(sampleText()).findings.map(f => f.recommendation).filter(Boolean);
    const missing = [...new Set(recs)].filter(r => /[ぁ-んァ-ヶ一-龠]/.test(recommendationEn(r)));
    expect(missing).toEqual([]);
  });
});

describe('診断カバレッジの英訳', () => {
  it('コマンドの案内は日本語と英語で同じ項目をそろえる', async () => {
    const { ITEM_COMMANDS, ITEM_COMMANDS_EN } = await import('../src/commands');
    expect(Object.keys(ITEM_COMMANDS_EN).sort()).toEqual(Object.keys(ITEM_COMMANDS).sort());
  });
  it('サンプルの診断カバレッジの理由は、すべて英訳できる', async () => {
    const { coverage } = await import('../src/engine/coverage');
    const { IMPLEMENTED } = await import('../src/rules/ruleset');
    const reasons = coverage(evaluate(sampleText()).findings, IMPLEMENTED).flatMap(c => c.reasons).filter(r => !/^v0\.|^MVP|^手動/.test(r));
    expect([...new Set(reasons)].filter(r => /[ぁ-んァ-ヶ一-龠]/.test(recommendationEn(r)))).toEqual([]);
  });
});
