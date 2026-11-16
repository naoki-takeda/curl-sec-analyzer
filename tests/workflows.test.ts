// .github の下の YAML（ワークフロー、Dependabot、Issue テンプレート）が構文として読めること。
// ワークフローは GitHub でしか動かせないため、少なくとも構文と、主要な設定が意図どおりかをここで確かめる
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { parse } from 'yaml';

const dir = new URL('../.github/', import.meta.url);
const workflows = readdirSync(new URL('workflows/', dir)).filter(f => /\.ya?ml$/.test(f)).map(f => `workflows/${f}`);
const files = [...workflows, 'dependabot.yml', ...readdirSync(new URL('ISSUE_TEMPLATE/', dir)).map(f => `ISSUE_TEMPLATE/${f}`)];
const read = (f: string) => readFileSync(new URL(f, dir), 'utf8');

type Step = { uses?: string; run?: string; with?: Record<string, unknown>; env?: Record<string, string> };
type Job = { permissions?: Record<string, string>; steps?: Step[]; uses?: string; with?: Record<string, unknown> };
const load = (f: string) => parse(read(f)) as { permissions?: unknown; jobs: Record<string, Job> };

describe('.github の YAML', () => {
  for (const f of files) it(`${f} が読める`, () => { expect(() => parse(read(f))).not.toThrow(); });

  it('共通の検査（checks.yml）：読み取りの権限だけで、認証情報を残さず、署名の検証・lint・単体テスト・ビルド・E2E を実行する', () => {
    const wf = load('workflows/checks.yml');
    expect(wf.permissions).toEqual({});
    const job = wf.jobs.check;
    expect(job.permissions).toEqual({ contents: 'read' });
    const steps = job.steps!;
    expect(steps.find(s => s.uses?.startsWith('actions/checkout@'))?.with?.['persist-credentials']).toBe(false);
    expect(steps.find(s => s.uses?.startsWith('actions/setup-node@'))?.with?.['node-version-file']).toBe('.nvmrc');
    const runs = steps.flatMap(s => s.run ?? []);
    // インストールスクリプトを動かす前に署名を検証する
    expect(runs.indexOf('npm ci --ignore-scripts')).toBeLessThan(runs.indexOf('npm run audit:signatures'));
    for (const r of ['npm run audit:deps', 'npm run lint', 'npm test', 'npx playwright test']) expect(runs).toContain(r);
    expect(steps.some(s => s.uses?.startsWith('actions/configure-pages'))).toBe(false);   // pages の権限を要する処理を入れない
    expect(steps.find(s => s.run === 'npm run build')?.env?.SITE_URL).toContain('github.io');
    expect(runs.find(r => r.startsWith('npx playwright install'))).toContain('firefox webkit');
    // E2E のレポートは失敗したときだけ保存する（成功時に成果物を残さない）
    const report = steps.find(s => s.uses?.startsWith('actions/upload-artifact@')) as Step & { if?: string };
    expect(report.with?.path).toBe('playwright-report/');
    expect(report.if).toContain("steps.e2e.outcome == 'failure'");
  });

  it('CI はプルリクエストで共通の検査を呼ぶ', () => {
    const wf = load('workflows/ci.yml');
    expect(wf.permissions).toEqual({});
    expect(wf.jobs.check.uses).toBe('./.github/workflows/checks.yml');
    expect(wf.jobs.check.permissions).toEqual({ contents: 'read' });
  });

  it('デプロイ：検査に通った dist だけを公開し、公開のジョブだけが Pages に書き込める', () => {
    const wf = load('workflows/deploy.yml');
    expect(wf.permissions).toEqual({});
    expect(wf.jobs.build.uses).toBe('./.github/workflows/checks.yml');
    expect(wf.jobs.build.permissions).toEqual({ contents: 'read' });
    expect(wf.jobs.build.with?.['upload-pages']).toContain("refs/heads/main");
    expect(wf.jobs.deploy.permissions).toEqual({ pages: 'write', 'id-token': 'write' });
  });

  it('外部の Action はすべてコミットSHAで固定し、バージョンをコメントに書く', () => {
    for (const f of workflows) {
      for (const line of read(f).split('\n').filter(l => /^\s*(-\s+)?uses:/.test(l))) {
        const ref = line.replace(/^\s*(-\s+)?uses:\s*/, '');
        if (ref.startsWith('./')) continue;
        expect(ref, `${f}: ${ref}`).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/);
      }
    }
  });

  it('どのワークフローも既定の権限を無効にし、checkout で認証情報を残さない', () => {
    for (const f of workflows) {
      const wf = load(f);
      expect(wf.permissions, f).toEqual({});
      for (const job of Object.values(wf.jobs)) {
        for (const s of job.steps ?? []) if (s.uses?.startsWith('actions/checkout@')) expect(s.with?.['persist-credentials'], f).toBe(false);
      }
    }
  });
});
