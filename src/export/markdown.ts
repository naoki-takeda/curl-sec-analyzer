// export/markdown.ts：重要度順の表。常にマスク済みの値だけを出す。見出しと項目名は画面の言語に合わせる
import type { Coverage, Finding, Profile, Suppression } from '../model';
import { coverageRate } from '../engine/coverage';
import { circled, countBySeverity, overall } from '../engine/summarize';
import { type DiffRow, diffSummary } from '../engine/diff';
import { RULESET_VERSION, TOOL_VERSION } from '../rules/ruleset';
import { API_TOP10 } from '../rules/api';
import { ASVS_VERSION, IPA_EDITION, IPA_EDITION_EN, asvsLevel, standardsOf, standardsShort } from '../engine/standards';
import { covLabel, diffLabel, getLang, itemTitle, sevLabel } from '../i18n';
import { recommendationEn } from '../recommendationsEn';

// 証跡には診断対象のHTML（<img src=…> など）がそのまま入る。表示側でタグとして描画されないよう < > を実体参照にする
// 画像・リンクの記法（![…](…)、[…](…)）とコードの記号もエスケープする。診断対象の応答（server ヘッダなど）に書かれた画像が、
// レポートを開いたときに外部から読み込まれないようにするため。改行（CR だけの改行も、CommonMark では行の区切り）も空白にし、見出しなどを差し込めないようにする
// 裸の URL・www.・メールアドレスは、GitHub の Markdown（GFM の自動リンク）がリンクにする。診断対象のサーバが返した Location: https://evil.example/…
// がレポートの中のリンクになるので、ゼロ幅の空白（&#8203;）を挟んで自動リンクにしない（表示は変わらない）
const noAutolink = (s: string) => s.replace(/(?<![A-Za-z0-9])(https?|ftp)(?=:\/\/)/gi, '$1&#8203;').replace(/(?<![A-Za-z0-9])(www)(?=\.)/gi, '$1&#8203;').replace(/@/g, '&#8203;@');
const cell = (v: unknown) => noAutolink(String(v ?? '').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/[|[\]!`\\]/g, '\\$&').replace(/\r\n?|\n/g, ' '));
const ORDER = ['high', 'medium', 'low', 'info'];

export interface ReportExtras { profile?: Profile; diff?: { rows: DiffRow[]; baselineAt: string; rulesetWarning?: string }; }

export function toMarkdown(fs: Finding[], cov: Coverage[], suppressions: Suppression[], generatedAt = new Date(), extra: ReportExtras = {}): string {
  const en = getLang() === 'en';
  const c = countBySeverity(overall(fs)); const rate = coverageRate(cov);
  const L: string[] = [];
  L.push(en ? '# Security self-assessment results' : '# 自主セキュリティ診断の結果', '');
  L.push(`- ${en ? 'Generated' : '生成日時'}：${generatedAt.toISOString()}`, `- ${en ? 'Tool' : 'ツール'}：curl-sec-analyzer ${TOOL_VERSION}（${en ? 'ruleset' : 'ルールセット'} ${RULESET_VERSION}）`);
  if (extra.profile) L.push(`- ${en ? 'Organization profile' : '組織プロファイル'}：${cell(extra.profile.name) || '-'}`);
  L.push(`- ${en ? 'Findings (check × condition)' : '指摘（項目×条件）'}：${en ? 'High' : '高'} ${c.high}、${en ? 'Medium' : '中'} ${c.medium}、${en ? 'Low' : '低'} ${c.low}、${en ? 'Info' : '情報'} ${c.info}`);
  L.push(`- ${en ? 'Coverage' : '診断カバレッジ'}：${rate.evaluated} / ${rate.denominator}`, '');
  if (extra.diff) {
    const s = diffSummary(extra.diff.rows);
    L.push(en ? '## Changes since previous results' : '## 前回との差分', '', `${en ? 'Previous' : '前回'}：${cell(extra.diff.baselineAt) || '-'}`, '');
    if (extra.diff.rulesetWarning) L.push(`> ${cell(extra.diff.rulesetWarning)}`, '');
    L.push(`- ${(['new', 'resolved', 'severity-changed', 'suppressed', 'not-rechecked', 'continuing'] as const).map(k => `${diffLabel(k)} ${s[k]}`).join('、')}`, '');
    L.push(`| ${en ? 'Change' : '変化'} | ${en ? 'Severity' : '重要度'} | ${en ? 'Check' : '項目'} | ${en ? 'Target' : 'ターゲット'} |`, '| --- | --- | --- | --- |');
    for (const r of extra.diff.rows.filter(x => x.kind !== 'continuing'))
      L.push(`| ${diffLabel(r.kind)} | ${sevLabel(r.severity)}${r.before ? `（${en ? 'was' : '前回'} ${sevLabel(r.before)}）` : ''} | ${r.item}${circled(r.condition)} ${cell(itemTitle(r.item, r.title))} | ${cell(r.target)} |`);
    L.push('');
  }
  L.push(en ? '## Findings' : '## 指摘', '', `| ${en ? 'Severity' : '重要度'} | ${en ? 'Check' : '項目'} | ${en ? 'Target' : '対象'} | ${en ? 'Evidence (masked)' : '証跡（マスク済み）'} | ${en ? 'Recommendation' : '推奨対応'} |`, '| --- | --- | --- | --- | --- |');
  for (const f of fs.filter(x => x.status === 'fail').sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity)))
    L.push(`| ${sevLabel(f.severity)}${f.originalSeverity ? `*` : ''} | ${f.item}${circled(f.condition)} ${cell(itemTitle(f.item, f.title))}${API_TOP10[f.item] ? `（OWASP ${API_TOP10[f.item]}）` : ''}${standardsShort(f.item) ? `（${cell(standardsShort(f.item))}）` : ''} | ${cell(f.target)}${f.url ? `（${cell(f.url)}）` : ''} | ${cell(f.evidence)} | ${cell(en ? recommendationEn(f.recommendation) : f.recommendation)} |`);
  if (fs.some(f => f.originalSeverity)) L.push('', en ? '\\* Severity changed by the organization profile.' : '\\* 組織プロファイルで重要度を変えた指摘。');
  const sup = fs.filter(f => f.status === 'suppressed');
  if (sup.length) {
    L.push('', en ? '## Exceptions' : '## 例外として扱った指摘', '', `| ${en ? 'Check' : '項目'} | ${en ? 'Target' : '対象'} | ${en ? 'Reason' : '理由'} | ${en ? 'Approver' : '承認者'} | ${en ? 'Expires' : '期限'} |`, '| --- | --- | --- | --- | --- |');
    for (const f of sup) L.push(`| ${f.item}${circled(f.condition)} | ${cell(f.target)} | ${cell(f.suppressedBy!.reason)} | ${cell(f.suppressedBy!.approver)} | ${cell(f.suppressedBy!.until) || '—'} |`);
  }
  L.push('', en ? '## Coverage' : '## 診断カバレッジ', '',
    en ? `ASVS: related requirements of OWASP ASVS ${ASVS_VERSION} (cite as v${ASVS_VERSION}-<ID>; L = level). IPA: ${IPA_EDITION_EN}. These are related requirements, not a verdict on whether they are met.`
       : `ASVS：OWASP ASVS ${ASVS_VERSION} の関連する要件（引用は v${ASVS_VERSION}-<ID>。L はレベル）。IPA：${IPA_EDITION}の項番。どちらも関連する要件で、その要件を満たすかどうかの判定ではありません。`, '',
    `| ${en ? 'Check' : '項目'} | ${en ? 'Description' : '内容'} | ${en ? 'Status' : '区分'} | ${en ? 'Reason / input needed' : '理由・必要な入力'} | ASVS ${ASVS_VERSION} | IPA |`, '| --- | --- | --- | --- | --- | --- |');
  for (const x of cov) {
    const s = standardsOf(x.item);
    L.push(`| ${x.item} | ${cell(itemTitle(x.item, x.title))} | ${covLabel(x.status)} | ${cell((en ? x.reasons.map(recommendationEn) : x.reasons).join(en ? '; ' : '、'))} | ${s.asvs.map(a => `${a} (L${asvsLevel(a)})`).join(', ') || '—'} | ${cell(s.ipa.join(', ')) || '—'} |`);
  }
  if (suppressions.length) L.push('', `${en ? 'Registered exceptions' : '登録済みの例外'}：${suppressions.length}`);
  L.push('', en ? '> A pass covers only what could be checked. It does not mean the system is secure.' : '> 合格は、判定できた範囲での結果です。安全であることの保証にはなりません。');
  return L.join('\n') + '\n';
}
