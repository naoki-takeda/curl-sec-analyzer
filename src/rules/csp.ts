// rules/csp.ts：Google csp_evaluator（Apache-2.0）で CSP を評価し、チェックリストの項目・条件に振り分ける
// csp_evaluator の指摘のうち「〜かもしれない」（HIGH_MAYBE・MEDIUM_MAYBE。'self' や未知のホストへの注意など）は、誤検知が多いため使わない。
// 'unsafe-hashes'（SCRIPT_UNSAFE_HASHES）は MEDIUM_MAYBE だが、同じディレクティブにハッシュがあるときだけ H-04⑥ の情報として出す（'unsafe-inline' より
// 安全で、ハッシュの合うイベントハンドラ・style 属性だけを許す。ハッシュがなければ何も許さないので指摘しない）。
// Strict CSP の推奨（STRICTCSP_CHECKS）は実行しない（evaluate() の既定のチェックだけを使う）
import { CspEvaluator } from 'csp_evaluator/dist/evaluator.js';
import { CspParser } from 'csp_evaluator/dist/parser.js';
import { Severity as EvSeverity, Type } from 'csp_evaluator/dist/finding.js';
import type { Severity } from '../model';

export interface CspIssue {
  item: 'H-04' | 'H-05' | 'H-07'; condition: number; severity: Severity;
  directive: string; value?: string; type: string;
}

const SCRIPT_DIRECTIVES = new Set(['script-src', 'script-src-elem', 'script-src-attr']);
const sevOf = (s: EvSeverity): Severity => (s === EvSeverity.HIGH ? 'high' : s === EvSeverity.MEDIUM ? 'medium' : 'info');

/** csp_evaluator が評価の途中で例外を出したポリシーの指摘の種類（H-07④ として出し、H-04 は合格にしない） */
export const EVALUATOR_ERROR = 'EVALUATOR_ERROR';

/**
 * 1つのポリシー（ヘッダ値1つ）を評価する。
 * csp_evaluator は値を new URL() で解釈するため、`img-src data:image/svg+xml` のような値で例外を出す。
 * 値は診断対象のサーバが決めるので、例外で判定全体を止めず、H-07④（構文）の指摘にする
 */
export function evaluateCsp(policy: string): CspIssue[] {
  try { return evaluateCspUnsafe(policy); }
  catch {
    return [{ item: 'H-07', condition: 4, severity: 'low', directive: '(ポリシー全体)', type: EVALUATOR_ERROR }];
  }
}

function evaluateCspUnsafe(policy: string): CspIssue[] {
  const csp = new CspParser(policy).csp;
  const out: CspIssue[] = [];
  // default-src の指摘は、フォールバックする先（script-src・object-src がないとき）の項目にだけ振り分ける。
  // script-src があれば default-src * でもスクリプトは制限されている（H-04 ではない）。object-src がなければ default-src * は H-05①
  const has = (d: string) => csp.directives[d] !== undefined;
  const isScriptDir = (d: string) => SCRIPT_DIRECTIVES.has(d) || (d === 'default-src' && !has('script-src'));
  const isObjectDir = (d: string) => d === 'object-src' || (d === 'default-src' && !has('object-src'));
  for (const f of new CspEvaluator(csp).evaluate()) {
    const maybe = f.severity === EvSeverity.HIGH_MAYBE || f.severity === EvSeverity.MEDIUM_MAYBE;
    // 'unsafe-eval' は csp_evaluator では MEDIUM_MAYBE だが、チェックリスト（H-04③）では中として扱う
    if ((maybe && f.type !== Type.SCRIPT_UNSAFE_EVAL && f.type !== Type.SCRIPT_UNSAFE_HASHES) || f.severity === EvSeverity.NONE) continue;
    const base = { directive: f.directive, value: f.value, type: Type[f.type] ?? String(f.type) };
    const isScript = isScriptDir(f.directive);
    switch (f.type) {
      case Type.SCRIPT_UNSAFE_INLINE: out.push({ ...base, item: 'H-04', condition: 1, severity: 'high' }); break;
      case Type.PLAIN_URL_SCHEMES: case Type.PLAIN_WILDCARD: case Type.SRC_HTTP:
        // default-src はスクリプトと object の両方のフォールバック先になりうるので、両方に出す
        if (isScript) out.push({ ...base, item: 'H-04', condition: 2, severity: 'high' });
        if (isObjectDir(f.directive)) out.push({ ...base, item: 'H-05', condition: 1, severity: 'medium' });
        break;
      // base-uri のなさ（H-05②）は rules/headers.ts で見る（csp_evaluator は nonce・hash のあるポリシーでしか指摘しない）
      case Type.MISSING_DIRECTIVES:
        if (f.directive === 'script-src') out.push({ ...base, item: 'H-04', condition: 2, severity: 'high' });
        else if (f.directive === 'object-src') out.push({ ...base, item: 'H-05', condition: 1, severity: 'medium' });
        break;
      case Type.SCRIPT_UNSAFE_EVAL: out.push({ ...base, item: 'H-04', condition: 3, severity: 'medium' }); break;
      case Type.SCRIPT_ALLOWLIST_BYPASS: out.push({ ...base, item: 'H-04', condition: 4, severity: 'medium' }); break;   // JSONP・AngularJS を置くホスト
      case Type.OBJECT_ALLOWLIST_BYPASS: out.push({ ...base, item: 'H-05', condition: 1, severity: 'medium' }); break;
      case Type.DEPRECATED_DIRECTIVE: out.push({ ...base, item: 'H-07', condition: 1, severity: 'low' }); break;
      // csp_evaluator が知らない、仕様にある新しいディレクティブ（fenced-frame-src など）は、未知のディレクティブにしない
      case Type.UNKNOWN_DIRECTIVE: if (NEW_DIRECTIVES.has(f.directive)) break;
        out.push({ ...base, item: 'H-07', condition: 4, severity: 'low' }); break;
      case Type.MISSING_SEMICOLON: case Type.INVALID_KEYWORD: case Type.NONCE_CHARSET:
        out.push({ ...base, item: 'H-07', condition: 4, severity: 'low' }); break;
      // イベントハンドラに効くディレクティブ（script-src-attr、なければ script-src、なければ default-src）のものだけ（script-src-attr 'none' が
      // あれば、script-src・default-src の 'unsafe-hashes' はハンドラを許さない。script-src-elem では意味がない）
      case Type.SCRIPT_UNSAFE_HASHES:
        if (f.directive === (has('script-src-attr') ? 'script-src-attr' : has('script-src') ? 'script-src' : 'default-src')
          && (csp.directives[f.directive] ?? []).some(v => HASH_SOURCE.test(v))) out.push({ ...base, item: 'H-04', condition: 6, severity: 'info' });
        break;
      case Type.NONCE_LENGTH: case Type.IP_SOURCE:
        if (isScript) out.push({ ...base, item: 'H-04', condition: 6, severity: sevOf(f.severity) });
        break;
      default: break;
    }
  }
  return out;
}

/** ハッシュのソース（'sha256-…'。引用符と大文字・小文字は CSP の仕様のとおり） */
const HASH_SOURCE = /^'sha(?:256|384|512)-/i;

/** csp_evaluator の一覧（Directive）にない、CSP の仕様（Level 3 と関連仕様）にあるディレクティブ */
const NEW_DIRECTIVES = new Set(['fenced-frame-src']);

/** 証跡：ディレクティブと値、csp_evaluator の指摘の種類 */
export const issueEvidence = (i: CspIssue) => `${i.directive}${i.value ? ` ${i.value}` : ''}（csp_evaluator: ${i.type}）`;
