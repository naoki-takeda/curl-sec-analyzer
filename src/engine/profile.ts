// engine/profile.ts：組織プロファイル（v0.4）
import type { Finding, Profile, Severity } from '../model';
import { sessionConfig } from '../parser/setCookie';

const SEV: Severity[] = ['high', 'medium', 'low', 'info'];
const ID = /^[HCRTEA]-\d\d(\.\d+)?$/;

export function parseProfile(text: string): { profile?: Profile; errors: string[] } {
  let d: Record<string, unknown>;
  try { d = JSON.parse(text); } catch { return { errors: ['JSONとして読めません'] }; }
  if (!d || typeof d !== 'object' || Array.isArray(d)) return { errors: ['オブジェクトが必要です'] };
  const errors: string[] = [];
  const severity: Record<string, Severity> = {};
  for (const [k, v] of Object.entries((d.severity as Record<string, unknown>) ?? {})) {
    if (!ID.test(k)) errors.push(`severity：「${k}」は項目IDではありません`);
    else if (!SEV.includes(v as Severity)) errors.push(`severity：「${k}」の重要度は high・medium・low・info のいずれか`);
    else severity[k] = v as Severity;
  }
  const exclude = Array.isArray(d.exclude) ? (d.exclude as unknown[]).filter((x): x is string => typeof x === 'string' && /^[HCRTEA]-\d\d$/.test(x)) : [];
  if (Array.isArray(d.exclude) && exclude.length !== d.exclude.length) errors.push('exclude：項目ID（例：H-17）の配列にしてください');
  const names = Array.isArray(d.sessionCookieNames) ? (d.sessionCookieNames as unknown[]).filter((x): x is string => typeof x === 'string' && /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(x)) : [];
  const ORIGIN = /^(?:https?:\/\/)?(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d+)?$/i;
  const rawOrigins = Array.isArray(d.trustedScriptOrigins) ? d.trustedScriptOrigins as unknown[] : [];
  const origins = rawOrigins.filter((x): x is string => typeof x === 'string' && ORIGIN.test(x));
  if (origins.length !== rawOrigins.length) errors.push('trustedScriptOrigins：https://cdn.example.com や *.example.com の形の配列にしてください');
  if (Array.isArray(d.sessionCookieNames) && names.length !== d.sessionCookieNames.length) errors.push('sessionCookieNames：Cookie名（英数字と記号）の配列にしてください');
  const hours = d.sessionMaxAgeHours === undefined ? 24 : Number(d.sessionMaxAgeHours);
  const hoursOk = hours > 0 && hours <= 24 * 400;
  if (!hoursOk) errors.push('sessionMaxAgeHours は 1 以上 9600 以下の時間数にしてください（既定の24時間を使います）');
  // エラーにした値は使わない（既定値に戻す）
  return { profile: { name: typeof d.name === 'string' ? d.name.slice(0, 100) : '', severity, exclude, sessionCookieNames: names, sessionMaxAgeHours: hoursOk ? hours : 24, trustedScriptOrigins: origins }, errors };
}

/** 実行中だけプロファイルのセッション設定を有効にする */
export function withProfile<T>(p: Profile | undefined, fn: () => T): T {
  const saved = { ...sessionConfig, names: [...sessionConfig.names] };
  if (p) { sessionConfig.names = p.sessionCookieNames; sessionConfig.maxAgeHours = p.sessionMaxAgeHours; }
  try { return fn(); } finally { Object.assign(sessionConfig, saved); }
}

/** 対象外の項目を除く。二重計上の除去より前に行う（除外した項目の代わりに数えられている指摘を、数えない扱いにしないため） */
export function excludeItems(fs: Finding[], p?: Profile): Finding[] {
  if (!p?.exclude.length) return fs;
  const ex = new Set(p.exclude);
  return fs.filter(f => !ex.has(f.item));
}

/** 重要度を上書きする（条件の指定が項目の指定より優先） */
export function overrideSeverity(fs: Finding[], p?: Profile): Finding[] {
  if (!p) return fs;
  return fs.map(f => {
    if (f.status !== 'fail' && f.status !== 'suppressed') return f;
    const s = (f.condition !== undefined ? p.severity[`${f.item}.${f.condition}`] : undefined) ?? p.severity[f.item];
    return s && s !== f.severity ? { ...f, severity: s, originalSeverity: f.severity } : f;
  });
}

export const profileTemplate = (): string => JSON.stringify({
  name: '組織名・プロファイル名',
  severity: { 'H-10': 'low', 'H-14.1': 'info' },
  exclude: ['T-12'],
  sessionCookieNames: ['APPSESSION'],
  sessionMaxAgeHours: 12,
  trustedScriptOrigins: ['https://assets.example.com'],
}, null, 2);

/** 配信元が自社のものとして登録されているか（https://cdn.example.com・cdn.example.com・*.example.com） */
export function isTrustedOrigin(url: URL, list: string[] = []): boolean {
  return list.some(e => {
    const m = e.match(/^(?:(https?):\/\/)?(.+)$/i)!;
    if (m[1] && `${m[1].toLowerCase()}:` !== url.protocol) return false;
    const host = m[2].toLowerCase();
    return host.startsWith('*.') ? url.host.endsWith(host.slice(1)) : url.host === host;
  });
}

/** 除外と重要度の上書きをまとめて行う（二重計上の除去を挟まない場合に使う） */
export const applyProfile = (fs: Finding[], p?: Profile): Finding[] => (p ? overrideSeverity(excludeItems(fs, p), p) : fs);
