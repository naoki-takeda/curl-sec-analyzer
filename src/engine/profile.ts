// engine/profile.ts：組織プロファイル（v0.4）
import type { Finding, Profile, Severity } from '../model';
import { sessionConfig } from '../parser/setCookie';
import ITEMS from './items.json';

const SEV: Severity[] = ['high', 'medium', 'low', 'info'];
const ID = /^[HCRTEA]-\d\d(\.\d+)?$/;
/** チェックリストにある項目か（H-99 のような存在しない項目を、黙って受け付けない） */
const ITEM_IDS = new Set((ITEMS as { id: string }[]).map(i => i.id));
const knownItem = (id: string) => ID.test(id) && ITEM_IDS.has(id.replace(/\.\d+$/, ''));
const PROFILE_KEYS = ['name', 'severity', 'exclude', 'sessionCookieNames', 'sessionMaxAgeHours', 'trustedScriptOrigins'];
// 配列にする項目が配列でない（"exclude": "T-12"）なら、黙って空にせずエラーにする（既定の設定のまま判定したことに気づけなかった）
const notArray = (v: unknown) => v !== undefined && !Array.isArray(v);

export function parseProfile(text: string): { profile?: Profile; errors: string[] } {
  let d: Record<string, unknown>;
  try { d = JSON.parse(text); } catch { return { errors: ['JSONとして読めません'] }; }
  if (!d || typeof d !== 'object' || Array.isArray(d)) return { errors: ['オブジェクトが必要です'] };
  const errors: string[] = [];
  // 知らない項目（綴りの誤りの excludes・sessionCookieName など）も知らせる
  for (const k of Object.keys(d)) if (!PROFILE_KEYS.includes(k)) errors.push(`「${k.slice(0, 40)}」は組織プロファイルの項目ではありません`);
  const severity: Record<string, Severity> = {};
  const sevOk = d.severity === undefined || (!!d.severity && typeof d.severity === 'object' && !Array.isArray(d.severity));
  if (!sevOk) errors.push('severity：項目ID（例：H-10）と重要度の組のオブジェクトにしてください');
  for (const [k, v] of Object.entries(sevOk ? (d.severity as Record<string, unknown> | undefined) ?? {} : {})) {
    if (!knownItem(k)) errors.push(`severity：「${k.slice(0, 40)}」は項目IDではありません`);
    else if (!SEV.includes(v as Severity)) errors.push(`severity：「${k}」の重要度は high・medium・low・info のいずれか`);
    else severity[k] = v as Severity;
  }
  const exclude = Array.isArray(d.exclude) ? (d.exclude as unknown[]).filter((x): x is string => typeof x === 'string' && /^[HCRTEA]-\d\d$/.test(x) && knownItem(x)) : [];
  if (notArray(d.exclude) || (Array.isArray(d.exclude) && exclude.length !== d.exclude.length)) errors.push('exclude：項目ID（例：H-17）の配列にしてください');
  const names = Array.isArray(d.sessionCookieNames) ? (d.sessionCookieNames as unknown[]).filter((x): x is string => typeof x === 'string' && /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(x)) : [];
  const ORIGIN = /^(?:https?:\/\/)?(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d+)?$/i;
  const rawOrigins = Array.isArray(d.trustedScriptOrigins) ? d.trustedScriptOrigins as unknown[] : [];
  const origins = rawOrigins.filter((x): x is string => typeof x === 'string' && ORIGIN.test(x));
  if (notArray(d.trustedScriptOrigins) || origins.length !== rawOrigins.length) errors.push('trustedScriptOrigins：https://cdn.example.com や *.example.com の形の配列にしてください');
  if (notArray(d.sessionCookieNames) || (Array.isArray(d.sessionCookieNames) && names.length !== d.sessionCookieNames.length)) errors.push('sessionCookieNames：Cookie名（英数字と記号）の配列にしてください');
  // 数値だけを受け付ける（Number() で変換すると true が1時間、"12"・[12] が12時間になり、書き誤りに気づけなかった）
  const hours = d.sessionMaxAgeHours === undefined ? 24 : typeof d.sessionMaxAgeHours === 'number' ? d.sessionMaxAgeHours : NaN;
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

/**
 * 配信元が自社のものとして登録されているか（https://cdn.example.com・cdn.example.com・*.example.com、ポート付きの cdn.example.com:8443）。
 * ポートを書かない登録は、そのホストのどのポートにも当てはまる。書いた登録は、そのポートだけ（既定のポート :443・:80 は、書かないものと同じ。
 * URL の host は既定のポートを持たないので、https://cdn.example.com:443 の登録がどれにも当たらなかった。*.example.com は :8443 の配信元に当たらなかった）
 */
export function isTrustedOrigin(url: URL, list: string[] = []): boolean {
  const urlPort = url.port || (url.protocol === 'http:' ? '80' : '443');
  return list.some(e => {
    const m = e.match(/^(?:(https?):\/\/)?(.+?)(?::(\d+))?$/i)!;
    if (m[1] && `${m[1].toLowerCase()}:` !== url.protocol) return false;
    if (m[3] !== undefined && String(Number(m[3])) !== urlPort) return false;
    const host = m[2].toLowerCase(), h = url.hostname.toLowerCase();
    return host.startsWith('*.') ? h.endsWith(host.slice(1)) : h === host;
  });
}

/** 除外と重要度の上書きをまとめて行う（二重計上の除去を挟まない場合に使う） */
export const applyProfile = (fs: Finding[], p?: Profile): Finding[] => (p ? overrideSeverity(excludeItems(fs, p), p) : fs);
