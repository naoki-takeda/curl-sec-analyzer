import type { HttpResponse, ParseWarning, ResponseKind, Target } from '../model';

/** 付け直したラベル（http#2 など）の元のラベル。ラベル対応表やラベルで判定を変えるルールは、この元のラベルで判定する */
export const baseLabel = (label: string) => label.replace(/#\d+$/, '');

/**
 * 同じラベルのターゲットを分ける（2つ目以降を「top#2」などにする）。適用する項目は元のラベルと同じ（baseLabel）。
 * 結果の表示・二重計上の除去・差分・例外はラベルで突き合わせるため、同じラベルのままだと別の応答の指摘が混ざる。
 * 横断ルール（pre-login と login の比較など）は最初のものだけを使う。curl の貼り付けと HAR を合わせたあとにも呼ぶ
 */
export function uniqueLabels(targets: Target[]): ParseWarning[] {
  const used = new Set(targets.map(t => t.label)); const seen = new Set<string>(); const renamed = new Map<string, string[]>();
  for (const t of targets) {
    if (!seen.has(t.label)) { seen.add(t.label); continue; }
    let n = 2; while (used.has(`${t.label}#${n}`)) n++;
    const to = `${t.label}#${n}`;
    renamed.set(t.label, [...(renamed.get(t.label) ?? []), to]);
    used.add(to); seen.add(to); t.label = to;
  }
  return [...renamed].map(([l, tos]) => ({ kind: 'duplicate-label', detail:
    `ラベル「${l}」のターゲットが${tos.length + 1}つあります。2つ目以降は ${tos.join('、')} として別に判定しました（横断の判定には最初のものだけを使います）` }));
}

export const finalResponse = (t: Target): HttpResponse | undefined =>
  t.responses.filter(x => x.kind !== 'informational' && x.kind !== 'connect').at(-1);   // -L なら最終ホップ

export const chainOf = (t: Target): HttpResponse[] =>
  t.responses.filter(x => x.kind !== 'informational' && x.kind !== 'connect');

/**
 * curl の出力の各ホップに、そのリクエストの URL を付ける（HAR は取り込みで付ける）。ターゲットの URL から Location をたどる。
 * -L で http から同じホストの https に転送されたかを、isHttps と ownChain が判定するのに使う
 */
export function assignHopUrls(t: Target): void {
  let cur = t.url;
  for (const r of chainOf(t)) {
    if (!cur) return;
    r.url ??= cur;
    if (r.kind !== 'redirect') return;
    try { const n = new URL(r.headers.get('location')![0], cur); n.hash = ''; cur = n.href; } catch { return; }
  }
}

/**
 * http の URL で採取し、-L で同じホストの https に転送された（最後のホップが https）。http ラベル（T-04）以外は、HTTPS の応答として判定する。
 * URL が http のままだと、H-・C- の項目がすべて黙って適用外になる（HAR では取り込みでターゲットの URL を https にしている）
 */
const upgradedToHttps = (t: Target): boolean => {
  if (baseLabel(t.label) === 'http' || !/^http:/i.test(t.url ?? '')) return false;
  const last = chainOf(t).at(-1)?.url;
  try { return !!last && new URL(last).protocol === 'https:' && new URL(last).hostname === new URL(t.url!).hostname; } catch { return false; }
};

/**
 * そのターゲットの URL 自身の応答から始まるチェーン。http から https に転送されたチェーン（HAR はターゲットの URL を https にする。
 * curl は upgradedToHttps）は、最初の https のホップから始める（apex の「自身の応答」や、E-05・E-11 の「そのURLの応答」に http の転送を使わないため）
 */
export function ownChain(t: Target): HttpResponse[] {
  const c = chainOf(t);
  if (!/^https:/i.test(t.url ?? '') && !upgradedToHttps(t)) return c;
  const i = c.findIndex(r => /^https:/i.test(r.url ?? ''));
  return i > 0 ? c.slice(i) : c;
}

export function isHttps(t: Target): boolean | undefined {
  const u = t.url ?? t.meta.url_effective;
  if (u) return /^https:\/\//i.test(u) || upgradedToHttps(t);   // スキームは大文字小文字を区別しない（HTTPS://…）
  if (t.info.some(l => /SSL connection using|ALPN:/.test(l))) return true;
  if (t.info.some(l => /^(?:Connected to|Established connection to) .* port 80\b/.test(l))) return false;   // 今の curl は Established connection to とも出す
  return undefined;
}

export function responseKind(t: Target, r?: HttpResponse): ResponseKind {
  if (t.kind !== 'auto') return t.kind;
  const ct = r?.headers.get('content-type')?.[0]?.toLowerCase() ?? '';
  if (/^application\/(?:[\w.-]+\+)?json\b/.test(ct)) return 'api';
  if (ct.startsWith('text/html')) return 'html';
  return 'other';
}

// 第0章 0.3：明示 > 送信側のCookie/Authorization > 不明
export const isSensitive = (t: Target): boolean | undefined => t.sensitive ?? (t.sentAuth ? true : undefined);

/**
 * 期限（Cookie の Expires、証明書の notAfter など）を比べる基準の時刻。採取した時刻（#META at、HAR の startedDateTime）があればそれを使う。
 * 判定した時刻を使うと、前に採取した出力を読み直したときに、採取時には有効だった期限を「切れている」と判定してしまうため。
 * #META at がなければ、応答の Date ヘッダ（サーバが応答した時刻）を使う。どちらもなければ判定した時刻
 */
export function capturedAt(t: Target): number {
  const at = t.meta.at ? Date.parse(t.meta.at) : NaN;   // 「2026-11-12T10:00:00」（タイムゾーンなし）は手元の時刻として読む
  if (!Number.isNaN(at)) return at;
  for (const r of t.responses) {
    const d = Date.parse(r.headers.get('date')?.[0] ?? '');
    if (!Number.isNaN(d)) return d;
  }
  return Date.now();
}

export function hostOf(t: Target): string | undefined {
  const u = t.url ?? t.meta.url_effective;
  try { return u ? new URL(u).host : undefined; } catch { return undefined; }
}

/** そのURL自身の最初の応答のステータス（分からなければ0） */
export const firstStatus = (t: Target): number => ownChain(t)[0]?.status ?? 0;
/**
 * ログアウトの応答が失敗（4xx・5xx）しているか。GET の /logout に 405 を返すアプリなどでは、ログアウトしていないので、
 * C-12（ログアウト後の無効化・Cookie の削除）と H-15 を判定しない
 */
export const logoutFailed = (t: Target): boolean => firstStatus(t) >= 400;
