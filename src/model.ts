// model.ts：型定義（ターゲット、ルール、指摘、例外、組織プロファイルなど）
export type Severity = 'high' | 'medium' | 'low' | 'info';
export type Status = 'pass' | 'fail' | 'na' | 'suppressed';
export type ResponseKind = 'html' | 'api' | 'other';
export const RESERVED_LABELS = ['http', 'apex', 'pre-login', 'login', 'logout', 'after-logout'] as const; // ほかに session-sample-N

export interface HttpResponse {
  httpVersion: string; status: number; reason?: string;
  headers: Map<string, string[]>;   // 名前は小文字
  rawNames: string[];               // 表示用の元の表記
  body?: string;                    // 先頭64KBまで
  // challenge：curl が認証し直した 401（--digest・--ntlm・--negotiate・--anyauth）。connect にはプロキシの 407 も含む
  kind: 'final' | 'redirect' | 'informational' | 'connect' | 'challenge';
  url?: string;                     // そのホップのリクエストのURL（HAR は記録から、curl はターゲットの URL から Location をたどって付ける）
}
export interface ParseWarning {
  kind: 'unparsed-lines' | 'orphan-block' | 'unknown-url' | 'tls-probe-error' | 'har-excluded' | 'har-sanitized' | 'duplicate-label' | 'ignored-marker' | 'proxy-only' | 'invalid-attr';
  detail: string;
  label?: string;                   // unknown-url：URLが分からないターゲットのラベル（画面のURL欄で補ったものだけ警告を消すため）
}
export interface ParseResult { targets: Target[]; warnings: ParseWarning[]; }
export interface Probe { path: string; code: number; size: number; contentType: string; headB64: string; }
export interface CipherProbe { cipher: string; result: 'accepted' | 'rejected' | 'error'; }
export interface TlsProbe { version: string; result: 'accepted' | 'rejected' | 'error'; }
export interface Target {
  label: string; url?: string; kind: 'html' | 'api' | 'auto'; sensitive?: boolean;
  verbose: boolean;                 // * Connected to などを検出したら true
  responses: HttpResponse[]; sentOrigin?: string; info: string[];
  /** 機密応答の推定（第0章 0.3②）：Authorization か、セッションCookieらしい名前の Cookie を送った。組織プロファイルの名前で engine/run.ts が作り直す */
  sentAuth: boolean;
  sentAuthorization?: boolean; sentCookieNames?: string[];   // 送った Authorization の有無と Cookie の名前（値は持たない。-v と HAR だけ）
  /** ブラウザが自動で送る方式（Basic・Digest・Negotiate・NTLM）の Authorization を送った。Bearer はページのスクリプトが付けるので、クロスサイトで送られない（R-09） */
  sentAutoAuth?: boolean;
  sentTokens: string[];             // -v の送信ヘッダにあったJWT。A-03 のデコードにだけ使い、画面・エクスポートには出さない
  meta: Record<string, string>; probes: Probe[]; tlsProbes: TlsProbe[]; cipherProbes: CipherProbe[]; openssl: string[];
}
export interface RuleContext {
  target: Target; final?: HttpResponse; chain: HttpResponse[];
  isHttps?: boolean; responseKind: ResponseKind; sensitive?: boolean;
  hostHsts?: boolean;               // 同じホストでHSTSが有効か（C-01②③が使う。ツール設計2「ルール間の依存」）
  hostSessionSameSite?: boolean;    // 同じホストのセッションCookieがすべて SameSite=Lax/Strict か（E-12 が使う。見えなければ undefined）
  profile?: Profile;                // 組織プロファイル（E-08 の自社の配信元など）
  now: number;                      // 期限の判定に使う時刻（採取時刻 #META at、なければ判定した時刻）。parser/target.ts の capturedAt
  findings: Finding[];
}
export interface CrossContext {     // ホスト単位・横断ルール用
  targets: Target[]; byLabel(label: string): Target | undefined; withPrefix(prefix: string): Target[];
  byHost(): Map<string, Target[]>; findings: Finding[];
}
export type CoverageStatus = 'evaluated' | 'missing-input' | 'manual' | 'not-implemented' | 'excluded';
export interface ItemInfo {
  id: string; title: string; titleEn: string; chapter: number; manual: boolean; phase: string;   // 必要なラベルは engine/labels.ts の requiredLabels で作る
  asvs: string[];                   // 関連する OWASP ASVS 5.0.0 の要件ID（例：3.4.1）。engine/standards.ts
  ipa: string[];                    // 関連する IPA「安全なウェブサイトの作り方」改訂第7版の項番（例：4-(iii)、2.3-1)）
}
export interface Coverage { item: string; title: string; chapter: number; status: CoverageStatus; reasons: string[]; fails: number; }
/** 例外登録（suppressions.json の1件） */
export interface Suppression {
  ruleId: string;                   // 項目ID（H-01）か条件（H-01.1）
  target: string;                   // ラベル、または URL のパターン（* は任意の文字列）
  reason: string; approver: string;
  until: string;                    // 期限（YYYY-MM-DD）。過ぎると無効になり fail に戻る
}
export interface Finding {
  ruleId: string;                   // 例: H-01.1 / H-01.ok / H-01.na
  item: string;                     // 例: H-01
  condition?: number;               // 例: 1（①）
  obsId?: string; title: string; severity: Severity; status: Status;
  target: string; url?: string; host?: string;
  partial?: boolean;                // 横断・ホスト単位の条件が入力不足で na（診断カバレッジで「一部の条件は入力不足」と示す）
  limited?: boolean;                // 機密でない応答（静的リソースなど）だけで判定した（H-12。項目のすべてがこれなら、カバレッジで「機密応答では判定していない」と示す）
  keyUrl?: string;                  // 対象の URL の突き合わせのキー（engine/targetKey.ts の urlKey。マスクした url ではなく生の URL から作る。例外の「ラベル URL」の照合に使う）
  targetKey?: string;               // 差分・例外の突き合わせに使う。curl はラベル（同じラベルが複数あれば「元のラベル＋URL」）、HAR は「メソッド＋URL（engine/targetKey.ts の urlKey。マスクとは別に作る）」
  evidence: string; recommendation: string; references: string[];
  score: number;                    // obsId があるルール以外は常に0
  suppressedBy?: Suppression;       // 例外に該当したとき
  originalSeverity?: Severity;      // 組織プロファイルで重要度を変えたときの元の重要度
  dedupedBy?: string;               // 二重計上を防ぐため、別のルールID（例：A-09.2）で数えたとき。status は na になる
}
/** 組織プロファイル（profile.json）：組織ごとの重要度、対象外の項目、セッションCookieの指定 */
export interface Profile {
  name: string;
  severity: Record<string, Severity>;     // 項目ID（H-10）か条件（H-10.1）→ 重要度
  exclude: string[];                      // 判定しない項目ID
  sessionCookieNames: string[];           // セッションCookieとして扱う名前（推定を上書き）
  sessionMaxAgeHours: number;             // C-05：これを超える期限を指摘する（既定24）
  trustedScriptOrigins: string[];         // E-08：自社の配信元（SRIの確認の対象外）。https://cdn.example.com、*.example.com など
}
export interface Rule {
  id: string; title: string; appliesTo: 'html' | 'api' | 'any';
  scope: 'target' | 'host' | 'cross'; dependsOn?: string[]; basis: string[];
  // 返り値の取り決め：評価したら必ず .ok か fail を返す。判定できなければ .na。
  // 空配列は「このターゲットには適用外」の意味にだけ使う（ツール設計2）。
  run?(ctx: RuleContext): Finding[];          // scope: target
  runCross?(ctx: CrossContext): Finding[];    // scope: host / cross
}
