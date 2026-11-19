// rules/exposure.ts：第5章 エラー・情報露出（E-01、E-02、E-04〜E-06、E-11、E-13）
import type { HttpResponse, Rule, RuleContext } from '../model';
import { clip } from '../mask';
import { probePattern } from './probes';
import { NO_BODY_REC, PROBE_UNREACHED_REC, bodyTruncated, header, isStaticResource, mk } from './util';
import { ownChain } from '../parser/target';
import { allowedItems } from '../engine/labels';
import { noHtmlBody } from './html';

const body = (ctx: RuleContext) => (ctx.final?.body?.trim() ? ctx.final.body : undefined);

/**
 * E-01①：接続文字列・認証情報らしき値。
 * - Server=…;…;Password=…; の形は、キーを大文字小文字を区別して照合し、Password は「;」の直後のキーとする。
 *   小文字の JS（var host = location.host; var password = form.value;）には一致させない（区別しないと、圧縮した JS の多くで高の誤検知になる）
 * - AWS のアクセスキーは大文字だけで、語の境目で区切る（base64 の途中の …zakia… に一致させない。rules/html.ts の SECRETS と同じ）
 * - jdbc: は資格情報を含むものだけ（//ユーザー:パスワード@、?password=・;password=、Oracle の thin:ユーザー/パスワード@）。
 *   資格情報のない jdbc:mysql://db/app は内部のホスト名の露出で、②（中）にする（①は高で、漏れた値の変更を求めるため）
 */
const CREDENTIALS: RegExp[] = [
  // 繰り返しには上限を付ける（「jdbc:」を繰り返した本文で2乗の時間にしない）。
  // ユーザー名とパスワードに ; ? & を含めない（jdbc:sqlserver://db;user=svc@corp を「ユーザー:パスワード@」とみなさない）。パスワードの / は認める
  /\bjdbc:\w{1,32}:(?:\w{1,32}:){0,3}\/\/[^\s/:@;?&"'<>]{1,256}:[^\s@;?&"'<>]{1,256}@/i,
  /\bjdbc:\w+:[^\s"'<>]{0,300}?[?;&](?:password|pwd)=[^&;\s"'<>]+/i,
  /\bjdbc:oracle:\w+:[^\s/@:"'<>]+\/[^\s@"'<>]+@/i,
  // ユーザー名とパスワードに引用符・「/」・「@」を含めない（mongodb://db.example.com:27017/app のあとのメールアドレスの @ までを
  // 「ユーザー:パスワード@」と読まない）
  /mongodb(?:\+srv)?:\/\/[^\s:"'<>/@]{1,256}:[^\s@"'<>/]{1,256}@/i,
  /\b(?:Server|Data Source|Host|User ID|Uid|Database|Initial Catalog)\s*=[^;\n]{0,200};(?:[^;\n]{0,200};){0,10}?\s*(?:Password|PWD|Pwd)\s*=\s*[^;\s]+/,
];
// AWS のアクセスキー。HTML の応答では E-09①（HTML本文の秘密情報）が同じ値を数えるので、E-01① では見ない（第0章 0.2「同じ事象は1つの項目でだけ減点」）
const AWS_KEY = /\bAKIA[0-9A-Z]{16}\b/;
const path = (ctx: RuleContext) => { try { return new URL(ctx.target.url ?? '').pathname; } catch { return ''; } };
/** 画面・データの形の Content-Type（HTML・XHTML・JSON・問題の詳細）。静的リソースの拡張子の URL でも、E-01 はこれなら本文を見る */
const DOC_CT = /^\s*(?:text\/html|application\/(?:xhtml\+xml|(?:problem\+)?json)|[\w.-]+\/[\w.-]+\+json)\b/i;

// E-01② のスタックトレース・SQL・絶対パスなど（errorDetail の中の注記を参照）
const TRACE = /\bat [\w$.<>[\] ]{1,200} \((?:\/|[A-Z]:\\)[^)\n]{1,300}\.[cm]?[jt]sx?:\d+:\d+\)|\bat [\w$.<>[\] ]{1,200} \(node:[\w/]{1,100}:\d+:\d+\)|(?<=(?:^|[\r\n>]|\\n|<br\s*\/?>|[[,]\s*"|"(?:stack|trace|stacktrace|stack_trace|error|err|exception)"\s*:\s*")(?:[ \t]|&nbsp;){0,20}|(?:[Ee]rror|[Ee]xception)\b[^\n"<]{0,200}\s)at (?:\/|[A-Z]:\\)[^\s()"',;]{1,300}\.[cm]?[jt]sx?:\d+:\d+|\bat node:[\w/]{1,100}:\d+:\d+|(?:\/[\w.-]{1,100}){1,20}\.rb:\d+:in\b|\bFile "(?:\/|[A-Z]:\\)[^"\n]{1,300}\.py", line \d+|goroutine \d+ \[running\]|Symfony\\Component\\[\w\\]{1,200}Exception|Traceback \(most recent call last\)|\bat (?:java|javax|org|com|jdk)\.[\w.$]+\([\w.]*(?::\d+)?\)|SQLSTATE\[\w+\]|\bORA-\d{5}|System\.[\w.]{1,200}Exception|Microsoft\.\w+\.\w+Exception|\.php on line \d+|\.php<\/b> on line <b>\d+|Stack trace:\s*#0 |(?:(?<=^|[\r\n]|\\n)[ \t]{1,20})at [A-Z]\w*(?:\.[\w<>`|$]+){2,}\(|(?<![\w.:/~%-])(?<!=\s*["']?)(?<!url\(\s*["']?)(?:\/home|\/var\/www|\/usr\/src|\/srv|\/opt)\/[\w./-]{1,200}\.(?:php|py|rb|js|ts|java)\b|[A-Z]:\\(?:inetpub|Users|Program Files)\\[^\s<"]+/;
const matchTrace = (s: string) => s.match(TRACE);
export const errorDetail: Rule = { id: 'E-01', title: 'スタックトレース・デバッグ情報', appliesTo: 'any', scope: 'target',
  basis: ['ISOG-J', 'OWASP Error Handling CS'],
  run(ctx) {
    // JS・CSS などの静的リソースは、エラーの応答ではない（圧縮した JS の文字列に ORA- や例外の名前が含まれていても、エラーの詳細ではない）。
    // ただし拡張子が静的リソースでも、エラーの応答（4xx・5xx）と、HTML・JSON を返したもの（/img/missing.png の 500 のエラーページ）は見る
    const doc = (ctx.final?.status ?? 0) >= 400 || DOC_CT.test(header(ctx, 'content-type')[0] ?? '');
    const b = isStaticResource(ctx) && !doc ? undefined : body(ctx);
    if (!b) return [];
    const out = [];
    // HTML の AWS のキーを E-09 に任せるのは、そのラベルで E-09 を判定し、組織プロファイルで E-09 を対象外にしていないときだけ
    // （error-* のラベルは E-01 と A-10 だけを判定する。任せた先が判定しないと、どの項目でも指摘しない）
    const e09 = ctx.responseKind === 'html' && allowedItems(ctx.target.label).allowsItem('E-09') && !ctx.profile?.exclude.includes('E-09');
    const cred = CREDENTIALS.some(re => re.test(b)) || (!e09 && AWS_KEY.test(b));
    if (cred)
      out.push(mk(errorDetail, ctx, 1, 'high', 'fail', '接続文字列・認証情報らしき値（値は表示しない）', '汎用のエラーメッセージにし、詳細はサーバのログだけに出す。漏れた値は変更する'));
    // ②（TRACE と資格情報のない jdbc:）の要点：
    // - 資格情報のない jdbc: は、接続先（ホスト名）を出さないよう「jdbc:mysql:」までを証跡にする
    // - ORA- は語の境目から（FLORA-12345 のような品番に一致させない）。絶対パスは URL のパスの一部（https://cdn…/opt/app.js、
    //   src="/srv/main.js"、url(/srv/…)）には一致させない（直前が URL の文字か、属性・url() の始まり）
    // - Node.js の「at 関数 (/パス:行:列)」は、ファイル（.js・.ts など）か node: の行と列まであるものだけ（文章の「at Building A (/floor:3:12)」に
    //   一致させない）。無名のフレーム（at /app/index.js:7:9）は行の始め（JSON の stack の「\n    at」、HTML の <br> と &nbsp;、JSON の配列の要素の
    //   始まりを含む）にあり、パスに引用符・カンマを含まないものだけ（"at /static/js/chunk.js:1:20345"、{"tip":"look at /docs","entry":"main.js:1:2"}
    //   に一致させない）。Go の panic の goroutine、Symfony の例外も見る
    // - Docker でよく使う /app の下は、行の形（Rails の「/app/…/x.rb:12:in」、Python の「File "/app/main.py", line 41」、Node.js の無名のフレーム）
    //   でだけ見る。/app を絶対パスの一覧に入れない（serviceWorker.register("/app/sw.js")・{"entry":"/app/main.js"} に一致させない）
    // JSON の文字列に入れたスタックトレース（Spring の "trace":"…\n\tat com.example…"、エスケープした File \"/app/main.py\"）は、
    // エスケープを戻した本文でも照合する
    const unescaped = b.includes('\\') ? b.replace(/\\[nt]/g, ' \n').replace(/\\(["/])/g, '$1') : b;
    const trace = matchTrace(b) ?? (unescaped !== b ? matchTrace(unescaped) : null)
      // 資格情報を含む jdbc: は①だけにする（②にも出すと二重になる。設計書は②を資格情報のない jdbc: に限る）。スタックトレースがあれば、そちらを証跡にする
      ?? (cred ? null : b.match(/\bjdbc:\w+:(?=\S)/));
    if (trace) out.push(mk(errorDetail, ctx, 2, 'medium', 'fail', clip(trace[0], 120), 'スタックトレース・SQL文・接続文字列・絶対パスを応答に含めない'));
    // ③ Laravel は既定のレイアウト（window.Laravel）ではなく、エラーページに固有の文言で見る。Rails も同じく、既定のエラーページ
    // （public/404.html・500.html）と開発用の画面の文言で見る（「Ruby on Rails」はブログの記事などにも出る）
    const page = b.match(/Whitelabel Error Page|Apache Tomcat\/[\d.]+|Werkzeug Debugger|Django Version:|Whoops, looks like something went wrong|Illuminate\\[\w\\]+Exception|Action Controller: Exception caught|<h1>Routing Error<\/h1>|We're sorry, but something went wrong\.|The page you were looking for doesn't exist\.|Server Error in '\/' Application|IIS \d+\.\d+ Detailed Error|<title>Express<\/title>/i)
      // nginx・Apache の既定のエラーページは、エラーの応答（4xx・5xx）だけ（同じ署名が既定の 301・302 の本文にもある）
      ?? ((ctx.final?.status ?? 0) >= 400 ? b.match(/<hr><center>nginx(?:\/[\d.]+[^<]{0,40})?<\/center>|<address>Apache(?:\/[\d.]+)?[^<]{0,80} Server at [^<]{0,200}<\/address>/i) : null)
      // Jetty の既定のエラーページ（<title>Error 404 Not Found</title>）は、本文の「HTTP ERROR 404」「Powered by Jetty」と合わせて見る。
      // <title>Error 404 - Page not found | MyShop</title> のような独自のエラーページを既定のページとしない
      ?? (/HTTP ERROR:?\s*\d{3}|Powered by Jetty/i.test(b) ? b.match(/<title>Error \d{3}[^<]*<\/title>/i) : null);
    // <title>Error 401 …</title>（Jetty など）の「…」は自由な文言で、アプリが「Invalid API key sk_live_…」のように秘密を入れうるので出さない
    if (page) out.push(mk(errorDetail, ctx, 3, 'low', 'fail', clip(page[0].replace(/^(<title>Error \d{3})[^<]*/i, '$1 …'), 120), 'フレームワーク既定のエラーページを独自のページ（またはRFC 9457の問題詳細形式）にする'));
    return out.length ? out : [mk(errorDetail, ctx, 'ok', 'info', 'pass', 'エラーの詳細らしき記述なし', '')];
  } };

/**
 * Spring Boot が既定で公開する actuator の応答：/actuator/health・info の状態だけのもの（{"status":"UP"}、Kubernetes の {"status":"UP","groups":["liveness","readiness"]}、
 * 空の info の {}）と、/actuator の一覧で、リンクが self・health・health-path・info だけのもの
 */
function actuatorDefault(p: string, b: string): boolean {
  let j: unknown; try { j = JSON.parse(b); } catch { return false; }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return false;
  const o = j as Record<string, unknown>;
  // ヘルスのグループ（Kubernetes の /actuator/health/liveness・readiness。Spring Boot が既定で公開する）も、状態だけなら既定の応答
  if (/\/actuator\/(?:health(?:\/[\w-]+)?|info)\/?$/i.test(p))
    return Object.entries(o).every(([k, v]) => (k === 'status' && typeof v === 'string' && /^[A-Z_]+$/.test(v)) || (k === 'groups' && Array.isArray(v) && v.every(x => typeof x === 'string')));
  if (/\/actuator\/?$/i.test(p) && Object.keys(o).length === 1 && o._links && typeof o._links === 'object')
    return Object.keys(o._links as object).length > 0 && Object.keys(o._links as object).every(k => /^(?:self|health|health-path|info)$/.test(k));
  return false;
}
export const dirListing: Rule = { id: 'E-02', title: 'ディレクトリリスティング', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-CONF-04'],
  run(ctx) {
    const b = body(ctx);
    // オブジェクトストレージの一覧（S3・GCS の <ListBucketResult>、Azure Blob の <EnumerationResults>）も一覧表示（XML の応答）
    const bucket = b && /^\s*(?:<\?xml[^>]*>\s*)?<(?:ListBucketResult|EnumerationResults)\b/.test(b) ? b.match(/<(?:ListBucketResult|EnumerationResults)\b/) : null;
    if (bucket) return [mk(dirListing, ctx, 1, 'medium', 'fail', `${bucket[0].slice(1)}（オブジェクトストレージの一覧）`, 'バケット・コンテナの一覧の公開を無効にする（S3 のブロックパブリックアクセス、Azure のコンテナのアクセスレベルを private に）')];
    if (ctx.responseKind !== 'html') return [];
    if (!b) return noHtmlBody(dirListing, ctx);
    // nginx・Apache の「Index of /」、Python の http.server、IIS の「[To Parent Directory]」、Tomcat の「Directory Listing For [/…]」、
    // Jetty の「<title>Directory: /…」、Express の serve-index の「listing directory /…」
    const m = b.match(/<title>\s*Index of \/[^<]*<\/title>|<h1>\s*Index of \/|Directory listing for \/|\[To Parent Directory\]|Directory Listing For \[?\/|<title>\s*Directory: \/|<title>\s*listing directory \//i);
    return m ? [mk(dirListing, ctx, 1, 'medium', 'fail', m[0], 'ディレクトリの一覧表示を無効にする（nginx: autoindex off、Apache: Options -Indexes）')]
             : [mk(dirListing, ctx, 'ok', 'info', 'pass', '一覧表示なし', '')];
  } };

// 機密らしい語は、英字の語の境目で見る（/devices/ の dev、/latest/ の test、/contest/ に一致させない）。admin・config・manage は
// 続く語（administrator、configuration、management）も含め、ほかは複数形（tests、internals）を含める。admin の前の語は
// よく使う接頭辞（sys・my・web・db・site・super）だけを認める（/badminton/ に一致させない）。/wp-admin/、/admin2/ は一致する
const ROBOTS_SENSITIVE = /^Disallow:\s*(\/\S*?(?<![a-z])(?:phpmyadmin|(?:sys|my|web|db|site|super)?admin[a-z]*|secrets?|backups?|privates?|internals?|staging|devs?|devel|development|tests?|testing|testsite|config[a-z]*|manage[a-z]*|consoles?)(?![a-z])\S*)/im;
export const robotsSecurityTxt: Rule = { id: 'E-04', title: 'robots.txt・security.txt', appliesTo: 'any', scope: 'target',
  basis: ['RFC 9116', 'OWASP WSTG-INFO-03'],
  run(ctx) {
    const p = path(ctx); const b = body(ctx);
    const probe = ctx.target.probes.find(x => /\/security\.txt$/.test(x.path));
    if (probe) {                                              // C13 の存在確認（probes ラベル）
      if (!probe.code) return [mk(robotsSecurityTxt, ctx, 'na', 'info', 'na', `${probe.path}（HTTP 000、接続できなかった）`, PROBE_UNREACHED_REC)];
      const hit = probePattern(probe.path, probe.headB64, probe.code);
      if (hit?.name === 'security-txt-comment') return [mk(robotsSecurityTxt, ctx, 'na', 'info', 'na', `${probe.path}（HTTP ${probe.code}。先頭の64バイトがコメントだけで、Contact・Expires があるかは分からない）`, '本文を取得して（C2）、Contact と Expires があるか確かめる')];
      return hit?.name === 'security-txt' ? [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `${probe.path}（HTTP ${probe.code}）`, '')]
        : [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `${probe.path}（HTTP ${probe.code}）`, '/.well-known/security.txt に Contact と Expires を書いて公開する')];
    }
    // 本文を取得したターゲット（一般のターゲット）。2xx でなければファイルがない（404 のエラーページの本文を、ファイルの中身として読まない）
    const st = ctx.final?.status ?? 0; const got = !st || (st >= 200 && st < 300);
    if (/\/robots\.txt$/.test(p) && (b || !got)) {
      // 転送（3xx）を -L なしで採取したものは、転送先の robots.txt を見ていない
      if (st >= 300 && st < 400) return [mk(robotsSecurityTxt, ctx, 'na', 'info', 'na', `HTTP ${st}（転送先を採取していない）`, '-L を付けて、転送先まで採取し直す')];
      if (!got) return [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `robots.txt なし（HTTP ${st}）`, '')];
      // どのパスにも index.html を返す SPA の 200 は、robots.txt ではない（security.txt と同じ扱い）
      // HTML かは本文で見る（robots.txt を text/html で返すサーバの User-agent・Disallow の行を見逃さない。robots.txt は < で始まらない）
      if (/^\s*</.test(b!))
        return [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `robots.txt なし（HTTP ${st}、HTML の画面。SPA の可能性）`, '')];
      const m = b!.match(ROBOTS_SENSITIVE);
      return m ? [mk(robotsSecurityTxt, ctx, 1, 'low', 'fail', `Disallow: ${m[1]}`, 'robots.txt に機密パスを書かない（アクセス制御で守る）')]
               : [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', 'robots.txt に機密パスらしき記述なし', '')];
    }
    if (/\/security\.txt$/.test(p) && (b || !got)) {
      if (!got) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `security.txt を取得できない（HTTP ${st}）`, '/.well-known/security.txt に Contact と Expires を書いて公開する')];
      // どのパスにも index.html を返す SPA の 200 は、security.txt ではない
      if (/^\s*text\/html/i.test(header(ctx, 'content-type')[0] ?? '') || /^\s*(?:<!doctype html|<html)/i.test(b!))
        return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `HTML の画面が返った（security.txt ではない。HTTP ${st || '不明'}）`, '/.well-known/security.txt に Contact と Expires を書いて公開する')];
      const ex = b!.match(/^Expires:\s*(.+)$/im)?.[1]; const contact = /^Contact:/im.test(b!);
      if (!contact || !ex) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `Contact: ${contact ? 'あり' : 'なし'} / Expires: ${ex ?? 'なし'}`, 'Contact と Expires を書く')];
      // 読めない Expires（never など）は、期限が書かれていないのと同じ（RFC 9116 は RFC 3339 の日時を求める）
      if (Number.isNaN(Date.parse(ex.trim()))) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `Expires: ${ex}（日時として読めない）`, 'Expires を RFC 3339 の日時（2027-01-01T00:00:00Z）で書く')];
      if (Date.parse(ex) < ctx.now) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `Expires: ${ex}（期限切れ）`, 'Expires を更新する')];
      return [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `Expires: ${ex}`, '')];
    }
    return [];
  } };

// パスの区切り（/）で区切った1つの部分として一致させる（/category/actuator-kits や /blog/swagger-tips は普通のページ）
const DOC_SEGMENT = /\/(actuator|swagger-ui(?:\.html)?|swagger(?:\.json|\.ya?ml)?|openapi\.(?:json|ya?ml)|api-docs|graphql)(?=\/|$)/i;
const docSegment = (p: string) => p.match(DOC_SEGMENT)?.[1].toLowerCase();
/**
 * 転送先が、同じホストで同じ機能のページ（転送元のパスに「/」か「/index.html」を足しただけ。springdoc の /swagger-ui.html → /swagger-ui/index.html
 * を含む）なら、そのパスを返す。/actuator → /actuator/login のようなログイン画面への転送は undefined（転送先の 200 で①にしない）
 */
function docRedirect(r: HttpResponse, targetUrl: string | undefined): string | undefined {
  const loc = r.headers.get('location')?.[0]; const base = r.url ?? targetUrl;
  if (!loc || !base) return undefined;
  try {
    const from = new URL(base), to = new URL(loc.trim(), from);
    if (to.host !== from.host || !docSegment(to.pathname)) return undefined;
    const stem = from.pathname.replace(/\.html?$/i, '').replace(/\/+$/, '');
    return to.pathname.startsWith(stem) && /^\/?(?:index\.html?)?$/i.test(to.pathname.slice(stem.length)) && to.pathname !== from.pathname ? to.pathname : undefined;
  } catch { return undefined; }
}

const GRAPHQL_REC = 'introspection のクエリ（{"query":"{__schema{types{name}}}"}）を POST して採取する';
export const apiDocsAdmin: Rule = { id: 'E-05', title: 'API仕様・管理機能', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API8・API9'],
  run(ctx) {
    // ステータスは、そのURL自身の応答（転送の最初のホップ）で見る。/actuator からログイン画面に転送した先の 200 で①（高）にしないため。
    // ただし、同じホストの仕様・管理機能のパスへの転送（/swagger-ui → /swagger-ui/index.html）は、同じ機能のページなので転送先で見る
    const p = path(ctx); const chain = ownChain(ctx.target);
    if (!chain[0] || !docSegment(p)) return [];
    let i = 0;
    while (chain[i].kind === 'redirect' && docRedirect(chain[i], ctx.target.url)) {
      if (!chain[i + 1]) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `HTTP ${chain[i].status}（同じホストの ${docRedirect(chain[i], ctx.target.url)} への転送。転送先を採取していない）`, '-L を付けて、転送先まで採取し直す')];
      i++;
    }
    const f = chain[i];
    const ok200 = f.status >= 200 && f.status < 300;
    const b = body(ctx) ?? '';
    // GraphQL：introspection を試した応答だけで判定する。GET /graphql の 400（Must provide query string）や 405 は、
    // introspection が無効かどうかを示さないので合格にしない
    if (docSegment(p) === 'graphql') {
      if (ok200 && /"__schema"/.test(b)) return [mk(apiDocsAdmin, ctx, 3, 'medium', 'fail', 'introspection の応答に __schema がある', '本番では introspection を無効にする')];
      // HTML は introspection の応答ではない。GraphiQL などの IDE の画面は、JS に introspection の語を含むので、拒否とみなさない。
      // IDE が未認証で開ける（そこから introspection を試せる）のは、API仕様の公開（②）と同じに扱う
      const html = /^\s*text\/html/i.test(header(ctx, 'content-type')[0] ?? '') || /^\s*(?:<!doctype html|<html)/i.test(b);
      if (html) {
        if (!ok200 || !/graphiql|graphql-playground|graphql playground|apollo sandbox|altair/i.test(b)) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `HTTP ${f.status}（HTML。introspection を試した応答ではない）`, GRAPHQL_REC)];
        if (ctx.target.sentAuth) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `${p}（HTTP ${f.status}、GraphQL の IDE。Cookie・Authorization を送った応答で、未認証で使えるかは分からない）`, 'Cookie・Authorization を付けずに採取し直す')];
        return [mk(apiDocsAdmin, ctx, 2, 'medium', 'fail', `${p}（HTTP ${f.status}、GraphQL の IDE（GraphiQL など）の画面）`, 'GraphQL の IDE は本番で無効にするか、認証の内側に置く（introspection は POST して別に確かめる）')];
      }
      if (/introspection/i.test(b)) return [mk(apiDocsAdmin, ctx, 'ok', 'info', 'pass', `HTTP ${f.status}（introspection を拒否）`, '')];
      return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `HTTP ${f.status}（introspection を試した応答ではない）`, GRAPHQL_REC)];
    }
    // ステータスが分からない応答（%{header_json} だけで #META response_code= がない）は、拒否されたかどうかも分からない
    if (!f.status) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', 'ステータスが分からない（HTTP 0）', 'ステータス行を含めて採取し直す（C10 なら #META response_code= も付ける）')];
    // 5xx は、公開していないとは言えない（認証の前に落ちた・一時的な障害の可能性。A-01 の 5xx と同じく na）
    if (f.status >= 500) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `${p}（HTTP ${f.status}。サーバのエラーで、公開しているかは分からない）`, '時間をおいて採取し直す')];
    if (!ok200) return [mk(apiDocsAdmin, ctx, 'ok', 'info', 'pass', `HTTP ${f.status}`, '')];
    // ①②は「未認証で使える・公開されている」。Cookie・Authorization を送った応答の 200 では、未認証で使えるかは分からない
    if (ctx.target.sentAuth) return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `${p}（HTTP ${f.status}。Cookie・Authorization を送った応答で、未認証で使えるかは分からない）`, 'Cookie・Authorization を付けずに採取し直す')];
    // HTML の 200 は、その機能の画面だと分かるときだけ①②にする。どのパスにも index.html を 200 で返す SPA（Netlify・Vercel・Firebase Hosting・
    // S3＋CloudFront）では、/actuator・/swagger-ui/ も同じ画面になる（E-03② と同じ考え方）。actuator と API 仕様（openapi.json など）の本体は JSON・YAML
    const isHtml = /^\s*text\/html/i.test(header(ctx, 'content-type')[0] ?? '') || /^\s*(?:<!doctype html|<html)/i.test(b);
    // 画面の印は、タイトルと、その画面を作る要素・スクリプトだけで見る（<title>Swagger UI</title>、<div id="swagger-ui">、swagger-ui-bundle.js、
    // <redoc>、<rapi-doc>、@scalar/api-reference）。本文の「Swagger UI」の語だけでは、SPA の文中の語と区別できない
    const ui = /<title>[^<]{0,100}(?:swagger[- ]ui|redoc|rapidoc|scalar)|\bid\s*=\s*["']?(?:swagger-ui|api-reference)\b|swagger-ui(?:-bundle|-standalone-preset)?(?:\.min)?\.(?:js|css)\b|SwaggerUIBundle|<redoc\b|redoc\.standalone|<rapi-doc\b|@scalar\/api-reference/i.test(b);
    if (isHtml && !(docSegment(p) !== 'actuator' && ui))
      return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `${p}（HTTP ${f.status}、HTML。${b ? 'その機能の画面と分からない（どのパスにも同じ画面を返す SPA の可能性）' : '本文を採取していない'}）`, b ? `${p} がその機能の画面かを、ブラウザで開いて確かめる` : NO_BODY_REC)];
    // /actuator/health・/actuator/info で、本文が状態だけ（components・details のない {"status":"UP"}、空の {}）のものは、Spring Boot が既定で公開する
    // 死活監視の応答なので対象外（Kubernetes・負荷分散装置が使う）
    if (docSegment(p) === 'actuator' && actuatorDefault(p, b))
      return [mk(apiDocsAdmin, ctx, 'ok', 'info', 'pass', `${p}（HTTP ${f.status}、既定で公開される死活監視の応答・一覧）`, '')];
    // 既定で公開される /actuator/health・info・一覧で本文を採取していない（-D - -o /dev/null・-I・HAR の本文なし）と、状態だけの応答かが分からない。
    // /actuator/env などは、取得できたこと自体が①
    if (docSegment(p) === 'actuator' && !b.trim() && /\/actuator(?:\/(?:health(?:\/[\w-]+)?|info))?\/?$/i.test(p))
      return [mk(apiDocsAdmin, ctx, 'na', 'info', 'na', `${p}（HTTP ${f.status}。本文を採取していないので、既定で公開される状態だけの応答かは分からない）`, NO_BODY_REC)];
    if (docSegment(p) === 'actuator') return [mk(apiDocsAdmin, ctx, 1, 'high', 'fail', `${p}（HTTP ${f.status}）`, 'actuator を本番で公開しない（必要なエンドポイントだけを認証の内側で有効にする）')];
    return [mk(apiDocsAdmin, ctx, 2, 'medium', 'fail', `${p}（HTTP ${f.status}）`, 'API仕様は本番で無効にするか、認証の内側に置く')];
  } };

export const jsonp: Rule = { id: 'E-06', title: 'JSONP', appliesTo: 'any', scope: 'target',
  basis: ['OWASP', 'Google csp_evaluator'],
  run(ctx) {
    let cb: string | null = null;
    try { cb = new URL(ctx.target.url ?? '').searchParams.get('callback') ?? new URL(ctx.target.url ?? '').searchParams.get('jsonp'); } catch { /* URLなし */ }
    if (!cb || !ctx.final) return [];
    if (!body(ctx) && ctx.final.status >= 200 && ctx.final.status < 300) return [mk(jsonp, ctx, 'na', 'info', 'na', `HTTP ${ctx.final.status}（本文を採取していない）`, NO_BODY_REC)];
    const b = (body(ctx) ?? '').trimStart();
    // 「cb(」「/**/cb(」のほか、Express の res.jsonp の形「/**/ typeof cb === 'function' && cb(」も JSONP とみなす
    const esc = cb.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const hit = new RegExp(`^(?:/\\*\\*/\\s*)?(?:typeof\\s+${esc}\\s*===?\\s*['"]function['"]\\s*&&\\s*)?${esc}\\s*\\(`).test(b.slice(0, 2048));
    if (!hit) return [mk(jsonp, ctx, 'ok', 'info', 'pass', `callback=${cb} は本文に反映されない`, '')];
    // 機密かどうか分からないときは①を判定しない（第0章 0.3）。JSONP があることは確かなので、より弱い②として出す
    if (ctx.sensitive === undefined) return [mk(jsonp, ctx, 2, 'low', 'fail', `本文が ${cb}( で始まる（機密応答かどうか分からない）`, 'JSONP をやめる。機密応答なら①（高）にあたる（#TARGET に sensitive=1 か sensitive=0 を付ける）')];
    return ctx.sensitive
      ? [mk(jsonp, ctx, 1, 'high', 'fail', `本文が ${cb}( で始まる（機密応答）`, 'JSONP をやめ、CORS（許可リスト）にする')]
      : [mk(jsonp, ctx, 2, 'low', 'fail', `本文が ${cb}( で始まる`, 'JSONP をやめる（CSPの許可リストを回避する足がかりになる）')];
  } };

// vnd.* でも +json・+xml（JSON:API の application/vnd.api+json など）は API の応答で、ダウンロードではない
const DOWNLOAD_CT = /^(application\/(octet-stream|pdf|zip|x-zip|vnd\.(?![\w.-]*\+(?:json|xml)\b)|msword|x-msdownload)|text\/csv)/i;
// ブラウザがその場でスクリプトを実行しうる種類（アップロード先で inline に配信すると①）
const ACTIVE_CT = /^\s*(?:text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/xml|application\/xml)\b/i;
// その場で表示するのが普通の種類（画像・音声・動画）。Content-Disposition がなくても②にしない
// HLS・DASH のプレイリスト（application/vnd.apple.mpegurl・x-mpegurl・dash+xml）も、プレイヤーが読み込むもので、ダウンロードではない
const INLINE_MEDIA_CT = /^\s*(?:image\/(?!svg)|audio\/|video\/|application\/(?:vnd\.apple\.mpegurl|x-mpegurl|dash\+xml)\b)/i;
// 旧式のフォント（application/vnd.ms-fontobject。.eot）も含める
const BUILD_ASSET_CT = /^\s*(?:text\/css|(?:text|application)\/(?:x-)?(?:java|ecma)script|font\/|application\/(?:x-)?font|application\/vnd\.ms-fontobject\b)/i;
export const downloadResponse: Rule = { id: 'E-11', title: 'ダウンロード応答', appliesTo: 'any', scope: 'target',
  basis: ['OWASP File Upload CS'],
  run(ctx) {
    const f = ctx.final; if (!f) return [];
    // そのURLがファイルを返した応答だけを見る：転送のない 2xx。404 のエラーページや、ログイン画面への転送先の HTML を、
    // アップロードしたファイルの inline 配信（①、高）にしないため
    if (ownChain(ctx.target).length !== 1 || f.status < 200 || f.status >= 300) return [];
    const ct = header(ctx, 'content-type')[0] ?? ''; const cd = header(ctx, 'content-disposition')[0] ?? '';
    // アップロードしたファイルの配信らしいURL：アップロード先らしいディレクトリの下で、最後がファイル名（拡張子付き）のもの
    // （/media/press-releases/ や /download/ のようなディレクトリ名だけのものは普通のHTMLページ）
    const p = path(ctx);
    // サーバ側で動くページ（/download/index.php、/files/list.aspx）と、ディレクトリの index.html は、アップロードしたファイルではないので除く
    const uploadPath = /\/(uploads?|files?|attachments?|media|download)\//i.test(p) && /\/[^/]+\.[a-z0-9]{1,10}$/i.test(p)
      && !/\.(?:php\d?|phtml|aspx?|ashx|jspx?|do|action|cgi|pl|cfm|shtml)$|\/index\.html?$/i.test(p)
      // /download/ の下の .html（/download/windows.html）は、配布物を案内する普通のページ。ただし、アップロード先らしいディレクトリ
      // （uploads・files・attachments・media）も含むもの（Redmine の /attachments/download/42/evil.html）は、利用者のファイルなので除かない
      // media は CMS の配布物の置き場にも使う（/media/download/press.html）ので、ここでは利用者のファイルの印にしない
      && !(/\/download\/(?:[^/]+\/)*[^/]+\.html?$/i.test(p) && !/\/(uploads?|files?|attachments?)\//i.test(p))
      // ビルドしたファイル（Create React App の /static/media/logo.6ce24c58.svg、Next.js の /_next/static/media/…）は、ページが読み込むもので、
      // 利用者がアップロードしたファイルではない。名前のハッシュだけでは見ない（/uploads/avatar.5f3a9c2e.svg、日付の minutes.20241231.html を見逃す）
      // ビルドの置き場の下でも、アップロード先らしいディレクトリ（/static/media/uploads/evil.html）は除かない
      && !(/\/_next\/static\/|\/static\/media\//i.test(p) && !/\/(?:uploads?|attachments?|user[-_]?files?)\//i.test(p));
    if (!DOWNLOAD_CT.test(ct) && !uploadPath && !cd) return [];   // ファイル配信の応答だけ
    // JSON の API の応答（/api/files/123.json など、パスがアップロード先らしくても）は、ダウンロードではない（DOWNLOAD_CT で +json を除くのと同じ）
    // Content-Type で見る（kind=api を明示したターゲットの SVG・PDF まで除かないため）
    if (/^\s*application\/(?:[\w.-]+\+)?json\b/i.test(ct) && !cd) return [];
    // Content-Disposition は種類（最初のトークン）で見る（RFC 6266。inline; filename="attachment.html" は inline）
    if (uploadPath && ACTIVE_CT.test(ct) && !/^\s*attachment\s*(?:;|$)/i.test(cd))
      return [mk(downloadResponse, ctx, 1, 'high', 'fail', `Content-Type: ${ct} / Content-Disposition: ${cd || '(なし)'}`, '利用者がアップロードしたファイルは別オリジンから attachment で配信する')];
    // ビルドした CSS・JS・フォント（Drupal の /sites/default/files/css/…、Next.js の /_next/static/media/…）は、ページが読み込むもので、ダウンロードではない
    if (!cd && BUILD_ASSET_CT.test(ct)) return [mk(downloadResponse, ctx, 'ok', 'info', 'pass', `Content-Type: ${ct}（CSS・JS・フォント）`, '')];
    if (!cd && INLINE_MEDIA_CT.test(ct)) return [mk(downloadResponse, ctx, 'ok', 'info', 'pass', `Content-Type: ${ct}（画像・音声・動画はその場で表示）`, '')];
    if (!cd) return [mk(downloadResponse, ctx, 2, 'low', 'fail', `Content-Type: ${ct}（Content-Dispositionなし）`, 'Content-Disposition: attachment; filename="…" を付ける')];
    return [mk(downloadResponse, ctx, 'ok', 'info', 'pass', `Content-Disposition: ${cd}`, '')];
  } };

export const sourceMap: Rule = { id: 'E-13', title: 'ソースマップの露出', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-INFO-05'],
  run(ctx) {
    const maps = ctx.target.probes.filter(p => /\.map$/.test(p.path));
    if (maps.length) {                                         // ① probes ラベル：.map を取得できるか
      const got = maps.filter(p => probePattern(p.path, p.headB64, p.code)?.name === 'source-map');
      const unreached = maps.filter(p => !p.code).length;
      return got.length ? got.map(p => mk(sourceMap, ctx, 1, 'medium', 'fail', `${p.path}（HTTP ${p.code}、一致したパターン: source-map）`, '本番では .map を配信しない（sourcesContent に元のソースがあるかは手動で確認）'))
        : unreached ? [mk(sourceMap, ctx, 'na', 'info', 'na', `${maps.length}件の .map のうち${unreached}件は接続できなかった（HTTP 000）`, PROBE_UNREACHED_REC)]
        : [mk(sourceMap, ctx, 'ok', 'info', 'pass', `${maps.length}件の .map は取得できなかった`, '')];
    }
    const f = ctx.final; if (!f) return [];
    const ref = header(ctx, 'sourcemap')[0] ?? header(ctx, 'x-sourcemap')[0] ?? body(ctx)?.match(/\/[/*]#\s*sourceMappingURL=(\S+)/)?.[1];
    const isJs = /javascript|ecmascript/i.test(header(ctx, 'content-type')[0] ?? '') || /\.m?js(?:[?#]|$)/.test(ctx.target.url ?? '');
    if (!isJs && !ref) return [];
    if (!ref && (!body(ctx) || bodyTruncated(ctx))) return [mk(sourceMap, ctx, 'na', 'info', 'na', body(ctx) ? '本文の先頭64KBに参照なし（参照は末尾にあることが多い）' : '本文を採取していない', NO_BODY_REC)];
    // 本文に埋め込んだソースマップ（data:application/json;base64,…）は、.map を配信しているのと同じ（sourcesContent に元のソースを含みうる）。
    // 「.map を C13 に追加して確かめる」は当てはまらないので、証跡と推奨を分ける（①はプローブ（probes ラベル）の条件なので②のまま。中身は証跡に出さない）
    if (ref && /^data:/i.test(ref)) return [mk(sourceMap, ctx, 2, 'low', 'fail', '本文に埋め込んだソースマップ（data:。中身は表示しない）', '本番ビルドではインラインのソースマップ（webpack の inline-source-map・Vite の sourcemap: \'inline\' など）を出さない（sourcesContent に元のソースがあるかは手動で確認）')];
    return ref ? [mk(sourceMap, ctx, 2, 'low', 'fail', `参照: ${clip(ref, 120)}`, '本番ビルドでは sourceMappingURL を出さない。.map を C13 のパス一覧に追加して取得できるか確認する')]
               : [mk(sourceMap, ctx, 'ok', 'info', 'pass', 'ソースマップへの参照なし', '')];
  } };
