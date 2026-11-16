// rules/exposure.ts：第5章 エラー・情報露出（E-01、E-02、E-04〜E-06、E-11、E-13）
import type { Rule, RuleContext } from '../model';
import { probePattern } from '../mask';
import { header, mk } from './util';

const body = (ctx: RuleContext) => (ctx.final?.body?.trim() ? ctx.final.body : undefined);
const path = (ctx: RuleContext) => { try { return new URL(ctx.target.url ?? '').pathname; } catch { return ''; } };

export const errorDetail: Rule = { id: 'E-01', title: 'スタックトレース・デバッグ情報', appliesTo: 'any', scope: 'target',
  basis: ['ISOG-J', 'OWASP Error Handling CS'],
  run(ctx) {
    const b = body(ctx);
    if (!b) return [];
    const out = [];
    // ①の Password=…; は接続文字列（Server=…;…;Password=…;）の形のときだけ。JS の「var password = …;」には一致させない
    if (/jdbc:\w+:|mongodb(?:\+srv)?:\/\/[^\s:]+:[^\s@]+@|(?:Server|Data Source|Host|User ID|Uid|Database|Initial Catalog)\s*=[^;\n]{0,200};[^\n]{0,200}?(?:Password|Pwd)\s*=\s*[^;\s]+;?|AKIA[0-9A-Z]{16}/i.test(b))
      out.push(mk(errorDetail, ctx, 1, 'high', 'fail', '接続文字列・認証情報らしき値（値は表示しない）', '汎用のエラーメッセージにし、詳細はサーバのログだけに出す。漏れた値は変更する'));
    const trace = b.match(/Traceback \(most recent call last\)|\bat (?:java|javax|org|com|jdk)\.[\w.$]+\([\w.]*(?::\d+)?\)|SQLSTATE\[\w+\]|ORA-\d{5}|System\.[\w.]{1,200}Exception|Microsoft\.\w+\.\w+Exception|\.php on line \d+|(?:\/home|\/var\/www|\/usr\/src|\/srv|\/opt)\/[\w./-]{1,200}\.(?:php|py|rb|js|ts|java)\b|[A-Z]:\\(?:inetpub|Users|Program Files)\\[^\s<"]+/);
    if (trace) out.push(mk(errorDetail, ctx, 2, 'medium', 'fail', trace[0].slice(0, 120), 'スタックトレース・SQL文・絶対パスを応答に含めない'));
    // ③ Laravel は既定のレイアウト（window.Laravel）ではなく、エラーページに固有の文言で見る
    const page = b.match(/Whitelabel Error Page|Apache Tomcat\/[\d.]+|Werkzeug Debugger|Django Version:|Whoops, looks like something went wrong|Illuminate\\[\w\\]+Exception|Ruby on Rails|Server Error in '\/' Application|IIS \d+\.\d+ Detailed Error|Express<\/title>|<title>Error \d{3}[^<]*<\/title>/i);
    if (page) out.push(mk(errorDetail, ctx, 3, 'low', 'fail', page[0].slice(0, 120), 'フレームワーク既定のエラーページを独自のページ（またはRFC 9457の問題詳細形式）にする'));
    return out.length ? out : [mk(errorDetail, ctx, 'ok', 'info', 'pass', 'エラーの詳細らしき記述なし', '')];
  } };

export const dirListing: Rule = { id: 'E-02', title: 'ディレクトリリスティング', appliesTo: 'any', scope: 'target',
  basis: ['OWASP WSTG-CONF-04'],
  run(ctx) {
    const b = body(ctx);
    if (!b || ctx.responseKind !== 'html') return [];
    const m = b.match(/<title>\s*Index of \/[^<]*<\/title>|<h1>\s*Index of \/|Directory listing for \//i);
    return m ? [mk(dirListing, ctx, 1, 'medium', 'fail', m[0], 'ディレクトリの一覧表示を無効にする（nginx: autoindex off、Apache: Options -Indexes）')]
             : [mk(dirListing, ctx, 'ok', 'info', 'pass', '一覧表示なし', '')];
  } };

const ROBOTS_SENSITIVE = /^Disallow:\s*(\/\S*(?:admin|secret|backup|private|internal|staging|dev|test|config|manage|console|phpmyadmin)\S*)/im;
export const robotsSecurityTxt: Rule = { id: 'E-04', title: 'robots.txt・security.txt', appliesTo: 'any', scope: 'target',
  basis: ['RFC 9116', 'OWASP WSTG-INFO-03'],
  run(ctx) {
    const p = path(ctx); const b = body(ctx);
    const probe = ctx.target.probes.find(x => /\/security\.txt$/.test(x.path));
    if (probe) {                                              // C13 の存在確認（probes ラベル）
      const hit = probePattern(probe.path, probe.headB64, probe.code);
      return hit?.name === 'security-txt' ? [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `${probe.path}（HTTP ${probe.code}）`, '')]
        : [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `${probe.path}（HTTP ${probe.code}）`, '/.well-known/security.txt に Contact と Expires を書いて公開する')];
    }
    if (/\/robots\.txt$/.test(p) && b) {
      const m = b.match(ROBOTS_SENSITIVE);
      return m ? [mk(robotsSecurityTxt, ctx, 1, 'low', 'fail', `Disallow: ${m[1]}`, 'robots.txt に機密パスを書かない（アクセス制御で守る）')]
               : [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', 'robots.txt に機密パスらしき記述なし', '')];
    }
    if (/\/security\.txt$/.test(p) && b) {
      const ex = b.match(/^Expires:\s*(.+)$/im)?.[1]; const contact = /^Contact:/im.test(b);
      if (!contact || !ex) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `Contact: ${contact ? 'あり' : 'なし'} / Expires: ${ex ?? 'なし'}`, 'Contact と Expires を書く')];
      if (Date.parse(ex) < ctx.now) return [mk(robotsSecurityTxt, ctx, 2, 'info', 'fail', `Expires: ${ex}（期限切れ）`, 'Expires を更新する')];
      return [mk(robotsSecurityTxt, ctx, 'ok', 'info', 'pass', `Expires: ${ex}`, '')];
    }
    return [];
  } };

export const apiDocsAdmin: Rule = { id: 'E-05', title: 'API仕様・管理機能', appliesTo: 'any', scope: 'target',
  basis: ['OWASP API Security Top 10 2023: API8・API9'],
  run(ctx) {
    const p = path(ctx); const f = ctx.final;
    if (!f || !/\/(actuator|swagger-ui|swagger|openapi\.(json|ya?ml)|v[23]\/api-docs|api-docs|graphql)\b/i.test(p)) return [];
    const ok200 = f.status >= 200 && f.status < 300;
    const b = body(ctx) ?? '';
    if (/\/graphql/i.test(p)) return ok200 && /"__schema"/.test(b)
      ? [mk(apiDocsAdmin, ctx, 3, 'medium', 'fail', 'introspection の応答に __schema がある', '本番では introspection を無効にする')]
      : [mk(apiDocsAdmin, ctx, 'ok', 'info', 'pass', `HTTP ${f.status}`, '')];
    if (!ok200) return [mk(apiDocsAdmin, ctx, 'ok', 'info', 'pass', `HTTP ${f.status}`, '')];
    if (/\/actuator/i.test(p)) return [mk(apiDocsAdmin, ctx, 1, 'high', 'fail', `${p}（HTTP ${f.status}）`, 'actuator を本番で公開しない（必要なエンドポイントだけを認証の内側で有効にする）')];
    return [mk(apiDocsAdmin, ctx, 2, 'medium', 'fail', `${p}（HTTP ${f.status}）`, 'API仕様は本番で無効にするか、認証の内側に置く')];
  } };

export const jsonp: Rule = { id: 'E-06', title: 'JSONP', appliesTo: 'any', scope: 'target',
  basis: ['OWASP', 'Google csp_evaluator'],
  run(ctx) {
    let cb: string | null = null;
    try { cb = new URL(ctx.target.url ?? '').searchParams.get('callback') ?? new URL(ctx.target.url ?? '').searchParams.get('jsonp'); } catch { /* URLなし */ }
    if (!cb || !ctx.final) return [];
    const b = (body(ctx) ?? '').trimStart();
    const hit = b.startsWith(`${cb}(`) || b.startsWith(`/**/${cb}(`) || b.startsWith(`/**/ ${cb}(`);
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
const INLINE_MEDIA_CT = /^\s*(?:image\/(?!svg)|audio\/|video\/)/i;
export const downloadResponse: Rule = { id: 'E-11', title: 'ダウンロード応答', appliesTo: 'any', scope: 'target',
  basis: ['OWASP File Upload CS'],
  run(ctx) {
    const f = ctx.final; if (!f) return [];
    const ct = header(ctx, 'content-type')[0] ?? ''; const cd = header(ctx, 'content-disposition')[0] ?? '';
    const uploadPath = /\/(uploads?|files?|attachments?|media|download)\//i.test(path(ctx));
    if (!DOWNLOAD_CT.test(ct) && !uploadPath && !cd) return [];   // ファイル配信の応答だけ
    if (uploadPath && ACTIVE_CT.test(ct) && !/attachment/i.test(cd))
      return [mk(downloadResponse, ctx, 1, 'high', 'fail', `Content-Type: ${ct} / Content-Disposition: ${cd || '(なし)'}`, '利用者がアップロードしたファイルは別オリジンから attachment で配信する')];
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
      return got.length ? got.map(p => mk(sourceMap, ctx, 1, 'medium', 'fail', `${p.path}（HTTP ${p.code}、一致したパターン: source-map）`, '本番では .map を配信しない（sourcesContent に元のソースがあるかは手動で確認）'))
                        : [mk(sourceMap, ctx, 'ok', 'info', 'pass', `${maps.length}件の .map は取得できなかった`, '')];
    }
    const f = ctx.final; if (!f) return [];
    const ref = header(ctx, 'sourcemap')[0] ?? header(ctx, 'x-sourcemap')[0] ?? body(ctx)?.match(/\/[/*]#\s*sourceMappingURL=(\S+)/)?.[1];
    const isJs = /javascript|ecmascript/i.test(header(ctx, 'content-type')[0] ?? '') || /\.m?js(?:[?#]|$)/.test(ctx.target.url ?? '');
    if (!isJs && !ref) return [];
    return ref ? [mk(sourceMap, ctx, 2, 'low', 'fail', `参照: ${ref.slice(0, 120)}`, '本番ビルドでは sourceMappingURL を出さない。.map を C13 のパス一覧に追加して取得できるか確認する')]
               : [mk(sourceMap, ctx, 'ok', 'info', 'pass', 'ソースマップへの参照なし', '')];
  } };
