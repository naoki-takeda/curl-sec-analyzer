// rules/ruleset.ts：ルールセット（全ルールの登録、ツールとルールセットの版）
import type { Rule } from '../model';
import { errorFormat, excessiveData, jsonHeaders, jwtClaims, methodControl, requestContentType, tokenExposure, unauthAccess } from './api';
import { cookieDomain, cookieHttpOnly, cookieLifetime, cookieOverHttp, cookiePrefix, cookieSameSite, cookieSecure,
         cookieSharedCache, cookiePartitioned, defaultCookieName, logoutDeletesCookie, sessionIdStrength, sessionInUrl } from './cookies';
import { corsExpose, corsNull, corsPartial, corsPreflight, corsReflect, corsVary, corsWildcard, timingAllowOrigin, websocketOrigin } from './cors';
import { CROSS_RULES } from './cross';
import { cacheControl, clearSiteData, clickjacking, contentType, crossOriginIsolation, cspDeprecated, cspObjectBase, cspPresence,
         cspScript, deprecatedHeaders, hsts, hstsPreload, nosniff, permissionsPolicy, productInfo, referrerPolicy, xpcdp } from './headers';
import { certificate, cipherSuites, knownFiles, tlsVersion } from './hostRules';
import { csrfToken, mixedContentRule, passwordForm, htmlSecrets, sriRule } from './html';
import { apiDocsAdmin, dirListing, downloadResponse, errorDetail, jsonp, robotsSecurityTxt, sourceMap } from './exposure';
import { crlfInjection, hostInjection, httpVersion, httpsRedirect, methods, openRedirect, redirectChain } from './transport';

export const TOOL_VERSION = '0.4.26';
export const RULESET_VERSION = '2026.11-v0.4.26';

export const TARGET_RULES: Rule[] = [
  hsts, hstsPreload, cspPresence, cspScript, cspObjectBase, clickjacking, cspDeprecated, nosniff, referrerPolicy, permissionsPolicy,
  crossOriginIsolation, cacheControl, contentType, xpcdp, clearSiteData, productInfo, deprecatedHeaders,
  cookieSecure, cookieHttpOnly, cookieSameSite, cookieDomain, cookieLifetime, cookiePrefix, sessionIdStrength, defaultCookieName,
  sessionInUrl, cookieOverHttp, logoutDeletesCookie, cookieSharedCache,
  corsReflect, corsNull, corsPartial, corsWildcard, corsPreflight, corsVary, corsExpose,
  httpsRedirect, redirectChain, hostInjection, crlfInjection, jsonHeaders,
  methods, openRedirect, httpVersion,
  cookiePartitioned, timingAllowOrigin, websocketOrigin,
  unauthAccess, tokenExposure, jwtClaims, excessiveData, requestContentType, methodControl,
  errorDetail, dirListing, robotsSecurityTxt, apiDocsAdmin, jsonp, mixedContentRule, sriRule, htmlSecrets, passwordForm, downloadResponse, csrfToken, sourceMap,
];
export const HOST_RULES: Rule[] = [tlsVersion, cipherSuites, certificate, knownFiles];
export const ALL_CROSS_RULES: Rule[] = [...CROSS_RULES, errorFormat];

/** 診断カバレッジの「実装済みの項目」：ルールセットに登録したルールの項目IDから作る */
export const IMPLEMENTED = new Set([...TARGET_RULES, ...HOST_RULES, ...ALL_CROSS_RULES].map(r => r.id));
