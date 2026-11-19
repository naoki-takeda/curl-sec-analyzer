// rules/jwt.ts：JWT の部分（base64url の JSON）の読み取り。A-03 と E-09（公開を前提にした JWT）で共有する

/** base64url の JSON をデコードする（読めなければ undefined。署名は検証しない） */
export const b64urlJson = (s: string): Record<string, unknown> | undefined => {
  try { return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0)))) as Record<string, unknown>; } catch { return undefined; }
};
