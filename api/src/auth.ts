// Per-engagement authorization gate.
//
// Every job carries an engagement token bound to a specific scope. The token is
// HMAC-signed and encodes <engagementId>.<scopeSha>.<exp>. A job is rejected
// unless its token is valid AND its declared engagement/scope match the token —
// this is what stops a job running against a target the token does not cover.
//
// The scheme is byte-compatible with the Python orchestrator's engagement.py so
// a token minted by either side verifies on the other.

import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";

const SECRET = process.env.MASAGENT_TOKEN_SECRET ?? "";

export function mintToken(
  engagementId: string,
  scopeSha: string,
  ttlSeconds = 86400,
  secret = SECRET,
): string {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `${engagementId}.${scopeSha}.${exp}`;
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

export interface TokenClaims {
  engagementId: string;
  scopeSha: string;
  exp: number;
}

export function verifyToken(
  token: string,
  secret = SECRET,
): { ok: true; claims: TokenClaims } | { ok: false; reason: string } {
  if (!secret) return { ok: false, reason: "server has no MASAGENT_TOKEN_SECRET configured" };
  const parts = token.split(".");
  if (parts.length !== 4) return { ok: false, reason: "malformed token" };
  const [engagementId, scopeSha, expStr, sig] = parts;
  const payload = `${engagementId}.${scopeSha}.${expStr}`;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "bad signature" };
  }
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: "token expired" };
  }
  return { ok: true, claims: { engagementId, scopeSha, exp } };
}

// Express request augmented with verified claims.
export interface AuthedRequest extends Request {
  claims?: TokenClaims;
}

// requireToken is the middleware on every protected endpoint. It rejects any
// request without a valid bearer token before the handler runs.
export function requireToken(req: AuthedRequest, res: Response, next: NextFunction): void {
  const header = req.header("authorization") ?? "";
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }
  const result = verifyToken(m[1]);
  if (!result.ok) {
    res.status(403).json({ error: `authorization failed: ${result.reason}` });
    return;
  }
  req.claims = result.claims;
  next();
}

// assertScopeMatch ensures the job's engagement/scope match the token's. A token
// for engagement A can never drive a job declared under engagement B.
export function assertScopeMatch(
  claims: TokenClaims,
  engagementId: string,
  scopeSha: string,
): string | null {
  if (claims.engagementId !== engagementId) return "token engagement does not match job engagement";
  if (claims.scopeSha !== scopeSha) return "token scope does not match job scope";
  return null;
}
