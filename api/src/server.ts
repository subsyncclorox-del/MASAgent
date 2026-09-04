// MASAgent API server.
//
// Authorization gate on EVERY job endpoint (requireToken). A job is only queued
// after (1) its bearer token verifies, (2) the token's engagement/scope match
// the job, and (3) the scope guard confirms the target is in scope. There is no
// unauthenticated path that touches the network.

import express from "express";
import type { Response } from "express";

import { requireToken, assertScopeMatch, mintToken, type AuthedRequest } from "./auth.js";
import { MemoryJobStore } from "./queue.js";
import { EngagementRegistry } from "./engagements.js";
import { checkScope, hostPortFromTarget } from "./scope.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

const jobs = new MemoryJobStore();
const engagements = new EngagementRegistry();

const ADMIN_KEY = process.env.MASAGENT_ADMIN_KEY ?? "";

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, service: "masagent-api" });
});

// Register an engagement and mint its first token. Admin-gated: creating an
// engagement is an operator action, not a customer one.
app.post("/engagements", (req, res: Response) => {
  if (!ADMIN_KEY || req.header("x-admin-key") !== ADMIN_KEY) {
    res.status(403).json({ error: "admin key required to register an engagement" });
    return;
  }
  const { engagementId, name, scopeSha, ttlSeconds } = req.body ?? {};
  if (typeof engagementId !== "string" || typeof scopeSha !== "string" || scopeSha.length !== 64) {
    res.status(400).json({ error: "engagementId and 64-char scopeSha are required" });
    return;
  }
  const eng = engagements.register(engagementId, name ?? "", scopeSha);
  const token = mintToken(engagementId, scopeSha, Number(ttlSeconds) || 86400);
  res.status(201).json({ engagement: eng, token });
});

// Submit a job. Requires a token bound to the declared engagement+scope, and an
// in-scope target.
app.post("/jobs", requireToken, async (req: AuthedRequest, res: Response) => {
  const claims = req.claims!;
  const { target, scopeSha } = req.body ?? {};
  if (typeof target !== "string" || typeof scopeSha !== "string") {
    res.status(400).json({ error: "target and scopeSha are required" });
    return;
  }
  const mismatch = assertScopeMatch(claims, claims.engagementId, scopeSha);
  if (mismatch) {
    res.status(403).json({ error: mismatch });
    return;
  }
  let host: string, port: number;
  try {
    ({ host, port } = hostPortFromTarget(target));
  } catch {
    res.status(400).json({ error: "invalid target URL" });
    return;
  }
  const scope = await checkScope(host, port, "api");
  if (!scope.allowed) {
    res.status(403).json({ error: `target out of scope: ${scope.reason}` });
    return;
  }
  const job = jobs.enqueue(claims.engagementId, target);
  res.status(202).json({ job });
});

// Fetch a job (own engagement only).
app.get("/jobs/:id", requireToken, (req: AuthedRequest, res: Response) => {
  const job = jobs.get(req.params.id);
  if (!job || job.engagementId !== req.claims!.engagementId) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  res.json({ job });
});

// List this engagement's jobs.
app.get("/jobs", requireToken, (req: AuthedRequest, res: Response) => {
  res.json({ jobs: jobs.listByEngagement(req.claims!.engagementId) });
});

// Stream findings via Server-Sent Events.
app.get("/jobs/:id/findings", requireToken, (req: AuthedRequest, res: Response) => {
  const job = jobs.get(req.params.id);
  if (!job || job.engagementId !== req.claims!.engagementId) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  let sent = 0;
  const tick = setInterval(() => {
    const current = jobs.get(job.id);
    if (!current) return;
    while (sent < current.findings.length) {
      res.write(`data: ${JSON.stringify(current.findings[sent])}\n\n`);
      sent++;
    }
    if (current.status === "completed" || current.status === "failed") {
      res.write(`event: done\ndata: ${JSON.stringify({ status: current.status })}\n\n`);
      clearInterval(tick);
      res.end();
    }
  }, 1000);
  req.on("close", () => clearInterval(tick));
});

const PORT = Number(process.env.PORT ?? 8787);
// Export the app + stores so a worker or tests can drive them in-process.
export { app, jobs, engagements };

if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`masagent-api listening on :${PORT}`);
  });
}
