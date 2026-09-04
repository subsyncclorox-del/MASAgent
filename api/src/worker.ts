// Job worker.
//
// Polls the job store for queued jobs and runs each through the masagent CLI,
// which itself only egresses through the scope guard. Findings are parsed from
// the CLI's report.json and pushed to the store so the SSE endpoint streams them.
//
// In production the worker is a separate process consuming from Redis/NATS; here
// it shares the in-memory store for a runnable reference.

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { jobs } from "./server.js";
import type { Finding } from "./types.js";

const SCOPE_FILE = process.env.MASAGENT_SCOPE_FILE ?? "";
const POLL_MS = Number(process.env.MASAGENT_WORKER_POLL_MS ?? 2000);

async function runJob(id: string, target: string): Promise<void> {
  jobs.update(id, { status: "running" });
  const outDir = join(tmpdir(), `masagent-${id}`);
  const args = ["run", "--scope", SCOPE_FILE, "--target", target, "--out", outDir];
  const child = spawn("masagent", args, { stdio: ["ignore", "inherit", "inherit"] });

  await new Promise<void>((resolve) => {
    child.on("exit", async (code) => {
      if (code !== 0) {
        jobs.update(id, { status: "failed", error: `cli exit ${code}` });
        resolve();
        return;
      }
      try {
        const report = JSON.parse(await readFile(join(outDir, "report.json"), "utf8"));
        for (const f of report.findings ?? []) {
          const finding: Finding = {
            vulnClass: f.vuln_class,
            endpoint: f.endpoint,
            title: f.title,
            severity: f.severity,
            source: f.source,
            proven: f.proof?.proven ?? false,
          };
          jobs.addFinding(id, finding);
        }
        jobs.update(id, { status: "completed" });
      } catch (e) {
        jobs.update(id, { status: "failed", error: String(e) });
      }
      resolve();
    });
  });
}

export function startWorker(): void {
  if (!SCOPE_FILE) {
    // eslint-disable-next-line no-console
    console.error("worker: MASAGENT_SCOPE_FILE not set; worker idle (jobs stay queued)");
    return;
  }
  let busy = false;
  setInterval(async () => {
    if (busy) return; // run one job at a time in this reference worker
    const next = jobs.pending()[0];
    if (!next) return;
    busy = true;
    try {
      await runJob(next.id, next.target);
    } finally {
      busy = false;
    }
  }, POLL_MS);
}

// A concrete single-job runner for tests / manual invocation.
export { runJob };
