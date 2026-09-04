// Minimal job queue front end.
//
// This is an in-memory reference implementation with the interface a Redis/NATS
// backed queue would expose (enqueue, get, list, update). Swap the store for a
// real broker in production; the API and workers only depend on this interface.

import { randomUUID } from "node:crypto";
import type { Job, Finding } from "./types.js";

export interface JobStore {
  enqueue(engagementId: string, target: string): Job;
  get(id: string): Job | undefined;
  listByEngagement(engagementId: string): Job[];
  update(id: string, patch: Partial<Job>): Job | undefined;
  addFinding(id: string, finding: Finding): void;
  pending(): Job[];
}

export class MemoryJobStore implements JobStore {
  private jobs = new Map<string, Job>();

  enqueue(engagementId: string, target: string): Job {
    const now = Date.now();
    const job: Job = {
      id: randomUUID(),
      engagementId,
      target,
      status: "queued",
      createdAt: now,
      updatedAt: now,
      findings: [],
    };
    this.jobs.set(job.id, job);
    return job;
  }

  get(id: string): Job | undefined {
    return this.jobs.get(id);
  }

  listByEngagement(engagementId: string): Job[] {
    return [...this.jobs.values()].filter((j) => j.engagementId === engagementId);
  }

  update(id: string, patch: Partial<Job>): Job | undefined {
    const job = this.jobs.get(id);
    if (!job) return undefined;
    Object.assign(job, patch, { updatedAt: Date.now() });
    return job;
  }

  addFinding(id: string, finding: Finding): void {
    const job = this.jobs.get(id);
    if (job) {
      job.findings.push(finding);
      job.updatedAt = Date.now();
    }
  }

  pending(): Job[] {
    return [...this.jobs.values()].filter((j) => j.status === "queued");
  }
}
