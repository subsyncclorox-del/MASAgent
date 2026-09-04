// Shared API types.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Engagement {
  engagementId: string;
  name: string;
  scopeSha: string; // sha256 of the canonical scope document
  createdAt: number;
}

export type JobStatus = "queued" | "running" | "completed" | "failed";

export interface Job {
  id: string;
  engagementId: string;
  target: string;
  status: JobStatus;
  createdAt: number;
  updatedAt: number;
  findings: Finding[];
  error?: string;
}

export interface Finding {
  vulnClass: string;
  endpoint: string;
  title: string;
  severity: Severity;
  source: string;
  proven: boolean;
}
