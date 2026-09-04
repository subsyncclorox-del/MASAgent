// Engagement registry. In production this is a database row per engagement; the
// reference implementation keeps them in memory. An engagement records the
// scope hash so the auth gate can bind tokens to a specific scope.

import type { Engagement } from "./types.js";

export class EngagementRegistry {
  private byId = new Map<string, Engagement>();

  register(engagementId: string, name: string, scopeSha: string): Engagement {
    const eng: Engagement = { engagementId, name, scopeSha, createdAt: Date.now() };
    this.byId.set(engagementId, eng);
    return eng;
  }

  get(engagementId: string): Engagement | undefined {
    return this.byId.get(engagementId);
  }

  list(): Engagement[] {
    return [...this.byId.values()];
  }
}
