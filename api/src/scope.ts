// Thin client to the Go scopeguard control API, used by the API to reject any
// job whose target is out of scope BEFORE it is queued. Fails closed.

const CONTROL = process.env.SCOPEGUARD_CONTROL ?? "http://127.0.0.1:8898";

export async function checkScope(
  host: string,
  port = 443,
  actor = "api",
): Promise<{ allowed: boolean; reason: string }> {
  const url = `${CONTROL}/check?host=${encodeURIComponent(host)}&port=${port}&actor=${encodeURIComponent(actor)}`;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return { allowed: false, reason: `scope guard returned ${r.status}` };
    const data = (await r.json()) as { allowed?: boolean; reason?: string };
    return { allowed: Boolean(data.allowed), reason: data.reason ?? "" };
  } catch (e) {
    // Fail closed: if we cannot confirm scope, deny.
    return { allowed: false, reason: `scope guard unreachable (${String(e)}); failing closed` };
  }
}

export function hostPortFromTarget(target: string): { host: string; port: number } {
  const withScheme = target.includes("//") ? target : `https://${target}`;
  const u = new URL(withScheme);
  const port = u.port ? Number(u.port) : u.protocol === "http:" ? 80 : 443;
  return { host: u.hostname, port };
}
