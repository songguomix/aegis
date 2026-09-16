import type { RdapStatus } from "../types.js";

export interface RdapResult {
  status: RdapStatus;
  registrant: string | null;
  organization: string | null;
  rawName?: string | null;
}

const cache = new Map<string, { at: number; value: RdapResult }>();
const TTL = 12 * 60 * 60 * 1000;

function pickName(entity: Record<string, unknown>): string | null {
  const vcard = entity.vcardArray;
  if (!Array.isArray(vcard) || vcard.length < 2) return null;
  const rows = vcard[1] as Array<[string, unknown, unknown, unknown]>;
  const fn = rows.find((r) => r[0] === "fn");
  const org = rows.find((r) => r[0] === "org");
  const name = (fn?.[3] as string) || (org?.[3] as string) || null;
  return name || null;
}

function extractOrg(entity: Record<string, unknown>): string | null {
  const vcard = entity.vcardArray;
  if (!Array.isArray(vcard) || vcard.length < 2) return null;
  const rows = vcard[1] as Array<[string, unknown, unknown, unknown]>;
  const org = rows.find((r) => r[0] === "org");
  return (org?.[3] as string) || null;
}

export async function fetchRdap(
  hostname: string,
  timeoutMs = 3000,
  enabled = true,
): Promise<RdapResult> {
  if (!enabled) {
    return { status: "disabled", registrant: null, organization: null };
  }
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const hit = cache.get(host);
  if (hit && Date.now() - hit.at < TTL) return hit.value;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(host)}`, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json, application/json" },
    });
    if (!res.ok) {
      const value: RdapResult = {
        status: "error",
        registrant: null,
        organization: null,
      };
      cache.set(host, { at: Date.now(), value });
      return value;
    }
    const data = (await res.json()) as {
      entities?: Array<Record<string, unknown>>;
      status?: string[];
    };
    const entities = data.entities ?? [];
    const registrant =
      entities.find((e) => (e.roles as string[] | undefined)?.includes("registrant")) ??
      entities[0];
    const value: RdapResult = {
      status: "ok",
      registrant: registrant ? pickName(registrant) : null,
      organization: registrant ? extractOrg(registrant) : null,
    };
    cache.set(host, { at: Date.now(), value });
    return value;
  } catch {
    const value: RdapResult = {
      status: "error",
      registrant: null,
      organization: null,
    };
    cache.set(host, { at: Date.now(), value });
    return value;
  } finally {
    clearTimeout(timer);
  }
}

export function clearRdapCache(): void {
  cache.clear();
}
