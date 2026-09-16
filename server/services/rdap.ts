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
    return { status: "skipped", registrant: null, organization: null };
  }
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const hit = cache.get(host);
  if (hit && Date.now() - hit.at < TTL) return hit.value;

  const urls: string[] = [`https://rdap.org/domain/${encodeURIComponent(host)}`];
  if (host.endsWith(".com") || host.endsWith(".net")) {
    urls.push(`https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(host)}`);
  }
  if (host.endsWith(".org")) {
    urls.push(`https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(host)}`);
  }

  for (const url of urls) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json, application/json" },
      });
      if (!res.ok) continue;
      const data = (await res.json()) as {
        entities?: Array<Record<string, unknown>>;
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
      /* try next endpoint */
    } finally {
      clearTimeout(timer);
    }
  }

  const value: RdapResult = {
    status: "error",
    registrant: null,
    organization: null,
  };
  cache.set(host, { at: Date.now(), value });
  return value;
}

export function clearRdapCache(): void {
  cache.clear();
}
