import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";

/**
 * Chinese-site domain lists (ECS_DOMAIN_LIST_URLS), on top of the static ECS_DOMAINS: names on them
 * are resolved through ECS_UPSTREAMS with the client's subnet (or ECS_FALLBACK_SUBNET), so they get
 * the domestic CDN node a resolver inside China would hand out. Accepted lines: `example.com` and
 * `domain:example.com` (the name and its subdomains), `full:www.example.com` (that name only), and
 * dnsmasq `server=/example.com/...`; `regexp:` and `keyword:` lines are skipped. Loads in the
 * background and refreshes daily; until the first load only ECS_DOMAINS apply.
 */

const MAX_LIST_BYTES = 16 * 1024 * 1024;
const REFRESH_MS = 24 * 60 * 60_000;
const RETRY_MS = 10 * 60_000;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9-]{2,63}$/;

export interface DomainList {
  suffix: Set<string>;
  exact: Set<string>;
}

export function parseDomainLists(lists: string[]): DomainList {
  const table: DomainList = { suffix: new Set(), exact: new Set() };
  for (const text of lists) {
    if (text.length > MAX_LIST_BYTES) throw new Error("domain list too large");
    for (const raw of text.split("\n")) {
      let line = raw.trim().toLowerCase();
      if (!line || line.startsWith("#")) continue;
      let exact = false;
      const dnsmasq = /^server=\/([^/]+)\//.exec(line);
      if (dnsmasq) line = dnsmasq[1]!;
      else if (line.startsWith("full:")) {
        exact = true;
        line = line.slice(5);
      } else if (line.startsWith("domain:")) line = line.slice(7);
      else if (line.includes(":")) continue; // regexp:, keyword:, anything else
      line = line.replace(/\.$/, "");
      if (DOMAIN.test(line)) (exact ? table.exact : table.suffix).add(line);
    }
  }
  if (table.suffix.size === 0 && table.exact.size === 0) throw new Error("domain lists have no usable entries");
  return table;
}

export function domainListMatch(table: DomainList, name: string): boolean {
  const labels = name.toLowerCase().replace(/\.$/, "").split(".");
  if (table.exact.has(labels.join("."))) return true;
  for (let index = 0; index < labels.length; index += 1) if (table.suffix.has(labels.slice(index).join("."))) return true;
  return false;
}

let current: DomainList | undefined;
let loadedAt = 0;
let failedAt = 0;
let inflight: Promise<void> | undefined;

async function refresh(urls: string[]): Promise<void> {
  const lists = await Promise.all(urls.map(async (url) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`domain list ${url}: HTTP ${response.status}`);
    return response.text();
  }));
  current = parseDomainLists(lists);
  loadedAt = Date.now();
}

/** Whether `name` is on the Chinese-site lists. Never waits on a download. */
export function isChineseSite(name: string, config: AppConfig): boolean {
  if (config.ecsDomainListUrls.length === 0) return false;
  const now = Date.now();
  if ((!current || now - loadedAt >= REFRESH_MS) && now - failedAt >= RETRY_MS) {
    inflight ??= refresh(config.ecsDomainListUrls)
      .catch((error: unknown) => {
        failedAt = Date.now();
        console.warn(JSON.stringify({ event: "ecs_domain_list_error", message: error instanceof Error ? error.message : String(error) }));
      })
      .finally(() => {
        inflight = undefined;
      });
  }
  return current ? domainListMatch(current, name) : false;
}

/**
 * The one domestic-name verdict: the static suffixes (ECS_DOMAINS, then the operator's CN_DOMAINS)
 * or any of the loaded lists. It decides both upstream routing (CN_UPSTREAMS vs the proxied
 * trust list) and, when no CN upstreams are configured, which names carry ECS.
 */
export function isDomesticSite(name: string, config: AppConfig): boolean {
  return domainMatches(name, config.ecsDomains)
    || domainMatches(name, config.cnDomains)
    || isChineseSite(name, config);
}

export function chineseSiteStatus(): { suffix: number; exact: number; loadedAt: string } | undefined {
  return current ? { suffix: current.suffix.size, exact: current.exact.size, loadedAt: new Date(loadedAt).toISOString() } : undefined;
}

/** Test hooks. */
export async function chineseSitesSettled(): Promise<void> {
  await inflight;
}

export function resetChineseSites(): void {
  current = undefined;
  loadedAt = 0;
  failedAt = 0;
  inflight = undefined;
}
