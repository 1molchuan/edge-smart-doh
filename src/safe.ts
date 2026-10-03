import type { AppConfig } from "./config";
import { DnsType, type DnsPacket } from "./dns/types";

/**
 * Opt-in ad and scam blocking (?safe=1). SAFE_LIST_URLS are block lists, one domain per line; each
 * entry also blocks its subdomains. Accepted line shapes: plain `example.com`, hosts `0.0.0.0 example.com`,
 * adblock `||example.com^` (rules with $options are skipped), `*.example.com`, and exceptions
 * `@@||example.com^`. SAFE_ALLOW names domains that are never blocked (a false positive is fixed there).
 * The lists load in the background and refresh daily; until the first load lands nothing is blocked.
 */

const MAX_LIST_BYTES = 16 * 1024 * 1024;
const REFRESH_MS = 24 * 60 * 60_000;
const RETRY_MS = 10 * 60_000;
/** Clients cache a blocked answer this long (via the SOA minimum), so an app is not re-asked every second. */
export const SAFE_BLOCK_TTL = 600;

const DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;
const NEVER = new Set(["localhost", "localhost.localdomain", "local", "broadcasthost"]);

export interface SafeTable {
  block: Set<string>;
  allow: Set<string>;
}

function entry(line: string): { name: string; allow: boolean } | undefined {
  let text = line.trim();
  if (!text || text.startsWith("#") || text.startsWith("!")) return undefined;
  let allow = false;
  if (text.startsWith("@@")) {
    allow = true;
    text = text.slice(2);
  }
  if (text.startsWith("||")) {
    if (!text.endsWith("^")) return undefined; // $options, paths and the like are not plain domains
    text = text.slice(2, -1);
  } else {
    const fields = text.split(/\s+/);
    if (fields.length >= 2 && (fields[0] === "0.0.0.0" || fields[0] === "127.0.0.1" || fields[0] === "::")) text = fields[1]!;
    else if (fields.length !== 1) return undefined;
    if (text.startsWith("*.")) text = text.slice(2);
  }
  const name = text.toLowerCase().replace(/\.$/, "");
  return DOMAIN.test(name) && !NEVER.has(name) ? { name, allow } : undefined;
}

export function parseSafeLists(lists: string[]): SafeTable {
  const table: SafeTable = { block: new Set(), allow: new Set() };
  for (const text of lists) {
    if (text.length > MAX_LIST_BYTES) throw new Error("safe list too large");
    for (const line of text.split("\n")) {
      const parsed = entry(line);
      if (parsed) (parsed.allow ? table.allow : table.block).add(parsed.name);
    }
  }
  if (table.block.size === 0) throw new Error("safe lists have no usable entries");
  return table;
}

/**
 * The list entry that blocks `name` (the name itself or a parent), or undefined. An allowed suffix wins:
 * a list exception or an entry of `allow` (SAFE_ALLOW, checked here so a change needs no list reload).
 */
export function safeMatch(table: SafeTable, name: string, allow: string[] = []): string | undefined {
  const labels = name.toLowerCase().replace(/\.$/, "").split(".");
  let match: string | undefined;
  for (let index = 0; index < labels.length - 1; index += 1) {
    const suffix = labels.slice(index).join(".");
    if (table.allow.has(suffix) || allow.includes(suffix)) return undefined;
    match ??= table.block.has(suffix) ? suffix : undefined;
  }
  return match;
}

let current: SafeTable | undefined;
let loadedAt = 0;
let failedAt = 0;
let inflight: Promise<void> | undefined;

async function refresh(config: AppConfig): Promise<void> {
  // All or nothing: a failed list keeps the previous table rather than silently blocking less.
  const lists = await Promise.all(config.safeListUrls.map(async (url) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`safe list ${url}: HTTP ${response.status}`);
    return response.text();
  }));
  current = parseSafeLists(lists);
  loadedAt = Date.now();
}

/** The list entry that blocks `name` for a ?safe=1 request, or undefined. Never waits on a download. */
export function safeBlocked(name: string, config: AppConfig): string | undefined {
  if (config.safeListUrls.length === 0) return undefined;
  const now = Date.now();
  if ((!current || now - loadedAt >= REFRESH_MS) && now - failedAt >= RETRY_MS) {
    inflight ??= refresh(config)
      .catch((error: unknown) => {
        failedAt = Date.now();
        console.warn(JSON.stringify({ event: "safe_list_error", message: error instanceof Error ? error.message : String(error) }));
      })
      .finally(() => {
        inflight = undefined;
      });
  }
  return current ? safeMatch(current, name, config.safeAllow) : undefined;
}

export function safeStatus(): { block: number; allow: number; loadedAt: string } | undefined {
  return current ? { block: current.block.size, allow: current.allow.size, loadedAt: new Date(loadedAt).toISOString() } : undefined;
}

/** NXDOMAIN with an SOA, so clients cache the refusal for SAFE_BLOCK_TTL instead of retrying at once. */
export function safeBlockedResponse(query: DnsPacket): DnsPacket {
  const name = query.questions[0]!.name;
  return {
    header: { ...query.header, flags: 0x8000 | (query.header.flags & 0x7910) | 0x0080 | 3, ancount: 0, nscount: 1, arcount: 0 },
    questions: query.questions,
    answers: [],
    authorities: [{
      name,
      type: DnsType.SOA,
      class: 1,
      ttl: SAFE_BLOCK_TTL,
      rdata: { kind: "soa", mname: "safe.invalid", rname: "blocked.safe.invalid", serial: 1, refresh: 3600, retry: 600, expire: 86400, minimum: SAFE_BLOCK_TTL },
    }],
    additionals: [],
  };
}

/** Test hooks. */
export async function safeListsSettled(): Promise<void> {
  await inflight;
}

export function resetSafeLists(): void {
  current = undefined;
  loadedAt = 0;
  failedAt = 0;
  inflight = undefined;
}
