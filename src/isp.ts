import { matchCache } from "./cache-api";
import type { AppConfig } from "./config";
import { parseIpv4, parseIpv6 } from "./dns/packet";

/**
 * Client IP → network operator, for operator-scoped preferred pools. In mainland China the route to
 * Cloudflare depends mostly on the operator (each has its own international exits), so the probe hub
 * (work/cfhub) aggregates volunteer reports per operator and pushes one pool per operator as scope
 * "isp:<name>". The table comes from the hub (ISP_TABLE_URL): one "<isp> <cidr>" per line, built daily
 * from github.com/gaoyifan/china-operator-ip. CIDRs may nest; the most specific one wins.
 */

const ISP_NAME = /^[a-z][a-z0-9-]{1,23}$/;
const MAX_TABLE_BYTES = 4 * 1024 * 1024;
/** Re-read the (cached) table this often; the hub rebuilds it daily. */
const REFRESH_MS = 10 * 60_000;
/** After a failed first load, don't retry on every query. */
const RETRY_MS = 60_000;

export function isIspName(value: string): boolean {
  return ISP_NAME.test(value);
}

/** Sorted CIDR ranges with a parent pointer to the nearest enclosing range (CIDRs nest or are disjoint). */
interface RangeSet {
  start: bigint[];
  end: bigint[];
  parent: Int32Array;
  isp: Uint16Array;
}

export interface IspTable {
  names: string[];
  v4: RangeSet;
  v6: RangeSet;
}

function toBigint(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function buildRanges(entries: { start: bigint; end: bigint; isp: number }[]): RangeSet {
  // Equal starts: broader range first, so the more specific one is found first and points at it.
  entries.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : a.end > b.end ? -1 : a.end < b.end ? 1 : 0));
  const parent = new Int32Array(entries.length);
  const stack: number[] = [];
  entries.forEach((entry, index) => {
    while (stack.length > 0 && entries[stack[stack.length - 1]!]!.end < entry.start) stack.pop();
    parent[index] = stack.length > 0 ? stack[stack.length - 1]! : -1;
    stack.push(index);
  });
  return {
    start: entries.map((entry) => entry.start),
    end: entries.map((entry) => entry.end),
    parent,
    isp: Uint16Array.from(entries.map((entry) => entry.isp)),
  };
}

export function parseIspTable(text: string): IspTable {
  if (text.length > MAX_TABLE_BYTES) throw new Error("ISP table too large");
  const names: string[] = [];
  const index = new Map<string, number>();
  const v4: { start: bigint; end: bigint; isp: number }[] = [];
  const v6: { start: bigint; end: bigint; isp: number }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [name, cidr] = line.split(/\s+/);
    // "national" names the hub's nationwide pool (preferred.ts), never an operator.
    if (!name || !cidr || !isIspName(name) || name === "national") continue;
    const [address, rawPrefix] = cidr.split("/");
    let bytes: Uint8Array;
    try {
      bytes = address!.includes(":") ? parseIpv6(address!) : parseIpv4(address!);
    } catch {
      continue;
    }
    const bits = bytes.length * 8;
    const prefix = Number(rawPrefix);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) continue;
    const hostMask = (1n << BigInt(bits - prefix)) - 1n;
    const start = toBigint(bytes) & ~hostMask;
    let isp = index.get(name);
    if (isp === undefined) {
      isp = names.push(name) - 1;
      index.set(name, isp);
    }
    (bits === 32 ? v4 : v6).push({ start, end: start | hostMask, isp });
  }
  if (v4.length === 0 && v6.length === 0) throw new Error("ISP table has no usable entries");
  return { names, v4: buildRanges(v4), v6: buildRanges(v6) };
}

export function lookupIsp(table: IspTable, ip: string): string | undefined {
  let address = ip.trim();
  if (address.toLowerCase().startsWith("::ffff:") && address.includes(".")) address = address.slice(7);
  let bytes: Uint8Array;
  try {
    bytes = address.includes(":") ? parseIpv6(address) : parseIpv4(address);
  } catch {
    return undefined;
  }
  const set = bytes.length === 4 ? table.v4 : table.v6;
  const value = toBigint(bytes);
  // Last range starting at or before the address is the most specific candidate; if it ends before the
  // address, any range containing it must enclose that candidate, so walk up the parent chain.
  let low = 0;
  let high = set.start.length - 1;
  let found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (set.start[middle]! <= value) {
      found = middle;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  for (let at = found; at >= 0; at = set.parent[at]!) {
    if (value <= set.end[at]!) return table.names[set.isp[at]!];
  }
  return undefined;
}

let current: IspTable | undefined;
let currentText: string | undefined;
let loadedAt = 0;
let failedAt = 0;
let inflight: Promise<void> | undefined;

async function refresh(url: string, cache: Cache): Promise<void> {
  const key = new Request("https://doh-config.invalid/isp-table");
  let text: string | undefined;
  const cached = await matchCache(cache, key);
  if (cached) text = await cached.text();
  if (text === undefined) {
    const response = await fetch(url, { headers: { "Cache-Control": "no-cache" }, signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`ISP table fetch failed: ${response.status}`);
    text = await response.text();
    parseIspTable(text); // validate before caching
    await cache.put(key, new Response(text, { headers: { "Cache-Control": "public, max-age=86400" } }));
  }
  if (text !== currentText) {
    current = parseIspTable(text);
    currentText = text;
  }
  loadedAt = Date.now();
}

/**
 * The operator scope ("isp:<name>") for a client address, or undefined when the feature is off, the
 * address is not in the table, or the table cannot be loaded. Never throws: a missing table only means
 * clients fall back to the nationwide pool. A stale table keeps serving while it refreshes in the background.
 */
export async function ispScopeOf(ip: string | undefined, config: AppConfig, cache: Cache): Promise<string | undefined> {
  if (!ip || !config.ispTableUrl) return undefined;
  const now = Date.now();
  if (!current || now - loadedAt >= REFRESH_MS) {
    if (!current && now - failedAt < RETRY_MS) return undefined;
    inflight ??= refresh(config.ispTableUrl, cache)
      .catch((error: unknown) => {
        failedAt = Date.now();
        if (config.debug) console.warn(JSON.stringify({ event: "isp_table_error", message: error instanceof Error ? error.message : String(error) }));
      })
      .finally(() => {
        inflight = undefined;
      });
    if (!current) await inflight;
  }
  const name = current ? lookupIsp(current, ip) : undefined;
  return name ? `isp:${name}` : undefined;
}

/** Whether a table is loaded: an address missing from it is then known to be outside every operator. */
export function ispTableReady(): boolean {
  return current !== undefined;
}

/** Test hook: forget the loaded table. */
export function resetIspTable(): void {
  current = undefined;
  currentText = undefined;
  loadedAt = 0;
  failedAt = 0;
  inflight = undefined;
}
