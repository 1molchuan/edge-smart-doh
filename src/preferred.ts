import type { AppConfig } from "./config";
import { parseIpv4, parseIpv6 } from "./dns/packet";
import { resolveDomainAddresses, type ResolvedAddresses } from "./rewrite";

/**
 * Learned preferred-IP lists pushed by out-of-band probers (see work/echprobe rank mode).
 * The default pool serves everyone; a scoped pool is keyed by the reporting prober's own client
 * prefix (/24, /48) and serves only clients in that prefix — so a prober on a home line teaches the
 * pool for that line without affecting anyone else. Entries live in memory and expire on their own
 * so a dead prober cannot pin a stale list forever.
 */
interface LearnedPool {
  ipv4: string[];
  ipv6: string[];
  expiresAt: number;
  source: string;
}

const MAX_SCOPED_POOLS = 32;
const MAX_DEFAULT_SOURCES = 8;
/** Operator pools ("isp:<name>", pushed by the probe hub, already aggregated there). */
const MAX_ISP_POOLS = 16;
/**
 * The probe hub's nationwide pool, built there from every mainland line's published pool. It is kept
 * with the operator pools but serves every client that relies on the default, ahead of the pool of
 * the maintainer's own probers (which stays as the fallback when the hub is quiet).
 */
export const HUB_NATIONAL_SCOPE = "isp:national";
/** Addresses served from a learned pool; probers may report more candidates than this. */
export const LEARNED_POOL_SIZE = 6;
/** Fewest addresses of a family a pool layer is served with on its own; a thinner layer is topped up. */
const MIN_SERVED_POOL = 2;
/**
 * Below this many IPs a majority of probers vouch for, fall back to interleaving the probers' lists.
 * Kept low: two IPs most lines vouch for beat six that mix in IPs only one line tolerates.
 */
const MIN_CONSENSUS = 2;

// Default-scope pools are kept per reporting prober and combined at read time, so probers on
// different networks (e.g. Aliyun Shanghai and Tencent Beijing) refine one pool instead of the
// last reporter overwriting the others.
const defaults = new Map<string, LearnedPool>();
const scoped = new Map<string, LearnedPool>();
const ispPools = new Map<string, LearnedPool>();

/**
 * `scope` undefined: one prober's report for the nationwide pool (combined across sources at read
 * time). A client prefix ("58.247.22/24"): that prober's pool for its own line. "isp:<name>": the
 * probe hub's already-aggregated pool for one operator.
 */
export function setLearnedPool(ipv4: string[], ipv6: string[], ttlSeconds: number, source: string, scope?: string): LearnedPool {
  for (const address of ipv4) parseIpv4(address);
  for (const address of ipv6) parseIpv6(address);
  const pool = { ipv4: [...new Set(ipv4)], ipv6: [...new Set(ipv6)], expiresAt: Date.now() + ttlSeconds * 1000, source };
  const isp = scope?.startsWith("isp:") === true;
  const target = scope === undefined ? defaults : isp ? ispPools : scoped;
  const key = scope ?? source;
  target.delete(key);
  target.set(key, pool);
  const limit = scope === undefined ? MAX_DEFAULT_SOURCES : isp ? MAX_ISP_POOLS : MAX_SCOPED_POOLS;
  while (target.size > limit) target.delete(target.keys().next().value as string);
  return pool;
}

export function clearLearnedPool(): void {
  defaults.clear();
  scoped.clear();
  ispPools.clear();
}

/** Most addresses served from one /24 (IPv6: /48), so one blocked range cannot empty the pool. */
const MAX_PER_BLOCK = 2;

function addressBlock(ip: string): string {
  if (ip.includes(":")) {
    try {
      return Array.from(parseIpv6(ip).slice(0, 6)).join(".");
    } catch {
      return ip;
    }
  }
  const dot = ip.lastIndexOf(".");
  return dot > 0 ? ip.slice(0, dot) : ip;
}

/**
 * Combine per-prober rankings (best first). An IP qualifies when a strict majority of probers
 * vouch for it: both of two, two of three. With three probers on different kinds of line, requiring
 * all of them let the strictest one decide alone (2026-09-24: 3 IPs good for all three, 13 for two
 * of three). More votes rank first, then the better average position; at most MAX_PER_BLOCK per
 * /24 (seven of those 13 sat in one /24). With too little agreement the lists are interleaved so
 * each prober still contributes.
 */
export function combineRankings(lists: string[][], size: number): string[] {
  const nonEmpty = lists.filter((list) => list.length > 0);
  if (nonEmpty.length <= 1) return (nonEmpty[0] ?? []).slice(0, size);
  const needed = Math.floor(nonEmpty.length / 2) + 1;
  const tally = new Map<string, { votes: number; positions: number }>();
  for (const list of nonEmpty) {
    list.forEach((ip, index) => {
      const entry = tally.get(ip) ?? { votes: 0, positions: 0 };
      entry.votes += 1;
      entry.positions += index;
      tally.set(ip, entry);
    });
  }
  const perBlock = new Map<string, number>();
  const consensus = [...tally]
    .filter(([, entry]) => entry.votes >= needed)
    .sort(([, a], [, b]) => b.votes - a.votes || a.positions / a.votes - b.positions / b.votes)
    .map(([ip]) => ip)
    .filter((ip) => {
      const key = addressBlock(ip);
      const used = perBlock.get(key) ?? 0;
      perBlock.set(key, used + 1);
      return used < MAX_PER_BLOCK;
    });
  if (consensus.length >= MIN_CONSENSUS) return consensus.slice(0, size);
  const interleaved: string[] = [];
  for (let index = 0; interleaved.length < size && nonEmpty.some((list) => index < list.length); index += 1) {
    for (const list of nonEmpty) {
      const ip = list[index];
      if (ip !== undefined && !interleaved.includes(ip)) interleaved.push(ip);
      if (interleaved.length >= size) break;
    }
  }
  return interleaved;
}

function activeDefaults(): LearnedPool[] {
  const now = Date.now();
  for (const [source, pool] of defaults) if (pool.expiresAt <= now) defaults.delete(source);
  return [...defaults.values()];
}

/**
 * Per-host IPv4 pools reported by several probers: each source's latest {host: [ips]} report replaces
 * its previous one, and a host's pool is merged at read time over the sources that list it (majority
 * first, see combineRankings). Reports expire, so a dead prober cannot pin a host forever.
 */
class HostPools {
  private readonly sources = new Map<string, { hosts: Map<string, string[]>; expiresAt: number }>();

  constructor(private readonly maxSources: number) {}

  set(source: string, hosts: Record<string, string[]>, ttlSeconds: number): void {
    const map = new Map<string, string[]>();
    for (const [host, ips] of Object.entries(hosts)) {
      const clean = [...new Set(ips)];
      for (const ip of clean) parseIpv4(ip);
      if (clean.length > 0) map.set(normalHost(host), clean);
    }
    this.sources.delete(source);
    this.sources.set(source, { hosts: map, expiresAt: Date.now() + ttlSeconds * 1000 });
    while (this.sources.size > this.maxSources) this.sources.delete(this.sources.keys().next().value as string);
  }

  clear(): void {
    this.sources.clear();
  }

  private active(): [string, { hosts: Map<string, string[]>; expiresAt: number }][] {
    const now = Date.now();
    for (const [source, report] of this.sources) if (report.expiresAt <= now) this.sources.delete(source);
    return [...this.sources];
  }

  /** The merged pool for host (majority of the sources listing it, best first); [] if none lists it. */
  poolFor(host: string): string[] {
    const name = normalHost(host);
    const lists = this.active().map(([, report]) => report.hosts.get(name)).filter((list): list is string[] => list !== undefined);
    return lists.length === 0 ? [] : combineRankings(lists, LEARNED_POOL_SIZE);
  }

  status(): { sources: { source: string; hosts: number; expiresAt: number }[]; hosts: Record<string, string[]> } | undefined {
    const active = this.active();
    if (active.length === 0) return undefined;
    const hosts: Record<string, string[]> = {};
    for (const [, report] of active) for (const name of report.hosts.keys()) hosts[name] ??= this.poolFor(name);
    return { sources: active.map(([source, report]) => ({ source, hosts: report.hosts.size, expiresAt: report.expiresAt })), hosts };
  }

  /** Every live report as posted, so a restart can post them back (deploy/restart-keep-state.sh). */
  reports(): HostReport[] {
    return this.active().map(([source, report]) => ({ source, hosts: Object.fromEntries(report.hosts), expiresAt: report.expiresAt }));
  }
}

export interface HostReport {
  source: string;
  hosts: Record<string, string[]>;
  expiresAt: number;
}

function normalHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/**
 * Per-domain preferred-IP pools for GitHub-family names. Unlike Cloudflare, GitHub publishes no ECH
 * (so nothing is hidden) and its hosts sit on unrelated infrastructures — GitHub's own ranges
 * (github.com, api, codeload, gist) and its Fastly user-content range 185.199.108.0/22 (raw, objects,
 * avatars, assets, *.github.io) — whose reachability from a given China line differs per host and per
 * IP. So each host gets its OWN measured pool: a prober reports {host: [ips]} it verified from inside
 * the GFW, and answers for that host are pinned to the merged pool. Candidates come from community
 * hosts sources; the prober keeps only what works from its line, like the Cloudflare pool.
 */
const github = new HostPools(8);

export function setGithubPools(source: string, hosts: Record<string, string[]>, ttlSeconds: number): void {
  github.set(source, hosts, ttlSeconds);
}

export function clearGithubPools(): void {
  github.clear();
}

/** The merged IPv4 pool a GitHub host is pinned to (majority of probers, best first); [] if none. */
export function githubPoolFor(host: string): string[] {
  return github.poolFor(host);
}

export function githubPoolStatus(): ReturnType<HostPools["status"]> {
  return github.status();
}

export function githubReports(): HostReport[] {
  return github.reports();
}

/**
 * Site pools: Cloudflare sites whose ORIGIN the general pool cannot reach from some line. The pool's
 * IPs are ranked by ECH handshakes, which end at the Cloudflare edge; a site can still hang when the
 * colo a line lands on cannot reach that site's origin (2026-09-26: linux.do requests through the
 * Singapore colo hung for everyone routed there, while Frankfurt answered in 300 ms). A site-check
 * prober (work/echprobe -sitecheck) fetches real pages through the general pool; when too many hang
 * it reports IPs it verified end to end, and the site's answers are pinned to them (keeping ECH).
 * A report without the host (the general pool works again) withdraws that source's override.
 */
const sites = new HostPools(8);

export function setSitePools(source: string, hosts: Record<string, string[]>, ttlSeconds: number): void {
  sites.set(source, hosts, ttlSeconds);
}

export function clearSitePools(): void {
  sites.clear();
}

export function sitePoolFor(host: string): string[] {
  return sites.poolFor(host);
}

export function sitePoolStatus(): ReturnType<HostPools["status"]> {
  return sites.status();
}

export function siteReports(): HostReport[] {
  return sites.reports();
}

/** Cache-key tag for a host with an active site pool (content hash: stable across restarts), else undefined. */
export function sitePoolCacheTag(host: string): string | undefined {
  const pool = sites.poolFor(host);
  return pool.length === 0 ? undefined : `site${fnv(pool.join(","))}`;
}

function fnv(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

export function learnedPoolStatus(): (LearnedPool & { active: boolean; sources: { source: string; ipv4: string[]; ipv6: string[]; expiresAt: number }[] }) | undefined {
  const pool = activeLearnedPool();
  if (!pool) return undefined;
  return {
    ...pool,
    active: true,
    sources: [...defaults.values()].map(({ source, ipv4, ipv6, expiresAt }) => ({ source, ipv4, ipv6, expiresAt })),
  };
}

export function scopedPoolStatus(): (LearnedPool & { scope: string; active: boolean })[] {
  const now = Date.now();
  return [...scoped].map(([scope, pool]) => ({ scope, ...pool, active: pool.expiresAt > now }));
}

export function ispPoolStatus(): (LearnedPool & { scope: string; active: boolean })[] {
  const now = Date.now();
  return [...ispPools].map(([scope, pool]) => ({ scope, ...pool, active: pool.expiresAt > now }));
}

function activePoolIn(pools: Map<string, LearnedPool>, scope: string | undefined): LearnedPool | undefined {
  if (scope === undefined) return undefined;
  const pool = pools.get(scope);
  if (pool && pool.expiresAt <= Date.now()) {
    pools.delete(scope);
    return undefined;
  }
  return pool;
}

/**
 * Meta does not publish its ECHConfig in DNS, so META_ECH_CONFIG_BASE64 is a static seed.
 * Meta's servers do, however, return their current key set in TLS `retry_configs` when a
 * client offers a stale one. A prober that sees an ECH rejection extracts that list and pushes
 * it here; the learned key overrides the seed until it expires, so a key rotation heals itself
 * without a redeploy. If the prober reports a rejection but cannot recover a key, injection is
 * suspended so clients get the untouched upstream answer instead of a guaranteed-failing ECH.
 */
interface MetaEchState {
  /** Learned ECHConfigList (raw bytes) or undefined when injection is suspended. */
  config?: Uint8Array;
  until: number;
  source: string;
  reason: string;
}


let metaEch: MetaEchState | undefined;
// Bumped on every override change; folded into the cache key of Meta HTTPS answers so a new key
// takes effect immediately instead of after the cached answer's TTL.
let metaEchGeneration = 0;

export function setMetaEch(config: Uint8Array | undefined, ttlSeconds: number, source: string, reason: string): MetaEchState {
  const sameKey = metaEch !== undefined && sameBytes(metaEch.config, config);
  metaEch = { config, until: Date.now() + ttlSeconds * 1000, source: source.slice(0, 64), reason: reason.slice(0, 200) };
  if (!sameKey) metaEchGeneration += 1;
  return metaEch;
}

function sameBytes(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

export function clearMetaEch(): void {
  if (metaEch) metaEchGeneration += 1;
  metaEch = undefined;
}

/** Returns the learned key to inject, `null` when injection is suspended, or `undefined` to use the configured seed. */
export function metaEchOverride(): Uint8Array | null | undefined {
  if (metaEch && metaEch.until <= Date.now()) {
    metaEch = undefined;
    metaEchGeneration += 1;
  }
  if (!metaEch) return undefined;
  return metaEch.config ?? null;
}

export function metaEchCacheTag(): string {
  metaEchOverride();
  return `meta${metaEchGeneration}`;
}

export function metaEchStatus(): { mode: "learned" | "suspended"; bytes: number; until: number; source: string; reason: string; active: boolean } | undefined {
  if (!metaEch) return undefined;
  return {
    mode: metaEch.config ? "learned" : "suspended",
    bytes: metaEch.config?.length ?? 0,
    until: metaEch.until,
    source: metaEch.source,
    reason: metaEch.reason,
    active: metaEch.until > Date.now(),
  };
}

function activeLearnedPool(): LearnedPool | undefined {
  const pools = activeDefaults();
  if (pools.length === 0) return undefined;
  return {
    ipv4: combineRankings(pools.map((pool) => pool.ipv4), LEARNED_POOL_SIZE),
    ipv6: combineRankings(pools.map((pool) => pool.ipv6), LEARNED_POOL_SIZE),
    expiresAt: Math.max(...pools.map((pool) => pool.expiresAt)),
    source: pools.map((pool) => pool.source).join("+"),
  };
}

async function mergedDomainPool(domains: string[], config: AppConfig, cache: Cache): Promise<ResolvedAddresses> {
  const results = await Promise.allSettled(domains.map((domain) => resolveDomainAddresses(domain, config, cache)));
  const ipv4 = new Set<string>();
  const ipv6 = new Set<string>();
  let failures = 0;
  for (const result of results) {
    if (result.status !== "fulfilled") {
      failures += 1;
      continue;
    }
    for (const address of result.value.ipv4) ipv4.add(address);
    for (const address of result.value.ipv6) ipv6.add(address);
  }
  if (failures === results.length) throw new Error(`Unable to resolve any preferred domain (${domains.join(", ")})`);
  return { ipv4: [...ipv4].slice(0, 16), ipv6: [...ipv6].slice(0, 16) };
}

/**
 * Resolve the preferred-IP pool for this request. Precedence: explicit ?ip4/?ip6 → the client's own
 * prefix pool → its operator's pool (`ispScope`, from the probe hub) → the hub's nationwide pool →
 * the nationwide learned pool of the maintainer's probers (all four only when the request relies on
 * the server default) → ?cf= / default domains. Each
 * address family is filled on its own from the narrowest pool that has at least MIN_SERVED_POOL
 * addresses of it (a thinner one is topped up from the wider ones, to at most LEARNED_POOL_SIZE), so
 * a narrower pool with only IPv4 does not hide the wider pool's IPv6 and a single address is never
 * served alone. `scope` names the narrower pools that contributed, so
 * callers can keep their answers out of the shared cache entry.
 * Answer ordering is rotated at serve time (see rotateAddressRecords), not here, so cached
 * responses spread clients across the pool too.
 */
export async function preferredPool(
  explicit: { ipv4?: string[]; ipv6?: string[] },
  domains: string[],
  usingDefault: boolean,
  config: AppConfig,
  cache: Cache,
  clientScope?: string,
  ispScope?: string,
): Promise<ResolvedAddresses & { scope?: string }> {
  let ipv4 = explicit.ipv4 ?? config.cfPreferredIpv4;
  let ipv6 = explicit.ipv6 ?? config.cfPreferredIpv6;
  const layers: { pool: LearnedPool; scope?: string }[] = [];
  if (usingDefault) {
    const client = activePoolIn(scoped, clientScope);
    if (client) layers.push({ pool: client, scope: clientScope });
    const isp = activePoolIn(ispPools, ispScope);
    if (isp) layers.push({ pool: isp, scope: ispScope });
    // Serves everyone on the default, like the pool below, so it needs no cache scope of its own.
    const hubNational = ispScope === HUB_NATIONAL_SCOPE ? undefined : activePoolIn(ispPools, HUB_NATIONAL_SCOPE);
    if (hubNational) layers.push({ pool: hubNational });
    const nationwide = activeLearnedPool();
    if (nationwide) layers.push({ pool: nationwide });
  }
  const used = new Set<string>();
  if (layers.length > 0) {
    // Narrowest layer first, served alone once it has MIN_SERVED_POOL addresses; a thinner one is
    // topped up from the wider ones. The hub publishes only each line's fast tier, so filling a short
    // operator pool up to six with nationwide addresses measured on other lines undid that cut
    // (2026-10-06: mobile's three fast IPs came with three that only telecom and cloud had measured).
    const fill = (family: "ipv4" | "ipv6"): string[] | undefined => {
      const out: string[] = [];
      for (const layer of layers) {
        const fresh = layer.pool[family].filter((ip) => !out.includes(ip)).slice(0, LEARNED_POOL_SIZE - out.length);
        if (fresh.length === 0) continue;
        out.push(...fresh);
        if (layer.scope) used.add(layer.scope);
        if (out.length >= MIN_SERVED_POOL) break;
      }
      return out.length > 0 ? out : undefined;
    };
    const v4 = explicit.ipv4 ? undefined : fill("ipv4");
    const v6 = explicit.ipv6 || config.cfDropAaaa ? undefined : fill("ipv6");
    if (v4) ipv4 = v4;
    if (v6) ipv6 = v6;
  } else if (domains.length > 0 && (!explicit.ipv4 || !explicit.ipv6)) {
    const resolved = await mergedDomainPool(domains, config, cache);
    if (!explicit.ipv4) ipv4 = resolved.ipv4;
    if (!explicit.ipv6) ipv6 = resolved.ipv6;
  }
  if (config.cfDropAaaa) ipv6 = [];
  return { ipv4, ipv6, scope: used.size > 0 ? [...used].join(",") : undefined };
}
