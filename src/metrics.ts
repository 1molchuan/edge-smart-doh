/**
 * Bounded, in-memory operational metrics behind GET /admin/stats. Every structure is sized so the
 * module cannot grow with traffic: per-minute buckets roll off, the fresh-resolution latency window
 * is a fixed ring, tracked names and upstream entries are capped, and the recent-queries list is a
 * ring. A restart resets everything, which the dashboard surfaces as uptime.
 *
 * Cache-hit outcomes say how the client was answered: "hit" from a fresh cache entry, "prefetch"
 * from one revalidated in the background, "stale" from an expired entry (serve-stale, or the
 * never-wait Chromium HTTPS rule). "miss" waited on an upstream, "blocked" was refused by rules
 * before any resolution, and "error" is a fresh-resolution failure — with `servfail` marking the
 * ones where no cached answer could hide it from the client.
 */

export type QueryOutcome = "hit" | "prefetch" | "stale" | "miss" | "blocked" | "error";
export type UpstreamRole = "default" | "ecs";

export interface QuerySample {
  name: string;
  /** DNS type as shown to clients ("A", "AAAA", ...). */
  type: string;
  outcome: QueryOutcome;
  latencyMs: number;
  /** Winning upstream hostname — fresh resolutions only. */
  upstream?: string;
  /** Route-plan label ("direct", "preferred-ip", "github-pool", ...) — fresh resolutions only. */
  strategy?: string;
  /** Why a fresh resolution failed (outcome "error", or "stale" served over the failure). */
  error?: string;
  /** The query failed with SERVFAIL: no cached answer to fall back to. */
  servfail?: boolean;
}

export interface UpstreamSample {
  label: string;
  role: UpstreamRole;
  latencyMs: number;
  ok: boolean;
  error?: string;
}

interface MinuteBucket {
  t: number;
  queries: number;
  /** Answered without waiting for an upstream: hit, prefetch and stale. */
  hits: number;
  /** Fresh resolutions (miss). */
  misses: number;
  /** Fresh resolutions that failed (the client may still have gotten a stale answer). */
  errors: number;
}

interface UpstreamStat {
  ok: number;
  fail: number;
  totalMs: number;
  maxMs: number;
  lastMs: number;
  lastError?: string;
  lastUsedAt: number;
}

interface StrategyStat {
  count: number;
  totalMs: number;
}

const MINUTE_MS = 60_000;
const MINUTE_BUCKETS = 120;
const RECENT_MAX = 100;
const FRESH_LATENCY_SAMPLES = 2000;
const TOP_TRACKED = 1024;
const TOP_REPORTED = 20;
const STRATEGIES_MAX = 64;

const startedAt = Date.now();
const outcomes: Record<QueryOutcome, number> = { hit: 0, prefetch: 0, stale: 0, miss: 0, blocked: 0, error: 0 };
let servfail = 0;
let minutes: MinuteBucket[] = [];
const freshLatencies: number[] = [];
const top = new Map<string, number>();
const recent: (QuerySample & { t: number })[] = [];
const upstreams = new Map<string, UpstreamStat>();
const strategies = new Map<string, StrategyStat>();

export function recordQuery(sample: QuerySample, now = Date.now()): void {
  outcomes[sample.outcome] += 1;
  if (sample.servfail) servfail += 1;
  const bucket = currentMinute(now);
  bucket.queries += 1;
  if (sample.outcome === "hit" || sample.outcome === "prefetch" || sample.outcome === "stale") bucket.hits += 1;
  else if (sample.outcome === "miss") bucket.misses += 1;
  else if (sample.outcome === "error") bucket.errors += 1;
  if (sample.outcome === "miss") {
    freshLatencies.push(sample.latencyMs);
    if (freshLatencies.length > FRESH_LATENCY_SAMPLES) freshLatencies.splice(0, freshLatencies.length - FRESH_LATENCY_SAMPLES);
  }
  const count = top.get(sample.name);
  if (count !== undefined) top.set(sample.name, count + 1);
  else if (top.size < TOP_TRACKED) top.set(sample.name, 1);
  recent.push({ ...sample, t: now });
  if (recent.length > RECENT_MAX) recent.splice(0, recent.length - RECENT_MAX);
  if (sample.strategy) {
    const stat = strategies.get(sample.strategy) ?? { count: 0, totalMs: 0 };
    stat.count += 1;
    stat.totalMs += sample.latencyMs;
    strategies.set(sample.strategy, stat);
    if (strategies.size > STRATEGIES_MAX) {
      const oldest = strategies.keys().next().value;
      if (oldest !== undefined && oldest !== sample.strategy) strategies.delete(oldest);
    }
  }
}

export function recordUpstream(sample: UpstreamSample, now = Date.now()): void {
  // One upstream can serve several roles (dns.google in UPSTREAMS and ECS_UPSTREAMS, say); the
  // measurements only make sense per role, so the key carries it.
  const key = `${sample.role}:${sample.label}`;
  const stat = upstreams.get(key) ?? { ok: 0, fail: 0, totalMs: 0, maxMs: 0, lastMs: 0, lastUsedAt: 0 };
  if (sample.ok) {
    stat.ok += 1;
    stat.totalMs += sample.latencyMs;
  } else {
    stat.fail += 1;
    stat.lastError = sample.error?.slice(0, 200);
  }
  stat.maxMs = Math.max(stat.maxMs, sample.latencyMs);
  stat.lastMs = sample.latencyMs;
  stat.lastUsedAt = now;
  upstreams.set(key, stat);
}

export function resetMetrics(): void {
  for (const key of Object.keys(outcomes) as QueryOutcome[]) outcomes[key] = 0;
  servfail = 0;
  minutes = [];
  freshLatencies.length = 0;
  top.clear();
  recent.length = 0;
  upstreams.clear();
  strategies.clear();
}

function currentMinute(now: number): MinuteBucket {
  const t = Math.floor(now / MINUTE_MS) * MINUTE_MS;
  const last = minutes[minutes.length - 1];
  if (last && last.t === t) return last;
  // A clock jump backwards must not rewrite recorded history; the stray bucket is dropped.
  if (last && last.t > t) return { t, queries: 0, hits: 0, misses: 0, errors: 0 };
  const bucket: MinuteBucket = { t, queries: 0, hits: 0, misses: 0, errors: 0 };
  minutes.push(bucket);
  if (minutes.length > MINUTE_BUCKETS) minutes = minutes.slice(-MINUTE_BUCKETS);
  return bucket;
}

function percentile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.floor(q * (sorted.length - 1))]!;
}

export interface StatsSnapshot {
  startedAt: string;
  uptimeSec: number;
  queries: Record<QueryOutcome, number> & { total: number; servfail: number };
  hitRate: number;
  freshLatency: { count: number; avgMs: number; p50Ms: number; p90Ms: number; p99Ms: number; maxMs: number };
  minutes: MinuteBucket[];
  upstreams: { role: UpstreamRole; name: string; ok: number; fail: number; avgMs: number; maxMs: number; lastMs: number; lastError?: string; lastUsedAgoSec: number }[];
  strategies: { name: string; count: number; avgMs: number }[];
  top: { name: string; count: number }[];
  recent: (QuerySample & { t: number })[];
}

export function statsSnapshot(now = Date.now()): StatsSnapshot {
  const total = Object.values(outcomes).reduce((sum, count) => sum + count, 0);
  const servedFromCache = outcomes.hit + outcomes.prefetch + outcomes.stale;
  const waited = servedFromCache + outcomes.miss;
  const sorted = [...freshLatencies].sort((a, b) => a - b);
  const firstMinute = Math.floor(now / MINUTE_MS) * MINUTE_MS - (MINUTE_BUCKETS - 1) * MINUTE_MS;
  const byT = new Map(minutes.map((bucket) => [bucket.t, bucket]));
  const filled: MinuteBucket[] = [];
  for (let t = firstMinute; t <= Math.floor(now / MINUTE_MS) * MINUTE_MS; t += MINUTE_MS) {
    const bucket = byT.get(t);
    filled.push(bucket ?? { t, queries: 0, hits: 0, misses: 0, errors: 0 });
  }
  return {
    startedAt: new Date(startedAt).toISOString(),
    uptimeSec: Math.floor((now - startedAt) / 1000),
    queries: { ...outcomes, total, servfail },
    hitRate: waited > 0 ? servedFromCache / waited : 0,
    freshLatency: {
      count: sorted.length,
      avgMs: sorted.length > 0 ? Math.round(sorted.reduce((sum, ms) => sum + ms, 0) / sorted.length) : 0,
      p50Ms: percentile(sorted, 0.5),
      p90Ms: percentile(sorted, 0.9),
      p99Ms: percentile(sorted, 0.99),
      maxMs: sorted.length > 0 ? sorted[sorted.length - 1]! : 0,
    },
    minutes: filled,
    upstreams: [...upstreams.entries()].map(([key, stat]) => ({
      role: key.slice(0, key.indexOf(":")) as UpstreamRole,
      name: key.slice(key.indexOf(":") + 1),
      ok: stat.ok,
      fail: stat.fail,
      avgMs: stat.ok > 0 ? Math.round(stat.totalMs / stat.ok) : 0,
      maxMs: stat.maxMs,
      lastMs: stat.lastMs,
      ...(stat.lastError !== undefined ? { lastError: stat.lastError } : {}),
      lastUsedAgoSec: Math.max(0, Math.round((now - stat.lastUsedAt) / 1000)),
    })).sort((a, b) => b.ok + b.fail - (a.ok + a.fail)),
    strategies: [...strategies.entries()].map(([name, stat]) => ({ name, count: stat.count, avgMs: Math.round(stat.totalMs / stat.count) }))
      .sort((a, b) => b.count - a.count),
    top: [...top.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, TOP_REPORTED),
    recent: recent.slice(-RECENT_MAX).reverse(),
  };
}
