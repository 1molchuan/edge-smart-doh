import { describe, expect, it } from "vitest";
import { recordQuery, recordUpstream, resetMetrics, statsSnapshot } from "../src/metrics";
import { handleRequest } from "../src/index";

const MINUTE = 60_000;

function query(overrides: Partial<Parameters<typeof recordQuery>[0]> = {}) {
  return { name: "example.com", type: "A", outcome: "miss" as const, latencyMs: 10, ...overrides };
}

function request(url: string, token?: string): Promise<Response> {
  return handleRequest(
    new Request(url, token ? { headers: { Authorization: `Bearer ${token}` } } : {}),
    { ADMIN_TOKEN: "s3cret" } as unknown as Env,
    { waitUntil: () => {} },
    { clientIp: () => "127.0.0.1", probe: () => ({}) },
  );
}

describe("metrics", () => {
  it("counts outcomes and derives the cache-hit rate", () => {
    resetMetrics();
    recordQuery(query({ outcome: "hit", latencyMs: 1 }));
    recordQuery(query({ outcome: "prefetch", latencyMs: 1 }));
    recordQuery(query({ outcome: "stale", latencyMs: 1 }));
    recordQuery(query({ outcome: "miss", latencyMs: 40, upstream: "up.example", strategy: "direct" }));
    recordQuery(query({ outcome: "miss", latencyMs: 60, upstream: "up.example", strategy: "direct" }));
    recordQuery(query({ outcome: "blocked" }));
    recordQuery(query({ outcome: "error", servfail: true }));
    const snapshot = statsSnapshot();
    expect(snapshot.queries).toMatchObject({ total: 7, hit: 1, prefetch: 1, stale: 1, miss: 2, blocked: 1, error: 1, servfail: 1 });
    expect(snapshot.hitRate).toBeCloseTo(3 / 5);
  });

  it("attributes fresh resolutions to upstreams and strategies", () => {
    resetMetrics();
    recordUpstream({ label: "dns.alidns.com", role: "cn", latencyMs: 12, ok: true });
    recordUpstream({ label: "dns.alidns.com", role: "cn", latencyMs: 28, ok: true });
    recordUpstream({ label: "dns.alidns.com", role: "cn", latencyMs: 1000, ok: false, error: "upstream timeout" });
    recordUpstream({ label: "dns.google", role: "ecs", latencyMs: 200, ok: true });
    recordUpstream({ label: "dns.google", role: "default", latencyMs: 210, ok: true });
    const snapshot = statsSnapshot();
    const alidns = snapshot.upstreams.find((upstream) => upstream.role === "cn" && upstream.name === "dns.alidns.com");
    expect(alidns).toMatchObject({ ok: 2, fail: 1, avgMs: 20, maxMs: 1000, lastError: "upstream timeout" });
    // The same host under another role is a separate line: the paths are configured separately.
    expect(snapshot.upstreams.filter((upstream) => upstream.name === "dns.google")).toHaveLength(2);
    recordQuery(query({ strategy: "github-pool", latencyMs: 30 }));
    recordQuery(query({ strategy: "github-pool", latencyMs: 50 }));
    const github = statsSnapshot().strategies.find((strategy) => strategy.name === "github-pool");
    expect(github).toEqual({ name: "github-pool", count: 2, avgMs: 40 });
  });

  it("rolls fresh resolutions up into path categories (relay/ech/pool/cn/direct)", () => {
    resetMetrics();
    recordQuery(query({ latencyMs: 30, strategy: "direct", path: "direct" }));
    recordQuery(query({ latencyMs: 36, strategy: "direct", path: "direct" }));
    recordQuery(query({ latencyMs: 10, strategy: "native-ech", path: "ech" }));
    recordQuery(query({ latencyMs: 12, strategy: "relay", path: "relay" }));
    recordQuery(query({ latencyMs: 5, strategy: "direct", path: "cn" }));
    recordQuery(query({ outcome: "hit", latencyMs: 1 })); // cache hits carry no routing decision
    const paths = Object.fromEntries(statsSnapshot().paths.map((entry) => [entry.path, entry]));
    expect(paths.direct).toEqual({ path: "direct", count: 2, avgMs: 33 });
    expect(paths.ech).toEqual({ path: "ech", count: 1, avgMs: 10 });
    expect(paths.relay).toEqual({ path: "relay", count: 1, avgMs: 12 });
    expect(paths.cn).toEqual({ path: "cn", count: 1, avgMs: 5 });
    expect(paths.pool).toEqual({ path: "pool", count: 0, avgMs: 0 });
  });

  it("keeps fresh-resolution latency percentiles", () => {
    resetMetrics();
    for (let index = 1; index <= 100; index += 1) recordQuery(query({ latencyMs: index }));
    const snapshot = statsSnapshot();
    expect(snapshot.freshLatency.count).toBe(100);
    expect(snapshot.freshLatency.p50Ms).toBe(50);
    expect(snapshot.freshLatency.p99Ms).toBe(99);
    expect(snapshot.freshLatency.maxMs).toBe(100);
  });

  it("keeps the recent list newest-first and bounded", () => {
    resetMetrics();
    for (let index = 0; index < 150; index += 1) recordQuery(query({ name: `n${index}.example` }));
    const recent = statsSnapshot().recent;
    expect(recent).toHaveLength(100);
    expect(recent[0]!.name).toBe("n149.example");
    expect(recent[99]!.name).toBe("n50.example");
  });

  it("tracks top names without growing with traffic", () => {
    resetMetrics();
    for (let index = 0; index < 1200; index += 1) recordQuery(query({ name: `n${index}.example` }));
    recordQuery(query({ name: "n0.example" }));
    const snapshot = statsSnapshot();
    expect(snapshot.top[0]).toEqual({ name: "n0.example", count: 2 });
    expect(snapshot.top).toHaveLength(20);
  });

  it("fills silent minutes with zero buckets and rolls old ones off", () => {
    resetMetrics();
    const aligned = Math.ceil(1_700_000_012_345 / MINUTE) * MINUTE;
    recordQuery(query({ outcome: "hit" }), aligned);
    recordQuery(query({ outcome: "hit" }), aligned);
    recordQuery(query({ outcome: "miss" }), aligned + 3 * MINUTE);
    const minutes = statsSnapshot(aligned + 5 * MINUTE).minutes;
    expect(minutes).toHaveLength(120);
    expect(minutes.at(-1)).toMatchObject({ queries: 0 });
    expect(minutes.at(-3)).toMatchObject({ queries: 1, misses: 1 });
    expect(minutes.at(-6)).toMatchObject({ queries: 2, hits: 2 });
    expect(minutes.filter((bucket) => bucket.queries > 0)).toHaveLength(2);
  });
});

describe("GET /admin/stats", () => {
  it("requires the admin token and reports metrics with the pool state", async () => {
    resetMetrics();
    recordQuery(query({ outcome: "hit", latencyMs: 1 }));
    expect((await request("https://doh.example/admin/stats")).status).toBe(401);
    const ok = await request("https://doh.example/admin/stats", "s3cret");
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { ok: boolean; queries: { total: number }; pools: Record<string, unknown>; freshLatency: Record<string, unknown> };
    expect(body.ok).toBe(true);
    expect(body.queries.total).toBe(1);
    expect(body.pools).toHaveProperty("github");
    expect(body.freshLatency).toHaveProperty("p50Ms");
  });

  it("answers 404 when no admin token is configured", async () => {
    const response = await handleRequest(
      new Request("https://doh.example/admin/stats"),
      {} as unknown as Env,
      { waitUntil: () => {} },
      { clientIp: () => "127.0.0.1", probe: () => ({}) },
    );
    expect(response.status).toBe(404);
  });
});
