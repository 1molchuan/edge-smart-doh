import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCidrList } from "../src/cidr";
import { rotateAddressRecords } from "../src/cache";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { SvcParamKey, describeHttpsParams } from "../src/dns/https-rr";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { handleRequest } from "../src/index";
import { clearLearnedPool, clearMetaEch, learnedPoolStatus, metaEchOverride, preferredPool, setLearnedPool } from "../src/preferred";
import { rewriteCloudflareAddresses, validatedEchConfig } from "../src/rewrite";
import { config } from "./helpers";

class MemoryCache {
  private readonly values = new Map<string, Response>();
  async match(request: RequestInfo | URL): Promise<Response | undefined> {
    const key = request instanceof Request ? request.url : String(request);
    return this.values.get(key)?.clone();
  }
  async put(request: RequestInfo | URL, response: Response): Promise<void> {
    const key = request instanceof Request ? request.url : String(request);
    this.values.set(key, response.clone());
  }
}

function dnsAnswer(name: string, type: number, addresses: string[]): Response {
  const packet: DnsPacket = {
    header: { id: 0x4543, flags: 0x8180, qdcount: 1, ancount: addresses.length, nscount: 0, arcount: 0 },
    questions: [{ name, type, class: 1 }],
    answers: addresses.map((address) => ({ name, type, class: 1, ttl: 60, rdata: type === DnsType.A ? { kind: "a", address } : { kind: "aaaa", address } })),
    authorities: [], additionals: [],
  };
  return new Response(Uint8Array.from(encodeDnsPacket(packet)).buffer, { headers: { "Content-Type": "application/dns-message" } });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  clearLearnedPool();
  clearMetaEch();
});

describe("preferred pool", () => {
  it("merges several source domains into one deduplicated pool", async () => {
    const answers: Record<string, string[]> = { "pool-a.example": ["1.1.1.1", "2.2.2.2"], "pool-b.example": ["3.3.3.3", "1.1.1.1"] };
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name, type } = query.questions[0]!;
      return dnsAnswer(name, type, type === DnsType.A ? answers[name] ?? [] : []);
    }));
    const cache = new MemoryCache() as unknown as Cache;
    const pool = await preferredPool({}, ["pool-a.example", "pool-b.example"], true, config(), cache);
    expect([...pool.ipv4].sort()).toEqual(["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
  });

  it("rotates A answers on every serve while keeping other records in place", () => {
    const packet: DnsPacket = {
      header: { id: 1, flags: 0x8180, qdcount: 1, ancount: 4, nscount: 0, arcount: 0 },
      questions: [{ name: "www.example", type: DnsType.A, class: 1 }],
      answers: [
        { name: "www.example", type: DnsType.CNAME, class: 1, ttl: 60, rdata: { kind: "name", name: "cdn.example" } },
        { name: "cdn.example", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "1.1.1.1" } },
        { name: "cdn.example", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "2.2.2.2" } },
        { name: "cdn.example", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "3.3.3.3" } },
      ],
      authorities: [], additionals: [],
    };
    const wire = encodeDnsPacket(packet);
    const firsts = new Set<string>();
    for (let i = 0; i < 3; i += 1) {
      const served = parseDnsPacket(rotateAddressRecords(wire));
      expect(served.answers[0]?.type).toBe(DnsType.CNAME);
      const addresses = served.answers.filter((r) => r.rdata.kind === "a").map((r) => (r.rdata as { address: string }).address);
      expect([...addresses].sort()).toEqual(["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
      firsts.add(addresses[0]!);
    }
    expect(firsts.size).toBe(3);
  });

  it("prefers a learned pool for default requests until it expires, never for explicit ?cf=", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    vi.stubGlobal("fetch", vi.fn(async () => dnsAnswer("cf.example", DnsType.A, ["9.9.9.9"])));
    const cache = new MemoryCache() as unknown as Cache;
    setLearnedPool(["5.5.5.5"], [], 60, "test");
    expect((await preferredPool({}, ["cf.example"], true, config(), cache)).ipv4).toEqual(["5.5.5.5"]);
    expect((await preferredPool({}, ["cf.example"], false, config(), cache)).ipv4).toEqual(["9.9.9.9"]);
    vi.setSystemTime(1_000_000 + 61_000);
    expect((await preferredPool({}, ["cf.example"], true, config(), cache)).ipv4).toEqual(["9.9.9.9"]);
    expect(learnedPoolStatus()).toBeUndefined();
  });

  it("explicit ip4 wins over learned and domain pools", async () => {
    setLearnedPool(["5.5.5.5"], [], 60, "test");
    const pool = await preferredPool({ ipv4: ["7.7.7.7"] }, ["cf.example"], true, config(), new MemoryCache() as unknown as Cache);
    expect(pool.ipv4).toEqual(["7.7.7.7"]);
  });

  it("rejects malformed addresses", () => {
    expect(() => setLearnedPool(["not-an-ip"], [], 60, "test")).toThrow();
  });

  it("serves the hub's nationwide pool between the operator pool and the maintainer probers' pool", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const cache = new MemoryCache() as unknown as Cache;
    const pool = (isp?: string) => preferredPool({}, ["cf.example"], true, config(), cache, undefined, isp);
    setLearnedPool(["5.5.5.5", "5.5.5.6", "5.5.5.7", "5.5.5.8", "5.5.5.9", "5.5.5.10"], ["2001:db8::5"], 3600, "prober");
    setLearnedPool(["6.6.6.1", "6.6.6.2", "6.6.6.3", "6.6.6.4", "6.6.6.5", "6.6.6.6"], [], 1800, "cfhub", "isp:national");
    setLearnedPool(["7.7.7.1", "7.7.7.2", "7.7.7.3", "7.7.7.4", "7.7.7.5", "7.7.7.6"], [], 1800, "cfhub", "isp:chinanet");
    // A client with no operator pool gets the hub's nationwide pool, with no cache scope (it is the
    // same for everyone); its missing IPv6 comes from the probers' pool.
    const other = await pool(undefined);
    expect(other.ipv4).toEqual(["6.6.6.1", "6.6.6.2", "6.6.6.3", "6.6.6.4", "6.6.6.5", "6.6.6.6"]);
    expect(other.ipv6).toEqual(["2001:db8::5"]);
    expect(other.scope).toBeUndefined();
    // An operator's own full pool still comes first.
    expect((await pool("isp:chinanet")).ipv4[0]).toBe("7.7.7.1");
    // When the hub's pool lapses, the probers' pool serves again.
    vi.setSystemTime(1_000_000 + 1_801_000);
    expect((await pool(undefined)).ipv4[0]).toBe("5.5.5.5");
  });
});

describe("AAAA drop and HTTPS hint rewrite", () => {
  const ranges = { ipv4: parseCidrList("104.16.0.0/13"), ipv6: parseCidrList("2606:4700::/32") };

  function response(): DnsPacket {
    return {
      header: { id: 1, flags: 0x8180, qdcount: 1, ancount: 3, nscount: 0, arcount: 0 },
      questions: [{ name: "site.example", type: DnsType.HTTPS, class: 1 }],
      answers: [
        { name: "site.example", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "104.16.1.1" } },
        { name: "site.example", type: DnsType.AAAA, class: 1, ttl: 60, rdata: { kind: "aaaa", address: "2606:4700::1" } },
        { name: "site.example", type: DnsType.HTTPS, class: 1, ttl: 60, rdata: { kind: "https", value: { priority: 1, target: "", params: [
          { key: SvcParamKey.ALPN, value: Uint8Array.from([2, 0x68, 0x32]) },
          { key: SvcParamKey.IPV4HINT, value: Uint8Array.from([104, 16, 1, 1]) },
          { key: SvcParamKey.IPV6HINT, value: Uint8Array.from([0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) },
        ] } } },
      ],
      authorities: [], additionals: [],
    };
  }

  it("rewrites ipv4hint/ipv6hint alongside A/AAAA", () => {
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: ["203.0.113.10"], cfPreferredIpv6: ["2001:db8::10"] });
    const out = rewriteCloudflareAddresses(response(), ranges, cfg);
    const https = out.answers.find((record) => record.rdata.kind === "https");
    const params = describeHttpsParams((https!.rdata as { kind: "https"; value: never }).value);
    expect(params.ipv4hint).toEqual(["203.0.113.10"]);
    expect(params.ipv6hint).toEqual(["2001:db8:0:0:0:0:0:10"]);
    expect(params.alpn).toEqual(["h2"]);
  });

  it("drops AAAA answers and ipv6hint when CF_DROP_AAAA is on", () => {
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: ["203.0.113.10"], cfPreferredIpv6: ["2001:db8::10"], cfDropAaaa: true });
    const out = rewriteCloudflareAddresses(response(), ranges, cfg);
    expect(out.answers.some((record) => record.type === DnsType.AAAA)).toBe(false);
    const https = out.answers.find((record) => record.rdata.kind === "https");
    const params = describeHttpsParams((https!.rdata as { kind: "https"; value: never }).value);
    expect(params.ipv6hint).toBeUndefined();
    expect(params.ipv4hint).toEqual(["203.0.113.10"]);
  });

  it("leaves non-Cloudflare hints untouched", () => {
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: ["203.0.113.10"] });
    const packet = response();
    (packet.answers[2]!.rdata as { kind: "https"; value: { params: { key: number; value: Uint8Array }[] } }).value.params[1]!.value = Uint8Array.from([192, 0, 2, 1]);
    (packet.answers[0]!.rdata as { kind: "a"; address: string }).address = "192.0.2.1";
    const out = rewriteCloudflareAddresses(packet, ranges, cfg);
    const https = out.answers.find((record) => record.rdata.kind === "https");
    expect(describeHttpsParams((https!.rdata as { kind: "https"; value: never }).value).ipv4hint).toEqual(["192.0.2.1"]);
  });
});

describe("/admin/preferred", () => {
  const env = { ADMIN_TOKEN: "secret-token" } as unknown as Env;
  const runtime = { clientIp: () => undefined, probe: () => ({}) };
  const ctx = { waitUntil: () => undefined };

  it("is hidden without a configured token and rejects a wrong one", async () => {
    const hidden = await handleRequest(new Request("https://doh.example/admin/preferred"), {} as Env, ctx, runtime);
    expect(hidden.status).toBe(404);
    const wrong = await handleRequest(new Request("https://doh.example/admin/preferred", { headers: { Authorization: "Bearer nope" } }), env, ctx, runtime);
    expect(wrong.status).toBe(401);
  });

  it("accepts a pool and reports it back", async () => {
    const post = await handleRequest(new Request("https://doh.example/admin/preferred", {
      method: "POST",
      headers: { Authorization: "Bearer secret-token", "Content-Type": "application/json" },
      body: JSON.stringify({ ipv4: ["104.18.1.1", "104.18.2.2"], ttl: 120, source: "vitest" }),
    }), env, ctx, runtime);
    expect(post.status).toBe(200);
    const get = await handleRequest(new Request("https://doh.example/admin/preferred", { headers: { Authorization: "Bearer secret-token" } }), env, ctx, runtime);
    const body = await get.json() as { learned: { ipv4: string[]; source: string; active: boolean } };
    expect(body.learned.ipv4).toEqual(["104.18.1.1", "104.18.2.2"]);
    expect(body.learned.source).toBe("vitest");
    expect(body.learned.active).toBe(true);
  });

  it("rejects an invalid address", async () => {
    const post = await handleRequest(new Request("https://doh.example/admin/preferred", {
      method: "POST",
      headers: { Authorization: "Bearer secret-token" },
      body: JSON.stringify({ ipv4: ["999.1.1.1"] }),
    }), env, ctx, runtime);
    expect(post.status).toBe(400);
  });
});

describe("/admin/health (Meta ECH)", () => {
  const env = { ADMIN_TOKEN: "secret-token" } as unknown as Env;
  const runtime = { clientIp: () => undefined, probe: () => ({}) };
  const ctx = { waitUntil: () => undefined };
  const seed = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=";
  // A second, distinct-but-valid ECHConfigList standing in for what Meta's retry_configs would carry.
  const rotated = (() => {
    const bytes = validatedEchConfig(seed)!.slice();
    for (let i = 11; i < 43; i += 1) bytes[i] = bytes[i]! ^ 0xff;
    return Buffer.from(bytes).toString("base64");
  })();
  const post = (body: unknown) => handleRequest(new Request("https://doh.example/admin/health", {
    method: "POST",
    headers: { Authorization: "Bearer secret-token", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }), env, ctx, runtime);

  it("'rotated' installs the recovered key and 'ok' clears it", async () => {
    expect(metaEchOverride()).toBeUndefined();
    const res = await post({ metaEch: "rotated", echConfig: rotated, ttl: 600, source: "vitest", reason: "seed rejected" });
    expect(res.status).toBe(200);
    const override = metaEchOverride();
    expect(override).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(override as Uint8Array).toString("base64")).toBe(rotated);
    const body = await res.json() as { metaEch: { mode: string; bytes: number } };
    expect(body.metaEch.mode).toBe("learned");
    expect(body.metaEch.bytes).toBe(74);
    await post({ metaEch: "ok", source: "vitest" });
    expect(metaEchOverride()).toBeUndefined();
  });

  it("'broken' suspends injection, and the override expires on its own", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    await post({ metaEch: "broken", ttl: 300, source: "vitest", reason: "no retry_configs" });
    expect(metaEchOverride()).toBeNull();
    vi.setSystemTime(1_000_000 + 301_000);
    expect(metaEchOverride()).toBeUndefined();
  });

  it("changes the Meta cache tag only when the effective key changes", async () => {
    const { metaEchCacheTag } = await import("../src/preferred");
    const before = metaEchCacheTag();
    await post({ metaEch: "rotated", echConfig: rotated, ttl: 600, source: "vitest" });
    const during = metaEchCacheTag();
    // 'ok' carrying the same verified key renews it without invalidating cached answers.
    await post({ metaEch: "ok", verified: rotated, source: "vitest" });
    expect(metaEchCacheTag()).toBe(during);
    expect(metaEchOverride()).toBeInstanceOf(Uint8Array);
    // 'ok' without (or with a different) verified key drops back to the seed.
    await post({ metaEch: "ok", source: "vitest" });
    const after = metaEchCacheTag();
    expect(metaEchOverride()).toBeUndefined();
    expect(new Set([before, during, after]).size).toBe(3);
  });

  it("rejects an unknown verdict and a malformed rotated key", async () => {
    expect((await post({ metaEch: "maybe" })).status).toBe(400);
    expect((await post({ metaEch: "rotated", echConfig: "AAAA" })).status).toBe(400);
    expect(metaEchOverride()).toBeUndefined();
  });
});

