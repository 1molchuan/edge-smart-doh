import { afterEach, describe, expect, it, vi } from "vitest";
import { normalizedCacheIdentity, readCache, writeCache } from "../src/cache";
import { addEcs, makeEcsValue } from "../src/dns/ecs";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { config } from "./helpers";

function query(id: number): DnsPacket {
  return {
    header: { id, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
    questions: [{ name: "Example.COM", type: DnsType.A, class: 1 }],
    answers: [], authorities: [], additionals: [],
  };
}

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

describe("normalized cache", () => {
  it("uses one key for different transaction IDs and restores the current ID", async () => {
    const first = normalizedCacheIdentity(query(0x1111), "none");
    const second = normalizedCacheIdentity(query(0x2222), "none");
    expect(first.text).toBe(second.text);
    const response: DnsPacket = {
      ...query(0x1111),
      header: { ...query(0x1111).header, flags: 0x8180, ancount: 1 },
      answers: [{ name: "example.com", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "192.0.2.1" } }],
    };
    const cache = new MemoryCache();
    await writeCache(cache as unknown as Cache, first, encodeDnsPacket(response), config());
    const hit = await readCache(cache as unknown as Cache, second, config());
    expect(hit?.state).toBe("fresh");
    expect(parseDnsPacket(hit!.packet).header.id).toBe(0x2222);
  });
});

describe("prefetch and serve-stale", () => {
  afterEach(() => vi.useRealTimers());

  function answer(ttl: number): Uint8Array {
    return encodeDnsPacket({
      ...query(1),
      header: { ...query(1).header, flags: 0x8180, ancount: 1 },
      answers: [{ name: "example.com", type: DnsType.A, class: 1, ttl, rdata: { kind: "a", address: "192.0.2.1" } }],
    });
  }

  it("flags a hit for background refresh inside the prefetch window", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const cfg = config({ cachePrefetchPercent: 10, cacheStaleTtl: 0 });
    const cache = new MemoryCache() as unknown as Cache;
    const identity = normalizedCacheIdentity(query(1), "none");
    await writeCache(cache, identity, answer(100), cfg);
    vi.setSystemTime(1_000_000 + 50_000);
    expect((await readCache(cache, identity, cfg))?.state).toBe("fresh");
    vi.setSystemTime(1_000_000 + 95_000);
    expect((await readCache(cache, identity, cfg))?.state).toBe("refresh");
  });

  it("serves an expired entry as stale with a 30s TTL, then drops it after the stale window", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const cfg = config({ cacheStaleTtl: 600 });
    const cache = new MemoryCache() as unknown as Cache;
    const identity = normalizedCacheIdentity(query(7), "none");
    await writeCache(cache, identity, answer(100), cfg);
    vi.setSystemTime(1_000_000 + 101_000);
    const stale = await readCache(cache, identity, cfg);
    expect(stale?.state).toBe("stale");
    const parsed = parseDnsPacket(stale!.packet);
    expect(parsed.header.id).toBe(7);
    expect(parsed.answers[0]?.ttl).toBe(30);
    vi.setSystemTime(1_000_000 + 100_000 + 601_000);
    expect(await readCache(cache, identity, cfg)).toBeUndefined();
  });

  it("does not serve stale when disabled", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const cfg = config({ cacheStaleTtl: 0 });
    const cache = new MemoryCache() as unknown as Cache;
    const identity = normalizedCacheIdentity(query(1), "none");
    await writeCache(cache, identity, answer(100), cfg);
    vi.setSystemTime(1_000_000 + 101_000);
    expect(await readCache(cache, identity, cfg)).toBeUndefined();
  });
});

describe("ECS", () => {
  it("truncates IPv4 to /24", () => {
    const ecs = makeEcsValue("198.51.100.34", 24, 48)!;
    expect(ecs.family).toBe(1);
    expect(ecs.address).toEqual(new Uint8Array([198, 51, 100]));
  });

  it("truncates IPv6 to /48 and encodes it into OPT", () => {
    const ecs = makeEcsValue("2001:db8:abcd:1234::1", 24, 48)!;
    expect(ecs.address).toEqual(new Uint8Array([0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd]));
    const packet = addEcs(query(1), ecs);
    const reparsed = parseDnsPacket(encodeDnsPacket(packet));
    const opt = reparsed.additionals[0]?.rdata;
    expect(opt?.kind).toBe("opt");
    if (opt?.kind === "opt") expect(opt.options[0]?.data).toEqual(new Uint8Array([0, 2, 48, 0, 0x20, 1, 0x0d, 0xb8, 0xab, 0xcd]));
  });
});
