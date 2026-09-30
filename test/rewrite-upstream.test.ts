import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCidrList } from "../src/cidr";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { rotateAddressRecords } from "../src/cache";
import { injectEchBytes, rewriteCloudflareAddresses, validatedEchConfig } from "../src/rewrite";
import { queryUpstreams } from "../src/upstream";
import { config } from "./helpers";

function response(address = "104.16.1.1"): DnsPacket {
  return {
    header: { id: 1, flags: 0x8180, qdcount: 1, ancount: 1, nscount: 0, arcount: 0 },
    questions: [{ name: "example.com", type: DnsType.A, class: 1 }],
    answers: [{ name: "example.com", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address } }],
    authorities: [], additionals: [],
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("Cloudflare address rewrite", () => {
  it("rewrites a Cloudflare CIDR hit and leaves a non-hit alone", () => {
    const ranges = { ipv4: parseCidrList("104.16.0.0/13"), ipv6: parseCidrList("2606:4700::/32") };
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: ["203.0.113.10"] });
    expect(rewriteCloudflareAddresses(response(), ranges, cfg).answers[0]?.rdata).toEqual({ kind: "a", address: "203.0.113.10" });
    expect(rewriteCloudflareAddresses(response("192.0.2.1"), ranges, cfg).answers[0]?.rdata).toEqual({ kind: "a", address: "192.0.2.1" });
  });

  it("does not repeat a pool address when upstream returns more records than the pool holds", () => {
    const ranges = { ipv4: parseCidrList("104.16.0.0/13"), ipv6: parseCidrList("2606:4700::/32") };
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: ["203.0.113.10", "203.0.113.11"] });
    const three: DnsPacket = { ...response(), answers: ["104.16.1.1", "104.16.1.2", "104.16.1.3"].map((address) => response(address).answers[0]!) };
    const out = rewriteCloudflareAddresses(three, ranges, cfg).answers.map((record) => (record.rdata as { address: string }).address);
    expect(out).toEqual(["203.0.113.10", "203.0.113.11"]);
  });

  it("serves the whole pool for a name with fewer upstream records, and rotation spreads clients over it", () => {
    const ranges = { ipv4: parseCidrList("104.16.0.0/13"), ipv6: parseCidrList("2606:4700::/32") };
    const pool = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"];
    const cfg = config({ cfRewriteEnabled: true, cfPreferredIpv4: pool, cfPreferredIpv6: ["2001:db8::1", "2001:db8::2", "2001:db8::3"] });
    const two: DnsPacket = {
      ...response(),
      answers: [
        { name: "example.com", type: DnsType.CNAME, class: 1, ttl: 300, rdata: { kind: "name", name: "example.com.cdn.cloudflare.net" } },
        ...["104.16.1.1", "104.16.1.2"].map((address) => ({ ...response(address).answers[0]!, name: "example.com.cdn.cloudflare.net" })),
        { name: "example.com.cdn.cloudflare.net", type: DnsType.AAAA, class: 1, ttl: 60, rdata: { kind: "aaaa", address: "2606:4700::1" } },
      ],
    };
    const out = rewriteCloudflareAddresses(two, ranges, cfg);
    expect(out.answers[0]?.type).toBe(DnsType.CNAME);
    const of = (type: number, packet: DnsPacket) => packet.answers.filter((r) => r.type === type).map((r) => (r.rdata as { address: string }).address);
    expect(of(DnsType.A, out)).toEqual(pool);
    expect(of(DnsType.AAAA, out)).toEqual(["2001:db8::1", "2001:db8::2", "2001:db8::3"]);
    expect(out.answers.filter((r) => r.type === DnsType.A).every((r) => r.name === "example.com.cdn.cloudflare.net" && r.ttl === 60)).toBe(true);
    // Served answers start at a different pool IP each time, across the whole pool.
    const wire = encodeDnsPacket(out);
    const firsts = new Set<string>();
    for (let i = 0; i < pool.length; i += 1) firsts.add(of(DnsType.A, parseDnsPacket(rotateAddressRecords(wire)))[0]!);
    expect([...firsts].sort()).toEqual(pool);
  });
});

describe("ECH injection", () => {
  it("synthesizes an HTTPS answer when the upstream returned none", () => {
    const encoded = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=";
    const ech = validatedEchConfig(encoded)!;
    const query: DnsPacket = {
      header: { id: 1, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
      questions: [{ name: "www.instagram.com", type: DnsType.HTTPS, class: 1 }],
      answers: [], authorities: [], additionals: [],
    };
    const result = injectEchBytes(query, ech);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0]?.rdata.kind).toBe("https");
  });

  // Chromium tries QUIC first when h3 is advertised; QUIC+ECH fails for X and Meta.
  it("offers only h2 in synthetic records and can pin upstream records to h2", () => {
    const ech = validatedEchConfig("AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=")!;
    const alpnOf = (packet: DnsPacket) => {
      const rdata = packet.answers[0]!.rdata;
      return rdata.kind === "https" ? [...rdata.value.params.find((param) => param.key === 1)!.value] : [];
    };
    const h2 = [2, 0x68, 0x32];
    const empty: DnsPacket = {
      header: { id: 1, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
      questions: [{ name: "abs.twimg.com", type: DnsType.HTTPS, class: 1 }],
      answers: [], authorities: [], additionals: [],
    };
    expect(alpnOf(injectEchBytes(empty, ech))).toEqual(h2);
    const withH3: DnsPacket = {
      ...empty,
      answers: [{ name: "abs.twimg.com", type: DnsType.HTTPS, class: 1, ttl: 300, rdata: { kind: "https", value: { priority: 1, target: "", params: [{ key: 1, value: Uint8Array.from([2, 0x68, 0x33, 2, 0x68, 0x32]) }] } } }],
    };
    expect(alpnOf(injectEchBytes(withH3, ech))).toEqual([2, 0x68, 0x33, 2, 0x68, 0x32]);
    expect(alpnOf(injectEchBytes(withH3, ech, ["h2"]))).toEqual(h2);
  });
});

describe("upstream fallback", () => {
  it("falls back after primary failure", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("bad", { status: 503 }))
      .mockResolvedValueOnce(new Response(Uint8Array.from(encodeDnsPacket(response())).buffer, { headers: { "Content-Type": "application/dns-message" } }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await queryUpstreams(encodeDnsPacket({ ...response(), header: { ...response().header, flags: 0x0100, ancount: 0 }, answers: [] }), config());
    expect(result.upstream).toContain("secondary");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("aborts a timed-out primary and falls back to secondary", async () => {
    const fetchMock = vi.fn()
      .mockImplementationOnce((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }))
      .mockResolvedValueOnce(new Response(Uint8Array.from(encodeDnsPacket(response())).buffer, { headers: { "Content-Type": "application/dns-message" } }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await queryUpstreams(new Uint8Array(12), config({ upstreamTimeoutMs: 10 }));
    expect(result.upstream).toContain("secondary");
  });

  it("throws when every upstream fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("bad", { status: 502 })));
    await expect(queryUpstreams(new Uint8Array(12), config())).rejects.toThrow(/all upstreams failed/i);
  });

  it("uses the ECS upstream list for ECS queries", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(Uint8Array.from(encodeDnsPacket(response())).buffer, { headers: { "Content-Type": "application/dns-message" } })));
    vi.stubGlobal("fetch", fetchMock);
    const cfg = config({ ecsUpstreams: ["https://ecs.example/dns-query"] });
    expect((await queryUpstreams(new Uint8Array(12), cfg, { ecs: true })).upstream).toBe("https://ecs.example/dns-query");
    expect((await queryUpstreams(new Uint8Array(12), cfg)).upstream).toBe("https://primary.example/dns-query");
  });
});

describe("hedged upstream", () => {
  const ok = () => new Response(Uint8Array.from(encodeDnsPacket(response())).buffer, { headers: { "Content-Type": "application/dns-message" } });
  const hang = (_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  });

  it("races the secondary after the hedge delay and aborts the slow primary", async () => {
    const aborted: string[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("primary")) {
        init?.signal?.addEventListener("abort", () => aborted.push(url));
        return hang(input, init);
      }
      return Promise.resolve(ok());
    });
    vi.stubGlobal("fetch", fetchMock);
    const started = Date.now();
    const result = await queryUpstreams(new Uint8Array(12), config({ upstreamHedgeMs: 20, upstreamTimeoutMs: 2000 }));
    expect(result.upstream).toContain("secondary");
    expect(Date.now() - started).toBeLessThan(500);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(aborted).toEqual(["https://primary.example/dns-query"]);
  });

  it("does not hedge when the primary answers before the delay", async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok());
    vi.stubGlobal("fetch", fetchMock);
    await queryUpstreams(new Uint8Array(12), config({ upstreamHedgeMs: 50 }));
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("takes a late primary success if the hedged secondary fails first", async () => {
    let releasePrimary: (() => void) | undefined;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      if (String(input).includes("primary")) return new Promise<Response>((resolve) => { releasePrimary = () => resolve(ok()); });
      return Promise.resolve(new Response("bad", { status: 503 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pending = queryUpstreams(new Uint8Array(12), config({ upstreamHedgeMs: 10, upstreamTimeoutMs: 2000 }));
    await new Promise((resolve) => setTimeout(resolve, 40));
    releasePrimary!();
    expect((await pending).upstream).toContain("primary");
  });
});
