import { afterEach, describe, expect, it, vi } from "vitest";
import { normalizedCacheIdentity, readCache, writeCache } from "../src/cache";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { handleRequest } from "../src/index";
import { makePlan, sortStrategies } from "../src/plan";
import { withoutDnssecClaims } from "../src/render";
import type { RequestOptions } from "../src/request-options";
import type { RuleSet } from "../src/rules";
import { PUBLIC_STRATEGIES } from "../src/strategies";
import { config } from "./helpers";

class MemoryCache {
  private readonly values = new Map<string, Response>();
  async match(request: RequestInfo | URL) { return this.values.get(String(request instanceof Request ? request.url : request))?.clone(); }
  async put(request: RequestInfo | URL, response: Response) { this.values.set(String(request instanceof Request ? request.url : request), response.clone()); }
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const ENV = { UPSTREAMS: "https://up.example/dns-query", ECS_DOMAINS: ".cn" } as unknown as Env;

function queryWire(name: string, extra: Partial<DnsPacket> = {}): Uint8Array {
  return encodeDnsPacket({
    header: { id: 7, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
    questions: [{ name, type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [], ...extra,
  });
}

async function ask(wire: Uint8Array, clientIp?: string): Promise<Uint8Array> {
  const res = await handleRequest(new Request("https://doh.example/dns-query", {
    method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(wire).buffer,
  }), ENV, { waitUntil: () => undefined }, { clientIp: () => clientIp, probe: () => ({}) });
  expect(res.status).toBe(200);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * An upstream answering every A query with 192.0.2.1 (TTL 300), recording the ECS it was sent and,
 * like a real resolver, echoing that ECS back with a scope of /20.
 */
function stubUpstream(seen: { ecs?: boolean; subnet?: string }[] = []) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
    const opt = query.additionals.find((record) => record.rdata.kind === "opt");
    const ecs = opt?.rdata.kind === "opt" ? opt.rdata.options.find((option) => option.code === 8) : undefined;
    seen.push({ ecs: ecs !== undefined, ...(ecs ? { subnet: `${Array.from(ecs.data.subarray(4)).join(".")}/${ecs.data[2]}` } : {}) });
    const echoed = ecs ? Uint8Array.from(ecs.data) : undefined;
    if (echoed) echoed[3] = 20;
    const packet = encodeDnsPacket({
      header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 1, nscount: 0, arcount: 0 },
      questions: query.questions,
      answers: [{ name: query.questions[0]!.name, type: DnsType.A, class: 1, ttl: 300, rdata: { kind: "a", address: "192.0.2.1" } }],
      authorities: [],
      additionals: opt ? [{ name: "", type: DnsType.OPT, class: 1232, ttl: 0, rdata: { kind: "opt", options: echoed ? [{ code: 8, data: echoed }] : [] } }] : [],
    });
    return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  const cache = new MemoryCache();
  vi.stubGlobal("caches", { open: async () => cache });
  return fetchMock;
}

const opt = (options: { code: number; data: Uint8Array }[] = [], ttl = 0) => ({
  additionals: [{ name: "", type: DnsType.OPT, class: 1232, ttl, rdata: { kind: "opt" as const, options } }],
});
const optOf = (packet: Uint8Array) => parseDnsPacket(packet).additionals.find((record) => record.type === DnsType.OPT);
const optionCodes = (packet: Uint8Array) => {
  const record = optOf(packet);
  return record?.rdata.kind === "opt" ? record.rdata.options.map((option) => option.code) : undefined;
};
const PADDING = { code: 12, data: new Uint8Array(20) };
const ecsIn = (packet: Uint8Array) => {
  const record = optOf(packet);
  const option = record?.rdata.kind === "opt" ? record.rdata.options.find((item) => item.code === 8) : undefined;
  return option ? `${option.data[1] === 2 ? "v6 " : ""}${Array.from(option.data.subarray(4)).join(".")}/${option.data[2]} scope /${option.data[3]}` : undefined;
};
const withEcs = (subnet: number[], prefix: number, family = 1) => opt([{ code: 8, data: Uint8Array.from([0, family, prefix, 0, ...subnet]) }]);

describe("protocol compliance", () => {
  it("answers BADVERS to an EDNS version above 0 without asking upstream", async () => {
    const fetchMock = stubUpstream();
    const opt = { name: "", type: DnsType.OPT, class: 1232, ttl: 1 << 16, rdata: { kind: "opt" as const, options: [] } };
    const reply = parseDnsPacket(await ask(queryWire("example.org", { additionals: [opt] })));
    const replyOpt = reply.additionals.find((record) => record.type === DnsType.OPT)!;
    expect(reply.header.flags & 0x0f).toBe(0);
    expect(replyOpt.ttl >>> 24).toBe(1); // extended rcode 16 = BADVERS
    expect((replyOpt.ttl >>> 16) & 0xff).toBe(0); // version 0
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("spells the question as the client did, even from a cache filled by another spelling", async () => {
    stubUpstream();
    await ask(queryWire("mixed.example.org"));
    const reply = await ask(queryWire("MiXeD.ExAmPlE.oRg"));
    expect(parseDnsPacket(reply).questions[0]!.name).toBe("MiXeD.ExAmPlE.oRg");
    expect(parseDnsPacket(reply).answers[0]!.rdata).toEqual({ kind: "a", address: "192.0.2.1" });
  });

  it("adds no ECS when the client opted out with a source prefix of 0", async () => {
    const seen: { ecs?: boolean }[] = [];
    stubUpstream(seen);
    await ask(queryWire("a.example.cn"), "58.247.1.1");
    const optOut = { name: "", type: DnsType.OPT, class: 1232, ttl: 0, rdata: { kind: "opt" as const, options: [{ code: 8, data: Uint8Array.from([0, 1, 0, 0]) }] } };
    await ask(queryWire("b.example.cn", { additionals: [optOut] }), "58.247.1.1");
    expect(seen.map((item) => item.ecs)).toEqual([true, false]);
  });

  it("does not show the server's own subnet to a client that sent none (RFC 7871 §7.2.2)", async () => {
    const seen: { ecs?: boolean; subnet?: string }[] = [];
    stubUpstream(seen);
    const plainOpt = { additionals: [{ name: "", type: DnsType.OPT, class: 1232, ttl: 0, rdata: { kind: "opt" as const, options: [] } }] };
    const withOpt = await ask(queryWire("c.example.cn", plainOpt), "58.247.1.1");
    expect(seen[0]).toEqual({ ecs: true, subnet: "58.247.1/24" });
    expect(ecsIn(withOpt)).toBeUndefined();
    expect(parseDnsPacket(withOpt).additionals.some((record) => record.type === DnsType.OPT)).toBe(true);
    // No OPT in the query: none in the answer either, though one carried the subnet upstream.
    const noOpt = await ask(queryWire("d.example.cn"), "58.247.1.1");
    expect(parseDnsPacket(noOpt).additionals.some((record) => record.type === DnsType.OPT)).toBe(false);
  });

  it("uses a client's own ECS (cut to /24) and echoes it back with upstream's scope", async () => {
    const seen: { ecs?: boolean; subnet?: string }[] = [];
    stubUpstream(seen);
    const reply = await ask(queryWire("e.example.cn", withEcs([8, 8, 8, 8], 32)), "58.247.1.1");
    expect(seen[0]).toEqual({ ecs: true, subnet: "8.8.8/24" });
    expect(ecsIn(reply)).toBe("8.8.8.8/32 scope /20");
    // A name that does not get ECS still echoes the client's option, with scope 0.
    const foreign = await ask(queryWire("www.example.org", withEcs([8, 8, 8], 24)), "58.247.1.1");
    expect(seen[1]).toEqual({ ecs: false });
    expect(ecsIn(foreign)).toBe("8.8.8/24 scope /0");
  });

  it("echoes a client's IPv6 ECS from the parsed fields", async () => {
    const seen: { ecs?: boolean; subnet?: string }[] = [];
    stubUpstream(seen);
    const reply = await ask(queryWire("f.example.cn", withEcs([0x24, 0x08, 0x80, 0x00], 32, 2)), "58.247.1.1");
    expect(seen[0]).toEqual({ ecs: true, subnet: "36.8.128.0/32" }); // 2408:8000::/32, under the /56 cut
    expect(ecsIn(reply)).toBe("v6 36.8.128.0/32 scope /20");
  });
});

// The cache is shared by every client of a name, so the OPT record of whichever query filled it must
// not reach the next client: each answer gets one made for its own query.
describe("EDNS does not depend on which query filled the cache", () => {
  it("OPT first, then none: the second answer has no OPT (RFC 6891 §7)", async () => {
    const fetchMock = stubUpstream();
    expect(optOf(await ask(queryWire("a.example.org", opt())))).toBeDefined();
    expect(optOf(await ask(queryWire("a.example.org")))).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("none first, then OPT or ECS: the second answer has OPT, and the client's ECS echoed (§6.1.1)", async () => {
    const fetchMock = stubUpstream();
    expect(optOf(await ask(queryWire("b.example.org")))).toBeUndefined();
    expect(optOf(await ask(queryWire("b.example.org", opt())))).toBeDefined();
    expect(ecsIn(await ask(queryWire("b.example.org", withEcs([8, 8, 8], 24))))).toBe("8.8.8/24 scope /0");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("a padded query gets a padded answer, a plain one never does (RFC 8467)", async () => {
    stubUpstream();
    const plain = await ask(queryWire("c.example.org"));
    const padded = await ask(queryWire("c.example.org", opt([PADDING])));
    expect(padded.length % 468).toBe(0);
    expect(optionCodes(padded)).toEqual([12]);
    const unpadded = await ask(queryWire("c.example.org", opt()));
    expect(optionCodes(unpadded)).toEqual([]);
    expect(await ask(queryWire("c.example.org"))).toHaveLength(plain.length);
    // Padded first: the cache does not keep the padding for the next client.
    await ask(queryWire("d.example.org", opt([PADDING])));
    expect(optOf(await ask(queryWire("d.example.org")))).toBeUndefined();
    expect(optionCodes(await ask(queryWire("d.example.org", opt())))).toEqual([]);
  });

  it("the OPT carries the query's DO bit", async () => {
    stubUpstream();
    expect(optOf(await ask(queryWire("e.example.org", opt([], 0x8000))))!.ttl & 0x8000).toBe(0x8000);
    expect(optOf(await ask(queryWire("e.example.org", opt())))!.ttl & 0x8000).toBe(0);
  });

  it("error answers carry OPT too when the query did", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    vi.stubGlobal("caches", { open: async () => new MemoryCache() });
    const reply = await ask(queryWire("f.example.org", opt()));
    expect(parseDnsPacket(reply).header.flags & 0x0f).toBe(2);
    expect(optOf(reply)).toBeDefined();
  });
});

describe("a query with more than one OPT record", () => {
  it("is answered FORMERR without asking upstream (RFC 6891 §6.1.1)", async () => {
    const fetchMock = stubUpstream();
    const two = { additionals: [...opt().additionals, ...opt([], 1 << 16).additionals] };
    const reply = await ask(queryWire("h.example.org", two));
    expect(parseDnsPacket(reply).header.flags & 0x0f).toBe(1);
    expect(parseDnsPacket(reply).additionals.filter((record) => record.type === DnsType.OPT)).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("a malformed client ECS option", () => {
  it.each([
    ["an IPv4 source prefix of 33", [0, 1, 33, 0, 8, 8, 8, 8, 0]],
    ["more address bytes than the prefix covers", [0, 1, 24, 0, 8, 8, 8, 8]],
    ["an unknown family", [0, 3, 24, 0, 8, 8, 8]],
    ["bits set past the prefix", [0, 1, 20, 0, 8, 8, 8]],
    ["a non-zero scope in the query", [0, 1, 24, 24, 8, 8, 8]],
    ["a truncated option", [0, 1]],
  ])("is answered FORMERR without asking upstream: %s", async (_label, data) => {
    const fetchMock = stubUpstream();
    const reply = await ask(queryWire("g.example.cn", opt([{ code: 8, data: Uint8Array.from(data) }])), "58.247.1.1");
    expect(parseDnsPacket(reply).header.flags & 0x0f).toBe(1);
    expect(optionCodes(reply)).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("cache TTLs", () => {
  it("count down while an answer sits in the cache", async () => {
    const cache = new MemoryCache() as unknown as Cache;
    const query = parseDnsPacket(queryWire("ttl.example.org"));
    const identity = normalizedCacheIdentity(query, "none");
    const answer = encodeDnsPacket({
      header: { id: 7, flags: 0x8180, qdcount: 1, ancount: 2, nscount: 0, arcount: 0 },
      questions: query.questions,
      answers: [
        { name: "ttl.example.org", type: DnsType.CNAME, class: 1, ttl: 600, rdata: { kind: "name", name: "edge.example.net" } },
        { name: "edge.example.net", type: DnsType.A, class: 1, ttl: 120, rdata: { kind: "a", address: "192.0.2.9" } },
      ],
      authorities: [], additionals: [],
    });
    const start = 1_800_000_000_000;
    vi.spyOn(Date, "now").mockReturnValue(start);
    await writeCache(cache, identity, answer, config());
    vi.spyOn(Date, "now").mockReturnValue(start + 45_000);
    const hit = await readCache(cache, identity, config());
    expect(parseDnsPacket(hit!.packet).answers.map((record) => record.ttl)).toEqual([555, 75]);
  });
});

describe("DNSSEC claims", () => {
  it("are dropped from a changed answer: no RRSIG, no AD", () => {
    const signed: DnsPacket = {
      header: { id: 1, flags: 0x81a0, qdcount: 1, ancount: 2, nscount: 0, arcount: 0 },
      questions: [{ name: "example.org", type: DnsType.A, class: 1 }],
      answers: [
        { name: "example.org", type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a", address: "104.16.1.1" } },
        { name: "example.org", type: 46, class: 1, ttl: 60, rdata: { kind: "raw", data: Uint8Array.from([0, 1]) } },
      ],
      authorities: [], additionals: [],
    };
    const out = withoutDnssecClaims(signed);
    expect(out.header.flags & 0x0020).toBe(0);
    expect(out.answers.map((record) => record.type)).toEqual([DnsType.A]);
    const unsigned = { ...signed, header: { ...signed.header, flags: 0x8180 }, answers: signed.answers.slice(0, 1) };
    expect(withoutDnssecClaims(unsigned)).toBe(unsigned);
  });
});

describe("Cloudflare's own services", () => {
  it("are answered untouched: tunnels and WARP do not work on preferred IPs", async () => {
    const plan = async (name: string) => (await makePlan(sortStrategies(PUBLIC_STRATEGIES), {
      config: config({ cfRewriteEnabled: true, cfPreferredIpv4: ["162.159.1.1"] }),
      options: {} as RequestOptions,
      query: parseDnsPacket(queryWire(name)),
      rules: {} as RuleSet,
      cache: new MemoryCache() as unknown as Cache,
    })).plan;
    for (const name of ["region1.v2.argotunnel.com", "argotunnel.com", "engage.cloudflareclient.com"]) {
      const result = await plan(name);
      expect(result.strategy).toBe("untouched");
      expect(result.passthrough).toBeDefined();
    }
    vi.stubGlobal("fetch", vi.fn(async () => new Response("104.16.0.0/13\n")));
    expect((await plan("www.example.org")).passthrough).toBeUndefined();
  });
});
