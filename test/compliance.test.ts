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

/** An upstream answering every A query with 192.0.2.1 (TTL 300), recording the ECS it was sent. */
function stubUpstream(seen: { ecs?: boolean }[] = []) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
    const opt = query.additionals.find((record) => record.rdata.kind === "opt");
    seen.push({ ecs: opt?.rdata.kind === "opt" && opt.rdata.options.some((option) => option.code === 8) });
    const packet = encodeDnsPacket({
      header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 1, nscount: 0, arcount: 0 },
      questions: query.questions,
      answers: [{ name: query.questions[0]!.name, type: DnsType.A, class: 1, ttl: 300, rdata: { kind: "a", address: "192.0.2.1" } }],
      authorities: [], additionals: [],
    });
    return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("caches", { open: async () => new MemoryCache() });
  return fetchMock;
}

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
    expect(seen).toEqual([{ ecs: true }, { ecs: false }]);
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
