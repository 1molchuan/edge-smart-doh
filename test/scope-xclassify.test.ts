import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { describeHttpsParams } from "../src/dns/https-rr";
import { chromiumEchVerdict, clearSelfChecks } from "../src/explain";
import { clearH3Verdicts } from "../src/h3";
import { handleRequest } from "../src/index";
import { clearGithubPools, clearLearnedPool, clearSitePools, combineRankings, githubPoolFor, learnedPoolStatus, preferredPool, scopedPoolStatus, setGithubPools, setLearnedPool, sitePoolFor } from "../src/preferred";
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

afterEach(() => {
  vi.unstubAllGlobals();
  clearLearnedPool();
  clearGithubPools();
  clearSelfChecks();
  clearH3Verdicts();
});

describe("Chromium ECH verdict", () => {
  const ech = Uint8Array.from([0, 4, 0xfe, 0x0d, 0, 0]);
  const packet = (records: DnsPacket["answers"]): DnsPacket => ({
    header: { id: 0, flags: 0x8180, qdcount: 1, ancount: records.length, nscount: 0, arcount: 0 },
    questions: [{ name: "abs.twimg.com", type: 1, class: 1 }],
    answers: records, authorities: [], additionals: [],
  });
  const a = (name: string) => ({ name, type: DnsType.A, class: 1, ttl: 60, rdata: { kind: "a" as const, address: "104.16.1.1" } });
  const https = (name: string, params = [{ key: 5, value: ech }]) => ({ name, type: DnsType.HTTPS, class: 1, ttl: 60, rdata: { kind: "https" as const, value: { priority: 1, target: "", params } } });
  const cname = { name: "abs.twimg.com", type: DnsType.CNAME, class: 1, ttl: 60, rdata: { kind: "name" as const, name: "twimg.twitter.map.fastly.net" } };

  it("accepts addresses and ECH at the same name", () => {
    expect(chromiumEchVerdict(packet([a("abs.twimg.com")]), packet([]), packet([https("abs.twimg.com")])).usable).toBe(true);
  });

  it("rejects the CNAME shape that broke x.com styling", () => {
    const verdict = chromiumEchVerdict(packet([cname, a("twimg.twitter.map.fastly.net")]), packet([]), packet([https("abs.twimg.com")]));
    expect(verdict).toEqual({ usable: false, reason: expect.stringContaining("addresses are at twimg.twitter.map.fastly.net") });
  });

  it("rejects A and AAAA at different names, and an HTTPS record without ECH", () => {
    const aaaa = { name: "other.example", type: DnsType.AAAA, class: 1, ttl: 60, rdata: { kind: "aaaa" as const, address: "2606:4700::1" } };
    expect(chromiumEchVerdict(packet([a("abs.twimg.com")]), packet([aaaa]), packet([https("abs.twimg.com")])).usable).toBe(false);
    expect(chromiumEchVerdict(packet([a("abs.twimg.com")]), packet([]), packet([https("abs.twimg.com", [])])).reason).toBe("the HTTPS record carries no ECH config");
  });
});

describe("combining default pools from several probers", () => {
  it("keeps IPs every prober vouches for, ordered by summed rank", () => {
    const aliyun = ["a", "b", "c", "d", "e", "x"];
    const tencent = ["c", "a", "y", "b", "d", "e"];
    // ranks: a 0+1=1, b 1+3=4, c 2+0=2, d 3+4=7, e 4+5=9; x and y are single-prober only.
    expect(combineRankings([aliyun, tencent], 6)).toEqual(["a", "c", "b", "d", "e"]);
  });

  it("serves just the IPs both probers vouch for, even if only two", () => {
    // summed ranks: b 1+0=1, a 0+2=2
    expect(combineRankings([["a", "b", "x"], ["b", "y", "a"]], 6)).toEqual(["b", "a"]);
  });

  it("interleaves the lists when the probers barely agree", () => {
    expect(combineRankings([["a", "b", "c"], ["x", "y", "a"]], 4)).toEqual(["a", "x", "b", "y"]);
  });

  // 2026-09-24: aliyun reported 6 IPs, tencent 15, school 48; all three agreed on 3, two of three on 13.
  it("with three probers, serves IPs two of them vouch for, those all three vouch for first", () => {
    const aliyun = ["1.0.1.1", "1.0.2.1", "1.0.3.1"];
    const tencent = ["1.0.4.1", "1.0.1.1", "1.0.5.1", "1.0.2.1"];
    const school = ["1.0.5.1", "1.0.4.1", "1.0.6.1", "1.0.2.1", "1.0.1.1"];
    // 1.0.1.1 and 1.0.2.1: three votes. 1.0.4.1, 1.0.5.1: two. 1.0.3.1, 1.0.6.1: one, left out.
    expect(combineRankings([aliyun, tencent, school], 6)).toEqual(["1.0.1.1", "1.0.2.1", "1.0.4.1", "1.0.5.1"]);
  });

  it("serves at most two addresses from one /24 or IPv6 /48", () => {
    const one = ["172.64.229.1", "172.64.229.2", "172.64.229.3", "104.16.1.1", "104.16.2.1"];
    expect(combineRankings([one, one], 6)).toEqual(["172.64.229.1", "172.64.229.2", "104.16.1.1", "104.16.2.1"]);
    const v6 = ["2606:4700:57::1", "2606:4700:57::2", "2606:4700:57:1::3", "2a06:98c1:3100::1"];
    expect(combineRankings([v6, v6], 6)).toEqual(["2606:4700:57::1", "2606:4700:57::2", "2a06:98c1:3100::1"]);
  });

  it("a second prober refines the pool instead of overwriting the first", async () => {
    setLearnedPool(["1.0.1.1", "1.0.2.1", "1.0.3.1", "1.0.4.1", "1.0.9.1"], [], 600, "aliyun");
    setLearnedPool(["1.0.4.1", "1.0.3.1", "1.0.2.1", "1.0.1.1", "1.0.8.1"], [], 600, "tencent");
    const status = learnedPoolStatus()!;
    expect(status.sources.map((source) => source.source).sort()).toEqual(["aliyun", "tencent"]);
    expect(new Set(status.ipv4)).toEqual(new Set(["1.0.1.1", "1.0.2.1", "1.0.3.1", "1.0.4.1"]));
    const pool = await preferredPool({}, [], true, config(), new MemoryCache() as unknown as Cache);
    expect(pool.ipv4).toEqual(status.ipv4);
  });

  it("an IPv6-only prober sets the IPv6 pool without touching the IPv4 consensus", async () => {
    setLearnedPool(["1.0.1.1", "1.0.2.1", "1.0.3.1"], [], 600, "aliyun");
    setLearnedPool(["1.0.3.1", "1.0.2.1", "1.0.1.1"], [], 600, "tencent");
    setLearnedPool([], ["2606:4700::1", "2606:4700::2"], 600, "aliyun-v6");
    const pool = await preferredPool({}, [], true, config(), new MemoryCache() as unknown as Cache);
    expect(new Set(pool.ipv4)).toEqual(new Set(["1.0.1.1", "1.0.2.1", "1.0.3.1"]));
    expect(pool.ipv6).toEqual(["2606:4700::1", "2606:4700::2"]);
    expect(learnedPoolStatus()!.sources.find((source) => source.source === "aliyun-v6")?.ipv6).toEqual(["2606:4700::1", "2606:4700::2"]);
    const dropped = await preferredPool({}, [], true, config({ cfDropAaaa: true }), new MemoryCache() as unknown as Cache);
    expect(dropped.ipv6).toEqual([]);
  });

  it("serves at most six addresses even when a prober reports more", async () => {
    setLearnedPool(Array.from({ length: 16 }, (_, index) => `1.0.1.${index + 1}`), [], 600, "aliyun");
    const pool = await preferredPool({}, [], true, config(), new MemoryCache() as unknown as Cache);
    expect(pool.ipv4).toHaveLength(6);
  });

  // Seen 2026-09-24: a third prober with 42 IPs tied within 3ms cut its report at 16, and only one IP
  // was left that all three had reported, although it had measured the others' IPs as perfect too.
  it("keeps long reports so IPs good for all probers are found beyond each one's top 16", async () => {
    const post = (source: string, ipv4: string[]) => handleRequest(new Request("https://doh.example/admin/preferred", {
      method: "POST",
      headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
      body: JSON.stringify({ ipv4, source, ttl: 600 }),
    }), { ADMIN_TOKEN: "t" } as unknown as Env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    const shared = ["1.0.21.1", "1.0.22.1", "1.0.23.1"];
    const own = (prefix: string) => Array.from({ length: 30 }, (_, index) => `${prefix}.${index + 1}`);
    expect((await post("aliyun", [...shared, ...own("1.0.3")])).status).toBe(200);
    expect((await post("school", [...own("1.0.4"), ...shared])).status).toBe(200);
    expect(learnedPoolStatus()!.sources.find((source) => source.source === "school")?.ipv4).toHaveLength(33);
    expect(new Set(learnedPoolStatus()!.ipv4)).toEqual(new Set(shared));
  });
});

describe("client-scoped learned pools", () => {
  const cache = new MemoryCache() as unknown as Cache;

  it("serves a scoped pool only to clients in that prefix", async () => {
    setLearnedPool(["1.1.1.1"], [], 600, "aliyun");
    setLearnedPool(["2.2.2.2"], [], 600, "home", "58.247.22/24");
    const home = await preferredPool({}, [], true, config(), cache, "58.247.22/24");
    expect(home.ipv4).toEqual(["2.2.2.2", "1.1.1.1"]); // topped up from the nationwide pool
    expect(home.scope).toBe("58.247.22/24");
    const other = await preferredPool({}, [], true, config(), cache, "23.94.182/24");
    expect(other.ipv4).toEqual(["1.1.1.1"]);
    expect(other.scope).toBeUndefined();
  });

  it("does not apply scoped pools when the request brings its own ?cf=", async () => {
    setLearnedPool(["2.2.2.2"], [], 600, "home", "58.247.22/24");
    const explicit = await preferredPool({ ipv4: ["9.9.9.9"] }, [], false, config(), cache, "58.247.22/24");
    expect(explicit.ipv4).toEqual(["9.9.9.9"]);
    expect(explicit.scope).toBeUndefined();
  });

  it("POST /admin/preferred with scope=client keys the pool by the caller's /24", async () => {
    const env = { ADMIN_TOKEN: "t" } as unknown as Env;
    const runtime = { clientIp: () => "58.247.22.207", probe: () => ({}) };
    const res = await handleRequest(new Request("https://doh.example/admin/preferred", {
      method: "POST",
      headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
      body: JSON.stringify({ ipv4: ["104.18.1.1", "104.18.2.2", "104.18.3.3"], scope: "client", source: "home" }),
    }), env, { waitUntil: () => undefined }, runtime);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { scope: string }).scope).toBe("58.247.22/24");
    expect(scopedPoolStatus().map((pool) => pool.scope)).toEqual(["58.247.22/24"]);
  });
});

describe("X domains are only rewritten when they are really on Cloudflare", () => {
  function answer(name: string, type: number, addresses: string[], alias?: string): Response {
    const owner = alias ?? name;
    const records: DnsPacket["answers"] = [
      ...(alias ? [{ name, type: DnsType.CNAME, class: 1, ttl: 120, rdata: { kind: "name" as const, name: alias } }] : []),
      ...addresses.map((address) => ({ name: owner, type, class: 1, ttl: 300, rdata: type === DnsType.A ? { kind: "a" as const, address } : { kind: "aaaa" as const, address } })),
    ];
    // Sites that publish their own HTTPS record with address hints, as Cloudflare does.
    const hints = type === DnsType.HTTPS ? upstreamHttpsHints[owner] : undefined;
    if (hints) {
      records.push({ name: owner, type, class: 1, ttl: 300, rdata: { kind: "https", value: { priority: 1, target: "", params: [
        { key: 1, value: Uint8Array.from([2, 104, 50]) },
        { key: 4, value: Uint8Array.from(hints.flatMap((ip) => ip.split(".").map(Number))) },
        { key: 6, value: Uint8Array.from([0x26, 0x06, 0x47, 0, ...new Array<number>(11).fill(0), 5]) },
      ] } } });
    }
    const packet: DnsPacket = {
      header: { id: 0, flags: 0x8180, qdcount: 1, ancount: records.length, nscount: 0, arcount: 0 },
      questions: [{ name, type, class: 1 }],
      answers: records,
      authorities: [], additionals: [],
    };
    return new Response(Uint8Array.from(encodeDnsPacket(packet)).buffer, { headers: { "Content-Type": "application/dns-message" } });
  }

  const upstreamA: Record<string, string[]> = {
    // Multi-CDN: this resolver steers abs.twimg.com to Fastly, but Cloudflare also serves it.
    "abs.twimg.com": ["151.101.76.159"],
    "abs.twimg.com.cdn.cloudflare.net": ["104.16.1.1"],
    // X's own network only; no Cloudflare CNAME target exists.
    "abs-0.twimg.com": ["104.244.43.131"],
    // Real-world shape: pbs.twimg.com is a CNAME into Fastly's map.
    "twimg.twitter.map.fastly.net": ["151.101.76.159"],
    "pbs.twimg.com.cdn.cloudflare.net": ["104.16.2.2"],
    // A non-X site on Cloudflare via CNAME setup.
    "cdn.example.org.cdn.cloudflare.net": ["104.16.3.3"],
    // Site pools: a Cloudflare forum, a second Cloudflare site, and a ?cf= preferred domain.
    "forum.example": ["104.16.5.5"],
    "shop.example": ["104.16.6.6"],
    "cfpick.example": ["104.16.7.7"],
  };
  const upstreamAaaa: Record<string, string[]> = { "cdn.example.org.cdn.cloudflare.net": ["2606:4700::3"], "forum.example": ["2606:4700::5"] };
  const upstreamHttpsHints: Record<string, string[]> = { "forum.example": ["104.16.5.5"] };
  const upstreamCname: Record<string, string> = {
    "pbs.twimg.com": "twimg.twitter.map.fastly.net",
    "cdn.example.org": "cdn.example.org.cdn.cloudflare.net",
  };

  function stubUpstream(cache = new MemoryCache(), upstreamDown = false): Env {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("ips-v4")) return new Response("104.16.0.0/13\n");
      if (url.includes("ips-v6")) return new Response("2606:4700::/32\n");
      if (upstreamDown) return new Promise<Response>(() => undefined);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name: qname, type: qtype } = query.questions[0]!;
      const alias = upstreamCname[qname];
      const target = alias ?? qname;
      const addresses = qtype === DnsType.A ? upstreamA[target] ?? [] : qtype === DnsType.AAAA ? upstreamAaaa[target] ?? [] : [];
      const response = answer(qname, qtype, addresses, alias);
      const bytes = new Uint8Array(await response.arrayBuffer());
      bytes[0] = query.header.id >>> 8;
      bytes[1] = query.header.id & 0xff;
      return new Response(bytes.buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    vi.stubGlobal("caches", { open: async () => cache });
    return {
      UPSTREAMS: "https://up.example/dns-query",
      X_DOMAINS: ".twimg.com",
      CF_PREFERRED_IPV4: "203.0.113.10",
      ECH_ENABLED: "true",
      ECH_CONFIG_BASE64: "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=",
      ADMIN_TOKEN: "t",
    } as unknown as Env;
  }

  async function ask(name: string, type: number, cache = new MemoryCache(), upstreamDown = false, query = ""): Promise<DnsPacket> {
    const env = stubUpstream(cache, upstreamDown);
    const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
    const res = await handleRequest(new Request(`https://doh.example/dns-query${query}`, {
      method: "POST",
      headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
      body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
  }

  interface Explained {
    results: { type: string; servedFrom: string; answer: string[]; steps: string[] }[];
    chromium: { usable: boolean; reason: string } | null;
    selfcheck: { source: string; ok: boolean; problems: string[] }[];
  }
  const runtime = { clientIp: () => "58.247.22.207", probe: () => ({}) };

  async function explain(name: string, extra = ""): Promise<Explained> {
    const env = stubUpstream();
    const res = await handleRequest(new Request(`https://doh.example/explain?name=${name}${extra}`), env, { waitUntil: () => undefined }, runtime);
    expect(res.status).toBe(200);
    return res.json() as Promise<Explained>;
  }

  it("/explain walks every step and confirms Chromium will use ECH", async () => {
    const out = await explain("pbs.twimg.com");
    expect(out.results.map((result) => result.type)).toEqual(["A", "AAAA", "HTTPS"]);
    const a = out.results[0]!;
    expect(a.servedFrom).toBe("upstream");
    expect(a.answer).toEqual(["pbs.twimg.com A 203.0.113.10 ttl=120"]);
    expect(a.steps.some((step) => step.includes("twimg.twitter.map.fastly.net"))).toBe(true);
    expect(a.steps.some((step) => step.startsWith("CNAME chain flattened"))).toBe(true);
    expect(out.results[2]!.answer[0]).toMatch(/^pbs\.twimg\.com HTTPS 1 \. alpn=h2 ech=\d+B/);
    expect(out.chromium).toEqual({ usable: true, reason: expect.stringContaining("agree on pbs.twimg.com") });
  });

  it("/explain says why a host gets no ECH", async () => {
    const out = await explain("abs-0.twimg.com");
    expect(out.chromium).toEqual({ usable: false, reason: "no HTTPS service record" });
    expect(out.results[2]!.steps).toContain("not on Cloudflare: no ECH injected");
  });

  describe("measured HTTP/3", () => {
    const alpnOf = (packet: DnsPacket) => packet.answers.flatMap((record) => (record.rdata.kind === "https" ? [describeHttpsParams(record.rdata.value).alpn?.join(",")] : []));
    async function report(source: string, verdicts: Record<string, boolean>, cache = new MemoryCache()) {
      const res = await handleRequest(new Request("https://doh.example/admin/h3", {
        method: "POST",
        headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
        body: JSON.stringify({ source, verdicts, ttl: 600 }),
      }), stubUpstream(cache), { waitUntil: () => undefined }, runtime);
      expect(res.status).toBe(200);
    }

    it("defaults X hosts to h2 without a measurement", async () => {
      expect(alpnOf(await ask("pbs.twimg.com", DnsType.HTTPS))).toEqual(["h2"]);
    });

    it("advertises h3 once every prober confirms QUIC+ECH, and the flip bypasses the cached answer", async () => {
      const cache = new MemoryCache();
      expect(alpnOf(await ask("pbs.twimg.com", DnsType.HTTPS, cache))).toEqual(["h2"]);
      await report("aliyun", { "twimg.com": true });
      expect(alpnOf(await ask("pbs.twimg.com", DnsType.HTTPS, cache))).toEqual(["h3,h2"]);
      await report("tencent", { "twimg.com": false });
      expect(alpnOf(await ask("pbs.twimg.com", DnsType.HTTPS, cache))).toEqual(["h2"]);
    });

    it("the most specific measured host wins", async () => {
      await report("aliyun", { "twimg.com": true, "pbs.twimg.com": false });
      expect(alpnOf(await ask("pbs.twimg.com", DnsType.HTTPS))).toEqual(["h2"]);
      expect(alpnOf(await ask("abs.twimg.com", DnsType.HTTPS))).toEqual(["h3,h2"]);
    });

    it("rejects malformed verdicts", async () => {
      const res = await handleRequest(new Request("https://doh.example/admin/h3", {
        method: "POST",
        headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
        body: JSON.stringify({ source: "x", verdicts: { "bad host/": true } }),
      }), stubUpstream(), { waitUntil: () => undefined }, runtime);
      expect(res.status).toBe(400);
    });
  });


  // 2026-09-26: linux.do hung through the Singapore colo (origin unreachable from there) while the
  // general pool's handshakes were perfect; a site-check prober reports IPs verified end to end.
  describe("site pools", () => {
    const addresses = (packet: DnsPacket) => packet.answers.flatMap((record) => (record.rdata.kind === "a" || record.rdata.kind === "aaaa" ? [record.rdata.address] : [])).sort();
    // The general-pool rewrite keeps the upstream's record count, so check membership, not the whole pool.
    const general = (packet: DnsPacket) => addresses(packet).length > 0 && addresses(packet).every((ip) => ["104.16.8.8", "104.16.9.8"].includes(ip));
    const hintsOf = (packet: DnsPacket) => {
      const record = packet.answers.find((answer) => answer.rdata.kind === "https");
      return record?.rdata.kind === "https" ? describeHttpsParams(record.rdata.value) : {};
    };
    function siteEnv(cache: MemoryCache): Env {
      setLearnedPool(["104.16.8.8", "104.16.9.8"], ["2606:4700::8"], 600, "aliyun");
      return { ...stubUpstream(cache), CF_PREFERRED_DOMAIN: "pool.example" } as unknown as Env;
    }
    async function askSite(name: string, type: number, cache = new MemoryCache(), query = ""): Promise<DnsPacket> {
      const env = siteEnv(cache);
      const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
      const res = await handleRequest(new Request(`https://doh.example/dns-query${query}`, {
        method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
      return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
    }
    async function reportSites(source: string, hosts: Record<string, string[]>, cache = new MemoryCache()): Promise<Response> {
      return handleRequest(new Request("https://doh.example/admin/site", {
        method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
        body: JSON.stringify({ source, ttl: 600, hosts }),
      }), siteEnv(cache), { waitUntil: () => undefined }, runtime);
    }
    afterEach(() => clearSitePools());

    it("pins a reported site to its pool, drops IPv6 and keeps ECH; other sites keep the general pool", async () => {
      expect((await reportSites("school", { "forum.example": ["162.159.1.1", "162.159.2.2"] })).status).toBe(200);
      expect(addresses(await askSite("forum.example", DnsType.A))).toEqual(["162.159.1.1", "162.159.2.2"]);
      expect(addresses(await askSite("forum.example", DnsType.AAAA))).toEqual([]);
      const https = hintsOf(await askSite("forum.example", DnsType.HTTPS));
      expect(https.ipv4hint).toEqual(["162.159.1.1", "162.159.2.2"]);
      expect(https.ipv6hint).toBeUndefined();
      expect(https.ech?.length).toBeGreaterThan(0);
      expect(general(await askSite("shop.example", DnsType.A))).toBe(true);
    });

    it("a report without the site withdraws the override, and the change bypasses the cached answer", async () => {
      const cache = new MemoryCache();
      expect(general(await askSite("forum.example", DnsType.A, cache))).toBe(true);
      await reportSites("school", { "forum.example": ["162.159.1.1", "162.159.2.2"] });
      expect(addresses(await askSite("forum.example", DnsType.A, cache))).toEqual(["162.159.1.1", "162.159.2.2"]);
      expect((await reportSites("school", {})).status).toBe(200);
      expect(general(await askSite("forum.example", DnsType.A, cache))).toBe(true);
    });

    it("merges several probers by majority and ignores one prober's odd IPs", async () => {
      await reportSites("school", { "forum.example": ["162.159.1.1", "162.159.2.2", "162.159.3.3"] });
      await reportSites("tencent", { "forum.example": ["162.159.2.2", "162.159.1.1", "104.25.4.4"] });
      await reportSites("aliyun", {});
      expect(sitePoolFor("forum.example")).toEqual(["162.159.1.1", "162.159.2.2"]);
    });

    it("leaves a request with its own ?cf= choice alone", async () => {
      await reportSites("school", { "forum.example": ["162.159.1.1", "162.159.2.2"] });
      expect(addresses(await askSite("forum.example", DnsType.A, new MemoryCache(), "?cf=cfpick.example"))).toEqual(["104.16.7.7"]);
    });

    it("/explain says the site is pinned, and the admin state lists it", async () => {
      await reportSites("school", { "forum.example": ["162.159.1.1", "162.159.2.2"] });
      const cache = new MemoryCache();
      const res = await handleRequest(new Request("https://doh.example/explain?name=forum.example&type=A"), siteEnv(cache), { waitUntil: () => undefined }, runtime);
      const out = (await res.json()) as Explained;
      expect(out.results[0]!.steps.some((step) => step.startsWith("site pool (origin unreachable through the general pool): pinned to 162.159.1.1, 162.159.2.2"))).toBe(true);
      const state = await handleRequest(new Request("https://doh.example/admin/site", { headers: { Authorization: "Bearer t" } }), siteEnv(cache), { waitUntil: () => undefined }, runtime);
      expect(((await state.json()) as { sites: { hosts: Record<string, string[]> } }).sites.hosts).toEqual({ "forum.example": ["162.159.1.1", "162.159.2.2"] });
    });

    it("rejects a report with a non-IPv4 address or a bad hostname", async () => {
      expect((await reportSites("school", { "forum.example": ["2606:4700::1"] })).status).toBe(400);
      expect((await reportSites("school", { "bad host/": ["162.159.1.1"] })).status).toBe(400);
    });
  });

  it("/explain rejects anything but a hostname", async () => {
    const res = await handleRequest(new Request("https://doh.example/explain?name=x.com/../a"), stubUpstream(), { waitUntil: () => undefined }, runtime);
    expect(res.status).toBe(400);
  });

  it("a prober's self-check report shows up in /explain", async () => {
    const post = await handleRequest(new Request("https://doh.example/admin/selfcheck", {
      method: "POST",
      headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
      body: JSON.stringify({ source: "aliyun-shanghai", ok: false, problems: ["abs.twimg.com: HTTPS record at wrong name"], hosts: 9 }),
    }), stubUpstream(), { waitUntil: () => undefined }, runtime);
    expect(post.status).toBe(200);
    const out = await explain("pbs.twimg.com");
    expect(out.selfcheck).toEqual([expect.objectContaining({ source: "aliyun-shanghai", ok: false, problems: ["abs.twimg.com: HTTPS record at wrong name"] })]);
  });

  it("pins a multi-CDN X host to the Cloudflare pool even when this resolver answered Fastly", async () => {
    const out = await ask("abs.twimg.com", DnsType.A);
    expect(out.answers.map((record) => (record.rdata as { address: string }).address)).toEqual(["203.0.113.10"]);
  });

  // Chromium only applies an HTTPS record's ECH when the A/AAAA records share its canonical name.
  it("flattens a CNAME'd X host so A and HTTPS (ECH) answers share the query name", async () => {
    const a = await ask("pbs.twimg.com", DnsType.A);
    expect(a.answers.map((record) => [record.name, record.type])).toEqual([["pbs.twimg.com", DnsType.A]]);
    expect((a.answers[0]!.rdata as { address: string }).address).toBe("203.0.113.10");
    expect(a.answers[0]!.ttl).toBeLessThanOrEqual(120);
    const https = await ask("pbs.twimg.com", DnsType.HTTPS);
    expect(https.answers.map((record) => [record.name, record.type])).toEqual([["pbs.twimg.com", DnsType.HTTPS]]);
    const aaaa = await ask("pbs.twimg.com", DnsType.AAAA);
    expect(aaaa.answers).toHaveLength(0);
  });

  describe("with an IPv6 pool", () => {
    async function askWith(name: string, type: number, extra: Record<string, string>, query = ""): Promise<DnsPacket> {
      const env = { ...stubUpstream(), CF_PREFERRED_IPV6: "2606:4700::10,2606:4700::11", ...extra } as unknown as Env;
      const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
      const res = await handleRequest(new Request(`https://doh.example/dns-query${query}`, {
        method: "POST",
        headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
        body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
      return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
    }
    const v6 = (packet: DnsPacket) => packet.answers.flatMap((record) => (record.rdata.kind === "aaaa" ? [record.rdata.address] : [])).sort();

    // X's zone answers every request that reaches Cloudflare over IPv6 with a 4-byte "IPv6" page
    // (/cdn-cgi/trace still says 200, so probers do not notice). Serving the pool's AAAA to X broke
    // x.com for dual-stack browsers on 2026-09-24 and was rolled back.
    it("gives X hosts no AAAA even when an IPv6 pool exists", async () => {
      expect(v6(await askWith("pbs.twimg.com", DnsType.AAAA, {}))).toEqual([]);
      expect(v6(await askWith("abs.twimg.com", DnsType.AAAA, {}))).toEqual([]);
    });


    it("leaves a non-Cloudflare X host's AAAA alone", async () => {
      expect(v6(await askWith("abs-0.twimg.com", DnsType.AAAA, {}))).toEqual([]);
    });
  });

  // Chromium waits ~50ms past the address answers for HTTPS; an upstream round trip would miss that.
  it("answers an expired HTTPS record from cache at once instead of waiting on upstream", async () => {
    vi.useFakeTimers({ now: 1_000_000, toFake: ["Date"] });
    try {
      const cache = new MemoryCache();
      expect((await ask("pbs.twimg.com", DnsType.HTTPS, cache)).answers).toHaveLength(1);
      vi.setSystemTime(1_000_000 + 400_000);
      const stale = await ask("pbs.twimg.com", DnsType.HTTPS, cache, true);
      expect(stale.answers.map((record) => [record.type, record.ttl])).toEqual([[DnsType.HTTPS, 30]]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("flattens a CNAME'd non-X Cloudflare site for A, AAAA and HTTPS alike", async () => {
    for (const type of [DnsType.A, DnsType.AAAA, DnsType.HTTPS]) {
      const out = await ask("cdn.example.org", type);
      expect(out.answers.length).toBeGreaterThan(0);
      expect(out.answers.every((record) => record.name === "cdn.example.org" && record.type === type)).toBe(true);
    }
  });

  it("leaves a non-Cloudflare X host (abs-0.twimg.com) untouched and injects no ECH", async () => {
    const a = await ask("abs-0.twimg.com", DnsType.A);
    expect(a.answers.map((record) => (record.rdata as { address: string }).address)).toEqual(["104.244.43.131"]);
    const https = await ask("abs-0.twimg.com", DnsType.HTTPS);
    expect(https.answers.filter((record) => record.type === DnsType.HTTPS)).toHaveLength(0);
  });
});

describe("GitHub per-host preferred pools", () => {
  it("merges probers by majority per host, best first", () => {
    setGithubPools("aliyun", { "github.com": ["140.82.116.4", "140.82.121.4"], "raw.githubusercontent.com": ["185.199.108.133"] }, 600);
    setGithubPools("tencent", { "github.com": ["140.82.121.4", "140.82.116.4"], "raw.githubusercontent.com": ["185.199.108.133", "185.199.110.133"] }, 600);
    setGithubPools("school", { "github.com": ["140.82.116.4", "140.82.116.5", "140.82.116.6"], "raw.githubusercontent.com": ["185.199.110.133", "185.199.108.133"] }, 600);
    // github.com: .116.4 (3 votes) then .121.4 (2); the extra .116.x are one-vote, excluded.
    expect(githubPoolFor("github.com")).toEqual(["140.82.116.4", "140.82.121.4"]);
    // raw: .108.133 (3 votes) then .110.133 (2); .109.133 never reported here.
    expect(githubPoolFor("raw.githubusercontent.com")).toEqual(["185.199.108.133", "185.199.110.133"]);
  });

  it("forgets a source when it expires and knows nothing about an unreported host", () => {
    vi.useFakeTimers({ now: 1_000_000, toFake: ["Date"] });
    try {
      setGithubPools("aliyun", { "github.com": ["140.82.116.4"] }, 60);
      expect(githubPoolFor("github.com")).toEqual(["140.82.116.4"]);
      expect(githubPoolFor("api.github.com")).toEqual([]);
      vi.setSystemTime(1_000_000 + 61_000);
      expect(githubPoolFor("github.com")).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  function githubEnv(): Env {
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name, type } = query.questions[0]!;
      // Upstream returns polluted/foreign A and a real AAAA, to prove we pin A and drop AAAA.
      const answers: DnsPacket["answers"] = type === DnsType.A
        ? [{ name, type: DnsType.A, class: 1, ttl: 300, rdata: { kind: "a", address: "1.2.3.4" } }]
        : type === DnsType.AAAA
          ? [{ name, type: DnsType.AAAA, class: 1, ttl: 300, rdata: { kind: "aaaa", address: "2606:50c0::1" } }]
          : [];
      const bytes = encodeDnsPacket({ header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: answers.length, nscount: 0, arcount: 0 }, questions: query.questions, answers, authorities: [], additionals: [] });
      return new Response(Uint8Array.from(bytes).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    vi.stubGlobal("caches", { open: async () => new MemoryCache() });
    return {
      UPSTREAMS: "https://up.example/dns-query",
      GITHUB_DOMAINS: "github.com,api.github.com,raw.githubusercontent.com,.githubusercontent.com",
      ADMIN_TOKEN: "t",
    } as unknown as Env;
  }

  async function ghAsk(env: Env, name: string, type: number, query = ""): Promise<DnsPacket> {
    const body = encodeDnsPacket({ header: { id: 0x77, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
    const res = await handleRequest(new Request(`https://doh.example/dns-query${query}`, {
      method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
  }
  const addrs = (packet: DnsPacket) => packet.answers.flatMap((r) => (r.rdata.kind === "a" || r.rdata.kind === "aaaa" ? [r.rdata.address] : []));

  // Answer order rotates at serve time (rotateAddressRecords), so compare as a set.
  const addrSet = (packet: DnsPacket) => new Set(addrs(packet));

  it("pins A to the measured pool, drops AAAA, and leaves an unmeasured host untouched", async () => {
    const env = githubEnv();
    setGithubPools("aliyun", { "github.com": ["140.82.116.4", "140.82.121.4"] }, 600);
    expect(addrSet(await ghAsk(env, "github.com", DnsType.A))).toEqual(new Set(["140.82.116.4", "140.82.121.4"]));
    expect(addrs(await ghAsk(env, "github.com", DnsType.AAAA))).toEqual([]); // AAAA dropped
    // api.github.com has no measured pool: upstream answer is passed through untouched.
    expect(addrs(await ghAsk(env, "api.github.com", DnsType.A))).toEqual(["1.2.3.4"]);
  });

  it("accepts a prober report over POST /admin/github and serves it", async () => {
    const env = githubEnv();
    const post = await handleRequest(new Request("https://doh.example/admin/github", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
      body: JSON.stringify({ source: "aliyun-shanghai", ttl: 600, hosts: { "raw.githubusercontent.com": ["185.199.110.133", "185.199.108.133"] } }),
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(post.status).toBe(200);
    expect(addrSet(await ghAsk(env, "raw.githubusercontent.com", DnsType.A))).toEqual(new Set(["185.199.110.133", "185.199.108.133"]));
  });


  it("GET /admin/github?detail=1 returns every report as posted, so a restart can post them back", async () => {
    const env = githubEnv();
    setGithubPools("aliyun", { "github.com": ["20.27.177.113"] }, 600);
    setGithubPools("tencent", { "github.com": ["20.200.245.247"], "api.github.com": ["20.27.177.116"] }, 600);
    const get = (query: string) => handleRequest(new Request(`https://doh.example/admin/github${query}`, { headers: { Authorization: "Bearer t" } }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect((await (await get("")).json() as { reports?: unknown }).reports).toBeUndefined();
    const detail = await (await get("?detail=1")).json() as { reports: { source: string; hosts: Record<string, string[]> }[] };
    expect(detail.reports.map((r) => [r.source, r.hosts])).toEqual([
      ["aliyun", { "github.com": ["20.27.177.113"] }],
      ["tencent", { "github.com": ["20.200.245.247"], "api.github.com": ["20.27.177.116"] }],
    ]);
  });

  it("rejects a report with a non-IPv4 address", async () => {
    const env = githubEnv();
    const res = await handleRequest(new Request("https://doh.example/admin/github", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
      body: JSON.stringify({ source: "x", hosts: { "github.com": ["2606:50c0::1"] } }),
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(res.status).toBe(400);
  });
});
