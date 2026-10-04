import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType } from "../src/dns/types";
import { readConfig } from "../src/config";
import { chineseSitesSettled, isDomesticSite, resetChineseSites } from "../src/cn-domains";
import { handleRequest } from "../src/index";
import { queryUpstreams } from "../src/upstream";
import { config } from "./helpers";

const CN_UPSTREAM = "https://cn-dns.example/dns-query";
const PROXIED_UPSTREAM = "https://up.example/dns-query";
const LIST_URL = "https://lists.example/direct-list.txt";
const LIST = "# china\nbilivideo.com\n";

afterEach(() => {
  vi.unstubAllGlobals();
  resetChineseSites();
});

describe("isDomesticSite", () => {
  it("counts ECS_DOMAINS, the operator's CN_DOMAINS, and the loaded lists", async () => {
    const fetchMock = vi.fn(async () => new Response(LIST));
    vi.stubGlobal("fetch", fetchMock);
    const cfg = config({ ecsDomainListUrls: [LIST_URL], cnDomains: [".mycompany.example"] });
    expect(isDomesticSite("x.example.cn", cfg)).toBe(true);
    expect(isDomesticSite("intranet.mycompany.example", cfg)).toBe(true);
    expect(isDomesticSite("upos.bilivideo.com", cfg)).toBe(false); // list not loaded yet
    await chineseSitesSettled();
    expect(isDomesticSite("upos.bilivideo.com", cfg)).toBe(true);
    expect(isDomesticSite("www.google.com", cfg)).toBe(false);
  });
});

describe("queryUpstreams CN group", () => {
  const answer = (query: ReturnType<typeof parseDnsPacket>) => encodeDnsPacket({
    header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
    questions: query.questions, answers: [], authorities: [], additionals: [],
  });

  it("routes to CN_UPSTREAMS when asked, falling back to the trust list when none are configured", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(new URL(String(input)).hostname);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      return new Response(Uint8Array.from(answer(query)).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    const wire = encodeDnsPacket({ header: { id: 1, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name: "example.com", type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
    const cfg = config({ cnUpstreams: [CN_UPSTREAM] });
    await queryUpstreams(wire, cfg, { cn: true });
    expect(seen).toEqual(["cn-dns.example"]);
    await queryUpstreams(wire, cfg, { cn: false });
    expect(seen).toEqual(["cn-dns.example", "primary.example"]);
    // No CN upstreams configured: the cn flag degrades to the default list.
    seen.length = 0;
    await queryUpstreams(wire, config(), { cn: true });
    expect(seen).toEqual(["primary.example"]);
  });
});

describe("domain-split resolution", () => {
  it("sends domestic names to the CN upstreams without ECS, everything else to the proxied trust list", async () => {
    const hits: Record<string, { upstream: string; ecs: boolean }> = {};
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === LIST_URL) return new Response(LIST);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const name = query.questions[0]!.name;
      const opt = query.additionals.find((record) => record.rdata.kind === "opt");
      const hasEcs = opt?.rdata.kind === "opt" && opt.rdata.options.some((option) => option.code === 8);
      hits[name] = { upstream: new URL(url).hostname, ecs: hasEcs };
      const packet = encodeDnsPacket({
        header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
        questions: query.questions, answers: [], authorities: [], additionals: [],
      });
      return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    class MemoryCache {
      private readonly values = new Map<string, Response>();
      async match(request: RequestInfo | URL) { return this.values.get(String(request))?.clone(); }
      async put(request: RequestInfo | URL, response: Response) { this.values.set(String(request), response.clone()); }
    }
    vi.stubGlobal("caches", { open: async () => new MemoryCache() });
    const env = {
      UPSTREAMS: PROXIED_UPSTREAM,
      ECS_DOMAINS: ".cn",
      ECS_DOMAIN_LIST_URLS: LIST_URL,
      CN_UPSTREAMS: CN_UPSTREAM,
      CN_DOMAINS: ".mycompany.example",
    } as unknown as Env;
    isDomesticSite("warm.example", readConfig(env));
    await chineseSitesSettled();

    const ask = async (name: string) => {
      const body = encodeDnsPacket({ header: { id: 1, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
      await handleRequest(new Request("https://doh.example/dns-query", {
        method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => "58.247.1.1", probe: () => ({}) });
    };
    await ask("upos.bilivideo.com");      // on the loaded list
    await ask("x.example.cn");            // ECS_DOMAINS
    await ask("intranet.mycompany.example"); // operator's CN_DOMAINS
    await ask("www.google.com");          // foreign name
    expect(hits["upos.bilivideo.com"]).toEqual({ upstream: "cn-dns.example", ecs: false });
    expect(hits["x.example.cn"]).toEqual({ upstream: "cn-dns.example", ecs: false });
    expect(hits["intranet.mycompany.example"]).toEqual({ upstream: "cn-dns.example", ecs: false });
    expect(hits["www.google.com"]).toEqual({ upstream: "up.example", ecs: false });
  });

  it("keeps a domestic name on the CN group even under ECS_MODE=always", async () => {
    const hits: Record<string, { upstream: string; ecs: boolean }> = {};
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const opt = query.additionals.find((record) => record.rdata.kind === "opt");
      hits[query.questions[0]!.name] = {
        upstream: new URL(String(input)).hostname,
        ecs: opt?.rdata.kind === "opt" && opt.rdata.options.some((option) => option.code === 8),
      };
      const packet = encodeDnsPacket({
        header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
        questions: query.questions, answers: [], authorities: [], additionals: [],
      });
      return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    class MemoryCache {
      private readonly values = new Map<string, Response>();
      async match(request: RequestInfo | URL) { return this.values.get(String(request))?.clone(); }
      async put(request: RequestInfo | URL, response: Response) { this.values.set(String(request), response.clone()); }
    }
    vi.stubGlobal("caches", { open: async () => new MemoryCache() });
    const env = {
      UPSTREAMS: PROXIED_UPSTREAM,
      ECS_MODE: "always",
      ECS_DOMAINS: ".cn",
      CN_UPSTREAMS: CN_UPSTREAM,
    } as unknown as Env;
    const body = encodeDnsPacket({ header: { id: 1, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name: "x.example.cn", type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
    await handleRequest(new Request("https://doh.example/dns-query", {
      method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => "58.247.1.1", probe: () => ({}) });
    expect(hits["x.example.cn"]).toEqual({ upstream: "cn-dns.example", ecs: false });
  });

  it("falls back to the ECS path for a domestic name when no CN upstreams are configured", async () => {
    const hits: Record<string, { upstream: string; ecs: boolean }> = {};
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const opt = query.additionals.find((record) => record.rdata.kind === "opt");
      hits[query.questions[0]!.name] = {
        upstream: new URL(String(input)).hostname,
        ecs: opt?.rdata.kind === "opt" && opt.rdata.options.some((option) => option.code === 8),
      };
      const packet = encodeDnsPacket({
        header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
        questions: query.questions, answers: [], authorities: [], additionals: [],
      });
      return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    class MemoryCache {
      private readonly values = new Map<string, Response>();
      async match(request: RequestInfo | URL) { return this.values.get(String(request))?.clone(); }
      async put(request: RequestInfo | URL, response: Response) { this.values.set(String(request), response.clone()); }
    }
    vi.stubGlobal("caches", { open: async () => new MemoryCache() });
    const env = {
      UPSTREAMS: PROXIED_UPSTREAM,
      ECS_DOMAINS: ".cn",
      CN_UPSTREAMS: "",
    } as unknown as Env;
    const body = encodeDnsPacket({ header: { id: 1, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name: "x.example.cn", type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
    await handleRequest(new Request("https://doh.example/dns-query", {
      method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => "58.247.1.1", probe: () => ({}) });
    expect(hits["x.example.cn"]).toEqual({ upstream: "up.example", ecs: true });
  });
});

describe("readConfig CN vars", () => {
  it("keeps https upstreams and lowercases extra domains", () => {
    const parsed = readConfig({ CN_UPSTREAMS: "https://dns.alidns.com/dns-query,http://insecure.example/dns-query", CN_DOMAINS: ".Huawei.COM" } as unknown as Env);
    expect(parsed.cnUpstreams).toEqual(["https://dns.alidns.com/dns-query"]);
    expect(parsed.cnDomains).toEqual([".huawei.com"]);
  });
});
