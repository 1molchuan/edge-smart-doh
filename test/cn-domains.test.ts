import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType } from "../src/dns/types";
import { handleRequest } from "../src/index";
import { chineseSitesSettled, domainListMatch, isChineseSite, parseDomainLists, resetChineseSites } from "../src/cn-domains";
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
  resetChineseSites();
});

const LIST_URL = "https://lists.example/direct-list.txt";
const LIST = "# china\nbilivideo.com\ndomain:hdslb.com\nfull:www.exact.example\nregexp:^ad.+\.com$\nkeyword:taobao\nserver=/biliapi.net/114.114.114.114\nnot a domain\n";

describe("Chinese-site lists", () => {
  const table = parseDomainLists([LIST]);

  it("reads plain, domain:, full: and dnsmasq lines, and skips regexp: and keyword:", () => {
    expect([...table.suffix].sort()).toEqual(["biliapi.net", "bilivideo.com", "hdslb.com"]);
    expect([...table.exact]).toEqual(["www.exact.example"]);
  });

  it("matches a listed name and its subdomains; full: only the name itself", () => {
    expect(domainListMatch(table, "upos-sz-mirrorali.bilivideo.com")).toBe(true);
    expect(domainListMatch(table, "BILIVIDEO.COM.")).toBe(true);
    expect(domainListMatch(table, "notbilivideo.com")).toBe(false);
    expect(domainListMatch(table, "www.exact.example")).toBe(true);
    expect(domainListMatch(table, "a.www.exact.example")).toBe(false);
  });

  it("is off without ECS_DOMAIN_LIST_URLS, and never waits on the download", async () => {
    const fetchMock = vi.fn(async () => new Response(LIST));
    vi.stubGlobal("fetch", fetchMock);
    expect(isChineseSite("x.bilivideo.com", config())).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
    const withList = config({ ecsDomainListUrls: [LIST_URL] });
    expect(isChineseSite("x.bilivideo.com", withList)).toBe(false);
    await chineseSitesSettled();
    expect(isChineseSite("x.bilivideo.com", withList)).toBe(true);
  });

  it("sends ECS for a listed name that ECS_DOMAINS does not cover", async () => {
    const sent: Record<string, boolean> = {};
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === LIST_URL) return new Response(LIST);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const opt = query.additionals.find((record) => record.rdata.kind === "opt");
      sent[query.questions[0]!.name] = opt?.rdata.kind === "opt" && opt.rdata.options.some((option) => option.code === 8);
      const answer = encodeDnsPacket({ header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: query.questions, answers: [], authorities: [], additionals: [] });
      return new Response(Uint8Array.from(answer).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    const cache = new MemoryCache();
    vi.stubGlobal("caches", { open: async () => cache });
    const env = { UPSTREAMS: "https://up.example/dns-query", ECS_DOMAINS: ".cn", ECS_DOMAIN_LIST_URLS: LIST_URL } as unknown as Env;
    isChineseSite("warm.example", config({ ecsDomainListUrls: [LIST_URL] }));
    await chineseSitesSettled();
    const ask = async (name: string) => {
      const body = encodeDnsPacket({ header: { id: 1, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
      await handleRequest(new Request("https://doh.example/dns-query", {
        method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => "58.247.1.1", probe: () => ({}) });
    };
    await ask("upos.bilivideo.com");
    await ask("www.google.com");
    expect(sent).toEqual({ "upos.bilivideo.com": true, "www.google.com": false });
  });
});
