import { afterEach, describe, expect, it, vi } from "vitest";
import { normalizedCacheIdentity } from "../src/cache";
import { parseRequestOptions } from "../src/request-options";
import { applyResponseRules, loadRules } from "../src/rules";
import { DnsType, type DnsPacket } from "../src/dns/types";
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

function packet(type: number, address?: string): DnsPacket {
  return {
    header: { id: 1, flags: address ? 0x8180 : 0x0100, qdcount: 1, ancount: address ? 1 : 0, nscount: 0, arcount: 0 },
    questions: [{ name: "sub.example.com", type, class: 1 }],
    answers: address ? [{
      name: "sub.example.com",
      type,
      class: 1,
      ttl: 60,
      rdata: type === DnsType.A ? { kind: "a", address } : { kind: "aaaa", address },
    }] : [],
    authorities: [],
    additionals: [],
  };
}

afterEach(() => vi.unstubAllGlobals());


describe("request options", () => {
  it("normalizes preferred addresses and an allowed rules URL", () => {
    const result = parseRequestOptions(
      new URL("https://doh.example/dns-query?cf=Preferred.Example.&ip4=104.18.1.1&rules=https%3A%2F%2Fpaste.rs%2Fabc"),
      config(),
    );
    expect(result.cfDomains).toEqual(["preferred.example"]);
    expect(result.preferredIpv4).toEqual(["104.18.1.1"]);
    expect(result.rulesUrl).toBe("https://paste.rs/abc");
    expect(result.cacheVariant).toContain("cf=preferred.example");
  });

  it("rejects invalid addresses and non-allowlisted rule hosts", () => {
    expect(() => parseRequestOptions(new URL("https://doh.example/dns-query?ip4=999.1.1.1"), config())).toThrow(/ip/i);
    expect(() => parseRequestOptions(new URL("https://doh.example/dns-query?rules=https%3A%2F%2Fexample.com%2Frules"), config())).toThrow(/not allowed/i);
  });

  it("falls back to the configured default preferred domains", () => {
    const result = parseRequestOptions(new URL("https://doh.example/dns-query"), config({ cfPreferredDomains: ["cf.090227.xyz", "skk.moe"] }));
    expect(result.cfDomains).toEqual(["cf.090227.xyz", "skk.moe"]);
    expect(result.cfDomainIsDefault).toBe(true);
    expect(result.cacheVariant).toBe("cf=cf.090227.xyz%2Cskk.moe");
  });

  it("lets explicit cf, ip4 or ip6 override the default preferred domain", () => {
    const defaults = config({ cfPreferredDomains: ["cf.090227.xyz"] });
    const explicit = parseRequestOptions(new URL("https://doh.example/dns-query?cf=other.example"), defaults);
    expect(explicit.cfDomains).toEqual(["other.example"]);
    expect(explicit.cfDomainIsDefault).toBeUndefined();
    const ip4 = parseRequestOptions(new URL("https://doh.example/dns-query?ip4=104.18.1.1"), defaults);
    expect(ip4.cfDomains).toEqual([]);
    expect(ip4.preferredIpv4).toEqual(["104.18.1.1"]);
    const ip6 = parseRequestOptions(new URL("https://doh.example/dns-query?ip6=2606:4700::1"), defaults);
    expect(ip6.cfDomains).toEqual([]);
  });

  it("separates cache entries for different rewrite options", () => {
    const query = packet(DnsType.A);
    expect(normalizedCacheIdentity(query, "none", "ip4=104.18.1.1").text)
      .not.toBe(normalizedCacheIdentity(query, "none", "ip4=104.18.2.2").text);
  });
});

describe("host map rules", () => {
  it("accepts the article's wildcard ipv4/ipv6 JSON format", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      "*.example.com": { ipv4: ["203.0.113.10"], ipv6: ["2001:db8::10"] },
    }), { headers: { "Content-Type": "application/json" } })));
    const rules = await loadRules(
      config({ rulesUrl: "https://paste.rs/test" }),
      new MemoryCache() as unknown as Cache,
    );
    const rewritten4 = applyResponseRules(rules, packet(DnsType.A), packet(DnsType.A, "192.0.2.1"));
    const rewritten6 = applyResponseRules(rules, packet(DnsType.AAAA), packet(DnsType.AAAA, "2001:db8::1"));
    expect(rewritten4.answers[0]?.rdata).toEqual({ kind: "a", address: "203.0.113.10" });
    expect(rewritten6.answers[0]?.rdata).toEqual({ kind: "aaaa", address: "2001:db8::10" });
  });
});
