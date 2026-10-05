import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { describeHttpsParams } from "../src/dns/https-rr";
import { readConfig } from "../src/config";
import { handleRequest } from "../src/index";
import { relayServes, resetRelayState, setRelayHealth } from "../src/relay";
import { clearGithubPools, setGithubPools } from "../src/preferred";
import { strategyCacheTags } from "../src/plan";
import { PUBLIC_STRATEGIES } from "../src/strategies";
import { parseRequestOptions } from "../src/request-options";
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

const RELAY_IP = "192.168.31.250";
const GITHUB_REAL = "140.82.121.3";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  resetRelayState();
  clearGithubPools();
});

function healthyRelay(): void {
  setRelayHealth({ source: "test", ttlSeconds: 120, healthy: true });
}

describe("RELAY_* configuration", () => {
  it("accepts only private RELAY_IP addresses and known modes", () => {
    const base = { RELAY_MODE: "always", RELAY_DOMAINS: "*.github.com", RELAY_EXCLUDE_DOMAINS: "ssh.github.com" };
    const env = (extra: Record<string, string>) => ({ ...base, ...extra } as unknown as Env);
    expect(readConfig(env({ RELAY_IP: "192.168.1.250" })).relayIp).toBe("192.168.1.250");
    expect(readConfig(env({ RELAY_IP: "10.1.2.3" })).relayIp).toBe("10.1.2.3");
    expect(readConfig(env({ RELAY_IP: "172.16.5.5" })).relayIp).toBe("172.16.5.5");
    expect(readConfig(env({ RELAY_IP: "172.32.0.1" })).relayIp).toBeUndefined();
    expect(readConfig(env({ RELAY_IP: "8.8.8.8" })).relayIp).toBeUndefined();
    expect(readConfig(env({ RELAY_IP: "not-an-ip" })).relayIp).toBeUndefined();
    expect(readConfig(env({ RELAY_IP: RELAY_IP })).relayMode).toBe("always");
    expect(readConfig(env({ RELAY_IP: RELAY_IP, RELAY_MODE: "sometimes" })).relayMode).toBe("off");
    expect(readConfig(env({ RELAY_IP: RELAY_IP })).relayDomains).toEqual(["*.github.com"]);
    expect(readConfig(env({ RELAY_IP: RELAY_IP })).relayExcludeDomains).toEqual(["ssh.github.com"]);
  });
});

describe("relayServes", () => {
  const cfg = config({ relayMode: "always", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayExcludeDomains: ["ssh.github.com"] });

  it("matches wildcards over bare and subdomains; exclusions win; everything else untouched", () => {
    healthyRelay();
    expect(relayServes("github.com", cfg)).toBe(true);
    expect(relayServes("api.github.com", cfg)).toBe(true);
    expect(relayServes("ssh.github.com", cfg)).toBe(false);
    expect(relayServes("evilgithub.com", cfg)).toBe(false);
    expect(relayServes("githubusercontent.com", cfg)).toBe(false);
    expect(relayServes("example.com", cfg)).toBe(false);
  });

  it("never serves before a healthy report, and stops when reports expire", () => {
    expect(relayServes("github.com", cfg)).toBe(false);
    healthyRelay();
    expect(relayServes("github.com", cfg)).toBe(true);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 121_000);
    expect(relayServes("github.com", cfg)).toBe(false);
  });

  it("a report saying unhealthy stops serving immediately", () => {
    healthyRelay();
    setRelayHealth({ source: "test", ttlSeconds: 120, healthy: false });
    expect(relayServes("github.com", cfg)).toBe(false);
  });

  it("off mode or a missing address never serves", () => {
    healthyRelay();
    expect(relayServes("github.com", config({ relayMode: "off", relayIp: RELAY_IP, relayDomains: ["*.github.com"] }))).toBe(false);
    expect(relayServes("github.com", config({ relayMode: "always", relayDomains: ["*.github.com"] }))).toBe(false);
  });
});

describe("relay answers over /dns-query", () => {
  function stubUpstream(cache = new MemoryCache()): Env {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("ips-v4")) return new Response("104.16.0.0/13\n");
      if (url.includes("ips-v6")) return new Response("2606:4700::/32\n");
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name: qname, type: qtype } = query.questions[0]!;
      const answers: DnsPacket["answers"] = [];
      if (qtype === DnsType.A) {
        answers.push({ name: qname, type: DnsType.A, class: 1, ttl: 3600, rdata: { kind: "a", address: GITHUB_REAL } });
      } else if (qtype === DnsType.AAAA) {
        answers.push({ name: qname, type: DnsType.AAAA, class: 1, ttl: 3600, rdata: { kind: "aaaa", address: "2606:50c0:8000::153" } });
      } else if (qtype === DnsType.HTTPS) {
        answers.push({ name: qname, type: DnsType.HTTPS, class: 1, ttl: 300, rdata: { kind: "https", value: { priority: 1, target: "", params: [
          { key: 1, value: Uint8Array.from([2, 0x68, 0x33, 2, 0x68, 0x32]) }, // alpn h3,h2
          { key: 4, value: Uint8Array.from([140, 82, 121, 3]) },              // ipv4hint
          { key: 5, value: Uint8Array.from([0xfe, 0x0d, 1, 2, 3]) },          // ech
          { key: 6, value: new Uint8Array(16).fill(1) },                      // ipv6hint
        ] } } });
      }
      const packet = encodeDnsPacket({ header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: answers.length, nscount: 0, arcount: 0 }, questions: query.questions, answers, authorities: [], additionals: [] });
      return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    vi.stubGlobal("caches", { open: async () => cache });
    return {
      UPSTREAMS: "https://up.example/dns-query",
      GITHUB_DOMAINS: "github.com,api.github.com",
      RELAY_MODE: "always",
      RELAY_IP: RELAY_IP,
      RELAY_DOMAINS: "*.github.com",
      RELAY_EXCLUDE_DOMAINS: "ssh.github.com",
      ADMIN_TOKEN: "t",
    } as unknown as Env;
  }

  async function ask(name: string, type: number, cache = new MemoryCache()): Promise<DnsPacket> {
    const env = stubUpstream(cache);
    const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
    const res = await handleRequest(new Request("https://doh.example/dns-query", {
      method: "POST",
      headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
      body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
  }

  it("pins A to the relay with a bounded TTL, drops AAAA, and scrubs the HTTPS record", async () => {
    healthyRelay();
    const a = await ask("github.com", DnsType.A);
    expect(a.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
    expect(a.answers.every((r) => r.type !== DnsType.AAAA)).toBe(true);
    expect(Math.min(...a.answers.filter((r) => r.type === DnsType.A).map((r) => r.ttl))).toBe(60);

    const aaaa = await ask("github.com", DnsType.AAAA, new MemoryCache());
    expect(aaaa.answers.filter((r) => r.type === DnsType.AAAA)).toEqual([]);

    const https = await ask("github.com", DnsType.HTTPS, new MemoryCache());
    const record = https.answers.find((r) => r.type === DnsType.HTTPS);
    expect(record).toBeDefined();
    const params = describeHttpsParams((record!.rdata as { kind: "https"; value: never }).value);
    expect(params.alpn).toEqual(["h2"]);
    expect(params.ipv4hint).toEqual([RELAY_IP]);
    expect(params.ipv6hint).toBeUndefined();
    expect(params.ech).toBeUndefined();
  });

  it("leaves excluded names and unknown names untouched", async () => {
    healthyRelay();
    const ssh = await ask("ssh.github.com", DnsType.A);
    expect(ssh.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
    expect(ssh.answers[0]!.ttl).toBe(3600);
  });

  it("takes precedence over the github pool while healthy, and falls back when not", async () => {
    setGithubPools("prober", { "github.com": [GITHUB_REAL] }, 600);
    healthyRelay();
    const relayed = await ask("github.com", DnsType.A);
    expect(relayed.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
    resetRelayState();
    const pooled = await ask("github.com", DnsType.A, new MemoryCache());
    expect(pooled.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
  });

  it("with the mode off the relay adds no cache variant; healthy always-mode answers carry one", () => {
    healthyRelay();
    const options = parseRequestOptions(new URL("https://doh.example/dns-query"), config());
    const offCtx = { config: config({ githubDomains: ["github.com"] }), options, name: "github.com", type: DnsType.A };
    expect(strategyCacheTags(PUBLIC_STRATEGIES, offCtx)).toBe("");
    const onCtx = { config: config({ relayMode: "always" as const, relayIp: RELAY_IP, relayDomains: ["*.github.com"], githubDomains: ["github.com"] }), options, name: "github.com", type: DnsType.A };
    expect(strategyCacheTags(PUBLIC_STRATEGIES, onCtx)).toMatch(/^\|relay=v\d+$/);
    expect(strategyCacheTags(PUBLIC_STRATEGIES, { ...onCtx, name: "example.com" })).toBe("");
  });
});

describe("relay admin endpoints", () => {
  const env = { UPSTREAMS: "https://up.example/dns-query", ADMIN_TOKEN: "t", RELAY_MODE: "always", RELAY_IP: RELAY_IP, RELAY_DOMAINS: "*.github.com" } as unknown as Env;

  function call(path: string, init?: RequestInit): Promise<Response> {
    return handleRequest(new Request(`https://doh.example${path}`, init), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
  }

  it("POST /admin/relay-health records liveness; GET /admin/relay reports mode and health; both need the token", async () => {
    const unauthorized = await call("/admin/relay");
    expect(unauthorized.status).toBe(401);
    const auth = { headers: { Authorization: "Bearer t" } };
    const post = await call("/admin/relay-health", { method: "POST", ...auth, headers: { ...auth.headers, "Content-Type": "application/json" }, body: JSON.stringify({ source: "relay@192.168.31.250", ttl: 120, healthy: true }) });
    expect(post.status).toBe(200);
    const status = (await (await call("/admin/relay", auth)).json()) as { relay: { healthy: boolean; mode: string; ip: string } };
    expect(status.relay).toMatchObject({ healthy: true, mode: "always", ip: RELAY_IP });
  });

  it("GET /admin/pool serves the measured pool for the relay daemon", async () => {
    setGithubPools("prober", { "github.com": [GITHUB_REAL] }, 600);
    const res = await call("/admin/pool?name=github.com", { headers: { Authorization: "Bearer t" } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pool: string[]; source: string };
    expect(body.pool).toEqual([GITHUB_REAL]);
    expect(body.source).toBe("github-pool");
    const none = await call("/admin/pool?name=unknown.example", { headers: { Authorization: "Bearer t" } });
    expect(((await none.json()) as { pool: string[] }).pool).toEqual([]);
  });
});
