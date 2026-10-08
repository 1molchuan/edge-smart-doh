import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { describeHttpsParams } from "../src/dns/https-rr";
import { readConfig, type AppConfig } from "../src/config";
import { handleRequest } from "../src/index";
import { isLanClientAddress, relayCacheTag, relayServes, relayStatus, resetRelayState, sanitizeRelayOverride, setRelayHealth, setRelayOverride } from "../src/relay";
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
/** A LAN client address, the normal case behind the home Caddy (deploy/Caddyfile sets X-Real-IP). */
const LAN = "192.168.31.10";
/** An address off the LAN, as the DoH port sees any client coming in from the internet. */
const WAN = "203.0.113.7";

/**
 * relayServes with the client stated: these tests are about the relay's own state machine and pools,
 * so the client is on the LAN unless a test says otherwise. The LAN gate itself is covered below.
 */
function lanServes(name: string, cfg: AppConfig, clientLan = true): boolean {
  return relayServes(name, cfg, clientLan);
}

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

  it("forced pool: only off/always are modes, everything else (including auto) is off", () => {
    const env = (extra: Record<string, string>) => ({ RELAY_IP: RELAY_IP, ...extra } as unknown as Env);
    expect(readConfig(env({ RELAY_FORCED_MODE: "always", RELAY_FORCED_DOMAINS: "*.google.com" }))).toMatchObject({ relayForcedMode: "always", relayForcedDomains: ["*.google.com"] });
    expect(readConfig(env({ RELAY_FORCED_MODE: "off" })).relayForcedMode).toBe("off");
    expect(readConfig(env({ RELAY_FORCED_MODE: "auto" })).relayForcedMode).toBe("off");
    expect(readConfig(env({})).relayForcedMode).toBe("off");
  });

  it("LAN-only gate: on unless explicitly off, and a junk value still fails safe to on", () => {
    const env = (extra: Record<string, string>) => ({ RELAY_IP: RELAY_IP, ...extra } as unknown as Env);
    expect(readConfig(env({})).relayLanOnly).toBe(true);
    expect(readConfig(env({ RELAY_LAN_ONLY: "true" })).relayLanOnly).toBe(true);
    expect(readConfig(env({ RELAY_LAN_ONLY: "" })).relayLanOnly).toBe(true);
    expect(readConfig(env({ RELAY_LAN_ONLY: "maybe" })).relayLanOnly).toBe(true);
    expect(readConfig(env({ RELAY_LAN_ONLY: "false" })).relayLanOnly).toBe(false);
    expect(readConfig(env({ RELAY_LAN_ONLY: "0" })).relayLanOnly).toBe(false);
    expect(readConfig(env({ RELAY_LAN_ONLY: "OFF" })).relayLanOnly).toBe(false);
  });
});

describe("LAN client classification", () => {
  it("counts RFC1918, loopback, link-local and ULA addresses as on-LAN", () => {
    for (const address of ["10.0.0.1", "10.255.255.254", "127.0.0.1", "172.16.0.1", "172.31.255.1", "192.168.3.10", "192.168.31.250", "169.254.1.1"]) {
      expect(isLanClientAddress(address), address).toBe(true);
    }
    expect(isLanClientAddress("::1")).toBe(true);
    expect(isLanClientAddress("[::1]")).toBe(true);
    expect(isLanClientAddress("fd00::1")).toBe(true);
    expect(isLanClientAddress("fcff::1")).toBe(true);
    expect(isLanClientAddress("fe80::1")).toBe(true);
    expect(isLanClientAddress("::ffff:192.168.3.10")).toBe(true);
  });

  it("counts public or unparsable addresses as off-LAN", () => {
    for (const address of [undefined, "", "   ", "8.8.8.8", "203.0.113.7", "172.32.0.1", "172.15.0.1", "169.253.1.1", "not-an-ip", "192.168.3", "::2", "2001:4860:4860::8888", "64:ff9b::1"]) {
      expect(isLanClientAddress(address as string | undefined), String(address)).toBe(false);
    }
  });
});

describe("relayServes", () => {
  const cfg = config({ relayMode: "always", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayExcludeDomains: ["ssh.github.com"] });

  it("matches wildcards over bare and subdomains; exclusions win; everything else untouched", () => {
    healthyRelay();
    expect(lanServes("github.com", cfg)).toBe(true);
    expect(lanServes("api.github.com", cfg)).toBe(true);
    expect(lanServes("ssh.github.com", cfg)).toBe(false);
    expect(lanServes("evilgithub.com", cfg)).toBe(false);
    expect(lanServes("githubusercontent.com", cfg)).toBe(false);
    expect(lanServes("example.com", cfg)).toBe(false);
  });

  it("never serves before a healthy report, and stops when reports expire", () => {
    expect(lanServes("github.com", cfg)).toBe(false);
    healthyRelay();
    expect(lanServes("github.com", cfg)).toBe(true);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 121_000);
    expect(lanServes("github.com", cfg)).toBe(false);
  });

  it("a report saying unhealthy stops serving immediately", () => {
    healthyRelay();
    setRelayHealth({ source: "test", ttlSeconds: 120, healthy: false });
    expect(lanServes("github.com", cfg)).toBe(false);
  });

  it("off mode or a missing address never serves", () => {
    healthyRelay();
    expect(lanServes("github.com", config({ relayMode: "off", relayIp: RELAY_IP, relayDomains: ["*.github.com"] }))).toBe(false);
    expect(lanServes("github.com", config({ relayMode: "always", relayDomains: ["*.github.com"] }))).toBe(false);
  });

  it("serves LAN clients only: an off-LAN or unknown client never gets the relay address", () => {
    healthyRelay();
    expect(relayServes("github.com", cfg, true)).toBe(true);
    expect(relayServes("github.com", cfg, false)).toBe(false);
    // Unknown (the caller could not resolve an address) is not on the LAN either: fail closed.
    expect(relayServes("github.com", cfg, undefined)).toBe(false);
  });

  it("the gate also closes the forced pool, which ignores measurement but not the client's side", () => {
    healthyRelay();
    const forcedCfg = config({ relayMode: "auto", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayForcedMode: "always", relayForcedDomains: ["*.google.com"] });
    expect(relayServes("www.google.com", forcedCfg, true)).toBe(true);
    expect(relayServes("www.google.com", forcedCfg, false)).toBe(false);
    expect(relayServes("www.google.com", forcedCfg, undefined)).toBe(false);
  });

  it("RELAY_LAN_ONLY=false restores the ungated behavior for callers that front the LAN", () => {
    healthyRelay();
    const gateOff = config({ relayLanOnly: false, relayMode: "auto", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayForcedMode: "always", relayForcedDomains: ["*.google.com"] });
    expect(relayServes("www.google.com", gateOff, false)).toBe(true);
    expect(relayServes("www.google.com", gateOff, undefined)).toBe(true);
    expect(relayServes("github.com", gateOff, false)).toBe(false); // still auto-gated: no samples
  });
});

describe("forced pool (RELAY_FORCED_*)", () => {
  const forcedCfg = config({ relayMode: "auto", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayForcedMode: "always", relayForcedDomains: ["*.google.com", "*.youtube.com"] });

  it("serves forced names with no measurement and the main pool still in auto", () => {
    healthyRelay();
    // The Google-family scenario exactly: auto has no samples for these hosts, forced answers anyway.
    expect(lanServes("www.google.com", forcedCfg)).toBe(true);
    expect(lanServes("google.com", forcedCfg)).toBe(true);
    expect(lanServes("youtu.be", forcedCfg)).toBe(false);
    // Main pool stays measurement-gated: an unmeasured github host is not served.
    expect(lanServes("github.com", forcedCfg)).toBe(false);
  });

  it("forced off, exclusions, liveness and a missing address all withdraw the forced answers", () => {
    healthyRelay();
    expect(lanServes("www.google.com", config({ ...forcedCfg, relayForcedMode: "off" }))).toBe(false);
    expect(lanServes("www.google.com", config({ ...forcedCfg, relayExcludeDomains: ["www.google.com"] }))).toBe(false);
    setRelayHealth({ source: "test", ttlSeconds: 120, healthy: false });
    expect(lanServes("www.google.com", forcedCfg)).toBe(false);
    healthyRelay();
    expect(lanServes("www.google.com", config({ ...forcedCfg, relayIp: undefined }))).toBe(false);
  });

  it("forced names ride the same answers as the main pool (pin, TTL, HTTPS scrub, cache tag)", async () => {
    healthyRelay();
    const env = {
      UPSTREAMS: "https://up.example/dns-query",
      GITHUB_DOMAINS: "github.com",
      RELAY_MODE: "auto",
      RELAY_IP: RELAY_IP,
      RELAY_DOMAINS: "*.github.com",
      RELAY_FORCED_MODE: "always",
      RELAY_FORCED_DOMAINS: "*.google.com",
      ADMIN_TOKEN: "t",
    } as unknown as Env;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("ips-v4")) return new Response("104.16.0.0/13\n");
      if (String(input).includes("ips-v6")) return new Response("2606:4700::/32\n");
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name: qname, type: qtype } = query.questions[0]!;
      const answers: DnsPacket["answers"] = [];
      if (qtype === DnsType.A) answers.push({ name: qname, type: DnsType.A, class: 1, ttl: 3600, rdata: { kind: "a", address: "142.250.72.196" } });
      else if (qtype === DnsType.AAAA) answers.push({ name: qname, type: DnsType.AAAA, class: 1, ttl: 3600, rdata: { kind: "aaaa", address: "2606:50c0:8000::153" } });
      else if (qtype === DnsType.HTTPS) answers.push({ name: qname, type: DnsType.HTTPS, class: 1, ttl: 300, rdata: { kind: "https", value: { priority: 1, target: "", params: [
        { key: 1, value: Uint8Array.from([2, 0x68, 0x33, 2, 0x68, 0x32]) },
        { key: 4, value: Uint8Array.from([142, 250, 1, 1]) },
        { key: 5, value: Uint8Array.from([0xfe, 0x0d, 1, 2, 3]) },
        { key: 6, value: new Uint8Array(16).fill(1) },
      ] } } });
      const packet = encodeDnsPacket({ header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: answers.length, nscount: 0, arcount: 0 }, questions: query.questions, answers, authorities: [], additionals: [] });
      return new Response(Uint8Array.from(packet).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    const cache = new MemoryCache();
    vi.stubGlobal("caches", { open: async () => cache });
    const ask = async (name: string, type: number): Promise<DnsPacket> => {
      const body = encodeDnsPacket({ header: { id: 0x4321, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
      const res = await handleRequest(new Request("https://doh.example/dns-query", {
        method: "POST",
        headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
        body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => LAN, probe: () => ({}) });
      return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
    };
    const a = await ask("www.google.com", DnsType.A);
    expect(a.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
    expect(Math.min(...a.answers.filter((r) => r.type === DnsType.A).map((r) => r.ttl))).toBe(60);
    const https = await ask("www.google.com", DnsType.HTTPS);
    const record = https.answers.find((r) => r.type === DnsType.HTTPS);
    const params = describeHttpsParams((record!.rdata as { kind: "https"; value: never }).value);
    expect(params.ipv4hint).toEqual([RELAY_IP]);
    expect(params.ech).toBeUndefined();
    expect(params.alpn).toEqual(["h2"]);
  });
});

describe("relay answers over /dns-query", () => {
  function stubUpstream(cache = new MemoryCache(), extra: Record<string, string> = {}): Env {
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
      ...extra,
    } as unknown as Env;
  }

  async function ask(name: string, type: number, cache = new MemoryCache(), clientIp: string | undefined = LAN, extra: Record<string, string> = {}): Promise<DnsPacket> {
    const env = stubUpstream(cache, extra);
    const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type, class: 1 }], answers: [], authorities: [], additionals: [] });
    const res = await handleRequest(new Request("https://doh.example/dns-query", {
      method: "POST",
      headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
      body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => clientIp, probe: () => ({}) });
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

  it("an off-LAN client keeps the ordinary answer — forced pool, pin and TTL included", async () => {
    healthyRelay();
    // Exactly the 2026-10-08 report: forcedMode=always + *.google.com pinned 192.168.3.250, which a
    // client outside the LAN can only time out on. The client's side now decides, not the domain list.
    const forced = { RELAY_MODE: "auto", RELAY_FORCED_MODE: "always", RELAY_FORCED_DOMAINS: "*.google.com" };
    const lan = await ask("www.google.com", DnsType.A, new MemoryCache(), LAN, forced);
    expect(lan.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
    const wan = await ask("www.google.com", DnsType.A, new MemoryCache(), WAN, forced);
    expect(wan.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
    expect(wan.answers[0]!.ttl).toBe(3600);
    // The main pool is closed the same way.
    const wanGithub = await ask("github.com", DnsType.A, new MemoryCache(), WAN);
    expect(wanGithub.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
    // An address the server cannot parse is not on the LAN either (the fully unknown case — the
    // runtime returning no address at all — is covered by the relayServes test above).
    const unknown = await ask("github.com", DnsType.A, new MemoryCache(), "not-an-ip");
    expect(unknown.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
    // Cache isolation: the LAN client's pinned answer must not leak to the off-LAN client.
    const shared = new MemoryCache();
    const sharedLan = await ask("github.com", DnsType.A, shared, LAN);
    expect(sharedLan.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
    const sharedWan = await ask("github.com", DnsType.A, shared, WAN);
    expect(sharedWan.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: GITHUB_REAL }]);
  });

  it("RELAY_LAN_ONLY=false serves the forced pool to any client (the escape hatch)", async () => {
    healthyRelay();
    const env = { RELAY_LAN_ONLY: "false", RELAY_MODE: "auto", RELAY_FORCED_MODE: "always", RELAY_FORCED_DOMAINS: "*.google.com" };
    const wan = await ask("www.google.com", DnsType.A, new MemoryCache(), WAN, env);
    expect(wan.answers.filter((r) => r.type === DnsType.A).map((r) => r.rdata)).toEqual([{ kind: "a", address: RELAY_IP }]);
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
    const offCtx = { config: config({ githubDomains: ["github.com"] }), options, lan: true, name: "github.com", type: DnsType.A };
    expect(strategyCacheTags(PUBLIC_STRATEGIES, offCtx)).toBe("");
    const onCtx = { config: config({ relayMode: "always" as const, relayIp: RELAY_IP, relayDomains: ["*.github.com"], githubDomains: ["github.com"] }), options, lan: true, name: "github.com", type: DnsType.A };
    expect(strategyCacheTags(PUBLIC_STRATEGIES, onCtx)).toMatch(/^\|relay=v\d+$/);
    expect(strategyCacheTags(PUBLIC_STRATEGIES, { ...onCtx, name: "example.com" })).toBe("");
    // An off-LAN client keys the ordinary answer, not the relay's pinned one (the pin is a LAN IP).
    expect(strategyCacheTags(PUBLIC_STRATEGIES, { ...onCtx, lan: false })).toBe("");
  });
});

describe("auto-mode hysteresis", () => {
  const autoCfg = config({ relayMode: "auto" as const, relayIp: RELAY_IP, relayDomains: ["*.github.com"] });

  function reportAt(minutes: number, direct: Record<string, { ok: boolean; rttMs?: number }>, healthy = true): void {
    vi.setSystemTime(Date.now() + minutes * 60_000);
    setRelayHealth({ source: "t", ttlSeconds: 600, healthy, direct });
  }

  it("hands a host over only after a persistently bad direct path, and back after a persistently good one", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    reportAt(0, {});
    expect(lanServes("github.com", autoCfg)).toBe(false);
    // 60% success is not bad enough to hand over.
    reportAt(1, { "github.com": { ok: true, rttMs: 120 } });
    reportAt(2, { "github.com": { ok: true, rttMs: 120 } });
    reportAt(3, { "github.com": { ok: false } });
    reportAt(4, { "github.com": { ok: false } });
    expect(lanServes("github.com", autoCfg)).toBe(false);
    // Now everything fails within the 15-minute enter window: 4/4 bad.
    reportAt(5, { "github.com": { ok: false } });
    reportAt(6, { "github.com": { ok: false } });
    expect(lanServes("github.com", autoCfg)).toBe(true);
    expect(lanServes("api.github.com", autoCfg)).toBe(false); // unmeasured host stays on the direct path
    // Recovery: good samples until the 30-minute exit window is >80% good.
    for (let i = 0; i < 12; i++) reportAt(3, { "github.com": { ok: true, rttMs: 90 } });
    expect(lanServes("github.com", autoCfg)).toBe(false);
  });

  it("bumps the cache tag on every decision change", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    reportAt(0, {});
    const before = relayCacheTag();
    for (let i = 0; i < 3; i++) reportAt(1, { "github.com": { ok: false } });
    const entered = relayCacheTag();
    expect(entered).not.toBe(before);
    for (let i = 0; i < 12; i++) reportAt(3, { "github.com": { ok: true, rttMs: 90 } });
    expect(relayCacheTag()).not.toBe(entered);
  });

  it("a relay going unhealthy hands every host back immediately", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    reportAt(0, {});
    for (let i = 0; i < 4; i++) reportAt(1, { "github.com": { ok: false }, "api.github.com": { ok: false } });
    expect(lanServes("github.com", autoCfg)).toBe(true);
    reportAt(1, {}, false);
    expect(lanServes("github.com", autoCfg)).toBe(false);
    expect(relayStatus(autoCfg).hosts.every((host) => !host.relayed)).toBe(true);
  });

  it("reports per-host rates for the monitor", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    reportAt(0, {});
    reportAt(1, { "github.com": { ok: true, rttMs: 100 } });
    reportAt(2, { "github.com": { ok: false } });
    const host = relayStatus(autoCfg).hosts.find((entry) => entry.host === "github.com");
    expect(host).toMatchObject({ relayed: false, samples: 2 });
    expect(host!.enterRate).toBeCloseTo(0.5);
  });
});

describe("runtime relay override (console control plane)", () => {
  const envOff = config({ relayMode: "off", relayIp: RELAY_IP, relayDomains: ["*.github.com"] });

  it("turns the relay on over an env value of off, and reset returns to the env", () => {
    healthyRelay();
    expect(lanServes("github.com", envOff)).toBe(false);
    const before = relayCacheTag();
    expect(setRelayOverride({ mode: "always" }, envOff)).toBe(true);
    expect(relayCacheTag()).not.toBe(before);
    expect(lanServes("github.com", envOff)).toBe(true);
    const status = relayStatus(envOff);
    expect(status).toMatchObject({ mode: "always", modeSource: "override", overridden: ["mode"], domains: ["*.github.com"] });
    expect(setRelayOverride({ mode: "always" }, envOff)).toBe(false); // same value: no bump
    expect(setRelayOverride(null, envOff)).toBe(true);
    expect(lanServes("github.com", envOff)).toBe(false);
    expect(relayStatus(envOff)).toMatchObject({ mode: "off", modeSource: "env", overridden: [] });
  });

  it("a domains override re-scopes which names are served", () => {
    const base = config({ relayMode: "always", relayIp: RELAY_IP, relayDomains: ["*.github.com"] });
    healthyRelay();
    setRelayOverride({ domains: ["*.example.com"], excludeDomains: ["bad.example.com"] }, base);
    expect(lanServes("www.example.com", base)).toBe(true);
    expect(lanServes("bad.example.com", base)).toBe(false);
    expect(lanServes("github.com", base)).toBe(false);
    setRelayOverride(null, base);
    expect(lanServes("www.example.com", base)).toBe(false);
    expect(lanServes("github.com", base)).toBe(true);
  });

  it("forced overrides: mode and domains, version bump, reset back to the env", () => {
    const base = config({ relayMode: "off", relayIp: RELAY_IP, relayDomains: ["*.github.com"], relayForcedMode: "off", relayForcedDomains: [] });
    healthyRelay();
    expect(lanServes("www.google.com", base)).toBe(false);
    const before = relayCacheTag();
    expect(setRelayOverride({ forcedMode: "always", forcedDomains: ["*.google.com"] }, base)).toBe(true);
    expect(relayCacheTag()).not.toBe(before);
    expect(lanServes("www.google.com", base)).toBe(true);
    const status = relayStatus(base);
    expect(status).toMatchObject({ forcedMode: "always", forcedModeSource: "override", overridden: expect.arrayContaining(["forcedMode", "forcedDomains"]), forcedDomains: ["*.google.com"] });
    expect(setRelayOverride({ forcedMode: "always", forcedDomains: ["*.google.com"] }, base)).toBe(false); // same values: no bump
    expect(setRelayOverride(null, base)).toBe(true);
    expect(lanServes("www.google.com", base)).toBe(false);
    expect(relayStatus(base)).toMatchObject({ forcedMode: "off", forcedModeSource: "env", overridden: [] });
  });

  it("sanitized persisted overrides drop an unknown forced mode but keep valid fields", () => {
    const base = config({ relayMode: "off", relayIp: RELAY_IP, relayDomains: ["*.github.com"] });
    healthyRelay();
    // sanitizeRelayOverride is what the Node boot path runs on the persisted JSON.
    const patch = sanitizeRelayOverride({ forcedMode: "auto", forcedDomains: ["*.google.com", "not a domain!"] });
    expect(patch).toEqual({ forcedDomains: ["*.google.com"] });
    setRelayOverride(patch, base);
    expect(lanServes("www.google.com", base)).toBe(false); // forcedMode "auto" was dropped → env off
    const patch2 = sanitizeRelayOverride({ forcedMode: "always", forcedDomains: ["*.google.com"] });
    setRelayOverride(patch2, base);
    expect(lanServes("www.google.com", base)).toBe(true);
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

  it("POST /admin/relay-config overrides mode and domains at runtime; reset returns to the env", async () => {
    expect((await call("/admin/relay-config", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status).toBe(401);
    const post = (payload: unknown): Promise<Response> =>
      call("/admin/relay-config", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    expect((await post({ mode: "sometimes" })).status).toBe(400);
    expect((await post({ domains: ["not a domain!"] })).status).toBe(400);
    expect((await post({})).status).toBe(400);

    healthyRelay();
    const cfg = () => readConfig(env);
    expect(lanServes("github.com", cfg())).toBe(true); // env: always + *.github.com
    const applied = await post({ mode: "off", domains: ["*.example.com"] });
    expect(applied.status).toBe(200);
    expect(((await applied.json()) as { relay: { mode: string; domains: string[]; modeSource: string } }).relay)
      .toMatchObject({ mode: "off", domains: ["*.example.com"], modeSource: "override" });
    expect(lanServes("github.com", cfg())).toBe(false); // override mode off wins over env always
    expect(lanServes("www.example.com", cfg())).toBe(false);

    await post({ mode: "always" });
    expect(lanServes("www.example.com", cfg())).toBe(true);
    expect(lanServes("github.com", cfg())).toBe(false);

    const reset = await post({ reset: true });
    expect(((await reset.json()) as { relay: { mode: string; modeSource: string; domains: string[] } }).relay)
      .toMatchObject({ mode: "always", modeSource: "env", domains: ["*.github.com"] });
    expect(lanServes("github.com", cfg())).toBe(true);
  });

  it("POST /admin/relay-health answers with the effective domain lists for the daemon to sync", async () => {
    const post = (payload: unknown): Promise<Response> =>
      call("/admin/relay-health", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const reported = (await (await post({ source: "relay@192.168.31.250", ttl: 120, healthy: true })).json()) as { relay: { domains: string[]; excludes: string[] } };
    expect(reported.relay).toMatchObject({ domains: ["*.github.com"], excludes: [] });
    await call("/admin/relay-config", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ domains: ["a.example", "*.b.example"], excludeDomains: ["x.a.example"] }) });
    const after = (await (await post({ source: "relay@192.168.31.250", ttl: 120, healthy: true })).json()) as { relay: { domains: string[]; excludes: string[]; forcedDomains: string[] } };
    expect(after.relay.domains).toEqual(["a.example", "*.b.example"]);
    expect(after.relay.excludes).toEqual(["x.a.example"]);
    expect(after.relay.forcedDomains).toEqual([]);
  });

  it("POST /admin/relay-config drives the forced pool: auto rejected, ECH conflicts rejected, no RELAY_IP rejected, valid turns on", async () => {
    const post = (payload: unknown): Promise<Response> =>
      call("/admin/relay-config", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const auto = await post({ forcedMode: "auto" });
    expect(auto.status).toBe(400);
    expect(await auto.text()).toContain("forcedMode");
    const badPattern = await post({ forcedDomains: ["not a domain!"] });
    expect(badPattern.status).toBe(400);
    const echEnv = { UPSTREAMS: "https://up.example/dns-query", ADMIN_TOKEN: "t", X_DOMAINS: "x.com,.x.com,twimg.com", RELAY_MODE: "always", RELAY_IP: RELAY_IP, RELAY_DOMAINS: "*.github.com" } as unknown as Env;
    const ech = await handleRequest(new Request("https://doh.example/admin/relay-config", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ forcedDomains: ["*.twimg.com"] }),
    }), echEnv, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(ech.status).toBe(400);
    expect(await ech.text()).toContain("ECH");
    const noIp = await handleRequest(new Request("https://doh.example/admin/relay-config", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ forcedMode: "always" }),
    }), { UPSTREAMS: "https://up.example/dns-query", ADMIN_TOKEN: "t", RELAY_DOMAINS: "*.github.com" } as unknown as Env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(noIp.status).toBe(400);
    expect(await noIp.text()).toContain("RELAY_IP");
    // Valid: forced on, and a forced name is served over an env of forced off.
    healthyRelay();
    const cfg = () => readConfig(env);
    expect(lanServes("www.google.com", cfg())).toBe(false);
    const applied = await post({ forcedMode: "always", forcedDomains: ["*.google.com"] });
    expect(applied.status).toBe(200);
    expect(((await applied.json()) as { relay: { forcedMode: string; forcedModeSource: string } }).relay).toMatchObject({ forcedMode: "always", forcedModeSource: "override" });
    expect(lanServes("www.google.com", cfg())).toBe(true);
    // The daemon side channel carries the forced list alongside the main lists.
    const health = (await (await call("/admin/relay-health", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ source: "relay@192.168.31.250", ttl: 120, healthy: true }) })).json()) as { relay: { forcedDomains: string[]; forcedMode: string } };
    expect(health.relay).toMatchObject({ forcedMode: "always", forcedDomains: ["*.google.com"] });
  });

  it("guards the control plane: version conflicts, ECH-domain conflicts, missing RELAY_IP", async () => {
    const post = (payload: unknown): Promise<Response> =>
      call("/admin/relay-config", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const version = (): Promise<number> => call("/admin/relay", { headers: { Authorization: "Bearer t" } }).then((res) => res.json().then((body: unknown) => (body as { relay: { configVersion: number } }).relay.configVersion));
    const stale = await version();
    await post({ mode: "auto" });
    const conflict = await post({ mode: "off", expectedVersion: stale });
    expect(conflict.status).toBe(409);
    const echEnv = { UPSTREAMS: "https://up.example/dns-query", ADMIN_TOKEN: "t", X_DOMAINS: "x.com,.x.com,twimg.com", RELAY_MODE: "always", RELAY_IP: RELAY_IP, RELAY_DOMAINS: "*.github.com" } as unknown as Env;
    const ech = await handleRequest(new Request("https://doh.example/admin/relay-config", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ domains: ["*.x.com"] }),
    }), echEnv, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(ech.status).toBe(400);
    expect(await ech.text()).toContain("ECH");
    const noIp = await handleRequest(new Request("https://doh.example/admin/relay-config", {
      method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ mode: "always" }),
    }), { UPSTREAMS: "https://up.example/dns-query", ADMIN_TOKEN: "t", RELAY_MODE: "off", RELAY_DOMAINS: "*.github.com" } as unknown as Env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(noIp.status).toBe(400);
    expect(await noIp.text()).toContain("RELAY_IP");
    // The daemon's applied-config receipt shows up in the status the console renders as "已同步".
    await call("/admin/relay-health", { method: "POST", headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify({ source: "relay@192.168.31.250", ttl: 120, healthy: true, appliedConfigVersion: 999 }) });
    const status = (await (await call("/admin/relay", { headers: { Authorization: "Bearer t" } })).json()) as { relay: { appliedConfigVersion: number } };
    expect(status.relay.appliedConfigVersion).toBeGreaterThanOrEqual(999);
  });
});
