import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { handleRequest } from "../src/index";
import { ispScopeOf, lookupIsp, parseIspTable, resetIspTable } from "../src/isp";
import { clearLearnedPool, ispPoolStatus, preferredPool, setLearnedPool } from "../src/preferred";
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

const TABLE = [
  "# operator table served by the probe hub",
  "chinanet 58.247.0.0/16",
  "chinanet 116.224.0.0/12",
  "cmcc 120.192.0.0/10",
  "cernet 58.247.22.0/24", // nested inside chinanet's /16: the more specific range must win
  "unicom 2408:8000::/20",
  "not a valid line",
  "BadName 1.2.3.0/24",
  "unicom 999.1.1.0/24",
].join("\n");

afterEach(() => {
  vi.unstubAllGlobals();
  clearLearnedPool();
  resetIspTable();
});

describe("operator table", () => {
  const table = parseIspTable(TABLE);

  it("maps addresses to operators, most specific CIDR first", () => {
    expect(lookupIsp(table, "58.247.1.1")).toBe("chinanet");
    expect(lookupIsp(table, "58.247.22.207")).toBe("cernet");
    expect(lookupIsp(table, "58.247.23.1")).toBe("chinanet"); // right after the nested /24
    expect(lookupIsp(table, "120.200.3.4")).toBe("cmcc");
    expect(lookupIsp(table, "2408:8001::1")).toBe("unicom");
  });

  it("covers range boundaries and rejects everything outside", () => {
    expect(lookupIsp(table, "116.224.0.0")).toBe("chinanet");
    expect(lookupIsp(table, "116.239.255.255")).toBe("chinanet");
    expect(lookupIsp(table, "116.240.0.0")).toBeUndefined();
    expect(lookupIsp(table, "8.8.8.8")).toBeUndefined();
    expect(lookupIsp(table, "2606:4700::1")).toBeUndefined();
    expect(lookupIsp(table, "not-an-ip")).toBeUndefined();
  });

  it("reads IPv4-mapped IPv6 client addresses as IPv4", () => {
    expect(lookupIsp(table, "::ffff:120.200.3.4")).toBe("cmcc");
  });

  it("skips malformed lines and refuses a table with nothing usable", () => {
    expect(table.names).toEqual(["chinanet", "cmcc", "cernet", "unicom"]);
    expect(() => parseIspTable("# empty\nbad line\n")).toThrow();
  });

  it("never names an operator \"national\" (that scope is the hub's nationwide pool)", () => {
    const t = parseIspTable("national 10.0.0.0/8\nchinanet 58.32.0.0/11\n");
    expect(t.names).toEqual(["chinanet"]);
    expect(lookupIsp(t, "10.1.2.3")).toBeUndefined();
  });
});

describe("operator lookup for a request", () => {
  const url = "http://127.0.0.1:8790/internal/isp-table";

  it("is off without ISP_TABLE_URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await ispScopeOf("58.247.1.1", config(), new MemoryCache() as unknown as Cache)).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("loads the table once and names the operator scope", async () => {
    const fetchMock = vi.fn(async () => new Response(TABLE));
    vi.stubGlobal("fetch", fetchMock);
    const cache = new MemoryCache() as unknown as Cache;
    expect(await ispScopeOf("58.247.1.1", config({ ispTableUrl: url }), cache)).toBe("isp:chinanet");
    expect(await ispScopeOf("120.200.3.4", config({ ispTableUrl: url }), cache)).toBe("isp:cmcc");
    expect(await ispScopeOf("8.8.8.8", config({ ispTableUrl: url }), cache)).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fails open when the hub is down, and backs off instead of retrying every query", async () => {
    const fetchMock = vi.fn(async () => new Response("down", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    const cache = new MemoryCache() as unknown as Cache;
    expect(await ispScopeOf("58.247.1.1", config({ ispTableUrl: url }), cache)).toBeUndefined();
    expect(await ispScopeOf("58.247.1.1", config({ ispTableUrl: url }), cache)).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("pool layering: client prefix → operator → nationwide", () => {
  const cache = new MemoryCache() as unknown as Cache;

  it("puts the operator pool ahead of the nationwide pool, topped up from it", async () => {
    setLearnedPool(["1.1.1.1"], ["2606:4700::1"], 600, "aliyun");
    setLearnedPool(["3.3.3.3"], ["2606:4700::3"], 600, "hub", "isp:chinanet");
    const telecom = await preferredPool({}, [], true, config(), cache, "58.247.1/24", "isp:chinanet");
    expect(telecom).toEqual({ ipv4: ["3.3.3.3", "1.1.1.1"], ipv6: ["2606:4700::3", "2606:4700::1"], scope: "isp:chinanet" });
    const other = await preferredPool({}, [], true, config(), cache, "8.8.8/24", "isp:cmcc");
    expect(other).toEqual({ ipv4: ["1.1.1.1"], ipv6: ["2606:4700::1"], scope: undefined });
  });

  it("serves a full operator pool alone", async () => {
    setLearnedPool(["1.1.1.1"], [], 600, "aliyun");
    const six = ["3.3.3.1", "3.3.4.1", "3.3.5.1", "3.3.6.1", "3.3.7.1", "3.3.8.1"];
    setLearnedPool(six, [], 600, "hub", "isp:chinanet");
    const telecom = await preferredPool({}, [], true, config(), cache, undefined, "isp:chinanet");
    expect(telecom.ipv4).toEqual(six);
  });

  // 2026-09-26: a lapsed prober left a three-IP pool; a short narrow pool must not be served alone.
  it("tops a short pool up to six from the wider layers, without duplicates", async () => {
    setLearnedPool(["1.0.1.1", "3.3.3.3", "1.0.2.1", "1.0.3.1", "1.0.4.1", "1.0.5.1"], [], 600, "aliyun");
    setLearnedPool(["3.3.3.3", "3.3.4.4"], [], 600, "hub", "isp:chinanet");
    const telecom = await preferredPool({}, [], true, config(), cache, undefined, "isp:chinanet");
    expect(telecom.ipv4).toEqual(["3.3.3.3", "3.3.4.4", "1.0.1.1", "1.0.2.1", "1.0.3.1", "1.0.4.1"]);
  });

  it("fills each address family on its own, so an IPv4-only operator pool keeps the nationwide IPv6", async () => {
    setLearnedPool(["1.1.1.1"], ["2606:4700::1"], 600, "aliyun");
    setLearnedPool(["3.3.3.3"], [], 600, "hub", "isp:chinanet");
    const telecom = await preferredPool({}, [], true, config(), cache, undefined, "isp:chinanet");
    expect(telecom).toEqual({ ipv4: ["3.3.3.3", "1.1.1.1"], ipv6: ["2606:4700::1"], scope: "isp:chinanet" });
  });

  it("puts a client's own prefix pool ahead of its operator pool", async () => {
    setLearnedPool(["3.3.3.3"], [], 600, "hub", "isp:chinanet");
    setLearnedPool(["2.2.2.2"], [], 600, "home", "58.247.22/24");
    const home = await preferredPool({}, [], true, config(), cache, "58.247.22/24", "isp:chinanet");
    expect(home.ipv4).toEqual(["2.2.2.2", "3.3.3.3"]);
    expect(home.scope).toBe("58.247.22/24,isp:chinanet");
  });

  it("ignores an expired operator pool and never applies it to a request with its own ?cf=", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    try {
      setLearnedPool(["1.1.1.1"], [], 600, "aliyun");
      setLearnedPool(["3.3.3.3"], [], 60, "hub", "isp:chinanet");
      const explicit = await preferredPool({ ipv4: ["9.9.9.9"] }, [], false, config(), cache, undefined, "isp:chinanet");
      expect(explicit.ipv4).toEqual(["9.9.9.9"]);
      vi.setSystemTime(1_000_000 + 61_000);
      const later = await preferredPool({}, [], true, config(), cache, undefined, "isp:chinanet");
      expect(later.ipv4).toEqual(["1.1.1.1"]);
      expect(later.scope).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("/admin/preferred with the hub token", () => {
  const env = { ADMIN_TOKEN: "admin-token", HUB_TOKEN: "hub-token" } as unknown as Env;
  const runtime = { clientIp: () => "127.0.0.1", probe: () => ({}) };

  function stubCloudflareRanges(): void {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("ips-v4")) return new Response("104.16.0.0/13\n172.64.0.0/13\n");
      if (url.includes("ips-v6")) return new Response("2606:4700::/32\n");
      return new Response("unexpected", { status: 500 });
    }));
    const cache = new MemoryCache();
    vi.stubGlobal("caches", { open: async () => cache });
  }

  const call = (token: string, method: string, body?: unknown, e = env) => handleRequest(new Request("https://doh.example/admin/preferred", {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }), e, { waitUntil: () => undefined }, runtime);

  it("writes an operator pool and gets only a minimal reply", async () => {
    stubCloudflareRanges();
    const res = await call("hub-token", "POST", { ipv4: ["104.16.1.1", "172.64.2.2"], ipv6: ["2606:4700::5"], ttl: 1800, source: "cfhub", scope: "isp:chinanet" });
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, scope: "isp:chinanet", ipv4: 2, ipv6: 1 });
    expect(body.learned).toBeUndefined(); // no admin state for the hub
    expect(ispPoolStatus().map((pool) => pool.scope)).toEqual(["isp:chinanet"]);
  });

  it("cannot read state or write the nationwide or client pools", async () => {
    stubCloudflareRanges();
    expect((await call("hub-token", "GET")).status).toBe(403);
    expect((await call("hub-token", "POST", { ipv4: ["104.16.1.1"], source: "x" })).status).toBe(403);
    expect((await call("hub-token", "POST", { ipv4: ["104.16.1.1"], scope: "client" })).status).toBe(403);
    expect((await call("hub-token", "POST", { ipv4: ["104.16.1.1"], scope: "default" })).status).toBe(403);
  });

  it("rejects addresses outside Cloudflare's published ranges and bad operator names", async () => {
    stubCloudflareRanges();
    const poisoned = await call("hub-token", "POST", { ipv4: ["104.16.1.1", "203.0.113.9"], scope: "isp:chinanet" });
    expect(poisoned.status).toBe(400);
    expect(await poisoned.text()).toContain("203.0.113.9");
    expect((await call("hub-token", "POST", { ipv4: ["104.16.1.1"], scope: "isp:China Telecom" })).status).toBe(400);
    expect(ispPoolStatus()).toEqual([]);
  });

  it("keeps the admin token's full access, including operator pools", async () => {
    stubCloudflareRanges();
    expect((await call("admin-token", "POST", { ipv4: ["104.16.1.1"], scope: "isp:cmcc", source: "manual" })).status).toBe(200);
    const state = await (await call("admin-token", "GET")).json() as { isp: { scope: string }[] };
    expect(state.isp.map((pool) => pool.scope)).toEqual(["isp:cmcc"]);
  });

  it("refuses unknown tokens, and is absent when no token is configured", async () => {
    expect((await call("nope", "POST", { ipv4: ["104.16.1.1"], scope: "isp:cmcc" })).status).toBe(401);
    expect((await call("hub-token", "POST", { ipv4: ["104.16.1.1"], scope: "isp:cmcc" }, {} as unknown as Env)).status).toBe(404);
  });
});

describe("DNS answers follow the client's operator", () => {
  function answer(name: string, type: number, addresses: string[]): Response {
    const packet: DnsPacket = {
      header: { id: 0, flags: 0x8180, qdcount: 1, ancount: addresses.length, nscount: 0, arcount: 0 },
      questions: [{ name, type, class: 1 }],
      answers: addresses.map((address) => ({ name, type, class: 1, ttl: 300, rdata: type === DnsType.A ? { kind: "a" as const, address } : { kind: "aaaa" as const, address } })),
      authorities: [], additionals: [],
    };
    return new Response(Uint8Array.from(encodeDnsPacket(packet)).buffer, { headers: { "Content-Type": "application/dns-message" } });
  }

  it("gives telecom and mobile clients their own pools, and keeps the cache entries apart", async () => {
    const cache = new MemoryCache();
    vi.stubGlobal("caches", { open: async () => cache });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("ips-v4")) return new Response("104.16.0.0/13\n");
      if (url.includes("ips-v6")) return new Response("2606:4700::/32\n");
      if (url.includes("isp-table")) return new Response(TABLE);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name, type } = query.questions[0]!;
      const response = answer(name, type, type === DnsType.A ? ["104.16.9.9"] : []);
      const bytes = new Uint8Array(await response.arrayBuffer());
      bytes[0] = query.header.id >>> 8;
      bytes[1] = query.header.id & 0xff;
      return new Response(bytes.buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    const env = {
      UPSTREAMS: "https://up.example/dns-query",
      CF_PREFERRED_DOMAIN: "preferred.example",
      ISP_TABLE_URL: "http://127.0.0.1:8790/internal/isp-table",
    } as unknown as Env;
    setLearnedPool(["104.17.1.1"], [], 600, "aliyun");
    setLearnedPool(["104.18.3.3"], [], 600, "cfhub", "isp:chinanet");
    setLearnedPool(["104.19.4.4"], [], 600, "cfhub", "isp:cmcc");

    const ask = async (clientIp: string): Promise<string[]> => {
      const body = encodeDnsPacket({ header: { id: 0x1234, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name: "site.example", type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
      const res = await handleRequest(new Request("https://doh.example/dns-query", {
        method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
      }), env, { waitUntil: () => undefined }, { clientIp: () => clientIp, probe: () => ({}) });
      return parseDnsPacket(new Uint8Array(await res.arrayBuffer())).answers.flatMap((record) => (record.rdata.kind === "a" ? [record.rdata.address] : []));
    };

    // Each client gets its whole pool (its operator's, topped up from the nationwide one), rotated at
    // serve time, so compare as sets.
    const pool = async (clientIp: string) => (await ask(clientIp)).sort();
    expect(await pool("58.247.1.1")).toEqual(["104.17.1.1", "104.18.3.3"]); // telecom
    expect(await pool("120.200.3.4")).toEqual(["104.17.1.1", "104.19.4.4"]); // mobile: must not get telecom's cached answer
    expect(await pool("8.8.8.8")).toEqual(["104.17.1.1"]); // not in the table: nationwide pool
    expect(await pool("58.247.1.1")).toEqual(["104.17.1.1", "104.18.3.3"]); // telecom again, from its own cache entry
  });
});
