import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeDnsPacket, getResponseTtl, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";
import { handleRequest } from "../src/index";
import { parseSafeLists, resetSafeLists, safeBlocked, safeListsSettled, safeMatch } from "../src/safe";
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
  resetSafeLists();
});

const LISTS: Record<string, string> = {
  "https://lists.example/ads.txt": "# ads\nads.example\n0.0.0.0 tracker.example\n||pop.example^\n||cdn.example^$third-party\n*.sdk.example\n@@||ok.ads.example^\nnot a domain line\nlocalhost\n",
  "https://lists.example/scam.txt": "! scam\nphish.example\nbank-login.example.\n",
};
const URLS = Object.keys(LISTS);
const fromLists = async (input: RequestInfo | URL) => new Response(LISTS[String(input)]);

describe("block lists", () => {
  const table = parseSafeLists(Object.values(LISTS));
  const allow = ["shop.phish.example"];

  it("reads plain, hosts, adblock and wildcard lines, and skips the rest", () => {
    expect([...table.block].sort()).toEqual(["ads.example", "bank-login.example", "phish.example", "pop.example", "sdk.example", "tracker.example"]);
    expect([...table.allow]).toEqual(["ok.ads.example"]);
  });

  it("blocks a listed name and its subdomains, never its parent or a lookalike", () => {
    expect(safeMatch(table, "ads.example")).toBe("ads.example");
    expect(safeMatch(table, "a.b.ads.example")).toBe("ads.example");
    expect(safeMatch(table, "Tracker.Example.")).toBe("tracker.example");
    expect(safeMatch(table, "example")).toBeUndefined();
    expect(safeMatch(table, "notads.example")).toBeUndefined();
    expect(safeMatch(table, "cdn.example")).toBeUndefined(); // $options rule skipped
  });

  it("lets an exception or SAFE_ALLOW entry win over a block of a parent", () => {
    expect(safeMatch(table, "ok.ads.example")).toBeUndefined();
    expect(safeMatch(table, "img.ok.ads.example")).toBeUndefined();
    expect(safeMatch(table, "shop.phish.example", allow)).toBeUndefined();
    expect(safeMatch(table, "shop.phish.example")).toBe("phish.example");
    expect(safeMatch(table, "www.phish.example", allow)).toBe("phish.example");
  });

  it("refuses lists with nothing usable", () => {
    expect(() => parseSafeLists(["# empty\nnot a domain\n"])).toThrow();
  });
});

describe("loading the lists", () => {
  it("is off without SAFE_LIST_URLS", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(safeBlocked("ads.example", config())).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never waits on the download, then blocks from the loaded lists", async () => {
    const fetchMock = vi.fn(fromLists);
    vi.stubGlobal("fetch", fetchMock);
    const withLists = config({ safeListUrls: URLS });
    expect(safeBlocked("ads.example", withLists)).toBeUndefined();
    await safeListsSettled();
    expect(safeBlocked("ads.example", withLists)).toBe("ads.example");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("loads nothing when one list fails, and backs off before retrying", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => (String(input).endsWith("scam.txt") ? new Response("down", { status: 502 }) : fromLists(input)));
    vi.stubGlobal("fetch", fetchMock);
    const withLists = config({ safeListUrls: URLS });
    safeBlocked("ads.example", withLists);
    await safeListsSettled();
    expect(safeBlocked("ads.example", withLists)).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("?safe=1 on /dns-query", () => {
  function stub(): Env {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url in LISTS) return fromLists(input);
      const query = parseDnsPacket(new Uint8Array(init!.body as ArrayBuffer));
      const { name, type } = query.questions[0]!;
      const answers: DnsPacket["answers"] = type === DnsType.A ? [{ name, type, class: 1, ttl: 300, rdata: { kind: "a", address: "192.0.2.7" } }] : [];
      const bytes = encodeDnsPacket({ header: { id: query.header.id, flags: 0x8180, qdcount: 1, ancount: answers.length, nscount: 0, arcount: 0 }, questions: query.questions, answers, authorities: [], additionals: [] });
      return new Response(Uint8Array.from(bytes).buffer, { headers: { "Content-Type": "application/dns-message" } });
    }));
    const cache = new MemoryCache();
    vi.stubGlobal("caches", { open: async () => cache });
    return { UPSTREAMS: "https://up.example/dns-query", SAFE_LIST_URLS: URLS.join(","), SAFE_ALLOW: "shop.phish.example" } as unknown as Env;
  }

  async function ask(env: Env, name: string, query = "?safe=1"): Promise<DnsPacket> {
    const body = encodeDnsPacket({ header: { id: 0x99, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 }, questions: [{ name, type: DnsType.A, class: 1 }], answers: [], authorities: [], additionals: [] });
    const res = await handleRequest(new Request(`https://doh.example/dns-query${query}`, {
      method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" }, body: Uint8Array.from(body).buffer,
    }), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(res.status).toBe(200);
    return parseDnsPacket(new Uint8Array(await res.arrayBuffer()));
  }
  const rcode = (packet: DnsPacket) => packet.header.flags & 0x0f;
  const addrs = (packet: DnsPacket) => packet.answers.flatMap((r) => (r.rdata.kind === "a" ? [r.rdata.address] : []));

  async function loaded(): Promise<Env> {
    const env = stub();
    safeBlocked("x.example", config({ safeListUrls: URLS }));
    await safeListsSettled();
    return env;
  }

  it("answers a blocked name NXDOMAIN with an SOA, so clients cache the refusal", async () => {
    const env = await loaded();
    const blocked = await ask(env, "sub.ads.example");
    expect(rcode(blocked)).toBe(3);
    expect(blocked.header.id).toBe(0x99);
    expect(getResponseTtl(blocked, 0, 86400, 3600)).toBe(600);
  });

  it("resolves everything else normally, and blocks nothing without ?safe=1", async () => {
    const env = await loaded();
    expect(addrs(await ask(env, "good.example"))).toEqual(["192.0.2.7"]);
    expect(addrs(await ask(env, "shop.phish.example"))).toEqual(["192.0.2.7"]);
    expect(addrs(await ask(env, "sub.ads.example", ""))).toEqual(["192.0.2.7"]);
    expect(addrs(await ask(env, "sub.ads.example", "?safe=0"))).toEqual(["192.0.2.7"]);
    // The unblocked answer cached above must not leak into a later ?safe=1 query.
    expect(rcode(await ask(env, "sub.ads.example"))).toBe(3);
  });

  it("rejects a malformed safe value", async () => {
    const env = stub();
    const res = await handleRequest(new Request("https://doh.example/dns-query?safe=yes&dns=AAABAAABAAAAAAAAAWEHZXhhbXBsZQAAAQAB"), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    expect(res.status).toBe(400);
  });

  it("/explain says which list entry blocked the name", async () => {
    const env = await loaded();
    const res = await handleRequest(new Request("https://doh.example/explain?name=www.phish.example&type=A&safe=1"), env, { waitUntil: () => undefined }, { clientIp: () => undefined, probe: () => ({}) });
    const out = await res.json() as { results: { blocked?: boolean; steps?: string[] }[] };
    expect(out.results[0]).toMatchObject({ blocked: true, steps: ["blocked by ?safe=1: phish.example is on the block lists (NXDOMAIN)"] });
  });
});
