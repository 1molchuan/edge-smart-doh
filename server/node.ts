import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { dirname } from "node:path";
import { handleRequest, type RequestRuntime, type WaitUntilContext } from "../src/index";
import { parseIpv4 } from "../src/dns/packet";
import { readConfig } from "../src/config";
import { sanitizeRelayOverride, setRelayOverride, setRelayPersistence } from "../src/relay";

const DEFAULTS = {
  UPSTREAMS: "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query",
  ECS_UPSTREAMS: "",
  UPSTREAM_TIMEOUT_MS: "2500",
  UPSTREAM_HEDGE_MS: "100",
  CACHE_MIN_TTL: "30",
  CACHE_MAX_TTL: "3600",
  NEGATIVE_CACHE_MAX_TTL: "300",
  CACHE_STALE_TTL: "86400",
  CACHE_PREFETCH_PERCENT: "10",
  ECS_MODE: "rules",
  ECS_DOMAINS: ".cn",
  ECS_IPV4_PREFIX: "24",
  ECS_IPV6_PREFIX: "48",
  ECS_FALLBACK_SUBNET: "",
  ECS_DOMAIN_LIST_URLS: "",
  CN_UPSTREAMS: "",
  CN_DOMAINS: "",
  EDGEONE_CLIENT_IP_HEADER: "X-EdgeOne-Client-IP-Configure-Me",
  CF_REWRITE_ENABLED: "false",
  CF_PREFERRED_DOMAIN: "",
  CF_PREFERRED_IPV4: "",
  CF_PREFERRED_IPV6: "",
  CF_DROP_AAAA: "false",
  ADMIN_TOKEN: "",
  HUB_TOKEN: "",
  ISP_TABLE_URL: "",
  CF_IPV4_URL: "https://www.cloudflare.com/ips-v4/",
  CF_IPV6_URL: "https://www.cloudflare.com/ips-v6/",
  RULES_JSON: "[]",
  RULES_URL: "",
  ECH_ENABLED: "false",
  ECH_CONFIG_BASE64: "",
  ECH_DOMAINS: "",
  ECH_SOURCE_DOMAIN: "cloudflare-ech.com",
  META_ECH_CONFIG_BASE64: "",
  META_DOMAINS: ".facebook.com,.facebook.net,.fbcdn.net,.fbsbx.com,.instagram.com,.cdninstagram.com,.threads.net,.whatsapp.com,.whatsapp.net,.messenger.com",
  X_DOMAINS: "x.com,.x.com,twitter.com,.twitter.com,twimg.com,.twimg.com,t.co",
  GITHUB_DOMAINS: "",
  RELAY_MODE: "off",
  RELAY_IP: "",
  RELAY_DOMAINS: "",
  RELAY_EXCLUDE_DOMAINS: "",
  // Where the console's relay overrides (POST /admin/relay-config) persist across restarts; empty
  // disables persistence (overrides then live in memory only, which workers also get).
  RELAY_CONFIG_PATH: "",
  SAFE_LIST_URLS: "",
  SAFE_ALLOW: "",
  DYNAMIC_RULE_HOSTS: "paste.rs,raw.githubusercontent.com,gist.githubusercontent.com",
  DYNAMIC_RULES_MAX_BYTES: "262144",
  DEBUG: "false",
  LOG_QUERIES: "false",
  MAX_DNS_PACKET_SIZE: "4096",
} as const;

interface StoredResponse {
  body: ArrayBuffer;
  headers: [string, string][];
  status: number;
  statusText: string;
  expiresAt: number;
}

class MemoryCache {
  private readonly entries = new Map<string, StoredResponse>();
  private readonly maximumEntries = numberFromEnvironment("CACHE_MAX_ENTRIES", 4096, 128, 65536);

  /** Snapshot live entries as [key, headers, status, statusText, expiresAt, base64 body] rows. */
  export(): unknown[] {
    const now = Date.now();
    const rows: unknown[] = [];
    for (const [key, stored] of this.entries) {
      if (stored.expiresAt <= now) continue;
      rows.push([key, stored.headers, stored.status, stored.statusText, stored.expiresAt, Buffer.from(stored.body).toString("base64")]);
    }
    return rows;
  }

  import(rows: unknown[]): number {
    const now = Date.now();
    let loaded = 0;
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 6) continue;
      const [key, headers, status, statusText, expiresAt, body] = row as [string, [string, string][], number, string, number, string];
      if (typeof key !== "string" || typeof expiresAt !== "number" || expiresAt <= now || typeof body !== "string") continue;
      const bytes = Buffer.from(body, "base64");
      this.entries.set(key, {
        body: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        headers,
        status,
        statusText,
        expiresAt,
      });
      loaded += 1;
      if (this.entries.size > this.maximumEntries) break;
    }
    return loaded;
  }

  async match(request: RequestInfo | URL): Promise<Response | undefined> {
    const key = cacheKey(request);
    const stored = this.entries.get(key);
    if (!stored) return undefined;
    if (stored.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, stored);
    return new Response(stored.body.slice(0), {
      status: stored.status,
      statusText: stored.statusText,
      headers: stored.headers,
    });
  }

  async put(request: RequestInfo | URL, response: Response): Promise<void> {
    const maxAge = parseMaxAge(response.headers.get("Cache-Control"));
    if (maxAge <= 0) return;
    const key = cacheKey(request);
    this.entries.delete(key);
    this.entries.set(key, {
      body: await response.clone().arrayBuffer(),
      headers: [...response.headers.entries()],
      status: response.status,
      statusText: response.statusText,
      expiresAt: Date.now() + maxAge * 1000,
    });
    while (this.entries.size > this.maximumEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }
}

function cacheKey(request: RequestInfo | URL): string {
  if (request instanceof Request) return `${request.method}:${request.url}`;
  return `GET:${request instanceof URL ? request.href : request}`;
}

function parseMaxAge(value: string | null): number {
  const match = value?.match(/(?:^|,)\s*(?:s-maxage|max-age)=(\d+)/i);
  return match?.[1] ? Number.parseInt(match[1], 10) : 0;
}

function numberFromEnvironment(name: string, fallback: number, minimum: number, maximum: number): number {
  const value = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(value) ? Math.max(minimum, Math.min(maximum, value)) : fallback;
}

const memoryCache = new MemoryCache();
const cacheStorage = {
  default: memoryCache,
  open: async () => memoryCache,
} as unknown as CacheStorage;
Object.defineProperty(globalThis, "caches", { configurable: true, value: cacheStorage });

const cachePersistPath = process.env.CACHE_PERSIST_PATH || "";

function loadPersistedCache(): void {
  if (!cachePersistPath) return;
  try {
    const rows: unknown = JSON.parse(readFileSync(cachePersistPath, "utf8"));
    if (Array.isArray(rows)) console.log(JSON.stringify({ event: "cache_loaded", entries: memoryCache.import(rows), path: cachePersistPath }));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") console.warn(JSON.stringify({ event: "cache_load_error", message: String(error) }));
  }
}

function persistCache(): void {
  if (!cachePersistPath) return;
  try {
    mkdirSync(dirname(cachePersistPath), { recursive: true });
    const rows = memoryCache.export();
    const tmp = `${cachePersistPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(rows));
    renameSync(tmp, cachePersistPath);
    console.log(JSON.stringify({ event: "cache_saved", entries: rows.length, path: cachePersistPath }));
  } catch (error) {
    console.warn(JSON.stringify({ event: "cache_save_error", message: String(error) }));
  }
}

const env = Object.fromEntries(
  Object.entries(DEFAULTS).map(([name, fallback]) => [name, process.env[name] ?? fallback]),
) as unknown as Env;

/**
 * Mirrors undici's NO_PROXY semantics — undici's EnvHttpProxyAgent is what actually decides
 * reachability when fetch is put behind a proxy (see contrib/home), so the check must follow the same
 * rules or it stays silent exactly where it matters: "*" bypasses everything, an entry may carry a
 * ":port" suffix, and a leading "*." or "." makes it a suffix match. Returns null when nothing is
 * bypassed. Ports are ignored, which can only over-report and never stay silent.
 */
function noProxyMatcher(entries: string[]): ((hostname: string) => boolean) | null {
  if (entries.length === 0) return null;
  if (entries.includes("*")) return () => true;
  const exact = new Set<string>();
  const suffixes: string[] = [];
  for (const entry of entries) {
    const bare = entry.replace(/:\d+$/, "");
    if (bare.startsWith("*.") || bare.startsWith(".")) suffixes.push(bare.slice(1));
    else exact.add(bare);
  }
  return (hostname) => exact.has(hostname) || suffixes.some((suffix) => hostname.endsWith(suffix));
}

/**
 * `UPSTREAMS` is a trust list: every entry must be reached the same way. Anything named in `NO_PROXY`
 * is dialed directly while the rest go through `HTTP(S)_PROXY`, and the direct one is typically an
 * order of magnitude faster, so it wins the hedged race with exactly the answer the proxy exists to
 * avoid (see contrib/home/README.md). Warn instead of refusing to start, so a misconfigured box keeps
 * serving while the operator fixes it.
 */
function warnOnMixedUpstreamTrust(): void {
  // Match undici's variable priority (lowercase wins) or the check reads a different configuration
  // than the dispatcher does.
  const proxy = process.env.https_proxy ?? process.env.HTTPS_PROXY ?? process.env.http_proxy ?? process.env.HTTP_PROXY;
  if (!proxy) return;
  const bypasses = noProxyMatcher(
    (process.env.no_proxy ?? process.env.NO_PROXY ?? "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean),
  );
  if (!bypasses) return;
  const direct: string[] = [];
  for (const item of (process.env.UPSTREAMS ?? DEFAULTS.UPSTREAMS).split(",")) {
    const value = item.trim();
    // readConfig keeps only https:// entries; naming the rest would warn about upstreams the server
    // never queries.
    if (!value.startsWith("https://")) continue;
    let hostname: string;
    try {
      hostname = new URL(value).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    } catch {
      continue;
    }
    if (bypasses(hostname)) direct.push(hostname);
  }
  if (direct.length === 0) return;
  console.warn(JSON.stringify({
    event: "upstream_trust_warning",
    message: "UPSTREAMS mixes proxied and direct (NO_PROXY) upstreams: the direct one answers first, and its answers are the ones the proxy was avoiding",
    direct,
    hint: "keep UPSTREAMS to proxied (trusted) resolvers; serve direct/domestic resolvers from CN_UPSTREAMS instead",
  }));
}

/**
 * RELAY_MODE without a usable private RELAY_IP degrades to off inside readConfig; naming that here
 * keeps a typo from silently disabling the relay (the failure would look like "GitHub is flaky
 * again", not like a configuration problem).
 */
function warnOnRelayConfig(): void {
  const mode = (process.env.RELAY_MODE ?? "").toLowerCase();
  if (mode !== "auto" && mode !== "always") return;
  const ip = (process.env.RELAY_IP ?? "").trim();
  if (!ip) {
    console.warn(JSON.stringify({ event: "relay_config_warning", message: `RELAY_MODE=${mode} but RELAY_IP is empty: the relay path is disabled` }));
    return;
  }
  const bytes = (() => {
    try {
      return parseIpv4(ip);
    } catch {
      return undefined;
    }
  })();
  const [a, b] = bytes ? [bytes[0]!, bytes[1]!] : [undefined, undefined];
  const priv = a === 10 || a === 127 || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168);
  if (!priv) {
    console.warn(JSON.stringify({
      event: "relay_config_warning",
      message: `RELAY_MODE=${mode} but RELAY_IP=${ip} is not a private address: the relay path is disabled`,
      hint: "the relay must only ever point at an address a stranger cannot reach; use a second private IP on the LAN interface",
    }));
  }
}

/**
 * CN_UPSTREAMS are the opposite of the trust list: they are dialed directly, so a proxy env var
 * reaching them is exactly wrong — the query leaves through the proxy, the resolver sees the
 * proxy's exit instead of the client's operator, and a domestic resolver is suddenly the slow
 * path. Warn instead of refusing to start, so a misconfigured box keeps serving while fixed.
 */
function warnOnCnUpstreamProxy(): void {
  const proxy = process.env.https_proxy ?? process.env.HTTPS_PROXY ?? process.env.http_proxy ?? process.env.HTTP_PROXY;
  if (!proxy) return;
  const bypasses = noProxyMatcher(
    (process.env.no_proxy ?? process.env.NO_PROXY ?? "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean),
  );
  const proxied: string[] = [];
  for (const item of (process.env.CN_UPSTREAMS ?? "").split(",")) {
    const value = item.trim();
    if (!value.startsWith("https://")) continue;
    let hostname: string;
    try {
      hostname = new URL(value).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    } catch {
      continue;
    }
    if (!bypasses?.(hostname)) proxied.push(hostname);
  }
  if (proxied.length === 0) return;
  console.warn(JSON.stringify({
    event: "cn_upstream_proxy_warning",
    message: "CN_UPSTREAMS entries are not in NO_PROXY: they go through the egress proxy, losing the domestic view and the speed the split exists for",
    proxied,
    hint: "add their hostnames to NO_PROXY (see contrib/home/deploy-home.sh, which keeps the drop-in in sync)",
  }));
}

function clientIp(request: Request): { value?: string; source?: string } {
  const candidates: [string, string | null][] = [
    ["X-Real-IP", request.headers.get("X-Real-IP")],
    ["CF-Connecting-IP", request.headers.get("CF-Connecting-IP")],
    ["X-Forwarded-For", request.headers.get("X-Forwarded-For")?.split(",", 1)[0]?.trim() ?? null],
  ];
  const match = candidates.find(([, value]) => Boolean(value));
  return match ? { value: match[1]!, source: match[0] } : {};
}

const runtime: RequestRuntime = {
  clientIp(request) {
    return clientIp(request).value;
  },
  probe(request) {
    const client = clientIp(request);
    return {
      provider: "azure-vps",
      region: process.env.AZURE_REGION ?? "japanwest",
      clientIp: client.value,
      clientIpSource: client.source,
    };
  },
};

const waitUntilContext: WaitUntilContext = {
  waitUntil(promise) {
    void promise.catch((error: unknown) => console.error("waitUntil failure", error));
  },
};

async function readBody(request: IncomingMessage): Promise<Uint8Array | undefined> {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  const maximum = numberFromEnvironment("MAX_DNS_PACKET_SIZE", 4096, 512, 65535);
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.byteLength;
    if (length > maximum) throw new Response("Request body too large", { status: 413 });
    chunks.push(buffer);
  }
  return Uint8Array.from(Buffer.concat(chunks));
}

function requestUrl(request: IncomingMessage): URL {
  const host = request.headers.host ?? "localhost";
  const forwardedProtocol = request.headers["x-forwarded-proto"];
  const protocol = typeof forwardedProtocol === "string" ? forwardedProtocol.split(",", 1)[0]!.trim() : "http";
  return new URL(request.url ?? "/", `${protocol}://${host}`);
}

const publicHostnames = new Set(
  (process.env.PUBLIC_HOSTNAMES ?? process.env.PUBLIC_HOSTNAME ?? "")
    .split(",")
    .map((hostname) => hostname.trim().toLowerCase())
    .filter(Boolean),
);

function validateHostname(url: URL): boolean {
  const hostname = url.hostname.toLowerCase();
  return publicHostnames.size === 0 || publicHostnames.has(hostname) || hostname === "127.0.0.1" || hostname === "localhost";
}

async function sendResponse(response: Response, target: ServerResponse): Promise<void> {
  target.statusCode = response.status;
  target.statusMessage = response.statusText;
  response.headers.forEach((value, name) => target.setHeader(name, value));
  target.end(Buffer.from(await response.arrayBuffer()));
}

/**
 * Relay overrides from the console (POST /admin/relay-config) persist next to the cache dump in a
 * small JSON file, so a restart keeps what the operator last set. A missing or corrupt file simply
 * means the env values apply; every write is atomic (tmp + rename) like the cache dump.
 */
const relayConfigPath = process.env.RELAY_CONFIG_PATH || "";

function loadRelayOverrideFile(): void {
  if (!relayConfigPath) return;
  try {
    const patch = sanitizeRelayOverride(JSON.parse(readFileSync(relayConfigPath, "utf8")));
    if (patch) {
      setRelayOverride(patch, readConfig(env));
      console.log(JSON.stringify({ event: "relay_override_loaded", fields: Object.keys(patch) }));
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      console.warn(JSON.stringify({ event: "relay_override_load_error", message: String(error) }));
    }
  }
  setRelayPersistence((value) => {
    try {
      mkdirSync(dirname(relayConfigPath), { recursive: true });
      const tmp = `${relayConfigPath}.tmp`;
      writeFileSync(tmp, JSON.stringify(value ?? null), { mode: 0o600 });
      renameSync(tmp, relayConfigPath);
    } catch (error) {
      console.warn(JSON.stringify({ event: "relay_override_save_error", message: String(error) }));
    }
  });
}

const server = createServer(async (incoming, outgoing) => {
  try {
    const url = requestUrl(incoming);
    if (!validateHostname(url)) {
      await sendResponse(new Response("Misdirected request", { status: 421 }), outgoing);
      return;
    }
    const body = await readBody(incoming);
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
      else if (value !== undefined) headers.set(name, value);
    }
    if (incoming.socket.remoteAddress && !headers.has("X-Real-IP")) headers.set("X-Real-IP", incoming.socket.remoteAddress);
    const requestBody = body ? Uint8Array.from(body).buffer : undefined;
    const request = new Request(url, { method: incoming.method, headers, body: requestBody });
    await sendResponse(await handleRequest(request, env, waitUntilContext, runtime), outgoing);
  } catch (error) {
    if (error instanceof Response) await sendResponse(error, outgoing);
    else {
      console.error(error);
      await sendResponse(new Response("Internal server error", { status: 500 }), outgoing);
    }
  }
});

const host = process.env.HOST ?? "127.0.0.1";
const port = numberFromEnvironment("PORT", 8787, 1, 65535);
loadPersistedCache();
warnOnMixedUpstreamTrust();
warnOnCnUpstreamProxy();
warnOnRelayConfig();
loadRelayOverrideFile();
server.listen(port, host, () => console.log(JSON.stringify({ event: "listening", host, port })));

// Periodic snapshot bounds the loss on an unclean exit (OOM kill, power loss).
const persistTimer = cachePersistPath ? setInterval(persistCache, 5 * 60 * 1000) : undefined;
persistTimer?.unref();

function shutdown(signal: string): void {
  console.log(JSON.stringify({ event: "shutdown", signal }));
  if (persistTimer) clearInterval(persistTimer);
  persistCache();
  server.close((error) => {
    if (error) console.error(error);
    process.exit(error ? 1 : 0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
