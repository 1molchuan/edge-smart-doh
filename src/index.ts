import { normalizedCacheIdentity, readCache, rotateAddressRecords, writeCache, type CacheHit, type CacheIdentity } from "./cache";
import { inAnyCidr } from "./cidr";
import { readConfig, type AppConfig } from "./config";
import { addEcs, domainMatches, makeEcsValue, removeEcs, shouldUseEcs } from "./dns/ecs";
import { encodeDnsPacket, makeServfail, parseDnsPacket, parseIpv4, patchTransactionId } from "./dns/packet";
import { DnsType, type DnsPacket } from "./dns/types";
import { chromiumEchVerdict, describeAnswers, dnsTypeName, selfCheckStatus, setSelfCheck } from "./explain";
import { alpnFor, h3CacheTag, h3Status, setH3Verdicts } from "./h3";
import { isIspName, ispScopeOf } from "./isp";
import { applyResponseRules, ecsOverride, loadRules, shouldBlock, type RuleSet } from "./rules";
import { parseRequestOptions, type RequestOptions } from "./request-options";
import { clearMetaEch, githubPoolFor, githubPoolStatus, ispPoolStatus, learnedPoolStatus, metaEchCacheTag, metaEchOverride, metaEchStatus, preferredPool, scopedPoolStatus, setGithubPools, setLearnedPool, setMetaEch, setSitePools, sitePoolCacheTag, sitePoolFor, sitePoolStatus } from "./preferred";
import {
  flattenAliases,
  injectEch,
  injectEchBytes,
  loadCloudflareRanges,
  pinAddresses,
  pinHttpsHints,
  resolveDomainAddresses,
  resolveEchConfig,
  responseUsesCloudflare,
  servedByCloudflare,
  rewriteCloudflareAddresses,
  rewriteXAddresses,
  validatedEchConfig,
} from "./rewrite";
import { queryUpstreams } from "./upstream";

const DNS_CONTENT_TYPE = "application/dns-message";

function dnsResponse(packet: Uint8Array, status = 200): Response {
  let body = packet;
  try {
    body = rotateAddressRecords(packet);
  } catch {
    // A packet we cannot re-encode (unknown RDATA with compression) is served as-is.
  }
  return new Response(Uint8Array.from(body).buffer, {
    status,
    headers: {
      "Content-Type": DNS_CONTENT_TYPE,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8" },
  });
}

export interface WaitUntilContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface RequestRuntime {
  clientIp(request: Request, env: Env): string | undefined | Promise<string | undefined>;
  probe(request: Request): Record<string, unknown>;
}

function acceptsDns(request: Request): boolean {
  const accept = request.headers.get("Accept");
  return !accept || accept === "*/*" || accept.toLowerCase().split(",").some((item) => item.trim().startsWith(DNS_CONTENT_TYPE));
}

function decodeBase64Url(value: string): Uint8Array {
  if (!value || value.length > 87384 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new Error("Invalid base64url DNS query");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(normalized + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function readDnsRequest(request: Request, maximum: number): Promise<Uint8Array> {
  if (!acceptsDns(request)) throw new Response("Accept must allow application/dns-message", { status: 406 });
  if (request.method === "GET") {
    const raw = new URL(request.url).searchParams.get("dns");
    if (!raw) throw new Response("Missing dns query parameter", { status: 400 });
    const packet = decodeBase64Url(raw);
    if (packet.length > maximum) throw new Response("DNS packet too large", { status: 413 });
    return packet;
  }
  if (request.method === "POST") {
    const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== DNS_CONTENT_TYPE) throw new Response("Content-Type must be application/dns-message", { status: 415 });
    const declared = Number(request.headers.get("Content-Length"));
    if (Number.isFinite(declared) && declared > maximum) throw new Response("DNS packet too large", { status: 413 });
    const packet = new Uint8Array(await request.arrayBuffer());
    if (packet.length > maximum) throw new Response("DNS packet too large", { status: 413 });
    return packet;
  }
  throw new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
}

function validateQuery(packet: DnsPacket): void {
  if ((packet.header.flags & 0x8000) !== 0) throw new Error("DNS request has QR set");
  if (((packet.header.flags >>> 11) & 0x0f) !== 0) throw new Error("Only standard DNS queries are supported");
  if (packet.questions.length !== 1) throw new Error("Exactly one DNS question is required");
}

function makeBlockedResponse(query: DnsPacket): Uint8Array {
  return encodeDnsPacket({
    header: { ...query.header, flags: 0x8000 | (query.header.flags & 0x7910) | 0x0080 | 3 },
    questions: query.questions,
    answers: [],
    authorities: [],
    additionals: [],
  });
}

async function timingSafeTokenMatches(provided: string | null, expected: string | undefined): Promise<boolean> {
  if (!provided || !expected) return false;
  const encoder = new TextEncoder();
  const a = encoder.encode(provided);
  const b = encoder.encode(expected);
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index]! ^ b[index]!;
  return difference === 0;
}

function optionalStringBinding(env: Env, name: string): string | undefined {
  const value: unknown = Reflect.get(env, name);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

async function cloudflareClientIp(request: Request, env: Env, edgeHeader: string): Promise<string | undefined> {
  const trusted = await timingSafeTokenMatches(request.headers.get("X-DoH-Origin-Token"), optionalStringBinding(env, "DOH_ORIGIN_TOKEN"));
  if (trusted) {
    const forwarded = request.headers.get(edgeHeader)?.split(",", 1)[0]?.trim();
    if (forwarded) return forwarded;
  }
  return request.headers.get("CF-Connecting-IP") ?? undefined;
}

/** Per-request state shared by every query of one request (a DoH query, or /explain's three). */
interface DnsSetup {
  config: AppConfig;
  options: RequestOptions;
  cache: Cache;
  ip?: string;
  scope?: string;
  rules: RuleSet;
}

async function prepareDns(request: Request, env: Env, runtime: RequestRuntime): Promise<DnsSetup | Response> {
  let config = readConfig(env);
  let options: RequestOptions;
  try {
    options = parseRequestOptions(new URL(request.url), config);
  } catch (error) {
    return new Response(error instanceof Error ? error.message : "Invalid request options", { status: 400 });
  }
  const cache = await caches.open("edge-smart-doh-v1");
  const ip = await runtime.clientIp(request, env);
  let preferred: { ipv4: string[]; ipv6: string[]; scope?: string } = {
    ipv4: options.preferredIpv4 ?? config.cfPreferredIpv4,
    ipv6: options.preferredIpv6 ?? config.cfPreferredIpv6,
  };
  try {
    // The operator lookup only matters when the request relies on the server default pool.
    const ispScope = options.cfDomainIsDefault === true ? await ispScopeOf(ip, config, cache) : undefined;
    preferred = await preferredPool(
      { ipv4: options.preferredIpv4, ipv6: options.preferredIpv6 },
      options.cfDomains,
      options.cfDomainIsDefault === true,
      config,
      cache,
      clientScopeKey(ip),
      ispScope,
    );
  } catch (error) {
    // A server-wide default must fail open: answer without the rewrite rather than break every query.
    if (options.cfDomainIsDefault) {
      if (config.debug) console.warn(JSON.stringify({ event: "cf_default_resolve_error", message: errorMessage(error) }));
    } else if (preferred.ipv4.length === 0 && preferred.ipv6.length === 0) {
      return new Response(`Unable to resolve cf hostname: ${errorMessage(error)}`, { status: 502 });
    }
  }
  config = {
    ...config,
    rulesUrl: options.rulesUrl ?? config.rulesUrl,
    cfRewriteEnabled: config.cfRewriteEnabled || preferred.ipv4.length > 0 || preferred.ipv6.length > 0,
    cfPreferredIpv4: preferred.ipv4,
    cfPreferredIpv6: preferred.ipv6,
  };
  const rules = await loadRules(config, cache);
  return { config, options, cache, ip, scope: preferred.scope, rules };
}

/** A site pool (see sitePoolFor) stands in for the server's default pool only; an explicit ?ip4= or ?cf= choice wins. */
function sitePool(name: string, options: RequestOptions): string[] {
  return options.cfDomainIsDefault === true ? sitePoolFor(name) : [];
}

/** ECS decision and cache key for one query. */
function planQuery(query: DnsPacket, setup: DnsSetup): { upstreamQuery: DnsPacket; useEcs: boolean; ecsIdentity?: string; identity: CacheIdentity } {
  const { config, options, rules, ip } = setup;
  const ecs = ip ? makeEcsValue(ip, config.ecsIpv4Prefix, config.ecsIpv6Prefix) : undefined;
  const useEcs = ecs ? shouldUseEcs(query, config, ecsOverride(rules, query)) : false;
  const upstreamQuery = useEcs && ecs ? addEcs(query, ecs) : removeEcs(query);
  const question = query.questions[0]!;
  let variant = options.cacheVariant;
  if (setup.scope) variant += `|pool=${setup.scope}`;
  if (sitePool(question.name, options).length > 0) variant += `|${sitePoolCacheTag(question.name)}`;
  if (config.echEnabled && question.type === DnsType.HTTPS) {
    variant += `|${h3CacheTag()}`;
    if (domainMatches(question.name, config.metaDomains)) variant += `|${metaEchCacheTag()}`;
  }
  const ecsIdentity = useEcs && ecs ? ecs.identity : undefined;
  return { upstreamQuery, useEcs, ecsIdentity, identity: normalizedCacheIdentity(query, ecsIdentity ?? "none", variant) };
}

/**
 * Chromium waits at most ~50ms after the A/AAAA answers for the HTTPS record before connecting
 * without ECH, so an HTTPS answer must never wait on upstream when any copy exists: an expired one
 * is served at once (short TTL) and revalidated in the background. ECH servers hand back fresh keys
 * via retry_configs if the served config has rotated meanwhile.
 */
function servesFromCache(cached: CacheHit, type: number): boolean {
  return cached.state !== "stale" || type === DnsType.HTTPS;
}

async function handleDns(request: Request, env: Env, ctx: WaitUntilContext, runtime: RequestRuntime): Promise<Response> {
  const started = Date.now();
  let wire: Uint8Array;
  try {
    wire = await readDnsRequest(request, readConfig(env).maxDnsPacketSize);
  } catch (error) {
    if (error instanceof Response) return error;
    return new Response(error instanceof Error ? error.message : "Malformed request", { status: 400 });
  }

  let query: DnsPacket;
  try {
    query = parseDnsPacket(wire);
    validateQuery(query);
  } catch (error) {
    return new Response(error instanceof Error ? error.message : "Malformed DNS packet", { status: 400 });
  }

  const setup = await prepareDns(request, env, runtime);
  if (setup instanceof Response) return setup;
  const { config, options, cache, rules } = setup;
  if (shouldBlock(rules, query)) return dnsResponse(makeBlockedResponse(query));

  const { upstreamQuery, useEcs, identity } = planQuery(query, setup);
  const question = query.questions[0]!;
  const cached = await readCache(cache, identity, config);

  const resolveAndStore = async (): Promise<{ wire: Uint8Array; upstream: string }> => {
    const resolved = await resolveFresh(query, upstreamQuery, useEcs, rules, options, config, cache);
    ctx.waitUntil(writeCache(cache, identity, resolved.wire, config).catch((error: unknown) => {
      if (config.debug) console.warn(JSON.stringify({ event: "cache_write_error", message: errorMessage(error) }));
    }));
    return resolved;
  };

  if (cached && servesFromCache(cached, question.type)) {
    if (cached.state !== "fresh") {
      // Serve the hit now and revalidate in the background so hot names never go cold.
      ctx.waitUntil(resolveAndStore().catch((error: unknown) => {
        if (config.debug) console.warn(JSON.stringify({ event: "prefetch_error", message: errorMessage(error) }));
      }));
    }
    logQuery(config, query, cached.state === "fresh" ? "hit" : cached.state === "refresh" ? "prefetch" : "stale", undefined, Date.now() - started);
    return dnsResponse(cached.packet);
  }

  try {
    const { wire: clientWire, upstream } = await resolveAndStore();
    logQuery(config, query, "miss", upstream, Date.now() - started);
    return dnsResponse(clientWire);
  } catch (error) {
    console.error(JSON.stringify({ event: "upstream_failure", message: errorMessage(error) }));
    if (cached) {
      // RFC 8767: an expired answer beats SERVFAIL when every upstream is unreachable.
      logQuery(config, query, "stale", undefined, Date.now() - started);
      return dnsResponse(cached.packet);
    }
    logQuery(config, query, "miss", undefined, Date.now() - started);
    return dnsResponse(makeServfail(wire));
  }
}

/** `notes`, when given, collects one line per decision for /explain. */
async function resolveFresh(
  query: DnsPacket,
  upstreamQuery: DnsPacket,
  useEcs: boolean,
  rules: RuleSet,
  options: RequestOptions,
  config: AppConfig,
  cache: Cache,
  notes?: string[],
): Promise<{ wire: Uint8Array; upstream: string }> {
  const upstreamWire = encodeDnsPacket(upstreamQuery);
  const result = await queryUpstreams(upstreamWire, config, { ecs: useEcs });
  const originalResponse = parseDnsPacket(result.packet);
  if (originalResponse.header.id !== upstreamQuery.header.id) throw new Error("Upstream transaction ID mismatch");
  if (notes) {
    const answers = describeAnswers(originalResponse);
    notes.push(`upstream ${new URL(result.upstream).hostname}${useEcs ? " (with ECS)" : ""}: rcode ${originalResponse.header.flags & 0x0f}, ${answers.length > 0 ? answers.join("; ") : "no answers"}`);
  }
  let transformed = applyResponseRules(rules, query, originalResponse);
  if (transformed !== originalResponse) notes?.push("response rules changed the answer");
  let cloudflareRanges: Awaited<ReturnType<typeof loadCloudflareRanges>> | undefined;
  if (config.cfRewriteEnabled || (config.echEnabled && query.questions[0]?.type === 65)) {
    try {
      cloudflareRanges = await loadCloudflareRanges(config, cache);
      if (config.cfRewriteEnabled) {
        const before = transformed;
        transformed = rewriteCloudflareAddresses(transformed, cloudflareRanges, config);
        if (transformed !== before) notes?.push(`Cloudflare addresses rewritten to the preferred pool (${[...config.cfPreferredIpv4, ...config.cfPreferredIpv6].join(", ")})`);
      }
    } catch (error) {
      notes?.push(`Cloudflare ranges unavailable: ${errorMessage(error)}`);
      if (config.debug) console.warn(JSON.stringify({ event: "cf_ranges_error", message: errorMessage(error) }));
    }
  }
  // X hosts are steered between Cloudflare and Fastly per resolver, and a few (abs-0/ton.twimg.com)
  // live only on X's own network. A host counts as Cloudflare if it resolves there now or, for the
  // multi-CDN X list, if Cloudflare serves it at all; only then is it pinned to the pool with ECH.
  const question = query.questions[0]!;
  const multiCdn = domainMatches(question.name, config.xDomains);
  let onCloudflare: boolean | undefined;
  const classify = async (): Promise<boolean> => {
    if (onCloudflare !== undefined) return onCloudflare;
    const ranges = cloudflareRanges;
    if (!ranges) return (onCloudflare = false);
    const checkCname = multiCdn;
    const [direct, viaCname] = await Promise.all([
      resolveDomainAddresses(question.name, config, cache).then((addresses) => responseUsesCloudflare(addresses, ranges), () => false),
      checkCname ? servedByCloudflare(question.name, config, cache) : Promise.resolve(false),
    ]);
    notes?.push(`Cloudflare check: current answer ${direct ? "is" : "is not"} on Cloudflare${checkCname ? `; ${question.name}.cdn.cloudflare.net ${viaCname ? "exists" : "does not exist"}` : ""}`);
    return (onCloudflare = direct || viaCname);
  };
  if (multiCdn) {
    try {
      if (await classify()) {
        transformed = rewriteXAddresses(transformed, query, config);
        notes?.push("X host served by Cloudflare: addresses pinned to the preferred pool");
      } else {
        notes?.push("X host not served by Cloudflare: answer left untouched");
      }
    } catch (error) {
      notes?.push(`X classification failed: ${errorMessage(error)}`);
      if (config.debug) console.warn(JSON.stringify({ event: "x_classify_error", message: errorMessage(error) }));
    }
  }
  // A site whose origin hangs through the general pool's colos gets the IPs a prober verified end to
  // end (see setSitePools). IPv6 is dropped: the site pools are IPv4, and a dual-stack client would
  // otherwise prefer the untested IPv6 pool. The HTTPS hints are pinned below, after ECH injection.
  const siteIps = sitePool(question.name, options);
  if (siteIps.length > 0 && (question.type === DnsType.A || question.type === DnsType.AAAA)) {
    try {
      if (await classify()) {
        transformed = pinAddresses(transformed, query, siteIps);
        notes?.push(`site pool (origin unreachable through the general pool): pinned to ${siteIps.join(", ")}, IPv6 dropped`);
      }
    } catch (error) {
      notes?.push(`site pool classification failed: ${errorMessage(error)}`);
    }
  }
  // GitHub-family names: pin A to the host's own measured pool (no ECH — GitHub's China pain is IP
  // reachability). AAAA is dropped (the pools are IPv4). Left untouched when nothing was measured.
  if (domainMatches(question.name, config.githubDomains) && (question.type === DnsType.A || question.type === DnsType.AAAA)) {
    const pool = githubPoolFor(question.name);
    if (pool.length > 0) {
      transformed = pinAddresses(transformed, query, pool);
      notes?.push(`GitHub host pinned to its measured pool (${pool.join(", ")}), IPv6 dropped`);
    } else {
      notes?.push("GitHub host: no measured pool yet, answer left untouched");
    }
  }
  const beforeConfiguredEch = transformed;
  transformed = injectEch(transformed, config);
  if (transformed !== beforeConfiguredEch) notes?.push("ECH injected from ECH_CONFIG_BASE64 (ECH_DOMAINS)");
  if (config.echEnabled && question.type === DnsType.HTTPS) {
    try {
      if (domainMatches(question.name, config.metaDomains)) {
        const override = metaEchOverride();
        const metaEch = override === null ? undefined : override ?? validatedEchConfig(config.metaEchConfigBase64);
        // Without a measurement, Meta gets h2 only: its QUIC times out in mainland China.
        const { alpn, why } = alpnFor(question.name, ["h2"]);
        if (metaEch) transformed = injectEchBytes(transformed, metaEch, alpn);
        notes?.push(`Meta ECH: ${override === null ? "suspended by the prober, not injected" : override ? "learned key injected" : metaEch ? "seed key injected" : "no valid seed configured"}; ALPN ${alpn?.join(",")} (${why})`);
      } else {
        if (await classify()) {
          const configured = validatedEchConfig(config.echConfigBase64);
          const ech = configured ?? await resolveEchConfig(options.echDomain ?? config.echSourceDomain, config, cache);
          // Without a measurement, X hosts get h2 only (X's zone rejects QUIC+ECH) and other
          // Cloudflare sites keep whatever ALPN their own record published.
          const { alpn, why } = alpnFor(question.name, multiCdn ? ["h2"] : undefined);
          transformed = injectEchBytes(transformed, ech, alpn);
          if (siteIps.length > 0) transformed = pinHttpsHints(transformed, siteIps);
          notes?.push(`Cloudflare ECH injected (${ech.length}B); ALPN ${alpn ? alpn.join(",") : "as published upstream"} (${why})${siteIps.length > 0 ? `; hints pinned to the site pool` : ""}`);
        } else {
          notes?.push("not on Cloudflare: no ECH injected");
        }
      }
    } catch (error) {
      notes?.push(`ECH injection failed: ${errorMessage(error)}`);
      if (config.debug) console.warn(JSON.stringify({ event: "ech_injection_error", message: errorMessage(error) }));
    }
  }
  if (question.type === DnsType.A || question.type === DnsType.AAAA || question.type === DnsType.HTTPS) {
    // Every answer type of an ECH host must sit at one canonical name, or Chromium drops the ECH
    // config (see flattenAliases). ECH hosts: Cloudflare-served (by address or X classification),
    // Meta, and explicitly configured ECH domains. Judged on the upstream addresses: the preferred
    // pool the answer was rewritten to need not fall inside the published Cloudflare ranges.
    const addresses = {
      ipv4: originalResponse.answers.flatMap((record) => (record.rdata.kind === "a" ? [record.rdata.address] : [])),
      ipv6: originalResponse.answers.flatMap((record) => (record.rdata.kind === "aaaa" ? [record.rdata.address] : [])),
    };
    const echHost = config.echEnabled && (domainMatches(question.name, config.metaDomains) || domainMatches(question.name, config.echDomains));
    if (echHost || onCloudflare === true || (cloudflareRanges !== undefined && responseUsesCloudflare(addresses, cloudflareRanges))) {
      const before = transformed;
      transformed = flattenAliases(transformed);
      if (transformed !== before) notes?.push(`CNAME chain flattened: every record now sits at ${question.name} (Chromium needs this to use ECH)`);
    }
  }
  const responseWire = transformed === originalResponse ? result.packet : encodeDnsPacket(transformed);
  return { wire: patchTransactionId(responseWire, query.header.id), upstream: result.upstream };
}

const EXPLAIN_TYPES: Record<string, number> = { A: DnsType.A, AAAA: DnsType.AAAA, HTTPS: DnsType.HTTPS };
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * GET /explain?name=x.com[&type=A|AAAA|HTTPS] — what this server answers for a name and why.
 * For each type: the answer a client gets right now (from cache or upstream, exactly as /dns-query
 * would serve it) and the steps of a fresh resolution. With all three types it also says whether
 * Chromium will use ECH for the name. Read-only: nothing is written to the cache. Accepts the same
 * options as /dns-query (?cf=, ?ip4=, ...), so the answer matches that endpoint's configuration.
 */
async function handleExplain(request: Request, env: Env, runtime: RequestRuntime): Promise<Response> {
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  const url = new URL(request.url);
  const name = (url.searchParams.get("name") ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!HOSTNAME.test(name)) return new Response("name must be a hostname, e.g. ?name=x.com", { status: 400 });
  const typeParam = url.searchParams.get("type")?.toUpperCase();
  if (typeParam && !(typeParam in EXPLAIN_TYPES)) return new Response("type must be A, AAAA or HTTPS", { status: 400 });
  const types = typeParam ? [EXPLAIN_TYPES[typeParam]!] : Object.values(EXPLAIN_TYPES);

  const setup = await prepareDns(request, env, runtime);
  if (setup instanceof Response) return setup;
  const results = await Promise.all(types.map(async (type) => {
    const query: DnsPacket = {
      header: { id: 0x4558, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
      questions: [{ name, type, class: 1 }],
      answers: [], authorities: [], additionals: [],
    };
    const label = dnsTypeName(type);
    if (shouldBlock(setup.rules, query)) return { type: label, blocked: true, packet: undefined };
    const plan = planQuery(query, setup);
    const cached = await readCache(setup.cache, plan.identity, setup.config);
    const notes: string[] = [];
    let fresh: DnsPacket | undefined;
    let error: string | undefined;
    try {
      const resolved = await resolveFresh(query, plan.upstreamQuery, plan.useEcs, setup.rules, setup.options, setup.config, setup.cache, notes);
      fresh = parseDnsPacket(resolved.wire);
    } catch (caught) {
      error = errorMessage(caught);
    }
    const served = cached && servesFromCache(cached, type) ? cached : undefined;
    const fromCache = served !== undefined;
    const packet = served ? parseDnsPacket(served.packet) : fresh;
    return {
      type: label,
      ecs: plan.ecsIdentity ?? null,
      cache: cached?.state ?? "none",
      servedFrom: fromCache ? "cache" : fresh ? "upstream" : "none",
      answer: packet ? describeAnswers(packet) : [],
      ...(fromCache && fresh ? { freshAnswer: describeAnswers(fresh) } : {}),
      steps: notes,
      ...(error ? { error } : {}),
      packet,
    };
  }));

  const byType = new Map(results.map((result) => [result.type, result.packet]));
  const [a, aaaa, https] = [byType.get("A"), byType.get("AAAA"), byType.get("HTTPS")];
  return json({
    name,
    clientIp: setup.ip ?? null,
    pool: { ipv4: setup.config.cfPreferredIpv4, ipv6: setup.config.cfPreferredIpv6, scope: setup.scope ?? "default" },
    results: results.map(({ packet: _packet, ...rest }) => rest),
    chromium: a && aaaa && https ? chromiumEchVerdict(a, aaaa, https) : null,
    selfcheck: selfCheckStatus(),
  });
}

/** Network prefix (/24 IPv4, /48 IPv6) that scoped learned pools are keyed by. */
function clientScopeKey(ip: string | undefined): string | undefined {
  return ip ? makeEcsValue(ip, 24, 48)?.identity : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function logQuery(config: ReturnType<typeof readConfig>, packet: DnsPacket, cache: "hit" | "miss" | "prefetch" | "stale", upstream: string | undefined, latency: number): void {
  if (!config.debug) return;
  const question = packet.questions[0];
  console.log(JSON.stringify({
    event: "dns_query",
    ...(config.logQueries && question ? { qname: question.name, qtype: question.type } : {}),
    cache,
    upstream: upstream ? new URL(upstream).hostname : undefined,
    latency_ms: latency,
  }));
}

export async function handleRequest(request: Request, env: Env, ctx: WaitUntilContext, runtime: RequestRuntime): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/health") return request.method === "GET" ? json({ ok: true }) : new Response("Method not allowed", { status: 405 });
  if (url.pathname === "/probe") {
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });
    return json({ ok: true, ...runtime.probe(request), timestamp: new Date().toISOString() });
  }
  if (url.pathname === "/admin/preferred") return handleAdminPreferred(request, env, runtime);
  if (url.pathname === "/admin/github") return handleAdminGithub(request, env);
  if (url.pathname === "/admin/site") return handleAdminSite(request, env);
  if (url.pathname === "/admin/health") return handleAdminHealth(request, env);
  if (url.pathname === "/admin/selfcheck") return handleAdminSelfCheck(request, env);
  if (url.pathname === "/admin/h3") return handleAdminH3(request, env);
  if (url.pathname === "/explain") return handleExplain(request, env, runtime);
  if (url.pathname !== "/dns-query") return new Response("Not found", { status: 404 });
  return handleDns(request, env, ctx, runtime);
}

/**
 * Out-of-band preferred-IP feed. A prober inside the target network (work/echprobe -rank)
 * POSTs {ipv4:[], ipv6:[], ttl} with a bearer token; the list overrides the default domain
 * pool until it expires. GET reports the current state.
 */
function bearerToken(request: Request): string | null {
  const auth = request.headers.get("Authorization") ?? "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
}

async function adminAuth(request: Request, env: Env): Promise<Response | undefined> {
  const config = readConfig(env);
  if (!config.adminToken) return new Response("Not found", { status: 404 });
  if (!(await timingSafeTokenMatches(bearerToken(request), config.adminToken))) return new Response("Unauthorized", { status: 401 });
  return undefined;
}

/** Who is calling /admin/preferred: the admin (everything) or the probe hub (operator pools only). */
async function preferredAuth(request: Request, env: Env): Promise<"admin" | "hub" | Response> {
  const config = readConfig(env);
  if (!config.adminToken && !config.hubToken) return new Response("Not found", { status: 404 });
  const provided = bearerToken(request);
  if (await timingSafeTokenMatches(provided, config.adminToken)) return "admin";
  if (await timingSafeTokenMatches(provided, config.hubToken)) return "hub";
  return new Response("Unauthorized", { status: 401 });
}

function adminState(): Record<string, unknown> {
  return { learned: learnedPoolStatus() ?? null, scoped: scopedPoolStatus(), isp: ispPoolStatus(), github: githubPoolStatus() ?? null, sites: sitePoolStatus() ?? null, metaEch: metaEchStatus() ?? null, selfcheck: selfCheckStatus(), h3: h3Status() };
}

/**
 * Per-host GitHub preferred-IP feed. A prober (work/echprobe -github) POSTs {source, ttl,
 * hosts: {"github.com": ["140.82.116.4", ...], ...}} — the IPs it verified reachable from inside the
 * GFW for each host. Answers for those hosts are pinned to the merged pool. GET reports the state.
 */
async function handleAdminGithub(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method === "GET") return json({ ok: true, github: githubPoolStatus() ?? null });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  const report = await readHostReport(request);
  if (report instanceof Response) return report;
  const { source, ttl, hosts } = report;
  if (Object.keys(hosts).length === 0) return new Response("no hosts with IPs", { status: 400 });
  setGithubPools(source, hosts, ttl);
  console.log(JSON.stringify({ event: "github_pools_updated", source, hosts: Object.keys(hosts).length, ttl }));
  return json({ ok: true, github: githubPoolStatus() ?? null });
}

/**
 * Per-site pools (see setSitePools). A site-check prober (work/echprobe -sitecheck) POSTs {source,
 * ttl, hosts: {"linux.do": ["162.159.157.114", ...]}} listing only the sites whose origin hangs
 * through the general pool from its line, each with IPs it verified end to end. Every run reports, so
 * an empty `hosts` withdraws that source's earlier overrides once the general pool works again.
 */
async function handleAdminSite(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method === "GET") return json({ ok: true, sites: sitePoolStatus() ?? null });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  const report = await readHostReport(request);
  if (report instanceof Response) return report;
  const { source, ttl, hosts } = report;
  setSitePools(source, hosts, ttl);
  console.log(JSON.stringify({ event: "site_pools_updated", source, hosts: Object.keys(hosts), ttl }));
  return json({ ok: true, sites: sitePoolStatus() ?? null });
}

/** Body of a per-host pool report: {source, ttl, hosts: {hostname: [IPv4]}}; hosts without IPs are left out. */
async function readHostReport(request: Request): Promise<{ source: string; ttl: number; hosts: Record<string, string[]> } | Response> {
  let body: { source?: unknown; ttl?: unknown; hosts?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  if (typeof body.hosts !== "object" || body.hosts === null || Array.isArray(body.hosts)) {
    return new Response("hosts must be an object of hostname → IPv4 array", { status: 400 });
  }
  const hosts: Record<string, string[]> = {};
  for (const [host, ips] of Object.entries(body.hosts)) {
    const name = host.toLowerCase().replace(/\.$/, "");
    if (!HOSTNAME.test(name)) return new Response(`invalid hostname ${host.slice(0, 80)}`, { status: 400 });
    if (!Array.isArray(ips)) return new Response(`hosts[${name}] must be an array`, { status: 400 });
    const clean = ips.filter((ip): ip is string => typeof ip === "string").slice(0, MAX_REPORTED_IPS);
    try {
      for (const ip of clean) parseIpv4(ip);
    } catch {
      return new Response(`hosts[${name}] has a non-IPv4 address`, { status: 400 });
    }
    if (clean.length > 0) hosts[name] = clean;
  }
  const source = typeof body.source === "string" ? body.source.slice(0, 64) : "unknown";
  const ttl = typeof body.ttl === "number" && Number.isFinite(body.ttl) ? Math.max(60, Math.min(86400, body.ttl)) : 3600;
  return { source, ttl, hosts };
}


/** Prober QUIC+ECH verdicts: {source, ttl, verdicts: {"linux.do": true, "x.com": false}}. */
async function handleAdminH3(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method === "GET") return json({ ok: true, h3: h3Status() });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  let body: { source?: unknown; ttl?: unknown; verdicts?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  if (typeof body.verdicts !== "object" || body.verdicts === null || Array.isArray(body.verdicts)) {
    return new Response("verdicts must be an object of hostname → boolean", { status: 400 });
  }
  const verdicts: Record<string, boolean> = {};
  for (const [host, ok] of Object.entries(body.verdicts)) {
    const name = host.toLowerCase().replace(/\.$/, "");
    if (!HOSTNAME.test(name) || typeof ok !== "boolean") return new Response(`invalid verdict for ${host.slice(0, 80)}`, { status: 400 });
    verdicts[name] = ok;
  }
  const source = typeof body.source === "string" ? body.source.slice(0, 64) : "unknown";
  const ttl = typeof body.ttl === "number" && Number.isFinite(body.ttl) ? Math.max(300, Math.min(86400, body.ttl)) : 5400;
  setH3Verdicts(source, verdicts, ttl);
  console.log(JSON.stringify({ event: "h3_verdicts_updated", source, verdicts, ttl }));
  return json({ ok: true, h3: h3Status() });
}

/** Prober self-check result: {source, ok, problems: string[], hosts}. Shown by /explain and admin GETs. */
async function handleAdminSelfCheck(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method === "GET") return json({ ok: true, selfcheck: selfCheckStatus() });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  let body: { source?: unknown; ok?: unknown; problems?: unknown; hosts?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  if (typeof body.ok !== "boolean") return new Response("ok must be a boolean", { status: 400 });
  const problems = Array.isArray(body.problems) ? body.problems.filter((item): item is string => typeof item === "string") : [];
  const source = typeof body.source === "string" ? body.source.slice(0, 64) : "unknown";
  const hosts = typeof body.hosts === "number" && Number.isFinite(body.hosts) ? body.hosts : 0;
  const report = setSelfCheck(source, body.ok, problems, hosts);
  if (!report.ok) console.error(JSON.stringify({ event: "selfcheck_failed", source, problems: report.problems }));
  return json({ ok: true, selfcheck: selfCheckStatus() });
}

/**
 * Prober-reported health for Meta ECH.
 *   {metaEch:"ok"}                                  → configured seed works; clear any override
 *   {metaEch:"rotated", echConfig:<base64>, ttl}     → seed rejected, server's retry_configs recovered; inject this instead
 *   {metaEch:"broken", ttl, reason}                  → seed rejected and no usable key recovered; stop injecting
 */
async function handleAdminHealth(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method === "GET") return json({ ok: true, ...adminState() });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  let body: { metaEch?: unknown; echConfig?: unknown; verified?: unknown; ttl?: unknown; source?: unknown; reason?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const source = typeof body.source === "string" ? body.source : "unknown";
  const reason = typeof body.reason === "string" ? body.reason : "";
  const ttl = typeof body.ttl === "number" && Number.isFinite(body.ttl) ? Math.max(300, Math.min(604800, body.ttl)) : 86400;
  switch (body.metaEch) {
    case "ok": {
      const override = metaEchOverride();
      if (override instanceof Uint8Array) {
        // A learned key was verified: renew it instead of falling back to the (possibly dead) seed.
        const verified = typeof body.verified === "string" ? validatedEchConfig(body.verified) : undefined;
        if (verified && verified.length === override.length && verified.every((byte, index) => byte === override[index])) {
          setMetaEch(override, ttl, source, "renewed");
          break;
        }
      }
      if (override !== undefined) console.log(JSON.stringify({ event: "meta_ech_seed_ok", source }));
      clearMetaEch();
      break;
    }
    case "rotated": {
      const learned = typeof body.echConfig === "string" ? validatedEchConfig(body.echConfig) : undefined;
      if (!learned) return new Response("echConfig must be a valid base64 ECHConfigList", { status: 400 });
      setMetaEch(learned, ttl, source, reason);
      console.warn(JSON.stringify({ event: "meta_ech_rotated", source, bytes: learned.length, ttl }));
      break;
    }
    case "broken":
      setMetaEch(undefined, Math.min(ttl, 86400), source, reason);
      console.error(JSON.stringify({ event: "meta_ech_suspended", source, reason: reason.slice(0, 200), ttl }));
      break;
    default:
      return new Response("metaEch must be \"ok\", \"rotated\" or \"broken\"", { status: 400 });
  }
  return json({ ok: true, ...adminState() });
}

const MAX_REPORTED_IPS = 64;

async function handleAdminPreferred(request: Request, env: Env, runtime: RequestRuntime): Promise<Response> {
  const role = await preferredAuth(request, env);
  if (role instanceof Response) return role;
  const hubOnly = "The hub token may only write operator pools (POST with scope \"isp:<name>\")";
  if (request.method === "GET") return role === "admin" ? json({ ok: true, ...adminState() }) : new Response(hubOnly, { status: 403 });
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  let body: { ipv4?: unknown; ipv6?: unknown; ttl?: unknown; source?: unknown; scope?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []);
  // Probers report every IP that passed (up to this many), not just their fastest few: with three
  // probers, a line where dozens of IPs tie within a few ms cut its list at 16 almost at random, and
  // the IPs every prober vouches for (see combineRankings) dropped to one.
  const ipv4 = strings(body.ipv4).slice(0, MAX_REPORTED_IPS);
  const ipv6 = strings(body.ipv6).slice(0, MAX_REPORTED_IPS);
  if (ipv4.length === 0 && ipv6.length === 0) return new Response("ipv4 or ipv6 required", { status: 400 });
  const ttl = typeof body.ttl === "number" && Number.isFinite(body.ttl) ? Math.max(60, Math.min(86400, body.ttl)) : 3600;
  const source = typeof body.source === "string" ? body.source.slice(0, 64) : "unknown";
  // "client" scopes the pool to the reporter's own network prefix: the prober measured from that
  // line, so its result is only authoritative for clients on it.
  let scope: string | undefined;
  if (body.scope === "client") {
    scope = clientScopeKey(await runtime.clientIp(request, env));
    if (!scope) return new Response("Cannot determine the reporting client's address for a client-scoped pool", { status: 400 });
  } else if (typeof body.scope === "string" && body.scope.startsWith("isp:")) {
    // An operator's pool, aggregated by the probe hub (work/cfhub) from volunteer probers.
    if (!isIspName(body.scope.slice(4))) return new Response("Invalid operator name", { status: 400 });
    scope = body.scope;
  } else if (body.scope !== undefined && body.scope !== "default") {
    return new Response("scope must be \"default\", \"client\" or \"isp:<name>\"", { status: 400 });
  }
  const operatorPool = scope?.startsWith("isp:") === true;
  if (role === "hub" && !operatorPool) return new Response(hubOnly, { status: 403 });
  if (operatorPool) {
    // Operator pools come from untrusted volunteers (checked by the hub too): only Cloudflare's own
    // published addresses, so a poisoned report cannot steer clients to a host someone else controls.
    let ranges;
    try {
      ranges = await loadCloudflareRanges(readConfig(env), await caches.open("edge-smart-doh-v1"));
    } catch (error) {
      return new Response(`Cloudflare ranges unavailable: ${errorMessage(error)}`, { status: 503 });
    }
    const outside = [...ipv4.filter((ip) => !inAnyCidr(ip, ranges.ipv4)), ...ipv6.filter((ip) => !inAnyCidr(ip, ranges.ipv6))];
    if (outside.length > 0) return new Response(`Not Cloudflare addresses: ${outside.slice(0, 8).join(", ")}`, { status: 400 });
  }
  try {
    const pool = setLearnedPool(ipv4, ipv6, ttl, source, scope);
    console.log(JSON.stringify({ event: "preferred_pool_updated", source, scope: scope ?? "default", ipv4: pool.ipv4.length, ipv6: pool.ipv6.length, ttl }));
    if (role === "hub") return json({ ok: true, scope, ipv4: pool.ipv4.length, ipv6: pool.ipv6.length, expiresAt: pool.expiresAt });
    return json({ ok: true, scope: scope ?? "default", ...adminState() });
  } catch (error) {
    return new Response(`Invalid address: ${errorMessage(error)}`, { status: 400 });
  }
}

const cloudflareRuntime: RequestRuntime = {
  clientIp: (request, env) => cloudflareClientIp(request, env, readConfig(env).edgeOneClientIpHeader),
  probe(request) {
    const cf = request.cf;
    return { provider: "cloudflare", colo: cf?.colo, country: cf?.country, asn: cf?.asn, httpProtocol: cf?.httpProtocol };
  },
};

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx, cloudflareRuntime);
  },
} satisfies ExportedHandler<Env>;
