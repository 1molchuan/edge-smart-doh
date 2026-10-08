import { normalizedCacheIdentity, readCache, rotateAddressRecords, writeCache, type CacheHit, type CacheIdentity } from "./cache";
import { inAnyCidr } from "./cidr";
import { readConfig, type AppConfig } from "./config";
import { addEcs, clientEcsValue, domainMatches, ecsSourceIp, makeEcsValue, readClientEcs, removeEcs, shouldUseEcs } from "./dns/ecs";
import { fitEdns } from "./dns/edns";
import { encodeDnsPacket, makeBadvers, makeServfail, matchQuestionCase, parseDnsPacket, parseIpv4, patchTransactionId } from "./dns/packet";
import { DnsType, type DnsPacket } from "./dns/types";
import { chromiumEchVerdict, describeAnswers, dnsTypeName, selfCheckStatus, setSelfCheck } from "./explain";
import { h3Status, setH3Verdicts } from "./h3";
import { isIspName, ispScopeOf, ispTableReady, loadIspTable, onOperatorNetwork } from "./isp";
import { recordQuery, statsSnapshot } from "./metrics";
import { applyResponseRules, ecsOverride, loadRules, shouldBlock, type RuleSet } from "./rules";
import { parseRequestOptions, type RequestOptions } from "./request-options";
import { clearMetaEch, githubPoolFor, githubPoolStatus, githubReports, ispPoolStatus, learnedPoolStatus, metaEchOverride, metaEchStatus, preferredPool, scopedPoolStatus, setGithubPools, setLearnedPool, setMetaEch, setSitePools, sitePoolFor, sitePoolStatus, siteReports } from "./preferred";
import { loadCloudflareRanges, validatedEchConfig } from "./rewrite";
import { describePlan, makePlan, sortStrategies, strategyCacheTags, type RoutePlan } from "./plan";
import { isLanClientAddress, parseRelayDomainPattern, relayOverrideSnapshot, relayStatus, setRelayHealth, setRelayOverride } from "./relay";
import { renderPlan } from "./render";
import { PUBLIC_STRATEGIES } from "./strategies";
import { queryUpstreams, upstreamLabel } from "./upstream";
import { safeBlocked, safeBlockedResponse, safeStatus } from "./safe";
import { chineseSiteStatus, isDomesticSite } from "./cn-domains";

const DNS_CONTENT_TYPE = "application/dns-message";
const STRATEGIES = sortStrategies(PUBLIC_STRATEGIES);

/** `query`, when given, is the client's wire query: its question spelling is restored in the answer. */
function dnsResponse(packet: Uint8Array, query?: Uint8Array, status = 200): Response {
  let body = packet;
  try {
    body = rotateAddressRecords(packet);
  } catch {
    // A packet we cannot re-encode (unknown RDATA with compression) is served as-is.
  }
  if (query) body = matchQuestionCase(body, query);
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

/** An answer-less response with `rcode`: 1 FORMERR, 3 NXDOMAIN. */
function rcodeResponse(query: DnsPacket, rcode: number): Uint8Array {
  return encodeDnsPacket({
    header: { ...query.header, flags: 0x8000 | (query.header.flags & 0x7910) | 0x0080 | rcode },
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
  /**
   * Whether the client address is on the LAN (relay gate, see relay.ts): resolved once here so every
   * later decision — cache variant included — sees the same answer. False for a missing or
   * unparsable address, which is the safe side.
   */
  lan: boolean;
  /** The address ECS is built from: the client's, ECS_FALLBACK_SUBNET for a client outside every operator, or none (non-routable client). */
  ecsIp?: string;
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
  // The operator matters for the server default pool and for the ECS fallback.
  const ispScope = options.cfDomainIsDefault === true || config.ecsFallbackSubnet ? await ispScopeOf(ip, config, cache) : undefined;
  const ecsIp = ecsSourceIp(ip, config.ecsFallbackSubnet, ispTableReady() && ispScope === undefined);
  try {
    preferred = await preferredPool(
      { ipv4: options.preferredIpv4, ipv6: options.preferredIpv6 },
      options.cfDomains,
      options.cfDomainIsDefault === true,
      config,
      cache,
      clientScopeKey(ip),
      options.cfDomainIsDefault === true ? ispScope : undefined,
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
  return { config, options, cache, ip, lan: isLanClientAddress(ip), ecsIp, scope: preferred.scope, rules };
}

/** ECS decision and cache key for one query. */
function planQuery(query: DnsPacket, setup: DnsSetup): { upstreamQuery: DnsPacket; useEcs: boolean; useCn: boolean; ecsIdentity?: string; identity: CacheIdentity } {
  const { config, options, rules, ecsIp } = setup;
  // A client that sent ECS with source prefix 0 asked that no subnet be passed on (RFC 7871 §7.1.2);
  // one that sent a subnet gets that subnet used; otherwise the server picks it from the client address.
  // (A malformed one never gets here: handleDns answers it FORMERR.)
  const client = readClientEcs(query);
  const ecs = client
    ? clientEcsValue(client, config.ecsIpv4Prefix, config.ecsIpv6Prefix)
    : ecsIp ? makeEcsValue(ecsIp, config.ecsIpv4Prefix, config.ecsIpv6Prefix) : undefined;
  // A domestic name goes to the direct CN resolvers when configured — no ECS: dialed from inside
  // China, they see the client's own operator by source IP, which is finer than any ECS /24.
  // Otherwise a rule decides first, and in rules mode the domestic lists add to ECS_DOMAINS.
  const domestic = isDomesticSite(query.questions[0]!.name, config);
  const useCn = domestic && config.cnUpstreams.length > 0;
  const override = ecsOverride(rules, query) ?? (config.ecsMode === "rules" && domestic ? true : undefined);
  const useEcs = !useCn && ecs ? shouldUseEcs(query, config, override) : false;
  const upstreamQuery = useEcs && ecs ? addEcs(query, ecs) : removeEcs(query);
  const question = query.questions[0]!;
  const variant = options.cacheVariant + strategyCacheTags(STRATEGIES, { config, options, scope: setup.scope, lan: setup.lan, name: question.name, type: question.type });
  const ecsIdentity = useEcs && ecs ? ecs.identity : undefined;
  return { upstreamQuery, useEcs, useCn, ecsIdentity, identity: normalizedCacheIdentity(query, useCn ? "cn" : ecsIdentity ?? "none", variant) };
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
  // RFC 6891 §6.1.1: more than one OPT record is FORMERR (below); one with a version above 0, BADVERS.
  const opts = query.additionals.filter((record) => record.type === DnsType.OPT);
  if (opts.length === 1 && ((opts[0]!.ttl >>> 16) & 0xff) !== 0) return dnsResponse(makeBadvers(query), wire);
  const client = readClientEcs(query);
  // Every answer, cached or not, leaves with an OPT record made for this query (dns/edns.ts).
  const reply = (packet: Uint8Array): Response => {
    let body = packet;
    try {
      body = fitEdns(packet, query, client ?? undefined);
    } catch {
      // A packet we cannot re-encode is served as-is.
    }
    return dnsResponse(body, wire);
  };
  if (opts.length > 1 || client === null) return reply(rcodeResponse(query, 1));

  const setup = await prepareDns(request, env, runtime);
  if (setup instanceof Response) return setup;
  const { config, options, cache, rules } = setup;
  const question = query.questions[0]!;
  const sample = () => ({ name: question.name, type: dnsTypeName(question.type), latencyMs: Date.now() - started });
  if (shouldBlock(rules, query)) {
    recordQuery({ ...sample(), outcome: "blocked" });
    return reply(rcodeResponse(query, 3));
  }
  // Blocked before the cache: every other answer is the same with or without ?safe=1, so they share it.
  if (options.safe && safeBlocked(question.name, config)) {
    recordQuery({ ...sample(), outcome: "blocked" });
    return reply(encodeDnsPacket(safeBlockedResponse(query)));
  }

  const { upstreamQuery, useEcs, useCn, identity } = planQuery(query, setup);
  const cached = await readCache(cache, identity, config);

  const resolveAndStore = async (): Promise<{ wire: Uint8Array; upstream: string; plan: RoutePlan }> => {
    const resolved = await resolveFresh(query, upstreamQuery, useEcs, useCn, rules, options, config, cache, setup.lan);
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
    const outcome = cached.state === "fresh" ? "hit" : cached.state === "refresh" ? "prefetch" : "stale";
    recordQuery({ ...sample(), outcome });
    logQuery(config, query, outcome, undefined, Date.now() - started);
    return reply(cached.packet);
  }

  try {
    const resolved = await resolveAndStore();
    recordQuery({ ...sample(), outcome: "miss", upstream: upstreamLabel(resolved.upstream), strategy: resolved.plan.strategy, path: pathCategory(resolved.plan, useCn) });
    logQuery(config, query, "miss", resolved.upstream, Date.now() - started);
    return reply(resolved.wire);
  } catch (error) {
    console.error(JSON.stringify({ event: "upstream_failure", message: errorMessage(error) }));
    if (cached) {
      // RFC 8767: an expired answer beats SERVFAIL when every upstream is unreachable.
      recordQuery({ ...sample(), outcome: "stale", error: errorMessage(error) });
      logQuery(config, query, "stale", undefined, Date.now() - started);
      return reply(cached.packet);
    }
    recordQuery({ ...sample(), outcome: "error", error: errorMessage(error), servfail: true });
    logQuery(config, query, "miss", undefined, Date.now() - started);
    return reply(makeServfail(wire));
  }
}

/**
 * The path rollup for /admin/stats (see metrics.ts QueryPath). Judged on the rendered plan, so
 * "preferred-ip" only counts when the rewrite actually changed the answer (render.ts renames the
 * strategy then) and ECH counts even when a pool strategy had claimed the label first.
 */
function pathCategory(plan: RoutePlan, useCn: boolean): "relay" | "ech" | "pool" | "cn" | "direct" {
  if (plan.strategy === "relay") return "relay";
  if (plan.ech) return "ech";
  if (useCn) return "cn";
  if (plan.pin || plan.xPool || plan.strategy === "preferred-ip") return "pool";
  return "direct";
}

/**
 * Whether an answer for a domestic name looks like the mainland view: it has no addresses, or at least
 * one is on a mainland operator's network (or no operator table is loaded to tell). Some sites' name
 * servers answer by the asking resolver's location and ignore ECS, and a public resolver queried from
 * Hong Kong may look names up from there: CNKI then sends kns.cnki.net to oversea.cnki.net, its
 * international site, whose logins are not the domestic site's (2026-10-07). AliDNS looks names up
 * from Hong Kong, DNSPod from the mainland, so such an answer waits for another ECS upstream.
 */
function domesticView(answer: DnsPacket): boolean {
  let addresses = 0;
  for (const record of answer.answers) {
    if (record.rdata.kind !== "a" && record.rdata.kind !== "aaaa") continue;
    addresses += 1;
    if (onOperatorNetwork(record.rdata.address) !== false) return true;
  }
  return addresses === 0;
}

/**
 * Asks upstream, then lets the strategies decide how the name is reached (plan.ts) and applies that
 * plan to the answer (render.ts). `notes`, when given, collects one line per decision for /explain.
 */async function resolveFresh(
  query: DnsPacket,
  upstreamQuery: DnsPacket,
  useEcs: boolean,
  useCn: boolean,
  rules: RuleSet,
  options: RequestOptions,
  config: AppConfig,
  cache: Cache,
  lan: boolean,
  notes?: string[],
): Promise<{ wire: Uint8Array; upstream: string; plan: RoutePlan }> {
  const upstreamWire = encodeDnsPacket(upstreamQuery);
  if (useEcs) await loadIspTable(config, cache); // domesticView needs it
  // A name whose servers answer by the resolver's location only takes the first ECS upstream's answer
  // (configured to be one that looks names up from the mainland): its overseas view need not have
  // an overseas address (CNKI's www goes through EdgeOne's mainland nodes, cnki.net to a Beijing server).
  const resolverView = useEcs && domainMatches(query.questions[0]!.name, config.resolverViewDomains);
  const acceptable = resolverView ? (_answer: DnsPacket, entry: number) => entry === 0 : domesticView;
  const result = await queryUpstreams(upstreamWire, config, { ecs: useEcs, cn: useCn, ...(useEcs ? { acceptable } : {}) });
  const originalResponse = parseDnsPacket(result.packet);
  if (originalResponse.header.id !== upstreamQuery.header.id) throw new Error("Upstream transaction ID mismatch");
  if (notes) {
    if (useCn) notes.push("domestic name: resolved through the direct CN upstreams (no ECS — the resolver sees the client's operator by source IP)");
    if (resolverView) notes.push("RESOLVER_VIEW_DOMAINS: only the first ECS upstream's answer is taken, over its budget if need be");
    else if (useEcs && !domesticView(originalResponse)) notes.push("no address in the answer is on a mainland network, from any ECS upstream that answered (the overseas view, or a site hosted abroad)");
    const answers = describeAnswers(originalResponse);
    notes.push(`upstream ${result.label}${useEcs ? " (with ECS)" : ""}: rcode ${originalResponse.header.flags & 0x0f}, ${answers.length > 0 ? answers.join("; ") : "no answers"}`);
  }
  const ruled = applyResponseRules(rules, query, originalResponse);
  if (ruled !== originalResponse) notes?.push("response rules changed the answer");
  const { plan, ctx } = await makePlan(STRATEGIES, { config, options, query, rules, cache, lan, notes });
  const transformed = renderPlan(plan, ctx, config, originalResponse, ruled);
  const responseWire = transformed === originalResponse ? result.packet : encodeDnsPacket(transformed);
  return { wire: patchTransactionId(responseWire, query.header.id), upstream: result.upstream, plan };
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
    const safeMatch = setup.options.safe ? safeBlocked(name, setup.config) : undefined;
    if (safeMatch) return { type: label, blocked: true, steps: [`blocked by ?safe=1: ${safeMatch} is on the block lists (NXDOMAIN)`], packet: undefined };
    const plan = planQuery(query, setup);
    const cached = await readCache(setup.cache, plan.identity, setup.config);
    const notes: string[] = [];
    let fresh: DnsPacket | undefined;
    let routePlan: Record<string, unknown> | undefined;
    let error: string | undefined;
    try {
      const resolved = await resolveFresh(query, plan.upstreamQuery, plan.useEcs, plan.useCn, setup.rules, setup.options, setup.config, setup.cache, setup.lan, notes);
      fresh = parseDnsPacket(resolved.wire);
      routePlan = describePlan(resolved.plan);
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
      ...(routePlan ? { plan: routePlan } : {}),
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
    // Why the relay did or did not apply for this client: the LAN gate is unconditional by design
    // (relay.ts / DESIGN.md §2.1.1), so this one boolean is the whole story. Informational only.
    lan: setup.lan,
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
  if (url.pathname === "/admin/relay") return handleAdminRelay(request, env);
  if (url.pathname === "/admin/relay-config") return handleAdminRelayConfig(request, env);
  if (url.pathname === "/admin/relay-health") return handleAdminRelayHealth(request, env);
  if (url.pathname === "/admin/pool") return handleAdminPool(request, env);
  if (url.pathname === "/admin/health") return handleAdminHealth(request, env);
  if (url.pathname === "/admin/selfcheck") return handleAdminSelfCheck(request, env);
  if (url.pathname === "/admin/h3") return handleAdminH3(request, env);
  if (url.pathname === "/admin/stats") return handleAdminStats(request, env);
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

function adminState(config: AppConfig): Record<string, unknown> {
  return { learned: learnedPoolStatus() ?? null, scoped: scopedPoolStatus(), isp: ispPoolStatus(), github: githubPoolStatus() ?? null, sites: sitePoolStatus() ?? null, safe: safeStatus() ?? null, chineseSites: chineseSiteStatus() ?? null, metaEch: metaEchStatus() ?? null, relay: relayStatus(config), selfcheck: selfCheckStatus(), h3: h3Status() };
}

/**
 * Live operational metrics for the LAN monitor (contrib/home/monitor): query counters, cache mix,
 * upstream latency and the pool state. Same bearer token as the other admin endpoints; the recent
 * list carries query names, so it must never be exposed without one.
 */
async function handleAdminStats(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  return json({
    ok: true,
    ...statsSnapshot(),
    pools: adminState(readConfig(env)),
    ...(typeof process !== "undefined" && typeof process.memoryUsage === "function" ? { memory: { rssBytes: process.memoryUsage().rss } } : {}),
  });
}

/**
 * Per-host GitHub preferred-IP feed. A prober (work/echprobe -github) POSTs {source, ttl,
 * hosts: {"github.com": ["140.82.116.4", ...], ...}} — the IPs it verified reachable from inside the
 * GFW for each host. Answers for those hosts are pinned to the merged pool. GET reports the state.
 */
async function handleAdminGithub(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  // ?detail=1 adds every live report as posted, for deploy/restart-keep-state.sh to post back.
  if (request.method === "GET") return json({ ok: true, github: githubPoolStatus() ?? null, ...(new URL(request.url).searchParams.get("detail") === "1" ? { reports: githubReports() } : {}) });
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
  if (request.method === "GET") return json({ ok: true, sites: sitePoolStatus() ?? null, ...(new URL(request.url).searchParams.get("detail") === "1" ? { reports: siteReports() } : {}) });
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


/**
 * SNI relay state (contrib/home/relay): GET reports liveness and the per-host decisions; the relay
 * daemon POSTs its self-check verdict {source, ttl, healthy[, direct]} so the server can withdraw
 * the override the moment the relay or the egress proxy dies. The health response carries the
 * effective domain lists so the daemon can pick console edits without a restart. State is in relay.ts.
 */
async function handleAdminRelay(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  return json({ ok: true, relay: relayStatus(readConfig(env)) });
}

/**
 * The console's control plane: overrides RELAY_MODE / RELAY_DOMAINS / RELAY_EXCLUDE_DOMAINS and the
 * forced pool's RELAY_FORCED_MODE / RELAY_FORCED_DOMAINS at runtime. A change takes effect on the
 * next resolution (the relay cache tag re-keys answers), is persisted by the Node server across
 * restarts, and is pushed to the relay daemon through the health-report response. `reset: true`
 * clears the override, returning to the env values. `expectedVersion` is the configVersion the
 * caller last saw: a mismatch means someone else changed the config in between and yields 409
 * rather than a silent last-write-wins.
 */
async function handleAdminRelayConfig(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method !== "GET" && request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  const config = readConfig(env);
  if (request.method === "GET") return json({ ok: true, relay: relayStatus(config) });
  let body: { mode?: unknown; domains?: unknown; excludeDomains?: unknown; forcedMode?: unknown; forcedDomains?: unknown; reset?: unknown; expectedVersion?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const current = relayStatus(config);
  if (typeof body.expectedVersion === "number" && Number.isFinite(body.expectedVersion) && body.expectedVersion !== current.configVersion) {
    return json({ ok: false, error: `config version mismatch: expected ${body.expectedVersion}, current ${current.configVersion}; refresh and retry`, configVersion: current.configVersion }, 409);
  }
  if (body.reset === true) {
    setRelayOverride(null, config);
    return json({ ok: true, changed: true, relay: relayStatus(config) });
  }
  const patch: { mode?: typeof config.relayMode; domains?: string[]; excludeDomains?: string[]; forcedMode?: typeof config.relayForcedMode; forcedDomains?: string[] } = {};
  if (body.mode !== undefined) {
    if (body.mode !== "off" && body.mode !== "auto" && body.mode !== "always") {
      return new Response("mode must be \"off\", \"auto\" or \"always\"", { status: 400 });
    }
    patch.mode = body.mode;
  }
  if (body.forcedMode !== undefined) {
    // The forced pool has no measurement loop, so "auto" is not a value it can honor.
    if (body.forcedMode !== "off" && body.forcedMode !== "always") {
      return new Response("forcedMode must be \"off\" or \"always\" (the forced pool has no auto: its names have no measured pool to judge them by)", { status: 400 });
    }
    patch.forcedMode = body.forcedMode;
  }
  // ECH names cannot go through the relay: the relay steers by reading SNI, and an ECH name's outer
  // SNI no longer points at the real target (the HTTPS cleanup would strip the ECH key anyway —
  // the entry is rejected so the operator notices before clients lose ECH, DESIGN.md §10).
  const echPatterns = [...(config.echEnabled ? config.echDomains : []), ...config.metaDomains, ...config.xDomains];
  const echConflicts = (patterns: string[]): string[] =>
    patterns.filter((entry) => echPatterns.some((ech) => domainMatches(entry.replace(/^\*\./, ""), [ech])));
  const readPatterns = (value: unknown, field: string): string[] | Response => {
    if (!Array.isArray(value)) return new Response(`${field} must be an array of domain patterns`, { status: 400 });
    if (value.length > 64) return new Response(`${field} is limited to 64 patterns`, { status: 400 });
    if (value.some((entry) => typeof entry !== "string")) return new Response(`${field} must contain only strings`, { status: 400 });
    const invalid = (value as string[]).filter((entry) => parseRelayDomainPattern(entry) === null);
    if (invalid.length > 0) {
      return new Response(`${field} has invalid entries (hostnames, optionally *.prefixed): ${invalid.slice(0, 3).join(", ")}`, { status: 400 });
    }
    const conflicts = echConflicts(value as string[]);
    if (conflicts.length > 0) {
      return new Response(`${field} entries conflict with ECH domains (the relay reads SNI, ECH encrypts it): ${conflicts.slice(0, 5).join(", ")}`, { status: 400 });
    }
    return [...new Set((value as string[]).map((entry) => parseRelayDomainPattern(entry)!))];
  };
  if (body.domains !== undefined) {
    const domains = readPatterns(body.domains, "domains");
    if (domains instanceof Response) return domains;
    patch.domains = domains;
  }
  if (body.excludeDomains !== undefined) {
    const excludes = readPatterns(body.excludeDomains, "excludeDomains");
    if (excludes instanceof Response) return excludes;
    patch.excludeDomains = excludes;
  }
  if (body.forcedDomains !== undefined) {
    const forced = readPatterns(body.forcedDomains, "forcedDomains");
    if (forced instanceof Response) return forced;
    patch.forcedDomains = forced;
  }
  if (Object.keys(patch).length === 0) return new Response("nothing to change: mode, domains, excludeDomains, forcedMode, forcedDomains or reset required", { status: 400 });
  // Turning the relay up needs a usable address; env typos must surface here rather than degrade silently.
  const nextMode = patch.mode ?? current.mode;
  if (nextMode !== "off" && !config.relayIp) {
    return new Response("relay not deployed: RELAY_IP is missing or not a private address (mode stays as-is)", { status: 400 });
  }
  const nextForcedMode = patch.forcedMode ?? current.forcedMode;
  if (nextForcedMode !== "off" && !config.relayIp) {
    return new Response("relay not deployed: RELAY_IP is missing or not a private address (forcedMode stays as-is)", { status: 400 });
  }
  // Fields left out of the request keep their current override values (absent = env), like a PATCH.
  const merged = { ...(relayOverrideSnapshot() ?? {}), ...patch } as typeof patch;
  const changed = setRelayOverride(merged, config);
  if (changed) console.log(JSON.stringify({ event: "relay_config_updated", fields: Object.keys(patch), configVersion: relayStatus(config).configVersion }));
  return json({ ok: true, changed, relay: relayStatus(config) });
}

async function handleAdminRelayHealth(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
  let body: { source?: unknown; ttl?: unknown; healthy?: unknown; direct?: unknown; appliedConfigVersion?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const source = typeof body.source === "string" ? body.source.slice(0, 64) : "unknown";
  const ttl = typeof body.ttl === "number" && Number.isFinite(body.ttl) ? Math.max(30, Math.min(3600, body.ttl)) : 120;
  const appliedConfigVersion = typeof body.appliedConfigVersion === "number" && Number.isFinite(body.appliedConfigVersion) && body.appliedConfigVersion >= 0
    ? Math.min(Math.floor(body.appliedConfigVersion), 2 ** 31)
    : undefined;
  setRelayHealth({ source, ttlSeconds: ttl, healthy: body.healthy === true, direct: readRelayDirectSamples(body.direct), ...(appliedConfigVersion !== undefined ? { appliedConfigVersion } : {}) });
  return json({ ok: true, relay: relayStatus(readConfig(env)) });
}

/** direct: {"github.com": {ok: true, rttMs: 120}} — per-host handshake samples from the relay's prober. */
function readRelayDirectSamples(value: unknown): Record<string, { ok: boolean; rttMs?: number }> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const direct: Record<string, { ok: boolean; rttMs?: number }> = {};
  for (const [host, sample] of Object.entries(value)) {
    const name = host.toLowerCase().replace(/\.$/, "");
    if (!HOSTNAME.test(name)) continue;
    if (typeof sample !== "object" || sample === null) continue;
    const ok = (sample as { ok?: unknown }).ok === true;
    const rtt = (sample as { rttMs?: unknown }).rttMs;
    direct[name] = { ok, ...(typeof rtt === "number" && Number.isFinite(rtt) && rtt >= 0 ? { rttMs: rtt } : {}) };
  }
  return direct;
}

/**
 * The measured pool for one host, for the relay daemon to dial by address (githubPoolFor, else the
 * site pool): a relay-pinned name's /dns-query answer is the relay IP itself, so the daemon needs
 * this side channel to learn the addresses it should be dialing.
 */
async function handleAdminPool(request: Request, env: Env): Promise<Response> {
  const denied = await adminAuth(request, env);
  if (denied) return denied;
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  const name = (new URL(request.url).searchParams.get("name") ?? "").toLowerCase().replace(/\.$/, "");
  if (!HOSTNAME.test(name)) return new Response("invalid name", { status: 400 });
  const github = githubPoolFor(name);
  const pool = github.length > 0 ? github : sitePoolFor(name);
  return json({ ok: true, name, source: github.length > 0 ? "github-pool" : pool.length > 0 ? "site-pool" : "none", pool });
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
  if (request.method === "GET") return json({ ok: true, ...adminState(readConfig(env)) });
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
  return json({ ok: true, ...adminState(readConfig(env)) });
}

const MAX_REPORTED_IPS = 64;

async function handleAdminPreferred(request: Request, env: Env, runtime: RequestRuntime): Promise<Response> {
  const role = await preferredAuth(request, env);
  if (role instanceof Response) return role;
  const hubOnly = "The hub token may only write operator pools (POST with scope \"isp:<name>\")";
  if (request.method === "GET") return role === "admin" ? json({ ok: true, ...adminState(readConfig(env)) }) : new Response(hubOnly, { status: 403 });
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
    return json({ ok: true, scope: scope ?? "default", ...adminState(readConfig(env)) });
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
