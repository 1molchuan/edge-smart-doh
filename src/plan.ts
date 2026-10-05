import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";
import { DnsType, type DnsPacket } from "./dns/types";
import type { RequestOptions } from "./request-options";
import type { RuleSet } from "./rules";
import { loadCloudflareRanges, resolveDomainAddresses, responseUsesCloudflare, servedByCloudflare } from "./rewrite";

/**
 * The strategy layer. For one query, a fixed list of strategies decides how the name should be
 * reached (which addresses, which ECH key, which ALPN) and writes it into a RoutePlan; render.ts then
 * applies the plan to the upstream answer. A strategy only decides, it never edits a packet, so a new
 * way of reaching sites is a new strategy, not another branch through the DNS flow.
 *
 * Strategies run in `order`. Later ones may override what earlier ones set, which is how the flow
 * always behaved (a GitHub pool pin replaces the preferred-pool rewrite, for instance). A strategy that
 * takes a decision for good sets `plan.locked`, and later strategies leave that part alone.
 */

export type CloudflareRanges = Awaited<ReturnType<typeof loadCloudflareRanges>>;

/** What is known before upstream is asked: enough to key the cache. */
export interface RequestContext {
  config: AppConfig;
  options: RequestOptions;
  /** Preferred-pool scope of the request (client prefix, operator), if any. */
  scope?: string;
  name: string;
  type: number;
}

export interface PlanContext extends RequestContext {
  query: DnsPacket;
  rules: RuleSet;
  cache: Cache;
  ranges?: CloudflareRanges;
  /** Whether Cloudflare serves the name; resolved at most once, and only if a strategy asks. */
  onCloudflare(): Promise<boolean>;
  /** The onCloudflare() answer if it was asked for, else undefined. */
  classified(): boolean | undefined;
  /**
   * Set (in prepare) by a strategy that steers the name to its own endpoint: the site pool steps
   * aside, and Cloudflare is also recognised by <name>.cdn.cloudflare.net.
   */
  steered: boolean;
  notes?: string[];
  debug(event: string, error: unknown): void;
}

export type EchSource = "configured" | "cloudflare" | "meta" | "rule" | "steered";

export interface RoutePlan {
  /** Label for /explain: direct, preferred-ip, native-ech, x-multicdn, meta-ech, site-pool, github-pool, ... */
  strategy: string;
  /** Return the upstream answer through this function and do nothing else. */
  passthrough?: (packet: DnsPacket) => DnsPacket;
  /** Rewrite Cloudflare addresses to the preferred pool. */
  preferredPool: boolean;
  /** Pin an X host to the preferred pool (multi-CDN). */
  xPool: boolean;
  /** Answer A with these and drop AAAA. */
  pin?: string[];
  /** TTL ceiling for the pinned A records (the relay pins at 60 so a withdrawn relay recovers fast). */
  pinTtl?: number;
  /** ECH for the HTTPS record, with its ALPN (undefined keeps what upstream published). */
  ech?: { config: Uint8Array; alpn?: string[]; source: EchSource };
  /** Point the HTTPS record's address hints here. */
  hints?: string[];
  /** Site-pool addresses, used as hints when the Cloudflare ECH step injects. */
  siteHints?: string[];
  /** Handed by a steering strategy to the Cloudflare ECH step: its own key (and how /explain names it), ALPN and hints. */
  steer?: { config?: Uint8Array; label?: string; alpn: string[]; why: string; hints: string[] };
  /** Final edits after everything else, each with the /explain line it logs when it changes the answer. */
  post: { apply: (packet: DnsPacket) => DnsPacket; note: string }[];
  locked: { addresses: boolean; ech: boolean };
}

export interface Strategy {
  name: string;
  order: number;
  /** Cache-key part: whatever this strategy's decision depends on beyond the query and options. */
  cacheTag?(ctx: RequestContext): string | undefined;
  /** Runs first, before Cloudflare ranges are loaded: may set `passthrough` or `ctx.steered`. */
  prepare?(ctx: PlanContext, plan: RoutePlan): void;
  apply?(ctx: PlanContext, plan: RoutePlan): Promise<void>;
}

export function sortStrategies(strategies: Strategy[]): Strategy[] {
  return [...strategies].sort((a, b) => a.order - b.order);
}

/** The cache variant suffix for a request: every strategy's tag, in strategy order. */
export function strategyCacheTags(strategies: Strategy[], ctx: RequestContext): string {
  let variant = "";
  for (const strategy of strategies) {
    const tag = strategy.cacheTag?.(ctx);
    if (tag !== undefined) variant += `|${tag}`;
  }
  return variant;
}

export interface PlanInput {
  config: AppConfig;
  options: RequestOptions;
  query: DnsPacket;
  rules: RuleSet;
  cache: Cache;
  notes?: string[];
}

export async function makePlan(strategies: Strategy[], input: PlanInput): Promise<{ plan: RoutePlan; ctx: PlanContext }> {
  const { config, query, cache, notes } = input;
  const question = query.questions[0]!;
  let onCloudflare: boolean | undefined;
  let classify: () => Promise<boolean> = async () => false;
  const ctx: PlanContext = {
    ...input,
    name: question.name,
    type: question.type,
    steered: false,
    onCloudflare: () => classify(),
    classified: () => onCloudflare,
    debug(event, error) {
      if (config.debug) console.warn(JSON.stringify({ event, message: error instanceof Error ? error.message : String(error) }));
    },
  };
  const plan: RoutePlan = { strategy: "direct", preferredPool: false, xPool: false, post: [], locked: { addresses: false, ech: false } };

  for (const strategy of strategies) {
    strategy.prepare?.(ctx, plan);
    if (plan.passthrough) return { plan, ctx };
  }

  if (config.cfRewriteEnabled || (config.echEnabled && question.type === DnsType.HTTPS)) {
    try {
      ctx.ranges = await loadCloudflareRanges(config, cache);
    } catch (error) {
      notes?.push(`Cloudflare ranges unavailable: ${error instanceof Error ? error.message : String(error)}`);
      ctx.debug("cf_ranges_error", error);
    }
  }

  // X hosts are steered between Cloudflare and Fastly per resolver, and a few (abs-0/ton.twimg.com)
  // live only on X's own network. A host counts as Cloudflare if it resolves there now or, for the
  // multi-CDN X list and steered names, if Cloudflare serves it at all.
  const checkCname = domainMatches(question.name, config.xDomains) || ctx.steered;
  classify = async () => {
    if (onCloudflare !== undefined) return onCloudflare;
    const ranges = ctx.ranges;
    if (!ranges) return (onCloudflare = false);
    const [direct, viaCname] = await Promise.all([
      resolveDomainAddresses(question.name, config, cache).then((addresses) => responseUsesCloudflare(addresses, ranges), () => false),
      checkCname ? servedByCloudflare(question.name, config, cache) : Promise.resolve(false),
    ]);
    notes?.push(`Cloudflare check: current answer ${direct ? "is" : "is not"} on Cloudflare${checkCname ? `; ${question.name}.cdn.cloudflare.net ${viaCname ? "exists" : "does not exist"}` : ""}`);
    return (onCloudflare = direct || viaCname);
  };

  for (const strategy of strategies) await strategy.apply?.(ctx, plan);
  return { plan, ctx };
}

/** The plan as /explain shows it. */
export function describePlan(plan: RoutePlan): Record<string, unknown> {
  return {
    strategy: plan.strategy,
    ...(plan.passthrough ? { passthrough: true } : {}),
    ...(plan.preferredPool ? { preferredPool: true } : {}),
    ...(plan.xPool ? { xPool: true } : {}),
    ...(plan.pin ? { pin: plan.pin } : {}),
    ...(plan.ech ? { ech: { source: plan.ech.source, bytes: plan.ech.config.length, alpn: plan.ech.alpn ?? "as published upstream" } } : {}),
    ...(plan.hints ? { hints: plan.hints } : {}),
  };
}
