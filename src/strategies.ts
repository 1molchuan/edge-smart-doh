import { domainMatches } from "./dns/ecs";
import { DnsType } from "./dns/types";
import { alpnFor, h3CacheTag } from "./h3";
import type { PlanContext, RequestContext, Strategy } from "./plan";
import { githubPoolFor, metaEchCacheTag, metaEchOverride, sitePoolCacheTag, sitePoolFor } from "./preferred";
import { RELAY_PIN_TTL, relayCacheTag, relayServes } from "./relay";
import type { RequestOptions } from "./request-options";
import { relayHttpsCleanup, resolveEchConfig, validatedEchConfig } from "./rewrite";

/** A site pool (see sitePoolFor) stands in for the server's default pool only; an explicit ?ip4= or ?cf= choice wins. */
export function sitePool(name: string, options: RequestOptions): string[] {
  return options.cfDomainIsDefault === true ? sitePoolFor(name) : [];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const isAddressQuery = (ctx: PlanContext) => ctx.type === DnsType.A || ctx.type === DnsType.AAAA;
const isEchQuery = (ctx: RequestContext) => ctx.config.echEnabled && ctx.type === DnsType.HTTPS;

/** Cloudflare addresses go to the preferred pool (the pool scope is part of the cache key). */
export const preferredIp: Strategy = {
  name: "preferred-ip",
  order: 10,
  cacheTag: (ctx) => (ctx.scope ? `pool=${ctx.scope}` : undefined),
  async apply(ctx, plan) {
    plan.preferredPool = ctx.config.cfRewriteEnabled;
  },
};

/** X hosts: pinned to the preferred pool only when Cloudflare really serves them (multi-CDN). */
export const xMultiCdn: Strategy = {
  name: "x-multicdn",
  order: 20,
  async apply(ctx, plan) {
    if (!domainMatches(ctx.name, ctx.config.xDomains)) return;
    try {
      if (await ctx.onCloudflare()) {
        plan.xPool = true;
        plan.strategy = "x-multicdn";
        ctx.notes?.push("X host served by Cloudflare: addresses pinned to the preferred pool");
      } else {
        ctx.notes?.push("X host not served by Cloudflare: answer left untouched");
      }
    } catch (error) {
      ctx.notes?.push(`X classification failed: ${errorMessage(error)}`);
      ctx.debug("x_classify_error", error);
    }
  },
};

/**
 * A site whose origin hangs through the general pool's colos gets the IPs a prober verified end to
 * end (see setSitePools). IPv6 is dropped: the site pools are IPv4, and a dual-stack client would
 * otherwise prefer the untested IPv6 pool. The HTTPS hints are pinned by the Cloudflare ECH step.
 */
export const sitePools: Strategy = {
  name: "site-pool",
  order: 40,
  cacheTag: (ctx) => (sitePool(ctx.name, ctx.options).length > 0 ? sitePoolCacheTag(ctx.name) : undefined),
  async apply(ctx, plan) {
    if (ctx.steered) return;
    const siteIps = sitePool(ctx.name, ctx.options);
    if (siteIps.length === 0) return;
    plan.siteHints = siteIps;
    if (!isAddressQuery(ctx)) return;
    try {
      if (await ctx.onCloudflare()) {
        plan.pin = siteIps;
        plan.strategy = "site-pool";
        ctx.notes?.push(`site pool (origin unreachable through the general pool): pinned to ${siteIps.join(", ")}, IPv6 dropped`);
      }
    } catch (error) {
      ctx.notes?.push(`site pool classification failed: ${errorMessage(error)}`);
    }
  },
};

/**
 * GitHub-family names: pin A to the host's own measured pool (no ECH — GitHub's China pain is IP
 * reachability). AAAA is dropped (the pools are IPv4). Left untouched when nothing was measured.
 */
export const githubPool: Strategy = {
  name: "github-pool",
  order: 50,
  async apply(ctx, plan) {
    if (plan.locked.addresses || !isAddressQuery(ctx) || !domainMatches(ctx.name, ctx.config.githubDomains)) return;
    const pool = githubPoolFor(ctx.name);
    if (pool.length > 0) {
      plan.pin = pool;
      plan.strategy = "github-pool";
      ctx.notes?.push(`GitHub host pinned to its measured pool (${pool.join(", ")}), IPv6 dropped`);
    } else {
      ctx.notes?.push("GitHub host: no measured pool yet, answer left untouched");
    }
  },
};

/**
 * The home SNI relay (contrib/home/relay, see its DESIGN.md): the name is answered with the LAN
 * address of a local relay that forwards the TCP flow through the egress proxy by SNI, TLS staying
 * end to end. "always" serves every name in RELAY_DOMAINS; "auto" only hosts whose measured direct
 * path went bad (relay.ts); both step aside the moment the relay stops reporting healthy, so the
 * worst case is the un-relayed answer of yesterday. Sits between the site-pool and GitHub-pool
 * strategies: it takes the addresses decision for good (github-pool then leaves the name alone).
 */
export const relay: Strategy = {
  name: "relay",
  order: 45,
  cacheTag: (ctx: RequestContext) => (relayServes(ctx.name, ctx.config) ? relayCacheTag() : undefined),
  async apply(ctx: PlanContext, plan) {
    if (!relayServes(ctx.name, ctx.config)) return;
    const ip = ctx.config.relayIp!;
    if (ctx.type === DnsType.A || ctx.type === DnsType.AAAA) {
      plan.pin = [ip];
      plan.pinTtl = RELAY_PIN_TTL;
      plan.locked.addresses = true;
      plan.strategy = "relay";
      ctx.notes?.push(`relay: answer pinned to ${ip}, IPv6 dropped (mode ${ctx.config.relayMode})`);
    } else if (ctx.type === DnsType.HTTPS) {
      plan.locked.ech = true;
      plan.strategy = "relay";
      plan.post.push({ apply: (packet) => relayHttpsCleanup(packet, [ip]), note: `relay: HTTPS hints → ${ip}, ECH removed, ALPN → h2` });
    }
  },
};

/** Meta's own ECH key (learned by a prober, or the configured seed). */
export const metaEch: Strategy = {
  name: "meta-ech",
  order: 70,
  cacheTag: (ctx) => (isEchQuery(ctx) && domainMatches(ctx.name, ctx.config.metaDomains) ? metaEchCacheTag() : undefined),
  async apply(ctx, plan) {
    if (!isEchQuery(ctx) || plan.locked.ech || !domainMatches(ctx.name, ctx.config.metaDomains)) return;
    plan.locked.ech = true;
    plan.strategy = "meta-ech";
    const override = metaEchOverride();
    const ech = override === null ? undefined : override ?? validatedEchConfig(ctx.config.metaEchConfigBase64);
    // Without a measurement, Meta gets h2 only: its QUIC times out in mainland China.
    const { alpn, why } = alpnFor(ctx.name, ["h2"]);
    if (ech) plan.ech = { config: ech, alpn, source: "meta" };
    ctx.notes?.push(`Meta ECH: ${override === null ? "suspended by the prober, not injected" : override ? "learned key injected" : ech ? "seed key injected" : "no valid seed configured"}; ALPN ${alpn?.join(",")} (${why})`);
  },
};

/**
 * Cloudflare sites get ECH: the configured key, else the one Cloudflare publishes, unless a steering
 * strategy handed its own. Without a measurement, X hosts get h2 only (X's zone rejects QUIC+ECH) and
 * other Cloudflare sites keep whatever ALPN their own record published.
 */
export const cloudflareEch: Strategy = {
  name: "native-ech",
  order: 80,
  cacheTag: (ctx) => (isEchQuery(ctx) ? h3CacheTag() : undefined),
  async apply(ctx, plan) {
    if (!isEchQuery(ctx) || plan.locked.ech) return;
    try {
      if (!(await ctx.onCloudflare())) {
        ctx.notes?.push("not on Cloudflare: no ECH injected");
        return;
      }
      const { config, options, cache } = ctx;
      const configured = validatedEchConfig(config.echConfigBase64);
      const steer = plan.steer;
      const ech = steer?.config ?? configured ?? await resolveEchConfig(options.echDomain ?? config.echSourceDomain, config, cache);
      const { alpn, why } = steer ? { alpn: steer.alpn, why: steer.why } : alpnFor(ctx.name, domainMatches(ctx.name, config.xDomains) ? ["h2"] : undefined);
      plan.ech = { config: ech, alpn, source: steer?.config ? "steered" : configured ? "configured" : "cloudflare" };
      const siteHints = steer ? [] : plan.siteHints ?? [];
      plan.hints = steer ? steer.hints : siteHints.length > 0 ? siteHints : undefined;
      if (plan.strategy === "direct" || plan.strategy === "preferred-ip") plan.strategy = "native-ech";
      ctx.notes?.push(`${steer?.config ? steer.label ?? "the steering endpoint's own ECH" : "Cloudflare ECH"} injected (${ech.length}B); ALPN ${alpn ? alpn.join(",") : "as published upstream"} (${why})${siteHints.length > 0 ? "; hints pinned to the site pool" : ""}`);
    } catch (error) {
      ctx.notes?.push(`ECH injection failed: ${errorMessage(error)}`);
      ctx.debug("ech_injection_error", error);
    }
  },
};

export const PUBLIC_STRATEGIES: Strategy[] = [preferredIp, xMultiCdn, sitePools, relay, githubPool, metaEch, cloudflareEch];
