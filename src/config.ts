export type EcsMode = "off" | "always" | "rules";

export interface AppConfig {
  upstreams: string[];
  /** Upstreams used for queries carrying ECS; only resolvers that forward ECS belong here. Falls back to `upstreams`. */
  ecsUpstreams: string[];
  upstreamTimeoutMs: number;
  /** Delay before racing the next upstream while the previous one is still pending. 0 disables hedging. */
  upstreamHedgeMs: number;
  /**
   * The same delay for the ECS group. Resolvers differ in how well Chinese GSLBs honour ECS from them
   * (Google often gets Baidu's and Huawei's overseas nodes, AliDNS the domestic ones), so the first
   * ECS upstream should get time to answer before the next races it. Defaults to UPSTREAM_HEDGE_MS.
   */
  ecsUpstreamHedgeMs: number;
  cacheMinTtl: number;
  cacheMaxTtl: number;
  negativeCacheMaxTtl: number;
  /** How long an expired entry stays servable when refresh fails (RFC 8767). 0 disables serve-stale. */
  cacheStaleTtl: number;
  /** Background-refresh a hit once remaining TTL drops below this percentage of the original. 0 disables prefetch. */
  cachePrefetchPercent: number;
  ecsMode: EcsMode;
  ecsDomains: string[];
  ecsIpv4Prefix: number;
  ecsIpv6Prefix: number;
  /**
   * Upstreams for domestic (mainland Chinese) names when the domain-split module is on: resolvers
   * dialed directly inside China. Empty = the module is off and domestic names keep using the ECS
   * path (ECS_UPSTREAMS with the client subnet or ECS_FALLBACK_SUBNET). Their hostnames must bypass
   * the egress proxy (server/node.ts warns otherwise): going through it both slows them down and
   * hands them a foreign resolver's view.
   */
  cnUpstreams: string[];
  /** Extra domestic domain suffixes on top of ECS_DOMAINS and the ECS_DOMAIN_LIST_URLS lists. */
  cnDomains: string[];
  /**
   * ECS subnet for clients outside every mainland operator network (needs ISP_TABLE_URL). Their DoH
   * query arrived through a proxy, typically in Hong Kong; with their own address a Chinese site
   * answers with its overseas CDN, which the proxy's GeoIP rules then send abroad. Unset = their own.
   */
  ecsFallbackSubnet?: string;
  /** Chinese-site domain lists that get ECS like ECS_DOMAINS (see cn-domains.ts); empty = ECS_DOMAINS only. */
  ecsDomainListUrls: string[];
  edgeOneClientIpHeader: string;
  cfRewriteEnabled: boolean;
  /** Preferred-IP source domains; all are resolved and merged into one pool. */
  cfPreferredDomains: string[];
  cfPreferredIpv4: string[];
  cfPreferredIpv6: string[];
  /** Strip AAAA from rewritten Cloudflare answers (for clients on broken IPv6 paths). */
  cfDropAaaa: boolean;
  /**
   * Names answered exactly as upstream gave them: Cloudflare's own non-web services (CF_SERVICE_DOMAINS)
   * and CF_REWRITE_EXCLUDE. Preferred IPs only serve HTTP/HTTPS, so a tunnel or WARP endpoint
   * rewritten to them stops working.
   */
  cfRewriteExclude: string[];
  /** Bearer token for POST /admin/preferred; empty disables the endpoint. */
  adminToken?: string;
  /**
   * Bearer token of the probe hub (work/cfhub). It may only write operator pools
   * (POST /admin/preferred with scope "isp:<name>"): no reads, no nationwide or client pools.
   */
  hubToken?: string;
  /** Client IP → operator table ("<isp> <cidr>" lines, served by the hub). Unset disables operator pools. */
  ispTableUrl?: string;
  cfIpv4Url: string;
  cfIpv6Url: string;
  rulesJson: string;
  rulesUrl?: string;
  echEnabled: boolean;
  echConfigBase64?: string;
  echDomains: string[];
  echSourceDomain: string;
  metaEchConfigBase64?: string;
  metaDomains: string[];
  xDomains: string[];
  /**
   * GitHub-family names served from per-host measured pools (see preferred.ts githubPoolFor). No ECH
   * (GitHub publishes none): pure preferred-IP, because GitHub's China pain is IP
   * reachability, not SNI DPI. AAAA is dropped for these (the pools are IPv4).
   */
  githubDomains: string[];
  /** Block lists for ?safe=1 (see safe.ts); empty disables the feature. */
  safeListUrls: string[];
  /** Domains (and their subdomains) ?safe=1 never blocks. */
  safeAllow: string[];
  dynamicRuleHosts: string[];
  dynamicRulesMaxBytes: number;
  debug: boolean;
  logQueries: boolean;
  maxDnsPacketSize: number;
}

function integer(value: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, parsed)) : fallback;
}

function enabled(value: string | undefined): boolean {
  return value?.toLowerCase() === "true";
}

// Secrets are not part of the generated Env type (they are set via `wrangler secret put`, not vars).
function optionalSecret(env: Env, name: string): string | undefined {
  const value: unknown = Reflect.get(env, name);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function list(value: string | undefined): string[] {
  return (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}

/**
 * Cloudflare's own services that are not websites: cloudflared tunnels reach the edge on port 7844
 * (argotunnel.com, cftunnel.com) and WARP on 2408 and MASQUE (cloudflareclient.com). Their addresses
 * sit in Cloudflare's ranges, but the preferred IPs do not serve those ports.
 */
const CF_SERVICE_DOMAINS = [".argotunnel.com", ".cftunnel.com", ".cloudflareclient.com"];

export function readConfig(env: Env): AppConfig {
  const rawMode: string = env.ECS_MODE;
  const mode = rawMode === "off" || rawMode === "always" ? rawMode : "rules";
  const upstreams = list(env.UPSTREAMS).filter((item) => item.startsWith("https://"));
  const ecsUpstreams = list(env.ECS_UPSTREAMS).filter((item) => item.startsWith("https://"));
  const upstreamHedgeMs = integer(env.UPSTREAM_HEDGE_MS, 100, 0, 5000);
  return {
    upstreams,
    ecsUpstreams: ecsUpstreams.length > 0 ? ecsUpstreams : upstreams,
    upstreamTimeoutMs: integer(env.UPSTREAM_TIMEOUT_MS, 2500, 250, 15000),
    upstreamHedgeMs,
    ecsUpstreamHedgeMs: integer(env.ECS_UPSTREAM_HEDGE_MS, upstreamHedgeMs, 0, 5000),
    cacheMinTtl: integer(env.CACHE_MIN_TTL, 30, 0, 3600),
    cacheMaxTtl: integer(env.CACHE_MAX_TTL, 3600, 1, 86400),
    negativeCacheMaxTtl: integer(env.NEGATIVE_CACHE_MAX_TTL, 300, 0, 3600),
    cacheStaleTtl: integer(env.CACHE_STALE_TTL, 86400, 0, 604800),
    cachePrefetchPercent: integer(env.CACHE_PREFETCH_PERCENT, 10, 0, 90),
    ecsMode: mode,
    ecsDomains: list(env.ECS_DOMAINS).map((item) => item.toLowerCase()),
    ecsIpv4Prefix: integer(env.ECS_IPV4_PREFIX, 24, 0, 32),
    ecsIpv6Prefix: integer(env.ECS_IPV6_PREFIX, 48, 0, 128),
    cnUpstreams: list(env.CN_UPSTREAMS).filter((item) => item.startsWith("https://")),
    cnDomains: list(env.CN_DOMAINS).map((item) => item.toLowerCase()),
    // A "/24" suffix is accepted and ignored: the prefix comes from ECS_IPV4_PREFIX/ECS_IPV6_PREFIX.
    ecsFallbackSubnet: (env.ECS_FALLBACK_SUBNET ?? "").split("/", 1)[0] || undefined,
    ecsDomainListUrls: list(env.ECS_DOMAIN_LIST_URLS).filter((item) => item.startsWith("https://") || item.startsWith("http://127.0.0.1")),
    edgeOneClientIpHeader: env.EDGEONE_CLIENT_IP_HEADER || "X-EdgeOne-Client-IP-Configure-Me",
    cfRewriteEnabled: enabled(env.CF_REWRITE_ENABLED),
    cfPreferredDomains: list(env.CF_PREFERRED_DOMAIN).map((item) => item.replace(/\.$/, "").toLowerCase()),
    cfPreferredIpv4: list(env.CF_PREFERRED_IPV4),
    cfPreferredIpv6: list(env.CF_PREFERRED_IPV6),
    cfDropAaaa: enabled(env.CF_DROP_AAAA),
    cfRewriteExclude: [...CF_SERVICE_DOMAINS, ...list(env.CF_REWRITE_EXCLUDE).map((item) => item.toLowerCase())],
    adminToken: optionalSecret(env, "ADMIN_TOKEN"),
    hubToken: optionalSecret(env, "HUB_TOKEN"),
    ispTableUrl: env.ISP_TABLE_URL || undefined,
    cfIpv4Url: env.CF_IPV4_URL || "https://www.cloudflare.com/ips-v4/",
    cfIpv6Url: env.CF_IPV6_URL || "https://www.cloudflare.com/ips-v6/",
    rulesJson: env.RULES_JSON || "[]",
    rulesUrl: env.RULES_URL || undefined,
    echEnabled: enabled(env.ECH_ENABLED),
    echConfigBase64: env.ECH_CONFIG_BASE64 || undefined,
    echDomains: list(env.ECH_DOMAINS).map((item) => item.toLowerCase()),
    echSourceDomain: env.ECH_SOURCE_DOMAIN || "cloudflare-ech.com",
    metaEchConfigBase64: env.META_ECH_CONFIG_BASE64 || undefined,
    metaDomains: list(env.META_DOMAINS).map((item) => item.toLowerCase()),
    xDomains: list(env.X_DOMAINS).map((item) => item.toLowerCase()),
    githubDomains: list(env.GITHUB_DOMAINS).map((item) => item.toLowerCase()),
    safeListUrls: list(env.SAFE_LIST_URLS).filter((item) => item.startsWith("https://") || item.startsWith("http://127.0.0.1")),
    safeAllow: list(env.SAFE_ALLOW).map((item) => item.toLowerCase().replace(/^\*?\./, "").replace(/\.$/, "")),
    dynamicRuleHosts: list(env.DYNAMIC_RULE_HOSTS).map((item) => item.toLowerCase()),
    dynamicRulesMaxBytes: integer(env.DYNAMIC_RULES_MAX_BYTES, 262144, 1024, 1048576),
    debug: enabled(env.DEBUG),
    logQueries: enabled(env.LOG_QUERIES),
    maxDnsPacketSize: integer(env.MAX_DNS_PACKET_SIZE, 4096, 512, 65535),
  };
}
