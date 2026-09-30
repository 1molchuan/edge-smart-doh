export type EcsMode = "off" | "always" | "rules";

export interface AppConfig {
  upstreams: string[];
  /** Upstreams used for queries carrying ECS; only resolvers that forward ECS belong here. Falls back to `upstreams`. */
  ecsUpstreams: string[];
  upstreamTimeoutMs: number;
  /** Delay before racing the next upstream while the previous one is still pending. 0 disables hedging. */
  upstreamHedgeMs: number;
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
  edgeOneClientIpHeader: string;
  cfRewriteEnabled: boolean;
  /** Preferred-IP source domains; all are resolved and merged into one pool. */
  cfPreferredDomains: string[];
  cfPreferredIpv4: string[];
  cfPreferredIpv6: string[];
  /** Strip AAAA from rewritten Cloudflare answers (for clients on broken IPv6 paths). */
  cfDropAaaa: boolean;
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

export function readConfig(env: Env): AppConfig {
  const rawMode: string = env.ECS_MODE;
  const mode = rawMode === "off" || rawMode === "always" ? rawMode : "rules";
  const upstreams = list(env.UPSTREAMS).filter((item) => item.startsWith("https://"));
  const ecsUpstreams = list(env.ECS_UPSTREAMS).filter((item) => item.startsWith("https://"));
  return {
    upstreams,
    ecsUpstreams: ecsUpstreams.length > 0 ? ecsUpstreams : upstreams,
    upstreamTimeoutMs: integer(env.UPSTREAM_TIMEOUT_MS, 2500, 250, 15000),
    upstreamHedgeMs: integer(env.UPSTREAM_HEDGE_MS, 100, 0, 5000),
    cacheMinTtl: integer(env.CACHE_MIN_TTL, 30, 0, 3600),
    cacheMaxTtl: integer(env.CACHE_MAX_TTL, 3600, 1, 86400),
    negativeCacheMaxTtl: integer(env.NEGATIVE_CACHE_MAX_TTL, 300, 0, 3600),
    cacheStaleTtl: integer(env.CACHE_STALE_TTL, 86400, 0, 604800),
    cachePrefetchPercent: integer(env.CACHE_PREFETCH_PERCENT, 10, 0, 90),
    ecsMode: mode,
    ecsDomains: list(env.ECS_DOMAINS).map((item) => item.toLowerCase()),
    ecsIpv4Prefix: integer(env.ECS_IPV4_PREFIX, 24, 0, 32),
    ecsIpv6Prefix: integer(env.ECS_IPV6_PREFIX, 48, 0, 128),
    edgeOneClientIpHeader: env.EDGEONE_CLIENT_IP_HEADER || "X-EdgeOne-Client-IP-Configure-Me",
    cfRewriteEnabled: enabled(env.CF_REWRITE_ENABLED),
    cfPreferredDomains: list(env.CF_PREFERRED_DOMAIN).map((item) => item.replace(/\.$/, "").toLowerCase()),
    cfPreferredIpv4: list(env.CF_PREFERRED_IPV4),
    cfPreferredIpv6: list(env.CF_PREFERRED_IPV6),
    cfDropAaaa: enabled(env.CF_DROP_AAAA),
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
    dynamicRuleHosts: list(env.DYNAMIC_RULE_HOSTS).map((item) => item.toLowerCase()),
    dynamicRulesMaxBytes: integer(env.DYNAMIC_RULES_MAX_BYTES, 262144, 1024, 1048576),
    debug: enabled(env.DEBUG),
    logQueries: enabled(env.LOG_QUERIES),
    maxDnsPacketSize: integer(env.MAX_DNS_PACKET_SIZE, 4096, 512, 65535),
  };
}
