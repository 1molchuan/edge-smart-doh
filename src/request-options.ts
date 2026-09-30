import type { AppConfig } from "./config";
import { parseIpv4, parseIpv6 } from "./dns/packet";

export interface RequestOptions {
  /** Domains whose addresses form the preferred-IP pool; from ?cf= (single) or the configured default (may be several). */
  cfDomains: string[];
  cfDomainIsDefault?: boolean;
  echDomain?: string;
  preferredIpv4?: string[];
  preferredIpv6?: string[];
  rulesUrl?: string;
  cacheVariant: string;
}

function hostname(value: string, parameter: string): string {
  const normalized = value.trim().replace(/\.$/, "").toLowerCase();
  if (!normalized || normalized.length > 253 || !/^[a-z0-9.-]+$/.test(normalized)) {
    throw new Error(`Invalid ${parameter} hostname`);
  }
  const labels = normalized.split(".");
  if (labels.length < 2 || labels.some((label) => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) {
    throw new Error(`Invalid ${parameter} hostname`);
  }
  return normalized;
}

function addresses(params: URLSearchParams, name: "ip4" | "ip6"): string[] | undefined {
  const raw = params.get(name);
  if (raw === null) return undefined;
  if (raw.length > 1024) throw new Error(`${name} is too long`);
  const values = [...new Set(raw.split(",").map((value) => value.trim()).filter(Boolean))];
  if (values.length === 0 || values.length > 16) throw new Error(`${name} must contain 1-16 addresses`);
  for (const value of values) name === "ip4" ? parseIpv4(value) : parseIpv6(value);
  return values;
}

function dynamicRulesUrl(raw: string, config: AppConfig): string {
  if (raw.length > 2048) throw new Error("rules URL is too long");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid rules URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443") || url.hash) {
    throw new Error("rules must be an HTTPS URL without credentials, a custom port, or a fragment");
  }
  const allowed = config.dynamicRuleHosts.some((host) => url.hostname.toLowerCase() === host);
  if (!allowed) throw new Error("rules hostname is not allowed");
  return url.href;
}

export function parseRequestOptions(url: URL, config: AppConfig): RequestOptions {
  const options: RequestOptions = { cfDomains: [], cacheVariant: "default" };
  const cf = url.searchParams.get("cf");
  const ech = url.searchParams.get("ech");
  const rules = url.searchParams.get("rules");
  if (cf !== null) options.cfDomains = [hostname(cf, "cf")];
  if (ech !== null) options.echDomain = hostname(ech, "ech");
  options.preferredIpv4 = addresses(url.searchParams, "ip4");
  options.preferredIpv6 = addresses(url.searchParams, "ip6");
  if (rules !== null) options.rulesUrl = dynamicRulesUrl(rules, config);
  // Explicit ip4/ip6 take precedence over any domain-based preference; ?cf= over the configured default.
  if (options.cfDomains.length === 0 && !options.preferredIpv4 && !options.preferredIpv6 && config.cfPreferredDomains.length > 0) {
    options.cfDomains = config.cfPreferredDomains;
    options.cfDomainIsDefault = true;
  }
  const variant = new URLSearchParams();
  if (options.cfDomains.length > 0) variant.set("cf", options.cfDomains.join(","));
  if (options.echDomain) variant.set("ech", options.echDomain);
  if (options.preferredIpv4) variant.set("ip4", options.preferredIpv4.join(","));
  if (options.preferredIpv6) variant.set("ip6", options.preferredIpv6.join(","));
  if (options.rulesUrl) variant.set("rules", options.rulesUrl);
  options.cacheVariant = variant.size === 0 ? "default" : variant.toString();
  return options;
}
