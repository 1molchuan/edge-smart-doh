import { inAnyCidr, parseCidrList, type Cidr } from "./cidr";
import { matchCache } from "./cache-api";
import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";
import { upsertSvcParam, SvcParamKey } from "./dns/https-rr";
import { DnsType, type DnsPacket, type DnsRecord } from "./dns/types";
import { parseIpv4, parseIpv6 } from "./dns/packet";

interface RuleMatch {
  domain_exact?: string[];
  domain_suffix?: string[];
  qtype?: number | number[];
  response_ip_cidr?: string[];
}

interface RuleAction {
  type?: "passthrough" | "replace-a" | "replace-aaaa" | "replace-cname" | "rewrite-https" | "enable-ecs" | "disable-ecs" | "block";
  values?: string[];
  replace_a?: string[];
  replace_aaaa?: string[];
  replace_cname?: string | string[];
  rewrite_https?: { ipv4hint?: string[]; ipv6hint?: string[] };
  enable_ecs?: boolean;
  disable_ecs?: boolean;
  block?: boolean;
}

interface Rule {
  match?: RuleMatch;
  action?: RuleAction | string;
}

export interface RuleSet {
  rules: Rule[];
}

function normalizeRules(input: unknown): RuleSet {
  const raw = Array.isArray(input) ? input : typeof input === "object" && input !== null && Array.isArray((input as { rules?: unknown }).rules)
    ? (input as { rules: unknown[] }).rules
    : hostMapRules(input);
  return { rules: raw.filter((item): item is Rule => typeof item === "object" && item !== null).slice(0, 1000) };
}

function validAddresses(value: unknown, family: 4 | 6): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => typeof item === "string").filter((item) => {
    try {
      family === 4 ? parseIpv4(item) : parseIpv6(item);
      return true;
    } catch {
      return false;
    }
  }))].slice(0, 16);
}

function hostMapRules(input: unknown): Rule[] {
  if (typeof input !== "object" || input === null) return [];
  const rules: Rule[] = [];
  for (const [pattern, rawValue] of Object.entries(input)) {
    if (rules.length >= 1000) break;
    if (typeof rawValue !== "object" || rawValue === null) continue;
    const wildcard = pattern.startsWith("*.");
    const domain = wildcard ? pattern.slice(2) : pattern;
    if (!domain || domain.length > 253) continue;
    const match = wildcard ? { domain_suffix: [domain] } : { domain_exact: [domain] };
    const ipv4 = validAddresses((rawValue as { ipv4?: unknown }).ipv4, 4);
    const ipv6 = validAddresses((rawValue as { ipv6?: unknown }).ipv6, 6);
    if (ipv4.length > 0) rules.push({ match: { ...match, qtype: DnsType.A }, action: { replace_a: ipv4 } });
    if (ipv6.length > 0) rules.push({ match: { ...match, qtype: DnsType.AAAA }, action: { replace_aaaa: ipv6 } });
  }
  return rules;
}

function parseRuleText(text: string): RuleSet {
  try {
    return normalizeRules(JSON.parse(text));
  } catch {
    return { rules: [] };
  }
}

export async function loadRules(config: AppConfig, cache: Cache): Promise<RuleSet> {
  const embedded = parseRuleText(config.rulesJson);
  if (!config.rulesUrl?.startsWith("https://")) return embedded;
  const key = new Request(`https://doh-config.invalid/rules/${encodeURIComponent(config.rulesUrl)}`, { method: "GET" });
  const cached = await matchCache(cache, key);
  if (cached) return parseRuleText(await cached.text());
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("rules timeout"), Math.min(5000, config.upstreamTimeoutMs * 2));
  try {
    const response = await fetch(config.rulesUrl, {
      headers: { Accept: "application/json", "Cache-Control": "no-cache" },
      redirect: "manual",
      signal: controller.signal,
    });
    if (!response.ok) return embedded;
    const declared = Number(response.headers.get("Content-Length"));
    if (Number.isFinite(declared) && declared > config.dynamicRulesMaxBytes) return embedded;
    const text = await response.text();
    if (new TextEncoder().encode(text).length > config.dynamicRulesMaxBytes) return embedded;
    const parsed = parseRuleText(text);
    if (parsed.rules.length === 0 && text.trim() !== "[]" && text.trim() !== "{}" && text.trim() !== '{"rules":[]}') return embedded;
    await cache.put(key, new Response(text, { headers: { "Cache-Control": "public, max-age=300" } }));
    return parsed;
  } catch {
    return embedded;
  } finally {
    clearTimeout(timeout);
  }
}

function qtypeMatches(match: RuleMatch | undefined, qtype: number): boolean {
  if (match?.qtype === undefined) return true;
  return (Array.isArray(match.qtype) ? match.qtype : [match.qtype]).includes(qtype);
}

function responseCidrs(match: RuleMatch | undefined): Cidr[] {
  if (!match?.response_ip_cidr) return [];
  try {
    return parseCidrList(match.response_ip_cidr.join("\n"));
  } catch {
    return [];
  }
}

function matches(rule: Rule, packet: DnsPacket, response?: DnsPacket): boolean {
  const question = packet.questions[0];
  if (!question || !qtypeMatches(rule.match, question.type)) return false;
  if (rule.match?.domain_exact && !domainMatches(question.name, rule.match.domain_exact)) return false;
  if (rule.match?.domain_suffix && !domainMatches(question.name, rule.match.domain_suffix.map((item) => item.startsWith(".") ? item : `.${item}`))) return false;
  const cidrs = responseCidrs(rule.match);
  if (rule.match?.response_ip_cidr && cidrs.length === 0) return false;
  if (cidrs.length > 0 && !response?.answers.some((record) => {
    const address = record.rdata.kind === "a" || record.rdata.kind === "aaaa" ? record.rdata.address : undefined;
    return address ? inAnyCidr(address, cidrs) : false;
  })) return false;
  return true;
}

function actionOf(rule: Rule): RuleAction {
  if (typeof rule.action === "string") return { type: rule.action as RuleAction["type"] };
  return rule.action ?? {};
}

export function ecsOverride(rules: RuleSet, query: DnsPacket): boolean | undefined {
  for (const rule of rules.rules) {
    if (!matches(rule, query)) continue;
    const action = actionOf(rule);
    if (action.type === "enable-ecs" || action.enable_ecs) return true;
    if (action.type === "disable-ecs" || action.disable_ecs) return false;
  }
  return undefined;
}

export function shouldBlock(rules: RuleSet, query: DnsPacket): boolean {
  return rules.rules.some((rule) => {
    if (!matches(rule, query)) return false;
    const action = actionOf(rule);
    return action.type === "block" || action.block === true;
  });
}

function replacementValues(action: RuleAction, key: "replace_a" | "replace_aaaa"): string[] {
  const direct = action[key];
  if (direct) return direct;
  return action.values ?? [];
}

function replaceAddressRecords(packet: DnsPacket, type: number, values: string[]): DnsPacket {
  if (values.length === 0) return packet;
  const matching = packet.answers.filter((record) => record.type === type);
  if (matching.length === 0) return packet;
  const ttl = Math.min(...matching.map((record) => record.ttl));
  const owner = matching[0]!.name;
  const additions: DnsRecord[] = values.map((address) => ({
    name: owner,
    type,
    class: 1,
    ttl,
    rdata: type === DnsType.A ? { kind: "a", address } : { kind: "aaaa", address },
  }));
  return { ...packet, answers: [...packet.answers.filter((record) => record.type !== type), ...additions] };
}


export function applyResponseRules(rules: RuleSet, query: DnsPacket, initial: DnsPacket): DnsPacket {
  let response = initial;
  for (const rule of rules.rules) {
    if (!matches(rule, query, response)) continue;
    const action = actionOf(rule);
    if (action.type === "replace-a" || action.replace_a) {
      response = replaceAddressRecords(response, DnsType.A, replacementValues(action, "replace_a"));
    } else if (action.type === "replace-aaaa" || action.replace_aaaa) {
      response = replaceAddressRecords(response, DnsType.AAAA, replacementValues(action, "replace_aaaa"));
    } else if (action.type === "replace-cname" || action.replace_cname) {
      const raw = action.replace_cname ?? action.values?.[0];
      const target = Array.isArray(raw) ? raw[0] : raw;
      if (target) response = {
        ...response,
        answers: response.answers.map((record) => record.type === DnsType.CNAME ? { ...record, rdata: { kind: "name", name: target } } : record),
      };
    } else if (action.type === "rewrite-https" || action.rewrite_https) {
      const rewrite = action.rewrite_https;
      if (rewrite) response = {
        ...response,
        answers: response.answers.map((record) => {
          if (record.type !== DnsType.HTTPS || record.rdata.kind !== "https") return record;
          let value = record.rdata.value;
          if (rewrite.ipv4hint) value = upsertSvcParam(value, SvcParamKey.IPV4HINT, Uint8Array.from(rewrite.ipv4hint.flatMap(parseIpv4Parts)));
          if (rewrite.ipv6hint) value = upsertSvcParam(value, SvcParamKey.IPV6HINT, Uint8Array.from(rewrite.ipv6hint.flatMap(parseIpv6Parts)));
          return { ...record, rdata: { kind: "https", value } };
        }),
      };
    }
  }
  return response;
}

function parseIpv4Parts(value: string): number[] {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return [];
  return parts;
}

function parseIpv6Parts(value: string): number[] {
  try {
    const halves = value.split("::");
    if (halves.length > 2) return [];
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const groups = [...left, ...Array.from({ length: 8 - left.length - right.length }, () => "0"), ...right];
    if (groups.length !== 8) return [];
    return groups.flatMap((group) => {
      const number = Number.parseInt(group, 16);
      return [(number >>> 8) & 0xff, number & 0xff];
    });
  } catch {
    return [];
  }
}
