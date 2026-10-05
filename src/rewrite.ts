import { inAnyCidr, parseCidrList, type Cidr } from "./cidr";
import { matchCache } from "./cache-api";
import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";
import { SvcParamKey, upsertSvcParam } from "./dns/https-rr";
import { encodeDnsPacket, parseDnsPacket, parseIpv4, parseIpv6 } from "./dns/packet";
import { DnsType, type DnsPacket, type DnsRecord, type HttpsRecord } from "./dns/types";
import { queryUpstreams } from "./upstream";

export interface CloudflareRanges {
  ipv4: Cidr[];
  ipv6: Cidr[];
}

export interface ResolvedAddresses {
  ipv4: string[];
  ipv6: string[];
}

function lookupQuery(name: string, type: number): Uint8Array {
  return encodeDnsPacket({
    header: { id: 0x4543, flags: 0x0100, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
    questions: [{ name, type, class: 1 }],
    answers: [],
    authorities: [],
    additionals: [],
  });
}

function addressesFromPacket(packet: DnsPacket): ResolvedAddresses {
  const ipv4: string[] = [];
  const ipv6: string[] = [];
  for (const record of packet.answers) {
    if (record.rdata.kind === "a") ipv4.push(record.rdata.address);
    if (record.rdata.kind === "aaaa") ipv6.push(record.rdata.address);
  }
  return { ipv4: [...new Set(ipv4)].slice(0, 16), ipv6: [...new Set(ipv6)].slice(0, 16) };
}

export async function resolveDomainAddresses(name: string, config: AppConfig, cache: Cache): Promise<ResolvedAddresses> {
  const key = new Request(`https://doh-config.invalid/addresses/${encodeURIComponent(name.toLowerCase())}`);
  const cached = await matchCache(cache, key);
  if (cached) {
    try {
      const value = await cached.json() as ResolvedAddresses;
      if (Array.isArray(value.ipv4) && Array.isArray(value.ipv6)) return value;
    } catch {
      // Ignore a malformed cache entry and refresh it.
    }
  }
  const results = await Promise.allSettled([
    queryUpstreams(lookupQuery(name, DnsType.A), config),
    queryUpstreams(lookupQuery(name, DnsType.AAAA), config),
  ]);
  const merged: ResolvedAddresses = { ipv4: [], ipv6: [] };
  for (const result of results) {
    if (result.status !== "fulfilled") continue;
    const addresses = addressesFromPacket(parseDnsPacket(result.value.packet));
    merged.ipv4.push(...addresses.ipv4);
    merged.ipv6.push(...addresses.ipv6);
  }
  merged.ipv4 = [...new Set(merged.ipv4)].slice(0, 16);
  merged.ipv6 = [...new Set(merged.ipv6)].slice(0, 16);
  if (merged.ipv4.length === 0 && merged.ipv6.length === 0) throw new Error(`No addresses found for ${name}`);
  await cache.put(key, new Response(JSON.stringify(merged), { headers: { "Cache-Control": "public, max-age=300" } }));
  return merged;
}

async function loadRangeUrl(url: string, keyName: string, cache: Cache): Promise<string> {
  const key = new Request(`https://doh-config.invalid/${keyName}`);
  const cached = await matchCache(cache, key);
  if (cached) return cached.text();
  const response = await fetch(url, { headers: { "Cache-Control": "no-cache" } });
  if (!response.ok) throw new Error(`CIDR fetch failed: ${response.status}`);
  const text = await response.text();
  parseCidrList(text);
  await cache.put(key, new Response(text, { headers: { "Cache-Control": "public, max-age=86400" } }));
  return text;
}

export async function loadCloudflareRanges(config: AppConfig, cache: Cache): Promise<CloudflareRanges> {
  const [ipv4, ipv6] = await Promise.all([
    loadRangeUrl(config.cfIpv4Url, "cf-ipv4", cache),
    loadRangeUrl(config.cfIpv6Url, "cf-ipv6", cache),
  ]);
  return { ipv4: parseCidrList(ipv4), ipv6: parseCidrList(ipv6) };
}

function hintAddresses(value: Uint8Array, size: 4 | 16): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let offset = 0; offset + size <= value.length; offset += size) out.push(value.subarray(offset, offset + size));
  return out;
}

function ipv4Text(bytes: Uint8Array): string {
  return Array.from(bytes).join(".");
}

function ipv6Text(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Array.from({ length: 8 }, (_, group) => view.getUint16(group * 2).toString(16)).join(":");
}

function packAddresses(addresses: string[], parse: (address: string) => Uint8Array): Uint8Array {
  const parts = addresses.map(parse);
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let cursor = 0;
  for (const part of parts) {
    output.set(part, cursor);
    cursor += part.length;
  }
  return output;
}

/**
 * Keep HTTPS/SVCB ipv4hint/ipv6hint consistent with the rewritten A/AAAA answers. Chrome ignores
 * hints, but Firefox and Safari may connect to them directly and would otherwise bypass the pool.
 */
function rewriteHttpsHints(record: HttpsRecord, ranges: CloudflareRanges, config: AppConfig): HttpsRecord | undefined {
  let value = record;
  let changed = false;
  const ipv4Hint = record.params.find((param) => param.key === SvcParamKey.IPV4HINT);
  if (ipv4Hint && hintAddresses(ipv4Hint.value, 4).some((hint) => inAnyCidr(ipv4Text(hint), ranges.ipv4))) {
    value = config.cfPreferredIpv4.length > 0
      ? upsertSvcParam(value, SvcParamKey.IPV4HINT, packAddresses(config.cfPreferredIpv4, parseIpv4))
      : { ...value, params: value.params.filter((param) => param.key !== SvcParamKey.IPV4HINT) };
    changed = true;
  }
  const ipv6Hint = record.params.find((param) => param.key === SvcParamKey.IPV6HINT);
  if (ipv6Hint && (config.cfDropAaaa || hintAddresses(ipv6Hint.value, 16).some((hint) => inAnyCidr(ipv6Text(hint), ranges.ipv6)))) {
    value = config.cfPreferredIpv6.length > 0 && !config.cfDropAaaa
      ? upsertSvcParam(value, SvcParamKey.IPV6HINT, packAddresses(config.cfPreferredIpv6, parseIpv6))
      : { ...value, params: value.params.filter((param) => param.key !== SvcParamKey.IPV6HINT) };
    changed = true;
  }
  return changed ? value : undefined;
}

export function rewriteCloudflareAddresses(packet: DnsPacket, ranges: CloudflareRanges, config: AppConfig): DnsPacket {
  if (!config.cfRewriteEnabled) return packet;
  let changed = false;
  const answers: DnsRecord[] = [];
  // A name's Cloudflare addresses are replaced by the whole pool, once, where the first of them
  // stood. Upstream answers carry two A records, and swapping them one for one served every client
  // the pool's first two IPs only (2026-09-28: linux.do and chatgpt.com got the same two); the whole
  // pool, rotated at serve time (rotateAddressRecords), spreads clients over it and leaves each
  // browser more addresses to fall back on.
  const expanded = new Set<string>();
  for (const record of packet.answers) {
    if (record.rdata.kind === "a" && config.cfPreferredIpv4.length > 0 && inAnyCidr(record.rdata.address, ranges.ipv4)) {
      changed = true;
      const key = `a|${record.name.toLowerCase()}`;
      if (!expanded.has(key)) {
        expanded.add(key);
        for (const address of config.cfPreferredIpv4) {
          parseIpv4(address);
          answers.push({ ...record, rdata: { kind: "a", address } });
        }
      }
      continue;
    }
    if (record.rdata.kind === "aaaa" && inAnyCidr(record.rdata.address, ranges.ipv6)) {
      if (config.cfDropAaaa) {
        changed = true;
        continue;
      }
      if (config.cfPreferredIpv6.length > 0) {
        changed = true;
        const key = `aaaa|${record.name.toLowerCase()}`;
        if (!expanded.has(key)) {
          expanded.add(key);
          for (const address of config.cfPreferredIpv6) {
            parseIpv6(address);
            answers.push({ ...record, rdata: { kind: "aaaa", address } });
          }
        }
        continue;
      }
    }
    if (record.rdata.kind === "https") {
      const rewritten = rewriteHttpsHints(record.rdata.value, ranges, config);
      if (rewritten) {
        changed = true;
        answers.push({ ...record, rdata: { kind: "https", value: rewritten } });
        continue;
      }
    }
    answers.push(record);
  }
  return changed ? { ...packet, answers } : packet;
}

export function responseUsesCloudflare(addresses: ResolvedAddresses, ranges: CloudflareRanges): boolean {
  return addresses.ipv4.some((address) => inAnyCidr(address, ranges.ipv4))
    || addresses.ipv6.some((address) => inAnyCidr(address, ranges.ipv6));
}

/**
 * Whether Cloudflare serves `name` even when its current answer points at another CDN. Multi-CDN
 * hosts (X's twimg.com, t.co, ...) are steered between Cloudflare and Fastly per resolver, but a
 * host onboarded to Cloudflare via CNAME setup always has `<name>.cdn.cloudflare.net`. Hosts that
 * Cloudflare does not serve (abs-0.twimg.com, ton.twimg.com) have no such record.
 *
 * The record's existence is the signal, not its addresses: a BYOIP customer's record points at the
 * customer's own prefix, outside Cloudflare's published ranges (claude.ai → 160.79.104.10), yet
 * Cloudflare terminates it and routes it from any of its anycast IPs. cdn.cloudflare.net has no
 * wildcard (checked 2026-09-26: non-Cloudflare and nonexistent names return no record).
 */
export async function servedByCloudflare(name: string, config: AppConfig, cache: Cache): Promise<boolean> {
  const key = new Request(`https://doh-config.invalid/cf-served/${encodeURIComponent(name.toLowerCase())}`);
  const cached = await matchCache(cache, key);
  if (cached) return (await cached.text()) === "1";
  let served = false;
  try {
    const target = await resolveDomainAddresses(`${name.replace(/\.$/, "")}.cdn.cloudflare.net`, config, cache);
    served = target.ipv4.length > 0 || target.ipv6.length > 0;
  } catch {
    served = false;
  }
  await cache.put(key, new Response(served ? "1" : "0", { headers: { "Cache-Control": "public, max-age=300" } }));
  return served;
}

export function rewriteXAddresses(packet: DnsPacket, query: DnsPacket, config: AppConfig): DnsPacket {
  const question = query.questions[0];
  if (!question || !domainMatches(question.name, config.xDomains)) return packet;
  return pinAddresses(packet, query, config.cfPreferredIpv4);
}

/**
 * Replace the answer's addresses with `ipv4` whatever upstream returned (A) and drop IPv6 (AAAA),
 * for hosts whose endpoint this server chooses: X hosts pinned to the Cloudflare pool, site and
 * GitHub hosts pinned to their measured pools. HTTPS answers are left to the caller. `maxTtl`
 * caps the served TTL (the relay pins at 60 so a withdrawn relay stops being served quickly).
 */
export function pinAddresses(packet: DnsPacket, query: DnsPacket, ipv4: string[], maxTtl?: number): DnsPacket {
  const question = query.questions[0];
  if (!question) return packet;
  if (question.type === DnsType.AAAA) {
    const answers = packet.answers.filter((record) => record.type !== DnsType.AAAA);
    return answers.length === packet.answers.length ? packet : { ...packet, answers };
  }
  if (question.type !== DnsType.A || ipv4.length === 0) return packet;
  const existing = packet.answers.filter((record) => record.type === DnsType.A);
  let ttl = existing.length > 0 ? Math.min(...existing.map((record) => record.ttl)) : 60;
  if (maxTtl !== undefined) ttl = Math.min(ttl, maxTtl);
  const owner = existing[0]?.name ?? question.name;
  const replacements: DnsRecord[] = ipv4.map((address) => {
    parseIpv4(address);
    return { name: owner, type: DnsType.A, class: 1, ttl, rdata: { kind: "a", address } };
  });
  return { ...packet, answers: [...packet.answers.filter((record) => record.type !== DnsType.A), ...replacements] };
}

/** Point every HTTPS record's address hints at `ipv4` (dropping IPv6 hints), for pinned hosts. */
export function pinHttpsHints(packet: DnsPacket, ipv4: string[]): DnsPacket {
  let changed = false;
  const answers = packet.answers.map((record) => {
    if (record.rdata.kind !== "https") return record;
    const params = record.rdata.value.params.filter((param) => param.key !== SvcParamKey.IPV6HINT);
    const hasV4Hint = params.some((param) => param.key === SvcParamKey.IPV4HINT);
    if (!hasV4Hint && params.length === record.rdata.value.params.length) return record;
    let value: HttpsRecord = { ...record.rdata.value, params };
    if (hasV4Hint) value = upsertSvcParam(value, SvcParamKey.IPV4HINT, packAddresses(ipv4, parseIpv4));
    changed = true;
    return { ...record, rdata: { kind: "https" as const, value } };
  });
  return changed ? { ...packet, answers } : packet;
}

/**
 * Prepare an HTTPS record for a relayed name (see the relay strategy): address hints point at the
 * relay, ECH is dropped (the relay routes by the plaintext SNI, which ECH hides behind its public
 * name) and ALPN is pinned to h2 (the relay forwards TCP only, so QUIC must not be offered).
 */
export function relayHttpsCleanup(packet: DnsPacket, ipv4: string[]): DnsPacket {
  const hints = packAddresses(ipv4, parseIpv4);
  const alpnH2 = Uint8Array.from([2, 0x68, 0x32]); // length-prefixed "h2"
  const answers = packet.answers.map((record): DnsRecord => {
    if (record.rdata.kind !== "https") return record;
    const touches =
      record.rdata.value.params.some((param) =>
        param.key === SvcParamKey.ECH || param.key === SvcParamKey.ALPN || param.key === SvcParamKey.IPV4HINT || param.key === SvcParamKey.IPV6HINT
      );
    if (!touches) return record;
    const stripped = record.rdata.value.params.filter((param) => param.key !== SvcParamKey.ECH && param.key !== SvcParamKey.IPV6HINT);
    let value: HttpsRecord = { ...record.rdata.value, params: stripped };
    value = upsertSvcParam(value, SvcParamKey.ALPN, alpnH2);
    value = upsertSvcParam(value, SvcParamKey.IPV4HINT, hints);
    return { ...record, rdata: { kind: "https" as const, value } };
  });
  return { ...packet, answers };
}

/**
 * Collapse the answer's CNAME chain so every record is owned by the query name. Chromium uses an
 * HTTPS record (and so ECH) only when the A/AAAA records sit at the same canonical name as the
 * HTTPS target; a CNAME'd host such as abs.twimg.com → twimg.twitter.map.fastly.net would
 * otherwise get its ECH config silently dropped and connect with a plaintext SNI. Applied to every
 * answer type of an ECH host so all three agree on the query name.
 */
export function flattenAliases(packet: DnsPacket): DnsPacket {
  const question = packet.questions[0];
  if (!question) return packet;
  const chain = new Set([question.name.toLowerCase()]);
  let current = question.name.toLowerCase();
  let aliasTtl = Infinity;
  for (let hop = 0; hop < 16; hop += 1) {
    const alias = packet.answers.find((record) => record.type === DnsType.CNAME && record.rdata.kind === "name" && record.name.toLowerCase() === current);
    if (!alias || alias.rdata.kind !== "name") break;
    aliasTtl = Math.min(aliasTtl, alias.ttl);
    current = alias.rdata.name.toLowerCase();
    chain.add(current);
  }
  if (chain.size === 1) return packet;
  const answers = packet.answers
    .filter((record) => !(record.type === DnsType.CNAME && chain.has(record.name.toLowerCase())))
    .map((record) => (chain.has(record.name.toLowerCase()) ? { ...record, name: question.name, ttl: Math.min(record.ttl, aliasTtl) } : record));
  return { ...packet, answers };
}

export function validatedEchConfig(base64: string | undefined): Uint8Array | undefined {
  if (!base64 || base64.length > 21848) return undefined;
  try {
    const binary = atob(base64.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (bytes.length < 6 || bytes.length > 16384) return undefined;
    const declared = (bytes[0]! << 8) | bytes[1]!;
    if (declared !== bytes.length - 2) return undefined;
    const firstConfigLength = (bytes[4]! << 8) | bytes[5]!;
    if (firstConfigLength + 6 > bytes.length) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

function validEchBytes(bytes: Uint8Array): boolean {
  if (bytes.length < 6 || bytes.length > 16384) return false;
  const declared = (bytes[0]! << 8) | bytes[1]!;
  const firstConfigLength = (bytes[4]! << 8) | bytes[5]!;
  return declared === bytes.length - 2 && firstConfigLength + 6 <= bytes.length;
}

export async function resolveEchConfig(name: string, config: AppConfig, cache: Cache): Promise<Uint8Array> {
  const key = new Request(`https://doh-config.invalid/ech/${encodeURIComponent(name.toLowerCase())}`);
  const cached = await matchCache(cache, key);
  if (cached) {
    const value = new Uint8Array(await cached.arrayBuffer());
    if (validEchBytes(value)) return value;
  }
  const result = await queryUpstreams(lookupQuery(name, DnsType.HTTPS), config);
  const response = parseDnsPacket(result.packet);
  for (const record of response.answers) {
    if (record.type !== DnsType.HTTPS || record.rdata.kind !== "https") continue;
    const ech = record.rdata.value.params.find((param) => param.key === SvcParamKey.ECH)?.value;
    if (!ech || !validEchBytes(ech)) continue;
    await cache.put(key, new Response(Uint8Array.from(ech).buffer, { headers: { "Cache-Control": "public, max-age=3600" } }));
    return ech;
  }
  throw new Error(`No ECHConfigList found for ${name}`);
}

function encodedAlpn(protocols: string[]): Uint8Array {
  const bytes: number[] = [];
  const encoder = new TextEncoder();
  for (const protocol of protocols) {
    const value = encoder.encode(protocol);
    if (value.length === 0 || value.length > 255) continue;
    bytes.push(value.length, ...value);
  }
  return Uint8Array.from(bytes);
}

/**
 * Put `ech` into the HTTPS answer, synthesizing a record when upstream returned none. `alpn`, when
 * given, also replaces the ALPN of upstream records; otherwise their ALPN is kept and a synthetic
 * record offers only h2. Advertising h3 makes Chromium try QUIC first, and QUIC+ECH fails for X
 * (the server rejects it) and Meta (UDP is black-holed in mainland China), so h3 is only kept where
 * the origin itself published it.
 */
export function injectEchBytes(packet: DnsPacket, ech: Uint8Array, alpn?: string[]): DnsPacket {
  if (!validEchBytes(ech) || packet.questions[0]?.type !== DnsType.HTTPS) return packet;
  let changed = false;
  const answers = packet.answers.map((record) => {
    if (record.type !== DnsType.HTTPS || record.rdata.kind !== "https") return record;
    changed = true;
    let value = upsertSvcParam(record.rdata.value, SvcParamKey.ECH, ech);
    if (alpn) value = upsertSvcParam(value, SvcParamKey.ALPN, encodedAlpn(alpn));
    return { ...record, rdata: { kind: "https" as const, value } };
  });
  if (changed) return { ...packet, answers };
  const question = packet.questions[0];
  if (!question) return packet;
  const synthetic: DnsRecord = {
    name: question.name,
    type: DnsType.HTTPS,
    class: 1,
    ttl: 300,
    rdata: {
      kind: "https",
      value: {
        priority: 1,
        target: "",
        params: [
          { key: SvcParamKey.ALPN, value: encodedAlpn(alpn ?? ["h2"]) },
          { key: SvcParamKey.ECH, value: ech.slice() },
        ],
      },
    },
  };
  return { ...packet, answers: [...packet.answers, synthetic] };
}

export function injectEch(packet: DnsPacket, config: AppConfig): DnsPacket {
  if (!config.echEnabled || !packet.questions[0] || !domainMatches(packet.questions[0].name, config.echDomains)) return packet;
  const ech = validatedEchConfig(config.echConfigBase64);
  if (!ech) return packet;
  return injectEchBytes(packet, ech);
}
