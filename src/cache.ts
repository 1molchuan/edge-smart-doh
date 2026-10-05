import { canonicalName } from "./dns/name";
import { encodeDnsPacket, getResponseTtl, parseDnsPacket, patchTransactionId } from "./dns/packet";
import { DnsType, type DnsPacket } from "./dns/types";
import type { AppConfig } from "./config";
import { matchCache } from "./cache-api";

export interface CacheIdentity {
  key: Request;
  transactionId: number;
  text: string;
}

export type CacheState = "fresh" | "refresh" | "stale";

export interface CacheHit {
  packet: Uint8Array;
  /** fresh: serve as-is; refresh: serve, then revalidate in the background; stale: expired, only use if upstream fails (HTTPS: serve, then revalidate). */
  state: CacheState;
}

const EXPIRES_HEADER = "X-DNS-Expires";
const ORIGINAL_TTL_HEADER = "X-DNS-TTL";
/** TTL presented to clients when serving expired data, as recommended by RFC 8767 §4. */
const STALE_RESPONSE_TTL = 30;

function hasDnssecOk(packet: DnsPacket): boolean {
  return packet.additionals.some((record) => record.type === DnsType.OPT && (record.ttl & 0x8000) !== 0);
}

export function normalizedCacheIdentity(query: DnsPacket, ecsIdentity: string, variant = "default"): CacheIdentity {
  if (query.questions.length !== 1) throw new Error("Exactly one DNS question is required");
  const question = query.questions[0]!;
  const text = [
    canonicalName(question.name),
    question.type,
    question.class,
    `do=${hasDnssecOk(query) ? 1 : 0}`,
    `cd=${(query.header.flags & 0x0010) !== 0 ? 1 : 0}`,
    `ecs=${ecsIdentity || "none"}`,
    `variant=${variant}`,
  ].join("|");
  const key = new Request(`https://doh-cache.invalid/${encodeURIComponent(text)}`, { method: "GET" });
  return { key, transactionId: query.header.id, text };
}

let rotation = 0;

/**
 * Rotate the starting point of the A/AAAA answer set so clients that always dial the first
 * address (or hit a dead one and give up) spread across the pool. Applied on every serve,
 * including cache hits, so the cached byte order does not pin the whole TTL to one address.
 * Records of other types keep their position; CNAME chains stay ahead of the addresses.
 */
export function rotateAddressRecords(packet: Uint8Array): Uint8Array {
  const parsed = parseDnsPacket(packet);
  const addresses = parsed.answers.filter((record) => record.type === DnsType.A || record.type === DnsType.AAAA);
  if (addresses.length < 2) return packet;
  rotation = (rotation + 1) >>> 0;
  const perType = new Map<number, DnsPacket["answers"]>();
  for (const record of addresses) perType.set(record.type, [...(perType.get(record.type) ?? []), record]);
  const rotated = new Map<number, DnsPacket["answers"]>();
  for (const [type, records] of perType) {
    const offset = rotation % records.length;
    rotated.set(type, [...records.slice(offset), ...records.slice(0, offset)]);
  }
  const cursor = new Map<number, number>();
  const answers = parsed.answers.map((record) => {
    const list = rotated.get(record.type);
    if (!list) return record;
    const index = cursor.get(record.type) ?? 0;
    cursor.set(record.type, index + 1);
    return list[index]!;
  });
  return encodeDnsPacket({ ...parsed, answers });
}

/** Each record's TTL less the seconds the answer has sat in the cache (at least 1), as a resolver should. */
function aged(packet: Uint8Array, elapsed: number): Uint8Array {
  if (elapsed < 1) return packet;
  const parsed = parseDnsPacket(packet);
  const patch = (records: DnsPacket["answers"]) => records.map((record) => (record.type === DnsType.OPT ? record : { ...record, ttl: Math.max(1, record.ttl - elapsed) }));
  return encodeDnsPacket({
    ...parsed,
    answers: patch(parsed.answers),
    authorities: patch(parsed.authorities),
    additionals: patch(parsed.additionals),
  });
}

function withTtl(packet: Uint8Array, ttl: number): Uint8Array {
  const parsed = parseDnsPacket(packet);
  const patch = (records: DnsPacket["answers"]) => records.map((record) => (record.type === DnsType.OPT ? record : { ...record, ttl }));
  return encodeDnsPacket({
    ...parsed,
    answers: patch(parsed.answers),
    authorities: patch(parsed.authorities),
    additionals: patch(parsed.additionals),
  });
}

export async function readCache(cache: Cache, identity: CacheIdentity, config: AppConfig): Promise<CacheHit | undefined> {
  const hit = await matchCache(cache, identity.key);
  if (!hit) return undefined;
  const expires = Number(hit.headers.get(EXPIRES_HEADER));
  const originalTtl = Number(hit.headers.get(ORIGINAL_TTL_HEADER));
  const packet = new Uint8Array(await hit.arrayBuffer());
  const now = Date.now();
  if (!Number.isFinite(expires) || !Number.isFinite(originalTtl)) {
    return { packet: patchTransactionId(packet, identity.transactionId), state: "fresh" };
  }
  const remaining = (expires - now) / 1000;
  if (remaining <= 0) {
    if (config.cacheStaleTtl <= 0 || -remaining > config.cacheStaleTtl) return undefined;
    return { packet: patchTransactionId(withTtl(packet, STALE_RESPONSE_TTL), identity.transactionId), state: "stale" };
  }
  const state: CacheState = config.cachePrefetchPercent > 0 && remaining <= originalTtl * (config.cachePrefetchPercent / 100) ? "refresh" : "fresh";
  let served: Uint8Array = packet;
  try {
    served = aged(packet, Math.floor(originalTtl - remaining));
  } catch {
    // A packet we cannot re-encode is served with its stored TTLs.
  }
  return { packet: patchTransactionId(served, identity.transactionId), state };
}

export async function writeCache(
  cache: Cache,
  identity: CacheIdentity,
  response: Uint8Array,
  config: AppConfig,
): Promise<number> {
  const parsed = parseDnsPacket(response);
  const ttl = getResponseTtl(parsed, config.cacheMinTtl, config.cacheMaxTtl, config.negativeCacheMaxTtl);
  if (ttl <= 0) return 0;
  const normalized = patchTransactionId(response, 0);
  await cache.put(
    identity.key,
    new Response(Uint8Array.from(normalized).buffer, {
      headers: {
        "Content-Type": "application/dns-message",
        // Keep the entry around past its DNS TTL so it can be served stale if refresh fails.
        "Cache-Control": `public, max-age=${ttl + config.cacheStaleTtl}`,
        [EXPIRES_HEADER]: String(Date.now() + ttl * 1000),
        [ORIGINAL_TTL_HEADER]: String(ttl),
      },
    }),
  );
  return ttl;
}
