import { ECS_OPTION_CODE, ecsEcho, responseEcsScope, type ClientEcs } from "./ecs";
import { encodeDnsPacket, parseDnsPacket } from "./packet";
import { DnsType, type DnsPacket, type DnsRecord, type EdnsOption } from "./types";

const PADDING_OPTION_CODE = 12;
/** RFC 8467 §4.1: a responder pads to a multiple of 468 bytes. */
const PADDING_BLOCK = 468;
const DO_FLAG = 0x8000;
const UDP_PAYLOAD_SIZE = 1232;

/**
 * The OPT record a stored answer keeps: each client gets its own (fitEdns), so only upstream's ECS
 * option, which carries the answer's scope, is worth keeping, not padding sized for whichever query
 * happened to fill the cache.
 */
export function storedEdns(packet: DnsPacket): DnsPacket {
  const opt = packet.additionals.find((record) => record.type === DnsType.OPT);
  if (!opt || opt.rdata.kind !== "opt") return packet;
  const rest = packet.additionals.filter((record) => record.type !== DnsType.OPT);
  const ecs = opt.rdata.options.filter((option) => option.code === ECS_OPTION_CODE);
  if (ecs.length === 0) return { ...packet, additionals: rest };
  return { ...packet, additionals: [...rest, { ...opt, class: UDP_PAYLOAD_SIZE, ttl: (opt.ttl & 0xff000000) >>> 0, rdata: { kind: "opt", options: ecs } }] };
}

/**
 * The answer's OPT record rebuilt for this query, whatever upstream, or the query that filled the
 * cache, had in it: none for a query without OPT (RFC 6891 §7), and one for a query with OPT (§6.1.1)
 * carrying the query's DO bit, the client's own ECS only when it sent one (RFC 7871 §7.2.2; the
 * scope is upstream's, never wider than the client's source prefix), and padding to a 468-byte
 * block when the query was padded (RFC 8467), so the answer's length does not give the name away.
 */
export function fitEdns(wire: Uint8Array, query: DnsPacket, client: ClientEcs | undefined): Uint8Array {
  const queryOpt = query.additionals.find((record) => record.type === DnsType.OPT);
  const parsed = parseDnsPacket(wire);
  const upstream = parsed.additionals.find((record) => record.type === DnsType.OPT);
  const additionals = parsed.additionals.filter((record) => record.type !== DnsType.OPT);
  if (!queryOpt) return upstream ? encodeDnsPacket({ ...parsed, additionals }) : wire;
  const options: EdnsOption[] = client ? [ecsEcho(client, responseEcsScope(upstream))] : [];
  // Extended rcode (upper TTL byte) kept from upstream; version 0; DO as the query had it.
  const ttl = ((((upstream?.ttl ?? 0) >>> 24) << 24) | (queryOpt.ttl & DO_FLAG)) >>> 0;
  const opt = (extra: EdnsOption[]): DnsRecord => ({ name: "", type: DnsType.OPT, class: UDP_PAYLOAD_SIZE, ttl, rdata: { kind: "opt", options: [...options, ...extra] } });
  const packet = encodeDnsPacket({ ...parsed, additionals: [...additionals, opt([])] });
  const padded = queryOpt.rdata.kind === "opt" && queryOpt.rdata.options.some((option) => option.code === PADDING_OPTION_CODE);
  if (!padded) return packet;
  const length = (PADDING_BLOCK - ((packet.length + 4) % PADDING_BLOCK)) % PADDING_BLOCK;
  return encodeDnsPacket({ ...parsed, additionals: [...additionals, opt([{ code: PADDING_OPTION_CODE, data: new Uint8Array(length) }])] });
}
