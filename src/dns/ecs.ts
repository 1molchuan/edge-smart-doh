import { canonicalName } from "./name";
import { encodeDnsPacket, parseDnsPacket, parseIpv4, parseIpv6 } from "./packet";
import { DnsType, type DnsPacket, type DnsRecord, type EdnsOption } from "./types";
import type { AppConfig } from "../config";

const ECS_OPTION_CODE = 8;

function truncate(bytes: Uint8Array, prefix: number): Uint8Array {
  const length = Math.ceil(prefix / 8);
  const output = bytes.slice(0, length);
  const remaining = prefix % 8;
  if (remaining !== 0 && output.length > 0) output[output.length - 1] = output[output.length - 1]! & (0xff << (8 - remaining));
  return output;
}

export interface EcsValue {
  family: 1 | 2;
  prefix: number;
  address: Uint8Array;
  identity: string;
}

export function makeEcsValue(ip: string, ipv4Prefix: number, ipv6Prefix: number): EcsValue | undefined {
  try {
    if (ip.includes(".")) {
      const prefix = Math.max(0, Math.min(32, ipv4Prefix));
      const address = truncate(parseIpv4(ip), prefix);
      return { family: 1, prefix, address, identity: `${Array.from(address).join(".")}/${prefix}` };
    }
    const prefix = Math.max(0, Math.min(128, ipv6Prefix));
    const address = truncate(parseIpv6(ip), prefix);
    const hex = Array.from(address, (value) => value.toString(16).padStart(2, "0")).join("");
    return { family: 2, prefix, address, identity: `${hex}/${prefix}` };
  } catch {
    return undefined;
  }
}

/** The ECS option the client sent itself, if any. */
export function clientEcsOption(packet: DnsPacket): EdnsOption | undefined {
  for (const record of packet.additionals) {
    if (record.rdata.kind !== "opt") continue;
    const option = record.rdata.options.find((item) => item.code === ECS_OPTION_CODE);
    if (option) return option;
  }
  return undefined;
}

/** The client sent ECS with a source prefix of 0: RFC 7871 §7.1.2 asks that no subnet be added for it. */
export function ecsOptedOut(packet: DnsPacket): boolean {
  const option = clientEcsOption(packet);
  return option !== undefined && option.data.length >= 3 && option.data[2] === 0;
}

/**
 * The subnet the client asked for in its own ECS option, cut to the server's own prefix length (it
 * never sends more of an address than it would of the client's own). Undefined when there is none,
 * an opt-out (source prefix 0), or one that does not parse: the server then picks the subnet itself.
 */
export function clientEcsValue(option: EdnsOption | undefined, ipv4Prefix: number, ipv6Prefix: number): EcsValue | undefined {
  if (!option || option.data.length < 4) return undefined;
  const family = (option.data[0]! << 8) | option.data[1]!;
  const source = option.data[2]!;
  const bytes = option.data.subarray(4);
  const width = family === 1 ? 4 : family === 2 ? 16 : 0;
  if (width === 0 || source === 0 || source > width * 8 || bytes.length !== Math.ceil(source / 8)) return undefined;
  const full = new Uint8Array(width);
  full.set(bytes);
  const ip = family === 1
    ? Array.from(full).join(".")
    : Array.from({ length: 8 }, (_, index) => ((full[index * 2]! << 8) | full[index * 2 + 1]!).toString(16)).join(":");
  return makeEcsValue(ip, Math.min(source, ipv4Prefix), Math.min(source, ipv6Prefix));
}

/**
 * The response's EDNS made to match the query (RFC 7871 §7.2.2, RFC 6891): the server's own ECS is
 * not shown to a client that sent none; a client that sent one gets its own option back, with the
 * scope upstream gave the answer (never wider than the client's source prefix); and a query without
 * OPT gets no OPT, even though one was added upstream to carry the subnet.
 */
export function alignResponseEdns(wire: Uint8Array, query: DnsPacket): Uint8Array {
  const parsed = parseDnsPacket(wire);
  if (!parsed.additionals.some((record) => record.type === DnsType.OPT)) return wire;
  if (!query.additionals.some((record) => record.type === DnsType.OPT)) {
    return encodeDnsPacket({ ...parsed, additionals: parsed.additionals.filter((record) => record.type !== DnsType.OPT) });
  }
  const client = clientEcsOption(query);
  const additionals = parsed.additionals.map((record) => {
    if (record.rdata.kind !== "opt") return record;
    const upstream = record.rdata.options.find((item) => item.code === ECS_OPTION_CODE);
    const options = record.rdata.options.filter((item) => item.code !== ECS_OPTION_CODE);
    if (client && client.data.length >= 4) {
      const echo = Uint8Array.from(client.data);
      echo[3] = Math.min(upstream && upstream.data.length >= 4 ? upstream.data[3]! : 0, echo[2]!);
      options.push({ code: ECS_OPTION_CODE, data: echo });
    }
    return { ...record, rdata: { kind: "opt" as const, options } };
  });
  return encodeDnsPacket({ ...parsed, additionals });
}

function encodeEcs(value: EcsValue): Uint8Array {
  const output = new Uint8Array(4 + value.address.length);
  const view = new DataView(output.buffer);
  view.setUint16(0, value.family);
  output[2] = value.prefix;
  output[3] = 0;
  output.set(value.address, 4);
  return output;
}

export function domainMatches(name: string, patterns: string[]): boolean {
  const domain = canonicalName(name);
  return patterns.some((raw) => {
    const pattern = canonicalName(raw.replace(/^\*\./, "."));
    return pattern.startsWith(".") ? domain.endsWith(pattern) || domain === pattern.slice(1) : domain === pattern;
  });
}

export function shouldUseEcs(packet: DnsPacket, config: AppConfig, ruleOverride?: boolean): boolean {
  if (ruleOverride !== undefined) return ruleOverride;
  if (config.ecsMode === "off") return false;
  if (config.ecsMode === "always") return true;
  const question = packet.questions[0];
  return question ? domainMatches(question.name, config.ecsDomains) : false;
}

export function addEcs(packet: DnsPacket, value: EcsValue): DnsPacket {
  const options: EdnsOption[] = [{ code: ECS_OPTION_CODE, data: encodeEcs(value) }];
  const additionals = packet.additionals.map((record) => {
    if (record.type !== DnsType.OPT || record.rdata.kind !== "opt") return record;
    return {
      ...record,
      rdata: { kind: "opt" as const, options: [...record.rdata.options.filter((item) => item.code !== ECS_OPTION_CODE), ...options] },
    };
  });
  if (!additionals.some((record) => record.type === DnsType.OPT)) {
    const opt: DnsRecord = { name: "", type: DnsType.OPT, class: 1232, ttl: 0, rdata: { kind: "opt", options } };
    additionals.push(opt);
  }
  return { ...packet, additionals };
}

export function removeEcs(packet: DnsPacket): DnsPacket {
  const additionals = packet.additionals.map((record) => {
    if (record.type !== DnsType.OPT || record.rdata.kind !== "opt") return record;
    return { ...record, rdata: { kind: "opt" as const, options: record.rdata.options.filter((item) => item.code !== ECS_OPTION_CODE) } };
  });
  return { ...packet, additionals };
}

function routableV4(bytes: Uint8Array): boolean {
  const [a = 0, b = 0] = bytes;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false; // multicast, reserved, broadcast
  return true;
}

function routableV6(bytes: Uint8Array): boolean {
  if (bytes.slice(0, 15).every((value) => value === 0) && bytes[15]! <= 1) return false; // :: and ::1
  if (bytes[0] === 0xff) return false; // multicast
  if ((bytes[0]! & 0xfe) === 0xfc) return false; // ULA fc00::/7
  if (bytes[0] === 0xfe && (bytes[1]! & 0xc0) === 0x80) return false; // link-local
  return true;
}

/**
 * Whether an address can stand for a client on the public internet. A loopback or RFC 1918 address
 * cannot: public resolvers reject ECS built from it (dns.google answers REFUSED), so behind a home
 * router every LAN client would fail Chinese-site queries outright. IPv4-mapped IPv6 counts as its
 * IPv4; anything unparseable counts as non-routable (no ECS rather than a broken one).
 */
export function isGloballyRoutable(ip: string): boolean {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return isGloballyRoutable(mapped[1]!);
  try {
    return ip.includes(".") ? routableV4(parseIpv4(ip)) : routableV6(parseIpv6(ip));
  } catch {
    return false;
  }
}

/**
 * The address ECS is built from: the client's own, the configured fallback subnet when the client is
 * known to sit outside every mainland operator (a non-routable LAN address always is — no ISP table
 * needed), or none — a non-routable client address must never become the ECS source, it would turn
 * every Chinese-site query into a REFUSED SERVFAIL instead of a plain overseas answer.
 */
export function ecsSourceIp(ip: string | undefined, fallback: string | undefined, clientOutsideOperators: boolean): string | undefined {
  if (!ip) return undefined;
  const routable = isGloballyRoutable(ip);
  if (fallback && (!routable || clientOutsideOperators)) return fallback;
  return routable ? ip : undefined;
}
