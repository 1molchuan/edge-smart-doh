import { canonicalName } from "./name";
import { parseIpv4, parseIpv6 } from "./packet";
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
