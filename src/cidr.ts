import { parseIpv4, parseIpv6 } from "./dns/packet";

export interface Cidr {
  bytes: Uint8Array;
  prefix: number;
}

export function parseCidr(value: string): Cidr {
  const [address, rawPrefix] = value.trim().split("/");
  if (!address || rawPrefix === undefined) throw new Error("Invalid CIDR");
  const bytes = address.includes(":") ? parseIpv6(address) : parseIpv4(address);
  const prefix = Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bytes.length * 8) throw new Error("Invalid CIDR prefix");
  return { bytes, prefix };
}

export function addressInCidr(address: string, cidr: Cidr): boolean {
  let bytes: Uint8Array;
  try {
    bytes = address.includes(":") ? parseIpv6(address) : parseIpv4(address);
  } catch {
    return false;
  }
  if (bytes.length !== cidr.bytes.length) return false;
  const fullBytes = Math.floor(cidr.prefix / 8);
  for (let index = 0; index < fullBytes; index += 1) if (bytes[index] !== cidr.bytes[index]) return false;
  const remaining = cidr.prefix % 8;
  if (remaining === 0) return true;
  const mask = (0xff << (8 - remaining)) & 0xff;
  return (bytes[fullBytes]! & mask) === (cidr.bytes[fullBytes]! & mask);
}

export function inAnyCidr(address: string, cidrs: Cidr[]): boolean {
  return cidrs.some((cidr) => addressInCidr(address, cidr));
}

export function parseCidrList(text: string): Cidr[] {
  return text.split(/\s+/).filter(Boolean).map(parseCidr);
}
