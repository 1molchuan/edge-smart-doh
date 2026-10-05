import { encodeHttpsRdata, parseHttpsRdata } from "./https-rr";
import { decodeName, encodeName } from "./name";
import { DnsType, type DnsPacket, type DnsQuestion, type DnsRecord, type EdnsOption, type ParsedRdata } from "./types";

const HEADER_LENGTH = 12;

class Writer {
  private readonly bytes: number[] = [];

  u8(value: number): void {
    this.bytes.push(value & 0xff);
  }

  u16(value: number): void {
    this.bytes.push((value >>> 8) & 0xff, value & 0xff);
  }

  u32(value: number): void {
    this.bytes.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  }

  data(value: Uint8Array): void {
    this.bytes.push(...value);
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }
}

function assertRemaining(packet: Uint8Array, offset: number, needed: number): void {
  if (offset < 0 || needed < 0 || offset + needed > packet.length) throw new Error("Truncated DNS packet");
}

function readQuestion(packet: Uint8Array, offset: number): { value: DnsQuestion; nextOffset: number } {
  const decoded = decodeName(packet, offset);
  assertRemaining(packet, decoded.nextOffset, 4);
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  return {
    value: {
      name: decoded.name,
      type: view.getUint16(decoded.nextOffset),
      class: view.getUint16(decoded.nextOffset + 2),
    },
    nextOffset: decoded.nextOffset + 4,
  };
}

function parseOptions(packet: Uint8Array, offset: number, length: number): EdnsOption[] {
  const end = offset + length;
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const options: EdnsOption[] = [];
  let cursor = offset;
  while (cursor < end) {
    assertRemaining(packet, cursor, 4);
    const code = view.getUint16(cursor);
    const optionLength = view.getUint16(cursor + 2);
    cursor += 4;
    if (cursor + optionLength > end) throw new Error("Truncated EDNS option");
    options.push({ code, data: packet.slice(cursor, cursor + optionLength) });
    cursor += optionLength;
  }
  return options;
}

function parseRdata(packet: Uint8Array, type: number, offset: number, length: number): ParsedRdata {
  assertRemaining(packet, offset, length);
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const end = offset + length;
  if (type === DnsType.A) {
    if (length !== 4) throw new Error("Invalid A RDATA");
    return { kind: "a", address: Array.from(packet.subarray(offset, end)).join(".") };
  }
  if (type === DnsType.AAAA) {
    if (length !== 16) throw new Error("Invalid AAAA RDATA");
    return {
      kind: "aaaa",
      address: Array.from({ length: 8 }, (_, index) => view.getUint16(offset + index * 2).toString(16)).join(":"),
    };
  }
  if (type === DnsType.CNAME || type === DnsType.NS || type === DnsType.PTR || type === 39) {
    const decoded = decodeName(packet, offset);
    if (decoded.nextOffset !== end) throw new Error("Invalid name RDATA length");
    return { kind: "name", name: decoded.name };
  }
  if (type === DnsType.MX) {
    if (length < 3) throw new Error("Invalid MX RDATA");
    const decoded = decodeName(packet, offset + 2);
    if (decoded.nextOffset !== end) throw new Error("Invalid MX RDATA length");
    return { kind: "mx", preference: view.getUint16(offset), exchange: decoded.name };
  }
  if (type === DnsType.SOA) {
    const mname = decodeName(packet, offset);
    const rname = decodeName(packet, mname.nextOffset);
    assertRemaining(packet, rname.nextOffset, 20);
    if (rname.nextOffset + 20 !== end) throw new Error("Invalid SOA RDATA length");
    return {
      kind: "soa",
      mname: mname.name,
      rname: rname.name,
      serial: view.getUint32(rname.nextOffset),
      refresh: view.getUint32(rname.nextOffset + 4),
      retry: view.getUint32(rname.nextOffset + 8),
      expire: view.getUint32(rname.nextOffset + 12),
      minimum: view.getUint32(rname.nextOffset + 16),
    };
  }
  if (type === DnsType.SRV) {
    if (length < 7) throw new Error("Invalid SRV RDATA");
    const target = decodeName(packet, offset + 6);
    if (target.nextOffset !== end) throw new Error("Invalid SRV RDATA length");
    return {
      kind: "srv",
      priority: view.getUint16(offset),
      weight: view.getUint16(offset + 2),
      port: view.getUint16(offset + 4),
      target: target.name,
    };
  }
  if (type === DnsType.HTTPS || type === 64) {
    return { kind: "https", value: parseHttpsRdata(packet, offset, length) };
  }
  if (type === DnsType.OPT) return { kind: "opt", options: parseOptions(packet, offset, length) };
  return { kind: "raw", data: packet.slice(offset, end) };
}

function readRecord(packet: Uint8Array, offset: number): { value: DnsRecord; nextOffset: number } {
  const decoded = decodeName(packet, offset);
  assertRemaining(packet, decoded.nextOffset, 10);
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const type = view.getUint16(decoded.nextOffset);
  const recordClass = view.getUint16(decoded.nextOffset + 2);
  const ttl = view.getUint32(decoded.nextOffset + 4);
  const length = view.getUint16(decoded.nextOffset + 8);
  const rdataOffset = decoded.nextOffset + 10;
  assertRemaining(packet, rdataOffset, length);
  return {
    value: { name: decoded.name, type, class: recordClass, ttl, rdata: parseRdata(packet, type, rdataOffset, length) },
    nextOffset: rdataOffset + length,
  };
}

export function parseDnsPacket(input: Uint8Array): DnsPacket {
  assertRemaining(input, 0, HEADER_LENGTH);
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const header = {
    id: view.getUint16(0),
    flags: view.getUint16(2),
    qdcount: view.getUint16(4),
    ancount: view.getUint16(6),
    nscount: view.getUint16(8),
    arcount: view.getUint16(10),
  };
  const totalRecords = header.qdcount + header.ancount + header.nscount + header.arcount;
  if (header.qdcount > 32 || totalRecords > 512) throw new Error("Unreasonable DNS record count");
  let offset = HEADER_LENGTH;
  const questions: DnsQuestion[] = [];
  const answers: DnsRecord[] = [];
  const authorities: DnsRecord[] = [];
  const additionals: DnsRecord[] = [];
  for (let index = 0; index < header.qdcount; index += 1) {
    const result = readQuestion(input, offset);
    questions.push(result.value);
    offset = result.nextOffset;
  }
  for (const [count, output] of [
    [header.ancount, answers],
    [header.nscount, authorities],
    [header.arcount, additionals],
  ] as const) {
    for (let index = 0; index < count; index += 1) {
      const result = readRecord(input, offset);
      output.push(result.value);
      offset = result.nextOffset;
    }
  }
  if (offset !== input.length) throw new Error("Trailing data in DNS packet");
  return { header, questions, answers, authorities, additionals };
}

function encodeOptions(options: EdnsOption[]): Uint8Array {
  const writer = new Writer();
  for (const option of options) {
    if (option.code < 0 || option.code > 0xffff || option.data.length > 0xffff) throw new Error("Invalid EDNS option");
    writer.u16(option.code);
    writer.u16(option.data.length);
    writer.data(option.data);
  }
  return writer.finish();
}

function encodeRdata(record: DnsRecord): Uint8Array {
  const { rdata } = record;
  if (rdata.kind === "a") return parseIpv4(rdata.address);
  if (rdata.kind === "aaaa") return parseIpv6(rdata.address);
  if (rdata.kind === "name") return encodeName(rdata.name);
  if (rdata.kind === "https") return encodeHttpsRdata(rdata.value);
  if (rdata.kind === "opt") return encodeOptions(rdata.options);
  if (rdata.kind === "raw") return rdata.data;
  const writer = new Writer();
  if (rdata.kind === "mx") {
    writer.u16(rdata.preference);
    writer.data(encodeName(rdata.exchange));
  } else if (rdata.kind === "soa") {
    writer.data(encodeName(rdata.mname));
    writer.data(encodeName(rdata.rname));
    writer.u32(rdata.serial);
    writer.u32(rdata.refresh);
    writer.u32(rdata.retry);
    writer.u32(rdata.expire);
    writer.u32(rdata.minimum);
  } else {
    writer.u16(rdata.priority);
    writer.u16(rdata.weight);
    writer.u16(rdata.port);
    writer.data(encodeName(rdata.target));
  }
  return writer.finish();
}

function encodeRecord(writer: Writer, record: DnsRecord): void {
  const data = encodeRdata(record);
  if (data.length > 0xffff) throw new Error("DNS RDATA too large");
  writer.data(encodeName(record.name));
  writer.u16(record.type);
  writer.u16(record.class);
  writer.u32(record.ttl);
  writer.u16(data.length);
  writer.data(data);
}

export function encodeDnsPacket(packet: DnsPacket): Uint8Array {
  const writer = new Writer();
  writer.u16(packet.header.id);
  writer.u16(packet.header.flags);
  writer.u16(packet.questions.length);
  writer.u16(packet.answers.length);
  writer.u16(packet.authorities.length);
  writer.u16(packet.additionals.length);
  for (const question of packet.questions) {
    writer.data(encodeName(question.name));
    writer.u16(question.type);
    writer.u16(question.class);
  }
  for (const record of [...packet.answers, ...packet.authorities, ...packet.additionals]) encodeRecord(writer, record);
  return writer.finish();
}

export function parseIpv4(address: string): Uint8Array {
  const parts = address.split(".");
  if (parts.length !== 4) throw new Error("Invalid IPv4 address");
  return Uint8Array.from(parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) throw new Error("Invalid IPv4 address");
    const value = Number(part);
    if (value > 255) throw new Error("Invalid IPv4 address");
    return value;
  }));
}

export function parseIpv6(address: string): Uint8Array {
  if (address.includes(".")) throw new Error("IPv4-mapped IPv6 is not supported");
  const halves = address.split("::");
  if (halves.length > 2) throw new Error("Invalid IPv6 address");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) throw new Error("Invalid IPv6 address");
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8) throw new Error("Invalid IPv6 address");
  const output = new Uint8Array(16);
  const view = new DataView(output.buffer);
  groups.forEach((group, index) => {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) throw new Error("Invalid IPv6 address");
    view.setUint16(index * 2, Number.parseInt(group, 16));
  });
  return output;
}

export function makeServfail(query: Uint8Array): Uint8Array {
  try {
    const parsed = parseDnsPacket(query);
    return encodeDnsPacket({
      header: { ...parsed.header, flags: 0x8000 | (parsed.header.flags & 0x7910) | 0x0080 | 2 },
      questions: parsed.questions,
      answers: [],
      authorities: [],
      additionals: [],
    });
  } catch {
    const output = new Uint8Array(12);
    if (query.length >= 2) output.set(query.subarray(0, 2));
    output[2] = 0x81;
    output[3] = 0x82;
    return output;
  }
}

/**
 * BADVERS (RFC 6891 §6.1.3) for a query with an EDNS version above 0, the only one spoken here: the
 * extended rcode 16 is header rcode 0 with 1 in the OPT record's upper TTL byte, and version 0.
 */
export function makeBadvers(query: DnsPacket): Uint8Array {
  return encodeDnsPacket({
    header: { ...query.header, flags: 0x8000 | (query.header.flags & 0x7910) | 0x0080 },
    questions: query.questions,
    answers: [],
    authorities: [],
    additionals: [{ name: "", type: DnsType.OPT, class: 1232, ttl: 1 << 24, rdata: { kind: "opt", options: [] } }],
  });
}

const lower = (byte: number) => (byte >= 0x41 && byte <= 0x5a ? byte | 0x20 : byte);

/**
 * The response with its question name spelled exactly as the query spelled it. Answers are cached
 * and shared case-insensitively, but a resolver using 0x20 case randomisation drops a reply whose
 * question differs in case from what it sent. Anything other than the same name is left alone.
 */
export function matchQuestionCase(response: Uint8Array, query: Uint8Array): Uint8Array {
  let offset = HEADER_LENGTH;
  for (;;) {
    const length = query[offset];
    if (length === undefined || length > 63 || response[offset] !== length) return response;
    if (length === 0) break;
    if (offset + 1 + length > query.length || offset + 1 + length > response.length) return response;
    for (let index = offset + 1; index <= offset + length; index++) {
      if (lower(query[index]!) !== lower(response[index]!)) return response;
    }
    offset += 1 + length;
  }
  const output = response.slice();
  output.set(query.subarray(HEADER_LENGTH, offset), HEADER_LENGTH);
  return output;
}

export function patchTransactionId(packet: Uint8Array, id: number): Uint8Array {
  if (packet.length < HEADER_LENGTH) throw new Error("Truncated DNS packet");
  const output = packet.slice();
  output[0] = (id >>> 8) & 0xff;
  output[1] = id & 0xff;
  return output;
}

export function getResponseTtl(packet: DnsPacket, minTtl: number, maxTtl: number, negativeMax: number): number {
  const rcode = packet.header.flags & 0x0f;
  if (rcode === 2) return 0;
  const answerTtls = packet.answers.filter((record) => record.type !== DnsType.OPT).map((record) => record.ttl);
  let ttl: number | undefined = answerTtls.length > 0 ? Math.min(...answerTtls) : undefined;
  if ((rcode === 3 || packet.answers.length === 0) && packet.authorities.length > 0) {
    const soa = packet.authorities.find((record) => record.rdata.kind === "soa");
    if (soa?.rdata.kind === "soa") ttl = Math.min(soa.ttl, soa.rdata.minimum, negativeMax);
  }
  if (ttl === undefined) return 0;
  return Math.max(minTtl, Math.min(maxTtl, ttl));
}
