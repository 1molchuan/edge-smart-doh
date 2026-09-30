import { decodeName, encodeName } from "./name";
import type { HttpsRecord, SvcParam } from "./types";

export const SvcParamKey = {
  MANDATORY: 0,
  ALPN: 1,
  NO_DEFAULT_ALPN: 2,
  PORT: 3,
  IPV4HINT: 4,
  ECH: 5,
  IPV6HINT: 6,
} as const;

export function parseHttpsRdata(packet: Uint8Array, offset: number, length: number): HttpsRecord {
  const end = offset + length;
  if (length < 3 || end > packet.length) throw new Error("Truncated HTTPS RDATA");
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const priority = view.getUint16(offset);
  const decoded = decodeName(packet, offset + 2);
  if (decoded.nextOffset > end) throw new Error("HTTPS target exceeds RDATA");
  let cursor = decoded.nextOffset;
  const params: SvcParam[] = [];
  let previousKey = -1;
  while (cursor < end) {
    if (cursor + 4 > end) throw new Error("Truncated HTTPS parameter");
    const key = view.getUint16(cursor);
    const valueLength = view.getUint16(cursor + 2);
    cursor += 4;
    if (cursor + valueLength > end) throw new Error("Truncated HTTPS parameter value");
    if (key <= previousKey) throw new Error("HTTPS parameters are not strictly ordered");
    params.push({ key, value: packet.slice(cursor, cursor + valueLength) });
    previousKey = key;
    cursor += valueLength;
  }
  return { priority, target: decoded.name, params };
}

export function encodeHttpsRdata(record: HttpsRecord): Uint8Array {
  const target = encodeName(record.target);
  const params = [...record.params].sort((a, b) => a.key - b.key);
  let length = 2 + target.length;
  const seen = new Set<number>();
  for (const param of params) {
    if (param.key < 0 || param.key > 0xffff || param.value.length > 0xffff || seen.has(param.key)) {
      throw new Error("Invalid HTTPS parameter");
    }
    seen.add(param.key);
    length += 4 + param.value.length;
  }
  const output = new Uint8Array(length);
  const view = new DataView(output.buffer);
  view.setUint16(0, record.priority);
  output.set(target, 2);
  let cursor = 2 + target.length;
  for (const param of params) {
    view.setUint16(cursor, param.key);
    view.setUint16(cursor + 2, param.value.length);
    output.set(param.value, cursor + 4);
    cursor += 4 + param.value.length;
  }
  return output;
}

export function describeHttpsParams(record: HttpsRecord): {
  alpn?: string[];
  ipv4hint?: string[];
  ipv6hint?: string[];
  ech?: Uint8Array;
} {
  const result: { alpn?: string[]; ipv4hint?: string[]; ipv6hint?: string[]; ech?: Uint8Array } = {};
  for (const param of record.params) {
    if (param.key === SvcParamKey.ALPN) {
      const values: string[] = [];
      let cursor = 0;
      while (cursor < param.value.length) {
        const length = param.value[cursor++]!;
        if (cursor + length > param.value.length) throw new Error("Invalid ALPN parameter");
        values.push(new TextDecoder().decode(param.value.subarray(cursor, cursor + length)));
        cursor += length;
      }
      result.alpn = values;
    } else if (param.key === SvcParamKey.IPV4HINT) {
      if (param.value.length % 4 !== 0) throw new Error("Invalid ipv4hint parameter");
      result.ipv4hint = Array.from({ length: param.value.length / 4 }, (_, index) =>
        Array.from(param.value.subarray(index * 4, index * 4 + 4)).join("."),
      );
    } else if (param.key === SvcParamKey.IPV6HINT) {
      if (param.value.length % 16 !== 0) throw new Error("Invalid ipv6hint parameter");
      result.ipv6hint = Array.from({ length: param.value.length / 16 }, (_, index) => {
        const part = param.value.subarray(index * 16, index * 16 + 16);
        const view = new DataView(part.buffer, part.byteOffset, part.byteLength);
        return Array.from({ length: 8 }, (__, group) => view.getUint16(group * 2).toString(16)).join(":");
      });
    } else if (param.key === SvcParamKey.ECH) {
      result.ech = param.value.slice();
    }
  }
  return result;
}

export function upsertSvcParam(record: HttpsRecord, key: number, value: Uint8Array): HttpsRecord {
  return {
    ...record,
    params: [...record.params.filter((param) => param.key !== key), { key, value: value.slice() }].sort(
      (a, b) => a.key - b.key,
    ),
  };
}
