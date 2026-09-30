export interface DecodedName {
  name: string;
  nextOffset: number;
}

const MAX_POINTER_HOPS = 32;
const MAX_LABELS = 128;

export function decodeName(packet: Uint8Array, offset: number): DecodedName {
  if (offset < 0 || offset >= packet.length) throw new Error("DNS name offset out of bounds");
  const labels: string[] = [];
  const decoder = new TextDecoder();
  let cursor = offset;
  let nextOffset = -1;
  let hops = 0;
  let labelsSeen = 0;
  const visited = new Set<number>();

  while (true) {
    if (cursor >= packet.length) throw new Error("Truncated DNS name");
    const length = packet[cursor]!;
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= packet.length) throw new Error("Truncated compression pointer");
      const pointer = ((length & 0x3f) << 8) | packet[cursor + 1]!;
      if (pointer >= packet.length) throw new Error("Compression pointer out of bounds");
      if (nextOffset < 0) nextOffset = cursor + 2;
      if (visited.has(pointer) || ++hops > MAX_POINTER_HOPS) throw new Error("Compression pointer loop");
      visited.add(pointer);
      cursor = pointer;
      continue;
    }
    if ((length & 0xc0) !== 0) throw new Error("Unsupported DNS label type");
    cursor += 1;
    if (length === 0) {
      if (nextOffset < 0) nextOffset = cursor;
      break;
    }
    if (length > 63 || cursor + length > packet.length) throw new Error("Invalid DNS label");
    if (++labelsSeen > MAX_LABELS) throw new Error("Too many DNS labels");
    labels.push(decoder.decode(packet.subarray(cursor, cursor + length)));
    cursor += length;
  }

  const name = labels.join(".");
  if (name.length > 253) throw new Error("DNS name too long");
  return { name, nextOffset };
}

export function encodeName(name: string): Uint8Array {
  const normalized = name.endsWith(".") ? name.slice(0, -1) : name;
  if (!normalized) return new Uint8Array([0]);
  const encoder = new TextEncoder();
  const parts: number[] = [];
  for (const label of normalized.split(".")) {
    const bytes = encoder.encode(label);
    if (bytes.length === 0 || bytes.length > 63) throw new Error("Invalid DNS label length");
    parts.push(bytes.length, ...bytes);
  }
  parts.push(0);
  if (parts.length > 255) throw new Error("Encoded DNS name too long");
  return Uint8Array.from(parts);
}

export function canonicalName(name: string): string {
  return name.replace(/\.$/, "").toLowerCase();
}
