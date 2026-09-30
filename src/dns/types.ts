export interface DnsHeader {
  id: number;
  flags: number;
  qdcount: number;
  ancount: number;
  nscount: number;
  arcount: number;
}

export interface DnsQuestion {
  name: string;
  type: number;
  class: number;
}

export type ParsedRdata =
  | { kind: "a"; address: string }
  | { kind: "aaaa"; address: string }
  | { kind: "name"; name: string }
  | { kind: "mx"; preference: number; exchange: string }
  | { kind: "soa"; mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number }
  | { kind: "srv"; priority: number; weight: number; port: number; target: string }
  | { kind: "https"; value: HttpsRecord }
  | { kind: "opt"; options: EdnsOption[] }
  | { kind: "raw"; data: Uint8Array };

export interface DnsRecord {
  name: string;
  type: number;
  class: number;
  ttl: number;
  rdata: ParsedRdata;
}

export interface DnsPacket {
  header: DnsHeader;
  questions: DnsQuestion[];
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
}

export interface EdnsOption {
  code: number;
  data: Uint8Array;
}

export interface SvcParam {
  key: number;
  value: Uint8Array;
}

export interface HttpsRecord {
  priority: number;
  target: string;
  params: SvcParam[];
}

export const DnsType = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  OPT: 41,
  HTTPS: 65,
} as const;
