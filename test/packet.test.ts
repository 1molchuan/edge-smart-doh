import { describe, expect, it } from "vitest";
import { describeHttpsParams, SvcParamKey } from "../src/dns/https-rr";
import { encodeDnsPacket, parseDnsPacket } from "../src/dns/packet";
import { DnsType, type DnsPacket } from "../src/dns/types";

function basePacket(): DnsPacket {
  return {
    header: { id: 0x1234, flags: 0x8180, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
    questions: [{ name: "example.com", type: DnsType.A, class: 1 }],
    answers: [],
    authorities: [],
    additionals: [],
  };
}

describe("DNS packet codec", () => {
  it("round-trips A, AAAA, CNAME and unknown raw records", () => {
    const packet = basePacket();
    packet.answers = [
      { name: "example.com", type: DnsType.A, class: 1, ttl: 120, rdata: { kind: "a", address: "192.0.2.1" } },
      { name: "example.com", type: DnsType.AAAA, class: 1, ttl: 120, rdata: { kind: "aaaa", address: "2001:db8::1" } },
      { name: "www.example.com", type: DnsType.CNAME, class: 1, ttl: 60, rdata: { kind: "name", name: "example.com" } },
      { name: "example.com", type: DnsType.TXT, class: 1, ttl: 30, rdata: { kind: "raw", data: new Uint8Array([3, 102, 111, 111]) } },
    ];
    const parsed = parseDnsPacket(encodeDnsPacket(packet));
    expect(parsed.answers[0]?.rdata).toEqual({ kind: "a", address: "192.0.2.1" });
    expect(parsed.answers[1]?.rdata).toEqual({ kind: "aaaa", address: "2001:db8:0:0:0:0:0:1" });
    expect(parsed.answers[2]?.rdata).toEqual({ kind: "name", name: "example.com" });
    expect(parsed.answers[3]?.rdata).toEqual({ kind: "raw", data: new Uint8Array([3, 102, 111, 111]) });
  });

  it("decodes compressed owner and CNAME RDATA names", () => {
    const wire = Uint8Array.from([
      0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
      7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 5, 0, 1,
      0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c,
    ]);
    const packet = parseDnsPacket(wire);
    expect(packet.answers[0]?.name).toBe("example.com");
    expect(packet.answers[0]?.rdata).toEqual({ kind: "name", name: "example.com" });
  });

  it("preserves unknown HTTPS parameters across parse and encode", () => {
    const packet = basePacket();
    packet.questions[0]!.type = DnsType.HTTPS;
    packet.answers = [{
      name: "example.com",
      type: DnsType.HTTPS,
      class: 1,
      ttl: 300,
      rdata: { kind: "https", value: { priority: 1, target: ".", params: [
        { key: SvcParamKey.ALPN, value: new Uint8Array([2, 104, 50]) },
        { key: 65400, value: new Uint8Array([1, 2, 3]) },
      ] } },
    }];
    const first = parseDnsPacket(encodeDnsPacket(packet));
    const second = parseDnsPacket(encodeDnsPacket(first));
    const value = second.answers[0]?.rdata;
    expect(value?.kind).toBe("https");
    if (value?.kind === "https") {
      expect(describeHttpsParams(value.value).alpn).toEqual(["h2"]);
      expect(value.value.params.find((param) => param.key === 65400)?.value).toEqual(new Uint8Array([1, 2, 3]));
    }
  });

  it("rejects a compression pointer loop", () => {
    const wire = new Uint8Array(18);
    wire.set([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1]);
    expect(() => parseDnsPacket(wire)).toThrow(/pointer loop/i);
  });

  it("rejects truncated packets", () => {
    expect(() => parseDnsPacket(new Uint8Array(11))).toThrow(/truncated/i);
    const valid = encodeDnsPacket(basePacket());
    expect(() => parseDnsPacket(valid.subarray(0, valid.length - 1))).toThrow(/truncated/i);
  });
});
