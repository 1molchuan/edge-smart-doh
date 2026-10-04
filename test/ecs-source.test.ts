import { describe, expect, it } from "vitest";
import { readConfig } from "../src/config";
import { ecsSourceIp, isGloballyRoutable } from "../src/dns/ecs";

describe("isGloballyRoutable", () => {
  it.each([
    ["8.8.8.8", true],
    ["1.2.3.4", true],
    ["219.141.136.10", true],
    ["127.0.0.1", false],
    ["10.1.2.3", false],
    ["172.20.1.2", false],
    ["192.168.1.10", false],
    ["100.64.0.1", false],
    ["169.254.169.254", false],
    ["224.0.0.1", false],
    ["::1", false],
    ["fe80::1", false],
    ["fd00::1", false],
    ["ff02::1", false],
    ["::ffff:192.168.1.2", false],
    ["::ffff:8.8.8.8", true],
    ["2606:4700::1111", true],
    ["not-an-ip", false],
  ])("%s -> %s", (ip, expected) => {
    expect(isGloballyRoutable(ip)).toBe(expected);
  });
});

describe("ecsSourceIp", () => {
  const fallback = "219.141.136.10";

  it("keeps a public client's own address", () => {
    expect(ecsSourceIp("203.0.100.7", fallback, false)).toBe("203.0.100.7");
  });

  it("replaces a foreign client's address with the fallback once the ISP table confirms it", () => {
    expect(ecsSourceIp("8.8.8.8", fallback, true)).toBe(fallback);
  });

  it("replaces a LAN client's address with the fallback without needing an ISP table", () => {
    expect(ecsSourceIp("127.0.0.1", fallback, false)).toBe(fallback);
    expect(ecsSourceIp("192.168.1.5", fallback, false)).toBe(fallback);
    expect(ecsSourceIp("::ffff:192.168.1.5", fallback, false)).toBe(fallback);
  });

  it("drops ECS for a LAN client when no fallback is configured instead of sending a REFUSED subnet", () => {
    expect(ecsSourceIp("127.0.0.1", undefined, false)).toBeUndefined();
    expect(ecsSourceIp("fd00::2", undefined, false)).toBeUndefined();
  });

  it("returns nothing without a client address", () => {
    expect(ecsSourceIp(undefined, fallback, false)).toBeUndefined();
  });
});

describe("readConfig ECS_FALLBACK_SUBNET", () => {
  it("accepts a CIDR suffix and keeps only the address", () => {
    const config = readConfig({ ECS_FALLBACK_SUBNET: "219.141.136.0/24" } as unknown as Env);
    expect(config.ecsFallbackSubnet).toBe("219.141.136.0");
  });

  it("stays unset when empty", () => {
    expect(readConfig({} as unknown as Env).ecsFallbackSubnet).toBeUndefined();
  });
});
