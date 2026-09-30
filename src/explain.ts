import { describeHttpsParams } from "./dns/https-rr";
import { DnsType, type DnsPacket, type DnsRecord } from "./dns/types";

const TYPE_NAMES: Record<number, string> = Object.fromEntries(Object.entries(DnsType).map(([name, code]) => [code, name]));

export function dnsTypeName(type: number): string {
  return TYPE_NAMES[type] ?? `TYPE${type}`;
}

/** One human-readable line per record, e.g. `abs.twimg.com HTTPS 1 . alpn=h2 ech=71B ttl=300`. */
export function describeRecord(record: DnsRecord): string {
  const head = `${record.name} ${dnsTypeName(record.type)}`;
  const rdata = record.rdata;
  let body: string;
  switch (rdata.kind) {
    case "a":
    case "aaaa":
      body = rdata.address;
      break;
    case "name":
      body = rdata.name;
      break;
    case "https": {
      const params = describeHttpsParams(rdata.value);
      const parts = [String(rdata.value.priority), rdata.value.target || "."];
      if (params.alpn) parts.push(`alpn=${params.alpn.join(",")}`);
      if (params.ipv4hint) parts.push(`ipv4hint=${params.ipv4hint.join(",")}`);
      if (params.ipv6hint) parts.push(`ipv6hint=${params.ipv6hint.join(",")}`);
      if (params.ech) parts.push(`ech=${params.ech.length}B`);
      body = parts.join(" ");
      break;
    }
    default:
      body = `(${rdata.kind})`;
  }
  return `${head} ${body} ttl=${record.ttl}`;
}

export function describeAnswers(packet: DnsPacket): string[] {
  return packet.answers.map(describeRecord);
}

/**
 * Whether Chromium (Chrome, Edge) will use the ECH config for this name, given the three answers
 * it resolves in parallel. Mirrors net/dns/host_cache.cc: an HTTPS record is used only when all
 * A/AAAA records sit at one canonical name and that name is the HTTPS record's target ("." meaning
 * the record's own owner name). Anything else makes Chromium connect with a plaintext SNI.
 */
export function chromiumEchVerdict(a: DnsPacket, aaaa: DnsPacket, https: DnsPacket): { usable: boolean; reason: string } {
  const owners = new Set(
    [...a.answers, ...aaaa.answers]
      .filter((record) => record.rdata.kind === "a" || record.rdata.kind === "aaaa")
      .map((record) => record.name.toLowerCase()),
  );
  if (owners.size === 0) return { usable: false, reason: "no A/AAAA addresses" };
  if (owners.size > 1) {
    return { usable: false, reason: `A/AAAA records sit at different names (${[...owners].join(", ")}), so Chromium ignores the HTTPS record` };
  }
  const canonical = [...owners][0]!;
  const services = https.answers.filter((record) => record.rdata.kind === "https" && record.rdata.value.priority > 0);
  if (services.length === 0) return { usable: false, reason: "no HTTPS service record" };
  const matching = services.filter((record) => {
    const target = record.rdata.kind === "https" ? record.rdata.value.target : "";
    return (target === "" || target === "." ? record.name : target).toLowerCase() === canonical;
  });
  if (matching.length === 0) {
    return { usable: false, reason: `addresses are at ${canonical} but the HTTPS record is at ${services[0]!.name}, so Chromium ignores it` };
  }
  const withEch = matching.find((record) => record.rdata.kind === "https" && describeHttpsParams(record.rdata.value).ech);
  if (!withEch) return { usable: false, reason: "the HTTPS record carries no ECH config" };
  return { usable: true, reason: `A/AAAA and HTTPS agree on ${canonical} and the HTTPS record carries ECH` };
}

/**
 * Latest result pushed by each self-check prober (work/echprobe -selfcheck), kept in memory so
 * /explain and the admin state show whether the answers still satisfy Chromium.
 */
interface SelfCheckReport {
  ok: boolean;
  problems: string[];
  hosts: number;
  at: number;
}

const MAX_SELFCHECK_SOURCES = 8;
const selfChecks = new Map<string, SelfCheckReport>();

export function setSelfCheck(source: string, ok: boolean, problems: string[], hosts: number): SelfCheckReport {
  const report = { ok, problems: problems.slice(0, 50).map((problem) => problem.slice(0, 300)), hosts, at: Date.now() };
  selfChecks.delete(source);
  selfChecks.set(source, report);
  while (selfChecks.size > MAX_SELFCHECK_SOURCES) selfChecks.delete(selfChecks.keys().next().value as string);
  return report;
}

export function selfCheckStatus(): (SelfCheckReport & { source: string })[] {
  return [...selfChecks].map(([source, report]) => ({ source, ...report }));
}

export function clearSelfChecks(): void {
  selfChecks.clear();
}
