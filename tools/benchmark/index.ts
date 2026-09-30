#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";

interface Options {
  endpoints: Array<{ name: string; url: string }>;
  count: number;
  timeoutMs: number;
  curlProtocols: boolean;
  json: boolean;
}

interface Sample {
  ok: boolean;
  latencyMs: number;
  error?: string;
}

function usage(): never {
  console.error("Usage: npm run benchmark -- --direct URL --edgeone URL [--esa URL] [--count 100] [--timeout 5000] [--curl-protocols] [--json]");
  process.exit(2);
}

function options(argv: string[]): Options {
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index]!;
    if (key === "--curl-protocols" || key === "--json") flags.add(key);
    else if (key.startsWith("--")) {
      const value = argv[++index];
      if (!value) usage();
      values.set(key, value);
    } else usage();
  }
  const endpoints = (["direct", "edgeone", "esa"] as const)
    .flatMap((name) => values.has(`--${name}`) ? [{ name, url: values.get(`--${name}`)! }] : []);
  if (endpoints.length === 0) usage();
  for (const endpoint of endpoints) {
    const url = new URL(endpoint.url);
    if (url.protocol !== "https:") throw new Error(`${endpoint.name} must be HTTPS`);
  }
  const count = Number.parseInt(values.get("--count") ?? "100", 10);
  const timeoutMs = Number.parseInt(values.get("--timeout") ?? "5000", 10);
  if (!Number.isInteger(count) || count < 1 || count > 10000 || !Number.isInteger(timeoutMs) || timeoutMs < 100) usage();
  return { endpoints, count, timeoutMs, curlProtocols: flags.has("--curl-protocols"), json: flags.has("--json") };
}

function encodeName(name: string): number[] {
  return [...name.replace(/\.$/, "").split(".").flatMap((label) => {
    const data = [...new TextEncoder().encode(label)];
    return [data.length, ...data];
  }), 0];
}

function dnsQuery(type: number): Uint8Array {
  const id = randomBytes(2);
  return Uint8Array.from([id[0]!, id[1]!, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...encodeName("example.com"), 0, type, 0, 1]);
}

async function timedFetch(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  validate?: (response: Response, body: Uint8Array) => void,
): Promise<Sample> {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    const body = new Uint8Array(await response.arrayBuffer());
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (body.length === 0) throw new Error("empty body");
    validate?.(response, body);
    return { ok: true, latencyMs: performance.now() - started };
  } catch (error) {
    return { ok: false, latencyMs: performance.now() - started, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timeout);
  }
}

function validateProbe(response: Response, body: Uint8Array): void {
  const value: unknown = JSON.parse(new TextDecoder().decode(body));
  if (typeof value !== "object" || value === null || (value as { ok?: unknown }).ok !== true) throw new Error("invalid probe response");
  const contentType = response.headers.get("Content-Type")?.toLowerCase();
  if (!contentType?.startsWith("application/json")) throw new Error("invalid probe Content-Type");
}

function validateDns(response: Response, body: Uint8Array): void {
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/dns-message") throw new Error("invalid DNS Content-Type");
  if (body.length < 12 || (body[2]! & 0x80) === 0) throw new Error("malformed DNS response");
  const rcode = body[3]! & 0x0f;
  if (rcode !== 0) throw new Error(`DNS RCODE ${rcode}`);
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)]!;
}

function summarize(samples: Sample[]) {
  const values = samples.filter((sample) => sample.ok).map((sample) => sample.latencyMs).sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return {
    attempts: samples.length,
    successes: values.length,
    failures: samples.length - values.length,
    successRate: values.length / samples.length,
    min: values[0] ?? Number.NaN,
    mean,
    median: percentile(values, 50),
    p90: percentile(values, 90),
    p95: percentile(values, 95),
    p99: percentile(values, 99),
    max: values.at(-1) ?? Number.NaN,
    stddev: Math.sqrt(variance),
    errors: [...new Set(samples.filter((sample) => !sample.ok).map((sample) => sample.error))],
  };
}

async function runSeries(count: number, operation: () => Promise<Sample>): Promise<Sample[]> {
  const output: Sample[] = [];
  for (let index = 0; index < count; index += 1) output.push(await operation());
  return output;
}

function probeUrl(dohUrl: string): string {
  const url = new URL(dohUrl);
  url.pathname = "/probe";
  url.search = "";
  return url.toString();
}

function curlTiming(url: string, protocol: "http2" | "http3") {
  const result = spawnSync("curl", [
    "--silent", "--show-error", `--${protocol}`, "--output", process.platform === "win32" ? "NUL" : "/dev/null",
    "--write-out", "%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{http_version}", url,
  ], { encoding: "utf8", timeout: 15000 });
  if (result.error || result.status !== 0) return { supported: false, detail: (result.error?.message ?? result.stderr).trim() };
  const [dns, connect, tls, ttfb, total, version] = result.stdout.trim().split("|");
  return { supported: true, dns: Number(dns) * 1000, connect: Number(connect) * 1000, tls: Number(tls) * 1000, ttfb: Number(ttfb) * 1000, total: Number(total) * 1000, version };
}

function printable(value: unknown): unknown {
  if (typeof value === "number") return Number.isFinite(value) ? Number(value.toFixed(2)) : null;
  if (Array.isArray(value)) return value.map(printable);
  if (typeof value === "object" && value !== null) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, printable(item)]));
  return value;
}

async function main(): Promise<void> {
  const opts = options(process.argv.slice(2));
  const report: Record<string, unknown> = { generatedAt: new Date().toISOString(), count: opts.count, endpoints: {} };
  const endpointReport = report.endpoints as Record<string, unknown>;
  for (const endpoint of opts.endpoints) {
    const probe = await runSeries(opts.count, () => timedFetch(probeUrl(endpoint.url), { headers: { Accept: "application/json" } }, opts.timeoutMs, validateProbe));
    const dns: Record<string, unknown> = {};
    for (const [name, type] of [["A", 1], ["AAAA", 28], ["HTTPS", 65]] as const) {
      dns[name] = summarize(await runSeries(opts.count, () => timedFetch(endpoint.url, {
        method: "POST",
        headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
        body: Uint8Array.from(dnsQuery(type)).buffer,
      }, opts.timeoutMs, validateDns)));
    }
    endpointReport[endpoint.name] = {
      url: endpoint.url,
      probe: summarize(probe),
      dns,
      ...(opts.curlProtocols ? { protocolTiming: {
        http2: curlTiming(probeUrl(endpoint.url), "http2"),
        http3: curlTiming(probeUrl(endpoint.url), "http3"),
      } } : {}),
    };
  }
  const output = printable(report);
  if (opts.json) console.log(JSON.stringify(output, null, 2));
  else {
    console.log("Probe represents endpoint/TLS path; DNS rows include DoH processing and upstream resolution.");
    for (const [name, value] of Object.entries(endpointReport)) {
      console.log(`\n[${name}] ${(value as { url: string }).url}`);
      const rows = { probe: (value as { probe: unknown }).probe, ...(value as { dns: Record<string, unknown> }).dns };
      console.table(Object.fromEntries(Object.entries(rows).map(([row, stats]) => [row, printable(stats)])));
      if ((value as { protocolTiming?: unknown }).protocolTiming) console.log("curl protocol timing:", JSON.stringify(printable((value as { protocolTiming: unknown }).protocolTiming), null, 2));
    }
  }
}

await main();
