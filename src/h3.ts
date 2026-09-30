import { domainMatches } from "./dns/ecs";

/**
 * Measured HTTP/3 policy. Advertising h3 in an HTTPS record makes Chromium try QUIC first; that only
 * pays off where QUIC+ECH actually works from the client's network (measured from Shanghai against
 * linux.do: ~75ms vs 230–1400ms over TCP), and costs a failed attempt where it does not (X rejects
 * QUIC+ECH, Meta's QUIC times out in mainland China). Probers (work/echprobe -h3check) handshake
 * QUIC+ECH to the addresses this server hands out and report a per-host verdict. h3 is advertised
 * for a host only while every reporting prober says it works; a verdict applies to the host and its
 * subdomains (the most specific reported host wins) and expires on its own, falling back to the
 * static defaults.
 */
interface Verdict {
  ok: boolean;
  expiresAt: number;
}

const MAX_SOURCES = 8;
const MAX_HOSTS = 64;
const sources = new Map<string, Map<string, Verdict>>();
// Bumped whenever the effective verdicts change; folded into the cache key of HTTPS answers so a
// flip takes effect at once instead of after the cached answers expire.
let generation = 0;
let lastSnapshot = "";

function prune(): void {
  const now = Date.now();
  for (const [source, hosts] of sources) {
    for (const [host, verdict] of hosts) if (verdict.expiresAt <= now) hosts.delete(host);
    if (hosts.size === 0) sources.delete(source);
  }
}

function effective(): Map<string, { allowed: boolean; sources: string[] }> {
  const result = new Map<string, { allowed: boolean; sources: string[] }>();
  for (const [source, hosts] of sources) {
    for (const [host, verdict] of hosts) {
      const entry = result.get(host) ?? { allowed: true, sources: [] };
      entry.allowed &&= verdict.ok;
      entry.sources.push(`${source}:${verdict.ok ? "ok" : "fail"}`);
      result.set(host, entry);
    }
  }
  return result;
}

function refreshGeneration(): void {
  prune();
  const snapshot = JSON.stringify([...effective()].map(([host, entry]) => [host, entry.allowed]).sort());
  if (snapshot !== lastSnapshot) {
    lastSnapshot = snapshot;
    generation += 1;
  }
}

export function setH3Verdicts(source: string, verdicts: Record<string, boolean>, ttlSeconds: number): void {
  const expiresAt = Date.now() + ttlSeconds * 1000;
  const hosts = new Map<string, Verdict>();
  for (const [host, ok] of Object.entries(verdicts).slice(0, MAX_HOSTS)) hosts.set(host.toLowerCase(), { ok, expiresAt });
  sources.delete(source);
  sources.set(source, hosts);
  while (sources.size > MAX_SOURCES) sources.delete(sources.keys().next().value as string);
  refreshGeneration();
}

export function clearH3Verdicts(): void {
  sources.clear();
  refreshGeneration();
}

/** Verdict for `name` from the most specific reported host covering it, or undefined without data. */
export function h3Verdict(name: string): { host: string; allowed: boolean; sources: string[] } | undefined {
  prune();
  let best: { host: string; allowed: boolean; sources: string[] } | undefined;
  for (const [host, entry] of effective()) {
    if (!domainMatches(name, [`.${host}`])) continue;
    if (!best || host.length > best.host.length) best = { host, ...entry };
  }
  return best;
}

/**
 * ALPN to put in an ECH-carrying HTTPS record for `name`: h3+h2 when probers confirm QUIC+ECH,
 * h2 when they found it failing, otherwise `fallback` (undefined keeps the upstream record's ALPN).
 */
export function alpnFor(name: string, fallback?: string[]): { alpn?: string[]; why: string } {
  const verdict = h3Verdict(name);
  if (!verdict) return { alpn: fallback, why: "no QUIC+ECH measurement; default" };
  const why = `QUIC+ECH ${verdict.allowed ? "works" : "fails"} per probers (${verdict.host}: ${verdict.sources.join(", ")})`;
  return { alpn: verdict.allowed ? ["h3", "h2"] : ["h2"], why };
}

export function h3CacheTag(): string {
  refreshGeneration();
  return `h3g${generation}`;
}

export function h3Status(): { effective: Record<string, boolean>; sources: { source: string; hosts: Record<string, boolean>; expiresAt: number }[] } {
  prune();
  return {
    effective: Object.fromEntries([...effective()].map(([host, entry]) => [host, entry.allowed])),
    sources: [...sources].map(([source, hosts]) => ({
      source,
      hosts: Object.fromEntries([...hosts].map(([host, verdict]) => [host, verdict.ok])),
      expiresAt: Math.max(...[...hosts.values()].map((verdict) => verdict.expiresAt)),
    })),
  };
}
