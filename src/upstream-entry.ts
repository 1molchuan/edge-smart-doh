/**
 * One entry of UPSTREAMS, ECS_UPSTREAMS or CN_UPSTREAMS. Usually a single DoH URL. It may also list
 * other paths to the same resolver, separated by "|", for instance the resolver itself and the same
 * resolver reached through another host of ours, so that it sees two source addresses. Each path may
 * carry a "#qps=N" budget: public resolvers throttle a single source address that sends them a
 * server's worth of queries (DNSPod answered SERVFAIL within minutes at ~19/s), so a budgeted path
 * takes at most N queries a second and the rest go on to the next entry (see upstream.ts).
 */
export interface UpstreamPath {
  url: string;
  qps?: number;
}

function privateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  return host === "::1" || /^f[cd][0-9a-f]{2}:/.test(host) || host === "localhost";
}

/**
 * The paths of an entry, or undefined when any of them is unusable: https:// anywhere, plain http://
 * only to a private or loopback address (a tunnel to another host of ours), and a budget of 1-1000.
 */
export function parseUpstreamEntry(entry: string): UpstreamPath[] | undefined {
  const paths: UpstreamPath[] = [];
  for (const raw of entry.split("|")) {
    const [url = "", fragment] = raw.trim().split("#", 2);
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return undefined;
    }
    if (!(parsed.protocol === "https:" || (parsed.protocol === "http:" && privateHost(parsed.hostname)))) return undefined;
    const path: UpstreamPath = { url };
    if (fragment !== undefined) {
      const qps = /^qps=(\d+)$/.exec(fragment);
      if (!qps || Number(qps[1]) < 1 || Number(qps[1]) > 1000) return undefined;
      path.qps = Number(qps[1]);
    }
    paths.push(path);
  }
  return paths.length > 0 ? paths : undefined;
}
