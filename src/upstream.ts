import { parseDnsPacket } from "./dns/packet";
import { DnsType, type DnsPacket } from "./dns/types";
import type { AppConfig } from "./config";
import { parseUpstreamEntry, type UpstreamPath } from "./upstream-entry";

export interface UpstreamResult {
  packet: Uint8Array;
  /** The URL that answered (one path of the entry). */
  upstream: string;
  /** For diagnostics: the resolver's host, and "via" the path's host when another path answered. */
  label: string;
}

/**
 * Budgeted paths (see upstream-entry.ts) also cool down after failures: a throttling resolver answers
 * SERVFAIL or nothing, and every query sent to it meanwhile costs the hedge delay. BREAKER_FAILURES
 * failures within BREAKER_WINDOW_MS take the path out for BREAKER_COOLDOWN_MS.
 */
const BREAKER_FAILURES = 5;
const BREAKER_WINDOW_MS = 30_000;
const BREAKER_COOLDOWN_MS = 120_000;

interface PathState {
  tokens: number;
  refilledAt: number;
  failures: number[];
  openUntil: number;
}

const pathStates = new Map<string, PathState>();
const parsedEntries = new Map<string, UpstreamPath[]>();

function stateOf(path: UpstreamPath): PathState {
  let state = pathStates.get(path.url);
  if (!state) {
    state = { tokens: path.qps ?? 0, refilledAt: Date.now(), failures: [], openUntil: 0 };
    pathStates.set(path.url, state);
  }
  return state;
}

/**
 * The first path of an entry within its budget and not cooling down, its token taken; or none.
 * `overBudget` also takes a path whose budget is spent (never one cooling down): the query is then
 * charged ahead, at most one second's worth, so the budget still holds on average.
 */
function pickPath(entry: string, overBudget = false): { path: UpstreamPath; paths: UpstreamPath[] } | undefined {
  let paths = parsedEntries.get(entry);
  if (!paths) {
    // An entry readConfig would have dropped is tried as-is, so it fails like any other upstream.
    paths = parseUpstreamEntry(entry) ?? [{ url: entry }];
    parsedEntries.set(entry, paths);
  }
  const now = Date.now();
  for (const path of paths) {
    if (path.qps === undefined) return { path, paths };
    const state = stateOf(path);
    if (state.openUntil > now) continue;
    state.tokens = Math.min(path.qps, state.tokens + ((now - state.refilledAt) / 1000) * path.qps);
    state.refilledAt = now;
    if (state.tokens < (overBudget ? 1 - path.qps : 1)) continue;
    state.tokens -= 1;
    return { path, paths };
  }
  return undefined;
}

function recordOutcome(path: UpstreamPath, ok: boolean): void {
  if (path.qps === undefined) return;
  const state = stateOf(path);
  const now = Date.now();
  if (ok) {
    state.failures = [];
    return;
  }
  state.failures = state.failures.filter((at) => now - at < BREAKER_WINDOW_MS);
  state.failures.push(now);
  if (state.failures.length >= BREAKER_FAILURES) {
    state.failures = [];
    state.openUntil = now + BREAKER_COOLDOWN_MS;
    console.warn(JSON.stringify({ event: "upstream_cooling_down", upstream: upstreamLabel(path.url), seconds: BREAKER_COOLDOWN_MS / 1000 }));
  }
}

export interface UpstreamOptions {
  /** Use the ECS-capable upstream list instead of the default one. */
  ecs?: boolean;
  /** Use the domestic-resolver list (CN_UPSTREAMS) instead of the default one. */
  cn?: boolean;
  /**
   * Whether an answer is good enough to stop at. One that is not is kept while the remaining entries
   * are asked, then those skipped over their budget (see pickPath); it is served if none does better.
   */
  acceptable?: (answer: DnsPacket, entry: number) => boolean;
}

/** Hostname for diagnostics; a malformed URL must not turn a failure path into a throw. */
function upstreamLabel(upstream: string): string {
  try {
    return new URL(upstream).hostname;
  } catch {
    return upstream;
  }
}

async function queryOne(upstream: string, query: Uint8Array, config: AppConfig, signal: AbortSignal): Promise<{ packet: Uint8Array; parsed: DnsPacket }> {
  const response = await fetch(upstream, {
    method: "POST",
    headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
    body: Uint8Array.from(query).buffer,
    signal,
    redirect: "manual",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/dns-message") throw new Error(`invalid Content-Type: ${contentType ?? "missing"}`);
  const packet = new Uint8Array(await response.arrayBuffer());
  if (packet.length > config.maxDnsPacketSize) throw new Error("response too large");
  const parsed = parseDnsPacket(packet);
  const flags = parsed.header.flags;
  if ((flags & 0x8000) === 0) throw new Error("not a DNS response");
  // A resolver that failed is not an answer: SERVFAIL/REFUSED/NOTIMP and truncated replies must fall
  // through to the next upstream instead of winning the race and starving it. NXDOMAIN (3) and
  // NODATA (rcode 0 without answers) are legitimate answers and keep their negative-cache semantics.
  const rcode = flags & 0x000f;
  if (rcode !== 0 && rcode !== 3) throw new Error(`rcode ${rcode}`);
  // BADVERS/BADCOOKIE and friends sit in the OPT record's TTL high byte while the header rcode stays
  // 0, so they need their own check or such failures would count as answers.
  if (parsed.additionals.some((record) => record.type === DnsType.OPT && (record.ttl >>> 24) !== 0)) {
    throw new Error("extended rcode");
  }
  // Truncated replies are deliberately failures: the next upstream usually answers in full, and half
  // an A/AAAA set must never reach the address-derived caches in rewrite.ts.
  if ((flags & 0x0200) !== 0) throw new Error("truncated response");
  return { packet, parsed };
}

/**
 * Hedged upstream query: the next upstream is started either when the previous one fails
 * or after `upstreamHedgeMs` (`ecsUpstreamHedgeMs` for the ECS group) without an answer,
 * whichever comes first. The first valid response wins and every other in-flight attempt is
 * aborted. With hedging disabled this degrades to plain sequential fallback. A response that
 * `options.acceptable` rejects does not win: see UpstreamOptions.
 */
export function queryUpstreams(query: Uint8Array, config: AppConfig, options: UpstreamOptions = {}): Promise<UpstreamResult> {
  const cn = options.cn === true && config.cnUpstreams.length > 0;
  const upstreams = cn ? config.cnUpstreams : options.ecs ? config.ecsUpstreams : config.upstreams;
  const hedgeMs = !cn && options.ecs ? config.ecsUpstreamHedgeMs : config.upstreamHedgeMs;
  if (upstreams.length === 0) return Promise.reject(new Error("No upstreams configured"));

  return new Promise<UpstreamResult>((resolve, reject) => {
    const errors: string[] = [];
    const controllers: AbortController[] = [];
    const timers: ReturnType<typeof setTimeout>[] = [];
    let next = 0;
    let pending = 0;
    let settled = false;
    // Entries skipped over budget or cooling down, and the earliest entry's unacceptable answer.
    const skipped: number[] = [];
    let kept: { result: UpstreamResult; index: number } | undefined;
    let retried = false;

    const finish = (result?: UpstreamResult) => {
      if (settled) return;
      settled = true;
      for (const timer of timers) clearTimeout(timer);
      for (const controller of controllers) controller.abort("superseded");
      result ??= kept?.result;
      if (result) resolve(result);
      else reject(new Error(`All upstreams failed (${errors.join("; ")})`));
    };

    // Nothing in flight and no entry left: with only an unacceptable answer, give the entries skipped
    // over their budget one more try before serving it.
    const exhausted = () => {
      if (kept && !retried && skipped.length > 0) {
        retried = true;
        for (const index of skipped) attempt(index, true);
        if (pending > 0) return;
      }
      finish();
    };

    const launch = (): void => {
      if (settled || next >= upstreams.length) return;
      attempt(next++, false);
    };

    const attempt = (index: number, overBudget: boolean): void => {
      const entry = upstreams[index]!;
      const picked = pickPath(entry, overBudget);
      if (!picked) {
        // Every path over budget or cooling down: on to the next entry at once.
        if (!overBudget) {
          skipped.push(index);
          errors.push(`${upstreamLabel(entry.split("|", 1)[0]!.split("#", 1)[0]!)}: over budget or cooling down`);
          if (next < upstreams.length) launch();
          else if (pending === 0) exhausted();
        }
        return;
      }
      const { path, paths } = picked;
      const upstream = path.url;
      const label = path === paths[0] ? upstreamLabel(upstream) : `${upstreamLabel(paths[0]!.url)} via ${upstreamLabel(upstream)}`;
      const controller = new AbortController();
      controllers.push(controller);
      pending += 1;
      const timeout = setTimeout(() => controller.abort("upstream timeout"), config.upstreamTimeoutMs);
      timers.push(timeout);
      if (hedgeMs > 0 && next < upstreams.length && !overBudget) {
        timers.push(setTimeout(launch, hedgeMs));
      }
      const settle = () => {
        clearTimeout(timeout);
        pending -= 1;
        if (next < upstreams.length) launch();
        else if (pending === 0) exhausted();
      };
      queryOne(upstream, query, config, controller.signal)
        .then(({ packet, parsed }) => {
          if (settled) return;
          recordOutcome(path, true);
          const result = { packet, upstream, label };
          if (!options.acceptable || options.acceptable(parsed, index)) return finish(result);
          errors.push(`${label}: answer not acceptable`);
          if (!kept || index < kept.index) kept = { result, index };
          settle();
        })
        .catch((error: unknown) => {
          if (settled) return;
          recordOutcome(path, false);
          // The abort reason ("upstream timeout") is the useful diagnostic: a fetch rejected by an
          // abort only reports "This operation was aborted". Superseded attempts never reach here
          // (finish() sets settled before aborting), so every entry below is a real failure.
          const reason: unknown = controller.signal.reason;
          const detail = typeof reason === "string" && reason.length > 0 ? reason : error instanceof Error ? error.message : String(error);
          errors.push(`${label}: ${detail}`);
          settle();
        });
    };

    launch();
  });
}
