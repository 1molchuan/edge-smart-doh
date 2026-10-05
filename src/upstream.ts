import { parseDnsPacket } from "./dns/packet";
import { DnsType } from "./dns/types";
import type { AppConfig } from "./config";

export interface UpstreamResult {
  packet: Uint8Array;
  upstream: string;
}

export interface UpstreamOptions {
  /** Use the ECS-capable upstream list instead of the default one. */
  ecs?: boolean;
  /** Use the domestic-resolver list (CN_UPSTREAMS) instead of the default one. */
  cn?: boolean;
}

/** Hostname for diagnostics; a malformed URL must not turn a failure path into a throw. */
function upstreamLabel(upstream: string): string {
  try {
    return new URL(upstream).hostname;
  } catch {
    return upstream;
  }
}

async function queryOne(upstream: string, query: Uint8Array, config: AppConfig, signal: AbortSignal): Promise<Uint8Array> {
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
  return packet;
}

/**
 * Hedged upstream query: the next upstream is started either when the previous one fails
 * or after `upstreamHedgeMs` (`ecsUpstreamHedgeMs` for the ECS group) without an answer,
 * whichever comes first. The first valid response wins and every other in-flight attempt is
 * aborted. With hedging disabled this degrades to plain sequential fallback.
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

    const finish = (result?: UpstreamResult) => {
      if (settled) return;
      settled = true;
      for (const timer of timers) clearTimeout(timer);
      for (const controller of controllers) controller.abort("superseded");
      if (result) resolve(result);
      else reject(new Error(`All upstreams failed (${errors.join("; ")})`));
    };

    const launch = () => {
      if (settled || next >= upstreams.length) return;
      const upstream = upstreams[next++]!;
      const controller = new AbortController();
      controllers.push(controller);
      pending += 1;
      const timeout = setTimeout(() => controller.abort("upstream timeout"), config.upstreamTimeoutMs);
      timers.push(timeout);
      if (hedgeMs > 0 && next < upstreams.length) {
        timers.push(setTimeout(launch, hedgeMs));
      }
      queryOne(upstream, query, config, controller.signal)
        .then((packet) => finish({ packet, upstream }))
        .catch((error: unknown) => {
          clearTimeout(timeout);
          pending -= 1;
          if (settled) return;
          // The abort reason ("upstream timeout") is the useful diagnostic: a fetch rejected by an
          // abort only reports "This operation was aborted". Superseded attempts never reach here
          // (finish() sets settled before aborting), so every entry below is a real failure.
          const reason: unknown = controller.signal.reason;
          const detail = typeof reason === "string" && reason.length > 0 ? reason : error instanceof Error ? error.message : String(error);
          errors.push(`${upstreamLabel(upstream)}: ${detail}`);
          if (next < upstreams.length) launch();
          else if (pending === 0) finish();
        });
    };

    launch();
  });
}
