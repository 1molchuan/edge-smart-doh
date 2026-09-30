import { parseDnsPacket } from "./dns/packet";
import type { AppConfig } from "./config";

export interface UpstreamResult {
  packet: Uint8Array;
  upstream: string;
}

export interface UpstreamOptions {
  /** Use the ECS-capable upstream list instead of the default one. */
  ecs?: boolean;
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
  if ((parsed.header.flags & 0x8000) === 0) throw new Error("not a DNS response");
  return packet;
}

/**
 * Hedged upstream query: the next upstream is started either when the previous one fails
 * or after `upstreamHedgeMs` without an answer, whichever comes first. The first valid
 * response wins and every other in-flight attempt is aborted. With hedging disabled this
 * degrades to plain sequential fallback.
 */
export function queryUpstreams(query: Uint8Array, config: AppConfig, options: UpstreamOptions = {}): Promise<UpstreamResult> {
  const upstreams = options.ecs ? config.ecsUpstreams : config.upstreams;
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
      if (config.upstreamHedgeMs > 0 && next < upstreams.length) {
        timers.push(setTimeout(launch, config.upstreamHedgeMs));
      }
      queryOne(upstream, query, config, controller.signal)
        .then((packet) => finish({ packet, upstream }))
        .catch((error: unknown) => {
          clearTimeout(timeout);
          pending -= 1;
          if (settled) return;
          errors.push(`${new URL(upstream).hostname}: ${error instanceof Error ? error.message : String(error)}`);
          if (next < upstreams.length) launch();
          else if (pending === 0) finish();
        });
    };

    launch();
  });
}
