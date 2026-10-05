import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";

/**
 * State behind the "relay" strategy: whether the local SNI relay (contrib/home/relay) is alive and,
 * in auto mode, which hosts it has taken over. The relay daemon reports its self-check every few
 * seconds and, once it probes, per-host direct-path handshake samples; when reports stop for longer
 * than a report's ttl the relay is assumed dead and every name falls back to the direct path — the
 * "worst case is yesterday's system" invariant of DESIGN.md. State is in-memory only; after a server
 * restart the relay re-establishes it with its next report.
 *
 * Auto mode judges each host on its own samples with hysteresis: it takes a persistently bad direct
 * path (ENTER: <50% handshakes over 15 minutes) to hand a host to the relay and a persistently good
 * one (EXIT: >80% over 30 minutes) to take it back, so minute-scale SNI flapping cannot ping-pong
 * answers between paths. A host with no samples is never handed over (like an unmeasured pool, the
 * answer stays untouched).
 */

/** Answer TTL for relay-pinned names: how fast a withdrawn relay stops being served. */
export const RELAY_PIN_TTL = 60;

/** Auto-mode hysteresis (DESIGN.md §3.1): enter/exit thresholds and their measurement windows. */
export const RELAY_ENTER_WINDOW_MS = 15 * 60 * 1000;
export const RELAY_ENTER_RATE = 0.5;
export const RELAY_EXIT_WINDOW_MS = 30 * 60 * 1000;
export const RELAY_EXIT_RATE = 0.8;
const MAX_HOSTS = 64;
const MAX_SAMPLES_PER_HOST = 32;
/** Fewer samples than this in a window means too little history to judge (one failed probe cycle is noise). */
const MIN_SAMPLES = 2;

/** One direct-path handshake sample: did a TLS handshake to a measured pool IP succeed? */
export interface RelayDirectSample {
  ok: boolean;
  rttMs?: number;
}

interface HostState {
  samples: { ok: boolean; ts: number }[];
  relayed: boolean;
  lastSampleAt: number;
}

interface RelayState {
  healthy: boolean;
  livenessUntil: number;
  lastSource: string;
  lastReportAt: number;
  /** Bumped on every decision change, folded into the answer cache key (like metaEchCacheTag). */
  version: number;
}

let state: RelayState = { healthy: false, livenessUntil: 0, lastSource: "", lastReportAt: 0, version: 1 };
const hosts = new Map<string, HostState>();

export interface RelayHealthReport {
  source: string;
  ttlSeconds: number;
  healthy: boolean;
  direct?: Record<string, RelayDirectSample>;
}

function relayAlive(): boolean {
  return state.healthy && Date.now() < state.livenessUntil;
}

function successRate(host: HostState, windowMs: number): number | undefined {
  const cutoff = Date.now() - windowMs;
  const samples = host.samples.filter((sample) => sample.ts >= cutoff);
  if (samples.length < MIN_SAMPLES) return undefined;
  return samples.filter((sample) => sample.ok).length / samples.length;
}

/** Hysteresis transitions for one host; returns whether its decision changed. */
function evaluateHost(host: HostState): boolean {
  if (!host.relayed) {
    const rate = successRate(host, RELAY_ENTER_WINDOW_MS);
    if (rate !== undefined && rate < RELAY_ENTER_RATE) {
      host.relayed = true;
      return true;
    }
  } else {
    const rate = successRate(host, RELAY_EXIT_WINDOW_MS);
    if (rate !== undefined && rate > RELAY_EXIT_RATE) {
      host.relayed = false;
      return true;
    }
  }
  return false;
}

export function setRelayHealth(report: RelayHealthReport): void {
  const wasAlive = relayAlive();
  const now = Date.now();
  state = {
    healthy: report.healthy,
    livenessUntil: now + report.ttlSeconds * 1000,
    lastSource: report.source.slice(0, 64),
    lastReportAt: now,
    version: state.version,
  };
  let changed = relayAlive() !== wasAlive;
  if (!relayAlive()) {
    // The relay (or the egress proxy behind it) is down: hand every host back to the direct path
    // immediately, so recovery starts from a clean state instead of stale decisions.
    for (const host of hosts.values()) {
      if (host.relayed) {
        host.relayed = false;
        changed = true;
      }
    }
  }
  for (const [rawName, sample] of Object.entries(report.direct ?? {})) {
    const name = rawName.toLowerCase().replace(/\.$/, "");
    const host = hosts.get(name) ?? { samples: [], relayed: false, lastSampleAt: 0 };
    host.samples.push({ ok: sample.ok, ts: now });
    if (host.samples.length > MAX_SAMPLES_PER_HOST) host.samples.splice(0, host.samples.length - MAX_SAMPLES_PER_HOST);
    host.lastSampleAt = now;
    if (evaluateHost(host)) changed = true;
    hosts.set(name, host);
    while (hosts.size > MAX_HOSTS) hosts.delete(hosts.keys().next().value as string);
  }
  if (changed) state.version += 1;
}

/** Whether the answer for `name` should point at the relay right now (mode, health, auto gating). */
export function relayServes(name: string, config: AppConfig): boolean {
  if (config.relayMode === "off" || !config.relayIp) return false;
  if (domainMatches(name, config.relayExcludeDomains)) return false;
  if (!domainMatches(name, config.relayDomains)) return false;
  if (!relayAlive()) return false;
  return config.relayMode === "always" || hosts.get(name)?.relayed === true;
}

export function relayCacheTag(): string {
  return `relay=v${state.version}`;
}

export function relayStatus(): {
  healthy: boolean;
  livenessUntil: number;
  lastSource: string;
  lastReportAt: number;
  version: number;
  hosts: { host: string; relayed: boolean; samples: number; enterRate: number | null; exitRate: number | null; lastSampleAt: number }[];
} {
  return {
    healthy: relayAlive(),
    livenessUntil: state.livenessUntil,
    lastSource: state.lastSource,
    lastReportAt: state.lastReportAt,
    version: state.version,
    hosts: [...hosts.entries()].map(([host, entry]) => ({
      host,
      relayed: entry.relayed,
      samples: entry.samples.length,
      enterRate: successRate(entry, RELAY_ENTER_WINDOW_MS) ?? null,
      exitRate: successRate(entry, RELAY_EXIT_WINDOW_MS) ?? null,
      lastSampleAt: entry.lastSampleAt,
    })),
  };
}

export function resetRelayState(): void {
  state = { healthy: false, livenessUntil: 0, lastSource: "", lastReportAt: 0, version: 1 };
  hosts.clear();
}
