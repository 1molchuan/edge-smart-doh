import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";

/**
 * State behind the "relay" strategy: whether the local SNI relay (contrib/home/relay) is alive and,
 * in auto mode, which hosts it has taken over. The relay daemon reports its self-check every few
 * seconds (and, once it probes, per-host direct-path handshake samples); when reports stop for
 * longer than a report's ttl the relay is assumed dead and every name falls back to the direct
 * path — the "worst case is yesterday's system" invariant of DESIGN.md. State is in-memory only;
 * after a server restart the relay re-establishes it with its next report.
 */

/** Answer TTL for relay-pinned names: how fast a withdrawn relay stops being served. */
export const RELAY_PIN_TTL = 60;

/** One direct-path handshake sample: did a TLS handshake to a measured pool IP succeed? */
export interface RelayDirectSample {
  ok: boolean;
  rttMs?: number;
}

interface HostState {
  samples: { ok: boolean; ts: number }[];
  /** Bounded: reports keep coming, so the map cannot outgrow the probed name set. */
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

const MAX_HOSTS = 64;
const MAX_SAMPLES_PER_HOST = 32;

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

/** Auto mode's per-host decision; M1 stub — samples are stored but not judged yet. */
function hostRelayed(_name: string): boolean {
  return false;
}

export function setRelayHealth(report: RelayHealthReport): void {
  const before = relayAlive();
  const now = Date.now();
  state = {
    healthy: report.healthy,
    livenessUntil: now + report.ttlSeconds * 1000,
    lastSource: report.source.slice(0, 64),
    lastReportAt: now,
    version: state.version,
  };
  for (const [host, sample] of Object.entries(report.direct ?? {})) {
    const name = host.toLowerCase().replace(/\.$/, "");
    const entry = hosts.get(name) ?? { samples: [], lastSampleAt: 0 };
    entry.samples.push({ ok: sample.ok, ts: now });
    if (entry.samples.length > MAX_SAMPLES_PER_HOST) entry.samples.splice(0, entry.samples.length - MAX_SAMPLES_PER_HOST);
    entry.lastSampleAt = now;
    hosts.set(name, entry);
    while (hosts.size > MAX_HOSTS) hosts.delete(hosts.keys().next().value as string);
  }
  if (relayAlive() !== before) state.version += 1;
}

/** Whether the answer for `name` should point at the relay right now (mode, health, auto gating). */
export function relayServes(name: string, config: AppConfig): boolean {
  if (config.relayMode === "off" || !config.relayIp) return false;
  if (domainMatches(name, config.relayExcludeDomains)) return false;
  if (!domainMatches(name, config.relayDomains)) return false;
  if (!relayAlive()) return false;
  return config.relayMode === "always" || hostRelayed(name);
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
  hosts: { host: string; samples: number }[];
} {
  return {
    healthy: relayAlive(),
    livenessUntil: state.livenessUntil,
    lastSource: state.lastSource,
    lastReportAt: state.lastReportAt,
    version: state.version,
    hosts: [...hosts.keys()].map((host) => ({ host, samples: hosts.get(host)!.samples.length })),
  };
}

export function resetRelayState(): void {
  state = { healthy: false, livenessUntil: 0, lastSource: "", lastReportAt: 0, version: 1 };
  hosts.clear();
}
