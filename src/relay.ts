import type { AppConfig, RelayMode } from "./config";
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
 *
 * On top of the env there is a runtime override layer (the console's control plane, POST
 * /admin/relay-config): mode and the two domain lists can be changed without a restart, the change
 * bumps the version (so cached answers re-key at once) and is persisted by the Node server.
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
const MAX_RELAY_DOMAINS = 64;

/**
 * Console overrides on top of the env (POST /admin/relay-config): each field, when present, replaces
 * the env value until cleared with `reset`. Kept in memory here and persisted by the Node server
 * (see server/node.ts) so a restart does not undo what the operator clicked. The IP is deliberately
 * not overridable: it must agree with the daemon's listen address, the second-IP unit and the
 * firewall, none of which can be safely changed at runtime.
 */
export interface RelayOverride {
  mode?: RelayMode;
  domains?: string[];
  excludeDomains?: string[];
}

let override: RelayOverride | null = null;
let persistOverride: ((value: RelayOverride | null) => void) | undefined;

export interface EffectiveRelayConfig {
  mode: RelayMode;
  ip?: string;
  domains: string[];
  excludeDomains: string[];
  /** Fields the console override owns; empty = the env values are in effect. */
  overridden: string[];
}

export function effectiveRelayConfig(config: AppConfig): EffectiveRelayConfig {
  const overridden: string[] = [];
  if (override?.mode !== undefined) overridden.push("mode");
  if (override?.domains !== undefined) overridden.push("domains");
  if (override?.excludeDomains !== undefined) overridden.push("excludeDomains");
  return {
    mode: override?.mode ?? config.relayMode,
    ip: config.relayIp,
    domains: override?.domains ?? config.relayDomains,
    excludeDomains: override?.excludeDomains ?? config.relayExcludeDomains,
    overridden,
  };
}

function relayFingerprint(effective: EffectiveRelayConfig): string {
  return JSON.stringify([effective.mode, effective.ip ?? "", [...effective.domains].sort(), [...effective.excludeDomains].sort()]);
}

/** Applies a console override (validated by the caller); bumps the cache version when the effective config changed. */
export function setRelayOverride(patch: RelayOverride | null, config: AppConfig): boolean {
  const before = relayFingerprint(effectiveRelayConfig(config));
  override = patch && Object.keys(patch).length > 0 ? {
    ...(patch.mode !== undefined ? { mode: patch.mode } : {}),
    ...(patch.domains !== undefined ? { domains: [...new Set(patch.domains)].slice(0, MAX_RELAY_DOMAINS) } : {}),
    ...(patch.excludeDomains !== undefined ? { excludeDomains: [...new Set(patch.excludeDomains)].slice(0, MAX_RELAY_DOMAINS) } : {}),
  } : null;
  const changed = relayFingerprint(effectiveRelayConfig(config)) !== before;
  if (changed) {
    state.version += 1;
    state.configVersion += 1;
    persistOverride?.(override);
  }
  return changed;
}

export function relayOverrideSnapshot(): RelayOverride | null {
  return override ? { ...override, domains: override.domains ? [...override.domains] : undefined, excludeDomains: override.excludeDomains ? [...override.excludeDomains] : undefined } : null;
}

/** Registers the persistence hook; the Node server writes the override to its state directory, workers keep it in memory. */
export function setRelayPersistence(save: ((value: RelayOverride | null) => void) | undefined): void {
  persistOverride = save;
}

// Domain patterns as the env accepts them: a bare hostname (exact match) or a `*.`/leading-dot
// suffix (which also covers the bare domain). Same regex contract as the HOSTNAME check in index.ts.
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** Normalizes one pattern entry (lowercase, no trailing dot) or rejects it with null. */
export function parseRelayDomainPattern(value: string): string | null {
  const clean = value.trim().toLowerCase().replace(/\.$/, "");
  if (!clean || clean.length > 255) return null;
  const bare = clean.replace(/^\*\./, "").replace(/^\./, "");
  return HOSTNAME.test(bare) ? clean : null;
}

/** Strict shape check for persisted/foreign JSON (the Node boot path); anything odd drops the field. */
export function sanitizeRelayOverride(value: unknown): RelayOverride | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const source = value as Record<string, unknown>;
  const patterns = (raw: unknown): string[] | undefined =>
    Array.isArray(raw) ? [...new Set(raw.filter((entry): entry is string => typeof entry === "string").map((entry) => parseRelayDomainPattern(entry)).filter((entry): entry is string => entry !== null))].slice(0, MAX_RELAY_DOMAINS) : undefined;
  const mode = source.mode === "off" || source.mode === "auto" || source.mode === "always" ? source.mode : undefined;
  const domains = patterns(source.domains);
  const excludeDomains = patterns(source.excludeDomains);
  const patch: RelayOverride = { ...(mode !== undefined ? { mode } : {}), ...(domains !== undefined ? { domains } : {}), ...(excludeDomains !== undefined ? { excludeDomains } : {}) };
  return Object.keys(patch).length > 0 ? patch : null;
}

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
  /**
   * Configuration epoch, separate from `version`: the per-host state machine bumps `version` on
   * every relayed/direct flip, while configVersion moves only when mode or the domain lists change.
   * The console shows it and the daemon echoes back the one it applied (appliedConfigVersion), so
   * "同步中" vs "已同步" is observable.
   */
  configVersion: number;
  /** The configVersion the relay daemon last confirmed applying (from its health report). */
  appliedConfigVersion: number;
}

let state: RelayState = { healthy: false, livenessUntil: 0, lastSource: "", lastReportAt: 0, version: 1, configVersion: 1, appliedConfigVersion: 0 };
const hosts = new Map<string, HostState>();

export interface RelayHealthReport {
  source: string;
  ttlSeconds: number;
  healthy: boolean;
  direct?: Record<string, RelayDirectSample>;
  /** The configVersion the daemon confirmed applying (domain-list sync receipt). */
  appliedConfigVersion?: number;
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
    configVersion: state.configVersion,
    appliedConfigVersion: Math.max(state.appliedConfigVersion, report.appliedConfigVersion ?? 0),
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
  const effective = effectiveRelayConfig(config);
  if (effective.mode === "off" || !effective.ip) return false;
  if (domainMatches(name, effective.excludeDomains)) return false;
  if (!domainMatches(name, effective.domains)) return false;
  if (!relayAlive()) return false;
  return effective.mode === "always" || hosts.get(name)?.relayed === true;
}

export function relayCacheTag(): string {
  return `relay=v${state.version}`;
}

export function relayStatus(config: AppConfig): {
  mode: RelayMode;
  modeSource: "env" | "override";
  overridden: string[];
  ip: string | null;
  domains: string[];
  excludes: string[];
  envDomains: string[];
  envExcludes: string[];
  healthy: boolean;
  livenessUntil: number;
  lastSource: string;
  lastReportAt: number;
  version: number;
  configVersion: number;
  appliedConfigVersion: number;
  hosts: { host: string; relayed: boolean; samples: number; enterRate: number | null; exitRate: number | null; lastSampleAt: number }[];
} {
  const effective = effectiveRelayConfig(config);
  return {
    mode: effective.mode,
    modeSource: effective.overridden.includes("mode") ? "override" : "env",
    overridden: effective.overridden,
    ip: effective.ip ?? null,
    domains: effective.domains,
    excludes: effective.excludeDomains,
    envDomains: config.relayDomains,
    envExcludes: config.relayExcludeDomains,
    healthy: relayAlive(),
    livenessUntil: state.livenessUntil,
    lastSource: state.lastSource,
    lastReportAt: state.lastReportAt,
    version: state.version,
    configVersion: state.configVersion,
    appliedConfigVersion: state.appliedConfigVersion,
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
  state = { healthy: false, livenessUntil: 0, lastSource: "", lastReportAt: 0, version: 1, configVersion: 1, appliedConfigVersion: 0 };
  hosts.clear();
  override = null;
}
