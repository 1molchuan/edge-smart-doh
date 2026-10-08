import type { AppConfig, RelayForcedMode, RelayMode } from "./config";
import { domainMatches } from "./dns/ecs";
import { parseIpv4, parseIpv6 } from "./dns/packet";

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
 * answer stays untouched). That is exactly why the forced pool exists: hosts without a measured
 * pool (the Google family) can never earn their way into the relay under auto, so their names live
 * in relayForcedDomains, which only has "off" and "always" — no measurement, no hysteresis, the
 * name is pinned whenever the daemon is alive. Both pools share the relay IP, the exclude list and
 * the liveness report.
 *
 * On top of the env there is a runtime override layer (the console's control plane, POST
 * /admin/relay-config): mode and the domain lists of both pools can be changed without a restart,
 * the change bumps the version (so cached answers re-key at once) and is persisted by the Node
 * server.
 *
 * The LAN gate is the outermost condition of every relay decision, and it is a design constraint
 * rather than a tunable: the pinned answer is the relay's private address, and that answer is only
 * useful to a client that can route to it. Both pools — forced included — are therefore served to
 * LAN clients only; a client off the LAN gets the ordinary answer (preferred pool, upstream), byte
 * for byte what it would get with the relay off. A client address that cannot be parsed counts as
 * off-LAN, so an unknown source never receives a LAN address. There is deliberately no environment
 * switch: an off-LAN client cannot reach the relay at all, so "relay for the internet" is not a
 * scenario this code supports.
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
  forcedMode?: RelayForcedMode;
  forcedDomains?: string[];
}

let override: RelayOverride | null = null;
let persistOverride: ((value: RelayOverride | null) => void) | undefined;
/** One loud warning per process: an override applied with no persistence configured is lost on restart. */
let warnedVolatileOverride = false;

export interface EffectiveRelayConfig {
  mode: RelayMode;
  ip?: string;
  domains: string[];
  excludeDomains: string[];
  forcedMode: RelayForcedMode;
  forcedDomains: string[];
  /** Fields the console override owns; empty = the env values are in effect. */
  overridden: string[];
}

/**
 * Whether the address of the client behind the request is on the LAN: RFC1918 and RFC3927 IPv4,
 * their IPv4-mapped IPv6 spelling, IPv6 loopback, ULA (fc00::/7) and link-local (fe80::/10).
 * Anything else — a public address, a malformed value, or no address at all — is not on the LAN,
 * which is the safe answer: a client we cannot place must not be handed the relay's private IP.
 * The value comes from the connection (Caddy rewrites X-Real-IP from {remote_host}, see
 * deploy/Caddyfile), never from a header the client itself can set.
 */
export function isLanClientAddress(address: string | undefined): boolean {
  const value = (address ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (!value) return false;
  // Proxies spell an IPv4 client behind an IPv6 listener as ::ffff:a.b.c.d; parseIpv6 rejects the
  // dotted form, so unwrap it first. (The all-hex spelling ::ffff:c0a8:0105 is not unwrapped.)
  const mapped = value.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const candidate = mapped ? mapped[1]! : value;
  if (!candidate.includes(":")) {
    let bytes: Uint8Array;
    try {
      bytes = parseIpv4(candidate);
    } catch {
      return false;
    }
    const [a, b] = [bytes[0]!, bytes[1]!];
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }
  let bytes: Uint8Array;
  try {
    bytes = parseIpv6(candidate);
  } catch {
    return false;
  }
  if (bytes.every((byte, index) => (index === 15 ? byte === 1 : byte === 0))) return true; // ::1
  if ((bytes[0]! & 0xfe) === 0xfc) return true; // fc00::/7 (ULA)
  if (bytes[0] === 0xfe && (bytes[1]! & 0xc0) === 0x80) return true; // fe80::/10
  return false;
}

export function effectiveRelayConfig(config: AppConfig): EffectiveRelayConfig {
  const overridden: string[] = [];
  if (override?.mode !== undefined) overridden.push("mode");
  if (override?.domains !== undefined) overridden.push("domains");
  if (override?.excludeDomains !== undefined) overridden.push("excludeDomains");
  if (override?.forcedMode !== undefined) overridden.push("forcedMode");
  if (override?.forcedDomains !== undefined) overridden.push("forcedDomains");
  return {
    mode: override?.mode ?? config.relayMode,
    ip: config.relayIp,
    domains: override?.domains ?? config.relayDomains,
    excludeDomains: override?.excludeDomains ?? config.relayExcludeDomains,
    forcedMode: override?.forcedMode ?? config.relayForcedMode,
    forcedDomains: override?.forcedDomains ?? config.relayForcedDomains,
    overridden,
  };
}

function relayFingerprint(effective: EffectiveRelayConfig): string {
  return JSON.stringify([effective.mode, effective.ip ?? "", [...effective.domains].sort(), [...effective.excludeDomains].sort(), effective.forcedMode, [...effective.forcedDomains].sort()]);
}

/** Applies a console override (validated by the caller); bumps the cache version when the effective config changed. */
export function setRelayOverride(patch: RelayOverride | null, config: AppConfig): boolean {
  const before = relayFingerprint(effectiveRelayConfig(config));
  override = patch && Object.keys(patch).length > 0 ? {
    ...(patch.mode !== undefined ? { mode: patch.mode } : {}),
    ...(patch.domains !== undefined ? { domains: [...new Set(patch.domains)].slice(0, MAX_RELAY_DOMAINS) } : {}),
    ...(patch.excludeDomains !== undefined ? { excludeDomains: [...new Set(patch.excludeDomains)].slice(0, MAX_RELAY_DOMAINS) } : {}),
    ...(patch.forcedMode !== undefined ? { forcedMode: patch.forcedMode } : {}),
    ...(patch.forcedDomains !== undefined ? { forcedDomains: [...new Set(patch.forcedDomains)].slice(0, MAX_RELAY_DOMAINS) } : {}),
  } : null;
  const changed = relayFingerprint(effectiveRelayConfig(config)) !== before;
  if (changed) {
    state.version += 1;
    state.configVersion += 1;
    if (persistOverride) persistOverride(override);
    else if (!warnedVolatileOverride) {
      // A restart silently forgets everything the console changed — exactly how a whole pool's
      // configuration "disappeared" after a redeploy on 2026-10-07. Say it when it happens, not after.
      warnedVolatileOverride = true;
      console.warn(JSON.stringify({ event: "relay_override_volatile", message: "relay override applied but RELAY_CONFIG_PATH is unset: it lives in memory only and the next restart forgets it" }));
    }
  }
  return changed;
}

export function relayOverrideSnapshot(): RelayOverride | null {
  return override ? {
    ...override,
    domains: override.domains ? [...override.domains] : undefined,
    excludeDomains: override.excludeDomains ? [...override.excludeDomains] : undefined,
    forcedDomains: override.forcedDomains ? [...override.forcedDomains] : undefined,
  } : null;
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
  const forcedMode = source.forcedMode === "off" || source.forcedMode === "always" ? source.forcedMode : undefined;
  const forcedDomains = patterns(source.forcedDomains);
  const patch: RelayOverride = {
    ...(mode !== undefined ? { mode } : {}),
    ...(domains !== undefined ? { domains } : {}),
    ...(excludeDomains !== undefined ? { excludeDomains } : {}),
    ...(forcedMode !== undefined ? { forcedMode } : {}),
    ...(forcedDomains !== undefined ? { forcedDomains } : {}),
  };
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

/**
 * Whether the answer for `name` should point at the relay right now (either pool: LAN gate, mode,
 * health, auto gating). `clientLan` is the caller's finding about the client address and is
 * deliberately required: only `true` passes the gate, and an undefined finding — the caller could
 * not place the client — must not receive a LAN address either. Direct callers that simply have no
 * client (tests, internal tooling) state `true` themselves rather than getting it by omission, so a
 * forgotten argument fails closed instead of open. The gate is unconditional by design (DESIGN.md
 * §2.1.1): it is not a configuration option. The reason is the answer itself — a relayed reply
 * carries RELAY_IP, a private address, so it can only help a client that can route to it; a client
 * off the LAN times out on it (2026-10-08), and there is no "relay for the internet" case that a
 * switch could enable.
 */
export function relayServes(name: string, config: AppConfig, clientLan: boolean | undefined): boolean {
  const effective = effectiveRelayConfig(config);
  if (!effective.ip || !relayAlive()) return false;
  if (clientLan !== true) return false; // off-LAN, unknown or unparsable client = no relay
  if (domainMatches(name, effective.excludeDomains)) return false;
  // The forced pool answers unconditionally (within liveness): its hosts have no measured pool, so
  // auto could never judge them — see the interface comment on AppConfig.relayForcedDomains.
  if (effective.forcedMode === "always" && domainMatches(name, effective.forcedDomains)) return true;
  if (effective.mode === "off") return false;
  if (!domainMatches(name, effective.domains)) return false;
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
  envMode: RelayMode;
  forcedMode: RelayForcedMode;
  forcedModeSource: "env" | "override";
  forcedDomains: string[];
  envForcedDomains: string[];
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
    envMode: config.relayMode,
    forcedMode: effective.forcedMode,
    forcedModeSource: effective.overridden.includes("forcedMode") ? "override" : "env",
    forcedDomains: effective.forcedDomains,
    envForcedDomains: config.relayForcedDomains,
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
