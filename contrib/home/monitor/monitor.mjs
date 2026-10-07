#!/usr/bin/env node
/**
 * edge-smart-doh 局域网控制台（contrib/home/monitor）——单文件、零依赖，Node ≥18。
 *
 * 两个页面（同进程、同端口）：
 *   · /          监控页：公开只读（不需要密码）。健康判定、查询统计、路径分布、图表、诊断。
 *   · /console   控制页：需要密码（CONSOLE_PASSWORD）。SNI 中转双池控制（主池三档 / 强制池两档）、
 *                名单编辑、操作记录（审计）。
 *
 * 访问控制（三层防线）：
 *   1. 来源过滤：默认绑定 0.0.0.0，但每个请求按 TCP 对端地址（socket.remoteAddress，绝不信任
 *      X-Forwarded-For 等可伪造头）过滤：仅回环、RFC1918、CGNAT、ULA、链路本地放行；
 *   2. 密码会话：CONSOLE_PASSWORD（monitor.env，0600 root）只把守控制页与控制端点（/api/relay*、
 *      /api/audit）。会话仅存本进程内存，HttpOnly + SameSite=Strict cookie，2h 空闲 + 24h 绝对
 *      过期，进程重启全部失效；每 IP 5 次失败冷却 60s。未设密码时控制页显示启用指引——监控页
 *      永远不需要密码；
 *   3. 凭据隔离：ADMIN_TOKEN 只存在本进程内存，页面只见会话 cookie，绝不回传。
 *   纵深防御：deploy-home.sh 的 nftables 规则（SETUP_FIREWALL=1）在网络层再限一次内网网段。
 *
 * 主题：明暗两套（CSS 变量切换），默认跟随系统偏好，手动切换存 localStorage。
 *
 * 其他配置（环境变量）：DOH_URL、ADMIN_TOKEN、CONSOLE_PASSWORD、MONITOR_HOST、MONITOR_PORT、
 *   MONITOR_INTERVAL_MS（采样间隔，≥5000）、MONITOR_PROBE_NAMES、MONITOR_PROBE_LABELS、
 *   MONITOR_ALLOW、MONITOR_PROBE_TIMEOUT_MS。
 */

import { createServer } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

// ============================== 配置 ==============================

const DOH_URL = (process.env.DOH_URL ?? "http://127.0.0.1:8787").replace(/\/+$/, "");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";
const CONSOLE_PASSWORD = process.env.CONSOLE_PASSWORD ?? "";
const HOST = process.env.MONITOR_HOST ?? "0.0.0.0";
const PORT = Number.parseInt(process.env.MONITOR_PORT ?? "8788", 10);
const INTERVAL_MS = Math.max(5000, Number.parseInt(process.env.MONITOR_INTERVAL_MS ?? "10000", 10));
const PROBE_TIMEOUT_MS = Math.max(1000, Number.parseInt(process.env.MONITOR_PROBE_TIMEOUT_MS ?? "5000", 10));
const PROBE_NAMES = (process.env.MONITOR_PROBE_NAMES ?? "www.taobao.com,github.com,www.google.com")
  .split(",").map((name) => name.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean).slice(0, 12);
const PROBE_LABELS = (process.env.MONITOR_PROBE_LABELS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
function probeLabel(name, index) {
  if (PROBE_LABELS[index]) return PROBE_LABELS[index];
  if (/github/.test(name)) return "GitHub 池";
  if (/(^|\.)(taobao|tmall|baidu|qq\.com|weibo|bilibili|jd\.com|aliyun|tencent|163\.com|zhihu|douyin)/.test(name)) return "国内直连";
  return "境外 / 代理";
}
const HISTORY_MAX = 360; // 每个探测域名的延迟历史（默认 10s 一采样 ≈ 1 小时）
const HISTORY_SENT = 240; // 发给页面的点数（约 40 分钟）

/** 有密码 = 控制页与控制端点要登录；监控页永远公开。控制端点还要求 ADMIN_TOKEN。 */
const AUTH_REQUIRED = CONSOLE_PASSWORD.length > 0;
const CONTROL_ENABLED = AUTH_REQUIRED && ADMIN_TOKEN.length > 0;

const PRIVATE_RANGES = [
  "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
  "::1/128", "fe80::/10", "fc00::/7",
];
const ALLOW_SPEC = (process.env.MONITOR_ALLOW ?? "private")
  .split(",").map((item) => item.trim()).filter(Boolean);
const ALLOW = ALLOW_SPEC.flatMap((item) => item === "private" ? PRIVATE_RANGES : [item])
  .map(parseCidr).filter(Boolean);
if (ALLOW.length === 0) {
  console.error(JSON.stringify({ event: "monitor_config_error", message: "MONITOR_ALLOW 未解析出任何网段，拒绝所有来源" }));
}

// ============================== 来源过滤 ==============================

function parseV4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const [a, b, c, d] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function parseV6(ip) {
  if (!ip.includes(":")) return null;
  const dc = ip.indexOf("::");
  const head = dc === -1 ? ip : ip.slice(0, dc);
  const tail = dc === -1 ? null : ip.slice(dc + 2);
  const groups = (part) => {
    if (part === "") return [];
    const out = [];
    const pieces = part.split(":");
    for (let i = 0; i < pieces.length; i += 1) {
      const piece = pieces[i];
      if (piece.includes(".")) {
        if (i !== pieces.length - 1) return null; // 内嵌 IPv4 只能出现在末尾
        const v4 = parseV4(piece);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
        out.push(parseInt(piece, 16));
      }
    }
    return out;
  };
  const h = groups(head);
  if (h === null) return null;
  let t = tail === null ? [] : groups(tail);
  if (t === null) return null;
  const total = h.length + t.length;
  if (tail === null) { if (total !== 8) return null; }
  else { if (total > 8) return null; for (let i = total; i < 8; i += 1) t.push(0); }
  let value = 0n;
  for (const g of [...h, ...t]) value = (value << 16n) | BigInt(g);
  return value;
}

function parseCidr(cidr) {
  const slash = cidr.lastIndexOf("/");
  const addr = slash === -1 ? cidr : cidr.slice(0, slash);
  const prefix = slash === -1 ? null : Number.parseInt(cidr.slice(slash + 1), 10);
  const v4 = parseV4(addr);
  if (v4 !== null) {
    const bits = prefix ?? 32;
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { family: 4, value: v4, mask };
  }
  const v6 = parseV6(addr);
  if (v6 !== null) {
    const bits = prefix ?? 128;
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
    const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
    return { family: 6, value: v6, mask };
  }
  return null;
}

/** 归一化 TCP 对端地址（::ffff: 映射形式折算成 IPv4）并与放行网段比对。 */
function sourceAllowed(remoteAddress) {
  if (!remoteAddress) return false;
  let ip = remoteAddress.toLowerCase();
  const mapped = /^::ffff:(.+)$/.exec(ip);
  if (mapped) ip = mapped[1];
  const v4 = parseV4(ip);
  if (v4 !== null) {
    return ALLOW.some(({ family, value, mask }) => family === 4 && ((v4 & mask) >>> 0) === ((value & mask) >>> 0));
  }
  const v6 = parseV6(ip);
  if (v6 !== null) {
    return ALLOW.some(({ family, value, mask }) => family === 6 && (v6 & mask) === (value & mask));
  }
  return false;
}

const denyLog = new Map(); // ip -> { count, last }
function logDenied(ip) {
  const now = Date.now();
  const entry = denyLog.get(ip) ?? { count: 0, last: 0 };
  entry.count += 1;
  if (now - entry.last > 60_000) {
    console.warn(JSON.stringify({ event: "monitor_denied", ip, count: entry.count }));
    entry.last = now;
    entry.count = 0;
  }
  denyLog.set(ip, entry);
  if (denyLog.size > 1024) denyLog.clear();
}

// ============================== 会话 / 防爆破 / 审计 ==============================

const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;   // 空闲 2 小时（滑动）
const SESSION_ABSOLUTE_MS = 24 * 60 * 60 * 1000; // 绝对 24 小时
const SESSION_MAX = 64;
const LOGIN_FAIL_LIMIT = 5;
const LOGIN_COOLDOWN_MS = 60_000;

/** id -> { label, ip, createdAt, lastSeenAt }；仅内存，重启即全部失效。 */
const sessions = new Map();

function passwordMatches(input) {
  const a = createHash("sha256").update(String(input ?? "")).digest();
  const b = createHash("sha256").update(CONSOLE_PASSWORD).digest();
  return timingSafeEqual(a, b);
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

/** 有效会话（顺手续期）；过期/未知 id 返回 null。 */
function sessionOf(request) {
  if (!AUTH_REQUIRED) return null;
  const id = parseCookies(request.headers.cookie)["console_session"];
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return { id, ...session };
}

function openSession(ip, label) {
  const id = randomBytes(32).toString("hex");
  const now = Date.now();
  sessions.set(id, { label, ip, createdAt: now, lastSeenAt: now });
  while (sessions.size > SESSION_MAX) sessions.delete(sessions.keys().next().value);
  return id;
}

/** 需要登录的控制端点统一走这里：返回 Response 即拒绝。 */
function requireSession(request) {
  if (!AUTH_REQUIRED) return undefined;
  const session = sessionOf(request);
  if (session) return undefined;
  return jsonResponse(401, { error: "未登录或会话已过期" });
}

const loginFailures = new Map(); // ip -> { count, cooldownUntil }

function loginDenied(ip) {
  const entry = loginFailures.get(ip) ?? { count: 0, cooldownUntil: 0 };
  entry.count += 1;
  if (entry.count >= LOGIN_FAIL_LIMIT) {
    entry.cooldownUntil = Date.now() + LOGIN_COOLDOWN_MS;
    entry.count = 0;
  }
  loginFailures.set(ip, entry);
  if (loginFailures.size > 1024) loginFailures.clear();
  return entry;
}

function loginCooldown(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return 0;
  const left = entry.cooldownUntil - Date.now();
  return left > 0 ? Math.ceil(left / 1000) : 0;
}

/** 内存环形操作记录（页面 50 条 / API 100 条）+ journald 结构化日志。 */
const auditLog = [];
const AUDIT_MAX = 100;

function audit(action, { ip = "", label = "", result = "ok", detail = "" } = {}) {
  // 连续登录失败聚合成一条：同 IP 60s 内的失败只累计次数
  if (action === "login-fail") {
    const last = auditLog[auditLog.length - 1];
    if (last && last.action === "login-fail" && last.ip === ip && Date.now() - last.t < 60_000) {
      last.count = (last.count ?? 1) + 1;
      last.t = Date.now();
      console.log(JSON.stringify({ event: "console_audit", ...last }));
      return;
    }
  }
  const entry = { t: Date.now(), action, ip, label, result, detail };
  if (action === "login-fail") entry.count = 1;
  auditLog.push(entry);
  if (auditLog.length > AUDIT_MAX) auditLog.splice(0, auditLog.length - AUDIT_MAX);
  console.log(JSON.stringify({ event: "console_audit", ...entry }));
}

// ============================== DoH 探测 ==============================

/** 手工构造一条最小 A 查询的线格式包（零依赖，不引 DNS 库）。 */
function dnsQueryPacket(name) {
  const id = Math.floor(Math.random() * 0xffff);
  const labels = name.split(".").map((label) => Buffer.concat([Buffer.from([label.length & 0x3f]), Buffer.from(label, "ascii")]));
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const question = Buffer.concat([...labels, Buffer.from([0])]);
  const typeClass = Buffer.alloc(4);
  typeClass.writeUInt16BE(1, 0); // A
  typeClass.writeUInt16BE(1, 2); // IN
  return Buffer.concat([header, question, typeClass]);
}

function describeError(error) {
  const cause = error?.cause ? `: ${error.cause.code ?? error.cause.message ?? error.cause}` : "";
  return String(error?.message ?? error).slice(0, 160) + cause;
}

async function fetchJson(path, timeoutMs) {
  const response = await fetch(`${DOH_URL}${path}`, {
    headers: ADMIN_TOKEN ? { Authorization: `Bearer ${ADMIN_TOKEN}` } : {},
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    const hint = response.status === 401 ? "（ADMIN_TOKEN 不对）"
      : response.status === 404 ? "（主服务还没有 /admin/stats，需要重启到新版本）" : "";
    throw Object.assign(new Error(`HTTP ${response.status}${hint}`), { status: response.status });
  }
  return response.json();
}

async function probeOne(probe) {
  const packet = dnsQueryPacket(probe.name);
  const started = Date.now();
  try {
    const response = await fetch(`${DOH_URL}/dns-query?dns=${packet.toString("base64url")}`, {
      headers: { Accept: "application/dns-message" },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const ms = Date.now() - started;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const wire = Buffer.from(await response.arrayBuffer());
    if (wire.length < 12) throw new Error("应答过短");
    const id = wire.readUInt16BE(0);
    const flags = wire.readUInt16BE(2);
    if ((flags & 0x8000) === 0) throw new Error("不是应答包");
    if (id !== packet.readUInt16BE(0)) throw new Error("事务 ID 不匹配");
    const rcode = flags & 0x000f;
    const ok = rcode === 0;
    probe.ok = ok;
    probe.latencyMs = ms;
    probe.rcode = rcode;
    probe.error = ok ? null : `rcode ${rcode}`;
    probe.history.push({ t: Date.now(), ms, ok });
  } catch (error) {
    probe.ok = false;
    probe.latencyMs = Date.now() - started;
    probe.rcode = null;
    probe.error = describeError(error);
    probe.history.push({ t: Date.now(), ms: probe.latencyMs, ok: false });
  }
  if (probe.history.length > HISTORY_MAX) probe.history.splice(0, probe.history.length - HISTORY_MAX);
  probe.lastCheck = Date.now();
}

// ============================== 采样循环 ==============================

const state = {
  startedAt: Date.now(),
  doh: { ok: null, latencyMs: null, error: null, lastCheck: null },
  stats: null,
  statsError: null,
  statsAt: null,
  cycles: 0,
  probes: PROBE_NAMES.map((name, index) => ({ name, label: probeLabel(name, index), ok: null, latencyMs: null, rcode: null, error: null, lastCheck: null, history: [] })),
};

/** 控制台进程缓存的 relay 状态：控制操作成功时立即更新，供审计 before/after 与错误上下文。 */
let RELAY = null;

async function pollOnce() {
  const started = Date.now();
  try {
    const response = await fetch(`${DOH_URL}/health`, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    state.doh = { ok: response.ok, latencyMs: Date.now() - started, error: response.ok ? null : `HTTP ${response.status}`, lastCheck: Date.now() };
  } catch (error) {
    state.doh = { ok: false, latencyMs: Date.now() - started, error: describeError(error), lastCheck: Date.now() };
  }
  try {
    state.stats = await fetchJson("/admin/stats", PROBE_TIMEOUT_MS);
    state.statsError = null;
    state.statsAt = Date.now();
  } catch (error) {
    state.statsError = describeError(error);
  }
  for (const probe of state.probes) await probeOne(probe);
  state.cycles += 1;
}

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    await pollOnce();
  } catch (error) {
    console.warn(JSON.stringify({ event: "monitor_poll_error", message: describeError(error) }));
  } finally {
    polling = false;
  }
}

// ============================== 汇总（公开：监控页不需要密码） ==============================

function summary(request) {
  const session = AUTH_REQUIRED ? sessionOf(request) : null;
  return {
    now: Date.now(),
    console: {
      authRequired: AUTH_REQUIRED,
      control: CONTROL_ENABLED,
      session: session ? { valid: true, label: session.label, ip: session.ip } : null,
    },
    monitor: {
      startedAt: state.startedAt,
      intervalMs: INTERVAL_MS,
      dohUrl: DOH_URL,
      allow: ALLOW_SPEC.join(","),
      cycles: state.cycles,
    },
    doh: state.doh,
    stats: state.stats,
    statsError: state.statsError,
    statsAt: state.statsAt,
    probes: state.probes.map((probe) => ({
      name: probe.name,
      label: probe.label,
      ok: probe.ok,
      latencyMs: probe.latencyMs,
      rcode: probe.rcode,
      error: probe.error,
      lastCheck: probe.lastCheck,
      history: probe.history.slice(-HISTORY_SENT),
    })),
  };
}

// ============================== 控制代理 ==============================

function jsonResponse(status, value) {
  return [status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }, JSON.stringify(value)];
}

/**
 * 转发控制操作到主服务 /admin/relay-config。错误一律带可读文案（运维 Agent 靠文案决策）：
 * 400/409 原样透传主服务的解释；主服务不可达 → 502 + 原因；ADMIN_TOKEN 失配 → 401 专用文案。
 */
async function relayConfigProxy(body) {
  if (!CONTROL_ENABLED) return jsonResponse(404, { error: "控制功能未启用（需要 CONSOLE_PASSWORD 与 ADMIN_TOKEN）" });
  let response;
  try {
    response = await fetch(`${DOH_URL}/admin/relay-config`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(Math.max(PROBE_TIMEOUT_MS, 8000)),
    });
  } catch (error) {
    return jsonResponse(502, { error: `配置未更改：主服务不可达（${describeError(error)}）`, cause: "upstream-unreachable", hint: "journalctl -u edge-smart-doh -n 30" });
  }
  const text = await response.text();
  if (response.status === 401) {
    return jsonResponse(502, { error: "ADMIN_TOKEN 与主服务不一致（是否改过主 env？在服务器上重跑 install-monitor.sh）", cause: "admin-token-mismatch" });
  }
  if (!response.ok) {
    // 主服务 400 多为纯文本解释、409 为 JSON：都归一成 {error[, configVersion]}
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    const error = typeof parsed?.error === "string" ? parsed.error : text.slice(0, 300) || `主服务返回 HTTP ${response.status}`;
    return jsonResponse(response.status, { error, ...(typeof parsed?.configVersion === "number" ? { configVersion: parsed.configVersion } : {}) });
  }
  return [200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, text];
}

/** 只允许已知字段透传，绝不当通用代理。 */
function sanitizeRelayConfigBody(value) {
  const out = {};
  if (value?.mode !== undefined) out.mode = value.mode;
  if (value?.domains !== undefined) out.domains = value.domains;
  if (value?.excludeDomains !== undefined) out.excludeDomains = value.excludeDomains;
  if (value?.forcedMode !== undefined) out.forcedMode = value.forcedMode;
  if (value?.forcedDomains !== undefined) out.forcedDomains = value.forcedDomains;
  if (value?.expectedVersion !== undefined) out.expectedVersion = value.expectedVersion;
  if (value?.reset !== undefined) out.reset = value.reset;
  return out;
}

async function relayStatusProxy() {
  if (!CONTROL_ENABLED) return jsonResponse(404, { error: "控制功能未启用（需要 CONSOLE_PASSWORD 与 ADMIN_TOKEN）" });
  try {
    const response = await fetch(`${DOH_URL}/admin/relay`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const text = await response.text();
    if (response.status === 401) return jsonResponse(502, { error: "ADMIN_TOKEN 与主服务不一致（是否改过主 env？在服务器上重跑 install-monitor.sh）", cause: "admin-token-mismatch" });
    if (!response.ok) return jsonResponse(502, { error: `主服务返回 HTTP ${response.status}`, cause: "upstream-error" });
    return [200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, text];
  } catch (error) {
    return jsonResponse(502, { error: `主服务不可达（${describeError(error)}）`, cause: "upstream-unreachable" });
  }
}

/** 读取（并限制大小）JSON 请求体；超限或坏 JSON 一律 null（不销毁连接，排干即可）。 */
function readJsonBody(request, maxBytes = 8192) {
  return new Promise((resolve) => {
    const chunks = [];
    let length = 0;
    let overflow = false;
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > maxBytes) {
        overflow = true;
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (overflow || chunks.length === 0) return resolve(null);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        resolve(null);
      }
    });
    request.on("error", () => resolve(null));
  });
}

// ============================== 页面资源 ==============================

// ECharts 由本地 vendor 目录提供（无公网依赖）；缺失时页面自动降级为"表格仍可用"。
const VENDOR_ECHARTS = new URL("./vendor/echarts.min.js", import.meta.url);
let echartsJs = null;
try {
  echartsJs = readFileSync(VENDOR_ECHARTS);
} catch {
  console.warn(JSON.stringify({ event: "monitor_vendor_missing", file: "vendor/echarts.min.js", hint: "图表面板将显示加载失败提示，表格不受影响" }));
}

// ============================== 共享样式（明暗双主题） ==============================

const CSS_COMMON = `
  :root {
    color-scheme: dark;
    --bg: #060a14; --s1: #0c1326; --s2: #0e1730; --s3: #0a1120;
    --line: #1b2547; --line-2: #141d38;
    --ink: #e7edf9; --ink-2: #97a2bf; --ink-3: #5d6a8c;
    --blue: #4f8dff; --ok: #34d399; --warn: #fbbf24; --bad: #f87171; --amber: #f59e0b;
    --bar-bg: rgba(6,10,20,.82); --tile-hover: #27345e; --track: #182345;
    --sb-hit: rgba(52,211,153,.8); --sb-miss: rgba(56,189,248,.8); --sb-err: rgba(248,113,113,.85);
    --chip-bg: #0d1834; --chip-line: #1e3a8a; --chip-ink: #93c5fd;
    --chip-ex-bg: #2c1216; --chip-ex-line: #7f1d1d; --chip-ex-ink: #fca5a5;
    --b-hit: #6ee7b7 #065f46 #06281e; --b-prefetch: #5eead4 #115e59 #04201e; --b-stale: #fcd34d #78350f #2a1c06;
    --b-miss: #93c5fd #1e40af #0d1834; --b-blocked: #d8b4fe #6b21a8 #20102e; --b-error: #fca5a5 #7f1d1d #2c1216;
    --head-ink: #b9c4de;
    --cwarn-bg: #2a1c06; --cwarn-line: #78350f; --cwarn-ink: #fcd34d;
    --cinfo-bg: #04201e; --cinfo-line: #115e59; --cinfo-ink: #5eead4;
    --cres-ok-bg: #06281e; --cres-ok-line: #065f46; --cres-ok-ink: #6ee7b7;
    --cres-err-bg: #2c1216; --cres-err-line: #7f1d1d; --cres-err-ink: #fca5a5;
    --deck-line: #54320d; --deck-edge: #6d3b0a; --deck-glow: rgba(245,158,11,.12);
    --seg-ink: #d7c9ae; --seg-hover: rgba(245,158,11,.1); --seg-on-bg: rgba(245,158,11,.16); --seg-on-ink: #fcd34d;
    --src-ink: #f59e0b; --src-line: #78350f; --src-bg: #2a1c06;
    --overlay: rgba(3,6,14,.74);
    --glow-ok: rgba(52,211,153,.14); --glow-warn: rgba(251,191,36,.13); --glow-bad: rgba(248,113,113,.16);
    --err-ink: #fca5a5; --ok-ink: #6ee7b7;
    --chart-axis: #6b7694; --chart-split: #182345; --chart-hit: #34d399; --chart-miss: #38bdf8; --chart-err: #f87171; --chart-bar: #818cf8;
    --shadow: 0 24px 70px rgba(0,0,0,.5);
  }
  html[data-theme="light"] {
    color-scheme: light;
    --bg: #eef1f7; --s1: #ffffff; --s2: #f0f4fa; --s3: #f7f9fd;
    --line: #d9e0ee; --line-2: #e7ecf5;
    --ink: #1c2436; --ink-2: #5a6478; --ink-3: #8b95ac;
    --blue: #2563eb; --ok: #059669; --warn: #b45309; --bad: #dc2626; --amber: #b45309;
    --bar-bg: rgba(255,255,255,.88); --tile-hover: #c8d3ea; --track: #e3e9f4;
    --sb-hit: rgba(5,150,105,.75); --sb-miss: rgba(37,99,235,.72); --sb-err: rgba(220,38,38,.8);
    --chip-bg: #eef4ff; --chip-line: #b6ccf5; --chip-ink: #1d4ed8;
    --chip-ex-bg: #fdecec; --chip-ex-line: #f0b6b6; --chip-ex-ink: #b91c1c;
    --b-hit: #047857 #a7dbc4 #e6f7ef; --b-prefetch: #0f766e #9ad8cf #e6f7f5; --b-stale: #92600a #ecc580 #fdf3e0;
    --b-miss: #1d4ed8 #b6ccf5 #eef4ff; --b-blocked: #7c3aed #d8c7f7 #f4eefe; --b-error: #b91c1c #f0b6b6 #fdeaea;
    --head-ink: #43506b;
    --cwarn-bg: #fdf3e0; --cwarn-line: #ecc580; --cwarn-ink: #92600a;
    --cinfo-bg: #e6f7f3; --cinfo-line: #9ad8cb; --cinfo-ink: #0f766e;
    --cres-ok-bg: #e6f7ef; --cres-ok-line: #9ad8bc; --cres-ok-ink: #0f766e;
    --cres-err-bg: #fdeaea; --cres-err-line: #f0b6b6; --cres-err-ink: #b91c1c;
    --deck-line: #ecc580; --deck-edge: #e2b46a; --deck-glow: rgba(180,83,9,.07);
    --seg-ink: #7c5a1e; --seg-hover: rgba(180,83,9,.08); --seg-on-bg: rgba(180,83,9,.14); --seg-on-ink: #92600a;
    --src-ink: #92600a; --src-line: #ecc580; --src-bg: #fdf3e0;
    --overlay: rgba(15,23,42,.45);
    --glow-ok: rgba(5,150,105,.1); --glow-warn: rgba(180,83,9,.1); --glow-bad: rgba(220,38,38,.1);
    --err-ink: #b91c1c; --ok-ink: #0f766e;
    --chart-axis: #5a6478; --chart-split: #dfe6f2; --chart-hit: #059669; --chart-miss: #2563eb; --chart-err: #dc2626; --chart-bar: #6366f1;
    --shadow: 0 18px 44px rgba(30,41,59,.14);
  }
  * { box-sizing: border-box; }
  html { scrollbar-color: var(--line) var(--bg); }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font: 14px/1.55 system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 20px 22px 48px; }

  /* ===================== 命令栏 ===================== */
  .bar {
    position: sticky; top: 0; z-index: 30;
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    margin: -20px -22px 18px; padding: 11px 22px;
    background: var(--bar-bg); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }
  .brand { display: flex; align-items: center; gap: 9px; }
  .brand b { font-size: 14.5px; letter-spacing: .2px; }
  .nav { display: flex; gap: 4px; }
  .nav a { color: var(--ink-2); text-decoration: none; font-size: 13px; padding: 5px 15px; border-radius: 9px; border: 1px solid transparent; }
  .nav a.on { color: var(--ink); background: var(--s2); border-color: var(--line); font-weight: 600; }
  .nav a:hover:not(.on) { color: var(--ink); }
  .pill {
    display: inline-flex; align-items: center; gap: 8px;
    border: 1px solid var(--line); border-radius: 999px; padding: 3px 12px 3px 9px;
    font-size: 12.5px; color: var(--ink-2); background: var(--s1);
  }
  .pill-dot { width: 9px; height: 9px; border-radius: 50%; background: #64748b; flex: none; }
  .pill-dot.ok { background: var(--ok); box-shadow: 0 0 8px var(--ok); }
  .pill-dot.warn { background: var(--warn); box-shadow: 0 0 8px var(--warn); }
  .pill-dot.bad { background: var(--bad); animation: pulse 1.2s ease-out infinite; }
  .bar-right { margin-left: auto; display: flex; align-items: center; gap: 10px; }
  .clock { color: var(--ink-3); font-size: 12.5px; font-variant-numeric: tabular-nums; letter-spacing: .5px; }
  .tbtn { background: var(--s1); border: 1px solid var(--line); color: var(--ink-2); border-radius: 9px; padding: 4px 11px; cursor: pointer; font-size: 12.5px; }
  .tbtn:hover { color: var(--ink); border-color: var(--blue); }

  #session-box { display: none; align-items: center; gap: 8px; color: var(--ink-2); font-size: 12px; }
  #session-box.show { display: inline-flex; }
  #session-box .slabel { border: 1px solid var(--line); border-radius: 999px; padding: 1px 9px; background: var(--s1); }
  #session-box button { background: none; border: 1px solid var(--line); color: var(--ink-2); border-radius: 6px; padding: 2px 9px; font-size: 11.5px; cursor: pointer; }
  #session-box button:hover { color: var(--ink); border-color: var(--blue); }

  /* ===================== 分区标题 / 磁贴 ===================== */
  .sect { display: flex; align-items: baseline; gap: 8px; margin: 22px 2px 10px; }
  .sect-tick { width: 4px; height: 13px; border-radius: 2px; background: var(--blue); align-self: center; }
  .sect-tick.amber { background: var(--amber); }
  .sect-t { font-size: 13px; font-weight: 700; letter-spacing: .12em; color: var(--head-ink); }
  .sect-s { color: var(--ink-3); font-size: 11px; letter-spacing: .14em; }

  .tile {
    background: var(--s1); border: 1px solid var(--line); border-radius: 16px;
    padding: 16px 18px; min-width: 0; transition: border-color .15s;
  }
  .tile:hover { border-color: var(--tile-hover); }

  .bento { display: grid; grid-template-columns: 1.35fr 1fr 1fr 1fr; gap: 12px; }
  .bento .status { grid-row: span 2; display: flex; flex-direction: column; }
  .bento .linktile { grid-column: 2 / -1; }
  @media (max-width: 980px) { .bento { grid-template-columns: 1fr 1fr; } .bento .status { grid-row: auto; grid-column: 1 / -1; } .bento .linktile { grid-column: 1 / -1; } }
  @media (max-width: 560px) { .bento { grid-template-columns: 1fr; } .bento .status, .bento .linktile { grid-column: auto; } }

  .status { position: relative; overflow: hidden; }
  .status::after { content: ""; position: absolute; inset: 0; pointer-events: none; transition: opacity .3s; }
  .status.ok::after { background: radial-gradient(340px 160px at 12% 0%, var(--glow-ok), transparent 70%); }
  .status.warn::after { background: radial-gradient(340px 160px at 12% 0%, var(--glow-warn), transparent 70%); }
  .status.bad::after { background: radial-gradient(340px 160px at 12% 0%, var(--glow-bad), transparent 70%); }
  .status-head { display: flex; align-items: center; gap: 12px; }
  .vdot { width: 15px; height: 15px; border-radius: 50%; background: #94a3b8; flex: none; }
  .vdot.ok { background: var(--ok); box-shadow: 0 0 14px var(--ok); }
  .vdot.warn { background: var(--warn); box-shadow: 0 0 14px var(--warn); }
  .vdot.bad { background: var(--bad); animation: pulse 1.2s ease-out infinite; }
  @keyframes pulse { 0% { box-shadow: 0 0 0 0 currentColor; } 70% { box-shadow: 0 0 0 11px transparent; } 100% { box-shadow: 0 0 0 0 transparent; } }
  #v-text { font-size: 28px; font-weight: 800; letter-spacing: 1px; }
  #v-text.ok { color: var(--ok); } #v-text.warn { color: var(--warn); } #v-text.bad { color: var(--bad); }
  .vwhy { display: none; margin: 12px 0 0; padding: 9px 12px; border-radius: 10px; font-size: 13px; line-height: 1.6; }
  .vwhy.bad { display: block; background: var(--cres-err-bg); border: 1px solid var(--cres-err-line); color: var(--cres-err-ink); }
  .vwhy.warn { display: block; background: var(--cwarn-bg); border: 1px solid var(--cwarn-line); color: var(--cwarn-ink); }
  .activity { margin: 16px 0 4px; }
  .activity .strip { display: flex; align-items: flex-end; gap: 2px; height: 42px; }
  .activity .sb { flex: 1 1 0; min-width: 0; height: 100%; display: flex; flex-direction: column; justify-content: flex-end; border-radius: 1.5px; overflow: hidden; background: var(--track); }
  .activity .sb i { display: block; width: 100%; }
  .activity .sb i.h { background: var(--sb-hit); }
  .activity .sb i.m { background: var(--sb-miss); }
  .activity .sb i.e { background: var(--sb-err); }
  .activity .cap { color: var(--ink-3); font-size: 11.5px; margin-top: 8px; }
  .status .meta { margin-top: auto; padding-top: 14px; }
  .vsub { color: var(--ink-2); font-size: 12.5px; }
  #refresh-line { display: block; color: var(--ink-3); font-size: 12px; margin-top: 3px; min-height: 15px; }

  .kk { color: var(--ink-3); font-size: 11px; font-weight: 600; letter-spacing: .1em; margin-bottom: 8px; }
  .kk .h2s { letter-spacing: 0; text-transform: none; }
  .kv { font-size: 29px; font-weight: 750; line-height: 1.15; font-variant-numeric: tabular-nums; }
  .kv small { font-size: 14px; font-weight: 500; color: var(--ink-2); }
  .ks { color: var(--ink-3); font-size: 12px; margin-top: 6px; }
  .kv-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .donut {
    --p: 0; flex: none; width: 46px; height: 46px; border-radius: 50%;
    background: conic-gradient(var(--ok) calc(var(--p) * 1%), var(--track) 0);
    display: grid; place-items: center;
  }
  .donut::before { content: ""; width: 33px; height: 33px; border-radius: 50%; background: var(--s2); }

  .paths-list { display: flex; flex-direction: column; justify-content: space-evenly; min-height: 118px; }
  .path { display: flex; align-items: center; gap: 9px; padding: 5px 0; font-size: 13.5px; min-width: 0; }
  .path + .path { border-top: 1px solid var(--line-2); }
  .pdot { width: 8px; height: 8px; border-radius: 50%; background: #94a3b8; flex: none; }
  .pdot.ok { background: var(--ok); } .pdot.bad { background: var(--bad); }
  .pl { color: var(--ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .spark { margin-left: auto; flex: none; opacity: .95; }
  .pv { flex: none; min-width: 64px; text-align: right; font-variant-numeric: tabular-nums; font-size: 14.5px; font-weight: 650; white-space: nowrap; }
  .pv.err { color: var(--err-ink); font-size: 12px; font-weight: 400; }

  .panel-t { padding: 15px 18px 13px; margin-bottom: 12px; }
  .panel-t h2 { font-size: 12px; margin: 0 0 10px; color: var(--head-ink); font-weight: 700; letter-spacing: .08em; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .panel-t h2::before { content: ""; width: 3px; height: 11px; border-radius: 2px; background: var(--blue); align-self: center; }
  .h2s { color: var(--ink-3); font-weight: 400; font-size: 11.5px; letter-spacing: 0; }
  .row { display: grid; grid-template-columns: 1fr 1.15fr 1.15fr; gap: 12px; margin-bottom: 12px; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  @media (max-width: 980px) { .row, .row2 { grid-template-columns: 1fr; } }
  .chart { width: 100%; }

  .segbar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--track); margin: 4px 0 12px; }
  .segbar .seg-piece { display: block; height: 100%; min-width: 2px; }
  .legend { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px 22px; }
  @media (max-width: 980px) { .legend { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 560px) { .legend { grid-template-columns: 1fr; } }
  .lg { display: flex; align-items: center; gap: 7px; font-size: 12.5px; padding: 2.5px 0; white-space: nowrap; min-width: 0; }
  .lgdot { width: 9px; height: 9px; border-radius: 3px; flex: none; }
  .lgname { color: var(--ink); overflow: hidden; text-overflow: ellipsis; }
  .lgn { margin-left: auto; font-variant-numeric: tabular-nums; color: var(--ink-2); }
  .lgp { font-variant-numeric: tabular-nums; color: var(--ink-3); width: 52px; text-align: right; }
  .lga { font-variant-numeric: tabular-nums; color: var(--ink-3); width: 74px; text-align: right; }
  .paths-note { font-size: 11.5px; margin-top: 10px; }

  table { width: 100%; border-collapse: collapse; font-size: 12.8px; }
  th { text-align: left; color: var(--ink-3); font-weight: 500; padding: 3px 6px; border-bottom: 1px solid var(--line); white-space: nowrap; }
  td { padding: 4.5px 6px; border-bottom: 1px solid var(--line-2); font-variant-numeric: tabular-nums; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  td.n { text-align: right; white-space: nowrap; }
  .muted { color: var(--ink-2); }
  .warn2 { color: var(--warn); }
  .err { color: var(--err-ink); }
  .ok2 { color: var(--ok-ink); }
  .badge { display: inline-block; padding: 0 7px; border-radius: 999px; font-size: 11px; border: 1px solid; line-height: 17px; white-space: nowrap; }
  .b-hit { color: var(--b-hit); border-color: var(--b-hit); background: var(--b-hit); }
  .b-prefetch { color: var(--b-prefetch); border-color: var(--b-prefetch); background: var(--b-prefetch); }
  .b-stale { color: var(--b-stale); border-color: var(--b-stale); background: var(--b-stale); }
  .b-miss { color: var(--b-miss); border-color: var(--b-miss); background: var(--b-miss); }
  .b-blocked { color: var(--b-blocked); border-color: var(--b-blocked); background: var(--b-blocked); }
  .b-error { color: var(--b-error); border-color: var(--b-error); background: var(--b-error); }
  .b-path { border-color: var(--line); background: var(--s2); }
  .role { color: var(--ink-2); font-size: 11px; border: 1px solid var(--line); border-radius: 4px; padding: 0 5px; margin-left: 6px; }

  .lrow { display: flex; align-items: center; gap: 10px; padding: 6px 0; }
  .lk { width: 34px; color: var(--ink-2); font-size: 12px; }
  .lbar { flex: 1; height: 8px; border-radius: 4px; background: var(--track); overflow: hidden; }
  .lbar i { display: block; height: 100%; border-radius: 4px; background: linear-gradient(90deg, var(--chart-miss), var(--chart-bar)); }
  .lv { width: 74px; text-align: right; font-variant-numeric: tabular-nums; font-size: 13px; }

  .tbar { height: 6px; border-radius: 3px; background: var(--track); overflow: hidden; min-width: 60px; }
  .tbar i { display: block; height: 100%; background: var(--chart-bar); opacity: .85; }

  details { background: var(--s1); border: 1px solid var(--line); border-radius: 14px; margin-bottom: 10px; }
  details:hover { border-color: var(--tile-hover); }
  summary { cursor: pointer; padding: 12px 18px; color: var(--head-ink); font-size: 13px; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 8px; border-radius: 14px; }
  summary::before { content: "▸"; color: var(--ink-3); transition: transform .15s; }
  details[open] summary::before { transform: rotate(90deg); }
  summary .cnt { margin-left: auto; color: var(--ink-3); font-weight: 400; font-size: 11.5px; }
  .dbody { padding: 2px 18px 13px; }
  footer { margin-top: 18px; color: var(--ink-3); font-size: 12px; text-align: center; }

  /* ===================== 控制甲板（琥珀语言，两池各一张卡） ===================== */
  .pool-card { border-color: var(--deck-edge); box-shadow: inset 0 1px 0 var(--deck-glow); }
  .phead { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; padding-bottom: 12px; margin-bottom: 14px; border-bottom: 1px dashed var(--deck-line); }
  .phead b { font-size: 14.5px; letter-spacing: .02em; }
  .lists { display: grid; grid-template-columns: 1fr; gap: 16px; }
  .list-edit h3 { font-size: 12px; color: var(--head-ink); margin: 0 0 8px; font-weight: 700; letter-spacing: .04em; }
  .list-edit h3 code { color: var(--ink-3); font-size: 11px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; min-height: 30px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; background: var(--chip-bg); border: 1px solid var(--chip-line); color: var(--chip-ink); border-radius: 999px; padding: 2px 6px 2px 10px; font-size: 12.5px; }
  .chip.ex { background: var(--chip-ex-bg); border-color: var(--chip-ex-line); color: var(--chip-ex-ink); }
  .chip button { background: none; border: none; color: inherit; cursor: pointer; font-size: 13px; padding: 0 4px; }
  .addrow { display: flex; gap: 6px; }
  .addrow input { flex: 1; min-width: 0; padding: 7px 11px; border-radius: 9px; border: 1px solid var(--line); background: var(--s3); color: var(--ink); font-size: 13px; }
  .addrow input:focus { outline: none; border-color: var(--amber); }
  .addrow button, .btn { background: var(--amber); border: none; color: #fff; border-radius: 9px; padding: 7px 15px; font-size: 13px; cursor: pointer; font-weight: 600; }
  html[data-theme="light"] .addrow button, html[data-theme="light"] .btn { color: #fff; }
  .addrow button:hover, .btn:hover { filter: brightness(1.08); }
  .btn.secondary { background: var(--s2); color: var(--ink-2); border: 1px solid var(--line); }
  .btn:disabled { opacity: .45; cursor: not-allowed; filter: none; }
  .field-err { color: var(--err-ink); font-size: 12px; min-height: 17px; margin-top: 4px; }
  .diff-box { background: var(--s3); border: 1px solid var(--deck-line); border-radius: 10px; padding: 10px 12px; margin-top: 12px; font-size: 12.5px; line-height: 1.7; }
  .diff-box .add { color: var(--ok-ink); } .diff-box .del { color: var(--err-ink); }
  .sync-line { color: var(--ink-2); font-size: 12.5px; }
  .ctl-actions { display: flex; gap: 10px; margin-top: 13px; flex-wrap: wrap; }

  .mode-now { display: flex; align-items: center; gap: 10px; margin: 2px 0 12px; flex-wrap: wrap; }
  .mode-now b { font-size: 24px; font-weight: 800; letter-spacing: .5px; }
  .srcbadge { color: var(--src-ink); border: 1px solid var(--src-line); background: var(--src-bg); font-size: 11px; border-radius: 999px; padding: 1px 9px; }
  .srcbadge.env { color: var(--ink-2); border-color: var(--line); background: var(--s2); }
  .seg { display: inline-flex; border: 1px solid var(--deck-line); border-radius: 11px; overflow: hidden; background: transparent; }
  .seg button { background: none; border: none; color: var(--seg-ink); padding: 9px 18px; font-size: 13px; cursor: pointer; border-right: 1px solid var(--deck-line); transition: background .12s; }
  .seg button:last-child { border-right: none; }
  .seg button:hover:not(:disabled):not(.on) { background: var(--seg-hover); }
  .seg button.on { background: var(--seg-on-bg); color: var(--seg-on-ink); font-weight: 700; box-shadow: inset 0 -2px 0 var(--amber); }
  .seg button:disabled { opacity: .35; cursor: not-allowed; }
  .seg button.danger:not(.on) { color: var(--warn); }
  .cwarn { background: var(--cwarn-bg); border: 1px solid var(--cwarn-line); color: var(--cwarn-ink); border-radius: 10px; padding: 9px 12px; font-size: 13px; }
  .cinfo { background: var(--cinfo-bg); border: 1px solid var(--cinfo-line); color: var(--cinfo-ink); border-radius: 10px; padding: 9px 12px; font-size: 13px; }
  .cresult { border-radius: 10px; padding: 10px 12px; font-size: 13px; line-height: 1.7; }
  .cresult.ok { background: var(--cres-ok-bg); border: 1px solid var(--cres-ok-line); color: var(--cres-ok-ink); }
  .cresult.warn { background: var(--cwarn-bg); border: 1px solid var(--cwarn-line); color: var(--cwarn-ink); }
  .cresult.err { background: var(--cres-err-bg); border: 1px solid var(--cres-err-line); color: var(--cres-err-ink); }

  /* ===================== 确认弹层 / 登录卡 ===================== */
  #modal { display: none; position: fixed; inset: 0; background: var(--overlay); z-index: 50; align-items: center; justify-content: center; padding: 20px; }
  #modal.show { display: flex; }
  .modal-card { width: 500px; max-width: 100%; max-height: 84vh; overflow: auto; background: var(--s1); border: 1px solid var(--deck-edge); border-radius: 16px; padding: 22px; box-shadow: var(--shadow); }
  .modal-card h3 { margin: 0 0 10px; font-size: 16px; }
  .modal-card .mbody { color: var(--ink); font-size: 13.5px; line-height: 1.7; }
  .modal-card .mbody ul { margin: 8px 0; padding-left: 20px; }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; }
  .modal-actions .btn.go.red { background: #b91c1c; }

  #login-view { display: none; min-height: 76vh; align-items: center; justify-content: center; padding: 20px 0; }
  #login-view.show { display: flex; }
  .login-card {
    width: 400px; max-width: 100%; background: var(--s1); border: 1px solid var(--line);
    border-top: 2px solid var(--blue); border-radius: 18px; padding: 30px 28px; box-shadow: var(--shadow);
  }
  .login-brand { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .login-brand b { font-size: 17px; }
  .login-card h1 { font-size: 17px; margin: 0; font-weight: 700; }
  .login-card .sub { color: var(--ink-2); margin: 6px 0 20px; font-size: 13px; }
  .login-card input { width: 100%; margin-bottom: 10px; padding: 10px 13px; border-radius: 10px; border: 1px solid var(--line); background: var(--s3); color: var(--ink); font-size: 14px; }
  .login-card input:focus { outline: none; border-color: var(--blue); }
  .login-card button { width: 100%; padding: 11px; border-radius: 10px; border: none; background: var(--blue); color: #fff; font-size: 14px; font-weight: 700; cursor: pointer; letter-spacing: .06em; }
  .login-card button:hover { filter: brightness(1.08); }
  .login-card button:disabled { opacity: .5; cursor: not-allowed; }
  #login-error { color: var(--err-ink); font-size: 13px; min-height: 18px; margin: 8px 0 4px; }
  #login-hint { color: var(--ink-3); font-size: 11.5px; margin-top: 16px; line-height: 1.7; border-top: 1px solid var(--line-2); padding-top: 12px; }
  body.auth #main { display: none; }
`;

// 主题引导：跟随系统偏好，手动选择存 localStorage（放 head 里避免闪色）
const THEME_BOOT = `<script>document.documentElement.setAttribute("data-theme", localStorage.getItem("doh-console-theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));</script>`;
const THEME_SCRIPT = `
(function () {
  var root = document.documentElement;
  function label() { return root.getAttribute("data-theme") === "light" ? "🌙 暗色" : "☀️ 亮色"; }
  var btn = document.getElementById("theme-toggle");
  function sync() { if (btn) btn.textContent = label(); }
  sync();
  if (btn) btn.addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("doh-console-theme", next); } catch {}
    sync();
  });
})();`

const BRAND_SVG = '<svg width="19" height="19" viewBox="0 0 24 24" fill="none"><path d="M12 2l8.66 5v10L12 22l-8.66-5V7L12 2z" stroke="#4f8dff" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="#4f8dff"/></svg>';

/** 命令栏：品牌 + 页面导航 + 状态胶囊 + 主题切换 + 会话 + 时钟。active: "monitor" | "console" */
function commandBar(active, extraRight) {
  return `<header class="bar">
    <div class="brand">${BRAND_SVG}<b>edge-smart-doh</b></div>
    <nav class="nav"><a href="/"${active === "monitor" ? ' class="on"' : ""}>监控</a><a href="/console"${active === "console" ? ' class="on"' : ""}>控制</a></nav>
    <span class="pill"><span class="pill-dot" id="pill-dot"></span><span id="pill-text">检测中…</span></span>
    <span class="bar-right">
      ${extraRight || ""}
      <button type="button" class="tbtn" id="theme-toggle" title="切换明暗主题">☀️ 亮色</button>
      <span class="clock" id="clock"></span>
    </span>
  </header>`;
}

// ============================== 监控页（公开只读，/） ==============================

const PAGE_MONITOR = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edge Smart DoH · 监控</title>
${THEME_BOOT}
<style>${CSS_COMMON}</style>
</head>
<body>
<div class="wrap" id="main">
  ${commandBar("monitor")}
  <div class="bento">
    <div class="tile status" id="status-tile">
      <div class="status-head">
        <span class="vdot" id="v-dot"></span>
        <span id="v-text">检测中…</span>
      </div>
      <div class="vwhy" id="v-why"></div>
      <div class="activity">
        <div class="strip" id="status-activity"></div>
        <div class="cap" id="status-activity-cap"></div>
      </div>
      <div class="meta">
        <div class="vsub" id="v-sub">正在连接 8788 监控服务…</div>
        <span id="refresh-line"></span>
      </div>
    </div>
    <div class="tile"><div class="kk">总查询</div><div class="kv" id="stat-total">—</div><div class="ks" id="stat-total-s">自上次重启</div></div>
    <div class="tile"><div class="kk">缓存命中率</div><div class="kv-row"><div class="kv" id="stat-rate">—</div><div class="donut" id="rate-donut"></div></div><div class="ks" id="stat-rate-s"></div></div>
    <div class="tile"><div class="kk">回源延迟 P50</div><div class="kv" id="stat-p50">—</div><div class="ks" id="stat-lat-s"></div></div>
    <div class="tile linktile"><div class="kk">解析链路 <span class="h2s">每 10 秒真实 DoH 探测</span></div><div id="path-health" class="paths-list muted">等待首次探测…</div></div>
  </div>

  <div class="sect"><span class="sect-tick"></span><span class="sect-t">监测</span><span class="sect-s">MONITOR</span></div>

  <div class="tile panel-t">
    <h2>解析路径分布 <span class="h2s">自启动累计 · 回源按路径归类，缓存应答单列</span></h2>
    <div id="paths-panel"></div>
  </div>

  <div class="row2">
    <div class="tile panel-t">
      <h2>查询量 <span class="h2s">近 2 小时 · 每分钟 · 绿=缓存命中 蓝=回源 红=失败</span></h2>
      <div id="minute-chart" class="chart" style="height:216px"></div>
    </div>
    <div class="tile panel-t">
      <h2>链路延迟趋势 <span class="h2s">每 10 秒真实 DoH 查询 · 断点=该次失败</span></h2>
      <div id="probe-chart" class="chart" style="height:216px"></div>
    </div>
  </div>

  <div class="row">
    <div class="tile panel-t">
      <h2>回源延迟 <span class="h2s" id="lat-n"></span></h2>
      <div id="latency-bars"></div>
    </div>
    <div class="tile panel-t">
      <h2>解析策略 <span class="h2s">回源时怎么解的（技术视图）</span></h2>
      <div id="strategy-chart" class="chart" style="height:190px"></div>
    </div>
    <div class="tile panel-t">
      <h2>上游解析器</h2>
      <div id="upstreams"></div>
    </div>
  </div>

  <div class="sect"><span class="sect-tick"></span><span class="sect-t">诊断</span><span class="sect-s">DETAILS</span></div>

  <details>
    <summary>高频域名 <span class="cnt" id="top-cnt"></span></summary>
    <div class="dbody"><table><tbody id="top-body"></tbody></table></div>
  </details>
  <details>
    <summary>最近查询 <span class="cnt" id="recent-cnt"></span></summary>
    <div class="dbody"><table><thead><tr><th>时间</th><th>域名</th><th>类型</th><th>结果</th><th class="n">延迟</th><th>上游</th></tr></thead><tbody id="recent-body"></tbody></table></div>
  </details>
  <details>
    <summary>优选池 / 规则状态 <span class="cnt" id="pools-cnt"></span></summary>
    <div class="dbody"><table><tbody id="pools-body"></tbody></table></div>
  </details>

  <footer>监控页公开只读 · 控制操作请前往 <a href="/console">控制页</a>（需要密码） · 数据来自主服务 <code>/admin/stats</code> 与本机主动探测 · 仅限局域网访问</footer>
</div>

<script src="/vendor/echarts.min.js"></script>
<script>
window.addEventListener("error", function (e) {
  if (!e.message) return;
  var el = document.getElementById("refresh-line");
  if (el && !el.textContent) el.textContent = "页面脚本无法运行：" + e.message;
}, true);
</script>
<script>
(function () {
"use strict";
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = (n) => Number(n == null ? 0 : n).toLocaleString("zh-CN");
const fmtMs = (n) => n == null ? "—" : (n >= 1000 ? (n / 1000).toFixed(2) + " s" : Math.round(n) + " ms");
const hhmmss = (t) => new Date(t).toLocaleTimeString("zh-CN", { hour12: false });
const hhmm = (t) => new Date(t).toTimeString().slice(0, 5);
const ago = (t) => { if (!t) return "—"; const s = Math.max(0, Math.round((Date.now() - t) / 1000)); return s < 60 ? s + " 秒前" : s < 3600 ? Math.round(s / 60) + " 分钟前" : Math.round(s / 3600) + " 小时前"; };
const dur = (sec) => { if (sec == null) return "—"; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return (d ? d + " 天 " : "") + (h ? h + " 小时 " : "") + m + " 分钟"; };
const inMin = (ts) => ts ? Math.max(0, Math.round((ts - Date.now()) / 60000)) : null;
const inMinTxt = (ts) => { const m = inMin(ts); return m == null ? "—" : m < 30 ? '<span class="warn2">' + m + " 分钟</span>" : m + " 分钟"; };
const OUTCOME = { hit: ["b-hit", "命中"], prefetch: ["b-prefetch", "预取"], stale: ["b-stale", "stale"], miss: ["b-miss", "回源"], blocked: ["b-blocked", "拦截"], error: ["b-error", "失败"] };
const ROLE = { default: "默认", ecs: "ECS", cn: "国内直连" };
const PATH_META = { relay: ["SNI 中转", "#f59e0b"], ech: ["ECH 注入", "#38bdf8"], pool: ["优选池", "#818cf8"], cn: ["国内直连", "#2dd4bf"], direct: ["直连", "#94a3b8"], cache: ["缓存应答", "#34d399"] };

const clockEl = document.getElementById("clock");
function tickClock() { clockEl.textContent = hhmmss(Date.now()); }
tickClock();
setInterval(tickClock, 1000);

function verdictOf(d) {
  if (d.doh.ok === false) return { cls: "bad", text: "服务不可达", why: (d.monitor ? d.monitor.dohUrl : "") + "：" + (d.doh.error || "无响应") };
  const dead = (d.probes || []).filter((p) => p.ok === false);
  if (dead.length) return { cls: "bad", text: "解析异常", why: dead.map((p) => (p.label || p.name) + "：" + (p.error || "失败")).join("；") };
  if (d.statsError) return { cls: "warn", text: "统计不可用", why: "数据通道不可用（仅展示降级数据）：" + d.statsError };
  const relay = d.stats && d.stats.pools && d.stats.pools.relay;
  if (relay && ((relay.mode && relay.mode !== "off") || relay.forcedMode === "always") && !relay.healthy) {
    return { cls: "warn", text: "中转离线", why: "SNI 中转未上报健康（relay 进程或代理出口故障）；名单域名已回退直连路径" };
  }
  const s = d.stats;
  if (s && s.minutes.length) {
    const last = s.minutes[s.minutes.length - 1];
    if (last.queries >= 5 && last.errors / last.queries > 0.2) return { cls: "warn", text: "失败率偏高", why: "最近 1 分钟 " + last.errors + "/" + last.queries + " 次解析失败" };
  }
  if (d.doh.ok === true) return { cls: "ok", text: "运行正常", why: null };
  return { cls: "", text: "检测中…", why: null };
}

// 图表颜色跟随主题（每次渲染重读 CSS 变量，切主题后 5 秒内自动换色）
function themeColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (name) => cs.getPropertyValue(name).trim();
  return { axis: v("--chart-axis"), split: v("--chart-split"), hit: v("--chart-hit"), miss: v("--chart-miss"), err: v("--chart-err"), bar: v("--chart-bar") };
}

const charts = {};
function getChart(id) {
  if (!window.echarts) {
    const el = document.getElementById(id);
    if (el && !el.getAttribute("data-nolib")) { el.setAttribute("data-nolib", "1"); el.innerHTML = '<div class="muted">图表库加载失败（/vendor/echarts.min.js 缺失）</div>'; }
    return null;
  }
  if (!charts[id]) {
    const host = document.getElementById(id);
    if (!host) return null;
    charts[id] = window.echarts.init(host, null, { renderer: "canvas" });
  }
  return charts[id];
}

function setVerdict(d) {
  const v = verdictOf(d);
  const dot = document.getElementById("v-dot"), text = document.getElementById("v-text"), why = document.getElementById("v-why");
  dot.className = "vdot " + v.cls;
  text.className = v.cls;
  text.textContent = v.text;
  why.className = "vwhy " + (v.why ? v.cls : "");
  why.textContent = v.why || "";
  document.getElementById("pill-dot").className = "pill-dot " + v.cls;
  document.getElementById("pill-text").textContent = v.text;
  const tile = document.getElementById("status-tile");
  tile.className = "tile status" + (v.cls ? " " + v.cls : "");
  const s = d.stats;
  const bits = ["上游 " + d.monitor.dohUrl, "采样每 " + Math.round(d.monitor.intervalMs / 1000) + "s"];
  if (s) {
    bits.push("服务运行 " + dur(s.uptimeSec));
    if (s.memory) bits.push("内存 " + (s.memory.rssBytes / 1048576).toFixed(0) + " MB");
  }
  document.getElementById("v-sub").textContent = bits.join(" · ");
}

function sparkline(history, ok) {
  const pts = (history || []).slice(-60);
  const good = pts.filter((p) => p.ok);
  if (good.length < 2) return "";
  const w = 64, h = 20;
  const max = Math.max(1, ...good.map((p) => p.ms));
  let d = "", pen = false;
  for (let i = 0; i < pts.length; i++) {
    const x = (i / (pts.length - 1) * (w - 2) + 1).toFixed(1);
    if (!pts[i].ok) { pen = false; continue; }
    const y = (h - 2 - (pts[i].ms / max) * (h - 4)).toFixed(1);
    d += (pen ? " L" : " M") + x + " " + y;
    pen = true;
  }
  if (!d) return "";
  const color = ok === false ? "var(--bad)" : "var(--ok)";
  return '<svg class="spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + " " + h + '"><path d="' + d + '" fill="none" style="stroke:' + color + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity=".9"/></svg>';
}

function pathHealth(probes, relay) {
  const el = document.getElementById("path-health");
  if (!probes.length) { el.innerHTML = "未配置探测"; return; }
  const patternHit = (name, patterns) => (patterns || []).some((p) => {
    const bare = String(p).replace(/^\\*\\./, "");
    return name === bare || name.endsWith("." + bare);
  });
  const excluded = (name) => patternHit(name, relay && relay.excludes);
  const viaRelay = (name) => {
    if (!relay || !relay.healthy) return false;
    if ((relay.forcedMode === "always") && patternHit(name, relay.forcedDomains) && !excluded(name)) return true;
    if (!relay.mode || relay.mode === "off" || excluded(name)) return false;
    if (relay.mode === "always") return patternHit(name, relay.domains);
    return (relay.hosts || []).some((h) => h.relayed && (name === h.host || name.endsWith("." + h.host)));
  };
  el.classList.remove("muted");
  el.innerHTML = probes.map((p) => {
    const cls = p.ok === null ? "" : p.ok ? "ok" : "bad";
    const val = p.ok === null ? "—" : p.ok ? fmtMs(p.latencyMs) : (p.error || "失败").slice(0, 26);
    return '<div class="path"><span class="pdot ' + cls + '"></span><span class="pl">' + esc(p.label || p.name) +
      (viaRelay(p.name) ? ' <span class="warn2">中转</span>' : "") +
      '</span>' + sparkline(p.history, p.ok) +
      '<span class="pv' + (p.ok === false ? " err" : "") + '" title="' + esc(p.name + (p.error ? " · " + p.error : "")) + '">' + esc(val) + "</span></div>";
  }).join("");
}

function statusActivity(s) {
  const strip = document.getElementById("status-activity");
  const cap = document.getElementById("status-activity-cap");
  if (!s || !s.minutes || !s.minutes.length) {
    strip.innerHTML = "";
    cap.textContent = "暂无查询数据";
    return;
  }
  const recent = s.minutes.slice(-60);
  const total = recent.reduce((sum, b) => sum + b.queries, 0);
  const hits = recent.reduce((sum, b) => sum + b.hits, 0);
  const errors = recent.reduce((sum, b) => sum + b.errors, 0);
  const max = Math.max(1, ...recent.map((b) => b.queries));
  strip.innerHTML = recent.map((b) => {
    const hp = b.queries ? Math.round(b.hits / b.queries * 100) : 0;
    const ep = b.queries ? Math.round(b.errors / b.queries * 100) : 0;
    const height = b.queries > 0 ? Math.max(8, Math.round(b.queries / max * 100)) : 2;
    return '<span class="sb" style="height:' + height + '%" title="' + hhmm(b.t) + " · " + fmt(b.queries) + ' 次">' +
      '<i class="h" style="height:' + hp + '%"></i><i class="m" style="height:' + (100 - ep - hp) + '%"></i><i class="e" style="height:' + ep + '%"></i></span>';
  }).join("");
  cap.textContent = "近 1 小时 " + fmt(total) + " 次查询 · 命中率 " + Math.round(total ? hits / total * 100 : 0) + "%" +
    (errors ? " · 失败 " + fmt(errors) + " 次" : "");
}

function heroCards(s) {
  const lastMin = s.minutes.length ? s.minutes[s.minutes.length - 1] : null;
  document.getElementById("stat-total").textContent = fmt(s.queries.total);
  document.getElementById("stat-total-s").textContent = "近 1 分钟 " + fmt(lastMin ? lastMin.queries : 0) + " 次";
  document.getElementById("stat-rate").innerHTML = Math.round(s.hitRate * 100) + "<small>%</small>";
  document.getElementById("rate-donut").style.setProperty("--p", String(Math.round(s.hitRate * 100)));
  document.getElementById("stat-rate-s").textContent = "失败 " + fmt(s.queries.error) + "（SERVFAIL " + fmt(s.queries.servfail) + "）";
  document.getElementById("stat-p50").textContent = fmtMs(s.freshLatency.p50Ms);
  document.getElementById("stat-lat-s").textContent = "P90 " + fmtMs(s.freshLatency.p90Ms) + " · 共 " + fmt(s.freshLatency.count) + " 次";
}

function minuteChart(minutes) {
  const c = getChart("minute-chart"); if (!c) return;
  const t = themeColors();
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 8, top: 24, bottom: 16, containLabel: true },
    legend: { top: 0, left: 0, textStyle: { color: t.axis, fontSize: 10 }, itemWidth: 10, itemHeight: 8 },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "category", data: minutes.map((b) => hhmm(b.t)), axisLabel: { color: t.axis, fontSize: 10 }, axisLine: { lineStyle: { color: t.split } } },
    yAxis: { type: "value", axisLabel: { color: t.axis, fontSize: 10 }, splitLine: { lineStyle: { color: t.split } } },
    series: [
      { name: "缓存命中", type: "bar", stack: "q", barMaxWidth: 9, itemStyle: { color: t.hit, borderRadius: [2, 2, 0, 0] }, data: minutes.map((b) => b.hits) },
      { name: "回源解析", type: "bar", stack: "q", barMaxWidth: 9, itemStyle: { color: t.miss }, data: minutes.map((b) => b.misses) },
      { name: "解析失败", type: "bar", stack: "q", barMaxWidth: 9, itemStyle: { color: t.err, borderRadius: [2, 2, 0, 0] }, data: minutes.map((b) => b.errors) },
    ],
  }, { notMerge: true });
}

function pathsPanel(s) {
  const el = document.getElementById("paths-panel");
  const freshTotal = (s.paths || []).reduce((sum, p) => sum + p.count, 0);
  const cached = (s.queries.hit || 0) + (s.queries.prefetch || 0) + (s.queries.stale || 0);
  const total = Math.max(1, s.queries.total || 0);
  const all = (s.paths || []).filter((p) => p.count > 0).map((p) => ({ key: p.path, count: p.count, avgMs: p.avgMs }));
  if (cached > 0) all.push({ key: "cache", count: cached, avgMs: null });
  if (all.length === 0) { el.innerHTML = '<div class="muted" style="padding:10px 0 4px">暂无回源记录</div>'; return; }
  const share = (r) => (r.count / total * 100);
  el.innerHTML = '<div class="segbar">' + all.map((r) => {
    const meta = PATH_META[r.key] || [r.key, "#64748b"];
    return '<span class="seg-piece" style="width:' + share(r).toFixed(2) + "%;background:" + meta[1] + '" title="' + esc(meta[0]) + " " + fmt(r.count) + ' 次"></span>';
  }).join("") + '</div><div class="legend">' + all.map((r) => {
    const meta = PATH_META[r.key] || [r.key, "#64748b"];
    const avg = r.avgMs == null ? "—" : "均 " + fmtMs(r.avgMs);
    return '<div class="lg"><span class="lgdot" style="background:' + meta[1] + '"></span><span class="lgname">' + esc(meta[0]) +
      '</span><span class="lgn">' + fmt(r.count) + ' 次</span><span class="lgp">' + share(r).toFixed(1) + '%</span><span class="lga">' + avg + "</span></div>";
  }).join("") + '</div><div class="paths-note muted">回源 ' + fmt(freshTotal) + " 次 · 缓存应答 " + fmt(cached) + " 次 · 分母为总查询 " + fmt(s.queries.total || 0) + " · 路径按回源时刻归类，已进缓存的查询不再重计</div>";
}

function latencyBars(f) {
  const rows = [["P50", f.p50Ms], ["P90", f.p90Ms], ["P99", f.p99Ms], ["峰值", f.maxMs]];
  const max = Math.max(1, ...rows.map((r) => r[1] || 0));
  document.getElementById("lat-n").textContent = f.count ? "近 " + fmt(f.count) + " 次回源" : "暂无回源";
  document.getElementById("latency-bars").innerHTML = f.count ? rows.map(([k, v]) =>
    '<div class="lrow"><span class="lk">' + k + '</span><span class="lbar"><i style="width:' + Math.max(2, Math.round((v || 0) / max * 100)) + '%"></i></span><span class="lv">' + fmtMs(v) + "</span></div>").join("")
    : '<div class="muted">暂无回源样本</div>';
}

function strategyChart(list) {
  const el = document.getElementById("strategy-chart");
  if (!list.length) { el.innerHTML = '<div class="muted" style="padding:20px 0;text-align:center">暂无回源记录</div>'; return; }
  const c = getChart("strategy-chart"); if (!c) return;
  const t = themeColors();
  const rows = list.slice(0, 8).reverse();
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 74, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "value", axisLabel: { color: t.axis, fontSize: 10 }, splitLine: { lineStyle: { color: t.split } } },
    yAxis: { type: "category", data: rows.map((s) => s.name), axisLabel: { color: t.axis, fontSize: 11 }, axisLine: { lineStyle: { color: t.split } } },
    series: [{ type: "bar", barMaxWidth: 12, itemStyle: { color: t.bar, borderRadius: [0, 3, 3, 0] },
      label: { show: true, position: "right", color: t.axis, fontSize: 10, formatter: (p) => p.value + " · 均 " + fmtMs(p.data.avgMs) },
      data: rows.map((s) => ({ value: s.count, avgMs: s.avgMs })) }],
  }, { notMerge: true });
}

function upstreams(list) {
  if (!list.length) { document.getElementById("upstreams").innerHTML = '<div class="muted">暂无数据</div>'; return; }
  document.getElementById("upstreams").innerHTML = '<table><tr><th>解析器</th><th>成功</th><th>失败</th><th class="n">平均</th><th class="n">峰值</th><th>最近</th></tr>' +
    list.map((u) => {
      const err = u.fail && u.lastError ? '<div class="err" title="' + esc(u.lastError) + '">' + esc(u.lastError.slice(0, 44)) + "</div>" : "";
      return "<tr><td>" + esc(u.name) + '<span class="role">' + esc(ROLE[u.role] || u.role) + "</span>" + err + "</td>" +
        '<td class="n">' + fmt(u.ok) + '</td><td class="n">' + (u.fail ? '<span class="err">' + fmt(u.fail) + "</span>" : "0") + '</td>' +
        '<td class="n">' + fmtMs(u.avgMs) + '</td><td class="n">' + fmtMs(u.maxMs) + '</td><td class="muted">' + ago(Date.now() - u.lastUsedAgoSec * 1000) + "</td></tr>";
    }).join("") + "</table>";
}

function probeChart(probes) {
  const c = getChart("probe-chart"); if (!c) return;
  const t = themeColors();
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 8, top: 26, bottom: 16, containLabel: true },
    legend: { top: 0, left: 0, textStyle: { color: t.axis, fontSize: 10 }, itemWidth: 14, itemHeight: 2,
      formatter: (name) => { const p = probes.filter((x) => x.name === name)[0]; return (p && p.label) || name; } },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "time", axisLabel: { color: t.axis, fontSize: 10, formatter: (v) => hhmm(v), hideOverlap: true }, axisLine: { lineStyle: { color: t.split } } },
    yAxis: { type: "value", axisLabel: { color: t.axis, fontSize: 10 }, splitLine: { lineStyle: { color: t.split } } },
    series: probes.map((p, i) => ({
      name: p.name, type: "line", showSymbol: false, connectNulls: false,
      lineStyle: { width: 1.2, color: t.line || ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#22d3ee", "#fb923c", "#e879f9"][i % 8] },
      itemStyle: { color: ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#22d3ee", "#fb923c", "#e879f9"][i % 8] },
      data: p.history.map((h) => [h.t, h.ok ? h.ms : null]),
    })),
  }, { notMerge: true });
}

function topTable(list) {
  document.getElementById("top-cnt").textContent = list.length ? "共 " + list.length + " 个" : "";
  if (!list.length) { document.getElementById("top-body").innerHTML = '<tr><td class="muted">暂无数据</td></tr>'; return; }
  const max = list[0].count;
  document.getElementById("top-body").innerHTML = list.map((t) =>
    '<tr><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(t.name) + '">' + esc(t.name) +
    '</td><td style="width:40%"><div class="tbar"><i style="width:' + Math.max(2, Math.round(t.count / max * 100)) + '%"></i></div></td><td class="n" style="width:70px">' + fmt(t.count) + "</td></tr>").join("");
}

function recentTable(list) {
  document.getElementById("recent-cnt").textContent = list.length ? "最新 " + Math.min(20, list.length) + " 条" : "";
  if (!list.length) { document.getElementById("recent-body").innerHTML = '<tr><td class="muted">暂无数据</td></tr>'; return; }
  document.getElementById("recent-body").innerHTML = list.slice(0, 20).map((r) => {
    const pair = OUTCOME[r.outcome] || ["b-error", r.outcome];
    const pathMeta = r.path ? (PATH_META[r.path] || [r.path, "#64748b"]) : null;
    const pathBadge = pathMeta ? ' <span class="badge b-path" style="color:' + pathMeta[1] + '">' + esc(pathMeta[0]) + "</span>" : "";
    return '<tr><td class="muted">' + hhmmss(r.t) + '</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.name) + '">' + esc(r.name) + "</td><td>" + esc(r.type) +
      '</td><td><span class="badge ' + pair[0] + '">' + pair[1] + "</span>" + pathBadge + '</td><td class="n">' + fmtMs(r.latencyMs) + "</td><td>" + esc(r.upstream == null ? "—" : r.upstream) + "</td></tr>";
  }).join("");
}

function poolsTable(p) {
  const rows = [];
  if (!p) { document.getElementById("pools-body").innerHTML = '<tr><td class="muted">暂无数据</td></tr>'; document.getElementById("pools-cnt").textContent = ""; return; }
  if (p.learned) rows.push(["默认优选池", "IPv4×" + p.learned.ipv4.length + " · IPv6×" + p.learned.ipv6.length + " · 来源 " + (p.learned.sources || []).map((s) => s.source).join(", ") + " · 剩余 " + inMinTxt(p.learned.expiresAt)]);
  const isps = p.isp || [];
  for (const isp of isps) rows.push(["运营商池 " + isp.scope, "IPv4×" + isp.ipv4.length + " · IPv6×" + isp.ipv6.length + (isp.active ? " · 剩余 " + inMinTxt(isp.expiresAt) : ' · <span class="err">已过期</span>')]);
  if (p.github) rows.push(["GitHub 池", Object.keys(p.github.hosts).length + " 主机 · 来源 " + p.github.sources.map((s) => s.source).join(", ") + " · 剩余 " + inMinTxt(Math.max.apply(null, p.github.sources.map((s) => s.expiresAt)))]);
  if (p.relay && p.relay.mode && (p.relay.mode !== "off" || p.relay.forcedMode === "always")) {
    const rh = p.relay.hosts || [];
    const relayed = rh.filter((h) => h.relayed);
    const forcedCount = (p.relay.forcedDomains || []).length;
    rows.push(["SNI 主池", (p.relay.healthy ? "健康" : '<span class="err">未上报</span>') + " · 档位 " + esc(p.relay.mode) + " · " + relayed.length + "/" + rh.length + " 主机走中转" + (p.relay.ip ? " · " + esc(p.relay.ip) : "") + " · 上报 " + ago(p.relay.lastReportAt)]);
    if (p.relay.forcedMode === "always" || forcedCount > 0) {
      rows.push(["　强制池", "档位 " + esc(p.relay.forcedMode) + " · " + forcedCount + " 条名单" + (p.relay.forcedMode === "always" ? ' · <span class="warn2">常开（不看测量）</span>' : "") + (forcedCount ? "：" + (p.relay.forcedDomains || []).slice(0, 6).map(esc).join("、") + (forcedCount > 6 ? " 等" : "") : "")]);
    }
    for (const h of rh) {
      rows.push(["　" + esc(h.host), (h.relayed ? "走中转" : "直连") + " · 直连成功率 " + (h.enterRate == null ? "—" : Math.round(h.enterRate * 100) + "%") + " · 样本 " + h.samples + " · 测于 " + ago(h.lastSampleAt)]);
    }
  }
  if (p.sites) rows.push(["Site 池", Object.keys(p.sites.hosts).length + " 站点 · 来源 " + p.sites.sources.map((s) => s.source).join(", ")]);
  if (p.chineseSites) rows.push(["国内域名名单", "后缀 " + fmt(p.chineseSites.suffix) + " · 精确 " + fmt(p.chineseSites.exact) + " · 更新于 " + hhmmss(Date.parse(p.chineseSites.loadedAt))]);
  if (p.safe) rows.push(["安全过滤 ?safe=1", "拦截名单 " + fmt(p.safe.block) + " · 放行 " + fmt(p.safe.allow)]);
  if (p.metaEch) rows.push(["Meta ECH", esc(JSON.stringify(p.metaEch).slice(0, 140))]);
  if (p.h3 && p.h3.sources && p.h3.sources.length) {
    const eff = p.h3.effective || {};
    rows.push(["QUIC/ECH 探测", Object.keys(eff).map((h) => h + (eff[h] ? " ✓" : " ✗")).join(" · ")]);
  }
  document.getElementById("pools-cnt").textContent = rows.length ? rows.length + " 项" : "";
  document.getElementById("pools-body").innerHTML = rows.length
    ? rows.map(([k, v]) => '<tr><td style="white-space:nowrap;color:var(--head-ink)">' + k + '</td><td class="muted">' + v + "</td></tr>").join("")
    : '<tr><td class="muted">主服务未配置任何池 / 名单</td></tr>';
}

let fetchFails = 0;
async function refresh() {
  const line = document.getElementById("refresh-line");
  try {
    const r = await fetch("/api/summary", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    fetchFails = 0;
    if (line) line.textContent = "更新于 " + hhmmss(Date.now());
    setVerdict(d);
    if (d.stats) {
      heroCards(d.stats); statusActivity(d.stats); minuteChart(d.stats.minutes); latencyBars(d.stats.freshLatency);
      pathsPanel(d.stats); strategyChart(d.stats.strategies); upstreams(d.stats.upstreams);
      topTable(d.stats.top); recentTable(d.stats.recent); poolsTable(d.stats.pools);
    } else {
      ["stat-total", "stat-rate", "stat-p50"].forEach((id) => { document.getElementById(id).textContent = "—"; });
      document.getElementById("paths-panel").innerHTML = '<div class="muted" style="padding:10px 0 4px">统计不可用</div>';
      statusActivity(null);
    }
    pathHealth(d.probes || [], d.stats && d.stats.pools ? d.stats.pools.relay : null); probeChart(d.probes || []);
  } catch (e) {
    fetchFails += 1;
    if (line) line.textContent = "取数据失败 ×" + fetchFails + "：" + (e && e.message ? e.message : e) + "（重试中）";
  }
}
refresh();
setInterval(refresh, 5000);
window.addEventListener("resize", function () { Object.keys(charts).forEach((id) => charts[id].resize()); });
})();
</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>
`;

// ============================== 控制页（需要密码，/console） ==============================

const PAGE_CONSOLE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edge Smart DoH · 控制</title>
${THEME_BOOT}
<style>${CSS_COMMON}
  .pools { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  @media (max-width: 980px) { .pools { grid-template-columns: 1fr; } }
  .strip-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
  .strip-row .rl { color: var(--ink-2); font-size: 12.5px; }
  .strip-row .rl b { color: var(--ink); font-weight: 700; }
  #console-disabled { max-width: 640px; }
</style>
</head>
<body>
<div id="login-view">
  <div class="login-card">
    <div class="login-brand">
      ${BRAND_SVG}
      <h1>SNI 中转控制台</h1>
    </div>
    <p class="sub" id="login-sub">请输入控制台密码</p>
    <form id="login-form">
      <input type="password" id="login-password" placeholder="密码" autocomplete="current-password" autofocus>
      <input type="text" id="login-label" placeholder="备注（可选，≤32 字符，便于审计）" maxlength="32">
      <button type="submit" id="login-button">登 录</button>
    </form>
    <div id="login-error"></div>
    <div id="login-hint">密码由安装脚本生成，可在服务器上查看：<br><code>sudo grep CONSOLE_PASSWORD /etc/edge-smart-doh/monitor.env</code><br>监控数据无需密码：<a href="/">返回监控页</a></div>
  </div>
</div>

<div class="wrap" id="main">
  ${commandBar("console", '<span id="session-box"><span class="slabel" id="session-label"></span><button type="button" id="logout-button">退出</button></span>')}

  <div class="tile" id="strip">
    <div class="status-head">
      <span class="vdot" id="v-dot"></span>
      <span id="v-text">检测中…</span>
      <span class="h2s" id="v-meta">正在连接 8788 监控服务…</span>
    </div>
    <div class="vwhy" id="v-why"></div>
    <div class="strip-row" id="relay-strip"><span class="rl muted">等待 relay 状态…</span></div>
  </div>

  <div class="sect"><span class="sect-tick amber"></span><span class="sect-t">控制</span><span class="sect-s">SNI RELAY · 双池</span></div>

  <div id="console-disabled" class="cwarn" hidden></div>

  <div class="pools" id="pools-wrap" hidden>
    <div class="tile pool-card">
      <div class="phead"><b>SNI 中转 · 主池</b><span class="h2s">GitHub 族 · off / auto / always</span></div>
      <div class="mode-now"><b id="relay-mode-text">—</b><span class="srcbadge" id="relay-mode-source"></span></div>
      <div class="seg" id="mode-seg">
        <button type="button" data-mode="off">off · 直连</button>
        <button type="button" data-mode="auto">auto · 自动</button>
        <button type="button" data-mode="always" class="danger">always · 常开</button>
      </div>
      <div class="cinfo" id="main-auto-note" hidden style="margin-top:12px">auto 档：relay 每 3 分钟直连实测握手，某主机 15 分钟成功率 &lt;50% 切中转、30 分钟 &gt;80% 切回；无实测池的主机保持直连。</div>
      <div class="lists" style="margin-top:14px">
        <div class="list-edit">
          <h3>中转名单 <code>RELAY_DOMAINS</code></h3>
          <div class="chips" id="domains-chips"></div>
          <div class="addrow"><input id="domain-input" placeholder="*.example.com；可黏贴多个（逗号/空格分隔）"><button type="button" id="domain-add">添加</button></div>
          <div class="field-err" id="domain-err"></div>
        </div>
      </div>
    </div>

    <div class="tile pool-card">
      <div class="phead"><b>SNI 中转 · 强制池</b><span class="h2s">Google 族等无实测池域名 · 仅 off / always</span></div>
      <div class="mode-now"><b id="forced-mode-text">—</b><span class="srcbadge" id="forced-mode-source"></span></div>
      <div class="seg" id="forced-mode-seg">
        <button type="button" data-fmode="off">off · 直连</button>
        <button type="button" data-fmode="always" class="danger">always · 常开</button>
      </div>
      <div class="cwarn" id="forced-note" hidden style="margin-top:12px">强制池 always 常开中：全部流量经代理节点出境（不看测量、不看直连质量），消耗节点带宽；relay 停止上报健康即整体回退直连（≤60s）。</div>
      <div class="lists" style="margin-top:14px">
        <div class="list-edit">
          <h3>强制名单 <code>RELAY_FORCED_DOMAINS</code></h3>
          <div class="chips" id="forced-chips"></div>
          <div class="addrow"><input id="forced-input" placeholder="*.google.com；可黏贴多个"><button type="button" id="forced-add">添加</button></div>
          <div class="field-err" id="forced-err"></div>
        </div>
      </div>
    </div>

    <div class="tile pool-card" style="grid-column: 1 / -1">
      <div class="phead"><b>共用设置</b><span class="h2s">两池共用 · 变更即刻生效 · 持久化（重启保留）</span></div>
      <div class="lists">
        <div class="list-edit">
          <h3>排除名单 <code>RELAY_EXCLUDE_DOMAINS</code> <span class="muted">排除优先于命中</span></h3>
          <div class="chips" id="excludes-chips"></div>
          <div class="addrow"><input id="exclude-input" placeholder="no-sni.example.com；可黏贴多个"><button type="button" id="exclude-add">添加</button></div>
          <div class="field-err" id="exclude-err"></div>
        </div>
        <div>
          <div id="relay-not-deployed" class="cwarn" hidden></div>
          <div id="relay-no-report" class="cinfo" hidden></div>
          <div id="relay-result" class="cresult" hidden></div>
          <div class="sync-line" id="relay-sync">—</div>
          <div class="ctl-actions">
            <button type="button" class="btn" id="domains-save" disabled>保存名单</button>
            <button type="button" class="btn secondary" id="relay-reset">恢复 env 默认配置</button>
          </div>
        </div>
      </div>
      <div id="domains-diff" class="diff-box" hidden></div>
    </div>
  </div>

  <div class="sect"><span class="sect-tick amber"></span><span class="sect-t">操作记录</span><span class="sect-s">AUDIT</span></div>
  <details id="audit-block" open>
    <summary>最近操作 <span class="cnt" id="audit-cnt"></span></summary>
    <div class="dbody"><table><thead><tr><th>时间</th><th>来源</th><th>操作</th><th>内容</th><th>结果</th></tr></thead><tbody id="audit-body"></tbody></table></div>
  </details>

  <footer>控制页需要密码 · 监控数据见 <a href="/">监控页</a>（公开只读） · 变更即刻生效并持久化 · 仅限局域网访问 · <span id="foot-mode"></span></footer>
</div>

<div id="modal"><div class="modal-card">
  <h3 id="modal-title"></h3>
  <div class="mbody" id="modal-body"></div>
  <div class="modal-actions">
    <button type="button" class="btn secondary" id="modal-cancel">取消</button>
    <button type="button" class="btn go" id="modal-go">确认</button>
  </div>
</div></div>

<script>
window.addEventListener("error", function (e) {
  if (!e.message) return;
  var el = document.getElementById("v-meta");
  if (el && !el.textContent) el.textContent = "页面脚本无法运行：" + e.message;
}, true);
</script>
<script>
(function () {
"use strict";
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = (n) => Number(n == null ? 0 : n).toLocaleString("zh-CN");
const fmtMs = (n) => n == null ? "—" : (n >= 1000 ? (n / 1000).toFixed(2) + " s" : Math.round(n) + " ms");
const hhmmss = (t) => new Date(t).toLocaleTimeString("zh-CN", { hour12: false });
const ago = (t) => { if (!t) return "—"; const s = Math.max(0, Math.round((Date.now() - t) / 1000)); return s < 60 ? s + " 秒前" : s < 3600 ? Math.round(s / 60) + " 分钟前" : Math.round(s / 3600) + " 小时前"; };
const dur = (sec) => { if (sec == null) return "—"; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return (d ? d + " 天 " : "") + (h ? h + " 小时 " : "") + m + " 分钟"; };
const MODE_TEXT = { off: "off · 直连", auto: "auto · 自动", always: "always · 常开" };

let CONSOLE_STATE = { authRequired: false, control: false, session: null };
let RELAY = null;
let EDIT = null;

const clockEl = document.getElementById("clock");
function tickClock() { clockEl.textContent = hhmmss(Date.now()); }
tickClock();
setInterval(tickClock, 1000);

function verdictOf(d) {
  if (d.doh.ok === false) return { cls: "bad", text: "服务不可达", why: (d.monitor ? d.monitor.dohUrl : "") + "：" + (d.doh.error || "无响应") };
  const dead = (d.probes || []).filter((p) => p.ok === false);
  if (dead.length) return { cls: "bad", text: "解析异常", why: dead.map((p) => (p.label || p.name) + "：" + (p.error || "失败")).join("；") };
  if (d.statsError) return { cls: "warn", text: "统计不可用", why: "数据通道不可用（控制操作不受影响）：" + d.statsError };
  const relay = d.stats && d.stats.pools && d.stats.pools.relay;
  if (relay && ((relay.mode && relay.mode !== "off") || relay.forcedMode === "always") && !relay.healthy) {
    return { cls: "warn", text: "中转离线", why: "SNI 中转未上报健康（relay 进程或代理出口故障）；名单域名已回退直连路径" };
  }
  if (d.doh.ok === true) return { cls: "ok", text: "运行正常", why: null };
  return { cls: "", text: "检测中…", why: null };
}

function setVerdict(d) {
  const v = verdictOf(d);
  const dot = document.getElementById("v-dot"), text = document.getElementById("v-text"), why = document.getElementById("v-why");
  dot.className = "vdot " + v.cls;
  text.className = v.cls;
  text.textContent = v.text;
  why.className = "vwhy " + (v.why ? v.cls : "");
  why.textContent = v.why || "";
  document.getElementById("pill-dot").className = "pill-dot " + v.cls;
  document.getElementById("pill-text").textContent = v.text;
  const s = d.stats;
  const bits = ["上游 " + d.monitor.dohUrl, "服务运行 " + dur(s ? s.uptimeSec : null)];
  if (s && s.memory) bits.push("内存 " + (s.memory.rssBytes / 1048576).toFixed(0) + " MB");
  document.getElementById("v-meta").textContent = bits.join(" · ");
}

// ===================== 登录 / 会话 =====================

function showLogin(message) {
  document.body.classList.add("auth");
  document.getElementById("login-view").classList.add("show");
  document.getElementById("login-sub").textContent = message || "请输入控制台密码";
}
function hideLogin() {
  document.body.classList.remove("auth");
  document.getElementById("login-view").classList.remove("show");
}

let loginCooldownLeft = 0;
setInterval(function () {
  if (loginCooldownLeft <= 0) return;
  loginCooldownLeft -= 1;
  const button = document.getElementById("login-button");
  button.disabled = loginCooldownLeft > 0;
  button.textContent = loginCooldownLeft > 0 ? "冷却 " + loginCooldownLeft + "s" : "登 录";
  if (loginCooldownLeft === 0) document.getElementById("login-error").textContent = "";
}, 1000);

document.getElementById("login-form").addEventListener("submit", async function (e) {
  e.preventDefault();
  if (loginCooldownLeft > 0) return;
  const password = document.getElementById("login-password").value;
  const label = document.getElementById("login-label").value.trim().slice(0, 32);
  const errorBox = document.getElementById("login-error");
  errorBox.textContent = "";
  try {
    const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password, label }) });
    if (r.status === 204) {
      hideLogin();
      document.getElementById("login-password").value = "";
      refresh(true);
      return;
    }
    const body = await r.json().catch(() => ({}));
    if (r.status === 429) {
      loginCooldownLeft = body.retryAfterSec || 60;
      errorBox.textContent = "失败次数过多，已进入冷却";
    } else {
      errorBox.textContent = body.error || "密码不正确";
    }
  } catch (err) {
    errorBox.textContent = "无法连接控制台：" + (err && err.message ? err.message : err);
  }
});

document.getElementById("logout-button").addEventListener("click", async function () {
  try { await fetch("/api/logout", { method: "POST" }); } catch {}
  RELAY = null;
  showLogin("已退出，请重新登录");
});

// ===================== 确认弹层 =====================

let modalResolve = null;
function confirmDialog(title, bodyHtml, goText, red) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML = bodyHtml;
  const go = document.getElementById("modal-go");
  go.textContent = goText || "确认";
  go.className = "btn go" + (red ? " red" : "");
  document.getElementById("modal").classList.add("show");
  return new Promise(function (resolve) { modalResolve = resolve; });
}
document.getElementById("modal-cancel").addEventListener("click", function () {
  document.getElementById("modal").classList.remove("show");
  if (modalResolve) { modalResolve(false); modalResolve = null; }
});
document.getElementById("modal-go").addEventListener("click", function () {
  document.getElementById("modal").classList.remove("show");
  if (modalResolve) { modalResolve(true); modalResolve = null; }
});

// ===================== 控制状态与双池甲板 =====================

function applyControlState(d) {
  CONSOLE_STATE = d.console || { authRequired: false, control: false, session: null };
  const wrap = document.getElementById("pools-wrap");
  const disabled = document.getElementById("console-disabled");
  const audit = document.getElementById("audit-block");
  const box = document.getElementById("session-box");
  if (!CONSOLE_STATE.control) {
    wrap.hidden = true;
    audit.hidden = true;
    disabled.hidden = false;
    disabled.textContent = CONSOLE_STATE.authRequired
      ? "控制功能未启用：有密码但缺少 ADMIN_TOKEN（主服务的 /admin/* 不可用）。在服务器上重跑 install-monitor.sh 同步 token。"
      : "控制功能未启用：尚未设置控制台密码。在服务器上执行 sudo bash contrib/home/install-monitor.sh 生成 CONSOLE_PASSWORD 并重启控制台服务；监控页不受影响。";
    document.getElementById("foot-mode").textContent = "控制未启用";
    box.classList.remove("show");
    return;
  }
  disabled.hidden = true;
  if (CONSOLE_STATE.session) {
    box.classList.add("show");
    document.getElementById("session-label").textContent = (CONSOLE_STATE.session.label || "已登录") + " · " + (CONSOLE_STATE.session.ip || "");
  } else {
    box.classList.remove("show");
  }
  document.getElementById("foot-mode").textContent = "控制台模式";
  if (CONSOLE_STATE.authRequired && !CONSOLE_STATE.session) {
    showLogin(d.__sessionExpired ? "会话已过期，请重新登录" : "请输入控制台密码");
    return;
  }
  hideLogin();
  wrap.hidden = false;
  audit.hidden = false;
  renderControl(d.stats && d.stats.pools ? d.stats.pools.relay : null);
  loadAudit();
}

function relayStripLine(relay) {
  const el = document.getElementById("relay-strip");
  if (!relay) { el.innerHTML = '<span class="rl muted">等待 relay 状态…</span>'; return; }
  const daemon = relay.healthy ? '<span class="ok2">守护健康</span>' : '<span class="err">守护未上报</span>';
  const sync = (relay.appliedConfigVersion || 0) >= (relay.configVersion || 1)
    ? '<span class="ok2">已同步 v' + relay.configVersion + "</span>"
    : '<span class="warn2">同步中 v' + (relay.appliedConfigVersion || 0) + "→v" + relay.configVersion + "</span>";
  el.innerHTML = '<span class="rl">主池 <b>' + esc(relay.mode) + "</b> · " + (relay.domains || []).length + " 条</span>" +
    '<span class="rl">强制池 <b>' + esc(relay.forcedMode || "off") + "</b> · " + (relay.forcedDomains || []).length + " 条</span>" +
    '<span class="rl">' + daemon + " · 上报 " + ago(relay.lastReportAt) + "</span>" +
    '<span class="rl">configVersion v' + relay.configVersion + " · " + sync + "</span>" +
    (relay.ip ? '<span class="rl muted">' + esc(relay.ip) + "</span>" : "");
}

function renderControl(relay) {
  RELAY = relay;
  relayStripLine(relay);
  if (!relay) return;
  document.getElementById("relay-mode-text").textContent = MODE_TEXT[relay.mode] || relay.mode;
  const sourceEl = document.getElementById("relay-mode-source");
  sourceEl.textContent = relay.modeSource === "override" ? "控制台覆盖" : "env 默认";
  sourceEl.className = "srcbadge" + (relay.modeSource === "override" ? "" : " env");
  document.getElementById("forced-mode-text").textContent = MODE_TEXT[relay.forcedMode] || relay.forcedMode || "off";
  const forcedSourceEl = document.getElementById("forced-mode-source");
  forcedSourceEl.textContent = relay.forcedModeSource === "override" ? "控制台覆盖" : "env 默认";
  forcedSourceEl.className = "srcbadge" + (relay.forcedModeSource === "override" ? "" : " env");
  const deployed = Boolean(relay.ip);
  for (const segId of ["mode-seg", "forced-mode-seg"]) {
    const seg = document.getElementById(segId);
    const key = segId === "mode-seg" ? "mode" : "forcedMode";
    const current = key === "mode" ? relay.mode : relay.forcedMode;
    for (const button of seg.querySelectorAll("button")) {
      const value = key === "mode" ? button.dataset.mode : button.dataset.fmode;
      button.classList.toggle("on", value === current);
      if (value !== "off" && !deployed) button.disabled = true;
    }
  }
  document.getElementById("forced-note").hidden = relay.forcedMode !== "always";
  document.getElementById("main-auto-note").hidden = relay.mode !== "auto";
  const notDeployed = document.getElementById("relay-not-deployed");
  notDeployed.hidden = deployed;
  if (!deployed) notDeployed.textContent = "未检测到 relay 部署（RELAY_IP 缺失或非私网地址）：档位仍可设为 off，auto/always 会被主服务拒绝。";
  const noReport = document.getElementById("relay-no-report");
  const noReports = !relay.lastReportAt;
  noReport.hidden = !(deployed && noReports);
  if (deployed && noReports) noReport.textContent = "未检测到 relay 进程上报（上次上报：从未）。档位仍可设置，但设置后名单域名会按安全不变量回退直连。";
  const sync = document.getElementById("relay-sync");
  const v = relay.configVersion || 1;
  if (noReports) {
    sync.innerHTML = "configVersion v" + v + " · <span class='warn2'>relay 未上报</span>";
  } else if ((relay.appliedConfigVersion || 0) >= v) {
    sync.innerHTML = "configVersion v" + v + " · <span class='ok2'>中转已应用 v" + relay.appliedConfigVersion + "</span>";
  } else {
    sync.innerHTML = "configVersion v" + v + " · <span class='warn2'>同步中（relay 回执 v" + (relay.appliedConfigVersion || 0) + "，≤30 秒）</span>——新增域名在'已同步'前可能被 relay 拒连，请稍候";
  }
  if (!EDIT) {
    renderChips("domains-chips", relay.domains || [], "domains");
    renderChips("forced-chips", relay.forcedDomains || [], "forced");
    renderChips("excludes-chips", relay.excludes || [], "excludes");
    document.getElementById("domains-save").disabled = true;
    hideDiff();
  }
}

function renderChips(id, list, key) {
  const el = document.getElementById(id);
  el.innerHTML = list.length ? list.map((d, i) =>
    '<span class="chip' + (key === "excludes" ? " ex" : "") + '" title="' + esc(d) + '">' + esc(d) +
    ' <button type="button" data-i="' + i + '" aria-label="删除">×</button></span>').join("")
    : '<span class="muted" style="align-self:center">（空）</span>';
  for (const button of el.querySelectorAll("button")) {
    button.addEventListener("click", function () {
      if (!EDIT) startEdit();
      EDIT[key].splice(Number(this.dataset.i), 1);
      refreshEdit();
    });
  }
}

/** 输入框支持一次黏贴多个：逗号（中英文皆可）、分号、空白、换行都是分隔符。 */
function parsePatternInput(text) {
  return String(text ?? "").split(/[,，;；\\s]+/).map((t) => t.trim()).filter(Boolean);
}

function validPattern(value) {
  const clean = value.trim().toLowerCase().replace(/\\.$/, "");
  if (!clean || clean.length > 253) return null;
  const bare = clean.replace(/^\\*\\./, "").replace(/^\\./, "");
  if (!/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(bare)) return null;
  return clean;
}

function startEdit() {
  if (!RELAY || EDIT) return;
  EDIT = { domains: [...(RELAY.domains || [])], forced: [...(RELAY.forcedDomains || [])], excludes: [...(RELAY.excludes || [])] };
}

function refreshEdit() {
  renderChips("domains-chips", EDIT.domains, "domains");
  renderChips("forced-chips", EDIT.forced, "forced");
  renderChips("excludes-chips", EDIT.excludes, "excludes");
  const dirty = RELAY && (JSON.stringify(EDIT.domains) !== JSON.stringify(RELAY.domains || [])
    || JSON.stringify(EDIT.forced) !== JSON.stringify(RELAY.forcedDomains || [])
    || JSON.stringify(EDIT.excludes) !== JSON.stringify(RELAY.excludes || []));
  document.getElementById("domains-save").disabled = !dirty;
  showDiff(dirty);
}

function showDiff(show) {
  const box = document.getElementById("domains-diff");
  if (!show || !EDIT || !RELAY) { box.hidden = true; box.innerHTML = ""; return; }
  const diff = (before, after) => {
    const added = after.filter((d) => !before.includes(d));
    const removed = before.filter((d) => !after.includes(d));
    return { added, removed };
  };
  const d1 = diff(RELAY.domains || [], EDIT.domains);
  const d2 = diff(RELAY.forcedDomains || [], EDIT.forced);
  const d3 = diff(RELAY.excludes || [], EDIT.excludes);
  const line = (label, d) => label + "：新增 " + d.added.length + " 条" + (d.added.length ? "（" + d.added.map(esc).join("、") + "）" : "") + " · 删除 " + d.removed.length + " 条" + (d.removed.length ? "（" + d.removed.map(esc).join("、") + "）" : "");
  const hasNew = d1.added.length > 0 || d2.added.length > 0;
  box.hidden = false;
  box.innerHTML = "<div>" + line("中转名单", d1) + "</div><div>" + line("强制名单", d2) + "</div><div>" + line("排除名单", d3) + "</div>" +
    (hasNew ? '<div class="warn2" style="margin-top:6px">新增域名有 ≤30 秒同步窗：relay 进程拿到新名单前，该域名的连接会被拒；无实测池的域名（强制池一律如此）依赖代理的 DOMAIN-SUFFIX 规则远程解析（curl -x &lt;代理&gt; -sI https://&lt;域名&gt; 验证）。</div>' : "");
}

function hideDiff() {
  const box = document.getElementById("domains-diff");
  box.hidden = true;
  box.innerHTML = "";
}

function wireAdd(inputId, errId, addId, key) {
  const input = document.getElementById(inputId);
  const err = document.getElementById(errId);
  const add = () => {
    err.textContent = "";
    const tokens = parsePatternInput(input.value);
    if (tokens.length === 0) { err.textContent = "请输入域名（可一次黏贴多个，用逗号或空格分隔）"; return; }
    startEdit();
    const arr = EDIT[key];
    const added = [], problems = [];
    for (const token of tokens) {
      const pattern = validPattern(token);
      if (!pattern) { problems.push(token + "：仅支持 精确域名 或 *.通配"); continue; }
      if (arr.includes(pattern)) { problems.push(pattern + "：已在名单中"); continue; }
      if (arr.length >= 64) { problems.push(pattern + "：名单上限 64 条"); continue; }
      arr.push(pattern);
      added.push(pattern);
    }
    if (added.length > 0) {
      input.value = "";
      err.textContent = problems.length ? "已添加 " + added.length + " 条；" + problems.slice(0, 3).join("；") + (problems.length > 3 ? " 等" : "") : "";
      refreshEdit();
    } else {
      err.textContent = problems.slice(0, 3).join("；") + (problems.length > 3 ? " 等" : "");
    }
  };
  document.getElementById(addId).addEventListener("click", add);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
}
wireAdd("domain-input", "domain-err", "domain-add", "domains");
wireAdd("forced-input", "forced-err", "forced-add", "forced");
wireAdd("exclude-input", "exclude-err", "exclude-add", "excludes");

document.getElementById("domains-save").addEventListener("click", async function () {
  if (!EDIT || !RELAY) return;
  const go = await confirmDialog("保存名单变更", document.getElementById("domains-diff").innerHTML, "确认保存");
  if (!go) return;
  const result = await postRelayConfig({ domains: EDIT.domains, forcedDomains: EDIT.forced, excludeDomains: EDIT.excludes, expectedVersion: RELAY.configVersion }, "relay-domains");
  if (result) { EDIT = null; }
});

document.getElementById("relay-reset").addEventListener("click", async function () {
  if (!RELAY) return;
  const go = await confirmDialog("恢复 env 默认配置",
    "<p>将清除控制台的运行时覆盖，回到 env 文件里的值：</p><ul><li>主池档位：<b>" + esc(MODE_TEXT[RELAY.envMode] || RELAY.envMode || "off") + "</b>（env RELAY_MODE）</li><li>强制池档位：<b>" + esc(MODE_TEXT[RELAY.envForcedMode] || RELAY.envForcedMode || "off") + "</b>（env RELAY_FORCED_MODE）</li><li>中转名单：" + ((RELAY.envDomains || []).map(esc).join("、") || "（空）") + "</li><li>强制名单：" + ((RELAY.envForcedDomains || []).map(esc).join("、") || "（空）") + "</li><li>排除名单：" + ((RELAY.envExcludes || []).map(esc).join("、") || "（空）") + "</li></ul>",
    "恢复默认");
  if (!go) return;
  EDIT = null;
  await postRelayConfig({ reset: true }, "relay-reset");
});

document.getElementById("mode-seg").addEventListener("click", async function (e) {
  const button = e.target.closest("button");
  if (!button || button.disabled || !RELAY) return;
  const mode = button.dataset.mode;
  if (mode === RELAY.mode) return;
  if (mode === "always") {
    const domains = (EDIT ? EDIT.domains : RELAY.domains) || [];
    const go = await confirmDialog("主池切换到 always（常开中转）",
      "<p>将<b>无条件</b>把以下域名的全部流量答成中转 IP，经代理节点出境：</p><ul><li>名单共 <b>" + domains.length + "</b> 条" + (domains.length ? "：" + domains.slice(0, 5).map(esc).join("、") + (domains.length > 5 ? " 等" : "") : "（空）") + "</li><li>这些站点的流量<b>消耗代理节点带宽</b>（大 clone 会显著走节点流量）</li><li>ECH 不适用：名单站点的 HTTPS RR 会被清洗（摘 ECH、hint 指中转、ALPN 压 h2）</li><li>always 不看健康：即使直连质量好也不回切</li></ul><p>确认切换？</p>",
      "确认切换到 always", true);
    if (!go) return;
  }
  await postRelayConfig({ mode, expectedVersion: RELAY.configVersion }, "relay-mode");
});

document.getElementById("forced-mode-seg").addEventListener("click", async function (e) {
  const button = e.target.closest("button");
  if (!button || button.disabled || !RELAY) return;
  const mode = button.dataset.fmode;
  if (mode === RELAY.forcedMode) return;
  if (mode === "always") {
    const domains = (EDIT ? EDIT.forced : RELAY.forcedDomains) || [];
    const go = await confirmDialog("强制池切换到 always（常开中转）",
      "<p>将<b>不看任何测量</b>、把以下域名的全部流量答成中转 IP，经代理节点出境：</p><ul><li>强制名单共 <b>" + domains.length + "</b> 条" + (domains.length ? "：" + domains.slice(0, 5).map(esc).join("、") + (domains.length > 5 ? " 等" : "") : "（空）——先在右侧添加域名") + "</li><li>这些站点的流量<b>消耗代理节点带宽</b>（视频站会显著走节点流量）</li><li>ECH 不适用：名单站点的 HTTPS RR 会被清洗（摘 ECH、hint 指中转、ALPN 压 h2）</li><li>安全不变量仍在：relay 守护停止上报健康即整体回退直连（≤60s）</li></ul><p>确认切换？</p>",
      "确认切换到 always", true);
    if (!go) return;
  }
  await postRelayConfig({ forcedMode: mode, expectedVersion: RELAY.configVersion }, "relay-forced-mode");
});

async function postRelayConfig(body, action) {
  const before = RELAY ? { mode: RELAY.mode, forcedMode: RELAY.forcedMode, domains: [...(RELAY.domains || [])], excludes: [...(RELAY.excludes || [])], version: RELAY.configVersion } : null;
  let response;
  try {
    response = await fetch("/api/relay-config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch (error) {
    showResult("err", "配置未更改：控制台无法提交（" + (error && error.message ? error.message : error) + "）");
    return false;
  }
  if (response.status === 401) {
    showLogin("会话已过期，请重新登录（未完成的操作需重新执行）");
    return false;
  }
  const payload = await response.json().catch(() => ({}));
  if (response.ok && payload.ok !== false && payload.relay) {
    const after = payload.relay;
    const lines = ["已" + (action === "relay-mode" ? "切换主池档位 → <b>" + esc(MODE_TEXT[after.mode] || after.mode) + "</b>"
      : action === "relay-forced-mode" ? "切换强制池档位 → <b>" + esc(MODE_TEXT[after.forcedMode] || after.forcedMode) + "</b>"
      : action === "relay-domains" ? "保存名单（中转 " + after.domains.length + " 条 · 强制 " + (after.forcedDomains || []).length + " 条 · 排除 " + after.excludes.length + " 条）"
      : "恢复 env 默认配置") + "（配置 v" + after.configVersion + "）",
      "已持久化：主服务重启后保留",
      "新 DNS 答案即刻生效；存量客户端最迟 60 秒收敛（中转答案 TTL ≤ 60s）",
      "relay 进程 ≤30 秒收到新名单（下次健康上报）；新增域名请等'已同步'再使用"];
    const mainOff = after.mode === "off" && before && before.mode !== "off";
    const forcedOff = after.forcedMode === "off" && before && before.forcedMode !== "off";
    if (mainOff || forcedOff) {
      showResult("warn", lines[0] + "<br>" + lines.slice(1).join("<br>") + "<br>⚠ 对应池的名单域名回到直连路径；relay 进程未停止（无害），彻底停用：systemctl disable --now edge-smart-doh-relay");
    } else {
      showResult("ok", lines.join("<br>"));
    }
    renderControl(after);
    return true;
  }
  if (response.status === 409) {
    showResult("err", "配置未更改：已被其他会话修改（当前 v" + (payload.configVersion || "?") + "）。正在刷新，请重试。");
    refresh(true);
    return false;
  }
  if (response.status === 502) {
    showResult("err", esc(payload.error || "主服务不可达") + (payload.hint ? "<br>排查：" + esc(payload.hint) : ""));
    return false;
  }
  showResult("err", "配置未更改：" + esc(payload.error || "主服务拒绝（HTTP " + response.status + "）"));
  return false;
}

function showResult(kind, html) {
  const box = document.getElementById("relay-result");
  box.className = "cresult " + kind;
  box.innerHTML = html;
  box.hidden = false;
}

async function loadAudit(force) {
  const block = document.getElementById("audit-block");
  if (!block.open && !force) return;
  try {
    const r = await fetch("/api/audit", { cache: "no-store" });
    if (!r.ok) return;
    const body = await r.json();
    const entries = (body.entries || []).slice(-50).reverse();
    document.getElementById("audit-cnt").textContent = entries.length ? "最近 " + entries.length + " 条" : "";
    document.getElementById("audit-body").innerHTML = entries.length ? entries.map((e) => {
      const label = e.action === "login-ok" ? "登录" : e.action === "login-fail" ? "登录失败" : e.action === "logout" ? "退出"
        : e.action === "relay-mode" ? "主池档位" : e.action === "relay-forced-mode" ? "强制池档位" : e.action === "relay-domains" ? "保存名单" : e.action === "relay-reset" ? "恢复默认" : esc(e.action);
      return "<tr><td class='muted'>" + hhmmss(e.t) + "</td><td>" + esc(e.ip) + (e.label ? '<br><span class="muted">' + esc(e.label) + "</span>" : "") + "</td><td>" + label + (e.count > 1 ? " ×" + e.count : "") + "</td><td class='muted'>" + esc(e.detail || "") + "</td><td>" + (e.result === "ok" ? '<span class="ok2">成功</span>' : '<span class="err">失败</span>') + "</td></tr>";
    }).join("") : '<tr><td class="muted">暂无操作记录</td></tr>';
  } catch {}
}
document.getElementById("audit-block").addEventListener("toggle", function () { if (this.open) loadAudit(true); });

// ===================== 主刷新循环 =====================

let fetchFails = 0;
async function refresh(force) {
  const meta = document.getElementById("v-meta");
  try {
    const r = await fetch("/api/summary", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    fetchFails = 0;
    setVerdict(d);
    applyControlState(d);
    if (d.statsError && meta) meta.textContent = "数据通道降级：" + d.statsError.slice(0, 80);
  } catch (e) {
    fetchFails += 1;
    if (meta && fetchFails > 2) meta.textContent = "取数失败 ×" + fetchFails + "：" + (e && e.message ? e.message : e);
  }
}
refresh();
setInterval(refresh, 5000);
})();
</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>
`;

// ============================== HTTP 服务 ==============================

const HEADERS = {
  "/": { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'", "Referrer-Policy": "no-referrer" },
  "/healthz": { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
};

const server = createServer(async (request, response) => {
  const remote = request.socket.remoteAddress ?? "";
  if (!sourceAllowed(remote)) {
    logDenied(remote);
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Forbidden: LAN only\n");
    return;
  }
  const send = (status, headers, body) => {
    response.writeHead(status, headers);
    response.end(request.method === "HEAD" ? undefined : body);
  };
  const path = (request.url ?? "/").split("?")[0];
  const jsonHeaders = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

  // ---- 登录（无会话也可访问；防爆破） ----
  if (path === "/api/login" && request.method === "POST") {
    const cooldown = loginCooldown(remote);
    if (cooldown > 0) {
      audit("login-fail", { ip: remote, result: "cooldown", detail: "冷却中重试" });
      return send(429, jsonHeaders, JSON.stringify({ error: "失败次数过多，请稍后再试", retryAfterSec: cooldown }));
    }
    const body = await readJsonBody(request);
    const password = body && typeof body.password === "string" ? body.password : "";
    const label = body && typeof body.label === "string" ? body.label.trim().slice(0, 32) : "";
    if (!password || !passwordMatches(password)) {
      const entry = loginDenied(remote);
      audit("login-fail", { ip: remote, result: "wrong-password" });
      const left = LOGIN_FAIL_LIMIT - entry.count;
      return send(401, jsonHeaders, JSON.stringify({ error: "密码不正确", remaining: Math.max(0, left) }));
    }
    loginFailures.delete(remote);
    const id = openSession(remote, label);
    audit("login-ok", { ip: remote, label });
    return send(204, {
      "Set-Cookie": `console_session=${id}; HttpOnly; SameSite=Strict; Path=/`,
      "Cache-Control": "no-store",
    }, undefined);
  }

  if (path === "/api/logout" && request.method === "POST") {
    const session = sessionOf(request);
    if (session) {
      sessions.delete(session.id);
      audit("logout", { ip: session.ip, label: session.label });
    }
    return send(204, { "Set-Cookie": "console_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0", "Cache-Control": "no-store" }, undefined);
  }

  // ---- 监控数据（公开：监控页不需要密码） ----
  if (path === "/api/summary" && request.method === "GET") {
    return send(200, jsonHeaders, JSON.stringify(summary(request)));
  }

  // ---- 控制端点（需要会话） ----
  if (path === "/api/relay" && request.method === "GET") {
    const denied = requireSession(request);
    if (denied) return send(denied[0], denied[1], denied[2]);
    const session = sessionOf(request);
    const [status, headers, body] = await relayStatusProxy();
    if (status !== 200) audit("relay-read", { ip: session?.ip ?? remote, label: session?.label ?? "", result: "fail", detail: `HTTP ${status}` });
    return send(status, headers, body);
  }

  if (path === "/api/relay-config" && request.method === "POST") {
    const denied = requireSession(request);
    if (denied) return send(denied[0], denied[1], denied[2]);
    const session = sessionOf(request);
    const raw = await readJsonBody(request);
    if (!raw || typeof raw !== "object") return send(400, jsonHeaders, JSON.stringify({ error: "请求体必须是 JSON 对象" }));
    const body = sanitizeRelayConfigBody(raw);
    const before = RELAY && { mode: RELAY.mode, forcedMode: RELAY.forcedMode, domains: [...RELAY.domains], excludes: [...RELAY.excludes], forced: [...(RELAY.forcedDomains || [])] };
    const [status, headers, text] = await relayConfigProxy(body);
    let after;
    try { after = JSON.parse(text); } catch { after = undefined; }
    if (status === 200 && after?.relay) {
      const action = body.reset ? "relay-reset"
        : body.forcedMode !== undefined ? "relay-forced-mode"
        : body.mode !== undefined ? "relay-mode"
        : "relay-domains";
      const detail = body.reset ? "reset → env 默认"
        : body.forcedMode !== undefined ? `强制池 ${before?.forcedMode ?? "?"} → ${after.relay.forcedMode}`
        : body.mode !== undefined ? `主池 ${before?.mode ?? "?"} → ${after.relay.mode}`
        : `名单 中转 ${after.relay.domains.length} 条 / 强制 ${(after.relay.forcedDomains || []).length} 条 / 排除 ${after.relay.excludes.length} 条`;
      audit(action, { ip: session.ip, label: session.label, detail });
      RELAY = after.relay;
    } else if (status !== 200) {
      let errorText = "";
      try { errorText = JSON.parse(text)?.error ?? String(text).slice(0, 120); } catch { errorText = String(text).slice(0, 120); }
      const action = body.reset ? "relay-reset" : body.forcedMode !== undefined ? "relay-forced-mode" : body.mode !== undefined ? "relay-mode" : "relay-domains";
      audit(action, { ip: session.ip, label: session.label, result: "fail", detail: `HTTP ${status}: ${errorText}` });
    }
    return send(status, headers, text);
  }

  if (path === "/api/audit" && request.method === "GET") {
    const denied = requireSession(request);
    if (denied) return send(denied[0], denied[1], denied[2]);
    return send(200, jsonHeaders, JSON.stringify({ entries: auditLog.slice(-100) }));
  }

  // ---- 页面 / 静态 / 健康 ----
  if (path === "/" && (request.method === "GET" || request.method === "HEAD")) {
    return send(200, HEADERS["/"], PAGE_MONITOR);
  }
  if (path === "/console" && (request.method === "GET" || request.method === "HEAD")) {
    return send(200, HEADERS["/"], PAGE_CONSOLE);
  }
  if (path === "/vendor/echarts.min.js" && (request.method === "GET" || request.method === "HEAD")) {
    if (echartsJs) {
      return send(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "public, max-age=86400" }, echartsJs);
    }
    return send(404, { "Content-Type": "text/plain; charset=utf-8" }, "Not found\n");
  }
  if (path === "/healthz" && (request.method === "GET" || request.method === "HEAD")) {
    return send(200, HEADERS["/healthz"], JSON.stringify({ ok: true, uptimeSec: Math.floor((Date.now() - state.startedAt) / 1000), authRequired: AUTH_REQUIRED, control: CONTROL_ENABLED }));
  }
  if (path === "/api/summary" || path === "/api/relay" || path === "/api/relay-config" || path === "/api/audit") {
    return send(405, { Allow: "GET, POST" }, "");
  }
  return send(404, { "Content-Type": "text/plain; charset=utf-8" }, "Not found\n");
});

server.listen(PORT, HOST, () => {
  console.log(JSON.stringify({
    event: "console_listening", host: HOST, port: PORT, dohUrl: DOH_URL,
    authRequired: AUTH_REQUIRED, control: CONTROL_ENABLED,
    allow: ALLOW_SPEC.join(","), probes: PROBE_NAMES,
  }));
  void poll();
  setInterval(poll, INTERVAL_MS);
});

function shutdown(signal) {
  console.log(JSON.stringify({ event: "console_shutdown", signal }));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
