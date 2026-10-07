#!/usr/bin/env node
/**
 * edge-smart-doh 局域网控制台（contrib/home/monitor）——单文件、零依赖，Node ≥18。
 *
 * 前身是纯监测站；按 contrib/home/monitor/PRD-console.md 升级为"控制台"：
 *   · 监测（不变）：/health 可达性、/admin/stats 指标、主动解析探测；
 *   · 控制（新）：代理主服务 POST /admin/relay-config——relay 档位（off/auto/always）与
 *     域名名单（RELAY_DOMAINS / RELAY_EXCLUDE_DOMAINS）的运行时变更，改完即生效；
 *   · 统计分类（新）：回源路径分布（SNI 中转 / ECH 注入 / 优选池 / 国内直连 / 直连 + 缓存应答）；
 *   · 访问控制（新）：CONSOLE_PASSWORD（monitor.env，0600 root）+ 内存会话 cookie。
 *
 * 安全模型（三层防线）：
 *   1. 来源过滤：默认绑定 0.0.0.0，但每个请求按 TCP 对端地址（socket.remoteAddress，绝不信任
 *      X-Forwarded-For 等可伪造头）过滤：仅回环、RFC1918、CGNAT、ULA、链路本地放行；
 *   2. 密码会话：设置了 CONSOLE_PASSWORD 后看与控都要登录（会话 id 仅存本进程内存，进程重启
 *      全部失效；HttpOnly + SameSite=Strict cookie；每 IP 5 次失败冷却 60s）；未设置密码时
 *      保持升级前的纯监测形态（控制区隐藏、无 /api 控制端点）——向后兼容；
 *   3. 凭据隔离：ADMIN_TOKEN 只存在本进程内存，页面与浏览器只见到会话 cookie，绝不回传。
 *   纵深防御：deploy-home.sh 的 nftables 规则（SETUP_FIREWALL=1）在网络层再限一次内网网段。
 *
 * 配置（环境变量，均有默认值）：DOH_URL、ADMIN_TOKEN、CONSOLE_PASSWORD、MONITOR_HOST、
 *   MONITOR_PORT、MONITOR_INTERVAL_MS（采样间隔，≥5000）、MONITOR_PROBE_NAMES（探测域名，逗号分隔）、
 *   MONITOR_ALLOW（放行来源：默认 "private"；可写网段列表整体替换）、MONITOR_PROBE_TIMEOUT_MS。
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
// 每个探测域名在页面上的"链路"名称：MONITOR_PROBE_LABELS（逗号分隔，与 NAMES 一一对应）可整体覆盖；
// 默认按域名特征推导（国内大站=国内直连、github=GitHub 池、其余=境外/代理）。
const PROBE_LABELS = (process.env.MONITOR_PROBE_LABELS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
function probeLabel(name, index) {
  if (PROBE_LABELS[index]) return PROBE_LABELS[index];
  if (/github/.test(name)) return "GitHub 池";
  if (/(^|\.)(taobao|tmall|baidu|qq\.com|weibo|bilibili|jd\.com|aliyun|tencent|163\.com|zhihu|douyin)/.test(name)) return "国内直连";
  return "境外 / 代理";
}
const HISTORY_MAX = 360; // 每个探测域名的延迟历史（默认 10s 一采样 ≈ 1 小时）
const HISTORY_SENT = 240; // 发给页面的点数（约 40 分钟）

/** 有密码 = 看与控都要登录；没密码 = 纯监测（升级前形态）。控制端点还要求 ADMIN_TOKEN。 */
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

/** id -> { label, ip, createdAt, lastSeenAt }；仅内存，重启即全部失效（PRD §3.1）。 */
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

/** 需要登录的端点统一走这里：返回 Response 即拒绝。 */
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
  // 连续登录失败聚合成一条（AC23a）：同 IP 60s 内的失败只累计次数
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
  // 1) 服务可达性
  const started = Date.now();
  try {
    const response = await fetch(`${DOH_URL}/health`, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    state.doh = { ok: response.ok, latencyMs: Date.now() - started, error: response.ok ? null : `HTTP ${response.status}`, lastCheck: Date.now() };
  } catch (error) {
    state.doh = { ok: false, latencyMs: Date.now() - started, error: describeError(error), lastCheck: Date.now() };
  }
  // 2) 指标（404 = 主服务未升级，仍可展示探测数据）
  try {
    state.stats = await fetchJson("/admin/stats", PROBE_TIMEOUT_MS);
    state.statsError = null;
    state.statsAt = Date.now();
  } catch (error) {
    state.statsError = describeError(error);
  }
  // 3) 主动解析探测（串行，延迟测量互不干扰）
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

// ============================== 汇总 ==============================

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

// ============================== 仪表盘页面 ==============================

// ECharts 由本地 vendor 目录提供（无公网依赖）；缺失时页面自动降级为"表格仍可用"。
const VENDOR_ECHARTS = new URL("./vendor/echarts.min.js", import.meta.url);
let echartsJs = null;
try {
  echartsJs = readFileSync(VENDOR_ECHARTS);
} catch {
  console.warn(JSON.stringify({ event: "monitor_vendor_missing", file: "vendor/echarts.min.js", hint: "图表面板将显示加载失败提示，表格不受影响" }));
}

const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edge Smart DoH 控制台</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0a0f1e; color: #dbe2f0; font: 14px/1.5 system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 28px 20px 48px; }

  /* ---- 第一屏：健康判定 + 核心数字 ---- */
  .hero { display: flex; align-items: center; gap: 14px; margin-bottom: 6px; flex-wrap: wrap; }
  .vdot { width: 14px; height: 14px; border-radius: 50%; background: #64748b; flex: none; }
  .vdot.ok { background: #34d399; animation: pulse 2.4s ease-out infinite; }
  .vdot.warn { background: #fbbf24; }
  .vdot.bad { background: #f87171; animation: pulse 1.2s ease-out infinite; }
  @keyframes pulse { 0% { box-shadow: 0 0 0 0 currentColor; opacity: 1; } 70% { box-shadow: 0 0 0 12px transparent; } 100% { box-shadow: 0 0 0 0 transparent; } }
  #v-text { font-size: 27px; font-weight: 700; letter-spacing: 1px; }
  #v-text.ok { color: #34d399; } #v-text.warn { color: #fbbf24; } #v-text.bad { color: #f87171; }
  #refresh-line { margin-left: auto; color: #5b6883; font-size: 12px; }
  .vsub { color: #8792ad; font-size: 12.5px; margin-bottom: 4px; }
  .vwhy { display: none; margin: 2px 0 0; padding: 7px 12px; border-radius: 8px; font-size: 13px; }
  .vwhy.show { display: block; }
  .vwhy.bad { background: #3a1420; border: 1px solid #7f1d1d; color: #fca5a5; }
  .vwhy.warn { background: #33240e; border: 1px solid #78350f; color: #fcd34d; }

  .cards { display: grid; grid-template-columns: 1.2fr 1fr 1fr 1fr; gap: 12px; margin: 16px 0 12px; }
  @media (max-width: 980px) { .cards { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 560px) { .cards { grid-template-columns: 1fr; } }
  .card { background: #0f1630; border: 1px solid #1c2742; border-radius: 12px; padding: 14px 16px; min-width: 0; }
  .card .k { color: #8792ad; font-size: 12px; margin-bottom: 6px; }
  .card .v { font-size: 30px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
  .card .v small { font-size: 14px; font-weight: 500; color: #8792ad; }
  .card .s { color: #8792ad; font-size: 12px; margin-top: 5px; }
  .path { display: flex; align-items: center; gap: 8px; padding: 4.5px 0; font-size: 13.5px; }
  .path + .path { border-top: 1px solid #16203a; }
  .pdot { width: 8px; height: 8px; border-radius: 50%; background: #64748b; flex: none; }
  .pdot.ok { background: #34d399; } .pdot.bad { background: #f87171; }
  .pl { color: #c6cfe2; }
  .pv { margin-left: auto; font-variant-numeric: tabular-nums; }
  .pv.err { color: #fca5a5; }

  /* ---- 面板 ---- */
  .panel { background: #0f1630; border: 1px solid #1c2742; border-radius: 12px; padding: 14px 16px; min-width: 0; margin-bottom: 12px; }
  .panel h2 { font-size: 13px; margin: 0 0 10px; color: #aab6d0; font-weight: 600; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .panel h2::before { content: ""; width: 3px; height: 12px; border-radius: 2px; background: #3b82f6; }
  .panel h2 .h2s { color: #5b6883; font-weight: 400; font-size: 11.5px; }
  .row { display: grid; grid-template-columns: 1fr 1.2fr 1.2fr; gap: 12px; margin-bottom: 12px; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  @media (max-width: 980px) { .row, .row2 { grid-template-columns: 1fr; } }
  .chart { width: 100%; }

  table { width: 100%; border-collapse: collapse; font-size: 12.8px; }
  th { text-align: left; color: #8792ad; font-weight: 500; padding: 3px 6px; border-bottom: 1px solid #1c2742; white-space: nowrap; }
  td { padding: 4px 6px; border-bottom: 1px solid #141d38; font-variant-numeric: tabular-nums; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  td.n { text-align: right; white-space: nowrap; }
  .muted { color: #8792ad; }
  .warn2 { color: #fbbf24; }
  .err { color: #fca5a5; }
  .ok2 { color: #6ee7b7; }
  .badge { display: inline-block; padding: 0 7px; border-radius: 999px; font-size: 11px; border: 1px solid; line-height: 17px; white-space: nowrap; }
  .b-hit { color: #6ee7b7; border-color: #065f46; background: #06281e; }
  .b-prefetch { color: #5eead4; border-color: #115e59; background: #04201e; }
  .b-stale { color: #fcd34d; border-color: #78350f; background: #2a1c06; }
  .b-miss { color: #93c5fd; border-color: #1e40af; background: #0d1834; }
  .b-blocked { color: #d8b4fe; border-color: #6b21a8; background: #20102e; }
  .b-error { color: #fca5a5; border-color: #7f1d1d; background: #2c1216; }
  .b-path { border-color: #334155; background: #0d1834; }
  .role { color: #8792ad; font-size: 11px; border: 1px solid #2a3550; border-radius: 4px; padding: 0 5px; margin-left: 6px; }

  /* 延迟分布条 */
  .lrow { display: flex; align-items: center; gap: 10px; padding: 5px 0; }
  .lk { width: 34px; color: #8792ad; font-size: 12px; }
  .lbar { flex: 1; height: 8px; border-radius: 4px; background: #16203a; overflow: hidden; }
  .lbar i { display: block; height: 100%; border-radius: 4px; background: linear-gradient(90deg, #38bdf8, #818cf8); }
  .lv { width: 74px; text-align: right; font-variant-numeric: tabular-nums; font-size: 13px; }

  /* 路径分布（面板④）：单条 = 名称+条+数字 */
  .prow { display: flex; align-items: center; gap: 10px; padding: 5px 0; font-size: 13px; }
  .prow .pk { width: 86px; color: #c6cfe2; flex: none; }
  .prow .pbar { flex: 1; height: 10px; border-radius: 5px; background: #16203a; overflow: hidden; }
  .prow .pbar i { display: block; height: 100%; border-radius: 5px; }
  .prow .pn { width: 190px; text-align: right; font-variant-numeric: tabular-nums; color: #8792ad; font-size: 12px; flex: none; }

  /* 内联小条（高频域名） */
  .tbar { height: 6px; border-radius: 3px; background: #16203a; overflow: hidden; min-width: 60px; }
  .tbar i { display: block; height: 100%; background: #818cf8; opacity: .8; }

  /* 折叠诊断区 */
  details { background: #0f1630; border: 1px solid #1c2742; border-radius: 12px; margin-bottom: 10px; }
  summary { cursor: pointer; padding: 11px 16px; color: #aab6d0; font-size: 13px; font-weight: 600; list-style: none; display: flex; align-items: center; gap: 8px; }
  summary::before { content: "▸"; color: #5b6883; transition: transform .15s; }
  details[open] summary::before { transform: rotate(90deg); }
  summary .cnt { margin-left: auto; color: #5b6883; font-weight: 400; font-size: 11.5px; }
  .dbody { padding: 2px 16px 12px; }
  footer { margin-top: 16px; color: #5b6883; font-size: 12px; text-align: center; }

  /* ---- 登录卡 ---- */
  #login-view { display: none; min-height: 100vh; align-items: center; justify-content: center; padding: 20px; }
  #login-view.show { display: flex; }
  .login-card { width: 380px; max-width: 100%; background: #0f1630; border: 1px solid #1c2742; border-radius: 14px; padding: 28px; }
  .login-card h1 { font-size: 20px; margin: 0 0 4px; }
  .login-card .sub { color: #8792ad; margin: 0 0 18px; font-size: 13px; }
  .login-card input { width: 100%; margin-bottom: 10px; padding: 9px 12px; border-radius: 8px; border: 1px solid #2a3550; background: #0a0f1e; color: #dbe2f0; font-size: 14px; }
  .login-card input:focus { outline: none; border-color: #3b82f6; }
  .login-card button { width: 100%; padding: 10px; border-radius: 8px; border: none; background: #2563eb; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; }
  .login-card button:disabled { opacity: .5; cursor: not-allowed; }
  #login-error { color: #fca5a5; font-size: 13px; min-height: 18px; margin: 8px 0 4px; }
  #login-hint { color: #5b6883; font-size: 11.5px; margin-top: 14px; line-height: 1.6; }
  body.auth #main { display: none; }

  /* ---- 会话徽标 ---- */
  #session-box { display: none; align-items: center; gap: 8px; color: #8792ad; font-size: 12px; }
  #session-box.show { display: inline-flex; }
  #session-box .slabel { border: 1px solid #2a3550; border-radius: 999px; padding: 1px 9px; }
  #session-box button { background: none; border: 1px solid #2a3550; color: #8792ad; border-radius: 6px; padding: 2px 9px; font-size: 11.5px; cursor: pointer; }
  #session-box button:hover { color: #dbe2f0; border-color: #3b82f6; }

  /* ---- 控制区（琥珀色边框，PRD §2.1）---- */
  .control-panel { border-color: #78350f; }
  .control-panel h2::before { background: #f59e0b; }
  .cwarn { background: #33240e; border: 1px solid #78350f; color: #fcd34d; border-radius: 8px; padding: 8px 12px; font-size: 13px; margin: 8px 0; }
  .cinfo { background: #04201e; border: 1px solid #115e59; color: #5eead4; border-radius: 8px; padding: 8px 12px; font-size: 13px; margin: 8px 0; }
  .mode-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin: 10px 0; }
  .mode-current { font-size: 15px; }
  .mode-current b { font-size: 22px; margin-right: 6px; }
  .seg { display: inline-flex; border: 1px solid #2a3550; border-radius: 10px; overflow: hidden; }
  .seg button { background: none; border: none; color: #c6cfe2; padding: 8px 16px; font-size: 13px; cursor: pointer; border-right: 1px solid #2a3550; }
  .seg button:last-child { border-right: none; }
  .seg button.on { background: #1d4ed8; color: #fff; }
  .seg button:disabled { opacity: .35; cursor: not-allowed; }
  .seg button.danger:not(.on) { color: #fbbf24; }
  .cresult { border-radius: 8px; padding: 10px 12px; font-size: 13px; margin: 10px 0; line-height: 1.7; }
  .cresult.ok { background: #06281e; border: 1px solid #065f46; color: #6ee7b7; }
  .cresult.warn { background: #2a1c06; border: 1px solid #78350f; color: #fcd34d; }
  .cresult.err { background: #2c1216; border: 1px solid #7f1d1d; color: #fca5a5; }
  .lists { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 12px; }
  @media (max-width: 980px) { .lists { grid-template-columns: 1fr; } }
  .list-edit h3 { font-size: 12px; color: #aab6d0; margin: 0 0 8px; font-weight: 600; }
  .list-edit h3 code { color: #5b6883; font-size: 11px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; min-height: 30px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; background: #0d1834; border: 1px solid #1e3a8a; color: #93c5fd; border-radius: 999px; padding: 2px 6px 2px 10px; font-size: 12.5px; }
  .chip.ex { border-color: #7f1d1d; color: #fca5a5; background: #2c1216; }
  .chip button { background: none; border: none; color: inherit; cursor: pointer; font-size: 13px; padding: 0 4px; }
  .addrow { display: flex; gap: 6px; }
  .addrow input { flex: 1; padding: 6px 10px; border-radius: 8px; border: 1px solid #2a3550; background: #0a0f1e; color: #dbe2f0; font-size: 13px; }
  .addrow input:focus { outline: none; border-color: #3b82f6; }
  .addrow button, .btn { background: #1d4ed8; border: none; color: #fff; border-radius: 8px; padding: 6px 14px; font-size: 13px; cursor: pointer; }
  .btn.secondary { background: #334155; }
  .btn:disabled { opacity: .4; cursor: not-allowed; }
  .field-err { color: #fca5a5; font-size: 12px; min-height: 16px; margin-top: 4px; }
  .diff-box { background: #0a0f1e; border: 1px solid #2a3550; border-radius: 8px; padding: 10px 12px; margin-top: 10px; font-size: 12.5px; }
  .diff-box .add { color: #6ee7b7; } .diff-box .del { color: #fca5a5; }
  .sync-line { color: #8792ad; font-size: 12.5px; margin-top: 12px; }
  .ctl-actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }

  /* ---- 确认弹层 ---- */
  #modal { display: none; position: fixed; inset: 0; background: rgba(4,8,20,.72); z-index: 50; align-items: center; justify-content: center; padding: 20px; }
  #modal.show { display: flex; }
  .modal-card { width: 480px; max-width: 100%; max-height: 84vh; overflow: auto; background: #0f1630; border: 1px solid #2a3550; border-radius: 14px; padding: 22px; }
  .modal-card h3 { margin: 0 0 10px; font-size: 16px; }
  .modal-card .mbody { color: #c6cfe2; font-size: 13.5px; line-height: 1.7; }
  .modal-card .mbody ul { margin: 8px 0; padding-left: 20px; }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; }
  .modal-actions .btn.go { background: #b45309; }
  .modal-actions .btn.go.red { background: #b91c1c; }
</style>
</head>
<body>
<div id="login-view">
  <div class="login-card">
    <h1>Edge Smart DoH 控制台</h1>
    <p class="sub" id="login-sub">请输入控制台密码</p>
    <form id="login-form">
      <input type="password" id="login-password" placeholder="密码" autocomplete="current-password" autofocus>
      <input type="text" id="login-label" placeholder="备注（可选，≤32 字符，便于审计）" maxlength="32">
      <button type="submit" id="login-button">登录</button>
    </form>
    <div id="login-error"></div>
    <div id="login-hint">密码由安装脚本生成，可在服务器上查看：<br><code>sudo grep CONSOLE_PASSWORD /etc/edge-smart-doh/monitor.env</code></div>
  </div>
</div>

<div class="wrap" id="main">
  <div class="hero">
    <span class="vdot" id="v-dot"></span>
    <span id="v-text">检测中…</span>
    <span id="session-box"><span class="slabel" id="session-label"></span><button type="button" id="logout-button">退出</button></span>
    <span id="refresh-line"></span>
  </div>
  <div class="vsub" id="v-sub">正在连接 8788 控制台服务…</div>
  <div class="vwhy" id="v-why"></div>

  <div class="cards">
    <div class="card"><div class="k">解析链路健康</div><div id="path-health" class="muted">等待首次探测…</div></div>
    <div class="card"><div class="k">总查询</div><div class="v" id="stat-total">—</div><div class="s" id="stat-total-s">自上次重启</div></div>
    <div class="card"><div class="k">缓存命中率</div><div class="v" id="stat-rate">—</div><div class="s" id="stat-rate-s"></div></div>
    <div class="card"><div class="k">回源延迟 P50</div><div class="v" id="stat-p50">—</div><div class="s" id="stat-lat-s"></div></div>
  </div>

  <div class="panel">
    <h2>查询量 <span class="h2s">近 2 小时 · 每分钟 · 绿=缓存命中 蓝=回源 红=失败</span></h2>
    <div id="minute-chart" class="chart" style="height:200px"></div>
  </div>

  <div class="panel">
    <h2>解析路径分布 <span class="h2s">自服务启动以来 · 回源按路径归类，缓存应答单列 · 路径按回源时刻归类，已进入缓存的查询不再重新计类</span></h2>
    <div id="paths-panel"></div>
  </div>

  <div class="row">
    <div class="panel">
      <h2>回源延迟 <span class="h2s" id="lat-n"></span></h2>
      <div id="latency-bars"></div>
    </div>
    <div class="panel">
      <h2>解析策略 <span class="h2s">回源时怎么解的（技术视图）</span></h2>
      <div id="strategy-chart" class="chart" style="height:190px"></div>
    </div>
    <div class="panel">
      <h2>上游解析器</h2>
      <div id="upstreams"></div>
    </div>
  </div>

  <div class="panel">
    <h2>链路延迟趋势 <span class="h2s">每 10 秒真实 DoH 查询 · 断点=该次失败</span></h2>
    <div id="probe-chart" class="chart" style="height:210px"></div>
  </div>

  <div class="panel control-panel" id="control-panel" hidden>
    <h2>SNI 中转控制 <span class="h2s">变更即刻生效并持久化（重启保留）· relay 进程 ≤30 秒同步新名单</span></h2>
    <div id="relay-not-deployed" class="cwarn" hidden></div>
    <div id="relay-no-report" class="cinfo" hidden></div>
    <div class="mode-row">
      <div class="mode-current">当前档位 <b id="relay-mode-text">—</b><span class="badge b-stale" id="relay-mode-source"></span></div>
      <div class="seg" id="mode-seg">
        <button type="button" data-mode="off">off · 直连</button>
        <button type="button" data-mode="auto">auto · 自动</button>
        <button type="button" data-mode="always" class="danger">always · 常开</button>
      </div>
    </div>
    <div id="relay-result" class="cresult" hidden></div>
    <div class="lists">
      <div class="list-edit">
        <h3>中转名单 <code>RELAY_DOMAINS</code></h3>
        <div class="chips" id="domains-chips"></div>
        <div class="addrow"><input id="domain-input" placeholder="*.example.com（精确域名或 *.通配）"><button type="button" id="domain-add">添加</button></div>
        <div class="field-err" id="domain-err"></div>
      </div>
      <div class="list-edit">
        <h3>排除名单 <code>RELAY_EXCLUDE_DOMAINS</code> <span class="muted">排除优先于命中</span></h3>
        <div class="chips" id="excludes-chips"></div>
        <div class="addrow"><input id="exclude-input" placeholder="no-sni.example.com"><button type="button" id="exclude-add">添加</button></div>
        <div class="field-err" id="exclude-err"></div>
      </div>
    </div>
    <div id="domains-diff" class="diff-box" hidden></div>
    <div class="ctl-actions">
      <button type="button" class="btn" id="domains-save" disabled>保存名单</button>
      <button type="button" class="btn secondary" id="relay-reset">恢复 env 默认配置</button>
    </div>
    <div class="sync-line" id="relay-sync">—</div>
  </div>

  <details>
    <summary>高频域名 <span class="cnt" id="top-cnt"></span></summary>
    <div class="dbody"><table><tbody id="top-body"></tbody></table></div>
  </details>
  <details>
    <summary>最近查询 <span class="cnt" id="recent-cnt"></span></summary>
    <div class="dbody"><table><tbody id="recent-body"></tbody></table></div>
  </details>
  <details>
    <summary>优选池 / 规则状态 <span class="cnt" id="pools-cnt"></span></summary>
    <div class="dbody"><table><tbody id="pools-body"></tbody></table></div>
  </details>
  <details id="audit-block" hidden>
    <summary>操作记录 <span class="cnt" id="audit-cnt"></span></summary>
    <div class="dbody"><table><thead><tr><th>时间</th><th>来源</th><th>操作</th><th>内容</th><th>结果</th></tr></thead><tbody id="audit-body"></tbody></table></div>
  </details>

  <footer>数据来自主服务 <code>/admin/stats</code> 与本机主动探测 · 图表 ECharts 本地渲染 · 仅限局域网访问 · <span id="foot-mode"></span></footer>
</div>

<div id="modal"><div class="modal-card">
  <h3 id="modal-title"></h3>
  <div class="mbody" id="modal-body"></div>
  <div class="modal-actions">
    <button type="button" class="btn secondary" id="modal-cancel">取消</button>
    <button type="button" class="btn go" id="modal-go">确认</button>
  </div>
</div></div>

<script src="/vendor/echarts.min.js"></script>
<script>
// 全局错误钩子：任何脚本错误直接显示，不再静默
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
const MODE_TEXT = { off: "off · 直连", auto: "auto · 自动", always: "always · 常开" };

let CONSOLE_STATE = { authRequired: false, control: false, session: null };
let RELAY = null;           // 最新一份 relay 状态（stats.pools.relay）
let EDIT = null;            // 名单编辑草稿 { domains: [], excludes: [] }，null = 未编辑
let OFF_WARN_SHOWN = false; // 切 off 后的持续警示（直到下一次档位变更）

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
  button.textContent = loginCooldownLeft > 0 ? "冷却 " + loginCooldownLeft + "s" : "登录";
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

// ===================== 健康判定：绿=全部正常 黄=降级 红=故障 =====================

function verdictOf(d) {
  if (d.doh.ok === false) return { cls: "bad", text: "服务不可达", why: (d.monitor ? d.monitor.dohUrl : "") + "：" + (d.doh.error || "无响应") };
  const dead = (d.probes || []).filter((p) => p.ok === false);
  if (dead.length) return { cls: "bad", text: "解析异常", why: dead.map((p) => (p.label || p.name) + "：" + (p.error || "失败")).join("；") };
  if (d.statsError) return { cls: "warn", text: "统计不可用", why: "控制通道不可用（仅展示降级数据）：" + d.statsError };
  // 中转档开着但守护进程没上报：名单域名已回退直连（可能变慢/抖动），值得黄牌提醒
  const relay = d.stats && d.stats.pools && d.stats.pools.relay;
  if (relay && relay.mode && relay.mode !== "off" && !relay.healthy) {
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

// ===================== ECharts =====================

const PAL = { hit: "#34d399", miss: "#38bdf8", err: "#f87171", bar: "#818cf8", axis: "#8792ad", split: "#1a2440" };
const LINE_COLORS = ["#38bdf8", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#22d3ee", "#fb923c", "#e879f9"];
const charts = {};
const axisLabel = { color: PAL.axis, fontSize: 10 };
const splitLine = { lineStyle: { color: PAL.split } };

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
  const s = d.stats;
  const bits = ["上游 " + d.monitor.dohUrl, "采样每 " + Math.round(d.monitor.intervalMs / 1000) + "s"];
  if (s) {
    bits.push("服务运行 " + dur(s.uptimeSec));
    if (s.memory) bits.push("内存 " + (s.memory.rssBytes / 1048576).toFixed(0) + " MB");
  }
  document.getElementById("v-sub").textContent = bits.join(" · ");
}

function pathHealth(probes, relay) {
  const el = document.getElementById("path-health");
  if (!probes.length) { el.innerHTML = "未配置探测"; return; }
  // 该探测域名此刻是否被中转接管（always=名单内即接管；auto=该主机状态机已切入）
  const viaRelay = (name) => {
    if (!relay || !relay.mode || relay.mode === "off" || !relay.healthy) return false;
    if (relay.mode === "always") return /github/.test(name);
    return (relay.hosts || []).some((h) => h.relayed && (name === h.host || name.endsWith("." + h.host)));
  };
  el.innerHTML = probes.map((p) => {
    const cls = p.ok === null ? "" : p.ok ? "ok" : "bad";
    const val = p.ok === null ? "—" : p.ok ? fmtMs(p.latencyMs) : (p.error || "失败").slice(0, 26);
    return '<div class="path"><span class="pdot ' + cls + '"></span><span class="pl">' + esc(p.label || p.name) +
      (viaRelay(p.name) ? ' <span class="warn2">中转</span>' : "") +
      '</span><span class="pv' + (p.ok === false ? " err" : "") + '" title="' + esc(p.name + (p.error ? " · " + p.error : "")) + '">' + esc(val) + "</span></div>";
  }).join("");
}

function heroCards(s) {
  const lastMin = s.minutes.length ? s.minutes[s.minutes.length - 1] : null;
  document.getElementById("stat-total").textContent = fmt(s.queries.total);
  document.getElementById("stat-total-s").textContent = "近 1 分钟 " + fmt(lastMin ? lastMin.queries : 0) + " 次";
  document.getElementById("stat-rate").innerHTML = Math.round(s.hitRate * 100) + "<small>%</small>";
  document.getElementById("stat-rate-s").textContent = "失败 " + fmt(s.queries.error) + "（SERVFAIL " + fmt(s.queries.servfail) + "）";
  document.getElementById("stat-p50").textContent = fmtMs(s.freshLatency.p50Ms);
  document.getElementById("stat-lat-s").textContent = "P90 " + fmtMs(s.freshLatency.p90Ms) + " · 共 " + fmt(s.freshLatency.count) + " 次";
}

function minuteChart(minutes) {
  const c = getChart("minute-chart"); if (!c) return;
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 8, top: 24, bottom: 16, containLabel: true },
    legend: { top: 0, left: 0, textStyle: { color: PAL.axis, fontSize: 10 }, itemWidth: 10, itemHeight: 8 },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "category", data: minutes.map((b) => hhmm(b.t)), axisLabel: axisLabel, axisLine: { lineStyle: { color: PAL.split } } },
    yAxis: { type: "value", axisLabel: axisLabel, splitLine: splitLine },
    series: [
      { name: "缓存命中", type: "bar", stack: "q", barMaxWidth: 10, itemStyle: { color: PAL.hit }, data: minutes.map((b) => b.hits) },
      { name: "回源解析", type: "bar", stack: "q", barMaxWidth: 10, itemStyle: { color: PAL.miss }, data: minutes.map((b) => b.misses) },
      { name: "解析失败", type: "bar", stack: "q", barMaxWidth: 10, itemStyle: { color: PAL.err }, data: minutes.map((b) => b.errors) },
    ],
  }, { notMerge: true });
}

function pathsPanel(s) {
  const el = document.getElementById("paths-panel");
  const rows = [];
  const freshTotal = (s.paths || []).reduce((sum, p) => sum + p.count, 0);
  const cached = (s.queries.hit || 0) + (s.queries.prefetch || 0) + (s.queries.stale || 0);
  const total = Math.max(1, s.queries.total || 0);
  const all = (s.paths || []).filter((p) => p.count > 0).map((p) => ({ key: p.path, count: p.count, avgMs: p.avgMs }));
  if (cached > 0) all.push({ key: "cache", count: cached, avgMs: null });
  const max = Math.max(1, ...all.map((r) => r.count));
  if (all.length === 0) { el.innerHTML = '<div class="muted" style="padding:12px 0">暂无回源记录</div>'; return; }
  el.innerHTML = all.map(function (r) {
    const meta = PATH_META[r.key] || [r.key, "#64748b"];
    const share = (r.count / total * 100);
    const note = r.avgMs == null ? "—" : "均 " + fmtMs(r.avgMs);
    return '<div class="prow"><span class="pk">' + esc(meta[0]) + '</span>' +
      '<span class="pbar"><i style="width:' + Math.max(1.5, Math.round(r.count / max * 100)) + "%;background:" + meta[1] + '"></i></span>' +
      '<span class="pn">' + fmt(r.count) + " 次 · " + share.toFixed(1) + "% · " + note + "</span></div>";
  }).join("") +
  '<div class="muted" style="font-size:11.5px;margin-top:6px">回源 ' + fmt(freshTotal) + " 次 · 缓存应答 " + fmt(cached) + " 次 · 分母为总查询 " + fmt(s.queries.total || 0) + "</div>";
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
  const rows = list.slice(0, 8).reverse();
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 74, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "value", axisLabel: axisLabel, splitLine: splitLine },
    yAxis: { type: "category", data: rows.map((s) => s.name), axisLabel: Object.assign({}, axisLabel, { fontSize: 11 }), axisLine: { lineStyle: { color: PAL.split } } },
    series: [{ type: "bar", barMaxWidth: 12, itemStyle: { color: PAL.bar },
      label: { show: true, position: "right", color: PAL.axis, fontSize: 10, formatter: (p) => p.value + " · 均 " + fmtMs(p.data.avgMs) },
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
        '<td class="n">' + fmtMs(u.avgMs) + '</td><td class="n">' + fmtMs(u.maxMs) + '</td><td>' + ago(Date.now() - u.lastUsedAgoSec * 1000) + "</td></tr>";
    }).join("") + "</table>";
}

function probeChart(probes) {
  const c = getChart("probe-chart"); if (!c) return;
  c.setOption({
    animation: false, backgroundColor: "transparent",
    grid: { left: 8, right: 8, top: 26, bottom: 16, containLabel: true },
    legend: { top: 0, left: 0, textStyle: { color: PAL.axis, fontSize: 10 }, itemWidth: 14, itemHeight: 2,
      formatter: (name) => { const p = probes.filter((x) => x.name === name)[0]; return (p && p.label) || name; } },
    tooltip: { trigger: "axis", textStyle: { fontSize: 11 } },
    xAxis: { type: "time", axisLabel: Object.assign({}, axisLabel, { formatter: (v) => hhmm(v), hideOverlap: true }), axisLine: { lineStyle: { color: PAL.split } } },
    yAxis: { type: "value", axisLabel: axisLabel, splitLine: splitLine },
    series: probes.map((p, i) => ({
      name: p.name, type: "line", showSymbol: false, connectNulls: false,
      lineStyle: { width: 1.2, color: LINE_COLORS[i % LINE_COLORS.length] },
      itemStyle: { color: LINE_COLORS[i % LINE_COLORS.length] },
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
  if (p.relay && p.relay.mode && p.relay.mode !== "off") {
    const rh = p.relay.hosts || [];
    const relayed = rh.filter((h) => h.relayed);
    rows.push(["SNI 中转", (p.relay.healthy ? "健康" : '<span class="err">未上报</span>') + " · 档位 " + esc(p.relay.mode) + (p.relay.ip ? " · " + esc(p.relay.ip) : "") + " · " + relayed.length + "/" + rh.length + " 主机走中转 · 上报 " + ago(p.relay.lastReportAt)]);
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
    ? rows.map(([k, v]) => '<tr><td style="white-space:nowrap;color:#aab6d0">' + k + '</td><td class="muted">' + v + "</td></tr>").join("")
    : '<tr><td class="muted">主服务未配置任何池 / 名单</td></tr>';
}

// ===================== 控制台状态与控制区 =====================

function applyConsoleState(d) {
  CONSOLE_STATE = d.console || { authRequired: false, control: false, session: null };
  if (CONSOLE_STATE.authRequired && !CONSOLE_STATE.session) {
    showLogin(d.__sessionExpired ? "会话已过期，请重新登录" : "请输入控制台密码");
    return;
  }
  hideLogin();
  const box = document.getElementById("session-box");
  if (CONSOLE_STATE.session) {
    box.classList.add("show");
    document.getElementById("session-label").textContent = (CONSOLE_STATE.session.label || "已登录") + " · " + (CONSOLE_STATE.session.ip || "");
  } else {
    box.classList.remove("show");
  }
  const control = document.getElementById("control-panel");
  const audit = document.getElementById("audit-block");
  if (CONSOLE_STATE.control) {
    control.hidden = false;
    audit.hidden = false;
    document.getElementById("foot-mode").textContent = "控制台模式";
    renderControl(d.stats && d.stats.pools ? d.stats.pools.relay : null);
    loadAudit();
  } else {
    control.hidden = true;
    audit.hidden = true;
    document.getElementById("foot-mode").textContent = CONSOLE_STATE.authRequired ? "只读模式" : "纯监控模式（未设密码）";
  }
}
document.getElementById("audit-block").addEventListener("toggle", function () { if (this.open) loadAudit(true); });

function renderControl(relay) {
  RELAY = relay;
  if (!relay || !CONSOLE_STATE.control) return;
  document.getElementById("relay-mode-text").textContent = MODE_TEXT[relay.mode] || relay.mode;
  document.getElementById("relay-mode-source").textContent = relay.modeSource === "override" ? "控制台覆盖" : "env 默认";
  const seg = document.getElementById("mode-seg");
  const deployed = Boolean(relay.ip);
  for (const button of seg.querySelectorAll("button")) {
    button.classList.toggle("on", button.dataset.mode === relay.mode);
    if (button.dataset.mode !== "off" && !deployed) button.disabled = true;
  }
  const notDeployed = document.getElementById("relay-not-deployed");
  notDeployed.hidden = deployed;
  if (!deployed) notDeployed.textContent = "未检测到 relay 部署（RELAY_IP 缺失或非私网地址）：档位仍可设为 off，auto/always 会被主服务拒绝。";
  const noReport = document.getElementById("relay-no-report");
  const noReports = !relay.lastReportAt;
  noReport.hidden = !(deployed && noReports);
  if (deployed && noReports) noReport.textContent = "未检测到 relay 进程上报（上次上报：从未）。档位仍可设置，但设置后名单域名会按安全不变量回退直连。";
  // 同步状态行
  const sync = document.getElementById("relay-sync");
  const v = relay.configVersion || 1;
  if (noReports) {
    sync.innerHTML = "configVersion v" + v + " · <span class='warn2'>relay 未上报</span>";
  } else if ((relay.appliedConfigVersion || 0) >= v) {
    sync.innerHTML = "configVersion v" + v + " · 中转已应用 v" + relay.appliedConfigVersion;
  } else {
    sync.innerHTML = "configVersion v" + v + " · <span class='warn2'>同步中（relay 回执 v" + (relay.appliedConfigVersion || 0) + "，≤30 秒）</span>——新增域名在'已同步'前可能被 relay 拒连，请稍候";
  }
  // 名单（未在编辑时回显服务端生效清单）
  if (!EDIT) {
    renderChips("domains-chips", relay.domains || [], false);
    renderChips("excludes-chips", relay.excludes || [], true);
    document.getElementById("domains-save").disabled = true;
    hideDiff();
  }
}

function renderChips(id, list, isExclude) {
  const el = document.getElementById(id);
  el.innerHTML = list.length ? list.map((d, i) =>
    '<span class="chip' + (isExclude ? " ex" : "") + '" title="' + esc(d) + '">' + esc(d) +
    ' <button type="button" data-i="' + i + '" aria-label="删除">×</button></span>').join("")
    : '<span class="muted" style="align-self:center">（空）</span>';
  for (const button of el.querySelectorAll("button")) {
    button.addEventListener("click", function () {
      if (!EDIT) startEdit();
      const arr = isExclude ? EDIT.excludes : EDIT.domains;
      arr.splice(Number(this.dataset.i), 1);
      refreshEdit(isExclude);
    });
  }
}

function validPattern(value) {
  const clean = value.trim().toLowerCase().replace(/\.$/, "");
  if (!clean || clean.length > 253) return null;
  const bare = clean.replace(/^\\*\\./, "").replace(/^\\./, "");
  if (!/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(bare)) return null;
  return clean;
}

function startEdit() {
  if (!RELAY || EDIT) return;
  EDIT = { domains: [...(RELAY.domains || [])], excludes: [...(RELAY.excludes || [])] };
}

function refreshEdit(isExclude) {
  renderChips("domains-chips", EDIT.domains, false);
  renderChips("excludes-chips", EDIT.excludes, true);
  const dirty = RELAY && (JSON.stringify(EDIT.domains) !== JSON.stringify(RELAY.domains || []) || JSON.stringify(EDIT.excludes) !== JSON.stringify(RELAY.excludes || []));
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
  const d2 = diff(RELAY.excludes || [], EDIT.excludes);
  const line = (label, d) => label + "：新增 " + d.added.length + " 条" + (d.added.length ? "（" + d.added.map(esc).join("、") + "）" : "") + " · 删除 " + d.removed.length + " 条" + (d.removed.length ? "（" + d.removed.map(esc).join("、") + "）" : "");
  const hasNew = d1.added.length > 0;
  box.hidden = false;
  box.innerHTML = "<div>" + line("中转名单", d1) + "</div><div>" + line("排除名单", d2) + "</div>" +
    (hasNew ? '<div class="warn2" style="margin-top:6px">新增域名有 ≤30 秒同步窗：relay 进程拿到新名单前，该域名的连接会被拒；无实测池的域名还依赖代理的 DOMAIN-SUFFIX 规则远程解析（curl -x &lt;代理&gt; -sI https://&lt;域名&gt; 验证）。</div>' : "");
}

function hideDiff() {
  const box = document.getElementById("domains-diff");
  box.hidden = true;
  box.innerHTML = "";
}

function wireAdd(inputId, errId, addId, isExclude) {
  const input = document.getElementById(inputId);
  const err = document.getElementById(errId);
  const add = () => {
    err.textContent = "";
    const pattern = validPattern(input.value);
    if (!pattern) { err.textContent = "仅支持 精确域名 或 *.通配 两种写法"; return; }
    startEdit();
    const arr = isExclude ? EDIT.excludes : EDIT.domains;
    if (arr.includes(pattern)) { err.textContent = "已在名单中"; return; }
    if (arr.length >= 64) { err.textContent = "名单上限 64 条"; return; }
    arr.push(pattern);
    input.value = "";
    refreshEdit(isExclude);
  };
  document.getElementById(addId).addEventListener("click", add);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
}
wireAdd("domain-input", "domain-err", "domain-add", false);
wireAdd("exclude-input", "exclude-err", "exclude-add", true);

document.getElementById("domains-save").addEventListener("click", async function () {
  if (!EDIT || !RELAY) return;
  const go = await confirmDialog("保存名单变更", document.getElementById("domains-diff").innerHTML, "确认保存");
  if (!go) return;
  const result = await postRelayConfig({ domains: EDIT.domains, excludeDomains: EDIT.excludes, expectedVersion: RELAY.configVersion }, "relay-domains");
  if (result) { EDIT = null; } // 成功后以下一次 summary 回显为准
});

document.getElementById("relay-reset").addEventListener("click", async function () {
  if (!RELAY) return;
  const envMode = MODE_TEXT.off;
  const go = await confirmDialog("恢复 env 默认配置",
    "<p>将清除控制台的运行时覆盖，回到 env 文件里的值：</p><ul><li>档位：<b>" + esc(MODE_TEXT.off) + "</b>（env RELAY_MODE）</li><li>中转名单：" + ((RELAY.envDomains || []).map(esc).join("、") || "（空）") + "</li><li>排除名单：" + ((RELAY.envExcludes || []).map(esc).join("、") || "（空）") + "</li></ul>",
    "恢复默认");
  if (!go) return;
  EDIT = null;
  await postRelayConfig({ reset: true }, "relay-reset");
});

// 档位切换
document.getElementById("mode-seg").addEventListener("click", async function (e) {
  const button = e.target.closest("button");
  if (!button || button.disabled || !RELAY) return;
  const mode = button.dataset.mode;
  if (mode === RELAY.mode) return;
  if (mode === "always") {
    const domains = (EDIT ? EDIT.domains : RELAY.domains) || [];
    const go = await confirmDialog("切换到 always（常开中转）",
      "<p>将<b>无条件</b>把以下域名的全部流量答成中转 IP，经代理节点出境：</p><ul><li>名单共 <b>" + domains.length + "</b> 条" + (domains.length ? "：" + domains.slice(0, 5).map(esc).join("、") + (domains.length > 5 ? " 等" : "") : "（空）") + "</li><li>这些站点的流量<b>消耗代理节点带宽</b>（大 clone 会显著走节点流量）</li><li>ECH 不适用：名单站点的 HTTPS RR 会被清洗（摘 ECH、hint 指中转、ALPN 压 h2）</li><li>always 不看健康：即使直连质量好也不回切</li></ul><p>确认切换？</p>",
      "确认切换到 always", true);
    if (!go) return;
  }
  await postRelayConfig({ mode, expectedVersion: RELAY.configVersion }, "relay-mode");
});

async function postRelayConfig(body, action) {
  const resultBox = document.getElementById("relay-result");
  const before = RELAY ? { mode: RELAY.mode, domains: [...(RELAY.domains || [])], excludes: [...(RELAY.excludes || [])], version: RELAY.configVersion } : null;
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
    const lines = ["已" + (action === "relay-mode" ? "切换档位 → <b>" + esc(MODE_TEXT[after.mode] || after.mode) + "</b>" : action === "relay-domains" ? "保存名单（中转 " + after.domains.length + " 条 · 排除 " + after.excludes.length + " 条）" : "恢复 env 默认配置") + "（配置 v" + after.configVersion + "）",
      "已持久化：主服务重启后保留",
      "新 DNS 答案即刻生效；存量客户端最迟 60 秒收敛（中转答案 TTL ≤ 60s）",
      "relay 进程 ≤30 秒收到新名单（下次健康上报）；新增域名请等'已同步'再使用"];
    if (after.mode === "off" && before && before.mode !== "off") {
      showResult("warn", lines[0] + "<br>" + lines.slice(1).join("<br>") + "<br>⚠ 名单域名回到直连路径，GitHub 族 SNI 抖动可能复发；relay 进程未停止（无害），彻底停用：systemctl disable --now edge-smart-doh-relay");
      OFF_WARN_SHOWN = true;
    } else {
      showResult("ok", lines.join("<br>"));
      OFF_WARN_SHOWN = false;
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
  if (!block.open && !force) return; // 折叠时不必刷
  try {
    const r = await fetch("/api/audit", { cache: "no-store" });
    if (!r.ok) return;
    const body = await r.json();
    const entries = (body.entries || []).slice(-50).reverse();
    document.getElementById("audit-cnt").textContent = entries.length ? "最近 " + entries.length + " 条" : "";
    document.getElementById("audit-body").innerHTML = entries.length ? entries.map((e) => {
      const label = e.action === "login-ok" ? "登录" : e.action === "login-fail" ? "登录失败" : e.action === "logout" ? "退出"
        : e.action === "relay-mode" ? "切换档位" : e.action === "relay-domains" ? "保存名单" : e.action === "relay-reset" ? "恢复默认" : esc(e.action);
      return "<tr><td class='muted'>" + hhmmss(e.t) + "</td><td>" + esc(e.ip) + (e.label ? '<br><span class="muted">' + esc(e.label) + "</span>" : "") + "</td><td>" + label + (e.count > 1 ? " ×" + e.count : "") + "</td><td class='muted'>" + esc(e.detail || "") + "</td><td>" + (e.result === "ok" ? '<span class="ok2">成功</span>' : '<span class="err">失败</span>') + "</td></tr>";
    }).join("") : '<tr><td class="muted">暂无操作记录</td></tr>';
  } catch {}
}

// ===================== 主刷新循环 =====================

let fetchFails = 0;
let sessionExpired = false;
async function refresh(force) {
  const line = document.getElementById("refresh-line");
  try {
    const r = await fetch("/api/summary", { cache: "no-store" });
    if (r.status === 401) {
      sessionExpired = true;
      applyConsoleState({ console: { authRequired: true, control: false, session: null }, __sessionExpired: sessionExpired });
      if (line) line.textContent = "";
      return;
    }
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    sessionExpired = false;
    fetchFails = 0;
    if (line) line.textContent = "更新于 " + hhmmss(Date.now());
    applyConsoleState(d);
    if (d.stats) {
      heroCards(d.stats); minuteChart(d.stats.minutes); latencyBars(d.stats.freshLatency);
      pathsPanel(d.stats); strategyChart(d.stats.strategies); upstreams(d.stats.upstreams);
      topTable(d.stats.top); recentTable(d.stats.recent); poolsTable(d.stats.pools);
    } else {
      ["stat-total", "stat-rate", "stat-p50"].forEach((id) => { document.getElementById(id).textContent = "—"; });
      document.getElementById("paths-panel").innerHTML = '<div class="muted" style="padding:12px 0">统计不可用</div>';
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
</body>
</html>`;

// ============================== HTTP 服务 ==============================

const HEADERS = {
  "/": { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'", "Referrer-Policy": "no-referrer" },
  "/healthz": { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
};

function htmlResponse(body, headers) {
  return [200, headers, body];
}

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

  // ---- 数据 / 控制端点 ----
  if (path === "/api/summary" && request.method === "GET") {
    const denied = requireSession(request);
    if (denied) return send(denied[0], denied[1], denied[2]);
    return send(200, jsonHeaders, JSON.stringify(summary(request)));
  }

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
    const before = RELAY && { mode: RELAY.mode, domains: [...RELAY.domains], excludes: [...RELAY.excludes] };
    const [status, headers, text] = await relayConfigProxy(body);
    let after;
    try { after = JSON.parse(text); } catch { after = undefined; }
    if (status === 200 && after?.relay) {
      const detail = body.reset ? "reset → env 默认"
        : body.mode !== undefined ? `${before?.mode ?? "?"} → ${after.relay.mode}`
        : `名单 ${after.relay.domains.length} 条 / 排除 ${after.relay.excludes.length} 条`;
      audit(body.reset ? "relay-reset" : body.mode !== undefined ? "relay-mode" : "relay-domains", { ip: session.ip, label: session.label, detail });
      RELAY = after.relay;
    } else if (status !== 200) {
      let errorText = "";
      try { errorText = JSON.parse(text)?.error ?? String(text).slice(0, 120); } catch { errorText = String(text).slice(0, 120); }
      audit(body.reset ? "relay-reset" : body.mode !== undefined ? "relay-mode" : "relay-domains", { ip: session.ip, label: session.label, result: "fail", detail: `HTTP ${status}: ${errorText}` });
    }
    return send(status, headers, text);
  }

  if (path === "/api/audit" && request.method === "GET") {
    const denied = requireSession(request);
    if (denied) return send(denied[0], denied[1], denied[2]);
    return send(200, jsonHeaders, JSON.stringify({ entries: auditLog.slice(-100) }));
  }

  // ---- 静态 / 健康 ----
  if (path === "/" && (request.method === "GET" || request.method === "HEAD")) {
    return send(200, HEADERS["/"], PAGE);
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
