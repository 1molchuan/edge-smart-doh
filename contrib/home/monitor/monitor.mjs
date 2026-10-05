#!/usr/bin/env node
/**
 * edge-smart-doh 局域网监测站（contrib/home/monitor）——单文件、零依赖，Node ≥18。
 *
 * 数据来源：
 *   · GET <DOH_URL>/health       服务可达性与延迟（每次采样）
 *   · GET <DOH_URL>/admin/stats  查询计数/缓存命中/上游延迟/策略分布/池状态（需要 ADMIN_TOKEN）
 *   · GET <DOH_URL>/dns-query    主动解析探测（真实 DoH 客户端行为，答案会进主服务缓存）
 *
 * 安全模型（"只在局域网内部访问"）：
 *   · 默认绑定 0.0.0.0，但每个请求按 TCP 对端地址（socket.remoteAddress，绝不信任
 *     X-Forwarded-For 等可伪造头）过滤：仅回环、RFC1918、CGNAT、ULA、链路本地放行；
 *   · ADMIN_TOKEN 只存在本进程内存里，页面和 /api/summary 携带数据、从不携带凭据；
 *   · 纵深防御：deploy-home.sh 的 nftables 规则（SETUP_FIREWALL=1）在网络层再限一次内网网段。
 *
 * 配置（环境变量，均有默认值）：DOH_URL、ADMIN_TOKEN、MONITOR_HOST、MONITOR_PORT、
 *   MONITOR_INTERVAL_MS（采样间隔，≥5000）、MONITOR_PROBE_NAMES（探测域名，逗号分隔）、
 *   MONITOR_ALLOW（放行来源：默认 "private"；可写网段列表整体替换，如 "192.168.3.0/24,127.0.0.1"）、
 *   MONITOR_PROBE_TIMEOUT_MS（单次上游请求超时）。
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";

// ============================== 配置 ==============================

const DOH_URL = (process.env.DOH_URL ?? "http://127.0.0.1:8787").replace(/\/+$/, "");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "";
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

function summary() {
  return {
    now: Date.now(),
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
<title>Edge Smart DoH 监测</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0a0f1e; color: #dbe2f0; font: 14px/1.5 system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 28px 20px 48px; }

  /* ---- 第一屏：健康判定 + 核心数字 ---- */
  .hero { display: flex; align-items: center; gap: 14px; margin-bottom: 6px; }
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
  .panel h2 { font-size: 13px; margin: 0 0 10px; color: #aab6d0; font-weight: 600; display: flex; align-items: center; gap: 8px; }
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
  .role { color: #8792ad; font-size: 11px; border: 1px solid #2a3550; border-radius: 4px; padding: 0 5px; margin-left: 6px; }

  /* 延迟分布条 */
  .lrow { display: flex; align-items: center; gap: 10px; padding: 5px 0; }
  .lk { width: 34px; color: #8792ad; font-size: 12px; }
  .lbar { flex: 1; height: 8px; border-radius: 4px; background: #16203a; overflow: hidden; }
  .lbar i { display: block; height: 100%; border-radius: 4px; background: linear-gradient(90deg, #38bdf8, #818cf8); }
  .lv { width: 74px; text-align: right; font-variant-numeric: tabular-nums; font-size: 13px; }

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
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <span class="vdot" id="v-dot"></span>
    <span id="v-text">检测中…</span>
    <span id="refresh-line"></span>
  </div>
  <div class="vsub" id="v-sub">正在连接 8788 监测服务…</div>
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

  <div class="row">
    <div class="panel">
      <h2>回源延迟 <span class="h2s" id="lat-n"></span></h2>
      <div id="latency-bars"></div>
    </div>
    <div class="panel">
      <h2>解析策略 <span class="h2s">回源时怎么解的</span></h2>
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

  <footer>数据来自主服务 <code>/admin/stats</code> 与本机主动探测 · 图表 ECharts 本地渲染 · 仅限局域网访问</footer>
</div>
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

// ---------- 健康判定：绿=全部正常 黄=降级 红=故障 ----------
function verdictOf(d) {
  if (d.doh.ok === false) return { cls: "bad", text: "服务不可达", why: (d.monitor ? d.monitor.dohUrl : "") + "：" + (d.doh.error || "无响应") };
  const dead = (d.probes || []).filter((p) => p.ok === false);
  if (dead.length) return { cls: "bad", text: "解析异常", why: dead.map((p) => (p.label || p.name) + "：" + (p.error || "失败")).join("；") };
  if (d.statsError) return { cls: "warn", text: "统计不可用", why: d.statsError };
  const s = d.stats;
  if (s && s.minutes.length) {
    const last = s.minutes[s.minutes.length - 1];
    if (last.queries >= 5 && last.errors / last.queries > 0.2) return { cls: "warn", text: "失败率偏高", why: "最近 1 分钟 " + last.errors + "/" + last.queries + " 次解析失败" };
  }
  if (d.doh.ok === true) return { cls: "ok", text: "运行正常", why: null };
  return { cls: "", text: "检测中…", why: null };
}

// ---------- ECharts ----------
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

function pathHealth(probes) {
  const el = document.getElementById("path-health");
  if (!probes.length) { el.innerHTML = "未配置探测"; return; }
  el.innerHTML = probes.map((p) => {
    const cls = p.ok === null ? "" : p.ok ? "ok" : "bad";
    const val = p.ok === null ? "—" : p.ok ? fmtMs(p.latencyMs) : (p.error || "失败").slice(0, 26);
    return '<div class="path"><span class="pdot ' + cls + '"></span><span class="pl">' + esc(p.label || p.name) +
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
        '<td class="n">' + fmt(u.ok) + '</td><td class="n">' + (u.fail ? '<span class="err">' + fmt(u.fail) + "</span>" : "0") + "</td>" +
        '<td class="n">' + fmtMs(u.avgMs) + '</td><td class="n">' + fmtMs(u.maxMs) + "</td><td>" + ago(Date.now() - u.lastUsedAgoSec * 1000) + "</td></tr>";
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
    return '<tr><td class="muted">' + hhmmss(r.t) + '</td><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.name) + '">' + esc(r.name) + "</td><td>" + esc(r.type) +
      '</td><td><span class="badge ' + pair[0] + '">' + pair[1] + '</span></td><td class="n">' + fmtMs(r.latencyMs) + "</td><td>" + esc(r.upstream == null ? "—" : r.upstream) + "</td></tr>";
  }).join("");
}

function poolsTable(p) {
  const rows = [];
  if (!p) { document.getElementById("pools-body").innerHTML = '<tr><td class="muted">暂无数据</td></tr>'; document.getElementById("pools-cnt").textContent = ""; return; }
  if (p.learned) rows.push(["默认优选池", "IPv4×" + p.learned.ipv4.length + " · IPv6×" + p.learned.ipv6.length + " · 来源 " + (p.learned.sources || []).map((s) => s.source).join(", ") + " · 剩余 " + inMinTxt(p.learned.expiresAt)]);
  const isps = p.isp || [];
  for (const isp of isps) rows.push(["运营商池 " + isp.scope, "IPv4×" + isp.ipv4.length + " · IPv6×" + isp.ipv6.length + (isp.active ? " · 剩余 " + inMinTxt(isp.expiresAt) : ' · <span class="err">已过期</span>')]);
  if (p.github) rows.push(["GitHub 池", Object.keys(p.github.hosts).length + " 主机 · 来源 " + p.github.sources.map((s) => s.source).join(", ") + " · 剩余 " + inMinTxt(Math.max.apply(null, p.github.sources.map((s) => s.expiresAt)))]);
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
      heroCards(d.stats); minuteChart(d.stats.minutes); latencyBars(d.stats.freshLatency);
      strategyChart(d.stats.strategies); upstreams(d.stats.upstreams);
      topTable(d.stats.top); recentTable(d.stats.recent); poolsTable(d.stats.pools);
    } else {
      ["stat-total", "stat-rate", "stat-p50"].forEach((id) => { document.getElementById(id).textContent = "—"; });
    }
    pathHealth(d.probes || []); probeChart(d.probes || []);
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
</html></html>`;

// ============================== HTTP 服务 ==============================

const HEADERS = {
  "/": { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'", "Referrer-Policy": "no-referrer" },
  "/api/summary": { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  "/healthz": { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
};

const server = createServer((request, response) => {
  const remote = request.socket.remoteAddress ?? "";
  if (!sourceAllowed(remote)) {
    logDenied(remote);
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Forbidden: LAN only\n");
    return;
  }
  const path = (request.url ?? "/").split("?")[0];
  const headers = HEADERS[path];
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" });
    response.end();
    return;
  }
  if (path === "/") {
    response.writeHead(200, headers);
    response.end(request.method === "HEAD" ? undefined : PAGE);
  } else if (path === "/api/summary") {
    response.writeHead(200, headers);
    response.end(request.method === "HEAD" ? undefined : JSON.stringify(summary()));
  } else if (path === "/vendor/echarts.min.js") {
    if (echartsJs) {
      response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "public, max-age=86400" });
      response.end(request.method === "HEAD" ? undefined : echartsJs);
    } else {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found\n");
    }
  } else if (path === "/healthz") {
    response.writeHead(200, headers);
    response.end(request.method === "HEAD" ? undefined : JSON.stringify({ ok: true, uptimeSec: Math.floor((Date.now() - state.startedAt) / 1000) }));
  } else {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found\n");
  }
});

server.listen(PORT, HOST, () => {
  console.log(JSON.stringify({ event: "monitor_listening", host: HOST, port: PORT, dohUrl: DOH_URL, allow: ALLOW_SPEC.join(","), probes: PROBE_NAMES }));
  void poll();
  setInterval(poll, INTERVAL_MS);
});

function shutdown(signal) {
  console.log(JSON.stringify({ event: "monitor_shutdown", signal }));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
