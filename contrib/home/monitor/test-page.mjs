#!/usr/bin/env node
/**
 * monitor.mjs 页面脚本桩测试：不真开浏览器，用最小 DOM/fetch 桩执行页面内嵌 JS，
 * 喂一份 /api/summary，断言关键面板真的被渲染（健康判定、路径分布、最近查询路径徽章、页脚模式）。
 *
 * 背景：页面是手写原生 JS，"函数定义了但 refresh() 里忘了调用"这类接线错误语法检查抓不住
 * （setVerdict 曾这样丢过，首屏永远停在"检测中…"）。改 monitor.mjs 的页面部分后跑一次：
 *   node contrib/home/monitor/test-page.mjs
 */
import { readFileSync } from "node:fs";

const sourcePath = new URL("./monitor.mjs", import.meta.url).pathname;
const source = readFileSync(sourcePath, "utf8");
const page = /^const PAGE = `([\s\S]*?)`;/m.exec(source)?.[1];
if (!page) {
  console.error("FAIL: 未能在 monitor.mjs 里找到 PAGE 模板");
  process.exit(1);
}
const scripts = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const js = scripts.join("\n;\n");
if (js.length < 10000) {
  console.error(`FAIL: 提取到的页面脚本过小（${js.length} B），提取逻辑可能失效`);
  process.exit(1);
}

// ---- DOM 桩：按 id 惰性建元素，记录 textContent / innerHTML ----
const elements = new Map();
function makeEl(id) {
  return {
    id, textContent: "", innerHTML: "", value: "", hidden: false, disabled: false, open: false,
    className: "", dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, appendChild() {},
    querySelectorAll() { return []; }, querySelector() { return null; },
    setAttribute() {}, getAttribute() { return null; },
  };
}
const documentStub = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, makeEl(id)); return elements.get(id); },
  addEventListener() {},
  body: { classList: { add() {}, remove() {} } },
};
const windowStub = { addEventListener() {} };

const now = Date.now();
const summary = {
  now,
  console: { authRequired: false, control: false, session: null },
  monitor: { startedAt: now, intervalMs: 10000, dohUrl: "http://127.0.0.1:8787", allow: "private", cycles: 3 },
  doh: { ok: true, latencyMs: 2, error: null, lastCheck: now },
  stats: {
    ok: true, startedAt: new Date(now - 3600_000).toISOString(), uptimeSec: 3600,
    queries: { hit: 600, prefetch: 10, stale: 5, miss: 400, blocked: 0, error: 3, total: 1018, servfail: 1 },
    hitRate: 0.59,
    freshLatency: { count: 400, avgMs: 60, p50Ms: 76, p90Ms: 180, p99Ms: 400, maxMs: 900 },
    minutes: Array.from({ length: 120 }, (_, i) => ({ t: now - (119 - i) * 60_000, queries: 8, hits: 5, misses: 3, errors: 0 })),
    paths: [
      { path: "cn", count: 180, avgMs: 30 }, { path: "ech", count: 90, avgMs: 120 },
      { path: "pool", count: 80, avgMs: 100 }, { path: "direct", count: 47, avgMs: 200 },
      { path: "relay", count: 3, avgMs: 60 },
    ],
    upstreams: [{ role: "cn", name: "dns.alidns.com", ok: 100, fail: 0, avgMs: 20, maxMs: 90, lastMs: 18, lastUsedAgoSec: 5 }],
    strategies: [{ name: "github-pool", count: 40, avgMs: 90 }],
    top: [{ name: "github.com", count: 30 }],
    recent: [{ t: now, name: "github.com", type: "A", outcome: "miss", latencyMs: 60, upstream: "dns.google", strategy: "relay", path: "relay" }],
    pools: {
      relay: {
        mode: "auto", modeSource: "env", overridden: [], ip: "192.168.3.250",
        domains: ["*.github.com"], excludes: ["ssh.github.com"], envDomains: ["*.github.com"], envExcludes: ["ssh.github.com"],
        healthy: true, livenessUntil: now + 60000, lastSource: "relay@192.168.3.250", lastReportAt: now - 5000,
        version: 3, configVersion: 2, appliedConfigVersion: 2,
        hosts: [{ host: "github.com", relayed: true, samples: 10, enterRate: 0.2, exitRate: null, lastSampleAt: now - 3000 }],
      },
    },
  },
  statsError: null, statsAt: now,
  probes: [
    { name: "www.taobao.com", label: "国内直连", ok: true, latencyMs: 3, rcode: 0, error: null, lastCheck: now, history: [{ t: now, ms: 3, ok: true }] },
    { name: "github.com", label: "GitHub 池", ok: true, latencyMs: 2, rcode: 0, error: null, lastCheck: now, history: [{ t: now, ms: 2, ok: true }] },
    { name: "www.google.com", label: "境外 / 代理", ok: true, latencyMs: 4, rcode: 0, error: null, lastCheck: now, history: [{ t: now, ms: 4, ok: true }] },
  ],
};

const fetchStub = async (url) => {
  if (String(url).includes("/api/summary")) return { ok: true, status: 200, json: async () => summary };
  return { ok: true, status: 204, json: async () => ({}) };
};

process.on("unhandledRejection", (error) => {
  console.error("FAIL: 页面脚本未捕获的异步异常\n", error?.stack ?? error);
  process.exit(1);
});
new Function("document", "window", "fetch", "setInterval", "setTimeout", js)(
  documentStub, windowStub, fetchStub, () => 0, () => 0,
);
await new Promise((resolve) => setTimeout(resolve, 50)); // 等 refresh() 的微任务链跑完

const text = (id) => elements.get(id)?.textContent ?? "<missing>";
const html = (id) => elements.get(id)?.innerHTML ?? "";
const failures = [];
const expect = (label, actual, includes) => {
  if (!String(actual).includes(includes)) failures.push(`${label}: 期望含 "${includes}"，实际 "${String(actual).slice(0, 80)}"`);
};
expect("健康判定 #v-text", text("v-text"), "运行正常");
if (text("v-sub").includes("正在连接")) failures.push(`#v-sub 仍是初始文案: ${text("v-sub")}`);
expect("#v-sub 含上游地址", text("v-sub"), "127.0.0.1:8787");
expect("总查询卡", text("stat-total"), "1,018");
expect("路径面板含 SNI 中转", html("paths-panel"), "SNI 中转");
expect("路径面板含 ECH 注入", html("paths-panel"), "ECH 注入");
expect("最近查询路径徽章", html("recent-body"), "badge");
expect("池状态含中转档位", html("pools-body"), "档位 auto");
expect("池状态含走中转主机", html("pools-body"), "走中转");
expect("页脚模式", text("foot-mode"), "纯监控");
if (failures.length) {
  console.error("FAIL\n" + failures.join("\n"));
  process.exit(1);
}
console.log("PASS: 健康判定/核心数字/路径分布/最近查询/池状态/页脚全部渲染，refresh 全程无异常");
