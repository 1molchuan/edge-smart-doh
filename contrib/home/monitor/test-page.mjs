#!/usr/bin/env node
/**
 * monitor.mjs 页面桩测试（v3：双页面架构）。
 *
 * 拉起真实控制台进程（上游指向一个不存在的地址——页面结构不依赖数据），取回两个页面：
 *   · /        监控页（公开）
 *   · /console 控制页（要密码）
 * 在 DOM 桩里执行各自的页面脚本，用 fixture 驱动状态，断言关键面板真的渲染。
 * 同时顺带验证服务端鉴权边界：/api/summary 公开 200、/api/relay 未登录 401。
 *
 * 背景：手写原生 JS 的"接线错误/转义陷阱"语法检查抓不住（setVerdict 丢失、validPattern
 * 的 \. 被模板字面量吃掉、强制池 UI 的 /^*\./ 崩溃都发生过）。改 monitor.mjs 页面后必跑：
 *   node contrib/home/monitor/test-page.mjs
 */
import { spawn } from "node:child_process";

const PORT = 18793;
const BASE = `http://127.0.0.1:${PORT}`;

// ---- 拉起真实控制台进程（上游不可达即可，结构完整） ----
const monitorPath = new URL("./monitor.mjs", import.meta.url).pathname;
const child = spawn(process.execPath, [monitorPath], {
  env: { ...process.env, MONITOR_PORT: String(PORT), MONITOR_HOST: "127.0.0.1", DOH_URL: "http://127.0.0.1:1", CONSOLE_PASSWORD: "pw", ADMIN_TOKEN: "tok" },
  stdio: ["ignore", "ignore", "ignore"],
});
const failures = [];
const check = (label, cond, extra) => { if (!cond) failures.push(label + (extra ? "：" + extra : "")); };

try {
  let up = false;
  for (let i = 0; i < 30 && !up; i++) {
    await new Promise((r) => setTimeout(r, 200));
    up = await fetch(`${BASE}/healthz`).then((r) => r.ok).catch(() => false);
  }
  if (!up) throw new Error("控制台进程 6 秒内未就绪");

  // ---- 服务端鉴权边界 ----
  const summaryRes = await fetch(`${BASE}/api/summary`);
  check("/api/summary 公开（200）", summaryRes.status === 200, `HTTP ${summaryRes.status}`);
  const relayRes = await fetch(`${BASE}/api/relay`);
  check("/api/relay 未登录 401", relayRes.status === 401, `HTTP ${relayRes.status}`);
  const health = await (await fetch(`${BASE}/healthz`)).json();
  check("healthz 报告 authRequired/control", health.authRequired === true && health.control === true);
  const consoleRes = await fetch(`${BASE}/console`);
  check("/console 200", consoleRes.status === 200, `HTTP ${consoleRes.status}`);

  // ---- DOM 桩 ----
  const makeStub = () => {
    const elements = new Map();
    const makeEl = (id) => ({
      id, textContent: "", innerHTML: "", value: "", hidden: false, disabled: false, open: false,
      className: "", dataset: {},
      style: { setProperty() {} },
      classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
      addEventListener() {}, appendChild() {},
      querySelectorAll() { return []; }, querySelector() { return null; },
      setAttribute() {}, getAttribute() { return null; },
    });
    return {
      elements,
      document: {
        getElementById(id) { if (!elements.has(id)) elements.set(id, makeEl(id)); return elements.get(id); },
        addEventListener() {},
        documentElement: { getAttribute: () => "dark", setAttribute() {} },
        body: { classList: { add() {}, remove() {} } },
      },
      window: { addEventListener() {} },
      text: (id) => elements.get(id)?.textContent ?? "<missing>",
      html: (id) => elements.get(id)?.innerHTML ?? "",
    };
  };

  const runPage = async (pageHtml, fetchStub) => {
    const scripts = [...pageHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]).filter((s) => s.length > 200);
    const js = scripts.join("\n;\n");
    const stub = makeStub();
    stub.document.getElementById("audit-block").open = true; // 真实 DOM 里该 details 自带 open
    process.on("unhandledRejection", (error) => {
      failures.push("页面脚本未捕获的异步异常：" + (error?.message ?? error));
    });
    new Function("document", "window", "fetch", "setInterval", "setTimeout", "localStorage", "matchMedia", js)(
      stub.document, stub.window, fetchStub, () => 0, () => 0,
      { getItem: () => null, setItem() {} },
      () => false,
    );
    await new Promise((r) => setTimeout(r, 80));
    return stub;
  };

  const now = Date.now();
  const minutes = Array.from({ length: 120 }, (_, i) => ({ t: now - (119 - i) * 60_000, queries: 10, hits: 6, misses: 4, errors: 0 }));
  const hist = (base) => Array.from({ length: 60 }, (_, i) => ({ t: now - (59 - i) * 10_000, ms: base, ok: true }));
  const statsFixture = {
    ok: true, startedAt: new Date(now - 3600_000).toISOString(), uptimeSec: 3600, memory: { rssBytes: 118 * 1048576 },
    queries: { hit: 600, prefetch: 10, stale: 5, miss: 400, blocked: 0, error: 3, total: 1018, servfail: 1 },
    hitRate: 0.6, freshLatency: { count: 400, avgMs: 60, p50Ms: 76, p90Ms: 180, p99Ms: 400, maxMs: 900 },
    minutes,
    paths: [ { path: "cn", count: 180, avgMs: 30 }, { path: "ech", count: 90, avgMs: 120 }, { path: "relay", count: 3, avgMs: 60 } ],
    upstreams: [], strategies: [], top: [ { name: "github.com", count: 30 } ],
    recent: [ { t: now, name: "github.com", type: "A", outcome: "miss", latencyMs: 60, upstream: "dns.google", strategy: "relay", path: "relay" } ],
    pools: { relay: {
      mode: "auto", modeSource: "env", overridden: [], ip: "192.168.3.250", envMode: "auto",
      domains: ["*.github.com"], excludes: ["ssh.github.com"], envDomains: ["*.github.com"], envExcludes: ["ssh.github.com"],
      forcedMode: "always", forcedModeSource: "env", forcedDomains: ["*.google.com"], envForcedDomains: ["*.google.com"],
      healthy: true, livenessUntil: now + 60000, lastSource: "relay@x", lastReportAt: now - 5000,
      version: 3, configVersion: 2, appliedConfigVersion: 2,
      hosts: [ { host: "github.com", relayed: false, samples: 10, enterRate: 0.9, exitRate: 0.95, lastSampleAt: now - 3000 } ],
    } },
  };
  const probesFixture = [
    { name: "www.taobao.com", label: "国内直连", ok: true, latencyMs: 3, rcode: 0, error: null, lastCheck: now, history: hist(3) },
    { name: "github.com", label: "GitHub 池", ok: true, latencyMs: 2, rcode: 0, error: null, lastCheck: now, history: hist(2) },
  ];
  const baseSummary = (consoleInfo) => ({
    now, console: consoleInfo,
    monitor: { startedAt: now - 3600_000, intervalMs: 10000, dohUrl: "http://127.0.0.1:8787", allow: "private", cycles: 7 },
    doh: { ok: true, latencyMs: 2, error: null, lastCheck: now },
    stats: statsFixture, statsError: null, statsAt: now, probes: probesFixture,
  });
  const summaryFetch = (consoleInfo) => async (url) => {
    if (String(url).includes("/api/summary")) return { ok: true, status: 200, json: async () => baseSummary(consoleInfo) };
    if (String(url).includes("/api/audit")) return { ok: true, status: 200, json: async () => ({ entries: [ { t: now, action: "relay-mode", ip: "127.0.0.1", label: "ops-agent", result: "ok", detail: "off → auto" } ] }) };
    return { ok: true, status: 204, json: async () => ({}) };
  };

  // ---- 监控页（公开，无登录概念） ----
  const monitorHtml = await (await fetch(`${BASE}/`)).text();
  check("监控页含导航链接", monitorHtml.includes('href="/console"') && monitorHtml.includes('href="/"'));
  check("监控页不含控制甲板", !monitorHtml.includes('id="mode-seg"'));
  const m = await runPage(monitorHtml, summaryFetch({ authRequired: true, control: true, session: null }));
  check("监控页健康判定", m.text("v-text").includes("运行正常"), m.text("v-text"));
  check("监控页活动条", m.text("status-activity-cap").includes("近 1 小时"));
  check("监控页总查询卡", m.text("stat-total").includes("1,018"));
  check("监控页路径分布", m.html("paths-panel").includes("SNI 中转"));
  check("监控页最近查询徽章", m.html("recent-body").includes("badge"));
  check("监控页池状态含强制池", m.html("pools-body").includes("强制池"));
  check("监控页链路火花线", m.html("path-health").includes("svg"));

  // ---- 控制页：已登录 ----
  const consoleHtml = await (await fetch(`${BASE}/console`)).text();
  check("控制页含双池卡", consoleHtml.includes('id="mode-seg"') && consoleHtml.includes('id="forced-mode-seg"') && consoleHtml.includes("强制池"));
  const c = await runPage(consoleHtml, summaryFetch({ authRequired: true, control: true, session: { valid: true, label: "ops-agent", ip: "127.0.0.1" } }));
  check("控制页状态条判定", c.text("v-text").includes("运行正常"));
  check("控制页主池档位", c.text("relay-mode-text").includes("auto"), c.text("relay-mode-text"));
  check("控制页强制池档位", c.text("forced-mode-text").includes("always"), c.text("forced-mode-text"));
  check("控制页主池名单 chips", c.html("domains-chips").includes("*.github.com"));
  check("控制页强制名单 chips", c.html("forced-chips").includes("*.google.com"));
  check("控制页同步状态", c.html("relay-sync").includes("已应用 v2"), c.html("relay-sync"));
  check("控制页会话徽标", c.text("session-label").includes("ops-agent"));
  check("控制页审计渲染", c.html("audit-body").includes("主池档位") || c.html("audit-body").includes("暂无操作记录"));
  check("控制页页脚模式", c.text("foot-mode").includes("控制台模式"));

  // ---- 校验/黏贴回归：渲染语义下的 validPattern 与 parsePatternInput（模板字面量转义陷阱曾让 *.gstatic.com 被拒） ----
  const renderedFn = (name) => {
    const m = consoleHtml.match(new RegExp("function " + name + "[\\s\\S]*?^}", "m"));
    if (!m) return null;
    return new Function(m[0] + ";\nreturn " + name + ";")(); // 已渲染页面即最终形态，不再过模板
  };
  const vp = renderedFn("validPattern");
  const pp = renderedFn("parsePatternInput");
  check("控制页校验函数存在", Boolean(vp) && Boolean(pp));
  if (vp) {
    check("validPattern 接受 *.gstatic.com", vp("*.gstatic.com") === "*.gstatic.com");
    check("validPattern 接受精确域名", vp("example.com") === "example.com");
    check("validPattern 拒绝 a..b", vp("a..b") === null);
    check("validPattern 与服务端一致接受单标签", vp("*.x") === "*.x");
  }
  if (pp) {
    check("parsePatternInput 逗号分隔", JSON.stringify(pp("*.a.com, *.b.com")) === JSON.stringify(["*.a.com", "*.b.com"]));
    check("parsePatternInput 中文逗号/分号/换行/空格", pp("*.a.com，*.b.com；*.c.com\n*.d.com *.e.com").length === 5);
    check("parsePatternInput 空输入", pp("   ").length === 0);
  }

  // ---- 控制页：未登录（应显示登录卡，不渲染甲板数据） ----
  const cOut = await runPage(consoleHtml, summaryFetch({ authRequired: true, control: true, session: null }));
  check("控制页未登录显示登录卡", cOut.text("login-sub").includes("请输入控制台密码"));
  check("控制页未登录不渲染名单", cOut.html("domains-chips") === "");

  // ---- 控制页：控制未启用（未设密码或缺 ADMIN_TOKEN） ----
  const cOff = await runPage(consoleHtml, summaryFetch({ authRequired: false, control: false, session: null }));
  check("控制页未启用显示指引", cOff.text("console-disabled").includes("控制功能未启用"), cOff.text("console-disabled").slice(0, 60));
} catch (error) {
  failures.push("测试框架异常：" + (error?.stack ?? error));
} finally {
  child.kill();
}

if (failures.length) {
  console.error("FAIL\n" + failures.join("\n"));
  process.exit(1);
}
console.log("PASS: 监控页/控制页双页面渲染、鉴权边界（summary 公开、relay 401）、双池甲板、登录/未启用三态全部正确");
