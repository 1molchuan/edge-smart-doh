# 上游信任修复记录（2026-10-03）

> 起因：配好代理后，`linux.do` 等被污染域名仍返回假 IP（如 `199.96.59.61`、`31.13.85.34`）。
> 结论：**不是缓存 bug**，是 `UPSTREAMS=cloudflare,google,alidns` 里混入了信任级别不同的上游。

---

## 一、根因（实测数据）

`src/upstream.ts` 的 hedge 竞速是「先到者胜」，而两个上游的延迟差了 10 倍：

| 上游 | 路径 | 实测耗时 | 返回 |
|---|---|---|---|
| cloudflare-dns.com | 经 7890 代理 | 679 / 1666 ms | `172.66.166.61`、`104.20.16.234` ✅ 干净 |
| dns.google | 经 7890 代理 | 649 / 475 ms | 干净 ✅ |
| **dns.alidns.com** | 直连（在 `NO_PROXY` 里） | **38 / 60 ms** | `199.96.59.61` ❌ 污染 |

生效配置 `UPSTREAM_HEDGE_MS=50`，所以时间线是：

```
t=0     启动 cloudflare（经代理，还在隧道里）
t=50    启动 google
t=100   启动 alidns（直连）
t=138   alidns 带污染答案返回 → 获胜，cloudflare/google 被 abort
```

污染还会被写进答案缓存，以及 `src/rewrite.ts` 里 ECH / Cloudflare 判定用的派生缓存（300s / 3600s），所以代理修好后仍持续生效。

**决策（2026-10-03）**：客户端是强制 DoH 的浏览器（SERVFAIL 不会回退明文 DNS），因此**主路径永不降级** —— 慢而可信 > 快而不可信。

---

## 二、需要 sudo 执行的改动（已完成）

```bash
# 1) 备份 env，并把 UPSTREAMS 里的 alidns 删掉
sudo cp /etc/edge-smart-doh/env /etc/edge-smart-doh/env.bak-$(date +%F) && \
sudo sed -i 's|^UPSTREAMS=.*|UPSTREAMS=https://cloudflare-dns.com/dns-query,https://dns.google/dns-query|' /etc/edge-smart-doh/env

# 2) 装新构建
sudo install -m 0644 ~/Projects/edge-smart-doh/dist/node.mjs /opt/edge-smart-doh/node.mjs

# 3) 停 → 清污染缓存 → 起
sudo systemctl stop edge-smart-doh && \
sudo mv /var/lib/edge-smart-doh/cache.bin /var/lib/edge-smart-doh/cache.bin.polluted-$(date +%F) && \
sudo systemctl start edge-smart-doh
```

### 验证命令

```bash
# a) 不应有混合信任告警（出现说明 sed 没生效）
journalctl -u edge-smart-doh -n 30 --no-pager | grep -i upstream_trust_warning || echo "OK：无告警"

# b) 确认 ECS 路径的前提（若为空，国内域名会经代理拿境外视角）
sudo grep -E '^(UPSTREAMS|ECS_UPSTREAMS|ECS_MODE)=' /etc/edge-smart-doh/env

# c) 上游应为 cloudflare/google，答案是干净 IP
curl -s "http://127.0.0.1:8787/explain?name=linux.do&type=A" | jq -c '{steps:.results[0].steps,answer:.results[0].answer}'
```

### 已实测结果（2026-10-03 21:14 之后）

- `systemctl is-active edge-smart-doh` → `active`
- `/opt/edge-smart-doh/node.mjs` 67236 字节，与 `~/Projects/edge-smart-doh/dist/node.mjs` 一致
- `linux.do`：上游 = **cloudflare-dns.com**，答案 = `172.66.166.61`、`104.20.16.234`（干净；旧值 `199.96.59.61` 已消失），最终交付为优选池 10 个 IP
- `x.com`：上游 = cloudflare-dns.com，答案 `172.66.0.227`，并被 pin 到优选池

---

## 三、配套的代码改动（无需 sudo，已完成）

### 1. `src/upstream.ts`

- `queryOne` 增加应答校验，以下情况**一律算该上游失败**（交给 hedge 阶梯的下一个可信上游，而不是赢下竞速并 `finish()` 掉并发中的上游）：
  - `rcode` 非 0（NOERROR）或 3（NXDOMAIN）—— 覆盖 SERVFAIL/REFUSED/NOTIMP
  - EDNS 扩展 rcode 非 0（OPT 记录 TTL 高 8 位）—— 覆盖 BADVERS/BADCOOKIE
  - `TC=1`（截断）—— 半截 A/AAAA 不得进 ECH/CF 判定用的派生缓存
  - 注意：NXDOMAIN / NODATA 仍是合法答案，否定缓存语义未变；SERVFAIL 本来就不进答案缓存
- `catch` 里的错误描述改为优先用 `signal.reason`，超时显示 `upstream timeout` 而不是 `This operation was aborted`
- 新增 `upstreamLabel()`：修掉一个能**挂死请求**的旧 bug —— `UPSTREAMS=https://` 这类值能过 `startsWith("https://")` 过滤，却让 catch 里的 `new URL()` 抛错，导致 Promise 永不 settle + unhandled rejection

### 2. `server/node.ts`

- 新增 `noProxyMatcher()` + `warnOnMixedUpstreamTrust()`：启动时若 `UPSTREAMS` 与 `NO_PROXY` 名单有交集，打印 `upstream_trust_warning`（附 hint）。匹配规则照 undici 的 `env-http-proxy-agent.js`（`*` 全直连、可带 `:port` 后缀、`.`/`*.` 为后缀匹配、小写变量优先），因为真正决定可达性的是 undici
- `env` 的断言类型改为 `Parameters<typeof handleRequest>[1]`，去掉对全局 `Env` 名字的隐式依赖；两处 `as unknown as` 补 `SAFETY` 注释

### 3. `deploy/deploy-home.sh`（入库的一键部署脚本）

- cn+代理分支：`UPSTREAMS_CFG` 去掉 `https://dns.alidns.com/dns-query`（**否则重跑脚本会把它写回去**）
- 无代理分支：补注释与 warn 文案，标明"违反信任清单约定，被污染域名必然拿假 IP，仅作过渡"
- `undici` 钉成 `undici@6`：undici 8 依赖 Node ≥22.19（`webidl.util.markAsUncloneable`），在 Node 20 上
  `--import` 阶段即抛 TypeError，装 latest 会让服务**一启动就崩**（2026-10-03 实际踩过，重启计数器 111 次后放弃）。
  另在重启服务前用系统 node 试加载一次 `proxy-preload.mjs`（版本自检），不兼容在这里拦截，
  而不是让服务陷进 systemd restart 循环
- 站点相关值（域名/代理/单元名/邮箱）不硬编码：留空则交互询问，首次答案持久化到
  `/etc/edge-smart-doh/deploy.conf`（root 0600，不进仓库）；内网 IP/网段/构建用户/仓库路径自动探测

### 4. `test/rewrite-upstream.test.ts` / `README.md`

- 新增 `describe("upstream answer validation")` 8 个用例：SERVFAIL 触发下一个上游、NXDOMAIN 不触发、TC 触发、EDNS 扩展 rcode 触发、NODATA 不触发、非法 URL 条目不挂死、全部失败时报 rcode、超时显示 `upstream timeout`
- README 第 5 步补「合法应答」的精确定义

### 验证

```
npx vitest run      → 114 passed (7 files)
npm run typecheck   → 4 个 tsc project + wrangler types --check 全绿
npm run build:node  → dist/node.mjs
```

改动前的副本在 `backups/`（`.bak` 后缀）。`README.md` 是 git tracked，可用 `git diff` 还原。

---

## 四、回滚

```bash
# 环境变量
sudo cp /etc/edge-smart-doh/env.bak-YYYY-MM-DD /etc/edge-smart-doh/env && sudo systemctl restart edge-smart-doh

# 代码（README.md 走 git）
cd ~/Projects/edge-smart-doh && git checkout -- src/upstream.ts server/node.ts test/rewrite-upstream.test.ts deploy/deploy-home.sh README.md
```

---

## 五、仍未处理（待决定）

1. **cn 无代理模式**：`deploy-doh.sh` 在 `DEPLOY_ENV=cn` 且留空 `PROXY_ADDR` 时，`UPSTREAMS` 必然包含直连国内递归（无代理时 cloudflare 被墙），与「永不降级」原则冲突。当前只在文档/脚本里标注为"仅过渡"，未删分支。
2. **「全都截断」的兜底**：TC=1 一律算失败，所有上游都截断时客户端拿到 SERVFAIL（而不是可自行重试的 TC 应答）。已按"有意为之"处理并注释，未做兜底。
3. **Worker 目标未重新部署**：本次只更新了 Node 版（`/opt/edge-smart-doh`）。若线上还有 Cloudflare Worker / EdgeOne / ESA 形态，需要各自 `wrangler deploy` 等才带上这批修复。

---

## 六、后续简化（2026-10-03 晚）：所有 DNS 查询全部出境，去掉国内解析器

「信任清单」修复后 UPSTREAMS 已全部经代理，但 ECS 路径（ECS_DOMAINS 命中的国内域名）仍配着
`1.12.12.12` / `dns.alidns.com` 直连。进一步的认识：这套 DoH 的目的就是解析可能被污染的域名，
国内视角不应该再依赖国内解析器——**dns.google 转发 ECS**，经代理查询照样带上客户端子网：

实测（ECS = 客户端 /24，dns.google 经本地代理出境）：

| 查询 | alidns 直连（原路径） | dns.google 经代理 + ECS |
|---|---|---|
| www.taobao.com | 123.235.x / 27.221.x / 119.167.x … | **同一批节点** |
| www.baidu.com | 110.242.x（联通） | 45.113.192.x（国内电信段；对照组：无 ECS 时给香港 103.235.46.x） |
| cdn.jsdelivr.net | 104.17.207/208.5 | 相同 |

改动（cn+代理模式）：

- `ECS_UPSTREAMS` 只留 `https://dns.google/dns-query`——cloudflare 不转发 ECS，不能进 ECS 列表；
- `NO_PROXY` 收敛为 `localhost,127.0.0.1,::1,www.cloudflare.com`（后者是 CF 网段表拉取，非 DNS 解析）。

代价与取舍：Google 的 ECS 地理映射比国内递归粗（按运营商选节点不如 alidns 精细），换取的是
**零国内解析器**——污染面不再存在，只剩一种出境路径；mihomo 故障时 ECS 路径同样干净失败
（stale 缓存按 RFC 8767 兜底），不再有"代理挂了国内还能解析"的部分可用性。
