# SNI 中转（relay）完整实施方案

> 状态：设计定稿，待实施。本文是实施蓝本：文件级改动清单、里程碑、验收标准、测试与回滚。
> 讨论结论沉淀：三档 `RELAY_MODE`（常开/按质量门控/关闭，只作用于名单内域名，不是全网流量）；
> 域名无关命名（`RELAY_*`，站点分组留作配置层后续升级）；通配 + 排除名单；ECH 站点不进名单。

## 0. 问题与定位

GitHub 族域名直连在联通线路上有分钟级 SNI 抖动（echprobe 实测一次 0/9、几分钟后全通）。
现有系统全部杠杆在控制面（测量 → 选答案），路径本身抖动无解。本方案补一个数据面杠杆：
DNS 把名单内域名答成中转机 IP，中转按 SNI 把 TCP 流经 mihomo 转给真实目标。

**设计不变量（高于一切功能）：任何新组件故障，系统退化为今天的系统。** relay 挂 / mihomo 挂 /
节点挂，最坏结果是回到"今天的抖动直连"，且在 TTL 上界（60s）内收敛。

**只适用于 home/Node 部署**（数据面在本机）。worker（公开实例）上设置 `RELAY_*` 没有数据面，
禁止；不设即零影响。

## 1. 架构总览

```
局域网客户端
  │ ① DNS：github.com → 192.168.x.250（TTL≤60，HTTPS RR 已清洗）
  ▼
edge-smart-doh :8787 ── relay 策略（src/strategies.ts，order 45）
  │                    └─ src/relay.ts：档位 + per-host 健康滑窗 + 滞回 + cacheTag 版本
  │ ② 连 192.168.x.250:443（网卡第二 IP，relay 只绑它）
  ▼
relay.mjs（contrib/home/relay/，root systemd，独立 env）
  │ ③ peek ClientHello → SNI；名单匹配（通配 + 排除）
  │ ④ GET 127.0.0.1:8787/admin/pool?name=<sni> 拿实测池 IP（无池则按域名）
  │ ⑤ HTTP CONNECT 经 mihomo 127.0.0.1:7890 → 池 IP:443（或节点远程解析）
  │ ⑥ 双向 pipe，TLS 端到端（relay 绝不终结 TLS）
  ▼
真实 GitHub（池 IP 经 mihomo GeoIP 走节点 / 或按 DOMAIN 规则远程解析）

控制回路（auto 档）：
relay 内置 prober（180s 周期）─ 直连池 IP 握手 + 经自身链路握手 ─→ POST /admin/relay-health
  → src/relay.ts 滑窗 + 滞回 → 档位/健康翻转 bump 版本 → cacheTag 变化 → 新答案即刻生效
监测站 :8788 ← GET /admin/relay（档位、健康、当前覆写主机数、两端时延）
```

防回环（本设计最危险的坑）：relay 拨号目标一律是**池 IP**（`/admin/pool` 给出，不经 DNS）；
仅当无池才按域名 CONNECT，此时依赖 mihomo 的 `DOMAIN-SUFFIX` 规则走节点远程解析（部署前置，
见 §6.3）。任何让 mihomo 解析路径拿到覆写答案的捷径都会自连死循环。

## 2. 配置面

### 2.1 环境变量（主服务 env，/etc/edge-smart-doh/env）

```bash
RELAY_MODE=off            # off | auto | always；未设置 = off
RELAY_IP=192.168.x.250    # 网卡第二内网 IP；mode≠off 时必填
RELAY_DOMAINS=*.github.com,*.githubusercontent.com,*.githubassets.com,*.github.io
RELAY_EXCLUDE_DOMAINS=ssh.github.com   # 排除优先于命中
```

### 2.2 src/config.ts

- `AppConfig` 增加：`relayMode: "off" | "auto" | "always"`、`relayIp?: string`、
  `relayDomains: string[]`、`relayExcludeDomains: string[]`。
- 解析仿现有风格（config.ts:147 一带）：
  `relayDomains: list(env.RELAY_DOMAINS).map(lower)`，`relayMode` 默认 `"off"`。
- 校验：`relayMode !== "off"` 且 `relayIp` 非法/缺失 → 启动打一条 `relay_config_warning` 日志并
  降级为 `off`（fail-safe，沿用 `upstream_trust_warning` 的告警先例）。
- `RELAY_IP` 用 `parseIpv4` 校验且必须是私网段（RFC1918/ULA），公网地址拒绝——这是防开放中继的
  第一道闸。

匹配语义复用 `domainMatches`（src/dns/ecs.ts:49）：精确或 `*.` 后缀（带点边界，覆盖裸域+子域）。
判定：`mode≠off && domainMatches(name, relayDomains) && !domainMatches(name, relayExcludeDomains)`。

## 3. 服务端改动

### 3.1 src/relay.ts（新文件，纯状态机，无 IO）

```ts
relayServes(name: string, config: AppConfig): boolean   // 策略层问它这个名字现在要不要覆写
setRelayHealth(report: RelayHealthReport): void          // POST /admin/relay-health 入口
relayStatus(): {...}                                     // GET /admin/relay 输出
relayCacheTag(): string | undefined                      // `relay=v<n>`，版本翻转即换缓存键
```

- 档位语义：`always` → 名单命中即服务；`auto` → 名单命中 **且** 该主机状态机在 relayed 态；
  `off` → 一律不服务（`relayCacheTag()` 恒 undefined）。
- per-host 状态机（auto 档）：默认 `direct`。
  - `direct → relayed`：直连滑窗（15 分钟）成功率 < 50% **且** relayHealthy；
  - `relayed → direct`：直连滑窗（30 分钟）成功率 > 80%，或 relayHealthy 变 false（**立即**，全主机）；
  - 滞回参数为模块常量（`ENTER_WINDOW_MS=15min`、`ENTER_RATE=0.5`、`EXIT_WINDOW_MS=30min`、
    `EXIT_RATE=0.8`、窗口容量 32 条），先不做 env 化。
- 每主机滑动窗口：`Map<host, {ok: boolean, ts: number}[]>`，上报驱动写入，读时按窗口过滤。
  无测量的主机在 auto 档 = 保持 direct（沿用 github-pool "no measured pool yet, answer left
  untouched" 的哲学，src/strategies.ts:94）。
- relayHealthy：上报自带 TTL（prober 每 180s 上报一次，超过 3 个周期没收到 = unhealthy 并撤）。
- **版本号**：任何主机状态转移、relayHealthy 翻转、档位变化（env 已固化，运行期不变）→ `bump()`。
  cacheTag 仿 `metaEchCacheTag`（src/preferred.ts:354）。

### 3.2 src/strategies.ts：relay 策略

```ts
export const relay: Strategy = {
  name: "relay",
  order: 45,   // sitePools(40) 之后、githubPool(50) 之前：后写覆盖 site-pool 的 pin，锁住 github-pool
  cacheTag: (ctx) => (relayServes(ctx.name, ctx.config) ? relayCacheTag() : undefined),
  async apply(ctx, plan) {
    if (!relayServes(ctx.name, ctx.config)) return;
    const ip = ctx.config.relayIp!;
    if (ctx.type === DnsType.A || ctx.type === DnsType.AAAA) {
      plan.pin = [ip];
      plan.locked.addresses = true;      // githubPool(50) 检查此标志，跳过
      plan.strategy = "relay";
    } else if (ctx.type === DnsType.HTTPS) {
      plan.locked.ech = true;            // metaEch(70)/cloudflareEch(80) 检查此标志，不再注入
      plan.strategy = "relay";
      plan.post.push({ apply: relayHttpsCleanup(packet, ip), note: "relay: HTTPS hints→relay IP, ECH removed, ALPN→h2" });
    }
  },
};
```

- `PUBLIC_STRATEGIES` 数组加入 `relay`（src/strategies.ts:150）。
- A/AAAA 渲染走现成的 `pinAddresses`（src/rewrite.ts:235）：A 替换为 relay IP、AAAA 清空。
  **需要一个小扩展**：`pinAddresses(packet, query, ipv4, maxTtl?)`——第 4 个可选参数，命中时
  `ttl = Math.min(现有最小 ttl, maxTtl)`；relay 传 60。默认不传 = 行为完全不变（现有调用零改动）。
  GitHub 上游 A 的 TTL 本就常为 60，此参数是保险上界。
- `relayHttpsCleanup`（放 src/rewrite.ts 或 https-rr.ts 旁）：对每个 HTTPS RR——
  1) 删 `ech` 参数（relay 是 SNI 观察者，ECH 外层名指错路，必须摘）；
  2) `ipv4hint` → `[relayIp]`、删 `ipv6hint`（复用 `pinHttpsHints` 的逻辑，src/rewrite.ts:254）；
  3) `alpn` 压到 `["h2"]`（`upsertSvcParam`，禁 QUIC/UDP 443——relay 只转 TCP）。
- `/explain` 免费获得：notes 里会出现 relay 策略行和 post 编辑行（plan.ts 注释语义）。
- metrics 免改：`sample.strategy` 泛型计数（src/metrics.ts:102），`"relay"` 自动进 /admin/stats
  的策略分布（监测站"解析策略"面板直接可见）。

### 3.3 src/index.ts：管理端点（仿 index.ts:428-434 的路由风格）

| 端点 | 方法 | 鉴权 | 作用 |
|---|---|---|---|
| `/admin/relay-health` | POST | ADMIN_TOKEN | relay prober 上报：`{healthy, direct: {host: {ok, rttMs}}, source}` → `setRelayHealth` |
| `/admin/relay` | GET | ADMIN_TOKEN | 状态：档位、relayHealthy、每主机状态+滑窗成功率、版本号 |
| `/admin/pool?name=` | GET | ADMIN_TOKEN | 返回该主机的实测池（`githubPoolFor ?? sitePoolFor`），relay 拨号用 |

`/admin/pool` 存在的理由（鸡生蛋）：auto 档下被覆写的主机，`/dns-query` 答的就是 relay IP，
relay 想测"直连质量"必须有一条**不经过覆写**的取 IP 通道；池本来就是服务端内存里的干净数据。

## 4. 数据面：contrib/home/relay/relay.mjs

单文件 Node 20 ESM，零第三方依赖（net/tls 内置），root systemd 运行，~300 行。

### 4.1 监听与转发

- 只绑 `RELAY_IP:443`（绝不 0.0.0.0——第二 IP 本身就是暴露边界）。
- 新连接：缓冲 peek 至多 16KB 或 3s，解析 ClientHello 的 SNI
  （record 5B → handshake 头 4B → ClientHello 里 extensions 找 type 0x0000；
  TLS 1.2/1.3 的 ClientHello 明文层结构相同）。解析失败 / 无 SNI → destroy（**不猜**，
  完整版 sniffer 的容错哲学）。
- SNI 名单检查：内置一份与 `domainMatches` 等价的通配匹配（~10 行），含排除优先。
- 拨号：
  1. `GET http://127.0.0.1:8787/admin/pool?name=<sni>`（带 token，结果缓存 60s）；
  2. 有池 → 取前 2 个 IP 逐个尝试：TCP 连 `PROXY_ADDR`，手写 `CONNECT <ip>:443 HTTP/1.1`，
     读到 2xx 后双向 pipe；
  3. 无池 → `CONNECT <sni>:443`（依赖 mihomo DOMAIN 规则远程解析，见 §6.3）；
  4. 上游失败 → 换下一个池 IP；全败 → 关连接（客户端重试，可能再落回直连）。
- 资源保护：并发连接上限 512（超限即拒）；单连接 30s 无数据超时；journal 日志，
  `RELAY_DEBUG=1` 时连接级日志。

### 4.2 内置 prober（auto 档测量回路 + 自检）

- 自检（relayHealthy）：每 30s 经自身全链路（绑定的 443 → CONNECT → tls 握手）打一个代表主机
  （github.com），连续 3 次失败 → unhealthy；恢复 1 次即 healthy。
- 质量测量：每 `RELAY_PROBE_INTERVAL`（默认 180s）对名单主机（`RELAY_PROBE_HOSTS` 可减，
  默认=全部 17 个）：
  - 直连端：从 `/admin/pool` 取该主机前 2 个池 IP，逐个 `tls.connect({host: ip, servername: host,
    timeout: 3000})`，任一成功记 ok（附最小 rtt）；
  - 中转端：经自身链路握手一次（自检已覆盖，不重复测）。
- 上报：`POST /admin/relay-health`，body 含 healthy + direct 结果。
- 周期选型依据：抖动是分钟级，控制回路周期必须短于被控现象——30 分钟的池探测追不上，
  180s 是探测负担（17 主机 × 2 IP × ~1s 串行 ≈ 35s）与收敛速度的折中。

### 4.3 relay 专用 env（/etc/edge-smart-doh/relay.env，deploy 脚本生成，0600 root）

```bash
RELAY_LISTEN_IP=192.168.x.250
RELAY_DOMAINS=...              # 与主 env 同源生成，不手工维护两份
RELAY_EXCLUDE_DOMAINS=...
RELAY_PROXY=127.0.0.1:7890
RELAY_ADMIN_TOKEN=...          # 与主 ADMIN_TOKEN 同值；不整份读主 env，最小权限
RELAY_PROBE_INTERVAL=180
```

刻意**不读**主 env：relay 不需要上游/ECS/名单 URL 那些控制面配置，避免把 secrets 洒给新进程。

## 5. systemd 与部署

### 5.1 单元（contrib/home/relay/relay.service → /etc/systemd/system/edge-smart-doh-relay.service）

```ini
[Unit]
Description=edge-smart-doh SNI relay (home)
After=network-online.target edge-smart-doh.service mihomo.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/node /opt/edge-smart-doh/relay.mjs
EnvironmentFile=/etc/edge-smart-doh/relay.env
Restart=always
RestartSec=3
# 独立 hardening：PrivateTmp=yes, ProtectHome=yes, CapabilityBoundingSet=（绑 <1024 端口需要
# CAP_NET_BIND_SERVICE，用 AmbientCapabilities= 授予而非 root 全能）

[Install]
WantedBy=multi-user.target
```

### 5.2 deploy-home.sh 扩展

配置区新键：`RELAY_ENABLED`（默认 `ask`：首次交互问"启用 SNI 中转？"，答案进 deploy.conf）、
`RELAY_IP_CFG`。执行步骤追加（幂等，仿现有步骤结构）：

7. relay：构建并安装 `/opt/edge-smart-doh/relay.mjs`，生成 relay.env（域名清单从
   `GITHUB_DOMAINS` 的通配形种子生成），装单元，`enable --now`；
8. 第二 IP：本次 `ip addr add` 生效，并安装常驻 oneshot 单元
   `edge-smart-doh-relay-ip.service`（`Type=oneshot` + `RemainAfterExit=yes`、
   `After=/Wants=network-online.target`、`Before=edge-smart-doh-relay.service`，ExecStart 幂等 +
   6×3s 重试覆盖 DHCP 迟到）`enable --now` 负责开机持久化——**不依赖网络后端**；探测不出默认路由
   网卡时只打印手工命令，网络后端（nmcli/ifupdown/networkd）信息仅作参考。relay 单元用 drop-in
   `edge-smart-doh-relay.service.d/10-wants-relay-ip.conf` 追加 `Wants=/After=`（不改仓库 relay.service，
   保留 install/升级的幂等比较）；
8b. 443 冲突：relay 只绑 `RELAY_IP:443`，而内核不允许“通配 + 具体地址”同端口共存，
   若 `*:443` 已被通配占用（典型：Caddy 未写 `bind`），先起 relay 必 EADDRINUSE。deploy 检测到
   通配占用者是本机 Caddy 时，给 Caddyfile 里绑 443 的站点加 `bind <主 IP>`、`caddy validate`
   通过后 reload，并轮询（≤20s）到旧通配释放 + 主 IP:443 在听，才允许启 relay；reload 失败/
   校验失败/超时 → 还原 Caddyfile 并中止（不留半完成态），占用者不是 Caddy → 明确提示并中止；
8c. nftables 幂等：`/etc/nftables.conf` 刻意无 `flush ruleset`（保 Docker 的表），`systemctl
   reload nftables` 会累积重复规则；deploy 写规则前查 `nft list ruleset`、写后断言内核里恰好 1 条，
   且用“删本表 inet home_firewall 再整体载入”而非 reload；
9. env 写入 `RELAY_MODE=auto`（首次种子；用户手动改 env 的值脚本要尊重，仿
   `ECS_FALLBACK_SUBNET_CFG` 的"配置区值优先"模式）；
10. `SETUP_FIREWALL=1` 时：nftables 增加放行 `RELAY_IP` 443/TCP 入站，源限制 RFC1918。

备份（改 env / nftables.conf / Caddyfile 前）一律落在**仓库外**的 `/var/backups/edge-smart-doh/`：
目录 0700，含 `ADMIN_TOKEN` 的 env/relay.env 副本 0600——本仓库挂着 `origin`/`fork` 两个 GitHub
remote，含密副本绝不能写进工作区。

### 5.3 mihomo 前置条件（脚本只检查+提示，不代改——mihomo 配置用户自管）

relay 无池回退按域名 CONNECT 时，mihomo 必须把这些域名交给节点远程解析，而不是本地解析直连：

```yaml
rules:
  - DOMAIN-SUFFIX,github.com,<代理组>
  - DOMAIN-SUFFIX,githubusercontent.com,<代理组>
  - DOMAIN-SUFFIX,githubassets.com,<代理组>
  - DOMAIN-SUFFIX,github.io,<代理组>
```

deploy 输出该片段 + 验证命令（`curl -x http://127.0.0.1:7890 -sI https://github.com` 应通，
且 mihomo 日志里该连接走代理组）。M0 验收里这项是硬门槛。

## 6. 监测站（contrib/home/monitor/monitor.mjs）

- 拉取 `GET /admin/relay`（token 在监测进程里，与 /admin/stats 同模式）。
- 三链路卡 → 四链路：**中转**卡显示档位（off/auto/always + 当前处于 relay 的主机数）、
  relayHealthy、直连 vs 经 relay 的握手时延。
- 链路延迟趋势线加 relay 一条：10s 探测改为"DoH 查 github.com 看答案是否 relay IP +
  TCP 连 relay IP:443 握手计时"。
- 探测 label 推导规则更新：github 域名命中 relay 时 label 显示"GitHub 中转"而非"GitHub 池"。
- 诊断区加 relay 状态 details（每主机状态机、滑窗成功率、版本号、上次上报时间——
  超过 3 周期没上报标红）。

## 7. 里程碑与验收

### M0 链路验证（手工，~半天，gost 或 50 行脚本）

1. `ip addr add 192.168.x.250/24 dev <lan>`；
2. `gost -L sniproxy://192.168.x.250:443 -F http://127.0.0.1:7890`（或等价手写脚本）；
3. 验收清单：
   - `curl --resolve api.github.com:443:192.168.x.250 https://api.github.com/rate_limit` 200；
   - 证书链真实（`openssl s_client -connect 192.168.x.250:443 -servername github.com` 看到
     GitHub 真实证书）；
   - mihomo 日志确认流量走节点；**无自连回环**（观察 mihomo 无对 192.168.x.250 的连接）；
   - LAN 另一台设备 `curl --resolve` 同样打通。

### M1 relay.mjs MVP + always 档（~1 天）

- relay.mjs（§4.1，无 prober）+ relay.service + relay.env 手工部署；
- 服务端：config、src/relay.ts（档位判断 + 版本号，auto 分支先留桩）、relay 策略、
  `pinAddresses` maxTtl、`GET /admin/relay`；
- 验收：`RELAY_MODE=always` 时 `/explain?name=github.com&type=A` 的 steps 出现 relay 策略行；
  `dig` A=relay IP、TTL≤60；HTTPS 查询的 RR 无 ech、hint=relay IP、alpn=h2；
  `git clone https://...` 走通；`systemctl stop edge-smart-doh-relay` 后（healthy 标记撤）
  答案在 TTL 内回退为池；
- 回归：`RELAY_MODE` 未设时现有 vitest 全绿。

### M2 auto 档全链路（~1 天）

- `/admin/pool`、`POST /admin/relay-health`、滑窗 + 滞回 + healthy 撤除、relay 内置 prober；
- 验收：手工把直连窗口打坏（临时 nft 阻断池 IP 出站）→ 15 分钟内切 relay → 解除 → 30 分钟内
  切回，`/admin/relay` 和 cacheTag 版本全程可观测；kill relay → 全主机立即回 direct。

### M3 集成（~半天）

- deploy-home.sh 步骤 7-10、第二 IP 自动化、nftables、监测站四链路卡、
  contrib/home/README.md 增"中转"章节（原理一段 + 档位 + 风险边界 + 回滚）。

## 8. 测试计划

- **vitest**（test/relay.test.ts，新）：
  - 匹配：通配命中/排除优先/裸域+子域/非名单不动；
  - 状态机：滞回进出阈值、healthy 撤除、无测量保持 direct、上报过期；
  - 策略：A pin + locked.addresses 短路 githubPool、HTTPS 三清（ech 删/hint 换/alpn 压）、
    cacheTag 在版本翻转后变化；
  - 回归底线：RELAY_MODE=off 时 `strategyCacheTags` 与现状逐字节一致。
- **pinAddresses maxTtl**：现有 preferred/site/github 调用路径不传参 → 输出不变（快照对照）。
- **集成脚本**（contrib/home/relay/test.sh，M1 起用）：dig/curl --resolve/HTTPS RR 检查/
  断 relay 回退计时/断 mihomo 回退。
- typecheck：`./node_modules/.bin/tsc` 三个配置单独跑（本机 Node 20 跑不了 wrangler types，
  沿用现有流程）。

## 9. 风险与回滚

| 风险 | 缓解 |
|---|---|
| DNS 回环（mihomo 解析路径拿到覆写答案） | 拨号一律池 IP；域名回退依赖 DOMAIN 规则（§5.3 硬门槛）；M0 验收含回环观察 |
| HTTPS RR 泄漏真实 IP / QUIC 打 UDP 443 | 三清 + 测试覆盖（ech/hint/alpn） |
| 开放中继被滥用 | 只绑第二私网 IP；config 校验拒绝公网 IP；nft 源限制；连接上限 |
| 节点带宽被 GitHub 大 clone 吃掉 | always 档自觉选择；auto 档默认（直连好就不走）；文档写明代价 |
| relay/mihomo 故障 | 设计不变量：撤覆写回直连，TTL 60s 收敛 |
| SNI 解析缺陷误伤 | 无 SNI 即断不猜；peek 缓冲上限；M1 全量 git/curl 实测 |

回滚（三层，任选）：`RELAY_MODE=off`（改 env + restart，最保守）→ `systemctl disable --now
edge-smart-doh-relay` → 删第二 IP（`ip addr del` + 后端配置移除）。DNS 侧 60s 自然收敛，
已建连接自然老化。

## 10. v1 明确不做（边界）

- UDP/QUIC 中转（ALPN 压 h2 已让客户端不走 QUIC）；
- SSH：22 端口、ssh.github.com:443（无 SNI 分流不了；文档给
  `ProxyCommand nc -X connect -x 127.0.0.1:7890 %h %p` 的客户端侧替代）；
- 80 端口（http 明文访问 GitHub 场景可忽略）；
- ECH 站点进名单（与 SNI 观察者天然冲突；要加就得接受"摘 ECH 走中转"）；
- 按站点分档/站点分组配置（等第二个站点真的来了，只动 config.ts 解析层）；
- relay 内直连优先+失败重拨（省节点带宽的 v1.1 优化项，默认关）；
- 全网流量接管（那是 mihomo TUN + fake-ip 合体形态的定位，与本方案互不越界）。
