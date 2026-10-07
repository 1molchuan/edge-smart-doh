# 在家里部署（社区贡献）

> 脚本和测量数据来自 [@liyu34](https://github.com/liyu34)（PR #1），在 Debian 13 + 家宽 + 本地代理出境的环境里实际跑通。这是社区贡献的部署方式，公开实例用的是仓库根目录 README 里的 Node.js + Caddy 方案。

适合：在家里的小主机、NAS 或国内小机上搭一个只给自己用的 DoH，用 cfhub 的优选池给 Cloudflare 网站换 IP、补 ECH。

## 先理解一件事：境外上游必须走代理，国内域名直接问国内 DNS

国内直连的解析器（阿里、腾讯等）对**被污染的域名**会返回假 IP，而且返回得很快。DoH 查上游是**竞速**的（先问第一个，`UPSTREAM_HEDGE_MS` 毫秒内没回再加问下一个，谁先回用谁），所以只要 `UPSTREAMS` 里混进一个直连的国内解析器，它就几乎每次都赢。作者实测（`UPSTREAM_HEDGE_MS=50`）：

| 上游 | 路径 | 耗时 | 结果 |
|---|---|---|---|
| cloudflare-dns.com | 经代理 | 679 / 1666 ms | 干净 |
| dns.google | 经代理 | 649 / 475 ms | 干净 |
| dns.alidns.com | 直连（在 `NO_PROXY` 里） | 38 / 60 ms | `linux.do` 返回 `199.96.59.61`（假 IP） |

```
t=0     问 cloudflare（经代理，还在路上）
t=50    问 google
t=100   问 alidns（直连）
t=138   alidns 带着假 IP 先回来 → 赢了，另外两个被取消
```

假 IP 还会进答案缓存和判断 Cloudflare 用的缓存，所以修好代理之后也要清掉缓存（见下面的"验证"）。

**规则：`UPSTREAMS` 是信任清单，只放经代理出境的上游。** 服务启动时如果发现 `UPSTREAMS` 里有在 `NO_PROXY` 名单上的（会直连），会打一条 `upstream_trust_warning` 日志。

但这不等于国内解析器没有用武之地——关键是**按域名分流，而不是混进同一个池子竞速**。国内域名本来就不在被污染的集合里，问国内解析器是安全的，而且国内解析器看到的查询源 IP 就是你的家宽出口（运营商级视角，比任何 ECS /24 都准），代理挂了也照常解析。所以现在国内模式默认开启域名分流（`CN_UPSTREAMS`）：

- **国内域名**（`ECS_DOMAIN_LIST_URLS` 名单 + `ECS_DOMAINS` + 你自加的 `CN_DOMAINS`）→ 直连 `https://dns.alidns.com/dns-query,https://doh.pub/dns-query`（阿里/腾讯 DoH，脚本自动把主机名加进服务的 `NO_PROXY`；改用自己的解析器设 `CN_UPSTREAMS_CFG`，设 `none` 关闭）；
- **其余域名** → `UPSTREAMS` 信任清单，经代理出境，照旧竞速。

两组上游各自组内竞速，互不见面，被污染域名永远不会碰到国内解析器。设 `CN_UPSTREAMS_CFG=none` 关闭分流时，国内域名退回 ECS 路径：`dns.google` 会转发 ECS，经代理查询照样按你的 /24 返回国内节点（作者实测 `www.taobao.com` 拿到的节点和直连阿里 DNS 相同）。所以脚本把 `ECS_UPSTREAMS` 也只设成 `dns.google`（Cloudflare 不转发 ECS，不能放进去）。代价：Google 按 ECS 选节点没有国内解析器细，且代理挂了时这些域名全部解析失败（缓存过期的记录还能临时顶一下）。

ECS 真正生效还差两个键，脚本会自动补齐（旧版 env 拷贝缺行、或留空时写入）：

- **`ECS_DOMAIN_LIST_URLS`**（默认 Loyalsoldier `direct-list.txt`，约 11 万国内域名，含 `huawei.com`，服务每天自动刷新）：上面说的"国内域名"判定名单，直连分流和 ECS 路径都用它。名单里没有的国内域名（新站、漏收）用 `CN_DOMAINS` 自己加。想关闭设 `ECS_DOMAIN_LIST_URLS_CFG=none`。
- **`ECS_FALLBACK_SUBNET`**（默认每次重跑自动探测家宽公网 IPv4，可用 `ECS_FALLBACK_SUBNET_CFG` 固定）：只在 `CN_UPSTREAMS_CFG=none` 的 ECS 回退路径里用。本机和局域网客户端的地址是 `127.0.0.1`/`192.168.x.x`，`dns.google` 对非公网子网一律 REFUSED（实测带 `127.0.0/24` 的查询直接 SERVFAIL），所以必须换成家宽公网地址；服务对非公网客户端直接用这个子网，不需要 `ISP_TABLE_URL`。家宽 PPPoE 重拨换 IP 后重跑脚本即可。探测必须直连（`--noproxy`），若代理以 TUN 全局接管导致探测失败，脚本会沿用旧值并告警。

分流的风险边界要说清楚：**名单误收一个被墙域名时，国内解析器会返回假 IP**。direct-list 是直连名单，收录标准保守，这个概率很低；如果你发现某个域名解析结果可疑，把它从分流里摘出去的办法是设 `ECS_DOMAIN_LIST_URLS_CFG=none`、`CN_UPSTREAMS_CFG=none` 重跑脚本（直接改 env 只能临时生效——脚本重跑会把这几个键写回配置区的值），该域名随即回到经代理的信任清单路径。

## 脚本做了什么

`sudo bash contrib/home/deploy-home.sh`，可以反复运行（幂等）。第一次运行会问域名、代理地址、邮箱等，答案存到 `/etc/edge-smart-doh/deploy.conf`（root 0600），之后不再问。

1. 装依赖，构建 `dist/node.mjs`，安装成 systemd 服务（`ADMIN_TOKEN` 自动生成，重跑不换）。
2. 国内模式：给服务加代理。Node 自带的 `fetch` 不认 `HTTP_PROXY`，脚本装 `undici@6` 并用 `--import` 预加载 `EnvHttpProxyAgent`。**固定 6.x**：undici 8 需要 Node ≥ 22.19，在 Node 20 上一启动就崩；脚本在重启服务前会先试加载一次，不兼容就停下报错，不会让服务陷入重启循环。
3. 国内模式：补齐国内域名配置——写入域名名单 `ECS_DOMAIN_LIST_URLS`（缺失/为空时）、国内直连上游 `CN_UPSTREAMS`（阿里/腾讯 DoH，主机名同步进代理 drop-in 的 `NO_PROXY`），探测家宽公网 IPv4 写入 `ECS_FALLBACK_SUBNET`（ECS 回退路径用，见上文）。
4. 每 5 分钟从 cfhub 的公开接口（`/api/v1/pools`）同步各运营商的优选池到本机 DoH。
5. （`OPEN_PUBLIC=1`）证书与对外服务：**先探测机器统一证书**——`/etc/ssl/<dir>/` 下成对 fullchain+privkey 且 SAN 覆盖 DoH 域名的（如 `/etc/ssl/wildcard` 的通配符，多份命中取剩余有效期最长的），就只引用不签发（续期/权限/reload 归机器统一环节，如 root cron 的 `acme.sh --cron` + `--reloadcmd`），Caddy 也只动自己的站点块（已指向就跳过、旧 `/etc/ssl/doh` 的 tls 行就原位切换、没有站点才写 `edge-smart-doh.caddy` site 文件 + import），绝不负责整写别的站点。没有统一证书才走 acme.sh DNS-01 自签到 `/etc/ssl/doh`（root cron 自动续期），可选 DDNS（只维护这一个域名的 A 记录）。
6. （`SETUP_FIREWALL=1`，默认关）用 nftables 收紧入站。**会整体替换 `/etc/nftables.conf`，入站默认丢弃**，只放行 SSH、mosh、DoH；NAS 或还跑着别的服务的机器上会把它们挡掉，确认后再开。替换前会备份原文件。

脚本做不了、需要你自己做的：路由器把外网 8443/TCP 转发到这台机器；用手机流量从外网验证一次。

主要选项在脚本开头的配置区：`DEPLOY_ENV`（`cn` 走代理 / `overseas` 直连）、`PROXY_ADDR`、`OPEN_PUBLIC`、`SETUP_DDNS`、`SETUP_FIREWALL`、`SKIP_BUILD`。

## 验证

```bash
# 没有混合信任告警（UPSTREAMS 混入直连上游）或国内上游被代理接管的告警
journalctl -u edge-smart-doh -n 30 --no-pager | grep -iE 'upstream_trust_warning|cn_upstream_proxy_warning' || echo "OK：无告警"

# 上游配置（两组：CN_UPSTREAMS 直连国内，UPSTREAMS/ECS_UPSTREAMS 经代理）
sudo grep -E '^(UPSTREAMS|ECS_UPSTREAMS|CN_UPSTREAMS|ECS_DOMAIN_LIST_URLS|ECS_FALLBACK_SUBNET)=' /etc/edge-smart-doh/env

# 境外域名：上游应该是 cloudflare/google，答案是干净的 Cloudflare 地址，最终换成优选池
curl -s "http://127.0.0.1:8787/explain?name=linux.do&type=A" | jq -c '{steps:.results[0].steps}'

# 国内域名：steps 第一行应是 domestic name + upstream dns.alidns.com（直连，无 ECS），
# 答案是国内的 CDN 节点；注意首次查询会触发名单下载（经代理），过几秒再查一次。
# 刚启动就查过的国内域名可能已按代理路径缓存（TTL 到期前 /dns-query 仍回旧答案，/explain 不受影响）
curl -s "http://127.0.0.1:8787/explain?name=developer.huawei.com&type=A" | jq -c '{steps:.results[0].steps, answer:.results[0].answer}'
```

之前跑过混了直连上游的配置，要清掉被污染的缓存：

```bash
sudo systemctl stop edge-smart-doh
sudo mv /var/lib/edge-smart-doh/cache.bin /var/lib/edge-smart-doh/cache.bin.polluted-$(date +%F)
sudo systemctl start edge-smart-doh
```

## 局域网控制台（:8788，监测 + 控制）

`deploy-home.sh` 会顺带装控制台（也可单独装/升级：`sudo bash contrib/home/install-monitor.sh`），手机或电脑浏览器打开 `http://<内网IP>:8788`。图表由 **ECharts**（Apache-2.0）渲染，库文件在 `contrib/home/monitor/vendor/` 里随安装复制到本机、由控制台自己提供——**不依赖公网 CDN**，纯内网环境可用；vendor 文件缺失时图表面板会提示加载失败，表格不受影响。

**访问控制**：`install-monitor.sh` 首次运行会生成 `CONSOLE_PASSWORD`（`openssl rand -hex 10`）写进 `/etc/edge-smart-doh/monitor.env`（0600 root）并只打印一次；设了密码后**看与控都要登录**（会话 cookie 仅存控制台进程内存，2 小时无活跃或 24 小时后过期，进程重启全部失效；同 IP 连错 5 次冷却 60 秒）。没设密码时保持纯监测形态（控制区隐藏）——向后兼容。轮换密码见 `OPERATIONS.md` §8。

页面按"打开的人想问什么"排序（v2 视觉：bento 磁贴布局 + 置顶命令栏，观察区蓝色数据语言、控制区琥珀甲板语言）：

1. **命令栏（置顶）**：品牌与状态胶囊（绿/黄/红随健康判定）、会话徽标（label · 来源 IP · 退出）、实时时钟；
2. **首屏 bento**：状态大磁贴（绿"运行正常" / 黄"统计不可用、失败率偏高、中转离线" / 红"服务不可达、解析异常"，异常原因直接写在磁贴里，辉光随状态着色）+ 总查询 / 缓存命中率（带甜甜圈环）/ 回源 P50 三个 KPI + 解析链路磁贴（国内直连 / GitHub 池 / 境外代理，当前延迟 + 近 10 分钟火花线，中转接管标注"中转"）；
3. **解析路径分布**：单条分段占比条 + 图例（SNI 中转 / ECH 注入 / 优选池 / 国内直连 / 直连 + 缓存应答，次数·占比·平均延迟；"最近查询"表也带路径徽章）；
4. **图表**：查询量（近 2 小时每分钟堆叠柱状）与链路延迟趋势（每 10 秒真实 DoH 探测）并排，回源延迟分位 / 解析策略（技术视图）/ 上游解析器三列；
5. **控制甲板**（琥珀色，登录后可见）：档位大字 + 三段选择器（切 `always` 有确认弹层列带宽代价，切 `off` 后常驻黄色警示）、中转/排除名单编辑（chips + 行内校验 + diff 预览 + 二次确认）、同步状态行（`configVersion` vs relay 回执 `appliedConfigVersion`）、"恢复 env 默认"、操作记录（审计）；
6. **诊断区（默认折叠）**：高频域名、最近查询、优选池与规则状态（池子剩余 TTL 少于 30 分钟会标黄）。

控制操作的通道：浏览器 → 控制台 `/api/relay-config`（会话鉴权）→ 主服务 `POST /admin/relay-config`（Bearer ADMIN_TOKEN）→ 运行时覆盖 + 持久化到 `/var/lib/edge-smart-doh/relay-config.json`（重启保留）→ 缓存版本立即换键生效 → relay 守护进程 ≤30 秒从健康上报响应热同步名单。**运维 Agent / 脚本走同一套 HTTP 接口**（登录→读→改→验证→回滚的 curl 全流程、语义表、故障预案见 `contrib/home/OPERATIONS.md`）。设计文档：`contrib/home/monitor/PRD-console.md`。

- **服务状态**：DoH 可达性、探测延迟、运行时长、内存；
- **查询统计**：总量、每分钟曲线（近 2 小时）、缓存命中率、回源延迟分位数（P50/P90/P99）、失败数、回源路径分布；
- **上游解析器**：默认/ECS/国内直连三组各自的成败、平均与峰值延迟、最近一次错误；
- **解析策略**：回源时 direct / preferred-ip / github-pool 等的分布（技术视图）；
- **主动探测**：对几个域名（默认淘宝/GitHub/Google，`MONITOR_PROBE_NAMES` 可改）定期发真实 DoH 查询，看国内直连、GitHub 池、代理出境三条链路是否各自正常（链路名称默认按域名特征推导，`MONITOR_PROBE_LABELS` 可整体覆盖）；
- **Top 域名 / 最近查询**、**优选池与名单状态**（cfhub 运营商池、GitHub 池、国内域名名单、?safe=1 名单、Meta ECH）。

数据来自主服务的 `GET /admin/stats`（`ADMIN_TOKEN` 鉴权）和控制台自己的探测；统计存在内存里，主服务重启后从零开始。

**只在局域网访问**是两层防线：控制台按 TCP 对端地址过滤（只放行回环与私网网段，可 `MONITOR_ALLOW` 覆盖，绝不信任 `X-Forwarded-For` 一类可伪造头）；`SETUP_FIREWALL=1` 时 nftables 只对内网网段放行 8788。`ADMIN_TOKEN` 与 `CONSOLE_PASSWORD` 只存在于控制台进程内存/本机 env，页面不带任何凭据（浏览器只见会话 cookie）。

## SNI 中转（GitHub 族域名，可选）

直连 GitHub 的 SNI 级抖动（时好时坏）是数据面问题，DNS 答案再准也治不了。中转是给系统补的数据面杠杆：把网卡的**第二个内网 IP**（如 192.168.1.250）答给名单域名，本机 relay 进程在该 IP 的 443 上读 TLS ClientHello 的 SNI，把 TCP 流经代理（HTTP CONNECT）转给真实目标——**TLS 端到端，relay 绝不终结**，客户端看到的证书仍是真 GitHub 的。设计与完整方案见 `contrib/home/relay/DESIGN.md`。

三档 `RELAY_MODE`（env 为默认值，控制台可运行时切换）：

| 档 | 语义 |
|---|---|
| `off` | 关闭（默认，代码路径不激活） |
| `auto` | 按主机健康门控：relay 每 3 分钟直连实测池 IP 握手，某主机 15 分钟内成功率 <50% 切中转，30 分钟内 >80% 切回直连 |
| `always` | 名单内域名无条件走中转 |

域名集合独立于档位：`RELAY_DOMAINS`（支持 `*.github.com` 通配）+ `RELAY_EXCLUDE_DOMAINS`（排除优先，默认排掉无 SNI 的 `ssh.github.com`）。HTTPS RR 会同步清洗（hint 指向中转 IP、删 ECH、ALPN 压 h2），AAAA 答空，TTL 压到 60。

启用：`deploy-home.sh` 配置区设 `RELAY_ENABLED=1` 重跑。脚本会问第二 IP，装 `edge-smart-doh-relay-ip.service`（`Type=oneshot` + `RemainAfterExit`，每次开机幂等补齐地址，重试覆盖 DHCP 迟到；relay 单元用 drop-in `Wants=/After=` 它），再装 `edge-smart-doh-relay.service`、生成最小权限的 `/etc/edge-smart-doh/relay.env`、种好 `RELAY_MODE=auto`。启 relay 前还会自动处理两个部署坑：

- **443 冲突**：relay 只绑 `RELAY_IP:443`，若本机已有通配 `*:443`（如 Caddy 未写 `bind`）就会 EADDRINUSE。脚本检测到通配占用者是本机 Caddy 时，给 Caddyfile 里绑 443 的站点加 `bind <主 IP>`、`caddy validate` 通过后 reload，并轮询到旧通配释放、主 IP:443 在听才启 relay（≤20s）；超时或占用者不是 Caddy → 还原 Caddyfile 并中止，不盲启。
- **nftables 幂等**：`/etc/nftables.conf` 刻意不加 `flush ruleset`（怕清掉 Docker 的表），于是 `systemctl reload nftables` 会累积重复规则。脚本改规则时先查 `nft list ruleset`、写后断言内核里恰好 1 条，且用"删本表再整体载入"而不是 reload。

两个前置认知：

- **防回环靠"按实测池 IP 拨号"**：relay 拨号用 `/admin/pool` 给的池 IP，不经 DNS，从根上避免"解析到中转 IP→连到自己"。仅池空时按域名 CONNECT，此时依赖代理配置里的 `DOMAIN-SUFFIX,github.com,<代理组>` 规则远程解析——装完用 `curl -x <代理> -sI https://github.com` 验证一次。
- **降级不变量**：relay 挂了/代理挂了 → 健康上报停止 → DNS 在 TTL 内回退直连路径，最坏情况 = 没装中转。`RELAY_IP` 只接受私网地址，服务端直接拒绝公网值。

控制台会显示中转状态（档位、健康、每主机直连成功率与是否走中转），并且**档位与两个名单都能在控制台上直接改**（运行时覆盖，立即生效、重启保留，relay 进程 ≤30 秒热同步名单，无需改 env 重启）；中转档开着但守护进程没上报时首页给黄牌。代价要想清楚：走中转的流量吃代理节点的带宽。回滚：控制台切回 `off`（或 `systemctl disable --now edge-smart-doh-relay`），60 秒内收敛。

## 回滚

- 环境变量：脚本每次改 env 前会备份到仓库外的 `/var/backups/edge-smart-doh/env.<时间>`（目录 0700，含 `ADMIN_TOKEN` 的副本 0600），拷回去再 `systemctl restart edge-smart-doh`。
- 防火墙：替换前备份到 `/var/backups/edge-smart-doh/nftables.conf.<时间>`，拷回去后 `nft delete table inet home_firewall && nft -f /etc/nftables.conf`。
- Caddy（若因 443 收窄失败，脚本会自行还原）：备份同样在 `/var/backups/edge-smart-doh/Caddyfile.<时间>`。

## 已知限制

- 国内模式不填代理时，脚本只能把国内直连解析器放进 `UPSTREAMS`，被污染的域名一定拿到假 IP，只能临时用。
- 开启分流后，国内直连上游（阿里/腾讯）全挂时国内域名是 SERVFAIL（缓存过期的记录还能临时顶一下），不会自动回退到经代理的 ECS 路径。
- 所有上游都返回截断应答（TC）时，客户端拿到的是 SERVFAIL，而不是可以自己重试的 TC 应答。
