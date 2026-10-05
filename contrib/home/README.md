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
5. （`OPEN_PUBLIC=1`）用 acme.sh 走 DNS 验证签证书，Caddy 在 8443 端口提供 HTTPS DoH，可选 DDNS（只维护这一个域名的 A 记录）。
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

## 局域网监测站（:8788）

`deploy-home.sh` 会顺带装一个监测站（也可单独装/升级：`sudo bash contrib/home/install-monitor.sh`），手机或电脑浏览器打开 `http://<内网IP>:8788`。图表由 **ECharts**（Apache-2.0）渲染，库文件在 `contrib/home/monitor/vendor/` 里随安装复制到本机、由监测站自己提供——**不依赖公网 CDN**，纯内网环境可用；vendor 文件缺失时图表面板会提示加载失败，表格不受影响。

页面按"打开的人想问什么"排序：

1. **健康判定（首屏大字）**：绿"运行正常" / 黄"统计不可用、失败率偏高" / 红"服务不可达、解析异常"，异常时直接给出原因（哪条链路、什么错误）；
2. **解析链路健康 + 核心数字**：国内直连 / GitHub 池 / 境外代理三条链路各自的当前延迟，以及总查询、缓存命中率、回源 P50；
3. **查询量曲线**（近 2 小时每分钟堆叠柱状）与**链路延迟趋势**（每 10 秒真实 DoH 探测）；
4. **诊断区（默认折叠）**：高频域名、最近查询、优选池与规则状态（池子剩余 TTL 少于 30 分钟会标黄）。

探测域名的链路名称默认按域名特征推导（国内大站=国内直连、github=GitHub 池、其余=境外/代理），可用 `MONITOR_PROBE_LABELS`（逗号分隔，与 `MONITOR_PROBE_NAMES` 一一对应）整体覆盖。

- **服务状态**：DoH 可达性、探测延迟、运行时长、内存；
- **查询统计**：总量、每分钟曲线（近 2 小时）、缓存命中率、回源延迟分位数（P50/P90/P99）、失败数；
- **上游解析器**：默认/ECS/国内直连三组各自的成败、平均与峰值延迟、最近一次错误；
- **解析策略**：回源时 direct / preferred-ip / github-pool 等的分布；
- **主动探测**：对几个域名（默认淘宝/GitHub/Google，`MONITOR_PROBE_NAMES` 可改）定期发真实 DoH 查询，看国内直连、GitHub 池、代理出境三条链路是否各自正常；
- **Top 域名 / 最近查询**、**优选池与名单状态**（cfhub 运营商池、GitHub 池、国内域名名单、?safe=1 名单、Meta ECH）。

数据来自主服务新增的 `GET /admin/stats`（`ADMIN_TOKEN` 鉴权）和监测站自己的探测；统计存在内存里，主服务重启后从零开始。

**只在局域网访问**是两层防线：监测站按 TCP 对端地址过滤（只放行回环与私网网段，可 `MONITOR_ALLOW` 覆盖，绝不信任 `X-Forwarded-For` 一类可伪造头）；`SETUP_FIREWALL=1` 时 nftables 只对内网网段放行 8788。`ADMIN_TOKEN` 只存在于监测进程里，页面不带任何凭据。

## 回滚

- 环境变量：脚本每次改 env 前会备份成 `/etc/edge-smart-doh/env.bak-<时间>`，拷回去再 `systemctl restart edge-smart-doh`。
- 防火墙：`/etc/nftables.conf.pre-doh-<时间>` 是替换前的备份，拷回去后 `nft delete table inet home_firewall && nft -f /etc/nftables.conf`。

## 已知限制

- 国内模式不填代理时，脚本只能把国内直连解析器放进 `UPSTREAMS`，被污染的域名一定拿到假 IP，只能临时用。
- 开启分流后，国内直连上游（阿里/腾讯）全挂时国内域名是 SERVFAIL（缓存过期的记录还能临时顶一下），不会自动回退到经代理的 ECS 路径。
- 所有上游都返回截断应答（TC）时，客户端拿到的是 SERVFAIL，而不是可以自己重试的 TC 应答。
