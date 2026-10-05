# 在家里部署（社区贡献）

> 脚本和测量数据来自 [@liyu34](https://github.com/liyu34)（PR #1），在 Debian 13 + 家宽 + 本地代理出境的环境里实际跑通。这是社区贡献的部署方式，公开实例用的是仓库根目录 README 里的 Node.js + Caddy 方案。

适合：在家里的小主机、NAS 或国内小机上搭一个只给自己用的 DoH，用 cfhub 的优选池给 Cloudflare 网站换 IP、补 ECH。

## 先理解一件事：在国内，上游必须全部走代理

国内直连的解析器（阿里、腾讯等）对被污染的域名会返回假 IP，而且返回得很快。DoH 查上游是**竞速**的（先问第一个，`UPSTREAM_HEDGE_MS` 毫秒内没回再加问下一个，谁先回用谁），所以只要 `UPSTREAMS` 里混进一个直连的国内解析器，它就几乎每次都赢。作者实测（`UPSTREAM_HEDGE_MS=50`）：

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

国内网站要拿到国内 CDN 节点靠的是 ECS，而不是国内解析器：`dns.google` 会转发 ECS，经代理查询照样按你的 /24 返回国内节点（作者实测 `www.taobao.com` 拿到的节点和直连阿里 DNS 相同）。所以脚本在国内模式下把 `ECS_UPSTREAMS` 也只设成 `dns.google`（Cloudflare 不转发 ECS，不能放进去）。代价：Google 按 ECS 选节点没有国内解析器细；代理挂了时全部解析都会失败（缓存过期的记录还能临时顶一下），不会出现"国内网站还能解析"的半可用状态。

## 脚本做了什么

`sudo bash contrib/home/deploy-home.sh`，可以反复运行（幂等）。第一次运行会问域名、代理地址、邮箱等，答案存到 `/etc/edge-smart-doh/deploy.conf`（root 0600），之后不再问。

1. 装依赖，构建 `dist/node.mjs`，安装成 systemd 服务（`ADMIN_TOKEN` 自动生成，重跑不换）。
2. 国内模式：给服务加代理。Node 自带的 `fetch` 不认 `HTTP_PROXY`，脚本装 `undici@6` 并用 `--import` 预加载 `EnvHttpProxyAgent`。**固定 6.x**：undici 8 需要 Node ≥ 22.19，在 Node 20 上一启动就崩；脚本在重启服务前会先试加载一次，不兼容就停下报错，不会让服务陷入重启循环。
3. 每 5 分钟从 cfhub 的公开接口（`/api/v1/pools`）同步各运营商的优选池到本机 DoH。
4. （`OPEN_PUBLIC=1`）用 acme.sh 走 DNS 验证签证书，Caddy 在 8443 端口提供 HTTPS DoH，可选 DDNS（只维护这一个域名的 A 记录）。
5. （`SETUP_FIREWALL=1`，默认关）用 nftables 收紧入站。**会整体替换 `/etc/nftables.conf`，入站默认丢弃**，只放行 SSH、mosh、DoH；NAS 或还跑着别的服务的机器上会把它们挡掉，确认后再开。替换前会备份原文件。

脚本做不了、需要你自己做的：路由器把外网 8443/TCP 转发到这台机器；用手机流量从外网验证一次。

主要选项在脚本开头的配置区：`DEPLOY_ENV`（`cn` 走代理 / `overseas` 直连）、`PROXY_ADDR`、`OPEN_PUBLIC`、`SETUP_DDNS`、`SETUP_FIREWALL`、`SKIP_BUILD`。

## 验证

```bash
# 没有混合信任告警
journalctl -u edge-smart-doh -n 30 --no-pager | grep -i upstream_trust_warning || echo "OK：无告警"

# 上游配置
sudo grep -E '^(UPSTREAMS|ECS_UPSTREAMS)=' /etc/edge-smart-doh/env

# 上游应该是 cloudflare/google，答案是干净的 Cloudflare 地址，最终换成优选池
curl -s "http://127.0.0.1:8787/explain?name=linux.do&type=A" | jq -c '{steps:.results[0].steps}'
```

之前跑过混了直连上游的配置，要清掉被污染的缓存：

```bash
sudo systemctl stop edge-smart-doh
sudo mv /var/lib/edge-smart-doh/cache.bin /var/lib/edge-smart-doh/cache.bin.polluted-$(date +%F)
sudo systemctl start edge-smart-doh
```

## SNI 中转（GitHub 族域名，可选）

直连 GitHub 的 SNI 级抖动（时好时坏）是数据面问题，DNS 答案再准也治不了。中转是给系统补的数据面杠杆：把网卡的**第二个内网 IP**（如 192.168.1.250）答给名单域名，本机 relay 进程在该 IP 的 443 上读 TLS ClientHello 的 SNI，把 TCP 流经代理（HTTP CONNECT）转给真实目标——**TLS 端到端，relay 绝不终结**，客户端看到的证书仍是真 GitHub 的。设计与完整方案见 `contrib/home/relay/DESIGN.md`。

三档 `RELAY_MODE`（主 env）：

| 档 | 语义 |
|---|---|
| `off` | 关闭（默认，代码路径不激活） |
| `auto` | 按主机健康门控：relay 每 3 分钟直连实测池 IP 握手，某主机 15 分钟内成功率 <50% 切中转，30 分钟内 >80% 切回直连 |
| `always` | 名单内域名无条件走中转 |

域名集合独立于档位：`RELAY_DOMAINS`（支持 `*.github.com` 通配）+ `RELAY_EXCLUDE_DOMAINS`（排除优先，默认排掉无 SNI 的 `ssh.github.com`）。HTTPS RR 会同步清洗（hint 指向中转 IP、删 ECH、ALPN 压 h2），AAAA 答空，TTL 压到 60。

启用：`deploy-home.sh` 配置区设 `RELAY_ENABLED=1` 重跑（会问第二 IP 并持久化，自动装 `edge-smart-doh-relay.service`、生成最小权限的 `/etc/edge-smart-doh/relay.env`、种好 `RELAY_MODE=auto`）。两个前置认知：

- **防回环靠"按实测池 IP 拨号"**：relay 拨号用 `/admin/pool` 给的池 IP，不经 DNS，从根上避免"解析到中转 IP→连到自己"。仅池空时按域名 CONNECT，此时依赖代理配置里的 `DOMAIN-SUFFIX,github.com,<代理组>` 规则远程解析——装完用 `curl -x <代理> -sI https://github.com` 验证一次。
- **降级不变量**：relay 挂了/代理挂了 → 健康上报停止 → DNS 在 TTL 内回退直连路径，最坏情况 = 没装中转。`RELAY_IP` 只接受私网地址，服务端直接拒绝公网值。

服务端侧的 `GET /admin/relay`（档位、健康、每主机直连成功率与是否走中转）与 `/admin/health` 的 `pools.relay` 已经能看到中转状态；监测站首页的中转卡片/"中转离线"黄牌属于监测站那个 PR（`GET /admin/stats` + `contrib/home/monitor`），本 PR 不含。代价要想清楚：走中转的流量吃代理节点的带宽。回滚：`RELAY_MODE=off` 重启主服务（或 `systemctl disable --now edge-smart-doh-relay`），60 秒内收敛。

## 回滚

- 环境变量：脚本每次改 env 前会备份成 `/etc/edge-smart-doh/env.bak-<时间>`，拷回去再 `systemctl restart edge-smart-doh`。
- 防火墙：`/etc/nftables.conf.pre-doh-<时间>` 是替换前的备份，拷回去后 `nft delete table inet home_firewall && nft -f /etc/nftables.conf`。

## 已知限制

- 国内模式不填代理时，脚本只能把国内直连解析器放进 `UPSTREAMS`，被污染的域名一定拿到假 IP，只能临时用。
- 所有上游都返回截断应答（TC）时，客户端拿到的是 SERVFAIL，而不是可以自己重试的 TC 应答。
