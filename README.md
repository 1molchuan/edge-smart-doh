# Edge Smart DoH

一个 DNS over HTTPS（DoH）服务：浏览器用它解析域名时，**托管在 Cloudflare 上的网站**会拿到两样东西：

1. **实测的优选 IP**：把 Cloudflare 返回的地址换成在国内线路上实测连得快、连得通的 Cloudflare 地址，并且按访问者所在的运营商（电信、联通、移动、教育网、国内云厂商）分别选择；
2. **ECH（加密的客户端问候）**：在 HTTPS 记录里补上 Cloudflare 的 ECH 配置。浏览器握手时，真正要访问的域名被加密，线路上只能看到 `cloudflare-ech.com`。

公开实例：浏览器设置 → 隐私/安全 → 使用安全 DNS → 自定义，填 `https://edge.1molchuan.top/linuxdo`（和 `/dns-query` 是同一个服务）。

- 许可证：AGPL-3.0。修改后作为网络服务提供，也需要公开源码。
- 优选 IP 的众包测速站和探针在另一个仓库：[github.com/1molchuan/cfhub](https://github.com/1molchuan/cfhub)。两者的关系见[下文](#和-cfhub-的关系)。

## 它是什么、不是什么

- 它只改 DNS 应答。**不是代理**：流量仍然由你的电脑直接连到 Cloudflare，不经过这台服务器，也不隐藏你的 IP。
- 优选 IP 和 ECH 只对**托管在 Cloudflare 上**的网站生效；其他网站的应答原样返回。
- ECH 需要浏览器自己用 DoH 查 HTTPS 记录。**必须在浏览器里设置**这个 DoH；只在系统或路由器上设置，浏览器拿不到 HTTPS 记录，也就用不上 ECH。
- 开着按域名分流的代理客户端时，ECH 会让客户端看不到真实域名，分流规则可能失效。

## 一次查询的全过程

`/explain?name=<域名>` 会把下面每一步的判断写出来，并同时给出 A、AAAA、HTTPS 三种记录的实际应答。例如 `https://edge.1molchuan.top/explain?name=linux.do`（结果里有你的 IP，截图记得打码）。

1. **解析请求**：支持 RFC 8484 的 GET（`?dns=`）和 POST。可选参数见[请求参数](#请求参数)。
2. **确定访问者**：Node 版本从 `X-Real-IP`（没有就用 TCP 对端地址）取得客户端 IP，Worker 版本用 `CF-Connecting-IP`。IP 只用来选池和决定 ECS，不写日志、不落盘。
3. **选出这次用的优选池**（见[优选池分层](#优选池分层)）。
4. **查缓存**（见[缓存](#缓存)）。命中就直接返回。
5. **查上游**：同时准备多个上游 DoH（默认 Cloudflare、Google、Quad9）。先问第一个，`UPSTREAM_HEDGE_MS` 毫秒内没回或者失败，就再问下一个，谁先给出合法应答用谁。“合法”指 HTTP 200 + `application/dns-message` + QR 位为响应，且 rcode 是 0（NOERROR）或 3（NXDOMAIN）、TC=0、OPT 记录的扩展 rcode 为 0；SERVFAIL/REFUSED/NOTIMP/截断一律算这次上游失败，交给下一个（否则它会赢下竞速并把并发的可信上游短路掉）。所有上游必须同样可信：竞速只比快慢，一个更快但被污染的上游会一直赢。命中 `ECS_DOMAINS` 的国内域名会带上客户端的 /24（IPv6 为 /48）子网信息（ECS），发给支持 ECS 的上游（`ECS_UPSTREAMS`），这样国内 CDN 能按你的位置返回节点。
6. **应用规则**：`RULES_JSON`、`RULES_URL` 或请求里的 `?rules=` 可以改写或屏蔽某些域名的应答。
7. **判断是不是 Cloudflare**：应答里的地址落在 Cloudflare 公布的网段内（`https://www.cloudflare.com/ips-v4/` 等，每天刷新），就算 Cloudflare。X（Twitter）这类在多家 CDN 之间切换的域名，还会查 `<域名>.cdn.cloudflare.net` 是否存在，以判断 Cloudflare 是否也在服务它。
8. **改写地址**：把应答里所有 Cloudflare 的 A/AAAA 记录换成整个优选池（每个地址族最多 6 个），HTTPS 记录的 `ipv4hint`/`ipv6hint` 同步改掉（Firefox 和 Safari 会直接用这些提示）。
9. **注入 ECH**：HTTPS 类型的查询，如果是 Cloudflare 的网站，就把 `cloudflare-ech.com` 当前发布的 ECH 配置放进 HTTPS 记录（上游没有 HTTPS 记录就补一条）。同时决定 ALPN：只有探针实测"QUIC + ECH 能通"的站点才给 `h3`，否则只给 `h2`，避免浏览器先试一次必然失败的 QUIC。
10. **展平 CNAME**：Chromium 只有在 A/AAAA 和 HTTPS 记录挂在同一个名字下时才会用 ECH，所以对这类站点把 CNAME 链展平到查询的域名上。`/explain` 里的 `chromium` 一项会直接告诉你 Chromium 能不能对这个域名用上 ECH。
11. **返回并缓存**。每次返回前都会轮换 A/AAAA 的顺序，让总是只连第一个地址的客户端分散到整个池子上。

## 优选池分层

每个请求按下面的顺序找池子，**越窄越优先**。IPv4 和 IPv6 分开处理：先取最窄一层的地址，不够 6 个再用下一层补足。

| 顺序 | 池子 | 来源 | 谁会用到 |
|---|---|---|---|
| 1 | 本网段专属池 | 某个探针用 `scope: "client"` 上报，只对和它同一个 /24（IPv6 /48）的访问者生效 | 探针所在网段的用户 |
| 2 | 运营商池 `isp:<运营商>` | cfhub 按运营商投票后推送 | 该运营商的用户 |
| 3 | 全国池 `isp:national` | cfhub 由各运营商池汇总后推送 | 所有人 |
| 4 | 自学习池 | 维护者自己的几台探针分别上报，DoH 用多数投票合并 | 所有人 |
| 5 | 优选域名池 / 静态池 | 解析 `CF_PREFERRED_DOMAIN`（社区维护的优选域名）得到的地址，或 `CF_PREFERRED_IPV4/IPV6` | 以上都没有时 |

几点细节：

- **每层都会过期**。探针或 cfhub 停止上报后，对应的池子在 TTL 到期后自动失效，请求自然退回下一层，解析不会中断。
- **自学习池的合并规则**（`combineRankings`，`src/preferred.ts`）：一个 IP 要有**严格过半**的探针认可才入选（两台里两台、三台里两台）；认可的探针越多越靠前，其次看平均排名；同一个 /24（IPv6 /48）最多入选 2 个，防止一整段被封时池子被清空。认可的 IP 少于 2 个时，改为把各探针的列表交错合并。
- **一个池子对应一个缓存分区**：用了专属池或运营商池的应答，缓存键里带着池子的名字，不同运营商的用户不会拿到彼此的缓存。
- 请求显式带了 `?ip4=`、`?ip6=` 或 `?cf=` 时，不使用上面的第 1～4 层。

## ECH

- **ECH 配置**：Cloudflare 所有网站共用一份 ECH 公钥，发布在 `cloudflare-ech.com` 的 HTTPS 记录里。DoH 查询并缓存它，注入到每个 Cloudflare 网站的 HTTPS 应答中。Cloudflare 轮换密钥时，浏览器握手会收到新的配置（`retry_configs`），DoH 缓存过期后也会取到新的。
- **什么时候给 h3**：探针（`echprobe -h3check`）定期对 DoH 返回的地址做 QUIC + ECH 握手，并按站点上报结果。只有**所有**上报的探针都说能通时，这个站点才会得到 `h3`。结论会过期，过期后回到默认值。
- **Meta（Facebook、Instagram 等）**：Meta 不在 DNS 里发布 ECH 配置，所以 `META_ECH_CONFIG_BASE64` 是一个种子配置。Meta 轮换密钥后，探针能从握手失败的 `retry_configs` 里拿到新配置，推给 `/admin/health`，DoH 改用新配置；拿不到时暂停注入，以免浏览器拿着必定失败的配置去连。

## 特殊处理

- **站点池**（`/admin/site`）：探针测速只测到 Cloudflare 边缘节点的握手，看不到"边缘节点能不能连上网站源站"。实际遇到过：某个 Cloudflare 机房连不上某网站的源站，经过这个机房的请求一直卡住，而同一网站走其他机房几百毫秒就返回。站点检查探针（`echprobe -sitecheck`）会通过普通优选池真实地抓取网站的几个小页面；卡住的比例过高时，它另外找端到端验证过的 IP 上报。之后这个网站的 A 记录固定为这些 IP（去掉 IPv6，HTTPS 记录的地址提示也同步），ECH 照常保留。普通池恢复后，下一次上报不再包含这个网站，覆盖自动撤销。
- **GitHub**（`GITHUB_DOMAINS`、`/admin/github`）：GitHub 没有 ECH，在国内的问题是某些 IP 连不上。探针从社区 hosts 源取候选地址，按主机逐个验证（校验证书的普通 TLS），每个主机得到自己的池子，应答固定为这些地址（去掉 IPv6）。
- **X（Twitter）**（`X_DOMAINS`）：X 的域名会在 Cloudflare 和 Fastly 之间切换，还有少数只在 X 自己的网络上。只有确认由 Cloudflare 服务的才改写，并且**不返回 AAAA**：X 对通过 IPv6 到达的请求会返回 403。

## 和 cfhub 的关系

cfhub 是一个众包测速站：志愿者在自己的线路上运行探针 `cfprobe`，测完上报；cfhub 按线路类别投票，得出每个运营商的优选池。**这个 DoH 是 cfhub 投票结果的使用者。**

```
志愿者的 cfprobe ──每小时上报──▶ cfhub ──每 5 分钟推送──▶ 本 DoH ──按访问者运营商返回──▶ 浏览器
 （各自的家宽、校园网、                  │  POST /admin/preferred
   云服务器）                           │  scope = isp:<运营商> / isp:national
                                        │  HUB_TOKEN，有效期 30 分钟
                                        └──运营商 IP 表──▶ ISP_TABLE_URL（DoH 每 10 分钟刷新）
```

- **判断访问者的运营商**：DoH 从 `ISP_TABLE_URL` 拉取"网段 → 运营商"表（每行 `<运营商> <CIDR>`）。cfhub 每天根据 [china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 和国内云厂商各自自治系统（ASN）宣告的网段（来自 RIPEstat）生成这张表。DoH 在内存里二分查找，同一个 IP 命中多个网段时取最精确的那个。
- **推送什么**：cfhub 每 5 分钟把已发布的运营商池（`isp:chinanet`、`isp:unicom`、`isp:cmcc`、`isp:cernet`、`isp:cloud`）和全国池（`isp:national`）推给 DoH，每次有效期 30 分钟。
- **全国池**：由已发布的各运营商池合并而成，每条线路算一票，被越多线路认可的 IP 越靠前；至少 2 条线路发布后才生成。它服务所有使用默认池的访问者，排在维护者自己的自学习池前面。
- **cfhub 能做什么、不能做什么**：`HUB_TOKEN` **只能写运营商池**（`scope` 必须是 `isp:<名字>`），不能读取 DoH 的状态，也不能改自学习池、专属池、站点池。DoH 收到运营商池后会**再检查一遍**每个 IP 是否在 Cloudflare 公布的网段内，不在就整批拒绝。所以即使 cfhub 被人控制，也只能在 Cloudflare 自己的地址里挑，没法把用户引到别人的服务器上。
- **cfhub 挂了会怎样**：运营商池和全国池 30 分钟后过期，用户退回维护者的自学习池和优选域名池，解析不中断。DoH 重启后，这些池子会在 cfhub 下一次推送时（最多 5 分钟）恢复；`deploy/restart-keep-state.sh` 可以在重启前保存、重启后立即写回。
- **投票规则**（防投毒）写在 cfhub 仓库的 `cfhub/aggregate.go`：只收 Cloudflare 网段内的 IP；一个网段只算一票；一个人在一个池里最多算 5 台探针；进池的 IP 要超过半数探针认可、且至少来自 2 个不同的人；一条线路至少 2 个人参与才发布。
- 不接 cfhub 也能单独运行：不设置 `HUB_TOKEN` 和 `ISP_TABLE_URL`，就只用第 1、4、5 层。

## 维护者自己的探针

自学习池、站点池、GitHub 池、h3 结论和 Meta 密钥都来自探针。探针是 `echprobe`（源码在 [cfhub 仓库](https://github.com/1molchuan/cfhub) 的 `echprobe/`，志愿者用的 `cfprobe` 就是它），用 `ADMIN_TOKEN` 上报。`deploy/prober/` 里是 systemd 定时任务和 Windows 计划任务的模板：

| 任务 | 做什么 | 上报到 |
|---|---|---|
| `echprobe-report` / `report6` | 对候选 Cloudflare IP 做 ECH 握手测速（IPv4 / IPv6），上报通过的 IP 及排名 | `/admin/preferred` |
| `echprobe-sitecheck` | 通过优选池真实抓取网站页面，卡住太多时上报端到端可用的 IP | `/admin/site` |
| `echprobe-github` | 按主机验证 GitHub 的候选 IP | `/admin/github` |
| `echprobe-h3` | 对各站点测 QUIC + ECH 能否握手 | `/admin/h3` |
| `echprobe-meta` | 检查 Meta 的 ECH 种子配置是否还有效，失效时取回新配置 | `/admin/health` |
| `echprobe-selfcheck` | 检查一组域名的应答能否让 Chromium 用上 ECH | `/admin/selfcheck` |

配置见 `deploy/prober/env.example`，安装脚本是 `deploy/prober/install.sh`（Linux）和 `deploy/prober/windows/install.ps1`。

## 缓存

- 缓存键是规范化后的查询（域名小写、去掉事务 ID）加上影响应答的因素：使用的池子、ECS 子网、请求参数、h3 结论和站点池的版本。
- TTL 限制在 `CACHE_MIN_TTL`～`CACHE_MAX_TTL` 之间，否定应答最多 `NEGATIVE_CACHE_MAX_TTL`。
- **预取**：剩余 TTL 低于原 TTL 的 `CACHE_PREFETCH_PERCENT`% 时，先返回缓存，再在后台刷新。
- **过期仍可用**（RFC 8767）：所有上游都失败时，`CACHE_STALE_TTL` 内的过期应答比 SERVFAIL 好。HTTPS 记录更进一步：只要有缓存就立即返回再后台刷新，因为 Chromium 在拿到 A/AAAA 后只等 HTTPS 记录约 50 毫秒，超时就不用 ECH 直接连了。
- Node 版本的缓存在内存里（最多 `CACHE_MAX_ENTRIES` 条），设置 `CACHE_PERSIST_PATH` 后每 5 分钟和退出时写盘，启动时读回。

## 隐私

- 默认不记录任何查询。`DEBUG=true` 时记录缓存命中、上游和耗时；再加 `LOG_QUERIES=true` 才会记录查询的域名。
- 客户端 IP 只在处理请求的过程中使用：选运营商池、选专属池、生成 ECS 子网（只用 /24 或 /48）。不写日志，不落盘。
- 缓存里存的是 DNS 应答，缓存键可能包含 /24（/48）子网（ECS 查询）或池子的名字，不包含完整 IP。
- `/explain` 会把你的 IP 显示给你自己看。

## 接口

| 路径 | 说明 |
|---|---|
| `/dns-query` | RFC 8484 DoH，GET（`?dns=`）或 POST |
| `/explain?name=<域名>[&type=A\|AAAA\|HTTPS]` | 这个域名现在的应答、每一步的判断、Chromium 能否用上 ECH |
| `/health` | 存活检查 |
| `/probe` | 服务端看到的客户端 IP 和部署信息 |
| `/admin/preferred` | GET：全部池子的状态（需 `ADMIN_TOKEN`）。POST `{ipv4, ipv6, ttl, source, scope}` 写入池子，`scope` 为 `default`（自学习池的一个来源）、`client`（上报者自己网段的专属池）或 `isp:<名字>`（运营商池，`HUB_TOKEN` 只能写这一种） |
| `/admin/site`、`/admin/github` | POST `{source, ttl, hosts: {主机: [IPv4]}}`，需 `ADMIN_TOKEN` |
| `/admin/h3` | POST `{source, ttl, verdicts: {主机: true\|false}}`，需 `ADMIN_TOKEN` |
| `/admin/health` | Meta ECH 的状态上报，需 `ADMIN_TOKEN` |
| `/admin/selfcheck` | 自检结果上报，需 `ADMIN_TOKEN` |

没有设置 `ADMIN_TOKEN` 时，所有 `/admin/*` 都返回 404。令牌用常数时间比较。

### 请求参数

`/dns-query` 和 `/explain` 都接受：

- `?cf=<域名>`：用这个域名解析出的地址作为优选池；
- `?ip4=a,b&ip6=c,d`：直接指定优选地址（每种最多 16 个）；
- `?ech=<域名>`：从这个域名的 HTTPS 记录取 ECH 配置；
- `?rules=<URL>`：加载一份规则（只允许 `DYNAMIC_RULE_HOSTS` 里的主机）；
- `?safe=1`：拦截广告和诈骗网站，详见下文。

### 广告和诈骗拦截（`?safe=1`）

在 DoH 地址后加上 `?safe=1`（例如 `https://<你的域名>/dns-query?safe=1`），就会拦截 `SAFE_LIST_URLS` 名单里的域名，默认不开启。

- **名单格式**：每行一个域名，同时拦截它的所有子域名。支持纯域名、hosts 格式（`0.0.0.0 example.com`）、adblock 格式（`||example.com^`，带 `$` 选项的规则会被跳过）和 `*.example.com`；`@@||example.com^` 是例外，表示放行。
- **加载**：名单在后台下载，每天更新一次，下载期间不影响查询。名单必须全部下载成功才会替换旧表，第一次加载完成之前不拦截任何域名。
- **被拦截的域名**：返回 NXDOMAIN，并附带一条 SOA（负缓存 600 秒），让 App 缓存这个结果，不会一直重试。
- **误拦**：把域名加进 `SAFE_ALLOW`（同样包括它的子域名），不用重新加载名单。
- **只拦截名单里的域名**：其他查询的结果和不加 `safe=1` 时完全一样，两者共用缓存。
- **效果边界**：能拦第三方广告 SDK（开屏、弹窗广告）、网页里的第三方广告和恶意网站。和正常内容来自同一个域名的广告（比如短视频或社交 App 里的信息流广告）拦不了。
- `/explain?name=<域名>&safe=1` 会显示命中了名单里的哪一条。

## 部署

### Node.js + Caddy（推荐，公开实例就是这种）

```bash
npm ci
npm run build:node                      # 生成 dist/node.mjs，单文件，无依赖
sudo useradd --system --no-create-home edge-smart-doh
sudo install -D -m 0644 dist/node.mjs /opt/edge-smart-doh/node.mjs
sudo install -D -m 0600 deploy/edge-smart-doh.env.example /etc/edge-smart-doh/env   # 然后按需修改
sudo install -m 0644 deploy/edge-smart-doh.service /etc/systemd/system/
sudo systemctl enable --now edge-smart-doh
```

Caddy 配置见 `deploy/Caddyfile`：直连时用 TCP 对端地址覆盖 `X-Real-IP`，客户端无法冒充别的网络；DoH 重启的一两秒内请求会等待而不是返回 502。需要 Node.js 18 以上。

改配置后用 `deploy/restart-keep-state.sh` 重启：它先把探针和 cfhub 推送的池子读出来，重启后立即写回，避免重启后到下一次上报前只能用优选域名池。

### 在家里部署（社区贡献）

家宽或国内小机上自用：`contrib/home/` 里有 [@liyu34](https://github.com/liyu34) 贡献的一键部署脚本和说明（代理出境、证书、DDNS、同步 cfhub 优选池）。在国内部署时上游必须全部经代理出境，原因见 [contrib/home/README.md](contrib/home/README.md)。

### Cloudflare Worker

`npm run deploy`（wrangler），变量写在 `wrangler.jsonc`，令牌用 `wrangler secret put ADMIN_TOKEN`。细节见 `docs/cloudflare.md`。注意：Worker 自己运行在 Cloudflare 上，大陆访问 Worker 本身的速度就取决于 Cloudflare 的线路。

### EdgeOne

`npm run build:edgeone` 生成边缘函数，见 `docs/edgeone.md`。

## 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `UPSTREAMS` | Cloudflare、Google、Quad9 | 上游 DoH，逗号分隔，只接受 https |
| `ECS_UPSTREAMS` | 同 `UPSTREAMS` | 带 ECS 的查询用的上游，应只放会转发 ECS 的解析器 |
| `UPSTREAM_TIMEOUT_MS` | 2500 | 单次上游超时 |
| `UPSTREAM_HEDGE_MS` | 100 | 多久没回就并发问下一个上游，0 表示不并发 |
| `CACHE_MIN_TTL` / `CACHE_MAX_TTL` | 30 / 3600 | 缓存 TTL 的上下限（秒） |
| `NEGATIVE_CACHE_MAX_TTL` | 300 | 否定应答最多缓存多久 |
| `CACHE_STALE_TTL` | 86400 | 过期应答在上游全挂时还能用多久，0 关闭 |
| `CACHE_PREFETCH_PERCENT` | 10 | 剩余 TTL 低于这个百分比时后台刷新，0 关闭 |
| `ECS_MODE` | `rules` | `off`、`always`，或 `rules`（只对 `ECS_DOMAINS` 和规则指定的域名） |
| `ECS_DOMAINS` | `.cn` | 带 ECS 的域名后缀 |
| `ECS_IPV4_PREFIX` / `ECS_IPV6_PREFIX` | 24 / 48 | ECS 子网长度 |
| `ECS_DOMAIN_LIST_URLS` | 空 | 国内网站域名名单（如 Loyalsoldier 的 `direct-list.txt`），名单里的域名和 `ECS_DOMAINS` 一样带 ECS 走 `ECS_UPSTREAMS`，拿到国内 CDN 节点；每天更新 |
| `ECS_FALLBACK_SUBNET` | 空 | 访客 IP 不属于任何国内运营商时（通常是 DoH 查询走了境外代理），ECS 改用这个国内子网，避免国内网站返回海外 CDN。需要配置 `ISP_TABLE_URL` |
| `CF_REWRITE_ENABLED` | false | 有池子时会自动开启，一般不用设 |
| `CF_PREFERRED_DOMAIN` | 空 | 优选域名，解析出的地址合并为第 5 层池子 |
| `CF_PREFERRED_IPV4` / `CF_PREFERRED_IPV6` | 空 | 静态优选地址 |
| `CF_DROP_AAAA` | false | 改写后去掉 AAAA（给 IPv6 不通的网络） |
| `CF_IPV4_URL` / `CF_IPV6_URL` | Cloudflare 官方列表 | Cloudflare 网段来源 |
| `ADMIN_TOKEN` | 空 | 管理接口令牌，空则关闭 `/admin/*` |
| `HUB_TOKEN` | 空 | cfhub 的令牌，只能写运营商池 |
| `ISP_TABLE_URL` | 空 | 运营商 IP 表，空则不分运营商 |
| `ECH_ENABLED` | false | 是否注入 ECH |
| `ECH_SOURCE_DOMAIN` | `cloudflare-ech.com` | 从哪个域名的 HTTPS 记录取 ECH 配置 |
| `ECH_CONFIG_BASE64` / `ECH_DOMAINS` | 空 | 给指定域名注入固定的 ECH 配置 |
| `META_ECH_CONFIG_BASE64` / `META_DOMAINS` | 空 / Meta 的域名 | Meta 的 ECH 种子配置及其适用域名 |
| `X_DOMAINS` | X 的域名 | 按多 CDN 方式判断、不返回 AAAA 的域名 |
| `GITHUB_DOMAINS` | 空 | 使用按主机优选池的 GitHub 域名 |
| `SAFE_LIST_URLS` | 空 | `?safe=1` 使用的拦截名单，逗号分隔，空则关闭这个功能 |
| `SAFE_ALLOW` | 空 | `?safe=1` 永不拦截的域名（包括子域名） |
| `RULES_JSON` / `RULES_URL` | `[]` / 空 | 应答规则 |
| `DYNAMIC_RULE_HOSTS` / `DYNAMIC_RULES_MAX_BYTES` | paste.rs 等 / 262144 | `?rules=` 允许的主机和大小上限 |
| `MAX_DNS_PACKET_SIZE` | 4096 | 请求和上游应答的大小上限 |
| `DEBUG` / `LOG_QUERIES` | false | 见[隐私](#隐私) |
| `EDGEONE_CLIENT_IP_HEADER`、`DOH_ORIGIN_TOKEN` | — | Worker 放在 EdgeOne 后面时，从哪个请求头取真实 IP，以及信任它所需的令牌 |

只在 Node 版本中有效：`HOST`、`PORT`（默认 127.0.0.1:8787）、`PUBLIC_HOSTNAMES`（只接受这些 Host，其他返回 421）、`CACHE_MAX_ENTRIES`、`CACHE_PERSIST_PATH`。

## 开发

```bash
npm ci
npm test            # vitest
npm run typecheck   # Worker、Node、tools 三套 tsconfig，以及 wrangler 生成的类型
npm run build:node
```

`tools/benchmark/` 是测量 DoH 延迟的脚本，方法见 `docs/benchmark.md`。
