# 运维手册（edge-smart-doh 家用部署）

> 读者：**运维 Agent（AI）优先**，人类可顺读。按本文操作即可完成日常巡检，无需读源码。
> 部署背景见 `contrib/home/README.md`；监控站实现见 `contrib/home/monitor/monitor.mjs` 头注释。
> 所有命令默认在部署机上执行；涉及 root 的用 sudo。本文假设：主服务 :8787、监控站 :8788。

## 1. 系统清单（是什么、在哪）

| 组件 | systemd 单元 | 端口 | 关键文件 |
|---|---|---|---|
| DoH 主服务 | `edge-smart-doh` | 127.0.0.1:8787（Caddy 可再加 8443） | `/opt/edge-smart-doh/node.mjs`、env `/etc/edge-smart-doh/env`、缓存 `/var/lib/edge-smart-doh/cache.bin` |
| 局域网监控站 | `edge-smart-doh-monitor` | 0.0.0.0:8788（仅私网来源放行，公开只读） | `/opt/edge-smart-doh/monitor.mjs`、env `/etc/edge-smart-doh/monitor.env`（含 `ADMIN_TOKEN`，0600） |

历史上的 SNI 中转守护（`edge-smart-doh-relay`）与控制页已随 relay 功能移除；`deploy-home.sh` 检测到旧安装会自动拆除（备份 relay.env 后删除单元与 `RELAY_*` env 键）。

## 2. 能力探测（无凭据）

```bash
curl -s http://127.0.0.1:8788/healthz
# {"ok":true,"uptimeSec":1234}
```

`ok:false` 或连接拒绝 = 监控站进程挂了：`journalctl -u edge-smart-doh-monitor -n 30`。

## 3. 读状态（监控站无任何写端点）

```bash
BASE=http://127.0.0.1:8788   # 监控页 $BASE/ 公开只读

# 监控数据（/api/summary 公开）：健康、路径分布、上游、探测
curl -s $BASE/api/summary | jq '{健康:.doh, 路径:.stats.paths, 上游:.stats.upstreams, 探测:.probes | map({name, ok, latencyMs})}'
```

需要更细的运行指标（Top 域名、最近查询、池状态）时走主服务（`ADMIN_TOKEN` 在 `/etc/edge-smart-doh/env`）：

```bash
TOKEN=$(sudo grep '^ADMIN_TOKEN=' /etc/edge-smart-doh/env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/admin/stats | jq '{queries:.queries, paths:.paths, upstreams:.upstreams, pools:.pools}'
```

**统计口径**：`paths`（ech/pool/cn/direct）只统计**回源**解析，按回源时刻归类；命中缓存的查询单列"缓存应答"。重启主服务后计数清零。

## 4. 验证与排查

```bash
# DNS 侧交叉验证：某域名现在被答成什么、为什么
curl -s "http://127.0.0.1:8787/explain?name=github.com&type=A" | jq -c '{answer:.results[0].answer, steps:.results[0].steps}'

# 服务健康与日志
systemctl status edge-smart-doh edge-smart-doh-monitor --no-pager
journalctl -u edge-smart-doh -n 50 --no-pager           # upstream_trust_warning / upstream_failure 等
journalctl -u edge-smart-doh-monitor -n 50 --no-pager
```

常见问题：

| 症状 | 判定 | 处置 |
|---|---|---|
| 页面"统计不可用"但服务正常 | ADMIN_TOKEN 失配 | 重跑 install-monitor.sh 同步 token |
| 页面"失败率偏高"黄牌 | 最近 1 分钟解析失败 >20% | 看 `upstreams` 谁在失败；代理出口（mihomo）是否挂了 |
| 境外域名解析到假 IP | `UPSTREAMS` 混入了直连上游 | 对照 `README.md` 的信任清单规则修 env，清缓存重启 |

## 5. 升级 / 回滚

```bash
# 升级监控站（幂等；monitor.env 自定义项保留）
sudo bash contrib/home/install-monitor.sh
# 升级主服务（保住在内存的优选池；dist 构建在 deploy-home.sh 内完成）
sudo bash contrib/home/deploy-home.sh
# 只重启主服务并保住池状态：
sudo bash deploy/restart-keep-state.sh
```

env 备份：deploy 脚本每次改 env 前备份到 `/var/backups/edge-smart-doh/`（0700，含密文件 0600）。

## 6. 边界

- 监控站**只读**，没有任何写端点；改配置（上游/ECH/缓存/CN 分流）走 SSH 改 env + restart；
- 不通过 API 启停 systemd 单元；
- 监控站为 LAN HTTP（无 TLS）——"家庭内网可信"假设内的取舍；
- worker（公开实例）没有任何 admin 端点（未设 `ADMIN_TOKEN` 时 `/admin/*` 全部 404）。
