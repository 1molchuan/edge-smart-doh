# 运维手册（edge-smart-doh 家用部署）

> 读者：**运维 Agent（AI）优先**，人类可顺读。按本文操作即可完成日常巡检与中转控制，无需读源码。
> 部署背景见 `contrib/home/README.md`；控制台设计见 `contrib/home/monitor/PRD-console.md`。
> 所有命令默认在部署机上执行；涉及 root 的用 sudo。本文假设：主服务 :8787、控制台 :8788。

## 1. 系统清单（是什么、在哪）

| 组件 | systemd 单元 | 端口 | 关键文件 |
|---|---|---|---|
| DoH 主服务 | `edge-smart-doh` | 127.0.0.1:8787（Caddy 可再加 8443） | `/opt/edge-smart-doh/node.mjs`、env `/etc/edge-smart-doh/env`、缓存 `/var/lib/edge-smart-doh/cache.bin` |
| 控制台（监测+控制） | `edge-smart-doh-monitor` | 0.0.0.0:8788（仅私网来源放行） | `/opt/edge-smart-doh/monitor.mjs`、env `/etc/edge-smart-doh/monitor.env`（含 `CONSOLE_PASSWORD`、`ADMIN_TOKEN`，0600） |
| SNI 中转守护 | `edge-smart-doh-relay` | 第二内网 IP:443 | `/opt/edge-smart-doh/relay.mjs`、env `/etc/edge-smart-doh/relay.env` |
| 第二 IP 持久化 | `edge-smart-doh-relay-ip` | — | oneshot，开机补 `ip addr add` |

控制台的运行时覆盖（档位/域名名单）持久化在 `/var/lib/edge-smart-doh/relay-config.json`；主服务重启后自动恢复。

## 2. 能力探测（无凭据）

```bash
curl -s http://127.0.0.1:8788/healthz
# {"ok":true,"uptimeSec":1234,"authRequired":true,"control":true}
```

- `authRequired:false` = 未设密码（纯监测模式，无控制能力；重跑 install-monitor.sh 补密码）；
- `authRequired:true, control:false` = 设了密码但缺 ADMIN_TOKEN（修 monitor.env 后 restart）；
- `ok:false` 或连接拒绝 = 控制台进程挂了：`journalctl -u edge-smart-doh-monitor -n 30`，应急通道见 §6。

## 3. 控制台 API（默认通道，:8788 + 会话 cookie）

**登录**（密码在 `/etc/edge-smart-doh/monitor.env`；Agent 约定带 `label`，审计里可区分人机）：

```bash
BASE=http://127.0.0.1:8788
PASS=$(sudo grep '^CONSOLE_PASSWORD=' /etc/edge-smart-doh/monitor.env | cut -d= -f2)
curl -s -c /tmp/cj -H 'Content-Type: application/json' \
  -d "{\"password\":\"$PASS\",\"label\":\"ops-agent\"}" $BASE/api/login   # 204=成功
```

失败语义：401=密码错（响应含剩余次数）；连续 5 次后 429（含 `retryAfterSec`，冷却 60s）；任何 `/api/*` 401=会话过期，重新登录即可。

**读状态**：

```bash
curl -s -b /tmp/cj $BASE/api/summary | jq '{健康:.doh, 路径:.stats.paths, relay:.stats.pools.relay}'
curl -s -b /tmp/cj $BASE/api/relay | jq '.relay | {mode, modeSource, domains, excludes, configVersion, appliedConfigVersion, healthy, lastReportAt}'
```

**改配置**（`POST /api/relay-config`，未出现的字段不修改）：

```bash
# 切档位（off | auto | always）
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' \
  -d '{"mode":"auto"}' $BASE/api/relay-config
# 改名单（整体替换该字段；支持 精确域名 / *.通配；排除优先）
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' \
  -d '{"domains":["*.github.com","*.githubusercontent.com"],"excludeDomains":["ssh.github.com"]}' \
  $BASE/api/relay-config
# 带 expectedVersion=读到的 configVersion 防并发覆盖（不符会 409，刷新后重试）
# 恢复 env 默认（清掉运行时覆盖）
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' -d '{"reset":true}' $BASE/api/relay-config
```

响应的 `relay.modeSource`：`env`=来自 env 文件，`override`=控制台覆盖中。成功返回 `{ok, changed, relay:{...}}`。

**审计**：`curl -s -b /tmp/cj $BASE/api/audit | jq '.entries[-10:]'`（时间/来源 IP/label/动作/结果）。

## 4. 语义速查

**三档 `RELAY_MODE`**：

| 档 | 语义 | 何时用 |
|---|---|---|
| `off` | DNS 不再把名单域名答成中转 IP；relay 进程继续跑（无害） | 怀疑中转引起问题时；回到"昨天的系统" |
| `auto`（默认推荐） | 每主机健康门控：直连 15 分钟成功率 <50% 切中转，30 分钟 >80% 切回；relay 挂则立即全部回直连 | 常态 |
| `always` | 名单内无条件中转（不看健康） | 直连长期很差时；**代价：这些站点的全部流量吃代理节点带宽** |

**生效时序（三层）**：改档位/删域名 → 新 DNS 答案即刻生效，存量客户端 ≤60s 收敛（中转答案 TTL≤60）；**新增域名** → relay 进程 ≤30s 才拿到新名单（同步前该域名的连接会被 relay 拒连，等 `appliedConfigVersion` 追平再用）。

**同步判据**：`configVersion` ≥ `appliedConfigVersion`（且 `healthy:true`）= 名单已同步。`healthy:false` 或 `lastReportAt` 停更 = relay 守护/代理出口故障，DNS 已自动回退直连。

**校验规则（服务端强校验，400 附原因）**：域名条目仅支持 精确域名 / `*.通配`；单名单 ≤64 条；ECH 域名（ECH/META/X 名单内）会被拒绝（中转读 SNI，ECH 加密 SNI，天然冲突）；`mode≠off` 且未部署（RELAY_IP 缺失/非私网）会 400 而不是静默降级。

**统计口径**：`paths`（relay/ech/pool/cn/direct）只统计**回源**解析，按回源时刻归类；命中缓存的查询单列"缓存应答"。重启主服务后计数清零。

## 5. 危险动作约定（Agent 必读）

1. 切 `always` 前必须先读 `/api/relay` 确认名单条数，并在结果中向主人说明带宽代价；
2. 新增域名后必须等 `appliedConfigVersion` 追平（≤30s）才算完成，并提醒"同步前该域名连不上是预期"；
3. 无实测池的新域名依赖代理的 `DOMAIN-SUFFIX` 规则远程解析——添加非 GitHub 族域名前验证：`curl -x <代理地址> -sI https://<域名>`；
4. 主服务不可达时禁止重试写操作超过 2 次，转 §6 应急通道或 systemd 检查；
5. 所有写操作成功后，用 `GET /api/relay`（或 `/explain`，见 §7）交叉验证一次再回报。

## 6. 应急通道（控制台不可达时，本机 root 直连主服务）

```bash
TOKEN=$(sudo grep '^ADMIN_TOKEN=' /etc/edge-smart-doh/env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/admin/relay | jq .relay
curl -s -H "Authorization: Bearer $TOKEN" -X POST -H 'Content-Type: application/json' \
  -d '{"mode":"off"}' http://127.0.0.1:8787/admin/relay-config | jq .relay
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/admin/stats | jq '{queries:.queries, paths:.paths, upstreams:.upstreams}'
```

与控制台的差异：绕过了控制台的会话/审计（操作只记在主服务 journal 的 `relay_config_updated` 行），API 语义完全相同。

## 7. 验证与排查

```bash
# DNS 侧交叉验证：github.com 现在被答成什么、为什么（relay 生效时 A=中转 IP、TTL≤60、HTTPS RR 无 ECH）
curl -s "http://127.0.0.1:8787/explain?name=github.com&type=A" | jq -c '{answer:.results[0].answer, steps:.results[0].steps}'
curl -s "http://127.0.0.1:8787/explain?name=github.com&type=HTTPS" | jq -c '{answer:.results[0].answer}'

# 服务健康与日志
systemctl status edge-smart-doh edge-smart-doh-monitor edge-smart-doh-relay --no-pager
journalctl -u edge-smart-doh -n 50 --no-pager           # relay_config_updated / upstream_failure / relay_config_warning
journalctl -u edge-smart-doh-relay -n 50 --no-pager     # config_applied / self_check / listening
journalctl -u edge-smart-doh-monitor -n 50 --no-pager   # console_audit（操作审计的另一份记录）

# 名单热同步验证：改名单后 ≤30s 应出现
journalctl -u edge-smart-doh-relay --since '-2 min' --no-pager | grep config_applied
```

常见问题：

| 症状 | 判定 | 处置 |
|---|---|---|
| 控制台"中转离线"黄牌 | `relay.healthy:false` 或 lastReportAt 停更 | `journalctl -u edge-smart-doh-relay`；常见为代理出口挂了（mihomo）|
| 切档返回 409 | 其他会话改过配置 | 重新 GET 读 version 再提交 |
| 切 always 返回 400 "RELAY_IP" | 未部署中转 | `RELAY_ENABLED=1` 重跑 deploy-home.sh |
| 加域名返回 400 "ECH" | 与 ECH 名单冲突 | 不加该域名，或确认可以接受（v1 不支持，见 PRD §7） |
| 页面"统计不可用"但服务正常 | ADMIN_TOKEN 失配 | 重跑 install-monitor.sh 同步 token |

## 8. 升级 / 轮换 / 回滚

```bash
# 升级控制台（幂等；monitor.env 自定义项与已有密码保留）
sudo bash contrib/home/install-monitor.sh
# 升级主服务（保留运行时覆盖与池状态；dist 构建在 deploy-home.sh 内完成）
sudo bash contrib/home/deploy-home.sh
# 只重启主服务并保住在内存的优选池：
sudo bash deploy/restart-keep-state.sh

# 轮换控制台密码（所有会话随进程重启失效）
sudo sed -i "s/^CONSOLE_PASSWORD=.*/CONSOLE_PASSWORD=$(openssl rand -hex 10)/" /etc/edge-smart-doh/monitor.env
sudo systemctl restart edge-smart-doh-monitor

# 回滚控制台到纯监测形态（去掉密码）
sudo sed -i '/^CONSOLE_PASSWORD=/d' /etc/edge-smart-doh/monitor.env && sudo systemctl restart edge-smart-doh-monitor

# 回滚中转：①控制台切 off（可逆，最快）②停守护 ③删第二 IP
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' -d '{"mode":"off"}' $BASE/api/relay-config
sudo systemctl disable --now edge-smart-doh-relay        # 彻底停（DNS 侧 60s 自然收敛）
```

env 备份：deploy 脚本每次改 env 前备份到 `/var/backups/edge-smart-doh/`（0700，含密文件 0600）。

## 9. 边界（不要尝试，v1 不存在这些接口）

- 不改 relay 以外的配置（上游/ECH/缓存/CN 分流仍走 SSH 改 env + restart）；
- 不启停 systemd 单元（API 无此能力；off 档 ≠ 停进程）；
- 无用户体系/多密码/角色；单密码 = 全部权限，靠审计事后可查；
- 控制台为 LAN HTTP（无 TLS）；会话 cookie 可被同网段嗅探——这是"家庭内网可信"假设内的取舍；
- worker（公开实例）没有任何控制端点。
