# PRD：edge-smart-doh 控制台（监测站 → 控制台）

> 状态：v1.0 定稿。由产品经理 Agent 基于代码库现状调研产出，是控制台升级的实施蓝本。
> 读者：实施者（人类 + 编码 Agent）；运维 Agent 的操作文档由本 PRD 派生（见 `contrib/home/OPERATIONS.md`）。
> 变更对象：`contrib/home/monitor/monitor.mjs`（升级为控制台，仍单文件零依赖）；主服务新增 `POST /admin/relay-config`、
> 扩展 `GET /admin/relay`；`contrib/home/relay/relay.mjs` 名单热同步；`install-monitor.sh` 密码生成。
> 系统不变量：最坏情况退化为"昨天的系统"——控制台故障 ≠ DNS 故障；relay 挂 → DNS 自动回退直连。

## 1. 定位与用户

### 1.1 一句话定位

**把家里那台 DNS 小主机的"仪表盘"升级为"驾驶台"：看健康的同时，能不登录 SSH 就完成 relay 档位与域名名单的运维操作，且每一项操作都有明确的生效反馈与失败呈现。**

### 1.2 目标用户与场景

| 用户 | 描述 | 典型场景 |
|---|---|---|
| 主人（人类） | 部署并维护这套系统的个人，会 SSH 但不想每次为小事登服务器 | ① 手机上打开 8788 看"GitHub 到底好不好"；② GitHub 抖动了，把 relay 从 auto 拨到 always 试一周；③ 新克隆某个 github.io 站点失败，顺手把 `*.github.io` 加进中转名单 |
| 运维 Agent（AI） | 按文档操作本系统的自动化代理，具备服务器 root 或局域网访问能力 | ① 主人留言"GitHub 又慢了"→ Agent 查路径统计与 relay 健康 → 切档 → 验证 → 回报；② 定期巡检：读状态 API，异常时按预案操作并在审计记录中留下 label |

两类用户共用同一后端：**控制台暴露的 HTTP API 与页面是同一能力的两个面**（§5.1）。这是本 PRD 的结构性决策——不为 AI 单做一套接口。

### 1.3 继承的设计原则

1. **只读优先**：页面首要任务仍是 3 秒内回答"系统正常吗"，控制功能不得挤占首屏。
2. **失败必须可见**：任何控制操作失败/超时，界面呈现明确错误与建议动作，绝不静默吞掉。
3. **零依赖单文件**：Node 20+ 内置 http/crypto，原生 JS + 本地 vendor ECharts，无构建链。
4. **纵深防御**：LAN 来源过滤（TCP 对端地址）为第一层，密码为第二层；ADMIN_TOKEN 永不出控制台进程。

## 2. 信息架构

### 2.1 页面结构（自上而下）

```
┌────────────────────────────────────────────────────────────┐
│ ① 健康判定 hero（绿/黄/红 + 原因）      [会话状态/登录] [更新于…] │
├────────────────────────────────────────────────────────────┤
│ ② 核心数字卡（总查询 / 缓存命中率 / 回源P50 / 解析链路健康）      │
├────────────────────────────────────────────────────────────┤
│ ③ 查询量分钟柱状图（既有）                                    │
├────────────────────────────────────────────────────────────┤
│ ④ 解析路径分布（新：中转/ECH/优选池/国内直连/直连 + 缓存应答       │
│    —— 次数·占比·平均延迟）                                    │
├────────────────────────────────────────────────────────────┤
│ ⑤ 回源延迟 | 解析策略(技术视图) | 上游解析器（既有一行三栏）      │
├────────────────────────────────────────────────────────────┤
│ ⑥ 链路延迟趋势（既有，每10s 真实 DoH 探测）                    │
├──────────────────────── ── 控制区分隔 ── ────────────────────┤
│ ⑦ 【控制区·琥珀色边框】SNI 中转控制                             │
│    7a 档位选择器（off / auto / always + 当前生效大字）          │
│    7b 名单管理（RELAY_DOMAINS / RELAY_EXCLUDE_DOMAINS）        │
│    7c 同步与生效状态行（configVersion · relay 已应用 v?）       │
│    7d 操作记录（审计，折叠）                                    │
├────────────────────────────────────────────────────────────┤
│ ⑧ 折叠诊断区（高频域名 / 最近查询[+路径列] / 池状态）（既有）      │
└────────────────────────────────────────────────────────────┘
```

控制区放在全部只读内容**之后**、折叠诊断区之前：想操作的人会滚动到位，只想看健康的人不被打扰。移动端控制区自动单列。

### 2.2 危险度分级（贯穿全站的配色与交互语言）

| 级别 | 操作 | 交互要求 |
|---|---|---|
| L0 只读 | 查看一切面板、刷新 | 无 |
| L1 低危可逆 | off↔auto 切换、名单**删除**条目、恢复 env 默认 | 单击 + 完成后结果条；off 方向附加内联警示（非弹层） |
| L2 中危 | 名单**新增/修改**条目 | 行内 diff 预览 + "保存"二次点击；显示 30s 同步窗与 mihomo 依赖提示 |
| L3 高危 | 切入 **always** | 确认弹层（§3.3），列出影响面与带宽代价 |

### 2.3 认证态决定页面形态（三态）

| 态 | 触发条件 | 页面形态 |
|---|---|---|
| 纯监控模式 | `monitor.env` 无 `CONSOLE_PASSWORD` | 与升级前一致（+新统计面板）；控制区整体隐藏；页脚标注"纯监控模式（未设密码）" |
| 未登录 | 设了密码，无有效会话 | 整页替换为登录卡：标题、密码框、错误区、密码找回提示（§3.1）；**不渲染任何监测数据** |
| 已登录 | 有效会话 cookie | 完整控制台；hero 右侧显示会话徽标（label/来源 IP）与"退出" |

## 3. 核心用户流程

### 3.1 密码启用与首次登录

**密码从哪来：**
- `install-monitor.sh`（及 `deploy-home.sh` 的对应步骤）检测 `monitor.env` 中无 `CONSOLE_PASSWORD` 时生成随机密码，追加写入（文件保持 0600 root），重启 `edge-smart-doh-monitor`，并在终端**打印一次**明文与提示"请保存，服务器上可随时再查"。已有值则沿用（幂等）。
- 修改/轮换：手工编辑 `monitor.env` + `systemctl restart edge-smart-doh-monitor`（运维手册写明）。密码不与 ADMIN_TOKEN 复用。

**登录页如何告知用户：**
登录卡固定显示一行提示："密码由安装脚本生成，可在服务器上执行 `sudo grep CONSOLE_PASSWORD /etc/edge-smart-doh/monitor.env` 查看"。该提示本身不泄露信息——能读到该文件的只有 root，忘记密码的人本来就该有服务器权限。

**登录流程：**
1. 输入密码 → `POST /api/login`（可带可选 `label`，≤32 字符，用于审计；运维 Agent 约定带 `label=ops-agent`）。
2. 服务端恒时比对；成功 → 下发会话 cookie（`HttpOnly; SameSite=Strict; Path=/`），会话表存内存。
3. 失败 → 401 + 行内错误"密码不正确"；**同一来源 IP 连续 5 次失败进入 60 秒冷却**，期间前端显示倒计时，接口返回 429 与 `retryAfterSec`。
4. 会话有效期：空闲 2 小时滑动 + 绝对 24 小时；控制台进程重启后全部会话失效（重新登录即可，无持久化会话）。

**验收：** 设密码后任何路径（`/`、`/api/summary`）未登录均只见到登录卡/401；删除 `CONSOLE_PASSWORD` 并重启后，页面回到纯监控模式且无需登录——向后兼容成立。

### 3.2 查看健康与分类统计

**路径分类的呈现方式（决策）：** 用户语言是"这条查询走了哪条路"。主服务在 `/admin/stats` 直接给出回源路径汇总 `paths`（relay/ech/pool/cn/direct，按渲染后的实际改写判定），控制台再叠加"缓存应答"一类（hit+prefetch+stale 合计）。面板④"解析路径分布"：横向占比条 + 明细表（路径 | 次数 | 占比 | 平均延迟[仅回源类]）。标注口径："自服务启动以来 · 仅回源查询计入路径，缓存应答单列"。

**技术视图保留：** 既有"解析策略"面板（direct/preferred-ip/…原样）作为二级视图，供深挖。

**交叉印证：** ⑧"最近查询"表新增"路径"列（recent 样本已含 `path`，直接映射为徽章）；GitHub 族查询可直观看到 `github-pool` 与 `relay` 的交替。

**口径歧义必须在 UI 上说清（否则数据"看起来不对"）：** relay 档切走后 60 秒内，客户端旧缓存的答案仍计入"缓存应答"而非"SNI 中转"——面板脚注固定一句："路径按回源时刻归类；已进入客户端/服务端缓存的查询不再重新计类。"

### 3.3 切换 relay 档位

**控件：** 7a 三段式选择器（off / auto / always），当前生效档大字显示 + 配置来源徽标（"env 默认"或"运行时覆盖"）。切换即 `POST /api/relay-config {mode}`（经控制台代理到主服务 `POST /admin/relay-config`，持久化 + bump configVersion 立即生效）。

**确认交互（决策）：**

| 切换方向 | 交互 | 理由 |
|---|---|---|
| → **always** | **L3 确认弹层**：列出"将无条件中转的域名 N 条（前 5 条预览）、这些站点的全部流量将经代理节点出境、消耗节点带宽；ECH 不适用（名单站点的 HTTPS RR 会被清洗）"。主按钮"确认切换到 always"，次按钮"取消" | 带宽代价真实且不可自动回退（always 不看健康）；必须显式知情 |
| → **off** | 无弹层，但切换后结果条内联**持续警示**（黄色，不自动消失）："名单域名回到直连路径，GitHub 族 SNI 抖动可能复发；relay 进程未停止（无害），彻底停用需 `systemctl disable --now edge-smart-doh-relay`" | off 是安全方向（回到昨天系统），但用户多半是"因为抖动才开的"，忘了代价会困惑 |
| → **auto** / auto↔off | L1 单击 + 绿色结果条 | auto 是默认推荐档 |

**生效反馈（消歧义的关键）：** 成功后结果条显示三行：① 已持久化（重启保留）；② 新 DNS 答案即刻生效，存量客户端最迟 60 秒收敛（中转答案 TTL 上界 60s）；③ relay 进程将在 ≤30 秒内收到新配置（下次健康上报响应携带）。7c 状态行随后显示 `configVersion vN` 与"中转已应用 vN"（relay 回执），两者一致前显示"同步中（vN→等待 relay 回执）"。

**前置校验：** 若主服务 `RELAY_IP` 未配置/非私网（readConfig 会静默降级为 off），控制台请求 mode≠off 时主服务返回 400"中转未部署（RELAY_IP 缺失或非私网地址）"而非静默降级——"不能静默"原则落在服务端。

### 3.4 管理域名名单

**控件（7b）：** 两个可编辑列表——"中转名单（RELAY_DOMAINS）"与"排除名单（RELAY_EXCLUDE_DOMAINS）"。每条一行：`*.github.com` + 删除按钮（L1）；底部输入框 + "添加"（L2）。输入即时校验：

- 语法：小写、去尾点；接受 `*.example.com`、`.example.com`（等价）、精确 `example.com`；不合法的输入红色行内错误"仅支持 精确域名 或 *.通配 两种写法"。
- 上限：名单 ≤64 条、单条 ≤253 字符（与服务端 host 追踪量级对齐）；超限给出明确条数提示。
- ECH 冲突：服务端保存时校验，命中 `ECH_DOMAINS` / `META_DOMAINS` / `X_DOMAINS` 已配置项的条目 → 400 + 列出冲突条目，前端逐条标红并说明"中转需读取 SNI，与 ECH 加密 SNI 天然冲突"。对未在名单内但实际启用 ECH 的 Cloudflare 站点无法预判，输入框 placeholder 旁固定提示这一残余风险。
- 排除名单语义提示：排除优先于命中；默认排除 `ssh.github.com`（无 SNI，中转无法分流）。

**保存流程（L2）：** 点击"保存名单"→ 展开行内 diff（新增 N 条 / 删除 N 条，逐条列出）→ 再点"确认保存" → `POST /api/relay-config {domains, excludeDomains}`。保存带 `expectedVersion`：若 configVersion 已被其他会话改变 → 409"配置已被修改（vN→vM），请刷新后再试"（乐观并发）。

**生效时序与方向性差异（UI 固定提示，排歧义）：**

- **新增域名有 ≤30 秒危险窗**：DNS 立即开始把新域名答成 relay IP，但 relay 进程要等下一次健康上报（≤30s）拿到新名单，此前到达 relay:443 的该域名连接会被直接断开。保存成功后 7c 显示"同步中"，直到 relay 回执 `appliedConfigVersion = vN` 才显示"已同步"。结果条附加建议："新增域名后请等待'已同步'再使用；低峰期操作更稳妥。"
- **删除域名安全**：DNS 立即停发中转答案，客户端 ≤60s 收敛；relay 多持有旧名单无害（不再有新连接到达）。
- **mihomo 依赖提示**：中转拨号优先用实测池 IP（GitHub 池覆盖 GitHub 族）；**无池的新域名回退按域名 CONNECT，依赖代理的 `DOMAIN-SUFFIX,<域名>,<代理组>` 规则远程解析**。添加非 GitHub 族域名时，diff 确认层固定显示该提示与验证命令（`curl -x <代理> -sI https://<域名>`）。

**恢复默认：** 控制区提供"恢复 env 默认配置"（L1）：清除运行时覆盖（`reset: true`），回到 env 中的档位与名单；前置确认显示将恢复成的值（来自 `GET /admin/relay` 的 `envDomains`/`envExcludes`）。

### 3.5 异常路径

| 异常 | 判定 | 界面行为 |
|---|---|---|
| 会话过期（空闲/绝对超时） | 任意 `/api/*` 返回 401 | 当前视图淡出，弹出登录卡"会话已过期，请重新登录"；登录成功回到原位。**不自动重放未完成的控制操作** |
| 密码错误/冷却 | 401 / 429 | 行内错误 + 剩余尝试次数或冷却倒计时；不泄露"密码存在"以外的信息 |
| 主服务不可达（控制操作） | 代理转发超时/ECONNREFUSED → 控制台返回 502 + 原因 | 全局红色结果条**持续显示**："配置未更改：主服务不可达（原因）。可查看 `journalctl -u edge-smart-doh`"。控制区按钮禁用，只读面板继续展示最后已知数据并标注"数据更新于 X 分钟前" |
| ADMIN_TOKEN 失配 | 主服务 401 | 专用错误："ADMIN_TOKEN 与主服务不一致（是否改过主 env？在服务器上重跑 `install-monitor.sh`）" |
| 校验失败 | 主服务 400 | 字段级错误（哪些条目语法错/冲突/超限），输入框逐条标红；已保存的配置未变 |
| relay 未部署/未上报 | `GET /admin/relay` 的 relay 状态：无上报记录 | 控制区显示置灰态横幅："未检测到 relay 进程上报（上次上报：从未）。档位仍可设置，但设置后名单域名会按安全不变量回退直连。" |
| 控制台自身故障 | — | 回滚手段即"退化为昨天"：浏览器丢失页面不影响 DNS；密码丢失 → 删 env 键重启即回纯监控模式 |

## 4. 面板与控件验收标准

格式：状态 → 显示。AC 编号供实施与测试对照。

### 4.1 登录卡（3.1）

- AC1 未设密码：登录卡不出现，全部内容直出，页脚含"纯监控模式"。
- AC2 设密码未登录：`/` 只输出登录卡（HTML 内无任何监测数据），`/api/summary` 返回 401 JSON。
- AC3 密码错：红字"密码不正确"；第 5 次起按钮禁用并显示 60s 倒计时；期间请求返回 429。
- AC4 登录成功：进入完整控制台；hero 右侧显示 label（或来源 IP）与退出按钮；cookie 带 HttpOnly/SameSite=Strict。
- AC5 登录卡含密码找回提示（`sudo grep CONSOLE_PASSWORD …`）。

### 4.2 健康判定 hero（既有，新增一态）

- AC6 沿用现有五态（服务不可达红 / 解析异常红 / 统计不可用黄 / 中转离线黄 / 失败率偏高黄 / 运行正常绿）。
- AC7 新增"控制通道断连"黄态：控制台与主服务管理接口连续失败但 /health 仍通时，hero 副行显示"控制通道不可用（仅展示降级数据）"。

### 4.3 核心数字卡与既有图表

- AC8 总查询/命中率/回源P50/解析链路健康、分钟柱状图、回源延迟、上游表、链路趋势：行为与升级前一致（回归底线：不设密码时页面与升级前逐面板等价，仅新增面板④与路径列）。

### 4.4 解析路径分布（新）

- AC9 任意时刻各路径条目显示：路径名、次数、占比（分母=总查询）；回源类显示平均延迟，缓存应答显示"—"。
- AC10 无回源样本时显示"暂无回源记录"，缓存应答条仍按总量显示。
- AC11 面板标题固定口径说明："自服务启动以来 · 回源按路径归类，缓存单列"。
- AC12 触发 relay 的 GitHub 查询出现后，"SNI 中转"条目计数 > 0 且颜色为琥珀；用 `/explain?name=github.com` 交叉验证档位生效。

### 4.5 SNI 中转控制区

- AC13 档位三段选择器：当前生效档高亮 + 大字；配置来源徽标（env 默认/运行时覆盖）与 `GET /admin/relay` 的 override 标记一致。
- AC14 relay 未部署（RELAY_IP 空）：控制区显示置灰横幅（§3.5），mode≠off 的两个选项禁用并附原因。
- AC15 切 always：弹层内容含域名条数预览、带宽代价、ECH 说明；取消则无任何变更；确认后 2 秒内出现结果条（成功绿/失败红）。
- AC16 切 off：无弹层；成功后黄色警示条常驻直到下一次档位变更。
- AC17 名单编辑器：语法错误行内标红且不可保存；保存走 diff → 确认两步；成功后列表回显服务端返回的生效清单（以服务端为准，含归一化去重）。
- AC18 ECH 冲突条目：服务端 400 返回后逐条标红并附原因文案。
- AC19 同步状态行：显示 `configVersion vN` 与 relay 回执状态——"已同步 vN"（回执=vN）/"同步中"（回执<N，附"≤30 秒"说明）/"relay 未上报"。
- AC20 并发修改：保存时 version 不匹配 → 提示刷新，不覆盖。
- AC21 恢复 env 默认：确认层显示将恢复的值；成功后徽标回到"env 默认"。
- AC22 控制操作结果条：成功含"改了什么/已持久化/生效时序"三要素；失败含"配置未更改 + 原因 + 建议动作"，红色持续显示，绝不自动消失。

### 4.6 操作记录（审计，7d）

- AC23 折叠区显示最近 50 条：时间、来源 IP、label（若有）、动作（档位/名单/恢复默认/登录成功）、变更前后摘要、结果。
- AC23a 登录失败也计入（仅 IP + 次数聚合，避免刷屏）。

### 4.7 折叠诊断区（既有 + 一列）

- AC24 "最近查询"新增"路径"徽章列；其余三块行为不变。

## 5. 运维 Agent（AI）使用视角

### 5.1 通道选择（写给 Agent 的规则）

**原则：没有"必须走 UI"的操作。** 页面与 API 同源，Agent 一律走 HTTP。三通道按优先级：

| 通道 | 用法 | 适用 |
|---|---|---|
| ① 控制台 API（:8788，会话 cookie） | `POST /api/login` 拿 cookie → 调 `/api/summary`、`/api/relay`、`/api/relay-config` | **默认通道**：读状态 + 控制操作；控制台进程内审计自动记录 |
| ② 主服务 API（:8787，本机 root，Bearer ADMIN_TOKEN） | 直接 `GET/POST /admin/*` | **应急通道**（控制台进程挂了）：`/admin/relay`、`/admin/relay-config`、`/admin/stats` 可用；代价是审计落在主服务 journal 而非控制台操作记录 |
| ③ systemd/SSH | `systemctl`、编辑 env | 仅当需要改 env 默认值、启停 relay 进程、轮换密码——这些 v1 不在 API 范围（§7） |

Agent 登录约定：`label=ops-agent`（或含任务 id），让审计可区分人机。

### 5.2 控制台自身 API 契约（v1）

| 方法/路径 | 鉴权 | 请求 | 成功响应 | 失败 |
|---|---|---|---|---|
| POST `/api/login` | 无（限 LAN + 防爆破） | `{password, label?}` | 204 + Set-Cookie（会话 cookie） | 401 密码错；429 `{retryAfterSec}` 冷却 |
| POST `/api/logout` | 会话 | — | 204 | — |
| GET `/api/summary` | 密码设了则需会话 | — | 既有 summary 结构 + `console: {authRequired, controlEnabled, session:{valid, label}}` | 401 |
| GET `/api/relay` | 同上 | — | 代理 `GET /admin/relay`（mode、ip、domains[]、excludes[]、modeSource、configVersion、appliedConfigVersion、healthy、hosts、lastReportAt） | 502 `{error, cause}`（主服务不可达，附原因） |
| POST `/api/relay-config` | 会话 | `{mode?, domains?, excludeDomains?, expectedVersion?, reset?}`，未出现的字段不修改 | 200 `{ok, changed, relay:{...生效配置}}` | 400（逐条校验错误/冲突/超限/RELAY_IP 缺失）；409（expectedVersion 不符）；502（主服务不可达） |
| GET `/api/audit` | 会话 | — | `{entries:[…最近100条…]}` | — |
| GET `/healthz` | 无（仅限 LAN） | — | `{ok, uptimeSec, authRequired, control}`（无敏感字段，供 Agent 探测能力） | — |

安全约定：所有 POST 仅接受 `Content-Type: application/json`（配合 SameSite=Strict 防 CSRF）；cookie 不设 `Secure`（v1 为 LAN HTTP，文档写明原因）；错误响应一律 JSON 且带可读 `error` 文案——Agent 依赖文案决策，禁止返回裸状态码。

主服务侧接口（实施依赖，PM 视角契约）：
- `POST /admin/relay-config`：校验（mode 枚举；域名语法；ECH 冲突 400；条数上限；mode≠off 且 RELAY_IP 无效 → 400 而非静默降级）→ 原子写 `RELAY_CONFIG_PATH`（StateDirectory 下）→ bump `configVersion` → 立即生效（缓存版本联动）。启动时加载该文件覆盖 env 默认。
- `GET /admin/relay` 扩展：生效配置全量清单 + override 标记 + env 默认值 + `configVersion`/`appliedConfigVersion`。
- `POST /admin/relay-health` 响应携带生效域名清单与 `configVersion`；relay.mjs 收到后热替换名单并回执 `appliedConfigVersion`（随下次上报送回）。

### 5.3 curl 模拟（写进 Agent 文档的样例）

```bash
BASE=http://192.168.1.10:8788
# 1. 探测能力（无凭据）
curl -s $BASE/healthz
# 2. 登录（Agent 带 label 便于审计区分）
curl -s -c /tmp/cj -H 'Content-Type: application/json' \
  -d '{"password":"<CONSOLE_PASSWORD>","label":"ops-agent"}' $BASE/api/login
# 3. 读生效配置与同步状态
curl -s -b /tmp/cj $BASE/api/relay | jq '{mode:.relay.mode, configVersion:.relay.configVersion, applied:.relay.appliedConfigVersion, healthy:.relay.healthy}'
# 4. 切档位（auto）
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' \
  -d '{"mode":"auto"}' $BASE/api/relay-config
# 5. 验证：configVersion 已 bump；等 relay 回执 appliedConfigVersion 追平（≤30s）
#    再用 /explain 交叉验证：curl -s "http://127.0.0.1:8787/explain?name=github.com&type=A"
# 6. 回滚：把 mode 改回原值（或 reset:true 恢复 env 默认）
curl -s -b /tmp/cj -X POST -H 'Content-Type: application/json' \
  -d '{"reset":true}' $BASE/api/relay-config
```

应急通道（控制台不可达、本机 root）：`curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8787/admin/relay-config -X POST -d '{"mode":"off"}'`（ADMIN_TOKEN 取自 `/etc/edge-smart-doh/env`）。

### 5.4 Agent 文档交付要求（本 PRD 派生任务）

运维手册以 Agent 为第一读者撰写（人类可顺读）：能力清单与探测方法；curl 全流程样例；语义表（三档含义、通配语法、排除优先、生效时序三层、`appliedConfigVersion` 追平判据）；危险动作约定；故障预案；边界清单（§7）。

## 6. 安全与误操作防护

### 6.1 防线层次

1. **LAN 来源过滤**（既有，不动）：TCP 对端私网地址校验，不信任任何转发头；
2. **密码会话**（新）：恒时比对、随机 256-bit 会话令牌仅存内存、HttpOnly/SameSite=Strict cookie、2h 滑动/24h 绝对过期、进程重启全会话失效；
3. **凭据隔离**（沿用）：ADMIN_TOKEN 只在控制台进程内存，浏览器只见会话 cookie；CONSOLE_PASSWORD 只在 monitor.env（0600 root，pid1 读取）；
4. **服务端校验**（新）：档位/名单的合法性与冲突在主服务强制校验，控制台校验仅为体验层。

### 6.2 防爆破与 CSRF

- 每 IP 5 次失败 → 60s 冷却（内存计数）；恒时比较防时序侧信道。
- 写接口仅收 JSON + SameSite=Strict；CSP 沿用现有，登录卡为同源内联，无第三方资源。

### 6.3 危险操作矩阵与确认弹层

见 §2.2/§3.3。弹层原则：只在"不可自动回退的代价"（always 的带宽）上设闸；对"回到昨天系统"（off）用持续警示而非打断；所有 L2 编辑走 diff 确认。弹层一律原生 DOM（无框架约束）。

### 6.4 审计："谁在何时改的"是否可行

**结论：可行，但"谁"的上界是（时间, 来源 IP, 会话 label）三元组**——没有用户体系，单密码无法区分自然人。设计：

- 每条审计记录：`{t, ip, label?, action, before→after, result}`；来源 IP 取 TCP 对端（与第一层过滤同源，不可伪造）。
- label 来自登录时的可选备注（人类可留名字/设备名，Agent 按 §5.1 约定留 `ops-agent`）。
- 存储：内存环形（页面展示最近 50）+ 结构化 `console.log` JSON 行落 journald。档位/名单/恢复默认/登录成败均入账。
- 诚实边界（写入文档）：应急通道（直连主服务 /admin/*）的操作只出现在主服务 journal，不在控制台操作记录中。

### 6.5 威胁模型边界（明说不防什么）

- LAN 内被动嗅探：v1 为 HTTP，会话 cookie 可被同网段嗅探——已由 LAN 过滤缩小到"家庭内网可信"假设；上 TLS 留给部署层（Caddy 可选），v1 不做（§7）。
- 拿到密码的 LAN 用户即拥有完整控制权：单密码模型下这是定义内的全部权限，靠审计事后可见。

## 7. v1 明确不做（边界）

1. **不做**用户体系/多密码/角色权限（单密码 + label 归因）。
2. **不做** relay 之外的控制：上游列表、ECH 开关、缓存参数、CN 分流等 env 项仍走 SSH 改 env；控制台只管档位 + 两个名单。
3. **不做**进程级操作：不在 API 里启停 relay/主服务 systemd 单元（off 档 ≠ 停进程，文案已澄清）。
4. **不做**控制台自身 HTTPS/TLS（LAN HTTP；防火墙与来源过滤兜底）。
5. **不做**统计持久化与历史回看：/admin/stats 仍是内存口径、重启清零（面板标注"自服务启动以来"）。
6. **不做**告警推送（webhook/邮件/IM）；页面黄红牌仍是唯一告警面。
7. **不做**名单批量导入/正则/站点分组档位；不做面板间钻取联动。
8. **不做**公开实例（worker 版）的任何控制能力——本 PRD 全部限于 home/Node 部署。
9. **不做**自动诊断/自愈（Agent 巡检是外置的，控制台只提供事实与操作）。

## 8. 里程碑

每个里程碑独立可验收、可独立回滚（回滚 = 恢复上一版 monitor.mjs / dist，配置状态文件向后兼容）。

| 里程碑 | 内容 | 验收要点 |
|---|---|---|
| **M1 主服务：relay 运行时配置 + 路径分类** | `POST /admin/relay-config`（校验/持久化/bump configVersion/expectedVersion 并发）；`GET /admin/relay` 扩展；`/admin/relay-health` 携带名单；relay.mjs 热同步 + 回执；`/admin/stats` 新增 `paths` | curl 改档位 → `/explain` 立即反映；重启主服务配置保留；改名单后 ≤30s relay 日志出现 `config_applied`；ECH 冲突/坏语法/超限/无 RELAY_IP 四类 400 各有明确文案；vitest 全绿 |
| **M2 控制台：认证骨架 + 路径面板** | 登录/登出/会话/防爆破/三态兼容；/api 代理骨架；路径分布面板 + 最近查询路径列 | AC1–AC5、AC9–AC12、AC24；curl 模拟登录全流程可用；未设密码时与升级前页面回归等价 |
| **M3 控制台：relay 控制面板** | 档位选择器 + always 确认弹层 + off 警示 + 名单编辑器（校验/diff/并发提示）+ 同步状态行 + 操作记录 + 恢复默认 | AC13–AC23a；手工演练：切 always → 大 clone 验证经代理；切 off → 60s 内答案回池 IP；新增域名 → "同步中→已同步" |
| **M4 装机集成与 Agent 文档** | install-monitor.sh / deploy-home.sh 密码生成与一次性打印；运维手册；README 控制台章节 | 按 §5.3 样例从零完成"探测→登录→读→切→验证→回滚"全流程；重跑 install 脚本幂等 |

## 附：实施对照（实施时记录的偏差）

- §3.2 路径分类升级为**服务端汇总**（`/admin/stats` 的 `paths`，按渲染后的真实改写判定 relay/ech/pool/cn/direct），比原案"控制台按 strategy 名映射"更准确——preferred-ip 只有在改写真正发生时才计入 pool；ECH 注入在 pool 策略占位时也能被归入 ech。控制台叠加"缓存应答"合计，两案 UI 等价。
- 排除名单上限与中转名单一致取 64（原案 32），服务端 `MAX_RELAY_DOMAINS` 统一约束。
- 会话为**进程内存表**（随机 256-bit 会话 id → {label, 来源 IP, 创建/最后活跃时间}，上限 64 条、超出逐出最旧），cookie 只携带 id；2 小时无活跃或超过 24 小时绝对过期即失效，进程重启全部失效（签名/查表之争就此终结：查表语义与 PRD 完全一致）。
