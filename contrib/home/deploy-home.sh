#!/usr/bin/env bash
# ============================================================================
#  edge-smart-doh 家庭/小机直连部署（8443 + acme.sh DNS-01 + DDNS）
#  位置：仓库 contrib/home/deploy-home.sh；上游信任模型见 contrib/home/README.md
#  用法：sudo bash contrib/home/deploy-home.sh    （幂等，可反复执行）
#  交互：仅在需要时——首次问 DoH 域名（存 /etc/edge-smart-doh/deploy.conf，重跑不再问）；
#        首次装 acme.sh 问邮箱；签证书/装 DDNS 需要 CF Token 时 read -s 输入；
#        DEPLOY_ENV=cn 且无代理地址时问代理；代理在本机时问其 systemd 单元名(可跳过)
#  脚本做不了的两件事（见运行结束的待办）：
#    1) 主路由加转发：外部 8443/TCP → 本机:8443
#    2) 外网验收（手机热点 curl /probe 与 dig +https）
# ============================================================================
set -euo pipefail

# ==================== 配置区（站点相关值留空 = 交互询问并持久化） ====================
DOH_DOMAIN=""                        # DoH 域名（证书/DDNS/Caddy 共用）；留空=首跑询问，存 deploy.conf
CF_ZONE=""                           # CF 托管 zone；留空=由域名推导（去最左标签），doh.example.com→example.com
LAN_IP=""                            # 本机内网 IP；留空=自动取第一个 IPv4
LAN_CIDR=""                          # 内网网段（8787 仅对它放行）；留空=LAN_IP 所在 /24
DEPLOY_ENV="cn"                      # cn      = 国内环境：上游必须经代理出境，否则被墙+被污染
                                     #           （被污染域名拿不到干净解析，见 contrib/home/README.md）
                                     # overseas = 境外服务器：上游直连，无需代理
PROXY_ADDR=""                        # DEPLOY_ENV=cn 时的出境代理(HTTP代理口)；
                                     # 留空 = 交互询问，答案持久化进 drop-in 后重跑不再问
PROXY_UNIT=""                        # 代理在本机时的 systemd 单元名（启动顺序用，可选）；
                                     # 留空且代理在本机时交互询问（可回车跳过），答案存 deploy.conf
CF_TOKEN=""                          # 留空 = 需要时交互输入（read -s，不进 history）
ACME_EMAIL=""                        # 留空 = 首次安装 acme.sh 时交互输入，答案存 deploy.conf
NPM_REGISTRY="https://registry.npmmirror.com"   # undici 安装源（仅 cn+代理路径用到）
ECS_DOMAIN_LIST_URLS_CFG=""           # 国内域名名单 URL（国内站拿国内 CDN 节点靠它）；留空=默认
                                      # Loyalsoldier direct-list；"none"=显式关闭（国内站将拿海外节点）
ECS_FALLBACK_SUBNET_CFG=""            # 解析国内域名时的 ECS 出口子网（填家宽公网 IPv4）；
                                      # 留空=每次重跑自动探测并更新（PPPoE 重拨换 IP 后重跑即可）
CN_UPSTREAMS_CFG=""                   # 国内域名的直连解析器（国内 DNS 看到的源 IP 即家宽运营商，
                                      # 比 ECS 更准且不依赖代理）；留空=默认阿里 DoH+腾讯 DoH；
                                      # "none"=关闭国内直连，国内域名退回 ECS 路径（经代理）
OPEN_PUBLIC=1                        # 1 = 完整公网部署(证书/Caddy/8443/DDNS)
                                     # 0 = 仅内网(服务+cfhub+8787)，公网零暴露，以后改 1 重跑
SETUP_DDNS=1                         # OPEN_PUBLIC=1 时生效
SKIP_BUILD=0                         # 1 = dist/node.mjs 已存在时跳过 npm ci/build（快速重跑）
SETUP_FIREWALL=0                     # 1 = 用 nftables 整体替换 /etc/nftables.conf：入站默认丢弃，只放行
                                     #     SSH/mosh/DoH。NAS 或跑着其他服务的机器上会挡掉它们，确认后再开
# ==========================================================

LOG_FILE="/var/log/deploy-home.log"
STAMP="$(date +%Y%m%d-%H%M%S)"
ENV_FILE=/etc/edge-smart-doh/env
CF_TOKEN_FILE=/etc/edge-smart-doh/cf-token
CONF_FILE=/etc/edge-smart-doh/deploy.conf
ACME=/root/.acme.sh/acme.sh

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [ok] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  [x] %s\033[0m\n' "$*" >&2; exit 1; }

# env 键值写入：键不存在则追加（旧版 env.example 的拷贝可能缺新键），存在则覆盖。
# 替换文本先转义 sed 的特殊字符（& | \）：URL 带 query（?a=1&b=2）时 & 会展开成整行。
set_env_value() {  # set_env_value KEY VALUE
  local escaped
  escaped="$(printf '%s' "$2" | sed -e 's/[\\|]/\\&/g' -e 's/&/\\&/g')"
  if grep -q "^$1=" "$ENV_FILE"; then
    sed -i "s|^$1=.*|$1=${escaped}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
}
env_has_value() { grep -qE "^$1=.+" "$ENV_FILE"; }

# 出口公网 IPv4 探测：必须直连（--noproxy，走代理拿到的是代理出口）；国内源互为备份。
# 拿到私网/CGNAT/回环段视为失败——代理 TUN 全局接管时会这样。
probe_public_ipv4() {
  local src ip
  for src in https://ip.3322.net/ https://4.ipw.cn; do
    ip="$(curl -4 --noproxy '*' -s --max-time 8 "$src" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)"
    case "$ip" in
      ""|10.*|127.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) continue ;;
      *) printf '%s\n' "$ip"; return 0 ;;
    esac
  done
  return 1
}

# 持久化站点配置（只写白名单键；文件 root 0600，不进仓库）
save_conf() {  # save_conf KEY VALUE
  local key="$1" value="$2" rest
  install -d -m 0755 /etc/edge-smart-doh
  rest="$(grep -v "^${key}=" "$CONF_FILE" 2>/dev/null || true)"
  printf '%s\n%s=%s\n' "$rest" "$key" "$value" > "$CONF_FILE"
  chmod 600 "$CONF_FILE"
}
# 读取已有配置（仅白名单键，且不覆盖配置区已填的值）
if [[ -f "$CONF_FILE" ]]; then
  while IFS='=' read -r k v; do
    case "$k" in
      DOH_DOMAIN|CF_ZONE|PROXY_UNIT|ACME_EMAIL)
        [[ -n "$v" && -z "${!k}" ]] && printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^(DOH_DOMAIN|CF_ZONE|PROXY_UNIT|ACME_EMAIL)=' "$CONF_FILE" || true)
fi

# ---------------------------------------------------------------------------
# 0. 前置检查与参数自举
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo bash $0"
command -v apt-get >/dev/null 2>&1 || die "这不是 Debian/apt 系系统"

# 仓库定位：本脚本在 contrib/home/ 下，仓库根即上两级（可用环境变量 PROJECT_DIR 覆盖）
PROJECT_DIR="${PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}"
[[ -f "$PROJECT_DIR/package.json" ]] || die "未找到 $PROJECT_DIR（脚本须在仓库 contrib/home/ 内运行）"

# 构建用户：sudo 传入的 SUDO_USER > 仓库属主 > logname
REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" || "$REAL_USER" == "root" ]]; then
  REAL_USER="$(stat -c %U "$PROJECT_DIR" 2>/dev/null || true)"
fi
if [[ -z "$REAL_USER" || "$REAL_USER" == "root" ]]; then
  REAL_USER="$(logname 2>/dev/null || true)"
fi
[[ -n "$REAL_USER" && "$REAL_USER" != "root" ]] && id "$REAL_USER" >/dev/null 2>&1 \
  || die "无法确定构建用的普通用户（试试 sudo bash 运行，或在配置区指定）"

# 域名（必填）：配置区 > deploy.conf > 交互（首次问完持久化）
if [[ -z "$DOH_DOMAIN" ]]; then
  read -rp "DoH 域名（如 doh.example.com；证书/DDNS/Caddy 共用）: " DOH_DOMAIN
fi
[[ "$DOH_DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
  || die "DOH_DOMAIN '$DOH_DOMAIN' 不是合法域名"
if ! grep -q '^DOH_DOMAIN=' "$CONF_FILE" 2>/dev/null; then
  save_conf DOH_DOMAIN "$DOH_DOMAIN"
  ok "域名已持久化到 $CONF_FILE（重跑不再询问）"
fi
[[ -z "$CF_ZONE" ]] && CF_ZONE="${DOH_DOMAIN#*.}"
[[ "$CF_ZONE" == *.* ]] || die "CF_ZONE 推导失败（$CF_ZONE）；深子域请在配置区显式指定"

# 网络参数：留空则自动探测
LAN_IP="${LAN_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[[ "$LAN_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "无法确定本机内网 IP（在配置区 LAN_IP 指定）"
LAN_CIDR="${LAN_CIDR:-${LAN_IP%.*}.0/24}"

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

FIREWALL_8443=""
[[ "$OPEN_PUBLIC" == "1" ]] && FIREWALL_8443=$'    # 8443：公网 DoH 入口（经路由器转发，主机上无法区分来源，全放）\n    tcp dport 8443 accept'

log "edge-smart-doh 部署开始（日志：$LOG_FILE）OPEN_PUBLIC=$OPEN_PUBLIC  DOMAIN=$DOH_DOMAIN"

# ---------------------------------------------------------------------------
# 1. 依赖
# ---------------------------------------------------------------------------
log "步骤 1/8：依赖（nodejs/npm/jq/curl + caddy←backports）"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y nodejs npm openssl curl jq dnsutils
if [[ "$OPEN_PUBLIC" == "1" ]]; then
  # main 源的 caddy 是 2.6.2，缺 client_ip matcher（≥2.7 才有），必须 backports 的 2.11.x
  apt-get install -y -t trixie-backports caddy || die "caddy(backports) 安装失败：检查 trixie-backports 源"
  ok "caddy $(caddy version 2>/dev/null | awk '{print $1}')"
fi
ok "node $(node --version)"

# ---------------------------------------------------------------------------
# 2. 构建
# ---------------------------------------------------------------------------
log "步骤 2/8：构建 dist/node.mjs"
if [[ "$SKIP_BUILD" == "1" && -f "$PROJECT_DIR/dist/node.mjs" ]]; then
  ok "SKIP_BUILD=1 且产物已存在，跳过"
else
  # 以普通用户构建，避免 root 属主文件留在仓库里
  runuser - "$REAL_USER" -c "cd '$PROJECT_DIR' && npm ci && npm run build:node" \
    || die "构建失败（看上方 npm 输出）"
  [[ -f "$PROJECT_DIR/dist/node.mjs" ]] || die "构建产物缺失 dist/node.mjs"
  ok "构建完成"
fi

# ---------------------------------------------------------------------------
# 3. 安装 DoH 服务
# ---------------------------------------------------------------------------
log "步骤 3/8：安装 edge-smart-doh 服务"

getent passwd edge-smart-doh >/dev/null 2>&1 || useradd --system --no-create-home edge-smart-doh
install -D -m 0644 "$PROJECT_DIR/dist/node.mjs" /opt/edge-smart-doh/node.mjs

[[ -f "$ENV_FILE" ]] || install -D -m 0600 "$PROJECT_DIR/deploy/edge-smart-doh.env.example" "$ENV_FILE"
cp -a "$ENV_FILE" "$ENV_FILE.bak-$STAMP"   # 下面会改 env，先备份（0600 权限一并保留）

# ---- 上游模式决策：国内环境必须解决"上游被墙/被污染"，否则被污染域名解析不到 ----
DROPIN_PROXY=/etc/systemd/system/edge-smart-doh.service.d/proxy.conf
if [[ "$DEPLOY_ENV" == "cn" ]]; then
  if [[ -z "$PROXY_ADDR" && -f "$DROPIN_PROXY" ]]; then
    PROXY_ADDR="$(sed -n 's/^Environment=HTTPS_PROXY=//p' "$DROPIN_PROXY" | head -1)"
    [[ -n "$PROXY_ADDR" ]] && ok "沿用已配置的出境代理：$PROXY_ADDR"
  fi
  if [[ -z "$PROXY_ADDR" ]]; then
    read -rp "出境代理地址（国内环境需要，如 http://127.0.0.1:7890；留空=无代理降级，被污染域名将解析不到）: " PROXY_ADDR
  fi
fi
ECS_UPSTREAMS_CFG=""                 # 非空时写入 env 的 ECS_UPSTREAMS（仅 cn+代理模式设置）
if [[ "$DEPLOY_ENV" != "cn" ]]; then
  UPSTREAMS_CFG="https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://unfiltered.adguard-dns.com/dns-query"
elif [[ -n "$PROXY_ADDR" ]]; then
  # UPSTREAMS 是「信任清单」：只放经代理出境的上游。直连国内递归对受污染域名返回假 IP，
  # 且只要几十 ms（经代理上游要数百 ms），在 hedge 竞速里必然先到并获胜，假 IP 还会被写进
  # 答案缓存与 ECH/CF 判定用的派生缓存（实测时间线见 contrib/home/README.md）。
  # 国内域名不进这个池子：由 CN_UPSTREAMS 直连国内解析器分流（见下方「国内网站的国内节点」），
  # 两组上游各查各的域名，互不竞速。ECS 路径（CN 分流关闭时的回退）只留 dns.google：
  # cloudflare 不转发 ECS，不能进 ECS 列表。
  UPSTREAMS_CFG="https://cloudflare-dns.com/dns-query,https://dns.google/dns-query"
  ECS_UPSTREAMS_CFG="https://dns.google/dns-query"
else
  # 无代理降级模式：没有出境路径，只能把直连国内递归放进 UPSTREAMS —— 这违反「信任清单」
  # 约定（见 contrib/home/README.md），被污染域名必然拿到假 IP，仅作过渡用。
  UPSTREAMS_CFG="https://dns.alidns.com/dns-query,https://1.12.12.12/dns-query,https://cloudflare-dns.com/dns-query"
  warn "国内环境无代理：被污染域名必然拿到假 IP，仅作过渡；装上代理后重跑本脚本即恢复"
fi

if grep -q '^ADMIN_TOKEN=[0-9a-f]\{64\}$' "$ENV_FILE"; then
  ok "沿用已有 ADMIN_TOKEN（重跑不轮换）"
else
  sed -i "s|^ADMIN_TOKEN=.*|ADMIN_TOKEN=$(openssl rand -hex 32)|" "$ENV_FILE"
  ok "已生成新 ADMIN_TOKEN"
fi

SED_ARGS=(
  -e "s/^HOST=.*/HOST=0.0.0.0/"
  -e "s/^PUBLIC_HOSTNAMES=.*/PUBLIC_HOSTNAMES=${DOH_DOMAIN},${LAN_IP}/"
  -e "s|^UPSTREAMS=.*|UPSTREAMS=${UPSTREAMS_CFG}|"
  -e "s/^MAX_DNS_PACKET_SIZE=.*/MAX_DNS_PACKET_SIZE=16384/"
)
[[ -n "$ECS_UPSTREAMS_CFG" ]] && SED_ARGS+=( -e "s|^ECS_UPSTREAMS=.*|ECS_UPSTREAMS=${ECS_UPSTREAMS_CFG}|" )
sed -i "${SED_ARGS[@]}" "$ENV_FILE"

# ---- 国内网站的国内节点（仅 cn+代理模式）：域名名单 + ECS 出口子网 ----
# 不带国内子网去问 dns.google，它按查询来源（=代理出口，境外）选 CDN：developer.huawei.com
# 拿到 Akamai 欧洲节点，浏览器分流再把海外 IP 送出国，国内站自然巨慢。两个键缺一不可：
# 名单决定哪些域名带 ECS，子网决定 CDN 按哪段地址选节点（本机/局域网客户端地址是
# 127.0.0.1/192.168.x.x，dns.google 对非公网子网一律 REFUSED，不能作为 ECS 源）。
if [[ "$DEPLOY_ENV" == "cn" && -n "$PROXY_ADDR" ]]; then
  if [[ "$ECS_DOMAIN_LIST_URLS_CFG" == "none" ]]; then
    set_env_value ECS_DOMAIN_LIST_URLS ""
    warn "ECS_DOMAIN_LIST_URLS_CFG=none：国内域名名单保持关闭（国内站将拿海外 CDN 节点）"
  else
    # CFG 非空时总是以它为准（换名单源改配置区即可）；CFG 留空时 env 里已有值不动（用户手填的
    # 名单源），缺失/为空才补默认。与 CN_UPSTREAMS_CFG 的覆盖语义保持一致。
    if [[ -n "$ECS_DOMAIN_LIST_URLS_CFG" ]] || ! env_has_value ECS_DOMAIN_LIST_URLS; then
      set_env_value ECS_DOMAIN_LIST_URLS "${ECS_DOMAIN_LIST_URLS_CFG:-https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt}"
      ok "国内域名名单：$(sed -n 's/^ECS_DOMAIN_LIST_URLS=//p' "$ENV_FILE" | head -1)"
    else
      ok "国内域名名单已配置：$(sed -n 's/^ECS_DOMAIN_LIST_URLS=//p' "$ENV_FILE" | head -1)"
    fi
  fi
  if [[ -z "$ECS_FALLBACK_SUBNET_CFG" ]] && ECS_FALLBACK_SUBNET_CFG="$(probe_public_ipv4)"; then
    ok "探测到出口公网 IPv4：$ECS_FALLBACK_SUBNET_CFG（作为 ECS 源，按 /24 截断）"
  fi
  if [[ -n "$ECS_FALLBACK_SUBNET_CFG" ]]; then
    set_env_value ECS_FALLBACK_SUBNET "$ECS_FALLBACK_SUBNET_CFG"
  else
    ECS_FALLBACK_SUBNET_CFG="$(sed -n 's/^ECS_FALLBACK_SUBNET=//p' "$ENV_FILE" | head -1)"
    if [[ -n "$ECS_FALLBACK_SUBNET_CFG" ]]; then
      ok "出口 IPv4 探测失败，沿用已有 ECS_FALLBACK_SUBNET=$ECS_FALLBACK_SUBNET_CFG"
    else
      warn "出口 IPv4 探测失败：国内域名暂无 ECS 子网，将拿海外节点；下次重跑会再探测"
    fi
  fi
  # 国内域名直连解析器：名单命中的域名不再经代理问 dns.google，而是直连国内 DNS——
  # 国内 DNS 看到的查询源 IP 就是家宽出口（运营商级视角，比 ECS /24 更准），也不再依赖代理。
  # 这些解析器的主机名必须绕过代理（drop-in 的 NO_PROXY，见步骤 3b），否则又变回代理路径。
  if [[ "$CN_UPSTREAMS_CFG" == "none" ]]; then
    set_env_value CN_UPSTREAMS ""
    warn "CN_UPSTREAMS_CFG=none：国内域名退回 ECS 路径（经代理查 dns.google）"
  else
    CN_UPSTREAMS_CFG="${CN_UPSTREAMS_CFG:-https://dns.alidns.com/dns-query,https://doh.pub/dns-query}"
    set_env_value CN_UPSTREAMS "$CN_UPSTREAMS_CFG"
    ok "国内域名直连上游：$CN_UPSTREAMS_CFG"
  fi
fi
# MAX_DNS_PACKET_SIZE=16384：node.ts 用它限制所有 POST 体（不止 DNS 包），
# cfhub 大运营商池的 JSON 可超默认 4096 → 413 → 池同步失败退社区池

install -m 0644 "$PROJECT_DIR/deploy/edge-smart-doh.service" /etc/systemd/system/

# ---- 3b：上游代理接线（仅 DEPLOY_ENV=cn 且有代理地址）----
if [[ "$DEPLOY_ENV" == "cn" && -n "$PROXY_ADDR" ]]; then
  log "步骤 3b：上游经代理出境（$PROXY_ADDR）"
  # Node 的 fetch 不认 HTTP_PROXY 环境变量，必须用 undici 的 EnvHttpProxyAgent 全局接管。
  # 钉 6.x 是版本边界问题：undici@8 依赖 Node >=22.19（webidl.util.markAsUncloneable），
  # 在 Node 20 上 --import 阶段即抛 TypeError，服务会陷入 restart 循环（实测踩过）。
  # undici@6 支持 Node 18.17+（含 22/24），没有理由冒险用更高大版本。
  npm --prefix /opt/edge-smart-doh install undici@6 \
    --registry="$NPM_REGISTRY" --no-fund --no-audit >/dev/null 2>&1 \
    || die "undici 安装失败（它是 fetch 走代理的前提）"

  tee /opt/edge-smart-doh/proxy-preload.mjs > /dev/null <<'EOF'
// 让本进程所有出站 fetch 走 HTTP(S)_PROXY；NO_PROXY 名单内的目标保持直连
import { setGlobalDispatcher, EnvHttpProxyAgent } from "undici";
setGlobalDispatcher(new EnvHttpProxyAgent());
EOF

  # 版本自检：重启服务前，先用系统 node 试加载一次 preload。
  # 任何 undici/Node 不兼容都会在 --import 阶段暴露——在这里拦截并给出可操作的报错，
  # 而不是让服务起来又崩、在 systemd restart 循环里默默重试
  if ! env HTTP_PROXY="$PROXY_ADDR" HTTPS_PROXY="$PROXY_ADDR" NO_PROXY=localhost \
       node --import /opt/edge-smart-doh/proxy-preload.mjs -e '' >/dev/null 2>&1; then
    node --import /opt/edge-smart-doh/proxy-preload.mjs -e '' || true   # 展示真实报错
    die "proxy-preload 在 node $(node --version) 下加载失败（undici/Node 版本不兼容；本脚本钉 undici@6）"
  fi
  ok "undici $(node -p "require('/opt/edge-smart-doh/node_modules/undici/package.json').version") 预加载自检通过"

  # 代理在本机：可选加启动顺序依赖（先代理后 DoH，开机首查询不白等上游超时）
  UNIT_DEP=""
  if [[ "$PROXY_ADDR" =~ ^(http://)?(127\.0\.0\.1|localhost|\[::1\]) ]]; then
    if [[ -z "$PROXY_UNIT" ]]; then
      read -rp "代理在本机：代理的 systemd 单元名（如 mihomo.service；回车跳过）: " PROXY_UNIT
      [[ -n "$PROXY_UNIT" ]] && ! grep -q '^PROXY_UNIT=' "$CONF_FILE" 2>/dev/null \
        && save_conf PROXY_UNIT "$PROXY_UNIT"
    fi
    if [[ -n "$PROXY_UNIT" ]] && systemctl list-unit-files "$PROXY_UNIT" --no-legend 2>/dev/null | grep -q .; then
      UNIT_DEP=$'After='"$PROXY_UNIT"$'\nWants='"$PROXY_UNIT"
      ok "启动依赖已设：edge-smart-doh 排在 $PROXY_UNIT 之后"
    else
      [[ -n "$PROXY_UNIT" ]] && warn "未找到单元 $PROXY_UNIT，跳过启动依赖（不影响功能）"
    fi
  fi

  install -d -m 0755 /etc/systemd/system/edge-smart-doh.service.d
  # 国内直连解析器（CN_UPSTREAMS）的主机名进 NO_PROXY：它们必须绕过代理直连，否则又变回
  # 代理路径（慢 + 解析器看到的是代理出口视角）。服务启动时也会自查（cn_upstream_proxy_warning）。
  CN_NOPROXY=""
  if [[ -n "$CN_UPSTREAMS_CFG" && "$CN_UPSTREAMS_CFG" != "none" ]]; then
    CN_NOPROXY="$(printf '%s' "$CN_UPSTREAMS_CFG" | tr ',' '\n' | sed -E 's|^https?://([^/@]*@)?([^/]+).*|\2|' | paste -sd, -)"
  fi
  NO_PROXY_VALUE="localhost,127.0.0.1,::1,www.cloudflare.com${CN_NOPROXY:+,$CN_NOPROXY}"
  tee "$DROPIN_PROXY" > /dev/null <<EOF
# 由 contrib/home/deploy-home.sh 生成：境外上游 fetch 经代理出境（国内环境）
[Unit]
${UNIT_DEP}

[Service]
Environment=HTTP_PROXY=${PROXY_ADDR}
Environment=HTTPS_PROXY=${PROXY_ADDR}
# 境外域名（默认上游、ECS 路径）经代理出境；国内域名走 CN_UPSTREAMS 直连。
# 直连名单：回环、www.cloudflare.com（CF 网段表拉取，非 DNS 解析）与国内解析器主机名
Environment=NO_PROXY=${NO_PROXY_VALUE}
ExecStart=
ExecStart=/usr/bin/node --import /opt/edge-smart-doh/proxy-preload.mjs /opt/edge-smart-doh/node.mjs
EOF
  ok "代理接线完成（境外上游走代理；NO_PROXY 名单直连${CN_NOPROXY:+：$CN_NOPROXY}）"
else
  # 无代理模式：清掉历史 drop-in，避免旧的 ExecStart 覆盖/代理变量残留
  rm -f "$DROPIN_PROXY"
fi

systemctl daemon-reload
systemctl enable edge-smart-doh >/dev/null 2>&1
# 重跑场景：服务已在运行时 enable 不会重启——env/代理 drop-in 的改动必须 restart 才生效
if systemctl is-active --quiet edge-smart-doh; then
  if [[ -f "$PROJECT_DIR/deploy/restart-keep-state.sh" ]]; then
    bash "$PROJECT_DIR/deploy/restart-keep-state.sh" || systemctl restart edge-smart-doh
  else
    systemctl restart edge-smart-doh
  fi
  ok "服务已重启（应用新 env / drop-in；池子经 keep-state 写回）"
else
  systemctl start edge-smart-doh
fi

TOKEN_FILE="/home/$REAL_USER/doh-admin-token.txt"
sed -n 's/^ADMIN_TOKEN=//p' "$ENV_FILE" > "$TOKEN_FILE"
chown "$REAL_USER":"$REAL_USER" "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

for _ in $(seq 1 15); do curl -fsS http://127.0.0.1:8787/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8787/health >/dev/null \
  || die "服务 15 秒内未就绪：journalctl -u edge-smart-doh -n 30（若见 --import 报错=undici/Node 版本问题）"
ok "edge-smart-doh 运行中；ADMIN_TOKEN 在 $TOKEN_FILE"

# ---------------------------------------------------------------------------
# 4. cfhub → 本机 同步（纯出站）
# ---------------------------------------------------------------------------
log "步骤 4/8：cfhub 优选池同步（每 5 分钟）"

tee /usr/local/bin/cfhub-sync.mjs > /dev/null <<'EOF'
// Sync cfhub published pools (public API) into local edge-smart-doh.
const HUB = "https://cfhub.1molchuan.top/api/v1/pools";
const DOH = process.env.DOH_URL ?? "http://127.0.0.1:8787/admin/preferred";
const TOKEN = process.env.ADMIN_TOKEN ?? "";
if (!TOKEN) { console.error("ADMIN_TOKEN missing"); process.exit(1); }

const res = await fetch(HUB, { signal: AbortSignal.timeout(15000) });
if (!res.ok) { console.error(`cfhub API HTTP ${res.status}`); process.exit(1); }
const { pools = [] } = await res.json();

const byIsp = new Map();
for (const p of pools) {
  if (!p?.published || !Array.isArray(p.ips)) continue;
  const entry = byIsp.get(p.isp) ?? { ipv4: [], ipv6: [] };
  entry[p.family === 6 ? "ipv6" : "ipv4"].push(...p.ips.map((x) => x.ip));
  byIsp.set(p.isp, entry);
}

let ok = 0, fail = 0;
for (const [isp, body] of byIsp) {
  if (body.ipv4.length === 0 && body.ipv6.length === 0) continue;
  const r = await fetch(DOH, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ scope: `isp:${isp}`, source: "cfhub-mirror", ttl: 1800, ...body }),
    signal: AbortSignal.timeout(15000),
  });
  if (r.ok) { ok++; console.log(`isp:${isp} v4=${body.ipv4.length} v6=${body.ipv6.length} -> OK`); }
  else { fail++; console.error(`isp:${isp} -> HTTP ${r.status} ${(await r.text()).slice(0, 200)}`); }
}
console.log(`synced ${ok} pool(s)${fail ? `, ${fail} failed` : ""}`);
if (ok === 0 && byIsp.size > 0) process.exit(1);
EOF
chmod 755 /usr/local/bin/cfhub-sync.mjs

# User=edge-smart-doh：fetch 脚本不必跑 root；EnvironmentFile 由 pid1 以 root 读取，降权无碍
tee /etc/systemd/system/cfhub-sync.service > /dev/null <<'EOF'
[Unit]
Description=Sync cfhub preferred pools into edge-smart-doh
After=network-online.target edge-smart-doh.service
Wants=edge-smart-doh.service

[Service]
Type=oneshot
User=edge-smart-doh
Group=edge-smart-doh
EnvironmentFile=/etc/edge-smart-doh/env
ExecStart=/usr/bin/node /usr/local/bin/cfhub-sync.mjs
EOF

tee /etc/systemd/system/cfhub-sync.timer > /dev/null <<'EOF'
[Unit]
Description=Sync cfhub preferred pools every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cfhub-sync.timer >/dev/null 2>&1
systemctl start cfhub-sync.service >/dev/null 2>&1 || true
sleep 2
if journalctl -u cfhub-sync.service --no-pager -n 10 2>/dev/null | grep -q 'synced'; then
  ok "cfhub 同步成功（journalctl -u cfhub-sync 查明细）"
else
  warn "本次同步未确认（cfhub 站点可能暂不可达）；timer 每 5 分钟自动重试"
fi

# ---------------------------------------------------------------------------
# 5. 本地解析验证
# ---------------------------------------------------------------------------
log "步骤 5/8：本地解析验证"
EXPLAIN="$(curl -fsS "http://127.0.0.1:8787/explain?name=linux.do" 2>/dev/null || true)"
if [[ -n "$EXPLAIN" ]]; then
  printf '%s\n' "$EXPLAIN" | head -c 500; printf '\n  ...\n'
  ok "/explain 可用（应答中 Cloudflare 地址应已换成优选池 IP）"
else
  warn "/explain 无响应，不影响继续；稍后 curl 'http://127.0.0.1:8787/explain?name=linux.do'"
fi

# ---------------------------------------------------------------------------
# 6. 证书（acme.sh DNS-01，全程 root）
# ---------------------------------------------------------------------------
if [[ "$OPEN_PUBLIC" != "1" ]]; then
  log "OPEN_PUBLIC=0：跳过 6/7 步与 8443/DDNS（仅内网部署完成）"
else
  log "步骤 6/8：证书（acme.sh DNS-01，root 模式）"

  if [[ ! -x "$ACME" ]]; then
    # root 装：续期/写证书/reload 全在 root cron，免 sudo
    #（用户装 + sudo install-cert 会在 ~/.acme.sh 留 root 属主文件，60 天后用户 cron 续期写入失败）
    if [[ -z "$ACME_EMAIL" ]]; then
      read -rp "acme.sh 联系邮箱: " ACME_EMAIL
      [[ -n "$ACME_EMAIL" ]] && save_conf ACME_EMAIL "$ACME_EMAIL"
    fi
    curl -s https://get.acme.sh | sh -s "email=$ACME_EMAIL" >/dev/null \
      || die "acme.sh 安装器下载失败（网络）"
    [[ -x "$ACME" ]] || die "acme.sh 安装失败"
    ok "acme.sh 已装到 /root/.acme.sh（root cron 自动续期）"
  fi

  # token 优先级：配置区 > 已存文件 > 交互输入
  NEED_TOKEN=0
  [[ -f "/root/.acme.sh/${DOH_DOMAIN}_ecc/${DOH_DOMAIN}.conf" ]] || NEED_TOKEN=1
  [[ "$SETUP_DDNS" == "1" && ! -s "$CF_TOKEN_FILE" ]] && NEED_TOKEN=1
  if [[ "$NEED_TOKEN" == "1" && -z "$CF_TOKEN" && -s "$CF_TOKEN_FILE" ]]; then
    CF_TOKEN="$(cat "$CF_TOKEN_FILE")"
  fi
  if [[ "$NEED_TOKEN" == "1" && -z "$CF_TOKEN" ]]; then
    read -rsp "CF API Token（权限 Zone:Read + DNS:Edit，限定 $CF_ZONE）: " CF_TOKEN; printf '\n'
  fi
  if [[ -n "$CF_TOKEN" ]]; then
    install -d -m 0755 /etc/edge-smart-doh
    printf '%s' "$CF_TOKEN" > "$CF_TOKEN_FILE"
    chmod 600 "$CF_TOKEN_FILE"
    ok "CF Token 已存 $CF_TOKEN_FILE (600)（acme.sh/DDNS 共用）"
  fi

  "$ACME" --set-default-ca --server letsencrypt >/dev/null
  export CF_Token="${CF_TOKEN:-$(cat "$CF_TOKEN_FILE" 2>/dev/null || true)}"
  set +e
  "$ACME" --issue --dns dns_cf -d "$DOH_DOMAIN" --ecc 2>&1 | tail -3
  RC=${PIPESTATUS[0]}
  set -e
  # rc=2 = "Domains not changed"（已签发且未到续期），幂等重跑的正常路径
  [[ $RC -eq 0 || $RC -eq 2 ]] || die "acme.sh 签发失败 (rc=$RC)：先查 token 是否含 Zone:Read"
  [[ $RC -eq 2 ]] && ok "证书已存在且无需续期" || ok "证书签发成功"

  install -d -m 0750 -o root -g caddy /etc/ssl/doh
  # reloadcmd 维护 caddy 可读权限（caddy.service 是 User=caddy，0600 root 私钥读不了）；
  # 首次执行时 caddy 可能未启动，reload 失败无害——下一步会带新证书启动
  "$ACME" --install-cert -d "$DOH_DOMAIN" --ecc \
    --fullchain-file /etc/ssl/doh/fullchain.pem \
    --key-file      /etc/ssl/doh/privkey.pem \
    --reloadcmd 'chgrp caddy /etc/ssl/doh/privkey.pem; chmod 640 /etc/ssl/doh/privkey.pem; chmod 644 /etc/ssl/doh/fullchain.pem; systemctl reload caddy || true'
  openssl x509 -checkend 2592000 -noout -in /etc/ssl/doh/fullchain.pem \
    && ok "证书就位（30 天内有效；续期由 root cron 自动完成）" \
    || die "证书文件异常"

  # -------------------------------------------------------------------------
  # 7. Caddy 反代 8443
  # -------------------------------------------------------------------------
  log "步骤 7/8：Caddy 反代 8443"

  tee /etc/caddy/Caddyfile > /dev/null <<EOF
{
	https_port 8443
	servers {
		# 路由器只转 TCP：不通告 h3（想开 HTTP/3：路由器补转 UDP 8443 + 删本行 + 防火墙加 udp dport 8443）
		protocols h1 h2
	}
}

${DOH_DOMAIN}:8443 {
	tls /etc/ssl/doh/fullchain.pem /etc/ssl/doh/privkey.pem

	# /admin 永不对外（应用层另有 token 鉴权，这里降噪）
	@admin path /admin/*
	respond @admin "Not found" 404

	# /explain 是调试端点，仅内网可用；/probe 保留公网（外网验收 + 自看出口 IP）
	@explain_external {
		path /explain*
		not client_ip private_ranges
	}
	respond @explain_external "Not found" 404

	reverse_proxy 127.0.0.1:8787 {
		# 用 TCP 对端覆盖可伪造的 X-Real-IP（选池/ECS 依据）
		header_up X-Real-IP {remote_host}
		# DoH 重启的几秒内 hold 住查询而非 502
		lb_try_duration 5s
		lb_try_interval 100ms
	}

	header {
		-Server
		X-Content-Type-Options nosniff
	}
}
EOF

  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || die "Caddyfile 校验失败（未 reload）"
  systemctl enable caddy >/dev/null 2>&1
  if systemctl is-active --quiet caddy; then systemctl reload caddy; else systemctl start caddy; fi
  sleep 1
  curl -fsSk --resolve "$DOH_DOMAIN:8443:127.0.0.1" "https://$DOH_DOMAIN:8443/health" >/dev/null \
    && ok "Caddy 8443 本机验证通过" \
    || die "Caddy 验证失败：journalctl -u caddy -n 30"
fi

# ---------------------------------------------------------------------------
# 8. 防火墙（整文件替换：最小入站规则 + DoH 放行；替换前自动备份）
# ---------------------------------------------------------------------------
if [[ "$SETUP_FIREWALL" == "1" ]]; then
log "步骤 8/8：防火墙（8787 仅内网${FIREWALL_8443:+；8443 公网}）"

[[ -f /etc/nftables.conf ]] && cp -a /etc/nftables.conf "/etc/nftables.conf.pre-doh-$STAMP"

tee /etc/nftables.conf > /dev/null <<EOF
#!/usr/sbin/nft -f
# 由 contrib/home/deploy-home.sh 生成：最小入站 + edge-smart-doh 放行
# 注意：不要加 "flush ruleset"，否则会清掉 Docker 运行时生成的规则

table inet home_firewall {
  chain input {
    type filter hook input priority filter; policy drop;

    # 回环与已建立连接
    iifname "lo" accept
    ct state established,related accept

    # ICMP：ping / 路径MTU / 不可达；IPv6 必须放行邻居发现(NDP)，否则断网
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept

    # DHCP 续约（v4:68 / v6:546）
    udp dport 68 accept
    udp dport 546 accept

    # SSH 与 mosh UDP 段
    tcp dport 22 accept
    udp dport 60000-61000 accept

    # edge-smart-doh
${FIREWALL_8443}
    # 8787：明文 DoH 仅内网直连，绝不放公网
    ip saddr ${LAN_CIDR} tcp dport 8787 accept

    # 其余入站：丢弃并计数
    counter drop
  }
}
EOF

nft -c -f /etc/nftables.conf >/dev/null 2>&1 || die "nft 语法校验失败（未做任何改动）"
nft delete table inet home_firewall 2>/dev/null || true   # 重复 nft -f 会叠加规则，先删再载
nft -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1 || true
nft list table inet home_firewall >/dev/null \
  && ok "防火墙已应用（已建立的 SSH 走 established，不受影响；重启自动加载）"
else
  log "步骤 8/8：防火墙（跳过：SETUP_FIREWALL=0）"
  warn "未改动防火墙。8787 是明文 DoH，只应对内网开放；需要时设 SETUP_FIREWALL=1 重跑（会整体替换 /etc/nftables.conf，入站默认丢弃）"
fi

# ---------------------------------------------------------------------------
# 附加：DDNS（仅维护 A 记录，绝不碰 AAAA / 其他记录）
# ---------------------------------------------------------------------------
if [[ "$OPEN_PUBLIC" == "1" && "$SETUP_DDNS" == "1" ]]; then
  log "附加：DDNS（$DOH_DOMAIN → 当前公网 IPv4）"
  if [[ -s "$CF_TOKEN_FILE" ]]; then
    tee /usr/local/bin/cf-ddns.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
# 把 DoH 域名的 A 记录保持为本机当前公网 IPv4。
# 只管理这一条 A 记录：绝不创建/修改 AAAA，绝不动同区其他记录。
set -euo pipefail
ZONE="__ZONE__"; NAME="__NAME__"
API="https://api.cloudflare.com/client/v4"
TOKEN="$(cat /etc/edge-smart-doh/cf-token)"
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

ip="$(curl -fs4 --max-time 10 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '$1=="ip"{print $2}' || true)"
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || ip="$(curl -fs4 --max-time 10 https://api.ipify.org || true)"
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "无法获取公网 IPv4"; exit 1; }

zid="$(curl -fsS "${AUTH[@]}" "$API/zones?name=$ZONE" | jq -r '.result[0].id // empty')"
[[ -n "$zid" ]] || { echo "查 zone 失败（token 需含 Zone:Read）"; exit 1; }

rec="$(curl -fsS "${AUTH[@]}" "$API/zones/$zid/dns_records?type=A&name=$NAME")"
cur="$(jq -r '.result[0].content // empty' <<<"$rec")"
[[ "$cur" == "$ip" ]] && exit 0

body="$(jq -nc --arg n "$NAME" --arg i "$ip" '{type:"A",name:$n,content:$i,ttl:60,proxied:false}')"
rid="$(jq -r '.result[0].id // empty' <<<"$rec")"
if [[ -n "$rid" ]]; then
  curl -fsS -X PUT "${AUTH[@]}" -d "$body" "$API/zones/$zid/dns_records/$rid" >/dev/null
else
  curl -fsS -X POST "${AUTH[@]}" -d "$body" "$API/zones/$zid/dns_records" >/dev/null
fi
echo "$(date '+%F %T') $NAME A: ${cur:-<无记录>} -> $ip"
EOF
    sed -i "s|__ZONE__|$CF_ZONE|; s|__NAME__|$DOH_DOMAIN|" /usr/local/bin/cf-ddns.sh
    chmod 755 /usr/local/bin/cf-ddns.sh

    tee /etc/systemd/system/cf-ddns.service > /dev/null <<'EOF'
[Unit]
Description=Keep the DoH domain A record at current public IPv4
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cf-ddns.sh
EOF
    tee /etc/systemd/system/cf-ddns.timer > /dev/null <<'EOF'
[Unit]
Description=Run cf-ddns every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now cf-ddns.timer >/dev/null 2>&1
    systemctl start cf-ddns.service >/dev/null 2>&1 || true
    ANS="$(dig +short "$DOH_DOMAIN" A | head -1)"
    [[ -n "$ANS" ]] && ok "DDNS 就绪，当前解析：$ANS" \
      || warn "DDNS 已装但暂无解析（看 journalctl -u cf-ddns -n 5）"
  else
    warn "无 CF Token，跳过 DDNS；拿到 token 后重跑本脚本即可补上"
  fi
fi

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
log "部署汇总"
IP_ADDR="$LAN_IP"
if [[ "$DEPLOY_ENV" != "cn" ]]; then
  printf '  上游模式     : 境外直连（cloudflare/google/adguard）\n'
elif [[ -n "$PROXY_ADDR" ]]; then
  printf '  上游模式     : 国内 + 代理出境（%s）\n' "$PROXY_ADDR"
else
  printf '  上游模式     : 国内无代理（降级：被污染域名解析不到）\n'
fi
for S in edge-smart-doh cfhub-sync.timer caddy cf-ddns.timer; do
  printf '  %-18s %s\n' "$S" "$(systemctl is-active "$S" 2>/dev/null || true)"
done
[[ -f /etc/ssl/doh/fullchain.pem ]] \
  && openssl x509 -noout -enddate -in /etc/ssl/doh/fullchain.pem 2>/dev/null | sed 's/notAfter/证书有效期至/'

if [[ "$OPEN_PUBLIC" == "1" ]]; then
  cat <<EOF

  内网 DoH   : http://$IP_ADDR:8787/dns-query
  公网 DoH   : https://$DOH_DOMAIN:8443/dns-query

  待办（脚本做不了的）：
    1) 主路由（拨号那台）加转发：外部 8443/TCP → $IP_ADDR:8443
    2) 外网验收（手机热点）：
         curl -s https://$DOH_DOMAIN:8443/probe
         dig +https=$DOH_DOMAIN:8443 linux.do A +short
    3) ECH：在浏览器"安全 DNS"里填公网地址（系统/路由器设置拿不到 ECH）
    注意 NAT 回环：在家用域名地址可能不通，在家用内网地址
EOF
else
  cat <<EOF

  内网 DoH   : http://$IP_ADDR:8787/dns-query
  公网入口未开（OPEN_PUBLIC=0）。想开公网：改配置区 OPEN_PUBLIC=1 后重跑本脚本
EOF
fi

ok "部署结束（日志：$LOG_FILE）"
