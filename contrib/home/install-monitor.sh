#!/usr/bin/env bash
# ============================================================================
#  edge-smart-doh 局域网监测站 安装/更新（不动主服务）
#  位置：contrib/home/install-monitor.sh；安全模型见 contrib/home/monitor/monitor.mjs 头注释
#  用法：sudo bash contrib/home/install-monitor.sh
#
#  做的事：
#    1) contrib/home/monitor/monitor.mjs → /opt/edge-smart-doh/monitor.mjs
#    2) /etc/edge-smart-doh/monitor.env（ADMIN_TOKEN 取自主 env；0600，pid1 以 root 读取）
#    3) deploy/edge-smart-doh-monitor.service → /etc/systemd/system/ 并 enable --now
#    4) 8788 端口健康检查
#
#  前提：主服务已带 /admin/stats（重启过新版本 dist/node.mjs），否则页面仍可用但无查询统计。
#  幂等：可反复执行；MONITOR_ALLOW 等自定义配置写在 monitor.env 里会被保留。
# ============================================================================
set -euo pipefail

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  [ok] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m  [x] %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo bash $0"

PROJECT_DIR="${PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}"
ENV_FILE=/etc/edge-smart-doh/env
MON_ENV=/etc/edge-smart-doh/monitor.env
UNIT=/etc/systemd/system/edge-smart-doh-monitor.service

[[ -f "$ENV_FILE" ]] || die "未找到 $ENV_FILE（先跑 contrib/home/deploy-home.sh）"
ADMIN_TOKEN="$(sed -n 's/^ADMIN_TOKEN=//p' "$ENV_FILE" | head -1)"
[[ -n "$ADMIN_TOKEN" ]] || die "$ENV_FILE 里没有 ADMIN_TOKEN"

log "安装监测站文件"
install -d -m 0755 /opt/edge-smart-doh
install -m 0644 "$PROJECT_DIR/contrib/home/monitor/monitor.mjs" /opt/edge-smart-doh/monitor.mjs

# 图表库本地提供（无公网依赖）；缺失时页面降级：图表面板提示加载失败，表格不受影响
if [[ -f "$PROJECT_DIR/contrib/home/monitor/vendor/echarts.min.js" ]]; then
  install -d -m 0755 /opt/edge-smart-doh/vendor
  install -m 0644 "$PROJECT_DIR/contrib/home/monitor/vendor/echarts.min.js" /opt/edge-smart-doh/vendor/echarts.min.js
  ok "ECharts 已安装到 /opt/edge-smart-doh/vendor/（Apache-2.0，本地提供）"
else
  printf '  [!] 缺少 contrib/home/monitor/vendor/echarts.min.js：图表面板将不可用（表格不受影响）\n'
fi

# monitor.env 只在缺失时创建：用户手工加过 MONITOR_* 自定义项不会被覆盖
if [[ ! -f "$MON_ENV" ]]; then
  {
    echo "ADMIN_TOKEN=$ADMIN_TOKEN"
    echo "DOH_URL=http://127.0.0.1:8787"
    echo "MONITOR_HOST=0.0.0.0"
    echo "MONITOR_PORT=8788"
  } > "$MON_ENV"
  chmod 600 "$MON_ENV"
  ok "已生成 $MON_ENV（0600）"
else
  ok "沿用已有 $MON_ENV"
fi

install -m 0644 "$PROJECT_DIR/deploy/edge-smart-doh-monitor.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now edge-smart-doh-monitor >/dev/null 2>&1
systemctl restart edge-smart-doh-monitor   # 更新 monitor.mjs / env 后必须重启才生效

for _ in $(seq 1 15); do
  curl --noproxy '*' -fsS http://127.0.0.1:8788/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl --noproxy '*' -fsS http://127.0.0.1:8788/healthz >/dev/null \
  || die "监测站 15 秒内未就绪：journalctl -u edge-smart-doh-monitor -n 30"

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
ok "监测站运行中：http://${LAN_IP:-<内网IP>}:8788  （仅回环/私网来源可访问）"

# 防火墙提示：SETUP_FIREWALL=1 部署过的机器上 8787 是放行的，8788 也要补一条
if nft list table inet home_firewall >/dev/null 2>&1 \
   && ! nft list table inet home_firewall | grep -q 'tcp dport 8788'; then
  log "补防火墙放行（inet home_firewall 已存在）"
  LAN_CIDR="${LAN_IP%.*}.0/24"
  if nft add rule inet home_firewall input ip saddr "$LAN_CIDR" tcp dport 8788 accept 2>/dev/null; then
    ok "nftables 已放行 8788（$LAN_CIDR；重启后由 deploy-home.sh 生成的规则继续生效）"
  else
    printf '  [!] 自动放行失败，请手工执行（网段换成你的内网段）：\n'
    printf '      nft add rule inet home_firewall input ip saddr 192.168.3.0/24 tcp dport 8788 accept\n'
  fi
fi
