#!/usr/bin/env bash
# Install the preferred-IP prober as a systemd timer. Expects, in the current directory:
#   echprobe (linux/amd64 static binary), echprobe-report.service, echprobe-report.timer, env
# and optionally echprobe-{meta,selfcheck,h3}.service/.timer. One Meta checker and one
# self-checker are enough; echprobe-h3 belongs on every prober (h3 needs all of them to agree).
# Each prober gets its own SOURCE; the server combines their reports.
set -euo pipefail

id -u echprobe >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin echprobe
install -d -m 0750 -o root -g echprobe /etc/echprobe
install -m 0640 -o root -g echprobe env /etc/echprobe/env
install -m 0755 echprobe /usr/local/bin/echprobe
[ -f github-extra-hosts ] && install -m 0644 github-extra-hosts /etc/echprobe/github-extra-hosts
timers=(echprobe-report.timer)
install -m 0644 echprobe-report.service /etc/systemd/system/echprobe-report.service
install -m 0644 echprobe-report.timer /etc/systemd/system/echprobe-report.timer
for optional in echprobe-meta echprobe-selfcheck echprobe-h3 echprobe-report6 echprobe-github echprobe-sitecheck; do
  if [ -f "$optional.service" ]; then
    install -m 0644 "$optional.service" "/etc/systemd/system/$optional.service"
    install -m 0644 "$optional.timer" "/etc/systemd/system/$optional.timer"
    timers+=("$optional.timer")
  fi
done
systemctl daemon-reload
systemctl enable --now "${timers[@]}"
systemctl list-timers 'echprobe-*' --no-pager
