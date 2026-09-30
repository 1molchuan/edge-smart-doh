#!/usr/bin/env bash
# Restart edge-smart-doh without losing what the probers taught it. The learned pool, h3 verdicts and
# self-check results live only in memory, so a plain restart falls back to the untested static pool
# until every prober has run again (~10 min). This saves them from the admin API, restarts, and
# posts each source back with its remaining TTL. Run as root on the DoH host, after editing the env.
# Not restored (the API does not expose them): a learned Meta ECH key (the seed is used meanwhile) and
# client-scoped pools; the next prober run brings those back.
set -euo pipefail
command -v node >/dev/null || { echo "node not found: not restarting" >&2; exit 1; }
ENV_FILE=${ENV_FILE:-/etc/edge-smart-doh/env}
ADMIN=${ADMIN:-http://127.0.0.1:8787}
TOKEN=$(grep '^ADMIN_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
STATE=$(mktemp)
trap 'rm -f "$STATE"' EXIT
curl -sf -H "Authorization: Bearer $TOKEN" "$ADMIN/admin/preferred" > "$STATE"
systemctl restart edge-smart-doh
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -H "Authorization: Bearer $TOKEN" "$ADMIN/admin/preferred" && break
  sleep 1
done
TOKEN="$TOKEN" ADMIN="$ADMIN" STATE="$STATE" node --input-type=module -e '
import { readFileSync } from "node:fs";
const state = JSON.parse(readFileSync(process.env.STATE, "utf8"));
const now = Date.now();
const post = async (path, body) => {
  const res = await fetch(process.env.ADMIN + path, {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  console.log(res.status, path, body.source, res.ok ? "" : await res.text());
};
const ttl = (expiresAt) => Math.round((expiresAt - now) / 1000);
for (const s of state.learned?.sources ?? []) {
  if (ttl(s.expiresAt) > 60) await post("/admin/preferred", { source: s.source, ipv4: s.ipv4, ipv6: s.ipv6, ttl: ttl(s.expiresAt) });
}
// Operator pools and the nationwide pool of the hub ("isp:*", pushed by cfhub every 5 min): restored
// so clients do not fall back to the pool of the probers until the next push.
for (const s of state.isp ?? []) {
  if (s.active && ttl(s.expiresAt) > 60) await post("/admin/preferred", { source: s.source, scope: s.scope, ipv4: s.ipv4, ipv6: s.ipv6, ttl: ttl(s.expiresAt) });
}
for (const s of state.h3?.sources ?? []) {
  if (ttl(s.expiresAt) > 0) await post("/admin/h3", { source: s.source, verdicts: s.hosts, ttl: ttl(s.expiresAt) });
}
for (const s of state.selfcheck ?? []) {
  await post("/admin/selfcheck", { source: s.source, ok: s.ok, problems: s.problems ?? [], hosts: s.hosts ?? 0 });
}
'
