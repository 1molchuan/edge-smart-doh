# EdgeOne 前置配置

本步骤需要已经可用的 `https://origin-doh.example.com/health`。

## 1. 站点与加速范围

在 EdgeOne 创建站点/域名：

- 公开 hostname：`doh.example.com`
- 服务区域：Global excluding Chinese Mainland（全球可用区，不含中国大陆）
- 按 EdgeOne 给出的目标为 `doh.example.com` 添加 CNAME

由于域名没有中国大陆 ICP 备案，不要选择中国大陆可用区。

## 2. Origin

配置自定义源站：

| 项目 | 值 |
|---|---|
| Origin | `origin-doh.example.com` |
| Protocol | HTTPS |
| Port | 443 |
| Origin Host | `origin-doh.example.com` |
| Origin SNI | `origin-doh.example.com` |
| HTTP/2 origin / connection reuse | 控制台支持时启用 |

不要假设 EdgeOne 一定支持 HTTP/3 回源；客户端到 EdgeOne 的 H3 与回源协议是两件事。

## 3. 安全 header 与真实客户端 IP

添加回源请求 header：

```text
X-DoH-Origin-Token: <与 Cloudflare DOH_ORIGIN_TOKEN 完全相同的 secret>
```

然后在 EdgeOne 当前控制台文档或回源调试中确认「传递真实客户端 IP」的实际 header 名。把这个精确名称写入 `wrangler.jsonc` 的 `EDGEONE_CLIENT_IP_HEADER` 后重新部署 Worker。项目默认值是不可误用的占位符，不代表真实产品 header。

验证方法：临时开启 `DEBUG=true`，发一条来自 EdgeOne 的 `.cn` 查询，确认 upstream 请求包含截断后的 ECS；不要打印完整用户 IP 或 ECS subnet。验证后关闭 DEBUG。

Worker 只有在 origin token 正确时才读取这个 header。普通客户端伪造 `X-Forwarded-For`、`X-Real-IP` 或同名 EdgeOne header 不会被信任。

## 4. Cache rule

创建最高优先级规则：

```text
Path matches /dns-query*
Cache: Bypass
```

DNS 报文不能由 EdgeOne HTTP cache 缓存，因为 POST body、Transaction ID、ECS 和 DNS TTL 都有语义。Worker 自己维护 DNS-aware Cache API。

`/health` 与 `/probe` 可以 bypass，或设置非常短的 cache；benchmark 时建议 bypass，避免把 EdgeOne cache latency 当成 Worker probe。

## 5. 验证

```bash
curl -i https://doh.example.com/health
curl -i https://doh.example.com/probe
curl --fail --output response.bin \
  -H 'Accept: application/dns-message' \
  'https://doh.example.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
```

检查：证书 hostname 正确、无重定向、DoH 返回 `application/dns-message`，并且 origin 日志没有 token 值。

## 6. DNS 切换与回退

- 公开地址：`https://doh.example.com/dns-query`
- Direct CF：`https://cf-doh.example.com/dns-query`

先保持较低 DNS TTL，完成三网多时段 benchmark 后再决定是否把 EdgeOne 设为长期主入口。EdgeOne 故障时，用户可切换到 Direct CF 地址；两者使用同一个 Smart DNS 核心。

## 7. 原生 Edge Function

`src/edgeone.ts` 是 EdgeOne 运行时入口，复用同一套 DNS、ECS、规则、改写和缓存实现。构建命令：

```bash
npm run build:edgeone
```

输出为 `dist/edgeone.js`。原生函数使用全局 `env` 环境变量、`event.waitUntil()`、EdgeOne Cache API，以及 `request.eo.clientIp`；不需要 `X-DoH-Origin-Token`。当前测试地址：

```text
https://eo-native-doh.example.com/dns-query
```

部署辅助脚本从进程环境读取 `EDGEONE_SECRET_ID` 和 `EDGEONE_SECRET_KEY`，凭据不得写入仓库：

```bash
npm run build:edgeone
EDGEONE_TRIGGER_HOST=eo-native-doh.example.com node work/edgeone-deploy-function.mjs
```
