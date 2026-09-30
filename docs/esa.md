# Alibaba ESA 对照线路

ESA 是可选 C 线路，不影响 Cloudflare + EdgeOne 主验收。

目标：

```text
esa-doh.example.com -> Alibaba ESA -> origin-doh.example.com -> Cloudflare Worker
```

配置原则与 EdgeOne 一致：HTTPS 回源，Origin Host 与 SNI 均为 `origin-doh.example.com`，`/dns-query*` 绕过 ESA HTTP cache，支持时启用 H2 回源和连接复用。为 ESA 使用一个独立高熵 origin token，或确认两家 CDN 都能安全保存同一个 secret 后复用；客户端 IP header 必须按 ESA 控制台当前实际名称确认，不能猜测。

当前 Worker 只配置一个 `EDGEONE_CLIENT_IP_HEADER`。如果 ESA 与 EdgeOne header 名不同，最小扩展方式是新增一个 `TRUSTED_PROXY_CLIENT_IP_HEADERS` 白名单，并仍以 origin token 作为信任边界；在没有真实 ESA 配置前不提前加入这层复杂度。

验证完成后把 `--esa https://esa-doh.example.com/dns-query` 加入 benchmark。不要从单一网络的一次测试推导全网结论。
