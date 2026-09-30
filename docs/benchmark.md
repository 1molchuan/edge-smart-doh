# Benchmark 方法

## 目标

比较同一 Worker Smart DNS 核心的入口差异：

- A：`cf-doh.example.com` → Cloudflare Worker
- B：`doh.example.com` → EdgeOne → `origin-doh.example.com` → Worker
- C（可选）：`esa-doh.example.com` → ESA → `origin-doh.example.com` → Worker
- D：`jp-doh.example.com` → 日本 Azure VPS → Node.js

## 运行

```bash
npm run benchmark -- \
  --direct https://cf-doh.example.com/dns-query \
  --edgeone https://doh.example.com/dns-query \
  --esa https://esa-doh.example.com/dns-query \
  --count 100 \
  --timeout 5000 \
  --curl-protocols
```

机器可读结果：增加 `--json` 并重定向到文件。

每条线路顺序执行：

- `/probe`：入口、TLS/CDN、回源到 Worker 的路径，不做 upstream DNS。
- A / AAAA / HTTPS `example.com`：完整 DoH 处理，包括 Worker cache/upstream。
- 可选 curl：一次 H2 与一次 H3 probe，报告 name lookup、connect、TLS、TTFB、total。curl 不支持对应协议时输出 `supported: false`，不静默降级。

Node `fetch` 无法可靠拆分 DNS/TCP/TLS，因此主统计只报告端到端 latency，不伪造分段精度。

## 采样计划

至少在以下网络分别执行，并保留原始 JSON：

- 中国电信
- 中国联通
- 中国移动
- CERNET

每个网络建议工作日/周末、白天/晚高峰各做多轮。先做 5–10 次预热，再做 100–500 次正式采样。控制客户端、目标域名、query 类型、Worker 配置和时间窗；不要同时修改 ECS/规则后比较入口。

重点比较 success rate、median、p95、p99、stddev。EdgeOne 是否值得保留，应由多个网络的尾延迟和失败率决定，不能只看单次最小值或本机结果。

`work/ssh-home-benchmark.ps1` 测量每次新建 TCP/TLS 连接的冷请求；`work/ssh-home-warm-benchmark.mjs` 会先预热并复用 Node HTTP 连接，更接近长期运行的 DoH 客户端。两类结果应分开解释。
