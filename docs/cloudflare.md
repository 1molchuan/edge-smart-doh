# Cloudflare 部署

## 1. 前置条件

- 一个 Cloudflare 账户和可部署 Workers 的 API Token/登录会话。
- 一个由 Cloudflare DNS 托管、可添加 Worker Custom Domain 的域名。
- Node.js 20+。

项目使用 `wrangler.jsonc`、当前兼容日期、`nodejs_compat` 和生成的 `Env` 类型。先执行：

```bash
npm install
npx wrangler whoami
npm run typecheck
npm test
npm run build
```

## 2. 设置 secret

生成高熵共享密钥，并在交互式提示中输入：

```bash
openssl rand -base64 32
npx wrangler secret put DOH_ORIGIN_TOKEN
```

不要把值放进命令参数、`wrangler.jsonc`、`.env.example` 或 Git。EdgeOne 回源 header 使用同一个值。

## 3. 部署与冒烟测试

```bash
npm run deploy
curl https://edge-smart-doh.<your-subdomain>.workers.dev/health
curl https://edge-smart-doh.<your-subdomain>.workers.dev/probe
```

用已知 GET query 验证真实 DNS：

```bash
curl --fail --output response.bin \
  -H 'Accept: application/dns-message' \
  'https://edge-smart-doh.<your-subdomain>.workers.dev/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
```

响应必须为 HTTP 200 且 `Content-Type: application/dns-message`。

## 4. 两个 Custom Domain

Cloudflare Dashboard → Workers & Pages → `edge-smart-doh` → Settings → Domains & Routes → Add → Custom Domain：

1. `origin-doh.example.com`：只作为 EdgeOne/ESA HTTPS 回源 hostname。
2. `cf-doh.example.com`：公开 fallback 和 Direct CF benchmark。

两个 hostname 均指向同一个 Worker。不要把 `doh.example.com` 绑定为 Custom Domain；它必须由 EdgeOne CNAME 接管。

## 5. 防滥用建议

在 `cf-doh.example.com` 与 `origin-doh.example.com` 所在 zone 配置：

- 只允许 `/dns-query` 的 GET/POST，`/health`、`/probe` 的 GET。
- 对单 IP 的 `/dns-query` 应用按实际用户规模调节的 Rate Limiting rule。
- 不对 DNS endpoint 使用 HTML challenge；DoH 客户端无法完成浏览器 challenge。
- 观察 4xx、5xx、CPU time 和请求量后再收紧，不在代码中自造 DDoS 系统。

`origin-doh` 可以保持可直接访问；不带正确 origin token 的请求只是不被允许提供 EdgeOne 客户端 IP，不会破坏 `cf-doh` fallback。

## 6. 配置变更

修改 `wrangler.jsonc` 中的普通变量后运行：

```bash
npx wrangler types
npm run typecheck
npm test
npm run deploy
```

回滚：

```bash
npx wrangler versions list
npx wrangler rollback
```
