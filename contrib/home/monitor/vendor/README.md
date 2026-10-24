# vendor

本地打包的第三方前端库，由监测站自己提供（`/vendor/…`），仪表盘不依赖公网 CDN，纯内网可用。

| 文件 | 版本 | 来源 | 许可证 |
|---|---|---|---|
| `echarts.min.js` | 5.5.1 | [apache/echarts](https://github.com/apache/echarts)（npmmirror dist 包） | Apache-2.0 |

升级方式：从 npmmirror 或 npm 重新下载对应版本的 `dist/echarts.min.js` 覆盖本文件，再跑一次 `sudo bash contrib/home/install-monitor.sh`。
