# vless2clash

把 VLESS 分享链接或订阅转换成 Mihomo/Clash YAML，支持明文及 Base64 订阅，并补充旧版 subconverter 缺少的 VLESS xHTTP/SplitHTTP 转换。

默认配置以原项目 `base/base/all_base.tpl` 的 Clash 部分为骨架，并结合项目目录下个人 `xray.json` 中不会被外部配置覆盖的全局设置扩充，副本位于 `src/vless2clash/resources/clash_base.yml`。它保留三个 mixed 入站、DNS hosts 与域名分流、HTTP/TLS 嗅探、日志级别和控制器；订阅节点、代理组、rule-provider 与路由规则仍由输入订阅及外部配置生成。

## 安装

项目已用 `uv init` 初始化，并用 `uv venv` 创建 `.venv`。依赖由 `uv add` 管理：

```bash
uv sync
```

## 使用

使用与 subconverter `/sub` 相近的命令行参数：

```bash
uv run vless2clash \
  --target clash \
  --url 'https://example.com/subscription' \
  --config 'https://example.com/external.ini' \
  --output output.yaml
```

也可以直接传入原来的完整请求 URL：

```bash
uv run vless2clash \
  'http://127.0.0.1:25500/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsubscription&config=https%3A%2F%2Fexample.com%2Fexternal.ini' \
  -o output.yaml
```

也可以在当前目录创建 `.env`，或直接设置同名系统环境变量。系统环境变量会覆盖
`.env`，命令行参数和完整请求 URL 中的对应查询参数会继续优先：

```dotenv
VLESS2CLASH_TARGET=clash
VLESS2CLASH_URL=https://example.com/subscription
VLESS2CLASH_CONFIG=https://example.com/external.ini
VLESS2CLASH_OUTPUT=output.yaml
VLESS2CLASH_TIMEOUT=20
```

随后无需传入转换参数即可运行：

```bash
uv run vless2clash
```

完整请求 URL 也可通过 `VLESS2CLASH_REQUEST` 提供。若环境文件不在当前目录，使用
`--env-file /path/to/settings.env` 指定。

`--url` 支持：

- HTTP/HTTPS 订阅；
- 本地订阅文件；
- 单个 `vless://` 链接；
- 使用 `|` 合并多个输入源；
- 明文、URL-safe Base64/标准 Base64 的 VLESS 列表；
- 已包含 `proxies:` 的 Clash/Mihomo YAML。

## VLESS 传输支持

- TCP/RAW、WebSocket、gRPC、HTTP、H2；
- HTTPUpgrade（转换成 Mihomo 的 WebSocket HTTP Upgrade 表示）；
- xHTTP 和旧称 SplitHTTP；
- xHTTP 的 `path`、`host`、`mode` 及当前 Mihomo `xhttp-opts` 常用字段；
- `extra` 中的 JSON 或 URL-safe Base64 JSON，以及 `xmux`/`reuse-settings`；
- TLS、Reality、ALPN、客户端指纹、`packet-encoding`；
- VLESS `encryption`，包括 ML-KEM-768/X25519 配置串。

外部 INI 当前支持 `custom_proxy_group`、Clash HTTP `ruleset`、`[]` 内联规则、`enable_rule_generator` 和 `overwrite_original_rules`。它不是完整重写 subconverter 的全部脚本、模板和规则格式。

`clash-classic:`、`clash-domain:` 和 `clash-ipcidr:` 保持原有二字段规则集逻辑：转换时不下载规则文件，只在结果中生成 `rule-provider`。

自带第三字段策略/代理组的完整 Clash 规则使用专用的 `clash-rules:` 前缀，不再与二字段规则集自动混合判断：

```ini
ruleset=clash-rules:https://example.com/full-rules.yaml
```

远程 YAML 使用 `rules:` 而不是 rule-provider 的 `payload:`：

```yaml
rules:
  - DOMAIN-SUFFIX,example.com,香港
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,香港
```

脚本只会下载 `clash-rules:` 指定的文件，把其中的完整规则复制进最终配置，并校验每条规则引用的策略。若策略对应的代理组、节点或内置策略不存在，脚本仍会写出完整配置并打印警告，但退出状态为 `2`。若文件仍使用 `payload:` 或某条规则缺少策略字段，则视为格式错误并退出。
