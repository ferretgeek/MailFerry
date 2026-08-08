# 信渡 / Mail Ferry

[![CI](https://github.com/ferretgeek/MailFerry/actions/workflows/ci.yml/badge.svg)](https://github.com/ferretgeek/MailFerry/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ferretgeek/MailFerry/actions/workflows/codeql.yml/badge.svg)](https://github.com/ferretgeek/MailFerry/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-177e89.svg)](LICENSE)
[![English](https://img.shields.io/badge/README-English-df835e)](README_EN.md)

![信渡界面预览](docs/images/social-preview.png)

把 IMAP 邮箱化成一条条独立、可撤销的取件链接。信渡自托管在你的电脑或服务器上，提供取件页、管理后台、缓存、健康检查和只读 API；运行时只依赖 Python 标准库。

## 一眼看懂

- **独立取件链接**：每个收件邮箱拥有密码学随机 URL，可停用或单独重置。
- **只读且可恢复**：按所属 IMAP 账号组隔离查询，临时断线时仍可读取缓存。
- **完整管理界面**：邮箱组检查、URL 管理、访问统计、分页与搜索都在浏览器完成。
- **四套全局主题**：天际蓝、青岚绿、霞光橙和深灰夜色，右上角切换并自动记忆。
- **安全默认值**：默认只监听 `127.0.0.1`；后台密码从标准输入读取；外部 IP 归属地查询默认关闭。
- **两种部署方式**：Windows、macOS、Linux 均可本地运行，也可在 Linux 服务器用 systemd 长期托管。

## 快速开始

要求 Python 3.10+、SQLite 3.35+。项目没有第三方运行依赖。

```powershell
python --version
python pickup_server/app.py init --admin-password-stdin --base-url "http://127.0.0.1:8080"
python pickup_server/app.py serve
```

第一条命令会从终端安全读取后台密码，并生成仅供本机使用的 `.env` 与 SQLite 数据库。随后访问：

- 管理后台：`http://127.0.0.1:8080/admin`
- 健康检查：`http://127.0.0.1:8080/health`
- 就绪检查：`http://127.0.0.1:8080/ready`

默认不会从局域网或公网访问。确需局域网直连时才显式使用 `--host 0.0.0.0`，并配置防火墙；公网部署推荐保持 `127.0.0.1`，由 Caddy 或 Nginx 提供 HTTPS。

## 导入邮箱

复制 `examples/待导入邮箱/示例账号组.txt` 到一个不进入 Git 的私有目录。每个 TXT 文件代表一个主邮箱账号组：

```text
owner@example.com----应用专用密码
pickup-one@example.com
pickup-two@example.com
```

然后导入并生成 URL：

```powershell
python pickup_server/app.py import --source "私有邮箱文件夹" --base-url "http://127.0.0.1:8080" --output "output/取件URL.txt"
python pickup_server/app.py audit-urls --input "output/取件URL.txt"
```

`audit-urls` 只报告格式、重复与数量，不回显邮箱或 token。完整的服务器部署、更新与回滚步骤见 [部署说明](docs/部署说明.md)，API 和数据模型见 [技术说明](docs/技术说明.md)。

## 取件 API

```text
GET /api/q/<token>/messages?wait=5&limit=30
```

当 `fetch.pending=true` 时，调用方应按 `Retry-After` 或 `fetch.retry_after_seconds` 稍后重试；`fetch.state=degraded` 表示本轮刷新失败，但已有缓存仍然可读。请使用每封邮件的稳定 `id` 去重。

## 隐私边界

运行时会保存邮箱配置、应用专用密码、取件 token、邮件缓存和访问统计。以下内容永远不应提交或公开：

```text
pickup_server/.env
pickup_server/data/
output/
真实邮箱导入文件
```

IP 归属地功能默认关闭。只有部署者显式设置 `PICKUP_ENABLE_IP_GEO=1` 时，访问者 IP 才会发送到受限的 HTTPS 服务 `ipwho.is` 或 `ipapi.co` 并缓存；不需要该能力时请保持关闭。

公开仓库经过源码、历史、文档、图片与元数据扫描，但部署者仍须保护运行时目录并使用 HTTPS。发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 验证

```powershell
python -m compileall -q pickup_server tests
python -m unittest discover -s tests -v
```

发布审计和工具结论记录在 [docs/发布审计.md](docs/发布审计.md)。

## License

[MIT](LICENSE)
