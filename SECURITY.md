# 安全策略 / Security Policy

## 支持范围

安全修复优先合入最新版本。部署者应更新到最新源码，并在更新前同时备份 `.env` 与
完整 SQLite 数据目录。

## 私密报告

请使用 GitHub 仓库的 **Private vulnerability reporting** 功能报告安全问题，不要在
公开 Issue、讨论、日志或截图中披露可利用细节。报告应包含受影响版本、影响范围、
最小复现条件和建议修复方向，但不要附带真实凭据或生产数据。

以下信息尤其不得公开：

- 真实邮箱、应用专用密码、取件 URL 或 `pk_...` token；
- `PICKUP_SESSION_SECRET`、`PICKUP_TOKEN_PEPPER`、Cookie 或 `.env`；
- 数据库、邮件缓存、访问记录、备份与运行日志；
- 服务器地址、SSH 凭据、私有域名、内部 IP 或部署身份。

## 部署者清单

- 使用独立低权限系统用户并限制 `.env`、数据库与备份的文件权限；
- 默认保持 `127.0.0.1` 监听，公网访问通过 HTTPS 反向代理；
- 反向代理必须覆盖客户端传入的 `X-Forwarded-For`，并把代理自身的精确 IP 写入 `PICKUP_TRUSTED_PROXY_IPS`；
- 使用独立后台密码，怀疑泄露时立即轮换密码、会话密钥和取件 token；
- 不需要 IP 归属地时不要设置 `PICKUP_ENABLE_IP_GEO=1`；
- 更新后核对 `/health`、`/ready`、后台登录和一条合成 canary 邮件链路；
- 不把真实运行数据、截图或发布包提交到公开仓库。

---

Security fixes target the latest release. Please report vulnerabilities through GitHub's private
reporting feature and never disclose real mailboxes, app passwords, pickup tokens, environment
files, databases, logs, server identities, or production screenshots in public issues.

Only exact `PICKUP_TRUSTED_PROXY_IPS` may supply forwarded client identities. Full IMAP messages are
size-checked and processed in bounded batches, while login hashing has atomic attempt reservations
and a global concurrency cap.
