# 信渡维护规则

本文件适用于“信渡 / Mail Ferry”。修改前先阅读 `README.md`、`README_EN.md`、
`SECURITY.md` 与 `docs/发布审计.md`。

## 产品与兼容性

- 保持 Python 3.10+、SQLite 3.35+ 和零第三方运行依赖；Windows、macOS、Linux
  本地入口与 Linux systemd 部署路径都必须可用。
- 取件查询必须按 `group_id` 隔离；数据库变更保持旧数据、现有 token 与回滚能力。
- 管理后台、取件页与登录页必须保留响应式布局、键盘可用性、右上角全局主题选择器、
  三套浅色主题和深灰色暗色主题。主题选择需要持久化。
- 浏览器图标同时维护 SVG 与 ICO。README 首屏与 GitHub Social preview 使用
  1280×640、实色背景、小于 1 MB 的 PNG。

## 安全与发布门禁

- 不提交真实邮箱、应用专用密码、取件 URL、token、`.env`、数据库、邮件缓存、访问
  记录、服务器身份、私有域名、IP、备份或日志。示例只使用 `example.com` 和保留地址。
- 服务默认监听 `127.0.0.1`；公网部署必须经 HTTPS 反向代理。外部 IP 归属地查询保持
  默认关闭，并只能访问代码中的 HTTPS 白名单。
- 日志必须持续脱敏 `pk_...`；后台写操作保持登录校验、同源限制和明确的危险操作确认。
- 发布前至少运行编译、全部单元测试、Ruff、Bandit、依赖漏洞审计、detect-secrets、
  Gitleaks 的工作树与完整 Git 历史扫描，以及桌面和移动端真实渲染检查。
- 静态工具误报需逐项确认并在发布审计中留下依据，不得整类禁用或忽略关键目录。
- 修改公开版本时同步中英文 README、预览图、`CHANGELOG.md`、工作区根 `README.md`
  和 GitHub 个人主页仓库 `README.md`。
