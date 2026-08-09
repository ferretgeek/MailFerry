# 更新记录 / Changelog

## Unreleased

- 主页与社交预览改为登录后的真实管理后台；README 同时展示内部工作状态与登录入口，所有画面仅使用合成数据。
- Replaced the profile and social preview with the authenticated dashboard, while keeping the sign-in view as a secondary README image. All visible data is synthetic.

## 1.0.0 - 2026-08-08

- 以“信渡 / Mail Ferry”发布首个公开版本。
- 提供独立取件链接、IMAP 分组隔离、后台管理、访问统计、健康检查和只读 API。
- 增加天际蓝、青岚绿、霞光橙与深灰夜色四套全局主题，并保存用户选择。
- 增加 SVG 与 ICO 浏览器图标、响应式桌面和移动界面。
- 默认监听地址改为 `127.0.0.1`；IP 归属地查询改为显式启用且仅允许 HTTPS 白名单。
- HTTPS 对外地址下的后台 Cookie 自动启用 `Secure`。
- 补齐中英文文档、本地与 systemd 部署、CI、CodeQL、依赖更新和发布审计。

---

- First public release under the Mail Ferry / 信渡 name.
- Ships isolated pickup links, an IMAP-backed cache, dashboard analytics, health probes, and a
  read-only API.
- Adds four persistent global themes, responsive UI, SVG/ICO favicons, secure local-only defaults,
  opt-in HTTPS-only IP geolocation, and hardened admin cookies.
