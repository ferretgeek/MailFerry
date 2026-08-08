# 参与贡献 / Contributing

感谢参与信渡。修改应保持邮件隔离、运行时隐私与安全默认值，不用伪数据或静默吞错
掩盖真实失败。

## 开发流程

1. 使用 Python 3.10+ 创建独立虚拟环境。
2. 只修改目标相关文件；数据库结构变化需保持旧数据和 token 兼容。
3. 为行为变化补充单元测试；界面变化检查桌面、移动端与四套主题。
4. 提交前执行：

```bash
python -m compileall -q pickup_server tests
python -m unittest discover -s tests -v
ruff check pickup_server tests
bandit -q -r pickup_server
```

## 提交要求

- 测试和文档只使用 `example.com`、保留 IP 与明确的合成值；
- 不提交邮箱、应用专用密码、取件 URL、token、Cookie、`.env`、数据库或日志；
- 不降低后台鉴权、同源保护、日志脱敏、请求限制或默认本机监听；
- 新依赖必须有明确必要性、兼容许可证和安全审计；运行时依赖应尽量保持为零；
- 用户界面保持简体中文、键盘可操作、窄屏无横向溢出。

Please keep runtime data private, preserve group-isolated mailbox lookups and secure defaults,
and add tests for behavior changes. Follow `SECURITY.md` for private vulnerability reports.
