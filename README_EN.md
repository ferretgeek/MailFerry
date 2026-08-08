# Mail Ferry / 信渡

[![CI](https://github.com/ferretgeek/MailFerry/actions/workflows/ci.yml/badge.svg)](https://github.com/ferretgeek/MailFerry/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ferretgeek/MailFerry/actions/workflows/codeql.yml/badge.svg)](https://github.com/ferretgeek/MailFerry/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-177e89.svg)](LICENSE)
[![简体中文](https://img.shields.io/badge/README-简体中文-df835e)](README.md)

![Mail Ferry interface preview](docs/images/social-preview.png)

Mail Ferry turns IMAP mailboxes into independent, revocable pickup links. It is self-hosted on a workstation or server and includes a pickup page, an admin dashboard, caching, health probes, and a read-only API—all with the Python standard library.

## At a glance

- **Independent pickup links:** each recipient gets a cryptographically random URL that can be disabled or rotated on its own.
- **Read-only and resilient:** lookups remain isolated to the owning IMAP group, while cached mail stays available during temporary outages.
- **Complete browser dashboard:** group checks, URL management, analytics, pagination, and search are included.
- **Four global themes:** Sky, Jade, Sunset, and a deep-gray dark theme, selected from the top right and persisted locally.
- **Secure defaults:** listens on `127.0.0.1`, reads the admin password from stdin, and keeps external IP geolocation disabled.
- **Local and server deployment:** runs on Windows, macOS, and Linux, with a systemd path for long-lived Linux hosts.

## Quick start

Python 3.10+ and SQLite 3.35+ are required. There are no third-party runtime dependencies.

```powershell
python --version
python pickup_server/app.py init --admin-password-stdin --base-url "http://127.0.0.1:8080"
python pickup_server/app.py serve
```

The first command reads the dashboard password without placing it in shell history, then creates a local `.env` and SQLite database. Open:

- Dashboard: `http://127.0.0.1:8080/admin`
- Health: `http://127.0.0.1:8080/health`
- Readiness: `http://127.0.0.1:8080/ready`

The default listener is local-only. Use `--host 0.0.0.0` only for an intentional LAN deployment with a firewall. For the public internet, keep the app on `127.0.0.1` and terminate HTTPS with Caddy or Nginx.

## Import mailboxes

Copy `examples/待导入邮箱/示例账号组.txt` into a private directory that is excluded from Git. Each TXT file describes one owner mailbox group:

```text
owner@example.com----app-specific password
pickup-one@example.com
pickup-two@example.com
```

Import it and export pickup links:

```powershell
python pickup_server/app.py import --source "private-mailbox-folder" --base-url "http://127.0.0.1:8080" --output "output/pickup-urls.txt"
python pickup_server/app.py audit-urls --input "output/pickup-urls.txt"
```

`audit-urls` reports structure, duplicates, and counts without printing mailboxes or tokens. See [Deployment](docs/部署说明.md) for server installation, updates, and rollback, and [Technical notes](docs/技术说明.md) for the API and data model.

## Pickup API

```text
GET /api/q/<token>/messages?wait=5&limit=30
```

When `fetch.pending=true`, retry using `Retry-After` or `fetch.retry_after_seconds`. A `fetch.state` of `degraded` means that the latest refresh failed while cached messages remain readable. Deduplicate with each message's stable `id`.

## Privacy boundary

Runtime data includes mailbox configuration, app-specific passwords, pickup tokens, cached messages, and access analytics. Never commit or publish:

```text
pickup_server/.env
pickup_server/data/
output/
real mailbox import files
```

IP geolocation is off by default. Only when the operator explicitly sets `PICKUP_ENABLE_IP_GEO=1` will visitor IPs be sent to the allowlisted HTTPS services `ipwho.is` or `ipapi.co` and cached. Leave it disabled when it is not required.

The public source, Git history, documentation, images, and metadata are scanned before release, but operators must still protect runtime directories and use HTTPS. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Verification

```powershell
python -m compileall -q pickup_server tests
python -m unittest discover -s tests -v
```

Release checks and tool findings are documented in [docs/发布审计.md](docs/发布审计.md).

## License

[MIT](LICENSE)
