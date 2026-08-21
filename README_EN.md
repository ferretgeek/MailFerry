![IMAP pickup links — one revocable web link per mailbox](docs/images/social-preview.png)

# IMAP pickup links

[中文](README.md) · English

[![CI](https://github.com/ferretgeek/imap-pickup-links/actions/workflows/ci.yml/badge.svg)](https://github.com/ferretgeek/imap-pickup-links/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ferretgeek/imap-pickup-links/actions/workflows/codeql.yml/badge.svg)](https://github.com/ferretgeek/imap-pickup-links/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Standard library](https://img.shields.io/badge/runtime_dependencies-standard_library-177e89)](#getting-started)
[![License: MIT](https://img.shields.io/badge/License-MIT-177e89.svg)](LICENSE)

> One independent web link per mailbox, so someone else can collect a verification code — without you handing over the password.

## Why this exists

Sometimes you need another person — a colleague, a family member, a temporary collaborator — to get a verification code out of a particular mailbox. Usually there are two options: give them the password, or sit there and relay codes by hand.

Neither is good. The first hands over the entire mailbox; the second costs your time.

This is a third option: **a cryptographically random web link per receiving mailbox.** Whoever opens it sees recent mail and codes from that one mailbox — nothing else, and no password. Any link can be disabled or rotated individually at any time.

The service runs on your own machine or server and uses **only the Python standard library** at runtime.

## Interface

![Authenticated dashboard and operational metrics](docs/images/dashboard.png)

![Admin sign-in](docs/images/login.png)

## What it does

- **Independent pickup links** — a cryptographically random URL per mailbox, individually revocable or rotatable, with no cross-effect.
- **Read-only, and degrades gracefully** — queries are isolated per IMAP account group, and cached content stays readable through a temporary upstream outage.
- **A real admin UI** — account-group checks, URL management, access statistics, paging, and search, all in the browser.
- **Four global themes** — Skyline Blue, Verdant Green, Sunset Orange, and deep-gray night, switchable from the top right and remembered.
- **Safe by default** — binds `127.0.0.1`; the admin password is read from stdin (never from shell history); external IP geolocation is off.
- **Local or server** — runs locally on Windows, macOS, and Linux, or long-term under systemd on Linux.

## Getting started

Requires Python 3.10+ and SQLite 3.35+. No third-party runtime dependencies.

```powershell
python --version
python pickup_server/app.py init --admin-password-stdin --base-url "http://127.0.0.1:8080"
python pickup_server/app.py serve
```

The first command reads the admin password securely from the terminal and generates a local-only `.env` and SQLite database. Then visit:

- Admin UI: `http://127.0.0.1:8080/admin`
- Health: `http://127.0.0.1:8080/health`
- Readiness: `http://127.0.0.1:8080/ready`

LAN and internet access are **off** by default. Only pass `--host 0.0.0.0` if you genuinely need direct LAN access, and configure your firewall. For public deployment, keep `127.0.0.1` and let Caddy or Nginx terminate HTTPS.

## Importing mailboxes

Copy `examples/待导入邮箱/示例账号组.txt` into a private directory that **stays out of Git**. Each TXT file represents one primary-account group:

```text
owner@example.com----app-specific-password
pickup-one@example.com
pickup-two@example.com
```

Then import and generate URLs:

```powershell
python pickup_server/app.py import --source "private-mailbox-folder" --base-url "http://127.0.0.1:8080" --output "output/pickup-urls.txt"
python pickup_server/app.py audit-urls --input "output/pickup-urls.txt"
```

`audit-urls` reports format, duplicates, and counts only — it **never echoes an address or token.**

## Pickup API

```text
GET /api/q/<token>/messages?wait=5&limit=30
```

- When `fetch.pending=true`, retry according to `Retry-After` or `fetch.retry_after_seconds`.
- `fetch.state=degraded` means this refresh failed but existing cache is still readable.
- Deduplicate using each message's stable `id`.

## Worth noting technically

**Degraded reads are a deliberate design.** IMAP upstreams misbehave. When that happens the API doesn't just error — it returns `fetch.state=degraded` alongside the existing cache, **and says explicitly that it's degraded.** Someone collecting a code gets the one from ten minutes ago while knowing the data isn't fresh, which is far more useful than a 500.

**Queries are isolated per account group.** A pickup token can only reach the IMAP account group it belongs to; cross-group access is cut off at the data layer rather than filtered in the UI.

**The password comes from stdin.** `--admin-password-stdin` keeps it out of command-line arguments, and therefore out of shell history, `ps` output, and systemd journals.

**IP geolocation is off by default.** Visitor IPs are sent to a restricted HTTPS service (`ipwho.is` or `ipapi.co`) and cached only if the operator explicitly sets `PICKUP_ENABLE_IP_GEO=1`. If you don't need it, leave it off — **visitor IPs shouldn't go to a third party by default.**

**Long polling, not polling.** The `wait` parameter lets callers block for new mail instead of requesting once a second.

**Standard library only.** Server, admin UI, cache, and statistics are all implemented with the Python standard library, so deployment involves no dependency resolution at all.

Full server deployment, update, and rollback steps are in [deployment](docs/部署说明.md); the API and data model are in [technical notes](docs/技术说明.md).

## What it doesn't do

- It doesn't send, delete, or modify anything in a mailbox (read-only).
- It neither accepts nor stores your primary mailbox password — use an app-specific password.
- It provides no public entry point by default (you configure the HTTPS reverse proxy).
- No spam filtering, no mail-client features.

## Privacy boundaries

At runtime it stores mailbox configuration, app-specific passwords, pickup tokens, message cache, and access statistics. The following must **never** be committed or published:

```text
pickup_server/.env
pickup_server/data/
output/
real mailbox import files
```

The public repository has been scanned across source, history, docs, images, and metadata — but the operator still has to protect the runtime directory and use HTTPS. Report security issues privately per [SECURITY.md](SECURITY.md).

## Verification

```powershell
python -m compileall -q pickup_server tests
python -m unittest discover -s tests -v
```

Release-audit findings are recorded in [docs/发布审计.md](docs/发布审计.md).

## More documentation

[Deployment](docs/部署说明.md) · [Technical notes](docs/技术说明.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

[MIT](LICENSE)
