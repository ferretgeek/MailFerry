from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path

PORT = 18090
ADMIN_PASSWORD = "LocalVisualTest-2026-Only"  # pragma: allowlist secret
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def seed() -> None:
    from pickup_server import app

    app.ensure_env()
    app.init_db()
    app.set_admin_password(ADMIN_PASSWORD)
    now = app.utc_now_ts()
    with app.db() as conn:
        app.set_setting(conn, "base_url", f"http://127.0.0.1:{PORT}")
        group = conn.execute(
            """
            INSERT INTO groups(
                master_email,app_password,enabled,last_fetch_at,last_success_at,
                last_error,last_count,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                "harbor@example.test",
                "generated-visual-fixture",
                0,
                now - 180,
                now - 240,
                "视觉预览环境未连接真实 IMAP",
                3,
                now - 86400,
                now,
            ),
        )
        group_id = int(group.lastrowid)
        mailboxes: list[tuple[int, str]] = []
        for index, email in enumerate(
            ("morning@example.test", "studio@example.test", "archive@example.test"),
            start=1,
        ):
            token = "pk_" + secrets.token_urlsafe(32)
            mailbox = conn.execute(
                """
                INSERT INTO mailboxes(
                    group_id,email,token,token_hash,token_tail,enabled,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    group_id,
                    email,
                    token,
                    app.token_hash(token),
                    token[-8:],
                    1 if index < 3 else 0,
                    now - index * 3600,
                    now,
                ),
            )
            mailboxes.append((int(mailbox.lastrowid), email))
        messages = (
            ("m-1", "取件空间已就绪", "hello@example.test", "打开这条链接就能收到验证码。", mailboxes[0][1]),
            ("m-2", "登录验证码 482 731", "security@example.test", "验证码 482 731，十分钟内有效。", mailboxes[1][1]),
            ("m-3", "每周摘要", "notes@example.test", "本周一共接住了 18 封新邮件。", mailboxes[0][1]),
        )
        for index, (uid, subject, sender, body, recipient) in enumerate(messages):
            conn.execute(
                """
                INSERT INTO messages(
                    group_id,uid,subject,sender,recipients,recipient_text,received_at,
                    received_ts,snippet,body,codes,fetched_at,first_seen_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    group_id,
                    uid,
                    subject,
                    sender,
                    f'["{recipient}"]',
                    recipient,
                    app.iso_from_ts(now - index * 1800),
                    now - index * 1800,
                    body,
                    body,
                    "[\"482731\"]" if "验证码" in subject else "[]",
                    now,
                    now - index * 1800,
                ),
            )
        for index in range(8):
            mailbox_id, _email = mailboxes[index % 2]
            conn.execute(
                """
                INSERT INTO access_events(mailbox_id,ip,action,created_at)
                VALUES(?,?,?,?)
                """,
                (
                    mailbox_id,
                    f"203.0.113.{10 + index}",
                    "page" if index % 2 == 0 else "api_messages",
                    now - index * 600,
                ),
            )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mailferry-visual-") as temp:
        home = Path(temp)
        os.environ["PICKUP_SERVER_HOME"] = str(home)
        os.environ["PICKUP_DATA_DIR"] = str(home / "data")
        os.environ["PICKUP_ENV"] = str(home / ".env")
        from pickup_server import app

        seed()
        server = app.PickupHTTPServer(("127.0.0.1", PORT), app.PickupHandler)
        print(f"visual server ready on http://127.0.0.1:{PORT}", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
