from __future__ import annotations

import json
import queue
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest import mock

from pickup_server import app


class PickupAppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)
        self.saved = {
            "APP_DIR": app.APP_DIR,
            "DATA_DIR": app.DATA_DIR,
            "DB_PATH": app.DB_PATH,
            "ENV_PATH": app.ENV_PATH,
            "DB_INITIALIZED": app.DB_INITIALIZED,
            "ENV_CACHE": app.ENV_CACHE,
            "ACCESS_EVENT_QUEUE": app.ACCESS_EVENT_QUEUE,
            "ACCESS_EVENT_THREAD": app.ACCESS_EVENT_THREAD,
        }
        app.APP_DIR = self.home
        app.DATA_DIR = self.home / "data"
        app.DB_PATH = app.DATA_DIR / "pickup.db"
        app.ENV_PATH = self.home / ".env"
        app.DB_INITIALIZED = False
        app.ENV_CACHE = None
        app.ACCESS_EVENT_QUEUE = queue.Queue(maxsize=1000)
        app.ACCESS_EVENT_THREAD = None
        app.ACCESS_EVENT_STOP.clear()
        app.TOKEN_MISS_CACHE.clear()
        app.REALTIME_FETCH_LAST.clear()
        app.REALTIME_FETCH_PENDING.clear()
        app.REALTIME_FETCH_ACTIVE.clear()
        app.REALTIME_FETCH_INFLIGHT.clear()
        app.REALTIME_FETCH_COMPLETED.clear()
        app.REALTIME_FETCH_RESULTS.clear()
        app.REALTIME_EMAIL_COMPLETED.clear()
        app.REALTIME_EMAIL_RESULTS.clear()
        app.ACCESS_EVENT_LAST.clear()
        app.FETCH_LOCKS.clear()
        app.REALTIME_FETCH_LIMITERS.clear()
        app.ensure_env()
        app.init_db()

    def tearDown(self) -> None:
        app.stop_access_event_writer(timeout=1.0)
        for name, value in self.saved.items():
            setattr(app, name, value)
        self.temp_dir.cleanup()

    def seed_group(
        self,
        mailbox_email: str = "alias+g1@example.test",
        master_email: str = "master@example.test",
    ) -> tuple[int, int, str]:
        now = app.utc_now_ts()
        token = "pk_" + "A" * 43
        with app.db() as conn:
            cursor = conn.execute(
                "INSERT INTO groups(master_email, app_password, created_at, updated_at) VALUES(?, ?, ?, ?)",
                (master_email, "test-password", now, now),
            )
            group_id = int(cursor.lastrowid)
            cursor = conn.execute(
                """
                INSERT INTO mailboxes(group_id, email, token, token_hash, token_tail, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (group_id, mailbox_email, token, app.token_hash(token), token[-8:], now, now),
            )
            mailbox_id = int(cursor.lastrowid)
        return group_id, mailbox_id, token

    def test_safe_local_defaults_and_global_theme_contract(self) -> None:
        args = app.build_parser().parse_args(["serve"])

        self.assertEqual("127.0.0.1", args.host)
        for html_source in (app.PICKUP_HTML, app.ADMIN_HTML, app.LOGIN_HTML):
            self.assertIn('href="/favicon.svg"', html_source)
            self.assertIn('href="/favicon.ico"', html_source)
            self.assertIn("<!-- THEME_PICKER -->", html_source)
            self.assertIn("<!-- THEME_SCRIPT -->", html_source)
        for theme in ("sky", "jade", "sunset", "dark"):
            self.assertIn(f'data-theme-value="{theme}"', app.THEME_PICKER_HTML)
        self.assertIn("#17191d", app.SHARED_THEME_STYLE)
        self.assertGreater(app.FAVICON_ICO_PATH.stat().st_size, 1024)

    def test_ip_geo_is_opt_in_and_rejects_unapproved_urls(self) -> None:
        with mock.patch.object(app, "IP_GEO_ENABLED", False), mock.patch.object(
            app.threading, "Thread"
        ) as thread:
            app.schedule_geo_lookups(["203.0.113.8"], {})
        thread.assert_not_called()

        for url in ("http://geo.example.test/203.0.113.8", "https://example.com/geo"):
            with self.assertRaisesRegex(ValueError, "不允许"):
                app.fetch_json_url(url)

    def test_https_base_url_adds_secure_admin_cookie(self) -> None:
        with app.db() as conn:
            app.set_setting(conn, "base_url", "https://pickup.example.test")

        cookie = app.admin_cookie("synthetic-session", 120)

        self.assertIn("; Secure", cookie)
        self.assertIn("; HttpOnly", cookie)
        self.assertIn("; SameSite=Lax", cookie)

    def test_login_page_and_favicon_routes_render_shared_ui(self) -> None:
        server = app.PickupHTTPServer(("127.0.0.1", 0), app.PickupHandler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.object(app.PickupHandler, "log_message"):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/admin", timeout=2) as response:
                    page = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/favicon.ico", timeout=2
                ) as response:
                    icon_type = response.headers.get_content_type()
                    icon = response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertIn("信渡 · 管理后台", page)
        self.assertIn("天际蓝", page)
        self.assertIn("深灰夜色", page)
        self.assertNotIn("<!-- THEME_", page)
        self.assertEqual("image/x-icon", icon_type)
        self.assertGreater(len(icon), 1024)

    def test_existing_token_recovers_after_pepper_change(self) -> None:
        _, mailbox_id, token = self.seed_group()
        app.ENV_CACHE = {
            "PICKUP_SESSION_SECRET": "new-session-secret",  # pragma: allowlist secret
            "PICKUP_TOKEN_PEPPER": "new-token-pepper",  # pragma: allowlist secret
        }

        row = app.lookup_mailbox_by_token(token)

        self.assertIsNotNone(row)
        self.assertEqual(mailbox_id, int(row["mailbox_id"]))
        with app.db() as conn:
            stored = conn.execute(
                "SELECT token_hash FROM mailboxes WHERE id = ?", (mailbox_id,)
            ).fetchone()[0]
        self.assertEqual(app.token_hash(token), stored)

    def test_old_database_schema_migrates_without_losing_existing_url(self) -> None:
        app.DB_PATH.unlink()
        token = "pk_" + "M" * 43
        now = app.utc_now_ts()
        connection = sqlite3.connect(app.DB_PATH)
        connection.executescript(
            """
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE groups(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                master_email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                app_password TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_fetch_at REAL,
                last_error TEXT,
                last_count INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE mailboxes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                token TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL UNIQUE,
                token_tail TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                uid TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                recipients TEXT,
                recipient_text TEXT,
                received_at TEXT,
                received_ts REAL,
                snippet TEXT,
                body TEXT,
                codes TEXT,
                fetched_at REAL NOT NULL,
                UNIQUE(group_id, uid)
            );
            CREATE TABLE access_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mailbox_id INTEGER,
                ip TEXT,
                action TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        group_id = int(
            connection.execute(
                "INSERT INTO groups(master_email, app_password, created_at, updated_at) VALUES(?, ?, ?, ?)",
                ("legacy@example.test", "password", now, now),
            ).lastrowid
        )
        connection.execute(
            """
            INSERT INTO mailboxes(group_id, email, token, token_hash, token_tail, created_at, updated_at)
            VALUES(?, ?, ?, 'legacy-hash', ?, ?, ?)
            """,
            (group_id, "legacy-alias@example.test", token, token[-8:], now, now),
        )
        connection.execute(
            "INSERT INTO messages(group_id, uid, recipients, recipient_text, fetched_at) "
            "VALUES(?, '900', ?, ?, ?)",
            (group_id, "legacy-alias@example.test", "legacy-alias@example.test", now),
        )
        connection.commit()
        connection.close()
        app.DB_INITIALIZED = False

        app.init_db()

        with app.db() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(groups)")}
            migrated_cursor = int(
                conn.execute(
                    "SELECT last_seen_uid FROM groups WHERE id = ?", (group_id,)
                ).fetchone()[0]
            )
        self.assertTrue(
            {"last_seen_uid", "last_success_at", "last_full_fetch_at", "uid_validity"}
            <= columns
        )
        self.assertEqual(
            "legacy-alias@example.test",
            app.lookup_mailbox_by_token(token)["email"],
        )
        self.assertEqual(0, migrated_cursor)

    def test_received_for_header_is_used_for_exact_recipient(self) -> None:
        raw = (
            b"Received: from sender.example by mx.example "
            b"for <alias+g2@example.test>; Tue, 14 Jul 2026 10:00:00 +0000\r\n"
            b"To: undisclosed-recipients:;\r\nSubject: test\r\n\r\n"
        )
        message = BytesParser(policy=policy.default).parsebytes(raw)

        _, recipient_text = app.build_recipient_text(message)

        self.assertTrue(
            app.exact_recipient_match(recipient_text, {"alias+g2@example.test"})
        )

    def test_code_extraction_supports_common_separated_and_alphanumeric_codes(self) -> None:
        codes = app.extract_codes(
            "Your OTP: AB12-CD34",
            "Your verification code is 123-456.",
        )

        self.assertIn("AB12-CD34", codes)
        self.assertIn("123456", codes)

    def test_missing_date_uses_null_so_database_can_fallback_to_fetch_time(self) -> None:
        parsed = app.parse_message(
            "1",
            b"To: alias+g1@example.test\r\nSubject: code 123456\r\n\r\nbody",
            1,
        )

        self.assertIsNone(parsed["received_ts"])

    def test_connect_imap_tries_backup_host_when_first_connection_fails(self) -> None:
        working = mock.Mock()
        working.login.return_value = ("OK", [b"logged in"])
        with (
            mock.patch.object(
                app.imaplib,
                "IMAP4_SSL",
                side_effect=[OSError("first host down"), working],
            ) as constructor,
            mock.patch.object(
                app,
                "imap_servers_for_email",
                return_value=[
                    ("imap-a.example.test", 993),
                    ("imap-b.example.test", 993),
                ],
            ),
        ):
            result = app.connect_imap_client("example-only@example.test", "password")

        self.assertIs(result, working)
        self.assertEqual(2, constructor.call_count)

    def test_imap_fetch_retries_only_missing_uids(self) -> None:
        client = mock.Mock()
        client.uid.side_effect = [
            (
                "OK",
                [(b"1 (UID 1 BODY[] {3})", b"one")],
            ),
            (
                "OK",
                [(b"2 (UID 2 BODY[] {3})", b"two")],
            ),
        ]

        result = app.imap_fetch_map(client, [b"1", b"2"], "UID BODY.PEEK[]")

        self.assertEqual({"1": b"one", "2": b"two"}, result)
        self.assertEqual("2", client.uid.call_args_list[1].args[1])

    def test_uidvalidity_change_namespaces_old_uids_and_resets_cursor(self) -> None:
        group_id, _, _ = self.seed_group()
        with app.db() as conn:
            conn.execute(
                "UPDATE groups SET uid_validity = 'old-generation', last_seen_uid = 99 WHERE id = ?",
                (group_id,),
            )
            conn.execute(
                "INSERT INTO messages(group_id, uid, fetched_at, first_seen_at) VALUES(?, '7', ?, ?)",
                (group_id, app.utc_now_ts(), app.utc_now_ts()),
            )

        changed = app.reconcile_uid_validity(group_id, "new-generation")

        self.assertTrue(changed)
        with app.db() as conn:
            group = conn.execute(
                "SELECT uid_validity, last_seen_uid FROM groups WHERE id = ?", (group_id,)
            ).fetchone()
            uid = conn.execute(
                "SELECT uid FROM messages WHERE group_id = ?", (group_id,)
            ).fetchone()[0]
        self.assertEqual("new-generation", group["uid_validity"])
        self.assertEqual(0, group["last_seen_uid"])
        self.assertEqual("vold-generation:7", uid)

    def test_requested_mail_can_be_recovered_from_junk_folder(self) -> None:
        group_id, _, _ = self.seed_group()

        class JunkImap:
            def select(self, folder, **_kwargs):
                return ("OK", [b"1"]) if folder == "Junk" else ("NO", [])

            def response(self, name):
                return name, [b"55"]

            def uid(self, command, *args):
                if command == "SEARCH":
                    return "OK", [b"9"]
                if command == "FETCH":
                    raw = (
                        b"To: alias+g1@example.test\r\n"
                        b"Subject: Junk verification code 654321\r\n\r\n"
                        b"Verification code: 654321"
                    )
                    return "OK", [(b"9 (UID 9 BODY[] {100})", raw)]
                raise AssertionError((command, args))

        rows, scanned, partial = app.fetch_extra_folder_messages(
            JunkImap(),
            group_id,
            {"alias+g1@example.test"},
            "13-Jul-2026",
        )

        self.assertEqual(1, scanned)
        self.assertFalse(partial)
        self.assertEqual(1, len(rows))
        self.assertTrue(str(rows[0]["uid"]).endswith(":9"))
        self.assertIn("654321", json.loads(str(rows[0]["codes"])))

    def test_all_available_extra_folders_are_scanned(self) -> None:
        group_id, _, _ = self.seed_group()

        class MultiFolderImap:
            def __init__(self) -> None:
                self.folder = ""
                self.selected: list[str] = []

            def select(self, folder, **_kwargs):
                self.folder = folder
                self.selected.append(folder)
                return ("OK", [b"1"]) if folder in {"Junk", "Spam"} else ("NO", [])

            def response(self, name):
                return name, [b"56" if self.folder == "Spam" else b"55"]

            def uid(self, command, *args):
                if command == "SEARCH":
                    return "OK", [b"9" if self.folder == "Spam" else b""]
                if command == "FETCH" and self.folder == "Spam":
                    raw = (
                        b"To: alias+g1@example.test\r\n"
                        b"Subject: Spam verification code 112233\r\n\r\n"
                        b"Verification code: 112233"
                    )
                    return "OK", [(b"9 (UID 9 BODY[] {100})", raw)]
                raise AssertionError((self.folder, command, args))

        client = MultiFolderImap()
        rows, scanned, partial = app.fetch_extra_folder_messages(
            client,
            group_id,
            {"alias+g1@example.test"},
            "13-Jul-2026",
        )

        self.assertEqual(["Junk", "Spam", "Junk Email"], client.selected)
        self.assertEqual(1, scanned)
        self.assertFalse(partial)
        self.assertEqual(1, len(rows))
        self.assertIn("112233", json.loads(str(rows[0]["codes"])))

    def test_extra_folder_select_exception_is_reported_as_partial(self) -> None:
        group_id, _, _ = self.seed_group()

        class DisconnectedImap:
            def select(self, *_args, **_kwargs):
                raise OSError("connection lost")

        rows, scanned, partial = app.fetch_extra_folder_messages(
            DisconnectedImap(),
            group_id,
            {"alias+g1@example.test"},
            "13-Jul-2026",
        )

        self.assertEqual([], rows)
        self.assertEqual(0, scanned)
        self.assertTrue(partial)

    def test_old_inbox_match_does_not_prevent_requested_junk_scan(self) -> None:
        group_id, _, _ = self.seed_group()
        old_row = app.parse_message(
            "9",
            b"To: alias+g1@example.test\r\nSubject: old inbox code 111111\r\n\r\n111111",
            group_id,
        )
        with app.db() as conn:
            app.store_messages(conn, group_id, [old_row])

        class InboxImap:
            def select(self, folder, **_kwargs):
                self.folder = folder
                return "OK", [b"1"]

            def response(self, name):
                return name, [b"55"]

            def uid(self, command, *args):
                if command == "SEARCH":
                    return "OK", [b"9"]
                if command == "FETCH":
                    raw = b"To: alias+g1@example.test\r\nSubject: old inbox code 111111\r\n\r\n"
                    return "OK", [(b"9 (UID 9 BODY[] {80})", raw)]
                raise AssertionError((command, args))

            def logout(self):
                return "BYE", []

        junk_row = app.parse_message(
            "fjunk:v55:10",
            b"To: alias+g1@example.test\r\nSubject: new junk code 445566\r\n\r\n445566",
            group_id,
        )
        with mock.patch.object(app, "connect_imap_client", return_value=InboxImap()), mock.patch.object(
            app,
            "fetch_extra_folder_messages",
            return_value=([junk_row], 1, False),
        ) as extra_fetch:
            result = app.refresh_group_recent(
                group_id,
                requested_emails={"alias+g1@example.test"},
            )

        self.assertTrue(result["ok"])
        self.assertEqual(
            {"alias+g1@example.test"},
            extra_fetch.call_args.args[2],
        )
        with app.db() as conn:
            stored = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE group_id = ? AND uid = 'fjunk:v55:10'",
                (group_id,),
            ).fetchone()[0]
        self.assertEqual(1, stored)

    def test_full_scan_does_not_jump_over_unscanned_middle_and_stores_newest_first(self) -> None:
        group_id, _, _ = self.seed_group()

        class BulkImap:
            def __init__(self) -> None:
                self.uids = list(range(1, 2101))

            def select(self, *_args, **_kwargs):
                return "OK", [b"2100"]

            def response(self, name):
                self_name = name
                return self_name, [b"777"]

            def logout(self):
                return "BYE", []

            def uid(self, command, *args):
                if command == "SEARCH":
                    criteria = [str(item) for item in args if item is not None]
                    if "UID" in criteria:
                        start = int(criteria[-1].split(":", 1)[0])
                        values = [uid for uid in self.uids if uid >= start]
                    else:
                        values = self.uids
                    return "OK", [" ".join(map(str, values)).encode("ascii")]
                if command != "FETCH":
                    raise AssertionError(command)
                uid_values = [int(value) for value in str(args[0]).split(",") if value]
                header_only = "HEADER" in str(args[1]).upper()
                payloads = []
                for uid in uid_values:
                    recipient = (
                        "alias+g1@example.test" if uid in {1300, 2100} else "other@example.test"
                    )
                    body = (
                        f"To: {recipient}\r\n"
                        f"Date: Tue, 14 Jul 2026 10:00:{uid % 60:02d} +0000\r\n"
                        f"Subject: code {100000 + uid}\r\n"
                    )
                    if not header_only:
                        body += f"\r\nVerification code: {100000 + uid}"
                    raw = body.encode("ascii")
                    meta = f"{uid} (UID {uid} BODY[] {{{len(raw)}}})".encode("ascii")
                    payloads.append((meta, raw))
                return "OK", payloads

        with mock.patch.object(app, "connect_imap_client", side_effect=lambda *_: BulkImap()):
            first = app.fetch_group(group_id, force=True)
            with app.db() as conn:
                first_uids = {
                    row[0]
                    for row in conn.execute(
                        "SELECT uid FROM messages WHERE group_id = ?", (group_id,)
                    ).fetchall()
                }
            second = app.fetch_group(group_id, force=True)

        self.assertTrue(first["ok"])
        self.assertEqual(1200, first["last_seen_uid"])
        self.assertIn("2100", first_uids)
        self.assertNotIn("1300", first_uids)
        self.assertTrue(second["ok"])
        with app.db() as conn:
            final_uids = {
                row[0]
                for row in conn.execute(
                    "SELECT uid FROM messages WHERE group_id = ?", (group_id,)
                ).fetchall()
            }
        self.assertIn("1300", final_uids)
        self.assertIn("2100", final_uids)

    def test_realtime_attempt_does_not_suppress_full_scan(self) -> None:
        group_id, _, _ = self.seed_group()
        with app.db() as conn:
            conn.execute(
                "UPDATE groups SET last_fetch_at = ?, last_full_fetch_at = NULL WHERE id = ?",
                (app.utc_now_ts(), group_id),
            )

        class EmptyImap:
            def select(self, *_args, **_kwargs):
                return "OK", [b"0"]

            def response(self, name):
                return name, [b"1"]

            def uid(self, command, *_args):
                if command == "SEARCH":
                    return "OK", [b""]
                raise AssertionError(command)

            def logout(self):
                return "BYE", []

        with mock.patch.object(app, "connect_imap_client", return_value=EmptyImap()) as connect:
            result = app.fetch_group(group_id, force=False)

        self.assertTrue(result["ok"])
        self.assertFalse(result.get("skipped", False))
        connect.assert_called_once()

    def test_access_logging_never_waits_for_database_writer(self) -> None:
        _, mailbox_id, _ = self.seed_group()
        blocker = sqlite3.connect(app.DB_PATH, timeout=0)
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            app.record_access_event(mailbox_id, "127.0.0.1", "api_messages", 200)
        finally:
            blocker.rollback()
            blocker.close()

        self.assertLess(time.monotonic() - started, 0.05)
        self.assertEqual(1, app.ACCESS_EVENT_QUEUE.qsize())

    def test_access_writer_flushes_queued_events_in_batch(self) -> None:
        _, mailbox_id, _ = self.seed_group()
        app.start_access_event_writer()

        app.record_access_event(mailbox_id, "127.0.0.1", "api_messages", 200)
        app.ACCESS_EVENT_QUEUE.join()

        with app.db() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM access_events").fetchone()[0])
        self.assertEqual(1, count)

    def test_busy_http_admission_rejects_without_waiting(self) -> None:
        server = object.__new__(app.PickupHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()
        started = time.monotonic()
        with mock.patch.object(server, "reject_busy_request") as reject:
            server.process_request(object(), ("127.0.0.1", 1))

        self.assertLess(time.monotonic() - started, 0.05)
        reject.assert_called_once()

    def test_api_contract_distinguishes_pending_from_empty_mailbox(self) -> None:
        group_id, _, token = self.seed_group()

        def schedule(*_args, **_kwargs):
            with app.REALTIME_FETCH_GUARD:
                app.REALTIME_FETCH_INFLIGHT.add(group_id)
                app.REALTIME_FETCH_ACTIVE[group_id] = {"alias+g1@example.test"}
            return {"ok": True, "realtime": True, "background": True, "started": True}

        with mock.patch.object(app, "refresh_group_recent_for_api", side_effect=schedule):
            result = app.mailbox_messages(token)
        with app.REALTIME_FETCH_GUARD:
            app.REALTIME_FETCH_INFLIGHT.discard(group_id)
            app.REALTIME_FETCH_ACTIVE.pop(group_id, None)

        self.assertTrue(result["ok"])
        self.assertEqual("alias+g1@example.test", result["email"])
        self.assertEqual([], result["messages"])
        self.assertEqual("pending", result["fetch"]["state"])
        self.assertTrue(result["fetch"]["pending"])
        self.assertFalse(result["fetch"]["completed"])
        self.assertFalse(result["fetch"]["fresh"])

    def test_wait_is_not_completed_by_an_unrelated_realtime_batch(self) -> None:
        group_id, _, _ = self.seed_group()
        target = "alias+g1@example.test"
        after = app.utc_now_ts()
        result_box: list[dict[str, object] | None] = []
        with app.REALTIME_FETCH_CONDITION:
            app.REALTIME_FETCH_ACTIVE[group_id] = {"other@example.test"}
            app.REALTIME_FETCH_PENDING[group_id] = {target}

        waiter = threading.Thread(
            target=lambda: result_box.append(
                app.wait_for_realtime_refresh(group_id, target, after, 1.0)
            )
        )
        waiter.start()
        time.sleep(0.03)
        with app.REALTIME_FETCH_CONDITION:
            app.REALTIME_FETCH_COMPLETED[group_id] = after + 1
            app.REALTIME_FETCH_RESULTS[group_id] = {"ok": True, "batch": "other"}
            app.REALTIME_FETCH_CONDITION.notify_all()
        time.sleep(0.03)
        self.assertTrue(waiter.is_alive())

        with app.REALTIME_FETCH_CONDITION:
            app.REALTIME_FETCH_PENDING[group_id].discard(target)
            app.REALTIME_FETCH_ACTIVE[group_id] = {target}
            app.REALTIME_EMAIL_COMPLETED[(group_id, target)] = after + 2
            app.REALTIME_EMAIL_RESULTS[(group_id, target)] = {"ok": True, "batch": "target"}
            app.REALTIME_FETCH_ACTIVE.pop(group_id, None)
            app.REALTIME_FETCH_CONDITION.notify_all()
        waiter.join(timeout=1)

        self.assertFalse(waiter.is_alive())
        self.assertEqual("target", result_box[0]["batch"])

    def test_realtime_thread_start_failure_rolls_back_inflight_state(self) -> None:
        group_id, _, _ = self.seed_group()
        target = "alias+g1@example.test"

        with mock.patch.object(app.threading.Thread, "start", side_effect=RuntimeError("no thread")):
            result = app.refresh_group_recent_for_api(group_id, target)

        self.assertFalse(result["ok"])
        with app.REALTIME_FETCH_GUARD:
            self.assertNotIn(group_id, app.REALTIME_FETCH_INFLIGHT)
            self.assertIn(target, app.REALTIME_FETCH_PENDING[group_id])

    def test_poll_due_selection_prioritizes_never_scheduled_groups(self) -> None:
        next_due: dict[int, float] = {}
        order: list[int] = []
        for tick in range(7):
            selected = app.due_poll_groups(
                list(range(1, 8)),
                set(),
                next_due,
                float(tick),
                1,
            )
            self.assertEqual(1, len(selected))
            group_id = selected[0]
            order.append(group_id)
            next_due[group_id] = float(tick + 6)

        self.assertEqual(list(range(1, 8)), order)

    def test_poll_loop_recovers_after_executor_submit_failure(self) -> None:
        group_id, _, _ = self.seed_group()
        app.POLL_STOP.clear()
        instances = []
        attempts: list[tuple[int, int]] = []

        class FakeExecutor:
            def __init__(self, index: int) -> None:
                self.index = index
                self.shutdown_called = False

            def submit(self, _fn, submitted_group_id, _force):
                attempts.append((self.index, submitted_group_id))
                if self.index == 0:
                    raise RuntimeError("temporary thread exhaustion")
                future = app.Future()
                future.set_result({"ok": True})
                app.POLL_STOP.set()
                return future

            def shutdown(self, **_kwargs):
                self.shutdown_called = True

        def make_executor(**_kwargs):
            instance = FakeExecutor(len(instances))
            instances.append(instance)
            return instance

        clock = 0.0

        def advancing_clock():
            nonlocal clock
            clock += 10.0
            return clock

        try:
            with mock.patch.object(app, "ThreadPoolExecutor", side_effect=make_executor), mock.patch.object(
                app.time, "sleep", return_value=None
            ), mock.patch.object(
                app.time, "monotonic", side_effect=advancing_clock
            ), mock.patch.object(
                app.POLL_STOP,
                "wait",
                side_effect=lambda _timeout: app.POLL_STOP.is_set(),
            ):
                app.poll_loop()
        finally:
            app.POLL_STOP.clear()

        self.assertGreaterEqual(len(instances), 2)
        self.assertEqual([(0, group_id), (1, group_id)], attempts[:2])
        self.assertTrue(instances[0].shutdown_called)

    def test_waiting_api_call_returns_message_from_completed_refresh(self) -> None:
        group_id, _, token = self.seed_group()

        def refresh(_group_id, requested_emails=None, wait_timeout=0):
            self.assertEqual(group_id, _group_id)
            self.assertIn("alias+g1@example.test", requested_emails or set())
            row = app.parse_message(
                "88",
                b"To: alias+g1@example.test\r\n"
                b"Date: Tue, 14 Jul 2026 10:00:00 +0000\r\n"
                b"Subject: Login code 778899\r\n\r\nVerification code: 778899",
                group_id,
            )
            with app.db() as conn:
                app.store_messages(conn, group_id, [row])
                conn.execute(
                    "UPDATE groups SET last_fetch_at = ?, last_success_at = ?, last_error = NULL WHERE id = ?",
                    (app.utc_now_ts(), app.utc_now_ts(), group_id),
                )
            return {"ok": True, "realtime": True, "count": 1}

        with mock.patch.object(app, "refresh_group_recent", side_effect=refresh):
            result = app.mailbox_messages(token, wait_seconds=1.0)

        self.assertEqual("ready", result["fetch"]["state"])
        self.assertTrue(result["fetch"]["fresh"])
        self.assertEqual("778899", result["messages"][0]["codes"][0])

    def test_real_http_health_page_api_and_disabled_page_contract(self) -> None:
        group_id, mailbox_id, token = self.seed_group()
        server = app.PickupHTTPServer(("127.0.0.1", 0), app.PickupHandler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def schedule(*_args, **_kwargs):
            with app.REALTIME_FETCH_GUARD:
                app.REALTIME_FETCH_INFLIGHT.add(group_id)
                app.REALTIME_FETCH_ACTIVE[group_id] = {"alias+g1@example.test"}
            return {"ok": True, "realtime": True, "background": True, "started": True}

        try:
            with mock.patch.object(app.PickupHandler, "log_message"), mock.patch.object(
                app, "refresh_group_recent_for_api", side_effect=schedule
            ):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                    health = json.loads(response.read().decode("utf-8"))
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/q/{token}", timeout=2) as response:
                    page_status = response.status
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/q/{token}/messages?wait=0&limit=10",
                    timeout=2,
                ) as response:
                    api_data = json.loads(response.read().decode("utf-8"))

                with app.db() as conn:
                    conn.execute("UPDATE mailboxes SET enabled = 0 WHERE id = ?", (mailbox_id,))
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/q/{token}", timeout=2)
        finally:
            with app.REALTIME_FETCH_GUARD:
                app.REALTIME_FETCH_INFLIGHT.discard(group_id)
                app.REALTIME_FETCH_ACTIVE.pop(group_id, None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(app.APP_VERSION, health["version"])
        self.assertEqual(200, page_status)
        self.assertEqual("alias+g1@example.test", api_data["email"])
        self.assertEqual("pending", api_data["fetch"]["state"])
        self.assertEqual(403, caught.exception.code)

    def test_url_audit_accepts_both_formats_and_conversion_is_lossless(self) -> None:
        token_a = "pk_" + "A" * 43
        token_b = "pk_" + "B" * 43
        source = self.home / "urls.txt"
        source.write_text(
            "first@example.test\thttp://example.test/q/" + token_a + "\n"
            "second@example.test----https://example.test/q/" + token_b + "\n",
            encoding="utf-8",
        )
        output = self.home / "converted.txt"

        audit = app.audit_pickup_url_file(source)
        converted = app.convert_pickup_url_file(source, output, "dashes")

        self.assertTrue(audit["ok"])
        self.assertEqual({"tab": 1, "dashes": 1}, audit["delimiter_counts"])
        self.assertEqual(2, converted["rows"])
        self.assertTrue(app.audit_pickup_url_file(output)["ok"])
        self.assertNotIn("\t", output.read_text(encoding="utf-8"))

    def test_url_audit_counts_invalid_port_instead_of_crashing(self) -> None:
        token = "pk_" + "A" * 43
        source = self.home / "bad-port.txt"
        source.write_text(
            f"first@example.test----http://example.test:not-a-port/q/{token}\n",
            encoding="utf-8",
        )

        result = app.audit_pickup_url_file(source)

        self.assertFalse(result["ok"])
        self.assertEqual(1, result["invalid_rows"])

    def test_import_refuses_cross_group_mailbox_rebinding(self) -> None:
        source = self.home / "source"
        source.mkdir()
        (source / "one.txt").write_text(
            "master-one@example.test----password-one\nshared@example.test\n",
            encoding="utf-8",
        )
        (source / "two.txt").write_text(
            "master-two@example.test----password-two\nshared@example.test\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "跨账号组重复"):
            app.import_source(source, "http://example.test")

    def test_readiness_reports_all_groups_stale(self) -> None:
        group_id, _, _ = self.seed_group()
        payload, status = app.health_status(strict=True)
        self.assertEqual(503, status)
        self.assertFalse(payload["ok"])

        with app.db() as conn:
            conn.execute(
                "UPDATE groups SET last_success_at = ?, last_error = NULL WHERE id = ?",
                (app.utc_now_ts(), group_id),
            )
        payload, status = app.health_status(strict=True)
        self.assertEqual(200, status)
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
