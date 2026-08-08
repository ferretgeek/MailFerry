#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import imaplib
import ipaddress
import json
import os
import queue
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_DIR = Path(os.environ.get("PICKUP_SERVER_HOME", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("PICKUP_DATA_DIR", APP_DIR / "data"))
DB_PATH = Path(os.environ.get("PICKUP_DB", DATA_DIR / "pickup.db"))
ENV_PATH = Path(os.environ.get("PICKUP_ENV", APP_DIR / ".env"))
APP_VERSION = "1.0.0"
# Public token namespace, not a password.
TOKEN_PREFIX = "pk_"  # nosec B105
IP_GEO_ENABLED = os.environ.get("PICKUP_ENABLE_IP_GEO", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
IP_GEO_HOSTS = frozenset({"ipwho.is", "ipapi.co"})
DEFAULT_POLL_SECONDS = 20
DEFAULT_SCAN_LIMIT = 120
REALTIME_REFRESH_SECONDS = 2.0
REALTIME_API_WAIT_SECONDS = 5.0
REALTIME_API_MAX_WAIT_SECONDS = 10.0
REALTIME_API_WAIT_CONCURRENCY = 16
REALTIME_HEADER_WINDOW = 600
REALTIME_MAX_HEADER_WINDOW = 5000
REALTIME_BODY_LIMIT = 80
REALTIME_REQUESTED_BODY_LIMIT = 3
REALTIME_TARGET_UID_LIMIT = 20
REALTIME_GROUP_CONCURRENCY = 2
REALTIME_TARGET_SEARCH_LIMIT = 4
FULL_FORWARD_HEADER_LIMIT = 1200
EXTRA_FOLDER_HEADER_LIMIT = 400
EXTRA_FOLDER_BODY_LIMIT = 20
EXTRA_FOLDER_CANDIDATES = ("Junk", "Spam", "Junk Email")
IMAP_FETCH_RETRIES = 2
IMAP_RETRY_DELAY_SECONDS = 0.15
IMAP_CONNECT_TIMEOUT_SECONDS = 18
POLL_MAX_WORKERS = 4
TOKEN_MISS_CACHE_SECONDS = 120
TOKEN_MISS_CACHE_MAX = 50_000
INVALID_ACCESS_LOG_SECONDS = 30
MAX_BODY_CHARS = 16_000
MAX_MESSAGES_PER_GROUP = 20_000
MAX_ACCESS_EVENTS = 100_000
ACCESS_ANALYTICS_LIMIT = 50_000
ACCESS_EVENT_QUEUE_MAX = 50_000
ACCESS_EVENT_BATCH_SIZE = 250
ACCESS_EVENT_FLUSH_SECONDS = 0.25
ANALYTICS_TZ = timezone(timedelta(hours=8))
GEO_CACHE_SECONDS = 7 * 24 * 3600
RECIPIENT_HEADERS = [
    "To",
    "Cc",
    "Bcc",
    "Delivered-To",
    "X-Delivered-To",
    "Envelope-To",
    "Apparently-To",
    "Original-Recipient",
    "Final-Recipient",
    "X-Original-To",
    "X-Envelope-To",
    "X-Apparently-To",
    "X-Apple-Original-To",
    "X-Original-Recipient",
    "X-Rcpt-To",
    "X-Recipient",
    "X-Envelope-Recipient",
    "X-Envelope-Recipients",
    "X-Forwarded-To",
    "X-Mail-Original-To",
    "Resent-To",
    "X-ICLOUD-HME",
    "X-MS-Exchange-Organization-OriginalEnvelopeRecipients",
]


FETCH_LOCKS: dict[int, threading.Lock] = {}
FETCH_LOCKS_GUARD = threading.Lock()
REALTIME_FETCH_LIMITERS: dict[int, threading.BoundedSemaphore] = {}
REALTIME_FETCH_GUARD = threading.Lock()
REALTIME_FETCH_CONDITION = threading.Condition(REALTIME_FETCH_GUARD)
TOKEN_MISS_CACHE: dict[str, float] = {}
TOKEN_MISS_GUARD = threading.Lock()
INVALID_ACCESS_LAST: dict[str, float] = {}
INVALID_ACCESS_GUARD = threading.Lock()
POLL_STOP = threading.Event()
LOGIN_FAILURES: dict[str, list[float]] = {}
LOGIN_FAILURES_GUARD = threading.Lock()
GEO_LOOKUP_INFLIGHT: set[str] = set()
GEO_LOOKUP_GUARD = threading.Lock()
ACCESS_PRUNE_LAST = 0.0
ACCESS_PRUNE_GUARD = threading.Lock()


REALTIME_BATCH_WINDOW_SECONDS = 0.08
REALTIME_MAX_BODY_LIMIT = 1500
DB_BUSY_TIMEOUT_MS = 15_000
HEALTH_DB_BUSY_TIMEOUT_MS = 250
HTTP_MAX_CONCURRENT_REQUESTS = 128
ACCESS_EVENT_SUCCESS_SECONDS = 15

REALTIME_FETCH_LAST: dict[int, float] = {}
REALTIME_FETCH_PENDING: dict[int, set[str]] = {}
REALTIME_FETCH_ACTIVE: dict[int, set[str]] = {}
REALTIME_FETCH_INFLIGHT: set[int] = set()
REALTIME_FETCH_COMPLETED: dict[int, float] = {}
REALTIME_FETCH_RESULTS: dict[int, dict[str, object]] = {}
REALTIME_EMAIL_COMPLETED: dict[tuple[int, str], float] = {}
REALTIME_EMAIL_RESULTS: dict[tuple[int, str], dict[str, object]] = {}
ACCESS_EVENT_LAST: dict[str, float] = {}
ACCESS_EVENT_GUARD = threading.Lock()
ACCESS_EVENT_QUEUE: queue.Queue[tuple[int | None, str, str, float, int]] = queue.Queue(
    maxsize=ACCESS_EVENT_QUEUE_MAX
)
ACCESS_EVENT_STOP = threading.Event()
ACCESS_EVENT_THREAD: threading.Thread | None = None
ACCESS_EVENT_THREAD_GUARD = threading.Lock()
API_WAIT_LIMITER = threading.BoundedSemaphore(REALTIME_API_WAIT_CONCURRENCY)
DB_INIT_LOCK = threading.Lock()
DB_INITIALIZED = False
ENV_CACHE: dict[str, str] | None = None
ENV_CACHE_LOCK = threading.Lock()


def utc_now_ts() -> float:
    return time.time()


def iso_from_ts(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


def load_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if ENV_PATH.exists():
        for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def write_env(values: dict[str, str]) -> None:
    ensure_dirs()
    lines = [f"{key}={value}" for key, value in sorted(values.items())]
    temp_path = ENV_PATH.with_name(f".{ENV_PATH.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        temp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, ENV_PATH)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def ensure_env() -> dict[str, str]:
    global ENV_CACHE
    with ENV_CACHE_LOCK:
        if ENV_CACHE is not None:
            return ENV_CACHE
        values = load_env()
        changed = False
        if not values.get("PICKUP_SESSION_SECRET"):
            values["PICKUP_SESSION_SECRET"] = secrets.token_urlsafe(48)
            changed = True
        if not values.get("PICKUP_TOKEN_PEPPER"):
            values["PICKUP_TOKEN_PEPPER"] = secrets.token_urlsafe(48)
            changed = True
        if changed:
            write_env(values)
        ENV_CACHE = values
        return ENV_CACHE


@contextmanager
def db(timeout_ms: int = DB_BUSY_TIMEOUT_MS):
    ensure_dirs()
    safe_timeout_ms = max(0, int(timeout_ms))
    conn = sqlite3.connect(DB_PATH, timeout=safe_timeout_ms / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={safe_timeout_ms}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    global DB_INITIALIZED
    if DB_INITIALIZED:
        return
    with DB_INIT_LOCK:
        if DB_INITIALIZED:
            return
        with db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    master_email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    app_password TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_fetch_at REAL,
                    last_success_at REAL,
                    last_full_fetch_at REAL,
                    last_error TEXT,
                    last_count INTEGER NOT NULL DEFAULT 0,
                    uid_validity TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mailboxes (
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

                CREATE TABLE IF NOT EXISTS token_aliases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_tail TEXT NOT NULL,
                    note TEXT,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
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
                    first_seen_at REAL,
                    UNIQUE(group_id, uid)
                );

                CREATE TABLE IF NOT EXISTS access_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mailbox_id INTEGER,
                    ip TEXT,
                    action TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ip_geo_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    provider TEXT,
                    updated_at REAL NOT NULL
                );
                """
            )
            migrate_schema(conn)
            repair_mailbox_token_hashes(conn)
            backfill_message_recipients(conn)
            set_default_setting(conn, "poll_seconds", str(DEFAULT_POLL_SECONDS))
            set_default_setting(conn, "scan_limit", str(DEFAULT_SCAN_LIMIT))
            set_default_setting(conn, "base_url", "")
        DB_INITIALIZED = True


def migrate_schema(conn: sqlite3.Connection) -> None:
    message_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(messages)").fetchall()
    }
    if "first_seen_at" not in message_columns:
        conn.execute("ALTER TABLE messages ADD COLUMN first_seen_at REAL")
        conn.execute("UPDATE messages SET first_seen_at = COALESCE(fetched_at, strftime('%s', 'now')) WHERE first_seen_at IS NULL")

    group_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(groups)").fetchall()
    }
    if "last_seen_uid" not in group_columns:
        conn.execute("ALTER TABLE groups ADD COLUMN last_seen_uid INTEGER NOT NULL DEFAULT 0")
    if "last_success_at" not in group_columns:
        conn.execute("ALTER TABLE groups ADD COLUMN last_success_at REAL")
        conn.execute(
            "UPDATE groups SET last_success_at = last_fetch_at "
            "WHERE COALESCE(last_error, '') = '' AND last_fetch_at IS NOT NULL"
        )
    if "last_full_fetch_at" not in group_columns:
        conn.execute("ALTER TABLE groups ADD COLUMN last_full_fetch_at REAL")
    if "uid_validity" not in group_columns:
        conn.execute("ALTER TABLE groups ADD COLUMN uid_validity TEXT")
    access_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(access_events)").fetchall()
    }
    if "status" not in access_columns:
        conn.execute("ALTER TABLE access_events ADD COLUMN status INTEGER")
        conn.execute("UPDATE access_events SET status = 200 WHERE status IS NULL")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ip_geo_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            region TEXT,
            city TEXT,
            provider TEXT,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS message_recipients (
            message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            email TEXT NOT NULL COLLATE NOCASE,
            PRIMARY KEY(message_id, email)
        );
        CREATE INDEX IF NOT EXISTS idx_access_events_created_at ON access_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_access_events_mailbox_created ON access_events(mailbox_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_access_events_status_created ON access_events(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_first_seen ON messages(first_seen_at);
        CREATE INDEX IF NOT EXISTS idx_messages_group_seen ON messages(group_id, first_seen_at);
        CREATE INDEX IF NOT EXISTS idx_messages_group_received ON messages(group_id, received_ts DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_message_recipients_email_message ON message_recipients(email, message_id);
        CREATE TABLE IF NOT EXISTS token_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            token_tail TEXT NOT NULL,
            note TEXT,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_token_aliases_mailbox ON token_aliases(mailbox_id);
        """
    )


def repair_mailbox_token_hashes(conn: sqlite3.Connection) -> int:
    rows = conn.execute("SELECT id, token, token_hash FROM mailboxes").fetchall()
    repairs: list[tuple[str, int]] = []
    for row in rows:
        expected = token_hash(str(row["token"]))
        if not hmac.compare_digest(expected, str(row["token_hash"] or "")):
            repairs.append((expected, int(row["id"])))
    if repairs:
        conn.executemany(
            "UPDATE mailboxes SET token_hash = ? WHERE id = ?",
            repairs,
        )
    return len(repairs)



def replace_message_recipients(conn: sqlite3.Connection, message_id: int, recipient_text: str) -> None:
    emails = sorted(extract_emails(recipient_text))
    conn.execute("DELETE FROM message_recipients WHERE message_id = ?", (message_id,))
    if emails:
        conn.executemany(
            "INSERT OR IGNORE INTO message_recipients(message_id, email) VALUES(?, ?)",
            [(message_id, email) for email in emails],
        )


def backfill_message_recipients(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT m.id, m.recipient_text
        FROM messages m
        WHERE NOT EXISTS(
            SELECT 1 FROM message_recipients r WHERE r.message_id = m.id
        )
        """
    ).fetchall()
    for row in rows:
        replace_message_recipients(conn, int(row["id"]), str(row["recipient_text"] or ""))


def set_default_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (key, value))


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    iterations = 260000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, iter_text, salt_text, digest_text = encoded.split("$", 3)
        if method != "pbkdf2_sha256":
            return False
        iterations = int(iter_text)
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def set_admin_password(password: str) -> None:
    with db() as conn:
        set_setting(conn, "admin_password_hash", password_hash(password))


def token_hash(token: str) -> str:
    pepper = ensure_env()["PICKUP_TOKEN_PEPPER"]
    return hashlib.sha256((pepper + ":" + token).encode("utf-8")).hexdigest()


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def normalize_email(value: str) -> str:
    return value.strip().lower()


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def extract_email(line: str) -> str | None:
    match = EMAIL_RE.search(line)
    if not match:
        return None
    return normalize_email(match.group(0))


def extract_emails(value: str) -> set[str]:
    return {normalize_email(match.group(0)) for match in EMAIL_RE.finditer(value or "")}


def imap_servers_for_email(email_addr: str) -> list[tuple[str, int]]:
    domain = normalize_email(email_addr).rsplit("@", 1)[-1]
    if domain in {"icloud.com", "me.com", "mac.com"}:
        return [("imap.mail.me.com", 993)]
    if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
        return [("outlook.office365.com", 993), ("imap-mail.outlook.com", 993)]
    return [("imap.mail.me.com", 993)]


def imap_password_candidates(email_addr: str, app_password: str) -> list[str]:
    password = app_password.strip()
    domain = normalize_email(email_addr).rsplit("@", 1)[-1]
    candidates = [password]
    if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
        compact = password.replace("-", "").replace(" ", "")
        candidates = [compact, password] if compact and compact != password else [password]
    return candidates


def parse_source_dir(source: Path) -> list[dict[str, object]]:
    groups: list[dict[str, object]] = []
    if not source.exists():
        raise FileNotFoundError(f"source not found: {source}")
    for file_path in sorted(source.glob("*.txt")):
        raw_lines = file_path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        lines = [line.strip() for line in raw_lines if line.strip()]
        if not lines:
            continue
        if "----" not in lines[0]:
            raise ValueError(f"{file_path.name}: first line must be email----app_password")
        master_part, app_password = lines[0].split("----", 1)
        master_email = extract_email(master_part)
        if not master_email or not app_password.strip():
            raise ValueError(f"{file_path.name}: invalid first line")
        seen: set[str] = set()
        aliases: list[str] = []
        for raw in [master_part] + lines[1:]:
            email_addr = extract_email(raw)
            if email_addr and email_addr not in seen:
                seen.add(email_addr)
                aliases.append(email_addr)
        groups.append(
            {
                "file": file_path.name,
                "master_email": master_email,
                "app_password": app_password.strip(),
                "aliases": aliases,
            }
        )
    return groups


def import_source(source: Path, base_url: str, output: Path | None = None) -> dict[str, int | str]:
    init_db()
    ensure_env()
    created_groups = updated_groups = created_boxes = existing_boxes = 0
    now = utc_now_ts()
    parsed = parse_source_dir(source)
    with db() as conn:
        if base_url:
            set_setting(conn, "base_url", base_url.rstrip("/"))
        for item in parsed:
            master_email = str(item["master_email"])
            app_password = str(item["app_password"])
            row = conn.execute("SELECT id FROM groups WHERE master_email = ?", (master_email,)).fetchone()
            if row:
                group_id = int(row["id"])
                updated_groups += 1
                conn.execute(
                    "UPDATE groups SET app_password = ?, enabled = 1, updated_at = ? WHERE id = ?",
                    (app_password, now, group_id),
                )
            else:
                cur = conn.execute(
                    "INSERT INTO groups(master_email, app_password, created_at, updated_at) VALUES(?, ?, ?, ?)",
                    (master_email, app_password, now, now),
                )
                group_id = int(cur.lastrowid)
                created_groups += 1
            for email_addr in item["aliases"]:  # type: ignore[index]
                existing = conn.execute(
                    "SELECT id, group_id FROM mailboxes WHERE email = ?",
                    (email_addr,),
                ).fetchone()
                if existing:
                    if int(existing["group_id"]) != group_id:
                        raise ValueError("检测到取件邮箱跨账号组重复，已取消导入以避免静默改绑")
                    existing_boxes += 1
                    conn.execute(
                        "UPDATE mailboxes SET enabled = 1, updated_at = ? WHERE id = ?",
                        (now, int(existing["id"])),
                    )
                    continue
                token = new_token()
                conn.execute(
                    """
                    INSERT INTO mailboxes(group_id, email, token, token_hash, token_tail, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (group_id, email_addr, token, token_hash(token), token[-8:], now, now),
                )
                created_boxes += 1
    if output:
        export_urls(output, base_url=base_url)
    return {
        "groups": len(parsed),
        "created_groups": created_groups,
        "updated_groups": updated_groups,
        "created_mailboxes": created_boxes,
        "existing_mailboxes": existing_boxes,
        "output": str(output) if output else "",
    }


def export_urls(output: Path, base_url: str | None = None) -> int:
    init_db()
    output.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        base = (base_url or get_setting(conn, "base_url", "")).rstrip("/")
        if not base:
            raise ValueError("base_url is required")
        rows = conn.execute(
            """
            SELECT g.master_email, m.email, m.token
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE m.enabled = 1 AND g.enabled = 1
            ORDER BY g.master_email COLLATE NOCASE, m.email COLLATE NOCASE
            """
        ).fetchall()
    lines = [f"{row['email']}----{base}/q/{row['token']}" for row in rows]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass
    return len(lines)


def get_group_lock(group_id: int) -> threading.Lock:
    with FETCH_LOCKS_GUARD:
        lock = FETCH_LOCKS.get(group_id)
        if lock is None:
            lock = threading.Lock()
            FETCH_LOCKS[group_id] = lock
        return lock


def get_realtime_fetch_limiter(group_id: int) -> threading.BoundedSemaphore:
    with REALTIME_FETCH_GUARD:
        limiter = REALTIME_FETCH_LIMITERS.get(group_id)
        if limiter is None:
            limiter = threading.BoundedSemaphore(REALTIME_GROUP_CONCURRENCY)
            REALTIME_FETCH_LIMITERS[group_id] = limiter
        return limiter


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def html_to_text(value: str) -> str:
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def extract_body_text(msg) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]
    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue
        content_type = (part.get_content_type() or "").lower()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(html_to_text(content))
    text = "\n".join(plain_parts).strip() or "\n".join(html_parts).strip()
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:MAX_BODY_CHARS]


def build_recipient_text(msg) -> tuple[str, str]:
    values: list[str] = []
    parsed: set[str] = set()
    for name in RECIPIENT_HEADERS:
        for raw in msg.get_all(name, []):
            decoded = decode_header_value(str(raw))
            if decoded:
                values.append(decoded)
                for _, address in getaddresses([decoded]):
                    if address:
                        parsed.add(normalize_email(address))
                parsed.update(extract_emails(decoded))
    for raw in msg.get_all("Received", []):
        decoded = decode_header_value(str(raw))
        for match in re.finditer(
            rf"(?i)\bfor\s+<?({EMAIL_RE.pattern})>?\s*(?:;|$)",
            decoded,
        ):
            parsed.add(normalize_email(match.group(1)))
    display = " ".join(values + sorted(parsed))
    recipient_text = " ".join(sorted(parsed))
    return display, recipient_text


def extract_codes(subject: str, body: str) -> list[str]:
    text = f"{subject}\n{body}"
    codes: list[str] = []
    seen: set[str] = set()

    context_pattern = re.compile(
        r"(?is)(?:verification\s*code|security\s*code|login\s*code|passcode|one[- ]time(?:\s+password)?|otp|验证码|校验码|登录码)"
        r"[^A-Za-z0-9]{0,20}([A-Z0-9](?:[A-Z0-9 -]{2,12}[A-Z0-9]))"
    )
    for match in context_pattern.finditer(text):
        candidate = re.sub(r"\s+", "", match.group(1).strip(" -:："))
        compact = candidate.replace("-", "")
        if not (4 <= len(compact) <= 10 and compact.isalnum() and any(ch.isdigit() for ch in compact)):
            continue
        code = candidate
        if code not in seen:
            seen.add(code)
            codes.append(code)

    for match in re.finditer(r"(?<!\d)(\d{3})[- ](\d{3})(?!\d)", text):
        code = f"{match.group(1)}{match.group(2)}"
        if code not in seen:
            seen.add(code)
            codes.append(code)

    for match in re.finditer(r"(?<!\d)(\d{4,8})(?!\d)", text):
        code = match.group(1)
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes[:8]


def parse_message(uid: str, raw: bytes, group_id: int) -> dict[str, object]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    fetched_at = utc_now_ts()
    subject = decode_header_value(msg.get("Subject", ""))
    sender = decode_header_value(msg.get("From", ""))
    recipients, recipient_text = build_recipient_text(msg)
    body = extract_body_text(msg)
    snippet = body[:280]
    received_at = ""
    received_ts: float | None = None
    date_header = msg.get("Date")
    if date_header:
        try:
            dt = parsedate_to_datetime(date_header)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            received_ts = dt.timestamp()
            received_at = dt.astimezone().isoformat(timespec="seconds")
        except Exception:
            received_at = ""
            received_ts = None
    codes = extract_codes(subject, body)
    return {
        "group_id": group_id,
        "uid": uid,
        "subject": subject[:400],
        "sender": sender[:400],
        "recipients": recipients[:1200],
        "recipient_text": recipient_text,
        "received_at": received_at,
        "received_ts": received_ts,
        "snippet": snippet,
        "body": body,
        "codes": json.dumps(codes, ensure_ascii=False),
        "fetched_at": fetched_at,
        "first_seen_at": fetched_at,
    }


def read_int_setting(conn: sqlite3.Connection, key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(get_setting(conn, key, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def exact_recipient_match(recipient_text: str, target_emails: set[str]) -> bool:
    if not target_emails:
        return False
    return bool(extract_emails(recipient_text) & target_emails)


def imap_fetch_map(client: imaplib.IMAP4_SSL, uids: list[bytes], data_items: str) -> dict[str, bytes]:
    if not uids:
        return {}
    result: dict[str, bytes] = {}
    batch_size = 80 if "HEADER" in data_items.upper() else 25
    for start in range(0, len(uids), batch_size):
        remaining = list(uids[start : start + batch_size])
        had_ok_response = False
        last_error: Exception | None = None
        for attempt in range(IMAP_FETCH_RETRIES + 1):
            if not remaining:
                break
            uid_set = b",".join(remaining).decode("ascii", errors="ignore")
            try:
                typ, fetch_data = client.uid("FETCH", uid_set, f"({data_items})")
                if typ != "OK":
                    raise RuntimeError("IMAP FETCH 返回非 OK")
                had_ok_response = True
                for item in fetch_data:
                    if not isinstance(item, tuple) or not item[1]:
                        continue
                    meta = item[0].decode("ascii", errors="ignore")
                    match = re.search(r"\bUID\s+(\d+)\b", meta)
                    if not match:
                        continue
                    result[match.group(1)] = item[1]
                remaining = [
                    uid
                    for uid in remaining
                    if uid.decode("ascii", errors="ignore") not in result
                ]
            except Exception as exc:
                last_error = exc
            if remaining and attempt < IMAP_FETCH_RETRIES:
                time.sleep(IMAP_RETRY_DELAY_SECONDS * (attempt + 1))
        if remaining and not had_ok_response:
            raise last_error or RuntimeError("IMAP FETCH 失败")
    return result



def existing_message_keys(
    conn: sqlite3.Connection,
    group_id: int,
    uid_values: list[str],
) -> set[str]:
    uid_values = list(dict.fromkeys(uid_values))
    known: set[str] = set()
    for start in range(0, len(uid_values), 500):
        batch = uid_values[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            # The interpolated text contains one literal "?" per list item; all values stay bound.
            f"SELECT uid FROM messages WHERE group_id = ? AND uid IN ({placeholders})",  # nosec
            (group_id, *batch),
        ).fetchall()
        known.update(str(row["uid"]) for row in rows)
    return known


def existing_message_uids(
    conn: sqlite3.Connection,
    group_id: int,
    uids: list[bytes],
) -> set[str]:
    return existing_message_keys(
        conn,
        group_id,
        [uid.decode("ascii", errors="replace") for uid in uids],
    )


def uid_number(value: bytes | str) -> int:
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="ignore")
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def unique_uids(uids: list[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    result: list[bytes] = []
    for uid in uids:
        if uid in seen:
            continue
        seen.add(uid)
        result.append(uid)
    return result


def select_realtime_message_uids(
    matched: list[tuple[float, int, set[str], bytes]],
    known_uids: set[str],
    requested: set[str],
) -> tuple[list[bytes], int]:
    unknown = [
        item
        for item in matched
        if item[3].decode("ascii", errors="replace") not in known_uids
    ]
    body_limit = min(
        REALTIME_MAX_BODY_LIMIT,
        max(REALTIME_BODY_LIMIT, len(requested) * REALTIME_REQUESTED_BODY_LIMIT),
    )
    selected: list[bytes] = []
    selected_set: set[bytes] = set()
    selected_per_requested = {email: 0 for email in requested}

    if requested:
        for _, _, matched_targets, uid_bytes in unknown:
            requested_targets = matched_targets & requested
            if not requested_targets:
                continue
            if all(
                selected_per_requested[email] >= REALTIME_REQUESTED_BODY_LIMIT
                for email in requested_targets
            ):
                continue
            if uid_bytes not in selected_set:
                selected.append(uid_bytes)
                selected_set.add(uid_bytes)
            for email in requested_targets:
                selected_per_requested[email] += 1
            if len(selected) >= body_limit:
                break

    for _, _, _, uid_bytes in unknown:
        if len(selected) >= body_limit:
            break
        if uid_bytes in selected_set:
            continue
        selected.append(uid_bytes)
        selected_set.add(uid_bytes)
    return selected, len(unknown)


def imap_search_uids(client: imaplib.IMAP4_SSL, *criteria: str) -> list[bytes]:
    typ, data = client.uid("SEARCH", None, *criteria)
    if typ != "OK":
        raise RuntimeError("IMAP SEARCH 返回非 OK")
    return (data[0] or b"").split()


def imap_search_recipient_uids(client: imaplib.IMAP4_SSL, since: str, target_email: str) -> list[bytes]:
    if not target_email:
        return []
    search_specs: list[tuple[str, ...]] = [
        ("TO", target_email),
        ("CC", target_email),
        ("HEADER", "X-ICLOUD-HME", target_email),
        ("HEADER", "X-Apple-Original-To", target_email),
        ("HEADER", "X-Original-To", target_email),
        ("HEADER", "Delivered-To", target_email),
        ("HEADER", "Envelope-To", target_email),
    ]
    seen: set[bytes] = set()
    matched: list[bytes] = []
    for spec in search_specs:
        try:
            uids = imap_search_uids(client, "SINCE", since, *spec)
        except Exception:
            # IMAP providers commonly reject unsupported search headers.
            uids = []
        for uid in uids:
            if uid not in seen:
                seen.add(uid)
                matched.append(uid)
    matched.sort(key=lambda item: int(item or b"0"))
    return matched


def connect_imap_client(master_email: str, app_password: str) -> imaplib.IMAP4_SSL:
    last_exception: Exception | None = None
    for imap_host, imap_port in imap_servers_for_email(master_email):
        for password_candidate in imap_password_candidates(master_email, app_password):
            client: imaplib.IMAP4_SSL | None = None
            try:
                client = imaplib.IMAP4_SSL(
                    imap_host,
                    imap_port,
                    timeout=IMAP_CONNECT_TIMEOUT_SECONDS,
                )
                client.login(master_email, password_candidate)
                return client
            except Exception as exc:
                last_exception = exc
                try:
                    if client is not None:
                        client.logout()
                except Exception:
                    client = None
                continue
    raise last_exception or RuntimeError("IMAP 登录失败")


def imap_uid_validity(client: imaplib.IMAP4_SSL) -> str:
    try:
        _, values = client.response("UIDVALIDITY")
    except Exception:
        values = None
    for value in values or []:
        if isinstance(value, bytes):
            match = re.search(rb"\d+", value)
        else:
            match = re.search(r"\d+", str(value))
        if match:
            raw = match.group(0)
            return raw.decode("ascii") if isinstance(raw, bytes) else raw
    return ""


def reconcile_uid_validity(group_id: int, current_uid_validity: str) -> bool:
    if not current_uid_validity:
        return False
    with db() as conn:
        row = conn.execute(
            "SELECT uid_validity FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()
        if not row:
            return False
        previous = str(row["uid_validity"] or "")
        if not previous:
            conn.execute(
                "UPDATE groups SET uid_validity = ?, updated_at = ? WHERE id = ?",
                (current_uid_validity, utc_now_ts(), group_id),
            )
            return False
        if previous == current_uid_validity:
            return False
        conn.execute(
            "UPDATE messages SET uid = ? || ':' || uid "
            "WHERE group_id = ? AND instr(uid, ':') = 0",
            (f"v{previous}", group_id),
        )
        conn.execute(
            "UPDATE groups SET uid_validity = ?, last_seen_uid = 0, updated_at = ? WHERE id = ?",
            (current_uid_validity, utc_now_ts(), group_id),
        )
    return True


def fetch_extra_folder_messages(
    client: imaplib.IMAP4_SSL,
    group_id: int,
    requested: set[str],
    since: str,
) -> tuple[list[dict[str, object]], int, bool]:
    if not requested:
        return [], 0, False
    all_rows: list[dict[str, object]] = []
    total_scanned = 0
    any_partial = False
    for folder in EXTRA_FOLDER_CANDIDATES:
        try:
            typ, _ = client.select(folder, readonly=True)
        except Exception:
            any_partial = True
            continue
        if typ != "OK":
            continue
        rows: list[dict[str, object]] = []
        partial = False
        scanned = 0
        try:
            uids = imap_search_uids(client, "SINCE", since)
            candidates = uids[-EXTRA_FOLDER_HEADER_LIMIT:]
            scanned = len(candidates)
            header_map = imap_fetch_map(client, candidates, "UID BODY.PEEK[HEADER]")
            matched: list[tuple[int, bytes, str]] = []
            folder_tag = hashlib.sha256(folder.encode("utf-8")).hexdigest()[:10]
            validity = imap_uid_validity(client) or "0"
            for uid_bytes in candidates:
                raw_uid = uid_bytes.decode("ascii", errors="replace")
                header_bytes = header_map.get(raw_uid)
                if not header_bytes:
                    partial = True
                    continue
                try:
                    header_msg = BytesParser(policy=policy.default).parsebytes(header_bytes)
                    _, recipient_text = build_recipient_text(header_msg)
                except Exception:
                    partial = True
                    continue
                if not (extract_emails(recipient_text) & requested):
                    continue
                storage_key = f"f{folder_tag}:v{validity}:{raw_uid}"
                matched.append((uid_number(uid_bytes), uid_bytes, storage_key))
            matched.sort(key=lambda item: item[0], reverse=True)
            with db() as conn:
                known = existing_message_keys(
                    conn,
                    group_id,
                    [storage_key for _, _, storage_key in matched],
                )
            selected = [
                item for item in matched if item[2] not in known
            ][:EXTRA_FOLDER_BODY_LIMIT]
            body_map = imap_fetch_map(
                client,
                [uid_bytes for _, uid_bytes, _ in selected],
                "UID BODY.PEEK[]",
            )
            for _, uid_bytes, storage_key in selected:
                raw_uid = uid_bytes.decode("ascii", errors="replace")
                raw = body_map.get(raw_uid)
                if not raw:
                    partial = True
                    continue
                try:
                    rows.append(parse_message(storage_key, raw, group_id))
                except Exception:
                    partial = True
        except Exception:
            partial = True
        all_rows.extend(rows)
        total_scanned += scanned
        any_partial = any_partial or partial
    return all_rows, total_scanned, any_partial


def store_messages(conn: sqlite3.Connection, group_id: int, rows: list[dict[str, object]]) -> int:
    for row in rows:
        message_row = conn.execute(
            """
            INSERT INTO messages(
                group_id, uid, subject, sender, recipients, recipient_text,
                received_at, received_ts, snippet, body, codes, fetched_at, first_seen_at
            ) VALUES(
                :group_id, :uid, :subject, :sender, :recipients, :recipient_text,
                :received_at, :received_ts, :snippet, :body, :codes, :fetched_at, :first_seen_at
            )
            ON CONFLICT(group_id, uid) DO UPDATE SET
                subject = excluded.subject,
                sender = excluded.sender,
                recipients = excluded.recipients,
                recipient_text = excluded.recipient_text,
                received_at = excluded.received_at,
                received_ts = excluded.received_ts,
                snippet = excluded.snippet,
                body = excluded.body,
                codes = excluded.codes,
                fetched_at = excluded.fetched_at
            RETURNING id, recipient_text
            """,
            row,
        ).fetchone()
        if message_row:
            replace_message_recipients(
                conn,
                int(message_row["id"]),
                str(message_row["recipient_text"] or ""),
            )
    prune_messages(conn, group_id)
    return len(rows)


def record_group_failure(group_id: int, error: Exception | str, full_scan: bool = False) -> None:
    message = str(error).strip() or type(error).__name__
    now = utc_now_ts()
    try:
        with db() as conn:
            if full_scan:
                conn.execute(
                    "UPDATE groups SET last_fetch_at = ?, last_full_fetch_at = ?, "
                    "last_error = ?, updated_at = ? WHERE id = ?",
                    (now, now, message[:500], now, group_id),
                )
            else:
                conn.execute(
                    "UPDATE groups SET last_fetch_at = ?, last_error = ?, updated_at = ? WHERE id = ?",
                    (now, message[:500], now, group_id),
                )
    except Exception as db_error:
        sys.stderr.write(f"group {group_id} error state write failed: {db_error}\n")


def refresh_group_recent(
    group_id: int,
    requested_emails: set[str] | None = None,
    wait_timeout: float = 5.0,
) -> dict[str, object]:
    init_db()
    requested = {
        normalize_email(email)
        for email in (requested_emails or set())
        if normalize_email(email)
    }
    limiter = get_realtime_fetch_limiter(group_id)
    if not limiter.acquire(timeout=max(0.0, wait_timeout)):
        return {"ok": True, "realtime": True, "already_running": True}

    try:
        now = utc_now_ts()
        with REALTIME_FETCH_GUARD:
            last_refresh = REALTIME_FETCH_LAST.get(group_id, 0.0)
            if now - last_refresh < REALTIME_REFRESH_SECONDS:
                return {"ok": True, "realtime": True, "skipped": True, "reason": "recent"}

        with db() as conn:
            group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
            if not group:
                return {"ok": False, "realtime": True, "error": "账号组不存在"}
            if not int(group["enabled"]):
                return {"ok": False, "realtime": True, "error": "账号组已禁用"}
            target_emails = {
                normalize_email(str(row["email"]))
                for row in conn.execute(
                    "SELECT email FROM mailboxes WHERE group_id = ? AND enabled = 1",
                    (group_id,),
                ).fetchall()
            }
            last_seen_uid = max(0, int(group["last_seen_uid"] or 0))
        if not target_emails:
            return {"ok": True, "realtime": True, "count": 0, "reason": "no_targets"}

        with REALTIME_FETCH_GUARD:
            REALTIME_FETCH_LAST[group_id] = utc_now_ts()

        rows: list[dict[str, object]] = []
        client: imaplib.IMAP4_SSL | None = None
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%d-%b-%Y")
            client = connect_imap_client(str(group["master_email"]), str(group["app_password"]))
            try:
                typ, _ = client.select("INBOX", readonly=True)
                if typ != "OK":
                    raise RuntimeError("无法打开 INBOX")
                selected_uid_validity = imap_uid_validity(client)
                reconcile_uid_validity(group_id, selected_uid_validity)
                with db() as conn:
                    cursor_row = conn.execute(
                        "SELECT last_seen_uid FROM groups WHERE id = ?",
                        (group_id,),
                    ).fetchone()
                    if cursor_row:
                        last_seen_uid = max(0, int(cursor_row["last_seen_uid"] or 0))
                typ, data = client.uid("SEARCH", None, "SINCE", since)
                if typ != "OK":
                    raise RuntimeError("无法搜索邮件")
                uids = (data[0] or b"").split()
                new_uids = [uid for uid in uids if uid_number(uid) > last_seen_uid]
                header_window = min(
                    REALTIME_MAX_HEADER_WINDOW,
                    max(
                        REALTIME_HEADER_WINDOW,
                        len(requested) * REALTIME_REQUESTED_BODY_LIMIT * 2,
                    ),
                )
                header_candidates = unique_uids(
                    new_uids[-REALTIME_MAX_HEADER_WINDOW:] + uids[-header_window:]
                )
                scanned = len(header_candidates)
                header_map = imap_fetch_map(client, header_candidates, "UID BODY.PEEK[HEADER]")
                missing_new_headers = {
                    uid_number(uid_bytes)
                    for uid_bytes in header_candidates
                    if uid_number(uid_bytes) > last_seen_uid
                    and uid_bytes.decode("ascii", errors="replace") not in header_map
                }
                matched: list[tuple[float, int, set[str], bytes]] = []
                for index, uid_bytes in enumerate(header_candidates):
                    uid = uid_bytes.decode("ascii", errors="replace")
                    header_bytes = header_map.get(uid)
                    if not header_bytes:
                        continue
                    header_msg = BytesParser(policy=policy.default).parsebytes(header_bytes)
                    _, recipient_text = build_recipient_text(header_msg)
                    matched_targets = extract_emails(recipient_text) & target_emails
                    if not matched_targets:
                        continue
                    received_ts = 0.0
                    date_header = header_msg.get("Date")
                    if date_header:
                        try:
                            dt = parsedate_to_datetime(date_header)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            received_ts = dt.timestamp()
                        except Exception:
                            received_ts = 0.0
                    matched.append((received_ts, index, matched_targets, uid_bytes))

                matched_requested: set[str] = set()
                for _, _, matched_targets, _ in matched:
                    matched_requested.update(matched_targets & requested)
                targeted_candidates: list[bytes] = []
                for target_email in sorted(requested - matched_requested)[:REALTIME_TARGET_SEARCH_LIMIT]:
                    targeted = imap_search_recipient_uids(client, since, target_email)
                    targeted_candidates.extend(targeted[-REALTIME_TARGET_UID_LIMIT:])
                header_candidate_set = set(header_candidates)
                targeted_candidates = [
                    uid
                    for uid in unique_uids(targeted_candidates)
                    if uid not in header_candidate_set
                ]
                if targeted_candidates:
                    targeted_map = imap_fetch_map(
                        client,
                        targeted_candidates,
                        "UID BODY.PEEK[HEADER]",
                    )
                    scanned += len(targeted_candidates)
                    for offset, uid_bytes in enumerate(targeted_candidates, start=len(header_candidates)):
                        uid = uid_bytes.decode("ascii", errors="replace")
                        header_bytes = targeted_map.get(uid)
                        if not header_bytes:
                            if uid_number(uid_bytes) > last_seen_uid:
                                missing_new_headers.add(uid_number(uid_bytes))
                            continue
                        header_msg = BytesParser(policy=policy.default).parsebytes(header_bytes)
                        _, recipient_text = build_recipient_text(header_msg)
                        matched_targets = extract_emails(recipient_text) & target_emails
                        if matched_targets:
                            matched.append((0.0, offset, matched_targets, uid_bytes))
                matched_requested = set()
                for _, _, matched_targets, _ in matched:
                    matched_requested.update(matched_targets & requested)
                matched.sort(
                    key=lambda item: (uid_number(item[3]), item[0], item[1]),
                    reverse=True,
                )

                with db() as conn:
                    known_uids = existing_message_uids(
                        conn,
                        group_id,
                        [uid_bytes for _, _, _, uid_bytes in matched],
                    )
                selected, unknown_count = select_realtime_message_uids(
                    matched,
                    known_uids,
                    requested,
                )
                body_map = imap_fetch_map(client, selected, "UID BODY.PEEK[]")
                missing_bodies = {
                    uid_bytes.decode("ascii", errors="replace")
                    for uid_bytes in selected
                    if uid_bytes.decode("ascii", errors="replace") not in body_map
                }
                for uid_bytes in selected:
                    uid = uid_bytes.decode("ascii", errors="replace")
                    raw_bytes = body_map.get(uid, b"")
                    if raw_bytes:
                        try:
                            rows.append(parse_message(uid, raw_bytes, group_id))
                        except Exception:
                            missing_bodies.add(uid)
                extra_rows, extra_scanned, extra_partial = fetch_extra_folder_messages(
                    client,
                    group_id,
                    requested,
                    since,
                )
                rows.extend(extra_rows)
                scanned += extra_scanned
            finally:
                try:
                    if client is not None:
                        client.logout()
                except Exception:
                    client = None
            partial = bool(missing_new_headers or missing_bodies or extra_partial)
            completed_at = utc_now_ts()
            with db() as conn:
                current_uid_validity = str(
                    conn.execute(
                        "SELECT uid_validity FROM groups WHERE id = ?",
                        (group_id,),
                    ).fetchone()[0]
                    or ""
                )
                if (
                    selected_uid_validity
                    and current_uid_validity
                    and selected_uid_validity != current_uid_validity
                ):
                    raise RuntimeError("UIDVALIDITY 在实时拉取期间发生变化")
                count = store_messages(conn, group_id, rows)
                previous = conn.execute(
                    "SELECT last_success_at, last_error FROM groups WHERE id = ?",
                    (group_id,),
                ).fetchone()
                should_write_heartbeat = bool(
                    rows
                    or partial
                    or (previous and previous["last_error"])
                    or not previous
                    or completed_at - float(previous["last_success_at"] or 0) >= 15
                )
                if should_write_heartbeat:
                    conn.execute(
                        "UPDATE groups SET last_fetch_at = ?, last_success_at = ?, "
                        "last_error = ?, last_count = ?, updated_at = ? WHERE id = ?",
                        (
                            completed_at,
                            completed_at,
                            "部分邮件读取失败，将自动重试" if partial else None,
                            count,
                            completed_at,
                            group_id,
                        ),
                    )
            return {
                "ok": True,
                "realtime": True,
                "count": len(rows),
                "scanned": scanned,
                "requested": len(requested),
                "unknown": unknown_count,
                "partial": partial,
            }
        except Exception as exc:
            record_group_failure(group_id, exc)
            return {"ok": False, "realtime": True, "error": "IMAP_REFRESH_FAILED"}
    finally:
        limiter.release()


def refresh_group_recent_for_api(group_id: int, requested_email: str) -> dict[str, object]:
    requested = normalize_email(requested_email)
    now = utc_now_ts()
    with REALTIME_FETCH_GUARD:
        pending = REALTIME_FETCH_PENDING.setdefault(group_id, set())
        if requested:
            pending.add(requested)
        if group_id in REALTIME_FETCH_INFLIGHT:
            return {"ok": True, "realtime": True, "background": True, "already_running": True}
        last_refresh = REALTIME_FETCH_LAST.get(group_id, 0.0)
        start_delay = max(
            REALTIME_BATCH_WINDOW_SECONDS,
            REALTIME_REFRESH_SECONDS - (now - last_refresh),
        )
        REALTIME_FETCH_INFLIGHT.add(group_id)

    def worker() -> None:
        schedule_follow_up = False
        batch: set[str] = set()
        requeued = False
        result: dict[str, object] = {
            "ok": False,
            "realtime": True,
            "error": "REALTIME_WORKER_FAILED",
        }
        try:
            time.sleep(start_delay)
            with REALTIME_FETCH_CONDITION:
                batch = REALTIME_FETCH_PENDING.pop(group_id, set())
                REALTIME_FETCH_ACTIVE[group_id] = set(batch)
            result = refresh_group_recent(group_id, requested_emails=batch, wait_timeout=5.0)
            if result.get("already_running") or result.get("skipped"):
                requeued = True
                with REALTIME_FETCH_CONDITION:
                    REALTIME_FETCH_PENDING.setdefault(group_id, set()).update(batch)
        except Exception as exc:
            record_group_failure(group_id, exc)
        finally:
            with REALTIME_FETCH_CONDITION:
                REALTIME_FETCH_ACTIVE.pop(group_id, None)
                REALTIME_FETCH_INFLIGHT.discard(group_id)
                completed_at = utc_now_ts()
                REALTIME_FETCH_COMPLETED[group_id] = completed_at
                REALTIME_FETCH_RESULTS[group_id] = dict(result)
                if not requeued:
                    for email in batch:
                        key = (group_id, email)
                        REALTIME_EMAIL_COMPLETED[key] = completed_at
                        REALTIME_EMAIL_RESULTS[key] = dict(result)
                schedule_follow_up = bool(REALTIME_FETCH_PENDING.get(group_id))
                REALTIME_FETCH_CONDITION.notify_all()
            if schedule_follow_up:
                refresh_group_recent_for_api(group_id, "")

    try:
        thread = threading.Thread(
            target=worker,
            name=f"realtime-fetch-group-{group_id}",
            daemon=True,
        )
        thread.start()
    except Exception as exc:
        failure = {
            "ok": False,
            "realtime": True,
            "error": "REALTIME_THREAD_START_FAILED",
        }
        with REALTIME_FETCH_CONDITION:
            REALTIME_FETCH_INFLIGHT.discard(group_id)
            REALTIME_FETCH_COMPLETED[group_id] = utc_now_ts()
            REALTIME_FETCH_RESULTS[group_id] = failure
            REALTIME_FETCH_CONDITION.notify_all()
        record_group_failure(group_id, exc)
        return failure
    return {
        "ok": True,
        "realtime": True,
        "background": True,
        "started": True,
        "scheduled_after": round(start_delay, 3),
    }


def wait_for_realtime_refresh(
    group_id: int,
    requested_email: str,
    after: float,
    timeout: float,
) -> dict[str, object] | None:
    timeout = max(0.0, min(REALTIME_API_MAX_WAIT_SECONDS, timeout))
    if timeout <= 0 or not API_WAIT_LIMITER.acquire(blocking=False):
        return None
    try:
        deadline = time.monotonic() + timeout
        requested = normalize_email(requested_email)
        key = (group_id, requested)
        with REALTIME_FETCH_CONDITION:
            while True:
                target_pending = bool(
                    requested
                    and (
                        requested in REALTIME_FETCH_PENDING.get(group_id, set())
                        or requested in REALTIME_FETCH_ACTIVE.get(group_id, set())
                    )
                )
                if REALTIME_EMAIL_COMPLETED.get(key, 0.0) > after and not target_pending:
                    return dict(REALTIME_EMAIL_RESULTS.get(key, {"ok": True}))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                REALTIME_FETCH_CONDITION.wait(remaining)
    finally:
        API_WAIT_LIMITER.release()


def fetch_group(group_id: int, force: bool = False) -> dict[str, object]:
    init_db()
    with db() as conn:
        group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            return {"ok": False, "error": "账号组不存在"}
        if not int(group["enabled"]):
            return {"ok": False, "error": "账号组已禁用"}
        poll_seconds = read_int_setting(conn, "poll_seconds", DEFAULT_POLL_SECONDS, 6, 120)
        last_full_fetch_at = float(group["last_full_fetch_at"] or 0)
        if not force and utc_now_ts() - last_full_fetch_at < poll_seconds:
            return {"ok": True, "skipped": True, "last_fetch_at": last_full_fetch_at}

    lock = get_group_lock(group_id)
    with lock:
        with db() as conn:
            group = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
            if not group:
                return {"ok": False, "error": "账号组不存在"}
            if not int(group["enabled"]):
                return {"ok": False, "error": "账号组已禁用"}
            poll_seconds = read_int_setting(conn, "poll_seconds", DEFAULT_POLL_SECONDS, 6, 120)
            scan_limit = read_int_setting(conn, "scan_limit", DEFAULT_SCAN_LIMIT, 20, 2000)
            last_full_fetch_at = float(group["last_full_fetch_at"] or 0)
            last_seen_uid = max(0, int(group["last_seen_uid"] or 0))
            target_emails = {
                normalize_email(str(row["email"]))
                for row in conn.execute(
                    "SELECT email FROM mailboxes WHERE group_id = ? AND enabled = 1",
                    (group_id,),
                ).fetchall()
            }
            if not force and utc_now_ts() - last_full_fetch_at < poll_seconds:
                return {"ok": True, "skipped": True, "last_fetch_at": last_full_fetch_at}
        if not target_emails:
            return {"ok": True, "count": 0, "pending": 0, "reason": "no_targets"}

        count = 0
        max_seen_uid = last_seen_uid
        pending_count = 0
        limiter = get_realtime_fetch_limiter(group_id)
        if not limiter.acquire(timeout=5.0):
            return {"ok": True, "skipped": True, "reason": "imap_busy"}
        client: imaplib.IMAP4_SSL | None = None
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%d-%b-%Y")
            client = connect_imap_client(str(group["master_email"]), str(group["app_password"]))
            try:
                typ, _ = client.select("INBOX", readonly=True)
                if typ != "OK":
                    raise RuntimeError("无法打开 INBOX")
                selected_uid_validity = imap_uid_validity(client)
                reconcile_uid_validity(group_id, selected_uid_validity)
                with db() as conn:
                    cursor_row = conn.execute(
                        "SELECT last_seen_uid FROM groups WHERE id = ?",
                        (group_id,),
                    ).fetchone()
                    if cursor_row:
                        last_seen_uid = max(0, int(cursor_row["last_seen_uid"] or 0))
                        max_seen_uid = last_seen_uid

                if last_seen_uid > 0:
                    new_uids = [
                        uid
                        for uid in imap_search_uids(client, "UID", f"{last_seen_uid + 1}:*")
                        if uid_number(uid) > last_seen_uid
                    ]
                else:
                    new_uids = imap_search_uids(client, "ALL")
                recent_uids = imap_search_uids(client, "SINCE", since)
                forward_candidates = new_uids[:FULL_FORWARD_HEADER_LIMIT]
                next_unscanned_uid = (
                    uid_number(new_uids[len(forward_candidates)])
                    if len(new_uids) > len(forward_candidates)
                    else 0
                )
                tail_size = min(
                    len(recent_uids),
                    max(REALTIME_HEADER_WINDOW, min(scan_limit * 2, 1200)),
                )
                header_candidates = unique_uids(
                    forward_candidates + recent_uids[-tail_size:]
                )

                header_map = imap_fetch_map(client, header_candidates, "UID BODY.PEEK[HEADER]")
                missing_header_uids = {
                    uid_number(uid_bytes)
                    for uid_bytes in header_candidates
                    if uid_number(uid_bytes) > last_seen_uid
                    and uid_bytes.decode("ascii", errors="replace") not in header_map
                }
                matched: list[tuple[float, int, bytes]] = []
                for index, uid_bytes in enumerate(header_candidates):
                    uid = uid_bytes.decode("ascii", errors="replace")
                    header_bytes = header_map.get(uid)
                    if not header_bytes:
                        continue
                    header_msg = BytesParser(policy=policy.default).parsebytes(header_bytes)
                    _, recipient_text = build_recipient_text(header_msg)
                    if target_emails and not exact_recipient_match(recipient_text, target_emails):
                        continue
                    received_ts = 0.0
                    date_header = header_msg.get("Date")
                    if date_header:
                        try:
                            dt = parsedate_to_datetime(date_header)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            received_ts = dt.timestamp()
                        except Exception:
                            received_ts = 0.0
                    matched.append((received_ts, index, uid_bytes))
                with db() as conn:
                    known_uids = existing_message_uids(
                        conn,
                        group_id,
                        [uid_bytes for _, _, uid_bytes in matched],
                    )
                unknown_matched = [
                    item
                    for item in matched
                    if item[2].decode("ascii", errors="replace") not in known_uids
                ]
                unknown_matched.sort(
                    key=lambda item: (uid_number(item[2]), item[0], item[1]),
                    reverse=True,
                )
                selected_entries = unknown_matched[:scan_limit]
                selected = [uid_bytes for _, _, uid_bytes in selected_entries]
                body_map = imap_fetch_map(client, selected, "UID BODY.PEEK[]")
                rows: list[dict[str, object]] = []
                missing_body_uids: set[int] = set()
                for uid_bytes in selected:
                    uid = uid_bytes.decode("ascii", errors="replace")
                    raw_bytes = body_map.get(uid, b"")
                    if raw_bytes:
                        try:
                            rows.append(parse_message(uid, raw_bytes, group_id))
                        except Exception:
                            missing_body_uids.add(uid_number(uid_bytes))
                    else:
                        missing_body_uids.add(uid_number(uid_bytes))

                stored_uid_numbers = {uid_number(str(row["uid"])) for row in rows}
                pending_new_uids = {
                    uid_number(uid_bytes)
                    for _, _, uid_bytes in unknown_matched
                    if uid_number(uid_bytes) > last_seen_uid
                    and uid_number(uid_bytes) not in stored_uid_numbers
                }
                pending_new_uids.update(missing_header_uids)
                pending_new_uids.update(missing_body_uids)
                if next_unscanned_uid > last_seen_uid:
                    pending_new_uids.add(next_unscanned_uid)
                pending_count = len(pending_new_uids)
                if pending_new_uids:
                    max_seen_uid = max(last_seen_uid, min(pending_new_uids) - 1)
                elif forward_candidates:
                    max_seen_uid = max(last_seen_uid, max(uid_number(uid) for uid in forward_candidates))

                partial = bool(missing_header_uids or missing_body_uids)
                completed_at = utc_now_ts()
                with db() as conn:
                    current_uid_validity = str(
                        conn.execute(
                            "SELECT uid_validity FROM groups WHERE id = ?",
                            (group_id,),
                        ).fetchone()[0]
                        or ""
                    )
                    if (
                        selected_uid_validity
                        and current_uid_validity
                        and selected_uid_validity != current_uid_validity
                    ):
                        raise RuntimeError("UIDVALIDITY 在完整拉取期间发生变化")
                    count = store_messages(conn, group_id, rows)
                    conn.execute(
                        """
                        UPDATE groups
                        SET last_fetch_at = ?, last_success_at = ?, last_full_fetch_at = ?,
                            last_error = ?, last_count = ?, last_seen_uid = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            completed_at,
                            completed_at,
                            completed_at,
                            "部分邮件读取失败，将自动重试" if partial else None,
                            count,
                            max_seen_uid,
                            completed_at,
                            group_id,
                        ),
                    )
            finally:
                try:
                    if client is not None:
                        client.logout()
                except Exception:
                    client = None
        except Exception as exc:
            record_group_failure(group_id, exc, full_scan=True)
            return {"ok": False, "error": "IMAP_FULL_FETCH_FAILED"}
        finally:
            limiter.release()
        return {
            "ok": True,
            "count": count,
            "last_seen_uid": max_seen_uid,
            "pending": pending_count,
            "partial": partial,
        }


def prune_messages(conn: sqlite3.Connection, group_id: int) -> None:
    ids = conn.execute(
        """
        SELECT id FROM messages
        WHERE group_id = ?
        ORDER BY COALESCE(NULLIF(received_ts, 0), fetched_at) DESC, id DESC
        LIMIT -1 OFFSET ?
        """,
        (group_id, MAX_MESSAGES_PER_GROUP),
    ).fetchall()
    if not ids:
        return
    conn.executemany("DELETE FROM messages WHERE id = ?", [(int(row["id"]),) for row in ids])


def is_cached_token_miss(digest: str) -> bool:
    now = utc_now_ts()
    with TOKEN_MISS_GUARD:
        ts = TOKEN_MISS_CACHE.get(digest)
        if not ts:
            return False
        if now - ts < TOKEN_MISS_CACHE_SECONDS:
            return True
        TOKEN_MISS_CACHE.pop(digest, None)
    return False


def cache_token_miss(digest: str) -> None:
    now = utc_now_ts()
    with TOKEN_MISS_GUARD:
        TOKEN_MISS_CACHE[digest] = now
        if len(TOKEN_MISS_CACHE) > TOKEN_MISS_CACHE_MAX:
            expired_before = now - TOKEN_MISS_CACHE_SECONDS
            for key, ts in list(TOKEN_MISS_CACHE.items()):
                if ts < expired_before:
                    TOKEN_MISS_CACHE.pop(key, None)
            if len(TOKEN_MISS_CACHE) > TOKEN_MISS_CACHE_MAX:
                for key, _ in sorted(TOKEN_MISS_CACHE.items(), key=lambda item: item[1])[: TOKEN_MISS_CACHE_MAX // 5]:
                    TOKEN_MISS_CACHE.pop(key, None)


def clear_token_miss(digest: str) -> None:
    with TOKEN_MISS_GUARD:
        TOKEN_MISS_CACHE.pop(digest, None)


def should_record_access_event(mailbox_id: int | None, ip: str, action: str, status: int) -> bool:
    now = utc_now_ts()
    safe_mailbox_id = int(mailbox_id or 0)
    safe_action = action[:40]
    safe_ip = ip[:80]

    if safe_mailbox_id > 0 and status < 500 and safe_action in {"api_messages", "page_open"}:
        key = f"{safe_mailbox_id}:{safe_ip}:{safe_action}:{status}"
        with ACCESS_EVENT_GUARD:
            last = ACCESS_EVENT_LAST.get(key, 0.0)
            if now - last < ACCESS_EVENT_SUCCESS_SECONDS:
                return False
            ACCESS_EVENT_LAST[key] = now
            if len(ACCESS_EVENT_LAST) > 50_000:
                expired_before = now - ACCESS_EVENT_SUCCESS_SECONDS
                for item_key, ts in list(ACCESS_EVENT_LAST.items()):
                    if ts < expired_before:
                        ACCESS_EVENT_LAST.pop(item_key, None)
        return True

    if safe_mailbox_id > 0 or status != 404:
        return True
    key = f"{safe_ip}:{safe_action}:{status}"
    with INVALID_ACCESS_GUARD:
        last = INVALID_ACCESS_LAST.get(key, 0.0)
        if now - last < INVALID_ACCESS_LOG_SECONDS:
            return False
        INVALID_ACCESS_LAST[key] = now
        if len(INVALID_ACCESS_LAST) > 10_000:
            expired_before = now - INVALID_ACCESS_LOG_SECONDS
            for item_key, ts in list(INVALID_ACCESS_LAST.items()):
                if ts < expired_before:
                    INVALID_ACCESS_LAST.pop(item_key, None)
    return True


def lookup_mailbox_by_token(token: str) -> sqlite3.Row | None:
    if not token or len(token) > 120 or not token.startswith(TOKEN_PREFIX):
        return None
    digest = token_hash(token)
    if is_cached_token_miss(digest):
        return None
    with db() as conn:
        row = conn.execute(
            """
            SELECT
                m.id AS mailbox_id, m.email, m.enabled AS mailbox_enabled, m.token_tail,
                g.id AS group_id, g.enabled AS group_enabled,
                g.last_fetch_at, g.last_success_at, g.last_error, g.last_count
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE m.token_hash = ?
            """,
            (digest,),
        ).fetchone()
        if row:
            clear_token_miss(digest)
            return row
        row = conn.execute(
            """
            SELECT
                m.id AS mailbox_id, m.email, m.enabled AS mailbox_enabled, m.token_tail,
                g.id AS group_id, g.enabled AS group_enabled,
                g.last_fetch_at, g.last_success_at, g.last_error, g.last_count
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE m.token = ?
            """,
            (token,),
        ).fetchone()
        if row:
            try:
                conn.execute(
                    "UPDATE mailboxes SET token_hash = ?, updated_at = ? WHERE id = ?",
                    (digest, utc_now_ts(), int(row["mailbox_id"])),
                )
            except sqlite3.IntegrityError:
                pass
            clear_token_miss(digest)
            return row
        row = conn.execute(
            """
            SELECT
                m.id AS mailbox_id, m.email, m.enabled AS mailbox_enabled, a.token_tail,
                g.id AS group_id, g.enabled AS group_enabled,
                g.last_fetch_at, g.last_success_at, g.last_error, g.last_count
            FROM token_aliases a
            JOIN mailboxes m ON m.id = a.mailbox_id
            JOIN groups g ON g.id = m.group_id
            WHERE a.token_hash = ?
            """,
            (digest,),
        ).fetchone()
        if row:
            clear_token_miss(digest)
            return row
    cache_token_miss(digest)
    return None


def write_access_event_batch(
    batch: list[tuple[int | None, str, str, float, int]],
) -> None:
    global ACCESS_PRUNE_LAST
    if not batch:
        return
    newest = max(item[3] for item in batch)
    with db() as conn:
        conn.executemany(
            "INSERT INTO access_events(mailbox_id, ip, action, created_at, status) VALUES(?, ?, ?, ?, ?)",
            batch,
        )
        should_prune = False
        with ACCESS_PRUNE_GUARD:
            if newest - ACCESS_PRUNE_LAST >= 60:
                ACCESS_PRUNE_LAST = newest
                should_prune = True
        if should_prune:
            ids = conn.execute(
                "SELECT id FROM access_events ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?",
                (MAX_ACCESS_EVENTS,),
            ).fetchall()
            if ids:
                conn.executemany(
                    "DELETE FROM access_events WHERE id = ?",
                    [(int(row["id"]),) for row in ids],
                )


def access_event_writer_loop() -> None:
    while not ACCESS_EVENT_STOP.is_set() or not ACCESS_EVENT_QUEUE.empty():
        batch: list[tuple[int | None, str, str, float, int]] = []
        try:
            batch.append(ACCESS_EVENT_QUEUE.get(timeout=ACCESS_EVENT_FLUSH_SECONDS))
        except queue.Empty:
            continue
        while len(batch) < ACCESS_EVENT_BATCH_SIZE:
            try:
                batch.append(ACCESS_EVENT_QUEUE.get_nowait())
            except queue.Empty:
                break
        try:
            write_access_event_batch(batch)
        except Exception as exc:
            sys.stderr.write(f"access event batch dropped ({len(batch)}): {exc}\n")
        finally:
            for _ in batch:
                ACCESS_EVENT_QUEUE.task_done()


def start_access_event_writer() -> None:
    global ACCESS_EVENT_THREAD
    with ACCESS_EVENT_THREAD_GUARD:
        if ACCESS_EVENT_THREAD is not None and ACCESS_EVENT_THREAD.is_alive():
            return
        ACCESS_EVENT_STOP.clear()
        ACCESS_EVENT_THREAD = threading.Thread(
            target=access_event_writer_loop,
            name="access-event-writer",
            daemon=True,
        )
        ACCESS_EVENT_THREAD.start()


def stop_access_event_writer(timeout: float = 2.0) -> None:
    ACCESS_EVENT_STOP.set()
    thread = ACCESS_EVENT_THREAD
    if thread is not None and thread.is_alive():
        thread.join(timeout=max(0.0, timeout))


def record_access_event(mailbox_id: int | None, ip: str, action: str, status: int = 200) -> None:
    if not should_record_access_event(mailbox_id, ip, action, status):
        return
    db_mailbox_id: int | None = int(mailbox_id or 0)
    if db_mailbox_id <= 0:
        db_mailbox_id = None
    event = (
        db_mailbox_id,
        ip[:80],
        action[:40],
        utc_now_ts(),
        max(100, min(599, int(status or 200))),
    )
    try:
        ACCESS_EVENT_QUEUE.put_nowait(event)
    except queue.Full:
        # 访问统计允许降级；取件请求绝不能等待统计写锁。
        return


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def geo_label(country: str | None, region: str | None, city: str | None) -> str:
    parts: list[str] = []
    for value in (country, region, city):
        clean = str(value or "").strip()
        if clean and clean.lower() not in {"none", "null", "unknown"} and clean not in parts:
            parts.append(clean)
    return " / ".join(parts) if parts else "未知"


def fetch_json_url(url: str) -> dict[str, object]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in IP_GEO_HOSTS:
        raise ValueError("不允许的地理查询地址")
    req = urllib.request.Request(url, headers={"User-Agent": "PickupServer/1.0"})
    # Scheme and host are both restricted immediately above.
    with urllib.request.urlopen(req, timeout=1.2) as resp:  # nosec B310
        if resp.status >= 400:
            raise OSError(f"geo service status {resp.status}")
        return json.loads(resp.read(65536).decode("utf-8", errors="replace"))


def fetch_ip_geo(ip: str) -> dict[str, str]:
    if not is_public_ip(ip):
        return {"country": "内网/本机", "region": "", "city": "", "provider": ""}
    services = [
        (
            f"https://ipwho.is/{urllib.parse.quote(ip)}?fields=success,country,region,city,connection",
            lambda data: (
                bool(data.get("success", False)),
                str(data.get("country") or ""),
                str(data.get("region") or ""),
                str(data.get("city") or ""),
                str((data.get("connection") or {}).get("org") or "") if isinstance(data.get("connection"), dict) else "",
            ),
        ),
        (
            f"https://ipapi.co/{urllib.parse.quote(ip)}/json/",
            lambda data: (
                not data.get("error"),
                str(data.get("country_name") or ""),
                str(data.get("region") or ""),
                str(data.get("city") or ""),
                str(data.get("org") or ""),
            ),
        ),
    ]
    for url, parser in services:
        try:
            ok, country, region, city, provider = parser(fetch_json_url(url))
            if ok and (country or region or city):
                return {"country": country, "region": region, "city": city, "provider": provider}
        except Exception:
            # The next bounded HTTPS provider is allowed to try.
            ok = False
    return {"country": "未知", "region": "", "city": "", "provider": ""}


def refresh_ip_geo(ip: str) -> None:
    try:
        geo = fetch_ip_geo(ip)
        with db() as conn:
            conn.execute(
                """
                INSERT INTO ip_geo_cache(ip, country, region, city, provider, updated_at)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    country = excluded.country,
                    region = excluded.region,
                    city = excluded.city,
                    provider = excluded.provider,
                    updated_at = excluded.updated_at
                """,
                (ip, geo["country"], geo["region"], geo["city"], geo["provider"], utc_now_ts()),
            )
    except Exception as exc:
        sys.stderr.write(f"ip geo lookup error for {ip[:80]}: {exc}\n")
    finally:
        with GEO_LOOKUP_GUARD:
            GEO_LOOKUP_INFLIGHT.discard(ip)


def schedule_geo_lookups(ips: list[str], cached: dict[str, dict[str, str]], limit: int = 10) -> None:
    if not IP_GEO_ENABLED:
        return
    scheduled = 0
    now = utc_now_ts()
    for ip in ips:
        if not ip or not is_public_ip(ip):
            continue
        item = cached.get(ip)
        if item and now - float(item.get("updated_at") or 0) < GEO_CACHE_SECONDS:
            continue
        with GEO_LOOKUP_GUARD:
            if ip in GEO_LOOKUP_INFLIGHT:
                continue
            GEO_LOOKUP_INFLIGHT.add(ip)
        threading.Thread(target=refresh_ip_geo, args=(ip,), name=f"ip-geo-{ip[:24]}", daemon=True).start()
        scheduled += 1
        if scheduled >= limit:
            break


def geo_cache_for_ips(conn: sqlite3.Connection, ips: list[str]) -> dict[str, dict[str, str]]:
    unique_ips = sorted({ip for ip in ips if ip})
    if not unique_ips:
        return {}
    placeholders = ",".join("?" for _ in unique_ips)
    rows = conn.execute(
        # The interpolated text contains one literal "?" per list item; all values stay bound.
        f"SELECT ip, country, region, city, provider, updated_at FROM ip_geo_cache WHERE ip IN ({placeholders})",  # nosec
        unique_ips,
    ).fetchall()
    return {
        str(row["ip"]): {
            "location": geo_label(row["country"], row["region"], row["city"]),
            "provider": str(row["provider"] or ""),
            "updated_at": float(row["updated_at"] or 0),
        }
        for row in rows
    }


def ip_location(ip: str, geo_cache: dict[str, dict[str, str]]) -> dict[str, str]:
    if not ip:
        return {"location": "", "provider": ""}
    cached = geo_cache.get(ip)
    if cached:
        return {"location": cached.get("location", "未知"), "provider": cached.get("provider", "")}
    if not is_public_ip(ip):
        return {"location": "内网/本机", "provider": ""}
    return {"location": "定位中" if IP_GEO_ENABLED else "未启用定位", "provider": ""}


def start_background_fetch(group_id: int) -> dict[str, object]:
    lock = get_group_lock(group_id)
    if lock.locked():
        return {"ok": True, "background": True, "already_running": True}

    def worker() -> None:
        fetch_group(group_id, force=False)

    thread = threading.Thread(target=worker, name=f"fetch-group-{group_id}", daemon=True)
    thread.start()
    return {"ok": True, "background": True, "started": True}


def due_poll_groups(
    group_ids: list[int],
    active: set[int],
    next_due: dict[int, float],
    now: float,
    capacity: int,
) -> list[int]:
    if capacity <= 0:
        return []
    candidates = [
        group_id
        for group_id in group_ids
        if group_id not in active and now >= next_due.get(group_id, 0.0)
    ]
    candidates.sort(
        key=lambda group_id: (
            0 if group_id not in next_due else 1,
            next_due.get(group_id, 0.0),
            group_id,
        )
    )
    return candidates[:capacity]


def poll_loop() -> None:
    time.sleep(2)
    wait_seconds = DEFAULT_POLL_SECONDS
    next_due: dict[int, float] = {}
    active: dict[int, Future[dict[str, object]]] = {}
    executor: ThreadPoolExecutor | None = None
    try:
        while not POLL_STOP.is_set():
            if executor is None:
                try:
                    executor = ThreadPoolExecutor(
                        max_workers=POLL_MAX_WORKERS,
                        thread_name_prefix="mail-poll",
                    )
                except Exception as exc:
                    sys.stderr.write(f"poll executor creation error: {exc}\n")
                    POLL_STOP.wait(1.0)
                    continue
            for group_id, future in list(active.items()):
                if not future.done():
                    continue
                active.pop(group_id, None)
                if future.cancelled():
                    next_due.pop(group_id, None)
                    continue
                next_due[group_id] = time.monotonic() + wait_seconds
                try:
                    future.result()
                except Exception as exc:
                    sys.stderr.write(f"poll group {group_id} error: {exc}\n")
            try:
                with db() as conn:
                    group_ids = [
                        int(row["id"])
                        for row in conn.execute(
                            "SELECT id FROM groups WHERE enabled = 1 ORDER BY id"
                        ).fetchall()
                    ]
                    wait_seconds = read_int_setting(
                        conn,
                        "poll_seconds",
                        DEFAULT_POLL_SECONDS,
                        6,
                        120,
                    )
            except Exception as exc:
                sys.stderr.write(f"poll loop database error: {exc}\n")
                POLL_STOP.wait(min(5, max(1, wait_seconds)))
                continue

            enabled = set(group_ids)
            for group_id in list(next_due):
                if group_id not in enabled:
                    next_due.pop(group_id, None)
            now = time.monotonic()
            capacity = max(0, POLL_MAX_WORKERS - len(active))
            for group_id in due_poll_groups(
                group_ids,
                set(active),
                next_due,
                now,
                capacity,
            ):
                try:
                    active[group_id] = executor.submit(fetch_group, group_id, False)
                except Exception as exc:
                    sys.stderr.write(f"poll submit error for group {group_id}: {exc}\n")
                    next_due[group_id] = time.monotonic() + min(
                        5.0,
                        max(1.0, float(wait_seconds)),
                    )
                    try:
                        executor.shutdown(wait=False, cancel_futures=True)
                    except Exception:
                        executor = None
                    executor = None
                    break
            POLL_STOP.wait(1.0 if active else min(5.0, max(1.0, float(wait_seconds))))
    finally:
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


def mailbox_messages(
    token: str,
    force: bool = False,
    mailbox: sqlite3.Row | None = None,
    wait_seconds: float = 0.0,
    limit: int = 30,
) -> dict[str, object]:
    request_started_at = utc_now_ts()
    wait_seconds = max(0.0, min(REALTIME_API_MAX_WAIT_SECONDS, float(wait_seconds or 0)))
    limit = max(1, min(100, int(limit or 30)))
    wait_completed = False
    try:
        row = mailbox if mailbox is not None else lookup_mailbox_by_token(token)
        if not row:
            return {"ok": False, "status": 404, "error": "取件链接不存在或已重置"}
        if not int(row["mailbox_enabled"]) or not int(row["group_enabled"]):
            return {"ok": False, "status": 403, "error": "该取件链接已停用"}
        target = normalize_email(str(row["email"]))
        fetch_result = (
            fetch_group(int(row["group_id"]), force=True)
            if force
            else refresh_group_recent_for_api(int(row["group_id"]), requested_email=target)
        )
        if not force and wait_seconds > 0 and fetch_result.get("ok", True):
            wait_result = wait_for_realtime_refresh(
                int(row["group_id"]),
                target,
                request_started_at,
                wait_seconds,
            )
            wait_completed = wait_result is not None
            if wait_result is not None:
                fetch_result = wait_result
        with db() as conn:
            group = conn.execute("SELECT * FROM groups WHERE id = ?", (int(row["group_id"]),)).fetchone()
            rows = conn.execute(
                """
                SELECT m.*
                FROM message_recipients r
                JOIN messages m ON m.id = r.message_id
                WHERE r.email = ?
                  AND m.group_id = ?
                ORDER BY COALESCE(NULLIF(m.received_ts, 0), m.fetched_at) DESC, m.id DESC
                LIMIT ?
                """,
                (target, int(row["group_id"]), limit + 1),
            ).fetchall()
    except sqlite3.Error as exc:
        sys.stderr.write(f"mailbox query error: {exc}\n")
        return {"ok": False, "status": 503, "error": "取件服务暂时不可用，请稍后重试"}

    has_more = len(rows) > limit
    messages: list[dict[str, object]] = []
    for msg in rows[:limit]:
        try:
            codes = json.loads(str(msg["codes"] or "[]"))
        except Exception:
            codes = []
        messages.append(
            {
                "id": str(msg["id"]),
                "subject": msg["subject"] or "",
                "sender": msg["sender"] or "",
                "received_at": msg["received_at"] or "",
                "snippet": msg["snippet"] or "",
                "codes": codes,
            }
        )
    with REALTIME_FETCH_GUARD:
        group_id = int(row["group_id"])
        pending = bool(
            target in REALTIME_FETCH_PENDING.get(group_id, set())
            or target in REALTIME_FETCH_ACTIVE.get(group_id, set())
        )
    has_error = bool(group and group["last_error"])
    fetch_failed = not bool(fetch_result.get("ok", True))
    deferred = bool(fetch_result.get("skipped") or fetch_result.get("already_running"))
    completed = bool((wait_completed or force) and not pending and not deferred)
    if has_error or fetch_failed:
        fetch_state = "degraded" if messages else "error"
    elif pending:
        fetch_state = "pending"
    elif wait_completed or force:
        fetch_state = "ready"
    else:
        fetch_state = "cached"
    public_fetch = {
        "ok": not fetch_failed and not has_error,
        "state": fetch_state,
        "realtime": bool(fetch_result.get("realtime")),
        "background": bool(fetch_result.get("background")),
        "pending": pending,
        "completed": completed,
        "fresh": bool(completed and not has_error and not fetch_failed),
        "retry_after_seconds": 2 if pending else 0,
    }
    return {
        "ok": True,
        "email": target,
        "messages": messages,
        "has_more": has_more,
        "last_fetch_at": iso_from_ts(float(group["last_success_at"] or 0)) if group else "",
        "last_success_at": iso_from_ts(float(group["last_success_at"] or 0)) if group else "",
        "last_attempt_at": iso_from_ts(float(group["last_fetch_at"] or 0)) if group else "",
        "last_error": "暂时无法更新，请稍后重试" if has_error or fetch_failed else "",
        "fetch": public_fetch,
        "server_time": iso_from_ts(utc_now_ts()),
    }



def health_status(strict: bool = False) -> tuple[dict[str, object], int]:
    try:
        with db(HEALTH_DB_BUSY_TIMEOUT_MS) as conn:
            poll_seconds = read_int_setting(conn, "poll_seconds", DEFAULT_POLL_SECONDS, 6, 120)
            rows = conn.execute(
                "SELECT last_success_at, last_error FROM groups WHERE enabled = 1"
            ).fetchall()
    except Exception as exc:
        sys.stderr.write(f"health database error: {exc}\n")
        return {
            "ok": False,
            "version": APP_VERSION,
            "error": "database_unavailable",
        }, 503
    now = utc_now_ts()
    stale_after = max(120, poll_seconds * 4)
    enabled_groups = len(rows)
    error_groups = sum(bool(row["last_error"]) for row in rows)
    stale_groups = sum(
        not row["last_success_at"]
        or now - float(row["last_success_at"] or 0) > stale_after
        for row in rows
    )
    all_unavailable = enabled_groups > 0 and stale_groups >= enabled_groups
    payload = {
        "ok": True,
        "version": APP_VERSION,
        "time": iso_from_ts(now),
        "enabled_groups": enabled_groups,
        "imap_error_groups": error_groups,
        "stale_groups": stale_groups,
        "stale_after_seconds": stale_after,
        "degraded": bool(error_groups or stale_groups),
        "access_event_queue": ACCESS_EVENT_QUEUE.qsize(),
    }
    if strict and all_unavailable:
        payload["ok"] = False
        payload["error"] = "imap_unavailable"
        return payload, 503
    return payload, 200


def sign_value(value: str) -> str:
    secret = ensure_env()["PICKUP_SESSION_SECRET"].encode("utf-8")
    sig = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def unsign_value(value: str) -> str | None:
    if "." not in value:
        return None
    raw, sig = value.rsplit(".", 1)
    expected = sign_value(raw).rsplit(".", 1)[1]
    if hmac.compare_digest(sig, expected):
        return raw
    return None


def make_session() -> str:
    payload = f"{int(utc_now_ts())}:{secrets.token_urlsafe(16)}"
    return sign_value(payload)


def is_valid_session(cookie_header: str | None) -> bool:
    if not cookie_header:
        return False
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header)
    except Exception:
        return False
    morsel = cookie.get("pickup_admin")
    if not morsel:
        return False
    raw = unsign_value(morsel.value)
    if not raw or ":" not in raw:
        return False
    try:
        created = int(raw.split(":", 1)[0])
    except ValueError:
        return False
    return utc_now_ts() - created < 12 * 3600


def admin_login(password: str) -> bool:
    with db() as conn:
        encoded = get_setting(conn, "admin_password_hash", "")
    return bool(encoded and verify_password(password, encoded))


def login_limited(ip: str) -> bool:
    cutoff = utc_now_ts() - 10 * 60
    with LOGIN_FAILURES_GUARD:
        failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if ts >= cutoff]
        LOGIN_FAILURES[ip] = failures
        return len(failures) >= 8


def record_login_failure(ip: str) -> None:
    cutoff = utc_now_ts() - 10 * 60
    with LOGIN_FAILURES_GUARD:
        failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if ts >= cutoff]
        failures.append(utc_now_ts())
        LOGIN_FAILURES[ip] = failures


def clear_login_failures(ip: str) -> None:
    with LOGIN_FAILURES_GUARD:
        LOGIN_FAILURES.pop(ip, None)


def public_base_url() -> str:
    with db() as conn:
        return get_setting(conn, "base_url", "").rstrip("/")


def admin_cookie(value: str, max_age: int) -> str:
    parts = [
        f"pickup_admin={value}",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        f"Max-Age={max(0, int(max_age))}",
    ]
    if public_base_url().lower().startswith("https://"):
        parts.append("Secure")
    return "; ".join(parts)


SHARED_THEME_STYLE = r"""
  :root,
  html[data-theme="sky"] {
    color-scheme: light;
    --page-bg: linear-gradient(135deg, #eaf4f7 0%, #f5f7f8 47%, #f8f1e5 100%);
    --ink: #17232d;
    --muted: #5d6d7a;
    --line: rgba(255, 255, 255, .68);
    --glass: rgba(255, 255, 255, .64);
    --glass-strong: rgba(255, 255, 255, .82);
    --glass-heavy: rgba(255, 255, 255, .88);
    --control: rgba(255, 255, 255, .78);
    --control-line: rgba(255, 255, 255, .86);
    --row-line: rgba(23, 35, 45, .09);
    --accent: #177e89;
    --accent-strong: #0f6871;
    --danger: #b42318;
    --warn: #a95808;
    --ok: #0f766e;
    --body-copy: #2d3b46;
    --shadow: 0 18px 55px rgba(31, 41, 55, .13);
    --theme-swatch: #58aeb6;
  }
  html[data-theme="jade"] {
    color-scheme: light;
    --page-bg: linear-gradient(135deg, #e8f4ed 0%, #f5f8f3 49%, #eef5df 100%);
    --ink: #173027;
    --muted: #5b7067;
    --line: rgba(255, 255, 255, .7);
    --glass: rgba(250, 255, 251, .67);
    --glass-strong: rgba(252, 255, 252, .84);
    --glass-heavy: rgba(252, 255, 252, .9);
    --control: rgba(255, 255, 255, .8);
    --control-line: rgba(255, 255, 255, .9);
    --row-line: rgba(23, 48, 39, .09);
    --accent: #2f7d5a;
    --accent-strong: #236447;
    --danger: #a83b32;
    --warn: #9a650a;
    --ok: #287a56;
    --body-copy: #31463d;
    --shadow: 0 18px 55px rgba(31, 67, 49, .12);
    --theme-swatch: #78aa68;
  }
  html[data-theme="sunset"] {
    color-scheme: light;
    --page-bg: linear-gradient(135deg, #fff0e7 0%, #faf5f0 48%, #f3ebdc 100%);
    --ink: #39261f;
    --muted: #7a655b;
    --line: rgba(255, 255, 255, .7);
    --glass: rgba(255, 252, 248, .7);
    --glass-strong: rgba(255, 253, 250, .86);
    --glass-heavy: rgba(255, 253, 250, .92);
    --control: rgba(255, 255, 255, .8);
    --control-line: rgba(255, 255, 255, .9);
    --row-line: rgba(57, 38, 31, .09);
    --accent: #c06143;
    --accent-strong: #a64b31;
    --danger: #a9362e;
    --warn: #9c5d12;
    --ok: #3f7b60;
    --body-copy: #533d34;
    --shadow: 0 18px 55px rgba(91, 55, 38, .13);
    --theme-swatch: #df835e;
  }
  html[data-theme="dark"] {
    color-scheme: dark;
    --page-bg: linear-gradient(135deg, #17191d 0%, #1c1f24 52%, #202126 100%);
    --ink: #edf1f5;
    --muted: #aab4bf;
    --line: rgba(255, 255, 255, .1);
    --glass: rgba(38, 42, 48, .86);
    --glass-strong: rgba(42, 46, 53, .94);
    --glass-heavy: rgba(45, 49, 56, .97);
    --control: rgba(56, 61, 69, .9);
    --control-line: rgba(255, 255, 255, .12);
    --row-line: rgba(255, 255, 255, .08);
    --accent: #64aeb2;
    --accent-strong: #78bdc1;
    --danger: #ff9c91;
    --warn: #efb96b;
    --ok: #83c8b0;
    --body-copy: #d2d9e0;
    --shadow: 0 20px 60px rgba(0, 0, 0, .3);
    --theme-swatch: #727983;
  }
  body {
    background: var(--page-bg);
    color: var(--ink);
    padding-top: 66px;
    transition: background .2s ease, color .2s ease;
  }
  .message, .empty, .error, .panel, .stat, .login, .hero { border-color: var(--line); }
  .pill, button.secondary, .btn.secondary, input, select {
    background: var(--control);
    border-color: var(--control-line);
    color: var(--ink);
  }
  table { background: var(--glass-heavy); }
  th, td, tr { border-color: var(--row-line); }
  .snippet { color: var(--body-copy); }
  button:focus-visible, .btn:focus-visible, input:focus-visible, select:focus-visible {
    outline: 3px solid color-mix(in srgb, var(--accent) 42%, transparent);
    outline-offset: 2px;
  }
  .theme-dock {
    position: fixed;
    z-index: 1000;
    top: 14px;
    right: 16px;
    display: flex;
    justify-content: flex-end;
    font-family: Inter, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
  }
  .theme-trigger {
    min-height: 38px;
    padding: 0 11px;
    border: 1px solid var(--control-line);
    border-radius: 9px;
    background: var(--control);
    color: var(--ink);
    box-shadow: 0 10px 28px rgba(24, 34, 43, .12);
    backdrop-filter: blur(18px);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-weight: 750;
    cursor: pointer;
  }
  .theme-trigger:hover { background: var(--glass-heavy); color: var(--ink); }
  .theme-swatch {
    width: 14px;
    height: 14px;
    flex: 0 0 auto;
    border: 2px solid rgba(255,255,255,.72);
    border-radius: 50%;
    background: var(--theme-swatch);
    box-shadow: 0 0 0 1px rgba(23, 35, 45, .14);
  }
  .theme-chevron { color: var(--muted); font-size: 11px; }
  .theme-menu {
    position: absolute;
    top: 44px;
    right: 0;
    width: 178px;
    padding: 7px;
    border: 1px solid var(--line);
    border-radius: 11px;
    background: var(--glass-heavy);
    box-shadow: var(--shadow);
    backdrop-filter: blur(20px);
  }
  .theme-menu[hidden] { display: none; }
  .theme-option {
    width: 100%;
    min-height: 38px;
    padding: 0 9px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--ink);
    box-shadow: none;
    display: flex;
    align-items: center;
    gap: 9px;
    text-align: left;
    cursor: pointer;
  }
  .theme-option:hover, .theme-option[aria-checked="true"] {
    background: color-mix(in srgb, var(--accent) 13%, transparent);
    color: var(--ink);
  }
  .theme-option-dot { width: 12px; height: 12px; border-radius: 50%; flex: 0 0 auto; }
  .theme-option[data-theme-value="sky"] .theme-option-dot { background: #58aeb6; }
  .theme-option[data-theme-value="jade"] .theme-option-dot { background: #78aa68; }
  .theme-option[data-theme-value="sunset"] .theme-option-dot { background: #df835e; }
  .theme-option[data-theme-value="dark"] .theme-option-dot { background: #555b64; }
  @media (max-width: 680px) {
    body { padding-top: 60px; }
    .theme-dock { top: 10px; right: 10px; }
    .theme-trigger-label { display: none; }
  }
"""

THEME_HEAD_SCRIPT = r"""<script>
  (() => {
    const allowed = new Set(['sky', 'jade', 'sunset', 'dark']);
    let saved = 'sky';
    try { saved = localStorage.getItem('pickup-theme') || 'sky'; } catch (_) {}
    document.documentElement.dataset.theme = allowed.has(saved) ? saved : 'sky';
  })();
</script>"""

THEME_PICKER_HTML = r"""
  <div class="theme-dock">
    <button class="theme-trigger" id="themeTrigger" type="button" aria-haspopup="menu" aria-expanded="false" aria-controls="themeMenu" title="切换全局主题">
      <span class="theme-swatch" aria-hidden="true"></span>
      <span class="theme-trigger-label" id="themeLabel">天际蓝</span>
      <span class="theme-chevron" aria-hidden="true">▾</span>
    </button>
    <div class="theme-menu" id="themeMenu" role="menu" aria-label="全局主题" hidden>
      <button class="theme-option" type="button" role="menuitemradio" data-theme-value="sky"><span class="theme-option-dot"></span><span>天际蓝</span></button>
      <button class="theme-option" type="button" role="menuitemradio" data-theme-value="jade"><span class="theme-option-dot"></span><span>青岚绿</span></button>
      <button class="theme-option" type="button" role="menuitemradio" data-theme-value="sunset"><span class="theme-option-dot"></span><span>霞光橙</span></button>
      <button class="theme-option" type="button" role="menuitemradio" data-theme-value="dark"><span class="theme-option-dot"></span><span>深灰夜色</span></button>
    </div>
  </div>
"""

THEME_SCRIPT = r"""<script>
  (() => {
    const themes = {
      sky: { label: '天际蓝', color: '#eaf4f7' },
      jade: { label: '青岚绿', color: '#e8f4ed' },
      sunset: { label: '霞光橙', color: '#fff0e7' },
      dark: { label: '深灰夜色', color: '#17191d' }
    };
    const trigger = document.getElementById('themeTrigger');
    const menu = document.getElementById('themeMenu');
    const label = document.getElementById('themeLabel');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (!trigger || !menu || !label) return;
    const apply = (name, persist = true) => {
      const theme = themes[name] || themes.sky;
      const key = themes[name] ? name : 'sky';
      document.documentElement.dataset.theme = key;
      label.textContent = theme.label;
      if (meta) meta.content = theme.color;
      menu.querySelectorAll('[data-theme-value]').forEach((option) => {
        option.setAttribute('aria-checked', option.dataset.themeValue === key ? 'true' : 'false');
      });
      if (persist) {
        try { localStorage.setItem('pickup-theme', key); } catch (_) {}
      }
    };
    const close = () => { menu.hidden = true; trigger.setAttribute('aria-expanded', 'false'); };
    trigger.addEventListener('click', () => {
      menu.hidden = !menu.hidden;
      trigger.setAttribute('aria-expanded', menu.hidden ? 'false' : 'true');
    });
    menu.addEventListener('click', (event) => {
      const option = event.target.closest('[data-theme-value]');
      if (!option) return;
      apply(option.dataset.themeValue);
      close();
      trigger.focus();
    });
    document.addEventListener('click', (event) => {
      if (!event.target.closest('.theme-dock')) close();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') { close(); trigger.focus(); }
    });
    apply(document.documentElement.dataset.theme || 'sky', false);
  })();
</script>"""


PICKUP_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="sky">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#eaf4f7">
  <title>信渡 · 取件邮箱</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="icon" href="/favicon.ico" sizes="any">
  <!-- THEME_HEAD_SCRIPT -->
  <style>
    :root {
      color-scheme: light;
      --ink: #17202a;
      --muted: #5d6b7a;
      --line: rgba(255, 255, 255, .46);
      --glass: rgba(255, 255, 255, .58);
      --glass-strong: rgba(255, 255, 255, .78);
      --accent: #177e89;
      --accent-strong: #0f6871;
      --warn: #b45309;
      --ok: #0f766e;
      font-family: Inter, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        linear-gradient(135deg, rgba(232, 245, 243, .94), rgba(241, 245, 249, .92) 45%, rgba(250, 245, 235, .9)),
        #eef3f4;
    }
    .wrap {
      width: min(980px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0 48px;
    }
    .hero {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      padding: 22px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--glass);
      box-shadow: 0 18px 60px rgba(31, 41, 55, .14);
      backdrop-filter: blur(18px);
    }
    h1 { margin: 0 0 8px; font-size: 28px; line-height: 1.18; letter-spacing: 0; }
    .mail { color: var(--muted); overflow-wrap: anywhere; }
    .status { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 32px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(255,255,255,.64);
      color: var(--muted);
      border: 1px solid rgba(255,255,255,.62);
      font-size: 13px;
    }
    button {
      min-height: 38px;
      border: 0;
      border-radius: 8px;
      padding: 0 14px;
      background: var(--accent);
      color: white;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 10px 22px rgba(23, 126, 137, .22);
    }
    button:hover { background: var(--accent-strong); }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
      margin-top: 18px;
    }
    .message, .empty, .error {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      background: var(--glass-strong);
      backdrop-filter: blur(16px);
      box-shadow: 0 12px 36px rgba(31, 41, 55, .1);
    }
    .message-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }
    .subject { font-size: 17px; font-weight: 800; overflow-wrap: anywhere; }
    .meta { color: var(--muted); font-size: 13px; margin-top: 5px; overflow-wrap: anywhere; }
    .codes { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0 10px; }
    .code {
      border-radius: 8px;
      background: rgba(15, 118, 110, .1);
      color: var(--ok);
      border: 1px solid rgba(15, 118, 110, .18);
      padding: 8px 10px;
      font-size: 24px;
      font-weight: 900;
      letter-spacing: 0;
      user-select: all;
    }
    .snippet { color: #2c3743; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
    .empty, .error { color: var(--muted); text-align: center; padding: 34px 20px; }
    .error { color: var(--warn); }
    @media (max-width: 680px) {
      .wrap { width: min(100% - 20px, 980px); padding-top: 14px; }
      .hero { display: block; padding: 16px; }
      h1 { font-size: 23px; }
      .status { justify-content: flex-start; margin-top: 14px; }
      .message-head { display: block; }
      .code { font-size: 21px; }
    }
  </style>
  <style><!-- SHARED_THEME_STYLE --></style>
</head>
<body>
  <!-- THEME_PICKER -->
  <main class="wrap">
    <section class="hero">
      <div>
        <h1>信渡 · 取件邮箱</h1>
        <div class="mail" id="email">正在载入</div>
      </div>
      <div class="status">
        <span class="pill" id="last">等待检查</span>
        <button id="refresh" type="button">刷新</button>
      </div>
    </section>
    <section class="grid" id="list"></section>
  </main>
  <script>
    const token = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');
    const list = document.getElementById('list');
    const emailEl = document.getElementById('email');
    const lastEl = document.getElementById('last');
    const refreshBtn = document.getElementById('refresh');
    let loading = false;
    const esc = (s) => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

    async function load() {
      if (loading) return;
      loading = true;
      refreshBtn.disabled = true;
      try {
        const res = await fetch(`/api/q/${encodeURIComponent(token)}/messages?wait=5`, { cache: 'no-store' });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error || '取件失败');
        emailEl.textContent = data.email || '';
        const pending = data.fetch && data.fetch.pending;
        lastEl.textContent = pending ? '正在检查新邮件' : (data.last_success_at ? `上次成功 ${data.last_success_at}` : '等待首次检查');
        const warning = data.last_error ? `<div class="error">${esc(data.last_error)}；下方仍显示已有邮件。</div>` : '';
        if (!data.messages || data.messages.length === 0) {
          list.innerHTML = warning + `<div class="empty">${pending ? '正在拉取，请稍候。' : '暂无匹配邮件，页面会自动刷新。'}</div>`;
          return;
        }
        list.innerHTML = warning + data.messages.map(msg => {
          const codes = (msg.codes || []).map(code => `<span class="code">${esc(code)}</span>`).join('');
          return `<article class="message">
            <div class="message-head">
              <div>
                <div class="subject">${esc(msg.subject || '无主题')}</div>
                <div class="meta">${esc(msg.sender || '')}</div>
              </div>
              <div class="meta">${esc(msg.received_at || '')}</div>
            </div>
            ${codes ? `<div class="codes">${codes}</div>` : ''}
            <div class="snippet">${esc(msg.snippet || '')}</div>
          </article>`;
        }).join('');
      } catch (err) {
        list.innerHTML = `<div class="error">${esc(err.message || err)}</div>`;
      } finally {
        loading = false;
        refreshBtn.disabled = false;
      }
    }
    refreshBtn.addEventListener('click', load);
    load();
    setInterval(load, 8000);
  </script>
  <!-- THEME_SCRIPT -->
</body>
</html>
"""


ADMIN_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="sky">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#eaf4f7">
  <title>信渡 · 管理后台</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="icon" href="/favicon.ico" sizes="any">
  <!-- THEME_HEAD_SCRIPT -->
  <style>
    :root {
      color-scheme: light;
      --ink: #14202b;
      --muted: #627284;
      --line: rgba(255, 255, 255, .5);
      --glass: rgba(255, 255, 255, .62);
      --glass-heavy: rgba(255, 255, 255, .82);
      --accent: #177e89;
      --accent-strong: #0d6871;
      --danger: #b42318;
      --ok: #0f766e;
      --shadow: 0 18px 55px rgba(31, 41, 55, .13);
      font-family: Inter, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        linear-gradient(135deg, rgba(226, 242, 240, .96), rgba(241, 245, 249, .93) 46%, rgba(252, 247, 238, .92)),
        #eef3f2;
    }
    .app {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 46px;
    }
    header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 18px;
    }
    h1 { margin: 0; font-size: 29px; line-height: 1.16; letter-spacing: 0; }
    .sub { color: var(--muted); margin-top: 7px; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    button, .btn {
      min-height: 38px;
      border: 0;
      border-radius: 8px;
      padding: 0 13px;
      background: var(--accent);
      color: #fff;
      font-weight: 800;
      cursor: pointer;
      box-shadow: 0 10px 22px rgba(23, 126, 137, .18);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      white-space: nowrap;
    }
    button:hover, .btn:hover { background: var(--accent-strong); }
    button.secondary, .btn.secondary {
      background: rgba(255,255,255,.72);
      color: var(--ink);
      border: 1px solid rgba(255,255,255,.72);
      box-shadow: none;
    }
    button.danger { background: rgba(180, 35, 24, .12); color: var(--danger); box-shadow: none; }
    button:disabled { opacity: .55; cursor: wait; }
    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .panel, .stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--glass);
      backdrop-filter: blur(18px);
      box-shadow: var(--shadow);
    }
    .stat { padding: 16px; }
    .stat strong { display: block; font-size: 28px; line-height: 1.1; }
    .stat span { display: block; color: var(--muted); margin-top: 7px; }
    .panel { padding: 16px; margin-top: 14px; }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }
    h2 { margin: 0; font-size: 18px; letter-spacing: 0; }
    input, select {
      width: 100%;
      min-height: 40px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,.72);
      background: rgba(255,255,255,.76);
      color: var(--ink);
      padding: 0 12px;
      outline: none;
    }
    .filters {
      display: grid;
      grid-template-columns: 1fr 170px;
      gap: 10px;
      width: min(520px, 100%);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      overflow: hidden;
      border-radius: 8px;
      background: var(--glass-heavy);
    }
    th, td {
      text-align: left;
      border-bottom: 1px solid rgba(20, 32, 43, .08);
      padding: 11px 10px;
      font-size: 14px;
      vertical-align: middle;
      overflow-wrap: anywhere;
    }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    tr:last-child td { border-bottom: 0; }
    .status {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      background: rgba(15, 118, 110, .1);
      color: var(--ok);
    }
    .status.off { background: rgba(180, 35, 24, .1); color: var(--danger); }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .actions button, .actions .btn { min-height: 32px; padding: 0 9px; font-size: 12px; }
    .pager {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 8px;
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
    }
    .pager button { min-height: 32px; padding: 0 10px; box-shadow: none; }
    .minor { display: block; color: var(--muted); font-size: 12px; margin-top: 4px; }
    .ip-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .notice { color: var(--muted); margin-top: 10px; min-height: 22px; }
    .login {
      width: min(420px, calc(100% - 28px));
      margin: 10vh auto 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--glass);
      backdrop-filter: blur(18px);
      box-shadow: var(--shadow);
      padding: 26px;
    }
    .login-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 20px;
    }
    .login-brand img {
      width: 46px;
      height: 46px;
      border-radius: 12px;
      box-shadow: 0 10px 26px rgba(23,126,137,.2);
    }
    .login-brand span {
      display: block;
      color: var(--muted);
      font-size: 13px;
      letter-spacing: .08em;
    }
    .login h1 { font-size: 25px; margin-bottom: 8px; }
    .login form { display: grid; gap: 12px; margin-top: 18px; }
    @media (max-width: 760px) {
      .app { width: min(100% - 20px, 1180px); padding-top: 16px; }
      header, .panel-head { display: block; }
      .toolbar { justify-content: flex-start; margin-top: 14px; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .filters { grid-template-columns: 1fr; margin-top: 12px; }
      table, thead, tbody, tr, th, td { display: block; }
      thead { display: none; }
      tr { border-bottom: 1px solid rgba(20, 32, 43, .08); padding: 8px 0; }
      td { border-bottom: 0; padding: 7px 8px; }
      td::before { content: attr(data-label); display: block; color: var(--muted); font-size: 12px; margin-bottom: 3px; }
    }
  </style>
  <style><!-- SHARED_THEME_STYLE --></style>
</head>
<body>
  <!-- THEME_PICKER -->
  <main class="app">
    <header>
      <div>
        <h1>信渡 · 管理后台</h1>
        <div class="sub" id="base"></div>
      </div>
      <div class="toolbar">
        <a class="btn secondary" id="exportBtn" href="/admin/api/export">导出URL</a>
        <button class="secondary" id="reloadBtn" type="button">刷新后台</button>
        <button class="danger" id="logoutBtn" type="button">退出</button>
      </div>
    </header>

    <section class="stats">
      <div class="stat"><strong id="statGroups">0</strong><span>IMAP账号组</span></div>
      <div class="stat"><strong id="statBoxes">0</strong><span>取件邮箱</span></div>
      <div class="stat"><strong id="statEnabled">0</strong><span>已启用URL</span></div>
      <div class="stat"><strong id="statMessages">0</strong><span>缓存邮件</span></div>
    </section>

    <section class="stats">
      <div class="stat"><strong id="todayPages">0</strong><span>今日打开页面</span></div>
      <div class="stat"><strong id="todayUsed">0</strong><span>今日使用邮箱</span></div>
      <div class="stat"><strong id="todayIps">0</strong><span>今日独立IP</span></div>
      <div class="stat"><strong id="todayMails">0</strong><span>今日新增邮件</span></div>
    </section>

    <section class="stats">
      <div class="stat"><strong id="todayRate">100%</strong><span>今日取件成功率</span></div>
      <div class="stat"><strong id="todaySuccess">0</strong><span>今日成功请求</span></div>
      <div class="stat"><strong id="todayFailed">0</strong><span>今日异常请求</span></div>
      <div class="stat"><strong id="imapErrors">0</strong><span>IMAP异常组</span></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>每日趋势</h2>
        <div class="notice">按北京时间统计，打开页面更接近真实使用人数，刷新邮件包含页面自动刷新。</div>
      </div>
      <table>
        <thead><tr><th>日期</th><th>成功率</th><th>异常</th><th>打开页面</th><th>刷新邮件</th><th>使用邮箱</th><th>独立IP</th><th>新增邮件</th></tr></thead>
        <tbody id="dailyBody"></tbody>
      </table>
      <div class="pager" id="dailyPager"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>使用最多的取件URL</h2>
        <div class="notice">按打开页面次数排序。</div>
      </div>
      <table>
        <thead><tr><th>邮箱</th><th>成功率</th><th>异常</th><th>打开页面</th><th>刷新邮件</th><th>独立IP</th><th>最后访问</th><th>24小时邮件</th><th>7天邮件</th></tr></thead>
        <tbody id="topUsageBody"></tbody>
      </table>
      <div class="pager" id="topUsagePager"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>最近访问记录</h2>
        <div class="notice">只在后台可见，不记录完整 token。</div>
      </div>
      <table>
        <thead><tr><th>时间</th><th>邮箱</th><th>动作</th><th>状态</th><th>访问IP</th><th>归属地</th></tr></thead>
        <tbody id="recentAccessBody"></tbody>
      </table>
      <div class="pager" id="recentAccessPager"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>最近新增邮件</h2>
        <div class="notice">这里统计服务器第一次缓存到邮件的时间。</div>
      </div>
      <table>
        <thead><tr><th>缓存时间</th><th>邮箱</th><th>标题</th><th>发件人</th><th>邮件时间</th></tr></thead>
        <tbody id="recentMailsBody"></tbody>
      </table>
      <div class="pager" id="recentMailsPager"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>IMAP账号</h2>
        <div class="notice" id="groupNotice"></div>
      </div>
      <table>
        <thead><tr><th>主邮箱</th><th>邮箱数</th><th>上次检查</th><th>状态</th><th>操作</th></tr></thead>
        <tbody id="groupsBody"></tbody>
      </table>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>取件URL</h2>
        <div class="filters">
          <input id="search" placeholder="搜索邮箱或主邮箱">
          <select id="enabledFilter">
            <option value="all">全部状态</option>
            <option value="on">只看启用</option>
            <option value="off">只看停用</option>
          </select>
        </div>
      </div>
      <table>
        <thead><tr><th>邮箱</th><th>主邮箱</th><th>创建时间</th><th>Token</th><th>状态</th><th>操作</th></tr></thead>
        <tbody id="mailboxesBody"></tbody>
      </table>
      <div class="pager" id="mailboxesPager"></div>
      <div class="notice" id="notice"></div>
    </section>
  </main>
  <script>
    const esc = (s) => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    let state = { groups: [], mailboxes: [], summary: {} };
    const pages = { daily: 1, topUsage: 1, recentAccess: 1, recentMails: 1, mailboxes: 1 };
    const pageSizes = { daily: 3, topUsage: 3, recentAccess: 5, recentMails: 10, mailboxes: 3 };
    const notice = document.getElementById('notice');
    const groupNotice = document.getElementById('groupNotice');

    function setNotice(text) {
      notice.textContent = text || '';
      if (text) setTimeout(() => { if (notice.textContent === text) notice.textContent = ''; }, 4200);
    }
    function pct(value) {
      const num = Number(value);
      return Number.isFinite(num) ? `${num.toFixed(num % 1 ? 2 : 0)}%` : '100%';
    }
    function pageSlice(rows, key) {
      const size = pageSizes[key] || 10;
      const totalPages = Math.max(1, Math.ceil(rows.length / size));
      pages[key] = Math.min(Math.max(1, pages[key] || 1), totalPages);
      const start = (pages[key] - 1) * size;
      return { rows: rows.slice(start, start + size), totalPages };
    }
    function renderPager(id, key, total, totalPages) {
      const el = document.getElementById(id);
      if (!el) return;
      const page = pages[key] || 1;
      el.innerHTML = total > (pageSizes[key] || 10)
        ? `<button class="secondary" data-page-key="${key}" data-dir="-1" ${page <= 1 ? 'disabled' : ''}>上一页</button>
           <span>${page} / ${totalPages}，共 ${total} 条</span>
           <button class="secondary" data-page-key="${key}" data-dir="1" ${page >= totalPages ? 'disabled' : ''}>下一页</button>`
        : `<span>共 ${total} 条</span>`;
    }
    function renderServerPager(id, key, meta) {
      const el = document.getElementById(id);
      if (!el) return;
      const total = Number(meta.matched || 0);
      const totalPages = Number(meta.total_pages || 1);
      pages[key] = Number(meta.page || 1);
      el.innerHTML = total > Number(meta.limit || pageSizes[key])
        ? `<button class="secondary" data-page-key="${key}" data-dir="-1" ${!meta.has_prev ? 'disabled' : ''}>上一页</button>
           <span>${pages[key]} / ${totalPages}，共 ${total} 条</span>
           <button class="secondary" data-page-key="${key}" data-dir="1" ${!meta.has_next ? 'disabled' : ''}>下一页</button>`
        : `<span>共 ${total} 条</span>`;
    }
    async function copyText(text) {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
      }
      const box = document.createElement('textarea');
      box.value = text;
      box.setAttribute('readonly', '');
      box.style.position = 'fixed';
      box.style.left = '-9999px';
      document.body.appendChild(box);
      box.select();
      document.execCommand('copy');
      document.body.removeChild(box);
    }
    async function api(url, options = {}) {
      const res = await fetch(url, Object.assign({ cache: 'no-store' }, options));
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || '操作失败');
      return data;
    }
    async function load() {
      const params = new URLSearchParams();
      const searchEl = document.getElementById('search');
      const filterEl = document.getElementById('enabledFilter');
      if (searchEl && searchEl.value.trim()) params.set('q', searchEl.value.trim());
      if (filterEl && filterEl.value !== 'all') params.set('enabled', filterEl.value);
      params.set('page', String(pages.mailboxes || 1));
      params.set('limit', String(pageSizes.mailboxes));
      state = await api(`/admin/api/data?${params.toString()}`);
      render();
    }
    function render() {
      const analytics = state.analytics || {};
      const today = analytics.today || {};
      const req = analytics.request_summary || {};
      document.getElementById('base').textContent = state.base_url || '';
      document.getElementById('statGroups').textContent = state.summary.groups || 0;
      document.getElementById('statBoxes').textContent = state.summary.mailboxes || 0;
      document.getElementById('statEnabled').textContent = state.summary.enabled || 0;
      document.getElementById('statMessages').textContent = state.summary.messages || 0;
      document.getElementById('todayPages').textContent = today.page_hits || 0;
      document.getElementById('todayUsed').textContent = today.used_mailboxes || 0;
      document.getElementById('todayIps').textContent = today.unique_ips || 0;
      document.getElementById('todayMails').textContent = today.new_mails || 0;
      document.getElementById('todayRate').textContent = pct(req.today_success_rate);
      document.getElementById('todaySuccess').textContent = req.today_success_requests || 0;
      document.getElementById('todayFailed').textContent = req.today_failed_requests || 0;
      document.getElementById('imapErrors').textContent = state.summary.imap_error_groups || 0;
      const groupsBody = document.getElementById('groupsBody');
      groupsBody.innerHTML = state.groups.map(g => `<tr>
        <td data-label="主邮箱">${esc(g.master_email)}</td>
        <td data-label="邮箱数">${g.mailboxes}</td>
        <td data-label="上次检查">${esc(g.last_fetch_at || '')}</td>
        <td data-label="状态"><span class="status ${g.last_error ? 'off' : ''}">${esc(g.last_error ? '异常' : '正常')}</span>${g.last_error ? `<span class="minor">${esc(g.last_error)}</span>` : ''}</td>
        <td data-label="操作"><div class="actions"><button data-test-group="${g.id}">测试IMAP</button></div></td>
      </tr>`).join('');
      renderAnalytics();
      renderMailboxes();
    }
    function emptyRow(colspan, text) {
      return `<tr><td data-label="" colspan="${colspan}">${esc(text)}</td></tr>`;
    }
    function renderAnalytics() {
      const analytics = state.analytics || {};
      const daily = (analytics.daily || []).slice().reverse();
      const dailyPage = pageSlice(daily, 'daily');
      document.getElementById('dailyBody').innerHTML = dailyPage.rows.length ? dailyPage.rows.map(row => `<tr>
        <td data-label="日期">${esc(row.date)}</td>
        <td data-label="成功率">${pct(row.success_rate)}</td>
        <td data-label="异常">${row.failed_requests || 0}</td>
        <td data-label="打开页面">${row.page_hits || 0}</td>
        <td data-label="刷新邮件">${row.api_hits || 0}</td>
        <td data-label="使用邮箱">${row.used_mailboxes || 0}</td>
        <td data-label="独立IP">${row.unique_ips || 0}</td>
        <td data-label="新增邮件">${row.new_mails || 0}</td>
      </tr>`).join('') : emptyRow(8, '暂无统计');
      renderPager('dailyPager', 'daily', daily.length, dailyPage.totalPages);
      const top = analytics.top_mailboxes || [];
      const topPage = pageSlice(top, 'topUsage');
      document.getElementById('topUsageBody').innerHTML = topPage.rows.length ? topPage.rows.map(row => `<tr>
        <td data-label="邮箱">${esc(row.email)}</td>
        <td data-label="成功率">${pct(row.success_rate)}</td>
        <td data-label="异常">${row.failed_requests || 0}</td>
        <td data-label="打开页面">${row.page_hits || 0}</td>
        <td data-label="刷新邮件">${row.api_hits || 0}</td>
        <td data-label="独立IP">${row.unique_ips || 0}</td>
        <td data-label="最后访问">${esc(row.last_access_at || '')}</td>
        <td data-label="24小时邮件">${row.new_mails_24h || 0}</td>
        <td data-label="7天邮件">${row.new_mails_7d || 0}</td>
      </tr>`).join('') : emptyRow(9, '暂无访问记录');
      renderPager('topUsagePager', 'topUsage', top.length, topPage.totalPages);
      const recentAccess = analytics.recent_access || [];
      const accessPage = pageSlice(recentAccess, 'recentAccess');
      document.getElementById('recentAccessBody').innerHTML = accessPage.rows.length ? accessPage.rows.map(row => `<tr>
        <td data-label="时间">${esc(row.created_at || '')}</td>
        <td data-label="邮箱">${esc(row.email || '')}</td>
        <td data-label="动作">${esc(row.action || '')}</td>
        <td data-label="状态">${row.status || ''}</td>
        <td data-label="访问IP">${esc(row.ip || '')}</td>
        <td data-label="归属地">${esc(row.ip_location || '')}${row.ip_provider ? `<span class="ip-meta">${esc(row.ip_provider)}</span>` : ''}</td>
      </tr>`).join('') : emptyRow(6, '暂无访问记录');
      renderPager('recentAccessPager', 'recentAccess', recentAccess.length, accessPage.totalPages);
      const recentMails = analytics.recent_mails || [];
      const mailPage = pageSlice(recentMails, 'recentMails');
      document.getElementById('recentMailsBody').innerHTML = mailPage.rows.length ? mailPage.rows.map(row => `<tr>
        <td data-label="缓存时间">${esc(row.first_seen_at || '')}</td>
        <td data-label="邮箱">${esc(row.email || '')}</td>
        <td data-label="标题">${esc(row.subject || '')}</td>
        <td data-label="发件人">${esc(row.sender || '')}</td>
        <td data-label="邮件时间">${esc(row.received_at || '')}</td>
      </tr>`).join('') : emptyRow(5, '暂无新增邮件');
      renderPager('recentMailsPager', 'recentMails', recentMails.length, mailPage.totalPages);
    }
    function renderMailboxes() {
      const rows = state.mailboxes || [];
      document.getElementById('mailboxesBody').innerHTML = rows.length ? rows.map(m => `<tr>
        <td data-label="邮箱">${esc(m.email)}</td>
        <td data-label="主邮箱">${esc(m.master_email)}</td>
        <td data-label="创建时间">${esc(m.created_at || '')}</td>
        <td data-label="Token">...${esc(m.token_tail)}</td>
        <td data-label="状态"><span class="status ${m.enabled ? '' : 'off'}">${m.enabled ? '启用' : '停用'}</span></td>
        <td data-label="操作"><div class="actions">
          <a class="btn secondary" href="${esc(m.url)}" target="_blank" rel="noreferrer">打开</a>
          <button data-copy="${esc(m.url)}">复制</button>
          <button data-rotate="${m.id}">重置</button>
          <button class="${m.enabled ? 'danger' : ''}" data-toggle="${m.id}">${m.enabled ? '停用' : '启用'}</button>
        </div></td>
      </tr>`).join('') : emptyRow(6, '暂无取件URL');
      const meta = state.mailbox_page || {};
      renderServerPager('mailboxesPager', 'mailboxes', meta);
    }
    let searchTimer = null;
    document.addEventListener('click', async (ev) => {
      const el = ev.target.closest('button');
      if (!el) return;
      try {
        if (el.id === 'reloadBtn') { await load(); return; }
        if (el.dataset.pageKey) {
          const key = el.dataset.pageKey;
          pages[key] = Math.max(1, (pages[key] || 1) + Number(el.dataset.dir || 0));
          if (key === 'mailboxes') await load(); else render();
          return;
        }
        if (el.id === 'logoutBtn') {
          await fetch('/admin/logout', { method: 'POST' });
          location.reload();
          return;
        }
        if (el.dataset.copy) {
          await copyText(el.dataset.copy);
          setNotice('已复制取件URL。');
          return;
        }
        if (el.dataset.rotate) {
          if (!confirm('重置后旧URL会立即失效，继续吗？')) return;
          const data = await api('/admin/api/mailbox/rotate', { method: 'POST', body: JSON.stringify({ id: Number(el.dataset.rotate) }) });
          await copyText(data.url);
          setNotice('新URL已生成并复制，旧URL已失效。');
          await load();
          return;
        }
        if (el.dataset.toggle) {
          await api('/admin/api/mailbox/toggle', { method: 'POST', body: JSON.stringify({ id: Number(el.dataset.toggle) }) });
          await load();
          return;
        }
        if (el.dataset.testGroup) {
          el.disabled = true;
          groupNotice.textContent = '正在测试 IMAP';
          const data = await api('/admin/api/group/test', { method: 'POST', body: JSON.stringify({ id: Number(el.dataset.testGroup) }) });
          groupNotice.textContent = `测试完成，已读取 ${data.count || 0} 封近期邮件。`;
          await load();
          return;
        }
      } catch (err) {
        setNotice(err.message || String(err));
      } finally {
        el.disabled = false;
      }
    });
    document.getElementById('search').addEventListener('input', () => {
      clearTimeout(searchTimer);
      pages.mailboxes = 1;
      searchTimer = setTimeout(() => load().catch(err => setNotice(err.message || String(err))), 260);
    });
    document.getElementById('enabledFilter').addEventListener('change', () => {
      pages.mailboxes = 1;
      load().catch(err => setNotice(err.message || String(err)));
    });
    load().catch(err => setNotice(err.message || String(err)));
  </script>
  <!-- THEME_SCRIPT -->
</body>
</html>
"""


LOGIN_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="sky">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#eaf4f7">
  <title>信渡 · 后台登录</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="icon" href="/favicon.ico" sizes="any">
  <!-- THEME_HEAD_SCRIPT -->
  <style>
    :root {
      color-scheme: light;
      --ink: #14202b;
      --muted: #627284;
      --line: rgba(255,255,255,.5);
      --glass: rgba(255,255,255,.66);
      --accent: #177e89;
      font-family: Inter, "Segoe UI", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background: linear-gradient(135deg, rgba(226,242,240,.96), rgba(241,245,249,.94) 48%, rgba(252,247,238,.92)), #eef3f2;
    }
    .login {
      width: min(420px, calc(100% - 28px));
      margin: 12vh auto 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--glass);
      backdrop-filter: blur(18px);
      box-shadow: 0 18px 55px rgba(31,41,55,.13);
      padding: 22px;
    }
    .login-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 20px;
    }
    .login-brand img {
      width: 46px;
      height: 46px;
      border-radius: 12px;
      box-shadow: 0 10px 26px rgba(23,126,137,.2);
    }
    .login-brand span {
      display: block;
      color: var(--muted);
      font-size: 13px;
      letter-spacing: .08em;
    }
    h1 { margin: 0; font-size: 25px; letter-spacing: 0; }
    p { color: var(--muted); margin: 8px 0 0; }
    form { display: grid; gap: 12px; margin-top: 18px; }
    input {
      width: 100%;
      min-height: 42px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,.74);
      background: rgba(255,255,255,.78);
      color: var(--ink);
      padding: 0 12px;
      outline: none;
    }
    button {
      min-height: 42px;
      border: 0;
      border-radius: 8px;
      background: var(--accent);
      color: white;
      font-weight: 800;
      cursor: pointer;
    }
    .error { color: #b42318; min-height: 22px; }
  </style>
  <style><!-- SHARED_THEME_STYLE --></style>
</head>
<body>
  <!-- THEME_PICKER -->
  <main class="login">
    <div class="login-brand">
      <img src="/favicon.svg" alt="" width="46" height="46">
      <span>SELF-HOSTED MAIL PICKUP</span>
    </div>
    <h1>信渡 · 管理后台</h1>
    <p>让每一封来信，都抵达它该去的地方。</p>
    <form method="post" action="/admin/login">
      <input name="password" type="password" autocomplete="current-password" aria-label="后台密码" placeholder="后台密码" autofocus>
      <button type="submit">登录</button>
      <div class="error">__ERROR__</div>
    </form>
  </main>
  <!-- THEME_SCRIPT -->
</body>
</html>
"""


FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="bg" x1="9" y1="8" x2="56" y2="58" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#d8f5f0"/>
      <stop offset="0.52" stop-color="#177e89"/>
      <stop offset="1" stop-color="#f2b84b"/>
    </linearGradient>
    <linearGradient id="mail" x1="18" y1="21" x2="47" y2="43" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#ffffff" stop-opacity="0.94"/>
      <stop offset="1" stop-color="#e7fbf8" stop-opacity="0.82"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="14" fill="url(#bg)"/>
  <path d="M16 22.8c0-2 1.6-3.6 3.6-3.6h24.8c2 0 3.6 1.6 3.6 3.6v18.4c0 2-1.6 3.6-3.6 3.6H19.6c-2 0-3.6-1.6-3.6-3.6V22.8Z" fill="url(#mail)" stroke="#ffffff" stroke-opacity="0.72" stroke-width="1.5"/>
  <path d="m18.5 22.5 13.5 11 13.5-11" fill="none" stroke="#177e89" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M21 42.2 30.4 34M43 42.2 33.6 34" fill="none" stroke="#177e89" stroke-opacity="0.42" stroke-width="2.2" stroke-linecap="round"/>
  <circle cx="47.5" cy="17.5" r="7.5" fill="#f2b84b" stroke="#fff6d9" stroke-width="2"/>
  <path d="M45 17.6h5M47.5 15.1v5" stroke="#6f4b00" stroke-width="2" stroke-linecap="round"/>
</svg>
"""
FAVICON_ICO_PATH = Path(__file__).with_name("favicon.ico")


def json_body(handler: BaseHTTPRequestHandler) -> dict[str, object]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length > 1_000_000:
        raise ValueError("请求体过大")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def int_param(params: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(params.get(key, [str(default)])[0] or default)
    except (TypeError, ValueError):
        return default


def float_param(params: dict[str, list[str]], key: str, default: float) -> float:
    try:
        return float(params.get(key, [str(default)])[0] or default)
    except (TypeError, ValueError):
        return default


class PickupHTTPServer(ThreadingHTTPServer):
    request_queue_size = 512
    daemon_threads = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._request_slots = threading.BoundedSemaphore(HTTP_MAX_CONCURRENT_REQUESTS)

    def reject_busy_request(self, request: object) -> None:
        previous_timeout = None
        try:
            previous_timeout = request.gettimeout()
            request.settimeout(0.0)
            request_head = bytearray()
            while b"\r\n\r\n" not in request_head and len(request_head) < 16_384:
                chunk = request.recv(4096)
                if not chunk:
                    break
                request_head.extend(chunk)
        except (BlockingIOError, OSError):
            pass
        finally:
            try:
                request.settimeout(previous_timeout)
            except OSError:
                pass

        payload = b'{"ok":false,"error":"server_busy"}'
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(payload)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + payload
        )
        try:
            request.sendall(response)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.reject_busy_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, request: object, client_address: object) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


class PickupHandler(BaseHTTPRequestHandler):
    server_version = "PickupServer/1.0"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, fmt: str, *args) -> None:
        message = fmt % args
        if "/health " in message:
            return
        if "/api/q/" in message:
            now = utc_now_ts()
            key = f"logapi:{self.client_address[0]}"
            with INVALID_ACCESS_GUARD:
                last = INVALID_ACCESS_LAST.get(key, 0.0)
                if now - last < INVALID_ACCESS_LOG_SECONDS:
                    return
                INVALID_ACCESS_LAST[key] = now
        if " 404 " in message and "/q/" in message:
            now = utc_now_ts()
            key = f"log404:{self.client_address[0]}"
            with INVALID_ACCESS_GUARD:
                last = INVALID_ACCESS_LAST.get(key, 0.0)
                if now - last < INVALID_ACCESS_LOG_SECONDS:
                    return
                INVALID_ACCESS_LAST[key] = now
        message = re.sub(r"pk_[A-Za-z0-9_\-]{20,}", "[token]", message)
        sys.stderr.write(
            f"{self.client_address[0]} - - [{self.log_date_time_string()}] {message}\n"
        )

    def send_html(self, body: str, status: int = 200) -> None:
        nonce = secrets.token_urlsafe(18)
        self._csp_nonce = nonce
        body = (
            body.replace("<!-- THEME_HEAD_SCRIPT -->", THEME_HEAD_SCRIPT)
            .replace("<!-- SHARED_THEME_STYLE -->", SHARED_THEME_STYLE)
            .replace("<!-- THEME_PICKER -->", THEME_PICKER_HTML)
            .replace("<!-- THEME_SCRIPT -->", THEME_SCRIPT)
        )
        body = body.replace("<style>", f'<style nonce="{nonce}">').replace("<script>", f'<script nonce="{nonce}">')
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, body: dict[str, object], status: int = 200) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_svg(self, body: str, status: int = 200) -> None:
        self._cache_control = "public, max-age=86400"
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_ico(self, status: int = 200) -> None:
        if not FAVICON_ICO_PATH.is_file():
            self.send_json({"ok": False, "error": "favicon unavailable"}, status=404)
            return
        self._cache_control = "public, max-age=86400"
        payload = FAVICON_ICO_PATH.read_bytes()
        self.send_response(status)
        self.send_header("Content-Type", "image/x-icon")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def end_headers(self) -> None:
        nonce = getattr(self, "_csp_nonce", "")
        if nonce:
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                "img-src 'self' data:; connect-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
            )
        else:
            csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", getattr(self, "_cache_control", "no-store"))
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        retry_after = getattr(self, "_retry_after", 0)
        if retry_after:
            self.send_header("Retry-After", str(max(1, int(retry_after))))
        super().end_headers()

    def require_admin(self) -> bool:
        if is_valid_session(self.headers.get("Cookie")):
            return True
        self.send_json({"ok": False, "error": "未登录"}, status=401)
        return False

    def same_origin_request(self) -> bool:
        host = self.headers.get("Host", "")
        for header_name in ("Origin", "Referer"):
            value = self.headers.get(header_name)
            if not value:
                continue
            parsed = urllib.parse.urlparse(value)
            if parsed.netloc != host:
                return False
        return True

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        if path in {"/health", "/ready"}:
            payload, status = health_status(strict=path == "/ready")
            self.send_json(payload, status=status)
            return
        if path == "/favicon.svg":
            self.send_svg(FAVICON_SVG)
            return
        if path == "/favicon.ico":
            self.send_ico()
            return
        if path == "/":
            self.redirect("/admin")
            return
        if path.startswith("/q/"):
            token = urllib.parse.unquote(path.split("/q/", 1)[1].strip("/"))
            try:
                mailbox = lookup_mailbox_by_token(token)
            except sqlite3.Error:
                self.send_html(PICKUP_HTML.replace("正在载入", "服务暂时不可用"), status=503)
                return
            if not mailbox:
                record_access_event(None, self.client_address[0], "page_open", 404)
                self.send_html(PICKUP_HTML.replace("正在载入", "链接无效"), status=404)
                return
            if not int(mailbox["mailbox_enabled"]) or not int(mailbox["group_enabled"]):
                record_access_event(int(mailbox["mailbox_id"]), self.client_address[0], "page_open", 403)
                self.send_html(PICKUP_HTML.replace("正在载入", "链接已停用"), status=403)
                return
            record_access_event(int(mailbox["mailbox_id"]), self.client_address[0], "page_open", 200)
            self.send_html(PICKUP_HTML)
            return
        if path.startswith("/api/q/") and path.endswith("/messages"):
            token = urllib.parse.unquote(path[len("/api/q/") : -len("/messages")].strip("/"))
            params = urllib.parse.parse_qs(parsed_url.query)
            wait_seconds = float_param(params, "wait", REALTIME_API_WAIT_SECONDS)
            message_limit = int_param(params, "limit", 30)
            try:
                mailbox = lookup_mailbox_by_token(token)
            except sqlite3.Error:
                self.send_json({"ok": False, "error": "取件服务暂时不可用，请稍后重试"}, status=503)
                return
            data = mailbox_messages(
                token,
                mailbox=mailbox,
                wait_seconds=wait_seconds,
                limit=message_limit,
            )
            status = int(data.get("status", 200))
            record_access_event(int(mailbox["mailbox_id"]) if mailbox else None, self.client_address[0], "api_messages", status)
            fetch_meta = data.get("fetch")
            if isinstance(fetch_meta, dict) and fetch_meta.get("pending"):
                self._retry_after = fetch_meta.get("retry_after_seconds", 2)
            self.send_json(data, status=status)
            return
        if path == "/admin":
            if not is_valid_session(self.headers.get("Cookie")):
                self.send_html(LOGIN_HTML.replace("__ERROR__", ""))
                return
            self.send_html(ADMIN_HTML)
            return
        if path == "/admin/api/data":
            if not self.require_admin():
                return
            params = urllib.parse.parse_qs(parsed_url.query)
            query = params.get("q", [""])[0]
            enabled_filter = params.get("enabled", ["all"])[0]
            page = int_param(params, "page", 1)
            limit = int_param(params, "limit", 3)
            self.send_json(admin_data(query=query, enabled_filter=enabled_filter, page=page, limit=limit))
            return
        if path == "/admin/api/export":
            if not is_valid_session(self.headers.get("Cookie")):
                self.send_response(401)
                self.end_headers()
                return
            body = export_urls_text()
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=pickup-urls.txt")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/admin/login":
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > 100_000:
                self.send_html(LOGIN_HTML.replace("__ERROR__", "请求体过大"), status=413)
                return
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            data = urllib.parse.parse_qs(raw)
            password = data.get("password", [""])[0]
            ip = self.client_address[0]
            if login_limited(ip):
                self.send_html(LOGIN_HTML.replace("__ERROR__", "登录尝试过多，请稍后再试"), status=429)
                return
            if admin_login(password):
                clear_login_failures(ip)
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.send_header("Set-Cookie", admin_cookie(make_session(), 12 * 3600))
                self.end_headers()
                return
            record_login_failure(ip)
            self.send_html(LOGIN_HTML.replace("__ERROR__", "密码不正确"), status=403)
            return
        if path == "/admin/logout":
            self.send_response(204)
            self.send_header("Set-Cookie", admin_cookie("", 0))
            self.end_headers()
            return
        if not self.require_admin():
            return
        if path.startswith("/admin/api/") and not self.same_origin_request():
            self.send_json({"ok": False, "error": "请求来源不正确"}, status=403)
            return
        try:
            data = json_body(self)
            if path == "/admin/api/mailbox/rotate":
                self.send_json(admin_rotate_mailbox(int(data.get("id", 0))))
                return
            if path == "/admin/api/mailbox/toggle":
                self.send_json(admin_toggle_mailbox(int(data.get("id", 0))))
                return
            if path == "/admin/api/group/test":
                group_id = int(data.get("id", 0))
                result = fetch_group(group_id, force=True)
                if not result.get("ok"):
                    self.send_json({"ok": False, "error": str(result.get("error", "测试失败"))}, status=400)
                    return
                self.send_json({"ok": True, "count": int(result.get("count", 0))})
                return
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)
            return
        self.send_json({"ok": False, "error": "Not found"}, status=404)


def export_urls_text() -> str:
    with db() as conn:
        base = get_setting(conn, "base_url", "").rstrip("/")
        rows = conn.execute(
            """
            SELECT m.email, m.token
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE m.enabled = 1 AND g.enabled = 1
            ORDER BY g.master_email COLLATE NOCASE, m.email COLLATE NOCASE
            """
        ).fetchall()
    return "\n".join(f"{row['email']}----{base}/q/{row['token']}" for row in rows) + "\n"


def analytics_day_key(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), ANALYTICS_TZ).strftime("%Y-%m-%d")


def analytics_day_start(days_ago: int = 0) -> float:
    now = datetime.now(ANALYTICS_TZ)
    target = (now - timedelta(days=days_ago)).date()
    return datetime(target.year, target.month, target.day, tzinfo=ANALYTICS_TZ).timestamp()


def build_mail_analytics(
    mailbox_rows: list[sqlite3.Row],
    message_rows: list[sqlite3.Row],
    start_14d: float,
    start_7d: float,
    start_24h: float,
) -> tuple[dict[str, int], dict[int, dict[str, int]], list[dict[str, object]]]:
    mailbox_by_key: dict[tuple[int, str], sqlite3.Row] = {
        (int(row["group_id"]), normalize_email(str(row["email"]))): row for row in mailbox_rows
    }
    daily_counts: dict[str, int] = {}
    mailbox_counts: dict[int, dict[str, int]] = {}
    recent_mails: list[dict[str, object]] = []
    for msg in message_rows:
        first_seen = float(msg["first_seen_at"] or msg["fetched_at"] or 0)
        if not first_seen:
            continue
        recipients = extract_emails(str(msg["recipient_text"] or ""))
        matched_rows = [
            mailbox_by_key[(int(msg["group_id"]), email)]
            for email in recipients
            if (int(msg["group_id"]), email) in mailbox_by_key
        ]
        if not matched_rows:
            continue
        day = analytics_day_key(first_seen)
        for mailbox in matched_rows:
            mailbox_id = int(mailbox["id"])
            if first_seen >= start_14d:
                daily_counts[day] = daily_counts.get(day, 0) + 1
            stats = mailbox_counts.setdefault(mailbox_id, {"new_mails_24h": 0, "new_mails_7d": 0})
            if first_seen >= start_24h:
                stats["new_mails_24h"] += 1
            if first_seen >= start_7d:
                stats["new_mails_7d"] += 1
            if len(recent_mails) < 80:
                recent_mails.append(
                    {
                        "first_seen_at": iso_from_ts(first_seen),
                        "email": mailbox["email"],
                        "master_email": mailbox["master_email"],
                        "subject": msg["subject"] or "",
                        "sender": msg["sender"] or "",
                        "received_at": msg["received_at"] or "",
                    }
                )
    recent_mails.sort(key=lambda item: str(item["first_seen_at"]), reverse=True)
    return daily_counts, mailbox_counts, recent_mails[:80]


def analytics_data(
    access_rows: list[sqlite3.Row],
    mailbox_rows: list[sqlite3.Row],
    message_rows: list[sqlite3.Row],
    geo_cache: dict[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    geo_cache = geo_cache or {}
    start_14d = analytics_day_start(13)
    start_7d = analytics_day_start(6)
    start_today = analytics_day_start(0)
    start_24h = utc_now_ts() - 24 * 3600
    daily_mail_counts, mailbox_mail_counts, recent_mails = build_mail_analytics(
        mailbox_rows, message_rows, start_14d, start_7d, start_24h
    )
    mailboxes_by_id = {int(row["id"]): row for row in mailbox_rows}

    def rate(success: int, total: int) -> float:
        return round((success * 100 / total), 2) if total else 100.0

    daily: dict[str, dict[str, object]] = {}
    for days_ago in range(13, -1, -1):
        ts = analytics_day_start(days_ago)
        key = analytics_day_key(ts)
        daily[key] = {
            "date": key,
            "page_hits": 0,
            "api_hits": 0,
            "unique_ips": set(),
            "used_mailboxes": set(),
            "new_mails": daily_mail_counts.get(key, 0),
            "total_requests": 0,
            "success_requests": 0,
            "failed_requests": 0,
        }
    mailbox_usage: dict[int, dict[str, object]] = {}
    recent_access: list[dict[str, object]] = []
    total_requests = 0
    success_requests = 0
    failed_requests = 0
    today_total = 0
    today_success = 0
    today_failed = 0
    for event in access_rows:
        mailbox_id = int(event["mailbox_id"] or 0)
        mailbox = mailboxes_by_id.get(mailbox_id)
        created_at = float(event["created_at"] or 0)
        action = str(event["action"] or "")
        ip = str(event["ip"] or "")
        status = int(event["status"] or 200)
        ok = 200 <= status < 400
        total_requests += 1
        if ok:
            success_requests += 1
        else:
            failed_requests += 1
        if created_at >= start_today:
            today_total += 1
            if ok:
                today_success += 1
            else:
                today_failed += 1
        day = analytics_day_key(created_at)
        if day in daily:
            if action == "page_open":
                daily[day]["page_hits"] = int(daily[day]["page_hits"]) + 1
            elif action == "api_messages":
                daily[day]["api_hits"] = int(daily[day]["api_hits"]) + 1
            daily[day]["unique_ips"].add(ip)  # type: ignore[union-attr]
            daily[day]["total_requests"] = int(daily[day]["total_requests"]) + 1
            if ok:
                daily[day]["success_requests"] = int(daily[day]["success_requests"]) + 1
            else:
                daily[day]["failed_requests"] = int(daily[day]["failed_requests"]) + 1
            if mailbox:
                daily[day]["used_mailboxes"].add(mailbox_id)  # type: ignore[union-attr]
        if mailbox:
            usage = mailbox_usage.setdefault(
                mailbox_id,
                {
                    "id": mailbox_id,
                    "email": mailbox["email"],
                    "master_email": mailbox["master_email"],
                    "page_hits": 0,
                    "api_hits": 0,
                    "success_requests": 0,
                    "failed_requests": 0,
                    "unique_ips_set": set(),
                    "last_access_at": "",
                    "last_access_ts": 0.0,
                },
            )
            if action == "page_open":
                usage["page_hits"] = int(usage["page_hits"]) + 1
            elif action == "api_messages":
                usage["api_hits"] = int(usage["api_hits"]) + 1
            if ok:
                usage["success_requests"] = int(usage["success_requests"]) + 1
            else:
                usage["failed_requests"] = int(usage["failed_requests"]) + 1
            usage["unique_ips_set"].add(ip)  # type: ignore[union-attr]
            if created_at >= float(usage["last_access_ts"]):
                usage["last_access_ts"] = created_at
                usage["last_access_at"] = iso_from_ts(created_at)
        if len(recent_access) < 160:
            location = ip_location(ip, geo_cache)
            action_label = "打开页面" if action == "page_open" else "刷新邮件" if action == "api_messages" else action
            if not ok:
                action_label = f"{action_label}失败"
            recent_access.append(
                {
                    "created_at": iso_from_ts(created_at),
                    "email": mailbox["email"] if mailbox else "无效或已重置链接",
                    "master_email": mailbox["master_email"] if mailbox else "",
                    "ip": ip,
                    "ip_location": location["location"],
                    "ip_provider": location["provider"],
                    "status": status,
                    "action": action_label,
                }
            )
    daily_rows: list[dict[str, object]] = []
    for item in daily.values():
        success = int(item["success_requests"])
        total = int(item["total_requests"])
        daily_rows.append(
            {
                "date": item["date"],
                "page_hits": item["page_hits"],
                "api_hits": item["api_hits"],
                "unique_ips": len(item["unique_ips"]),  # type: ignore[arg-type]
                "used_mailboxes": len(item["used_mailboxes"]),  # type: ignore[arg-type]
                "new_mails": item["new_mails"],
                "success_requests": success,
                "failed_requests": int(item["failed_requests"]),
                "success_rate": rate(success, total),
            }
        )
    top_mailboxes: list[dict[str, object]] = []
    for mailbox_id, usage in mailbox_usage.items():
        mail_counts = mailbox_mail_counts.get(mailbox_id, {"new_mails_24h": 0, "new_mails_7d": 0})
        top_mailboxes.append(
            {
                "id": mailbox_id,
                "email": usage["email"],
                "master_email": usage["master_email"],
                "page_hits": usage["page_hits"],
                "api_hits": usage["api_hits"],
                "success_requests": usage["success_requests"],
                "failed_requests": usage["failed_requests"],
                "success_rate": rate(int(usage["success_requests"]), int(usage["success_requests"]) + int(usage["failed_requests"])),
                "unique_ips": len(usage["unique_ips_set"]),  # type: ignore[arg-type]
                "last_access_at": usage["last_access_at"],
                "new_mails_24h": mail_counts["new_mails_24h"],
                "new_mails_7d": mail_counts["new_mails_7d"],
            }
        )
    top_mailboxes.sort(
        key=lambda item: (
            int(item["page_hits"]),
            int(item["unique_ips"]),
            int(item["api_hits"]),
            str(item["last_access_at"]),
        ),
        reverse=True,
    )
    today_key = analytics_day_key(start_today)
    today = next((row for row in daily_rows if row["date"] == today_key), {})
    return {
        "today": today,
        "request_summary": {
            "total_requests": total_requests,
            "success_requests": success_requests,
            "failed_requests": failed_requests,
            "success_rate": rate(success_requests, total_requests),
            "today_total_requests": today_total,
            "today_success_requests": today_success,
            "today_failed_requests": today_failed,
            "today_success_rate": rate(today_success, today_total),
        },
        "daily": daily_rows,
        "top_mailboxes": top_mailboxes[:60],
        "recent_access": recent_access[:120],
        "recent_mails": recent_mails,
    }


def admin_data(query: str = "", enabled_filter: str = "all", page: int = 1, limit: int = 3) -> dict[str, object]:
    query = (query or "").strip()
    enabled_filter = enabled_filter if enabled_filter in {"all", "on", "off"} else "all"
    page = max(1, int(page or 1))
    limit = max(3, min(100, int(limit or 3)))
    offset = (page - 1) * limit
    access_ips: list[str] = []
    geo_cache: dict[str, dict[str, str]] = {}
    with db() as conn:
        base = get_setting(conn, "base_url", "").rstrip("/")
        group_rows = conn.execute(
            """
            SELECT
                g.id, g.master_email, g.enabled, g.last_fetch_at, g.last_success_at,
                g.last_full_fetch_at, g.last_error, g.last_count, g.last_seen_uid,
                COUNT(m.id) AS mailboxes
            FROM groups g
            LEFT JOIN mailboxes m ON m.group_id = g.id
            GROUP BY g.id
            ORDER BY g.master_email COLLATE NOCASE
            """
        ).fetchall()
        analytics_box_rows = conn.execute(
            """
            SELECT m.id, m.group_id, m.email, m.token_tail, m.enabled, g.master_email
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            ORDER BY m.email COLLATE NOCASE
            """
        ).fetchall()
        like = f"%{query}%"
        filter_params: tuple[object, ...] = (
            query,
            like,
            like,
            enabled_filter,
            enabled_filter,
            enabled_filter,
        )
        count_query = """
            SELECT COUNT(*) AS c
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE (? = '' OR m.email LIKE ? OR g.master_email LIKE ?)
              AND (
                ? = 'all'
                OR (? = 'on' AND m.enabled = 1)
                OR (? = 'off' AND m.enabled = 0)
              )
            """
        matched = conn.execute(count_query, filter_params).fetchone()["c"]
        total_pages = max(1, (int(matched) + limit - 1) // limit)
        if page > total_pages:
            page = total_pages
            offset = (page - 1) * limit
        mailbox_query = """
            SELECT m.id, m.group_id, m.email, m.token, m.token_tail, m.enabled, m.created_at, m.updated_at, g.master_email
            FROM mailboxes m
            JOIN groups g ON g.id = m.group_id
            WHERE (? = '' OR m.email LIKE ? OR g.master_email LIKE ?)
              AND (
                ? = 'all'
                OR (? = 'on' AND m.enabled = 1)
                OR (? = 'off' AND m.enabled = 0)
              )
            ORDER BY m.created_at DESC, m.id DESC
            LIMIT ? OFFSET ?
            """
        box_rows = conn.execute(
            mailbox_query,
            (*filter_params, limit, offset),
        ).fetchall()
        access_rows = conn.execute(
            """
            SELECT * FROM access_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (ACCESS_ANALYTICS_LIMIT,),
        ).fetchall()
        access_ips = [str(row["ip"] or "") for row in access_rows[:160]]
        geo_cache = geo_cache_for_ips(conn, access_ips)
        message_rows = conn.execute(
            """
            SELECT * FROM messages
            WHERE COALESCE(first_seen_at, fetched_at) >= ?
            ORDER BY COALESCE(first_seen_at, fetched_at) DESC, id DESC
            LIMIT 2000
            """,
            (analytics_day_start(13),),
        ).fetchall()
        summary = {
            "groups": conn.execute("SELECT COUNT(*) AS c FROM groups").fetchone()["c"],
            "mailboxes": conn.execute("SELECT COUNT(*) AS c FROM mailboxes").fetchone()["c"],
            "enabled": conn.execute("SELECT COUNT(*) AS c FROM mailboxes WHERE enabled = 1").fetchone()["c"],
            "messages": conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"],
            "access_events": conn.execute("SELECT COUNT(*) AS c FROM access_events").fetchone()["c"],
            "imap_error_groups": conn.execute(
                "SELECT COUNT(*) AS c FROM groups WHERE COALESCE(last_error, '') <> ''"
            ).fetchone()["c"],
        }
    schedule_geo_lookups(access_ips, geo_cache, limit=10)
    groups = [
        {
            "id": int(row["id"]),
            "master_email": row["master_email"],
            "enabled": bool(row["enabled"]),
            "mailboxes": int(row["mailboxes"] or 0),
            "last_fetch_at": iso_from_ts(float(row["last_success_at"] or 0)),
            "last_success_at": iso_from_ts(float(row["last_success_at"] or 0)),
            "last_attempt_at": iso_from_ts(float(row["last_fetch_at"] or 0)),
            "last_full_fetch_at": iso_from_ts(float(row["last_full_fetch_at"] or 0)),
            "last_error": row["last_error"] or "",
            "last_count": int(row["last_count"] or 0),
            "last_seen_uid": int(row["last_seen_uid"] or 0),
        }
        for row in group_rows
    ]
    mailboxes = [
        {
            "id": int(row["id"]),
            "email": row["email"],
            "master_email": row["master_email"],
            "token_tail": row["token_tail"],
            "enabled": bool(row["enabled"]),
            "url": f"{base}/q/{row['token']}",
            "created_at": iso_from_ts(float(row["created_at"] or 0)),
            "updated_at": iso_from_ts(float(row["updated_at"] or 0)),
        }
        for row in box_rows
    ]
    analytics = analytics_data(access_rows, analytics_box_rows, message_rows, geo_cache=geo_cache)
    return {
        "ok": True,
        "base_url": base,
        "summary": summary,
        "groups": groups,
        "mailboxes": mailboxes,
        "mailbox_page": {
            "limit": limit,
            "matched": int(matched),
            "returned": len(mailboxes),
            "query": query,
            "enabled": enabled_filter,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
        "analytics": analytics,
    }


def admin_rotate_mailbox(mailbox_id: int) -> dict[str, object]:
    if mailbox_id <= 0:
        return {"ok": False, "error": "邮箱不存在"}
    token = new_token()
    now = utc_now_ts()
    with db() as conn:
        row = conn.execute("SELECT id FROM mailboxes WHERE id = ?", (mailbox_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "邮箱不存在"}
        conn.execute(
            "UPDATE mailboxes SET token = ?, token_hash = ?, token_tail = ?, updated_at = ? WHERE id = ?",
            (token, token_hash(token), token[-8:], now, mailbox_id),
        )
        base = get_setting(conn, "base_url", "").rstrip("/")
    return {"ok": True, "url": f"{base}/q/{token}", "token_tail": token[-8:]}


def admin_toggle_mailbox(mailbox_id: int) -> dict[str, object]:
    if mailbox_id <= 0:
        return {"ok": False, "error": "邮箱不存在"}
    with db() as conn:
        row = conn.execute("SELECT enabled FROM mailboxes WHERE id = ?", (mailbox_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "邮箱不存在"}
        new_value = 0 if int(row["enabled"]) else 1
        conn.execute("UPDATE mailboxes SET enabled = ?, updated_at = ? WHERE id = ?", (new_value, utc_now_ts(), mailbox_id))
    return {"ok": True, "enabled": bool(new_value)}


def parse_pickup_url_line(line: str) -> tuple[str, str, str]:
    raw = line.strip()
    if "\t" in raw:
        parts = raw.split("\t")
        delimiter = "tab"
    elif "----" in raw:
        parts = raw.split("----")
        delimiter = "dashes"
    else:
        raise ValueError("缺少受支持的分隔符")
    if len(parts) != 2:
        raise ValueError("字段数量不正确")
    email_addr = normalize_email(parts[0])
    url = parts[1].strip()
    if not EMAIL_RE.fullmatch(email_addr):
        raise ValueError("邮箱格式不正确")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL 必须是绝对 HTTP(S) 地址")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL 端口格式不正确") from exc
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("URL 不得包含查询、片段或用户信息")
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) != 2 or path_parts[0] != "q":
        raise ValueError("URL 路径必须是 /q/<token>")
    token = urllib.parse.unquote(path_parts[1])
    if not re.fullmatch(r"pk_[A-Za-z0-9_-]{40,100}", token):
        raise ValueError("token 格式不正确")
    return email_addr, url, delimiter


def audit_pickup_url_file(path: Path) -> dict[str, object]:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig", errors="strict").splitlines()
        if line.strip()
    ]
    emails: set[str] = set()
    urls: set[str] = set()
    delimiter_counts = {"tab": 0, "dashes": 0}
    endpoints: set[tuple[str, int | None, str]] = set()
    plaintext_rows = 0
    invalid = duplicate_emails = duplicate_urls = 0
    for line in lines:
        try:
            email_addr, url, delimiter = parse_pickup_url_line(line)
        except ValueError:
            invalid += 1
            continue
        delimiter_counts[delimiter] += 1
        parsed_url = urllib.parse.urlparse(url)
        endpoints.add((str(parsed_url.hostname or ""), parsed_url.port, parsed_url.scheme))
        if parsed_url.scheme == "http":
            plaintext_rows += 1
        if email_addr in emails:
            duplicate_emails += 1
        if url in urls:
            duplicate_urls += 1
        emails.add(email_addr)
        urls.add(url)
    return {
        "ok": not (invalid or duplicate_emails or duplicate_urls),
        "rows": len(lines),
        "valid_rows": len(lines) - invalid,
        "invalid_rows": invalid,
        "duplicate_emails": duplicate_emails,
        "duplicate_urls": duplicate_urls,
        "delimiter_counts": delimiter_counts,
        "endpoint_count": len(endpoints),
        "single_endpoint": len(endpoints) == 1 and bool(lines),
        "plaintext_http_rows": plaintext_rows,
    }


def convert_pickup_url_file(source: Path, output: Path, delimiter: str) -> dict[str, object]:
    separator = "\t" if delimiter == "tab" else "----"
    parsed_rows: list[tuple[str, str]] = []
    for line in source.read_text(encoding="utf-8-sig", errors="strict").splitlines():
        if not line.strip():
            continue
        email_addr, url, _ = parse_pickup_url_line(line)
        parsed_rows.append((email_addr, url))
    if len({email for email, _ in parsed_rows}) != len(parsed_rows):
        raise ValueError("输入存在重复邮箱，未生成输出")
    if len({url for _, url in parsed_rows}) != len(parsed_rows):
        raise ValueError("输入存在重复 URL，未生成输出")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output.with_name(f".{output.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        temp_path.write_text(
            "\n".join(f"{email}{separator}{url}" for email, url in parsed_rows) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, output)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return {"ok": True, "rows": len(parsed_rows), "delimiter": delimiter, "output": str(output)}


def cmd_init(args: argparse.Namespace) -> None:
    ensure_env()
    init_db()
    password = args.admin_password
    if args.admin_password_stdin:
        password = sys.stdin.read().strip()
    if password:
        set_admin_password(password)
    if args.base_url:
        with db() as conn:
            set_setting(conn, "base_url", args.base_url.rstrip("/"))
    print("initialized")


def cmd_import(args: argparse.Namespace) -> None:
    result = import_source(Path(args.source), base_url=args.base_url.rstrip("/"), output=Path(args.output) if args.output else None)
    print(json.dumps(result, ensure_ascii=False))


def cmd_export(args: argparse.Namespace) -> None:
    count = export_urls(Path(args.output), base_url=args.base_url)
    print(json.dumps({"exported": count, "output": args.output}, ensure_ascii=False))


def cmd_check_imap(args: argparse.Namespace) -> None:
    init_db()
    results = []
    with db() as conn:
        groups = conn.execute("SELECT id, master_email FROM groups ORDER BY id").fetchall()
    for group in groups:
        result = fetch_group(int(group["id"]), force=True)
        results.append(
            {
                "master_email": group["master_email"],
                "ok": bool(result.get("ok")),
                "count": int(result.get("count", 0)) if result.get("ok") else 0,
                "error": "" if result.get("ok") else str(result.get("error", "")),
            }
        )
    print(json.dumps(results, ensure_ascii=False))


def cmd_audit_urls(args: argparse.Namespace) -> None:
    result = audit_pickup_url_file(Path(args.input))
    print(json.dumps(result, ensure_ascii=False))
    if not result["ok"]:
        raise SystemExit(2)


def cmd_convert_urls(args: argparse.Namespace) -> None:
    result = convert_pickup_url_file(
        Path(args.input),
        Path(args.output),
        args.delimiter,
    )
    print(json.dumps(result, ensure_ascii=False))


def cmd_serve(args: argparse.Namespace) -> None:
    ensure_env()
    init_db()
    POLL_STOP.clear()
    start_access_event_writer()
    threading.Thread(target=poll_loop, name="mail-poll-loop", daemon=True).start()
    server = PickupHTTPServer((args.host, args.port), PickupHandler)
    print(f"serving {APP_VERSION} on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        POLL_STOP.set()
        server.server_close()
        stop_access_event_writer()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure token mail pickup server")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("--admin-password")
    p_init.add_argument("--admin-password-stdin", action="store_true")
    p_init.add_argument("--base-url", default="")
    p_init.set_defaults(func=cmd_init)

    p_import = sub.add_parser("import")
    p_import.add_argument("--source", required=True)
    p_import.add_argument("--base-url", required=True)
    p_import.add_argument("--output")
    p_import.set_defaults(func=cmd_import)

    p_export = sub.add_parser("export")
    p_export.add_argument("--output", required=True)
    p_export.add_argument("--base-url")
    p_export.set_defaults(func=cmd_export)

    p_check = sub.add_parser("check-imap")
    p_check.set_defaults(func=cmd_check_imap)

    p_audit_urls = sub.add_parser("audit-urls")
    p_audit_urls.add_argument("--input", required=True)
    p_audit_urls.set_defaults(func=cmd_audit_urls)

    p_convert_urls = sub.add_parser("convert-urls")
    p_convert_urls.add_argument("--input", required=True)
    p_convert_urls.add_argument("--output", required=True)
    p_convert_urls.add_argument("--delimiter", choices=("dashes", "tab"), default="dashes")
    p_convert_urls.set_defaults(func=cmd_convert_urls)

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=int(os.environ.get("PICKUP_PORT", "8080")))
    p_serve.set_defaults(func=cmd_serve)
    return parser


def ensure_runtime_compatibility() -> None:
    if sys.version_info < (3, 10):
        raise RuntimeError("需要 Python 3.10 或更高版本")
    if sqlite3.sqlite_version_info < (3, 35, 0):
        raise RuntimeError("需要 SQLite 3.35 或更高版本（当前环境不支持 RETURNING）")


def main(argv: list[str] | None = None) -> None:
    ensure_runtime_compatibility()
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
