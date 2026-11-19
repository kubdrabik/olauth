import io
import sqlite3
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from olauth.core import OLAuth, _build_smtp_sender

from olauth.crypto import (
    hash_password,
    hash_token,
    verify_password,
    verify_password_constant_time,
)
from olauth.database import DatabaseManager, detect_dialect
from olauth.ui import (
    RateLimiter,
    is_same_origin_post,
    render_auth_page,
    render_forgot_password_page,
    render_reset_password_page,
    render_verify_page,
    resolve_redirect_target,
    validate_credentials,
)


class CryptoTests(unittest.TestCase):
    def test_hash_and_verify_standard_password(self):
        hashed = hash_password("correct-horse-battery")
        self.assertTrue(verify_password("correct-horse-battery", hashed))
        self.assertFalse(verify_password("wrong-password", hashed))

    def test_passwords_over_72_bytes_are_supported_without_error(self):
        long_pw = "p" * 100
        hashed = hash_password(long_pw)
        self.assertTrue(verify_password(long_pw, hashed))
        self.assertFalse(verify_password("p" * 99 + "x", hashed))

        unicode_pw = "🔐" * 25  # 100 UTF-8 bytes
        hashed_u = hash_password(unicode_pw)
        self.assertTrue(verify_password(unicode_pw, hashed_u))
        self.assertFalse(verify_password("🔐" * 24, hashed_u))

    def test_oversized_guess_against_standard_hash_does_not_crash(self):
        hashed = hash_password("short-secret")
        self.assertFalse(verify_password("x" * 100, hashed))

    def test_constant_time_verification_handles_missing_hash(self):
        self.assertFalse(verify_password_constant_time("anything", None))
        self.assertFalse(verify_password_constant_time("anything", ""))

    def test_hash_token_uses_sha256_hex(self):
        digest = hash_token("raw-session-token")
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, hash_token("raw-session-token"))
        self.assertNotEqual(digest, "raw-session-token")


class DatabaseTests(unittest.TestCase):
    def test_detect_dialect(self):
        self.assertEqual(detect_dialect(None), "sqlite")
        self.assertEqual(detect_dialect("olauth.db"), "sqlite")
        self.assertEqual(detect_dialect(":memory:"), "sqlite")
        self.assertEqual(detect_dialect("sqlite:///local.db"), "sqlite")
        self.assertEqual(detect_dialect("postgres://u:p@host/db"), "postgres")
        self.assertEqual(detect_dialect("postgresql://u:p@host/db"), "postgres")
        self.assertEqual(detect_dialect("postgresql+psycopg2://u:p@host/db"), "postgres")
        self.assertEqual(detect_dialect("mysql://u:p@host/db"), "mysql")
        self.assertEqual(detect_dialect("mysql+pymysql://u:p@host/db"), "mysql")

    def test_sqlite_user_and_session_lifecycle(self):
        db = DatabaseManager()
        db.initialize_db(":memory:")
        try:
            self.assertTrue(db.create_user("  Alice@Example.com ", "hash1"))
            self.assertFalse(db.create_user("alice@example.com", "hash2"))

            user = db.get_user_by_email("ALICE@example.com")
            self.assertIsNotNone(user)
            self.assertEqual(user["email"], "alice@example.com")
            self.assertEqual(user["password_hash"], "hash1")

            public_user = db.get_user_by_id(user["id"])
            self.assertEqual(public_user["email"], "alice@example.com")
            self.assertNotIn("password_hash", public_user)

            raw_token = db.create_session(user["id"], ttl_seconds=3600)
            row = db.connection.execute("SELECT token FROM olauth_sessions").fetchone()
            self.assertNotEqual(row["token"], raw_token)
            self.assertEqual(row["token"], hash_token(raw_token))

            session_user = db.get_user_by_session(raw_token)
            self.assertIsNotNone(session_user)
            self.assertEqual(session_user["id"], user["id"])
            self.assertEqual(session_user["email"], "alice@example.com")
            self.assertNotIn("password_hash", session_user)

            db.delete_session(raw_token)
            self.assertIsNone(db.get_user_by_session(raw_token))

            # Expired session is rejected and cleaned up
            expired_token = db.create_session(user["id"], ttl_seconds=-10)
            self.assertIsNone(db.get_user_by_session(expired_token))
            remaining = db.connection.execute("SELECT COUNT(*) FROM olauth_sessions").fetchone()[0]
            self.assertEqual(remaining, 0)

            # Bulk session cleanup and user session revocation
            t_active = db.create_session(user["id"], ttl_seconds=3600)
            db.create_session(user["id"], ttl_seconds=-5)
            cleaned = db.cleanup_expired_sessions()
            self.assertEqual(cleaned, 1)
            self.assertIsNotNone(db.get_user_by_session(t_active))

            db.delete_user_sessions(user["id"])
            self.assertIsNone(db.get_user_by_session(t_active))
        finally:
            db.close()

    def test_dialect_sql_and_ddl_generation(self):
        db = DatabaseManager()
        db.dialect = "sqlite"
        self.assertEqual(db.adapt_sql("SELECT * FROM users WHERE email = ?"), "SELECT * FROM users WHERE email = ?")
        self.assertEqual(db._primary_key_ddl(), "INTEGER PRIMARY KEY AUTOINCREMENT")

        db.dialect = "postgres"
        self.assertEqual(db.adapt_sql("SELECT * FROM users WHERE email = ?"), "SELECT * FROM users WHERE email = %s")
        self.assertEqual(db._primary_key_ddl(), "SERIAL PRIMARY KEY")

        db.dialect = "mysql"
        self.assertEqual(db.adapt_sql("SELECT * FROM users WHERE email = ?"), "SELECT * FROM users WHERE email = %s")
        self.assertEqual(db._primary_key_ddl(), "INT AUTO_INCREMENT PRIMARY KEY")

    def test_mocked_postgres_and_mysql_drivers(self):
        class FakeIntegrityError(Exception):
            pass

        class FakeCursor:
            def __init__(self, conn):
                self.conn = conn
                self.description = None
                self.rowcount = 0
                self._rows = []

            def execute(self, sql, params=()):
                self.conn.executed.append((sql, params))
                sqlite_sql = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                sqlite_sql = sqlite_sql.replace("INT AUTO_INCREMENT PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                sqlite_sql = sqlite_sql.replace("%s", "?")
                try:
                    self._cur = self.conn.sqlite_conn.execute(sqlite_sql, params)
                    self.description = self._cur.description
                    self.rowcount = self._cur.rowcount
                except sqlite3.IntegrityError as exc:
                    raise FakeIntegrityError(str(exc)) from exc

            def fetchone(self):
                return self._cur.fetchone()

            def fetchall(self):
                return self._cur.fetchall()

            def close(self):
                pass

        class FakeConnection:
            def __init__(self):
                self.sqlite_conn = sqlite3.connect(":memory:")
                self.sqlite_conn.execute("PRAGMA foreign_keys=ON;")
                self.executed = []
                self.closed = 0
                self.open = True
                self.rolled_back = False

            def cursor(self):
                return FakeCursor(self)

            def commit(self):
                self.sqlite_conn.commit()

            def rollback(self):
                self.rolled_back = True
                self.sqlite_conn.rollback()

            def ping(self, reconnect=True):
                self.open = True

            def close(self):
                self.closed = 1
                self.open = False
                self.sqlite_conn.close()

        # Test PostgreSQL via mocked psycopg module
        fake_pg_conn = FakeConnection()
        fake_psycopg = types.ModuleType("psycopg")
        fake_psycopg.IntegrityError = FakeIntegrityError
        pg_urls = []
        fake_psycopg.connect = lambda url: (pg_urls.append(url) or fake_pg_conn)

        orig_psycopg = sys.modules.get("psycopg")
        sys.modules["psycopg"] = fake_psycopg
        try:
            pg_db = DatabaseManager()
            pg_db.initialize_db("postgresql+psycopg://user:pw@localhost:5432/mydb")
            self.assertEqual(pg_db.dialect, "postgres")
            self.assertEqual(pg_urls[0], "postgresql://user:pw@localhost:5432/mydb")
            self.assertTrue(pg_db.create_user("bob@example.com", "h1"))
            self.assertFalse(pg_db.create_user("bob@example.com", "h2"))
            self.assertTrue(fake_pg_conn.rolled_back)
            user = pg_db.get_user_by_email("bob@example.com")
            token = pg_db.create_session(user["id"])
            self.assertEqual(pg_db.get_user_by_session(token)["email"], "bob@example.com")
            pg_db.close()
        finally:
            if orig_psycopg is None:
                sys.modules.pop("psycopg", None)
            else:
                sys.modules["psycopg"] = orig_psycopg

        # Test MySQL via mocked pymysql module
        fake_my_conn = FakeConnection()
        fake_pymysql = types.ModuleType("pymysql")
        fake_pymysql.IntegrityError = FakeIntegrityError
        my_kwargs = []
        fake_pymysql.connect = lambda **kw: (my_kwargs.append(kw) or fake_my_conn)

        orig_pymysql = sys.modules.get("pymysql")
        sys.modules["pymysql"] = fake_pymysql
        try:
            my_db = DatabaseManager()
            my_db.initialize_db("mysql://admin:p%40ss@db.internal:3307/appdb?ssl=true")
            self.assertEqual(my_db.dialect, "mysql")
            self.assertEqual(my_kwargs[0]["host"], "db.internal")
            self.assertEqual(my_kwargs[0]["port"], 3307)
            self.assertEqual(my_kwargs[0]["user"], "admin")
            self.assertEqual(my_kwargs[0]["password"], "p@ss")
            self.assertEqual(my_kwargs[0]["database"], "appdb")
            self.assertIn("ssl", my_kwargs[0])
            self.assertTrue(my_db.create_user("carol@example.com", "h1"))
            self.assertFalse(my_db.create_user("carol@example.com", "h2"))
            user = my_db.get_user_by_email("carol@example.com")
            token = my_db.create_session(user["id"])
            self.assertEqual(my_db.get_user_by_session(token)["email"], "carol@example.com")
            my_db.close()
        finally:
            if orig_pymysql is None:
                sys.modules.pop("pymysql", None)
            else:
                sys.modules["pymysql"] = orig_pymysql

    def test_missing_postgres_and_mysql_drivers_raise_clear_error(self):
        orig_psycopg = sys.modules.get("psycopg")
        orig_psycopg2 = sys.modules.get("psycopg2")
        orig_pymysql = sys.modules.get("pymysql")
        sys.modules["psycopg"] = None
        sys.modules["psycopg2"] = None
        sys.modules["pymysql"] = None
        try:
            db = DatabaseManager()
            with self.assertRaises(RuntimeError) as pg_ctx:
                db.initialize_db("postgresql://u:p@localhost/db")
            self.assertIn("olauth[postgres]", str(pg_ctx.exception))

            with self.assertRaises(RuntimeError) as my_ctx:
                db.initialize_db("mysql://u:p@localhost/db")
            self.assertIn("olauth[mysql]", str(my_ctx.exception))
        finally:
            for name, orig in (("psycopg", orig_psycopg), ("psycopg2", orig_psycopg2), ("pymysql", orig_pymysql)):
                if orig is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = orig

    def test_sqlite_verification_code_lifecycle(self):
        db = DatabaseManager()
        db.initialize_db(":memory:")
        try:
            self.assertTrue(db.create_user("verify@example.com", "hash1", is_verified=False))
            user = db.get_user_by_email("verify@example.com")
            self.assertEqual(user["is_verified"], 0)

            code = db.create_verification_code(user["id"], ttl_seconds=600)
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

            # Wrong code fails and keeps user unverified
            self.assertIsNone(db.verify_user_code("verify@example.com", "000000" if code != "000000" else "999999"))
            self.assertEqual(db.get_user_by_email("verify@example.com")["is_verified"], 0)

            # Valid code verifies user and is single-use
            verified = db.verify_user_code("verify@example.com", code)
            self.assertIsNotNone(verified)
            self.assertEqual(verified["email"], "verify@example.com")
            self.assertEqual(db.get_user_by_email("verify@example.com")["is_verified"], 1)
            self.assertIsNone(db.verify_user_code("verify@example.com", code))

            # Expired code fails and deletes itself
            expired_code = db.create_verification_code(user["id"], ttl_seconds=-5)
            self.assertIsNone(db.verify_user_code("verify@example.com", expired_code))
            remaining = db.connection.execute("SELECT COUNT(*) FROM olauth_verifications").fetchone()[0]
            self.assertEqual(remaining, 0)
        finally:
            db.close()

    def test_sqlite_reset_user_password_lifecycle(self):
        db = DatabaseManager()
        db.initialize_db(":memory:")
        try:
            self.assertTrue(db.create_user("reset@example.com", "old-hash", is_verified=False))
            user = db.get_user_by_email("reset@example.com")
            old_session = db.create_session(user["id"], ttl_seconds=3600)
            self.assertIsNotNone(db.get_user_by_session(old_session))

            code = db.create_verification_code(user["id"], ttl_seconds=600)
            wrong = "000000" if code != "000000" else "999999"
            self.assertIsNone(db.reset_user_password("reset@example.com", wrong, "new-hash"))
            self.assertEqual(db.get_user_by_email("reset@example.com")["password_hash"], "old-hash")
            self.assertIsNotNone(db.get_user_by_session(old_session))

            updated = db.reset_user_password("reset@example.com", code, "new-hash")
            self.assertIsNotNone(updated)
            self.assertEqual(updated["email"], "reset@example.com")

            refreshed = db.get_user_by_email("reset@example.com")
            self.assertEqual(refreshed["password_hash"], "new-hash")
            self.assertEqual(refreshed["is_verified"], 1)
            # Single-use code consumed and prior sessions revoked
            self.assertIsNone(db.reset_user_password("reset@example.com", code, "newer-hash"))
            self.assertIsNone(db.get_user_by_session(old_session))
        finally:
            db.close()

    def test_postgres_and_mysql_reconnect_on_dropped_connection(self):
        class FakeIntegrityError(Exception):
            pass

        class FakeOperationalError(Exception):
            pass

        shared_sqlite = sqlite3.connect(":memory:")
        shared_sqlite.execute("PRAGMA foreign_keys=ON;")

        class DroppableCursor:
            def __init__(self, conn):
                self.conn = conn
                self.description = None
                self.rowcount = 0
                self._cur = None

            def execute(self, sql, params=()):
                if self.conn.fail_next_execute:
                    self.conn.fail_next_execute = False
                    raise FakeOperationalError("server closed the connection unexpectedly")
                sqlite_sql = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                sqlite_sql = sqlite_sql.replace("INT AUTO_INCREMENT PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                sqlite_sql = sqlite_sql.replace("%s", "?")
                try:
                    self._cur = shared_sqlite.execute(sqlite_sql, params)
                    self.description = self._cur.description
                    self.rowcount = self._cur.rowcount
                except sqlite3.IntegrityError as exc:
                    raise FakeIntegrityError(str(exc)) from exc

            def fetchone(self):
                return self._cur.fetchone()

            def fetchall(self):
                return self._cur.fetchall()

            def close(self):
                pass

        class DroppableConnection:
            def __init__(self):
                self.closed = 0
                self.broken = False
                self.open = True
                self.fail_next_execute = False

            def cursor(self):
                return DroppableCursor(self)

            def commit(self):
                shared_sqlite.commit()

            def rollback(self):
                shared_sqlite.rollback()

            def ping(self, reconnect=True):
                if not self.open:
                    raise FakeOperationalError("MySQL server has gone away")

            def close(self):
                self.closed = 1
                self.open = False

        # PostgreSQL reconnect on closed=1 and on OperationalError mid-query
        pg_conns = []
        fake_psycopg = types.ModuleType("psycopg")
        fake_psycopg.IntegrityError = FakeIntegrityError
        fake_psycopg.OperationalError = FakeOperationalError
        fake_psycopg.connect = lambda _url: (pg_conns.append(DroppableConnection()) or pg_conns[-1])

        orig_psycopg = sys.modules.get("psycopg")
        sys.modules["psycopg"] = fake_psycopg
        try:
            pg_db = DatabaseManager()
            pg_db.initialize_db("postgresql://u:p@localhost/db")
            self.assertEqual(len(pg_conns), 1)
            self.assertTrue(pg_db.create_user("pgdrop@example.com", "h1"))

            # Pre-query closed connection reconnects cleanly
            pg_conns[-1].closed = 1
            self.assertEqual(pg_db.get_user_by_email("pgdrop@example.com")["email"], "pgdrop@example.com")
            self.assertEqual(len(pg_conns), 2)

            # Mid-query OperationalError triggers reconnect + retry once
            pg_conns[-1].fail_next_execute = True
            self.assertEqual(pg_db.get_user_by_email("pgdrop@example.com")["email"], "pgdrop@example.com")
            self.assertEqual(len(pg_conns), 3)
            pg_db.close()
        finally:
            if orig_psycopg is None:
                sys.modules.pop("psycopg", None)
            else:
                sys.modules["psycopg"] = orig_psycopg

        # MySQL reconnect on open=False and on OperationalError mid-query
        my_conns = []
        fake_pymysql = types.ModuleType("pymysql")
        fake_pymysql.IntegrityError = FakeIntegrityError
        fake_pymysql.OperationalError = FakeOperationalError
        fake_pymysql.connect = lambda **_kw: (my_conns.append(DroppableConnection()) or my_conns[-1])

        orig_pymysql = sys.modules.get("pymysql")
        sys.modules["pymysql"] = fake_pymysql
        try:
            my_db = DatabaseManager()
            my_db.initialize_db("mysql://u:p@localhost/db")
            self.assertEqual(len(my_conns), 1)

            my_conns[-1].open = False
            self.assertEqual(my_db.get_user_by_email("pgdrop@example.com")["email"], "pgdrop@example.com")
            self.assertEqual(len(my_conns), 2)

            my_conns[-1].fail_next_execute = True
            self.assertEqual(my_db.get_user_by_email("pgdrop@example.com")["email"], "pgdrop@example.com")
            self.assertEqual(len(my_conns), 3)
            my_db.close()
        finally:
            if orig_pymysql is None:
                sys.modules.pop("pymysql", None)
            else:
                sys.modules["pymysql"] = orig_pymysql
            shared_sqlite.close()


class UITests(unittest.TestCase):
    def test_render_auth_page_escapes_xss(self):
        html_out = render_auth_page(
            title="<script>alert(1)</script>",
            heading="Log in",
            button_text="Log in",
            switch_prompt="New?",
            switch_url="/signup",
            switch_action="Sign up",
            error='<img src=x onerror="alert(1)">',
            email_value='"><script>alert(2)</script>',
        )
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertNotIn("<script>alert(2)</script>", html_out)
        self.assertNotIn('<img src=x onerror="alert(1)">', html_out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", html_out)

    def test_render_verify_page_escapes_xss(self):
        html_out = render_verify_page(
            email_value='"><script>alert(1)</script>',
            error='<svg onload="alert(2)">',
            switch_url="/login",
        )
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertNotIn('<svg onload="alert(2)">', html_out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertIn("&lt;svg onload=&quot;alert(2)&quot;&gt;", html_out)

    def test_render_forgot_and_reset_pages_escape_xss(self):
        forgot_html = render_forgot_password_page(
            email_value='"><script>alert(1)</script>',
            error='<img src=x onerror="alert(2)">',
            switch_url="/login",
        )
        self.assertNotIn("<script>alert(1)</script>", forgot_html)
        self.assertNotIn('<img src=x onerror="alert(2)">', forgot_html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", forgot_html)
        self.assertIn("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;", forgot_html)

        reset_html = render_reset_password_page(
            email_value='"><script>alert(3)</script>',
            error='<svg onload="alert(4)">',
            switch_url="/login",
        )
        self.assertNotIn("<script>alert(3)</script>", reset_html)
        self.assertNotIn('<svg onload="alert(4)">', reset_html)
        self.assertIn("&lt;script&gt;alert(3)&lt;/script&gt;", reset_html)
        self.assertIn("&lt;svg onload=&quot;alert(4)&quot;&gt;", reset_html)

    def test_validate_credentials(self):
        _, _, err = validate_credentials("not-an-email", "password123")
        self.assertIsNotNone(err)

        _, _, err = validate_credentials("a@b.com", "short", min_password_length=8)
        self.assertIn("8", err)

        _, _, err = validate_credentials("a@b.com", "x" * 129)
        self.assertIsNotNone(err)

        email, pw, err = validate_credentials("  User@Example.COM ", "validpass123")
        self.assertIsNone(err)
        self.assertEqual(email, "user@example.com")
        self.assertEqual(pw, "validpass123")

    def test_resolve_redirect_target_blocks_open_redirects(self):
        self.assertEqual(resolve_redirect_target("/dashboard", "/"), "/dashboard")
        self.assertEqual(resolve_redirect_target("/items?page=2&q=a", "/"), "/items?page=2&q=a")
        self.assertEqual(resolve_redirect_target("//evil.com", "/"), "/")
        self.assertEqual(resolve_redirect_target("/\\evil.com", "/"), "/")
        self.assertEqual(resolve_redirect_target("https://evil.com", "/"), "/")
        self.assertEqual(resolve_redirect_target("javascript:alert(1)", "/"), "/")
        self.assertEqual(resolve_redirect_target("dashboard", "/"), "/")
        self.assertEqual(resolve_redirect_target("/bad\r\nHeader: x", "/"), "/")

    def test_same_origin_post_check(self):
        self.assertTrue(is_same_origin_post({}, "localhost:5000"))
        self.assertTrue(
            is_same_origin_post({"Origin": "http://localhost:5000"}, "localhost:5000")
        )
        self.assertFalse(
            is_same_origin_post({"Origin": "https://evil.com"}, "localhost:5000")
        )
        self.assertFalse(
            is_same_origin_post({"Origin": "null"}, "localhost:5000")
        )
        self.assertFalse(
            is_same_origin_post({"Sec-Fetch-Site": "cross-site"}, "localhost:5000")
        )

    def test_rate_limiter_sliding_window(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        self.assertTrue(limiter.is_allowed("1.2.3.4"))
        limiter.record_failure("1.2.3.4")
        limiter.record_failure("1.2.3.4")
        self.assertTrue(limiter.is_allowed("1.2.3.4"))
        limiter.record_failure("1.2.3.4")
        self.assertFalse(limiter.is_allowed("1.2.3.4"))
        limiter.reset("1.2.3.4")
        self.assertTrue(limiter.is_allowed("1.2.3.4"))


class BuiltinSenderTests(unittest.TestCase):
    def test_builtin_smtp_sender_sends_verification_email(self):
        sender = _build_smtp_sender("sender@example.com", "app-pw", "smtp.gmail.com", 465)
        with patch("olauth.core.smtplib.SMTP_SSL") as mock_smtp:
            server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = server
            sender("user@example.com", "654321")

            mock_smtp.assert_called_once()
            args, kwargs = mock_smtp.call_args
            self.assertEqual(args, ("smtp.gmail.com", 465))
            self.assertEqual(kwargs.get("timeout"), 10)
            server.login.assert_called_once_with("sender@example.com", "app-pw")
            server.send_message.assert_called_once()
            sent_msg = server.send_message.call_args[0][0]
            self.assertEqual(sent_msg["To"], "user@example.com")
            self.assertIn("654321", sent_msg.get_content())

    def test_console_verification_sender_prints_code(self):
        from flask import Flask

        auth = OLAuth()
        app = Flask(__name__)
        auth.init(app, db=":memory:", verify_email="console")
        try:
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                status, _, _, err = auth.process_signup(
                    "console@example.com", "strongpassword123", "127.0.0.1"
                )
            self.assertEqual(status, 201)
            self.assertIsNone(err)
            self.assertIn("console@example.com", buf.getvalue())
            self.assertIn("[OL-Auth] Verification code", buf.getvalue())
        finally:
            auth.db.close()

    def test_verify_email_true_without_credentials_raises_error(self):
        from flask import Flask

        auth = OLAuth()
        app = Flask(__name__)
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                auth.init(app, db=":memory:", verify_email=True)
            auth.db.close()

    def test_custom_template_fallback_without_jinja_and_missing_paths(self):
        import tempfile
        from pathlib import Path
        from flask import Flask

        auth = OLAuth()
        app = Flask(__name__)

        with self.assertRaises(FileNotFoundError):
            auth.init(app, db=":memory:", template_dir="/nonexistent/olauth/templates")
        auth.db.close()

        with self.assertRaises(FileNotFoundError):
            auth.init(app, db=":memory:", login_template="/nonexistent/olauth/login.html")
        auth.db.close()

        with tempfile.TemporaryDirectory() as tmpdir:
            tpl = Path(tmpdir) / "login.html"
            tpl.write_text(
                "<style>body { color: #111; }</style>"
                "<h1>{{ heading }}</h1><p>{{ error }}</p><input value='{email_value}'>",
                encoding="utf-8",
            )
            auth.init(app, db=":memory:", template_dir=tmpdir)
            try:
                with patch.dict(sys.modules, {"jinja2": None}):
                    rendered = auth.render_page(
                        "login",
                        error='<script>xss</script>',
                        email_value='a"b@example.com',
                    )
                self.assertIn("body { color: #111; }", rendered)
                self.assertIn("<h1>Log in to your account</h1>", rendered)
                self.assertIn("&lt;script&gt;xss&lt;/script&gt;", rendered)
                self.assertIn("a&quot;b@example.com", rendered)
            finally:
                auth.db.close()


if __name__ == "__main__":
    unittest.main()
