from datetime import datetime, timedelta, timezone
import hmac
import os
import secrets
import sqlite3
import threading
from urllib.parse import parse_qs, unquote, urlparse

from .crypto import hash_token


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def detect_dialect(db_url: str | None) -> str:
    """Determines the database dialect ('sqlite', 'postgres', or 'mysql') from a URL or path."""
    if not db_url:
        return "sqlite"
    lowered = db_url.strip().lower()
    if lowered.startswith(("postgres://", "postgresql://", "postgresql+")):
        return "postgres"
    if lowered.startswith(("mysql://", "mysql+pymysql://")):
        return "mysql"
    return "sqlite"


def _collect_driver_errors(module, *names: str) -> tuple[type[BaseException], ...]:
    """Safely extracts exception subclasses exposed by a database driver module."""
    errors: list[type[BaseException]] = []
    for name in names:
        candidate = getattr(module, name, None)
        if isinstance(candidate, type) and issubclass(candidate, BaseException):
            errors.append(candidate)
    return tuple(errors)


class DatabaseManager:
    """Manages database connections, schemas, users, and sessions across SQLite, PostgreSQL, and MySQL."""

    def __init__(self):
        self.connection = None
        self.dialect = "sqlite"
        self.db_url: str | None = None
        self._lock = threading.RLock()
        self._driver = None
        self._integrity_errors: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,)
        self._operational_errors: tuple[type[BaseException], ...] = ()

    def close(self) -> None:
        """Closes the active database connection if open."""
        with self._lock:
            if self.connection is not None:
                try:
                    self.connection.close()
                except Exception:
                    pass
                self.connection = None

    def initialize_db(self, db_url: str | None = None) -> None:
        """Establishes a database connection, configures dialect pragmas, and creates schemas."""
        with self._lock:
            self.close()

            resolved = db_url if db_url is not None else os.environ.get("OLAUTH_DATABASE_URL")
            if not resolved:
                resolved = "olauth.db"

            self.db_url = resolved
            self.dialect = detect_dialect(resolved)
            self._connect()
            self._create_schema()

    def _connect(self) -> None:
        if self.dialect == "sqlite":
            db_path = self.db_url or "olauth.db"
            if db_path.startswith("sqlite:///"):
                db_path = db_path[len("sqlite:///"):]
            if not db_path:
                db_path = "olauth.db"
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA busy_timeout=5000;")
            if db_path != ":memory:":
                cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.close()
            self.connection = conn
            self._driver = "sqlite3"
            self._integrity_errors = (sqlite3.IntegrityError,)
            self._operational_errors = ()
            return

        if self.dialect == "postgres":
            conn_url = self.db_url or ""
            for prefix in ("postgresql+psycopg://", "postgresql+psycopg2://"):
                if conn_url.lower().startswith(prefix):
                    conn_url = "postgresql://" + conn_url[len(prefix):]
                    break

            try:
                import psycopg  # type: ignore

                self.connection = psycopg.connect(conn_url)
                self._driver = "psycopg"
                self._integrity_errors = (psycopg.IntegrityError,)
                self._operational_errors = _collect_driver_errors(
                    psycopg, "OperationalError", "InterfaceError"
                )
                return
            except ImportError:
                pass

            try:
                import psycopg2  # type: ignore

                self.connection = psycopg2.connect(conn_url)
                self._driver = "psycopg2"
                self._integrity_errors = (psycopg2.IntegrityError,)
                self._operational_errors = _collect_driver_errors(
                    psycopg2, "OperationalError", "InterfaceError"
                )
                return
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires psycopg or psycopg2-binary. "
                    "Install with: pip install \"olauth[postgres]\""
                ) from exc

        if self.dialect == "mysql":
            try:
                import pymysql  # type: ignore
            except ImportError as exc:
                raise RuntimeError(
                    "MySQL support requires pymysql. "
                    "Install with: pip install \"olauth[mysql]\""
                ) from exc

            conn_url = self.db_url or ""
            if conn_url.lower().startswith("mysql+pymysql://"):
                conn_url = "mysql://" + conn_url[len("mysql+pymysql://"):]

            parsed = urlparse(conn_url)
            query = parse_qs(parsed.query)
            connect_kwargs: dict = {
                "host": parsed.hostname or "localhost",
                "port": parsed.port or 3306,
                "user": unquote(parsed.username) if parsed.username else None,
                "password": unquote(parsed.password) if parsed.password else "",
                "database": parsed.path.lstrip("/") if parsed.path else None,
                "charset": query.get("charset", ["utf8mb4"])[0],
                "autocommit": False,
            }
            if query.get("ssl", ["false"])[0].lower() in ("1", "true", "yes"):
                connect_kwargs["ssl"] = {}

            self.connection = pymysql.connect(**connect_kwargs)
            self._driver = "pymysql"
            self._integrity_errors = (pymysql.IntegrityError,)
            self._operational_errors = _collect_driver_errors(
                pymysql, "OperationalError", "InterfaceError"
            )
            return

        raise ValueError(f"Unsupported database dialect: {self.dialect}")

    def _reconnect(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None
        self._connect()

    def _is_connection_lost(self) -> bool:
        if self.connection is None:
            return True
        if self.dialect == "postgres":
            return bool(getattr(self.connection, "closed", 0)) or bool(
                getattr(self.connection, "broken", False)
            )
        if self.dialect == "mysql":
            return not getattr(self.connection, "open", True)
        return False

    def _should_reconnect_after_error(self, exc: BaseException) -> bool:
        return bool(self._operational_errors and isinstance(exc, self._operational_errors)) or (
            self._is_connection_lost()
        )

    def _ensure_connection(self) -> None:
        if self.connection is None:
            self._connect()
            return

        if self.dialect == "postgres":
            if self._is_connection_lost():
                self._reconnect()
        elif self.dialect == "mysql":
            if self._is_connection_lost():
                self._reconnect()
            elif hasattr(self.connection, "ping"):
                try:
                    self.connection.ping(reconnect=True)
                except Exception:
                    self._reconnect()
                else:
                    if self._is_connection_lost():
                        self._reconnect()

    def adapt_sql(self, sql: str) -> str:
        """Adapts '?' SQL placeholders to the active database dialect."""
        if self.dialect in ("postgres", "mysql"):
            return sql.replace("?", "%s")
        return sql

    def _primary_key_ddl(self) -> str:
        if self.dialect == "postgres":
            return "SERIAL PRIMARY KEY"
        if self.dialect == "mysql":
            return "INT AUTO_INCREMENT PRIMARY KEY"
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def _create_schema(self) -> None:
        pk = self._primary_key_ddl()
        users_ddl = f"""
            CREATE TABLE IF NOT EXISTS users (
                id {pk},
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """
        sessions_ddl = f"""
            CREATE TABLE IF NOT EXISTS olauth_sessions (
                id {pk},
                token VARCHAR(128) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at VARCHAR(64) NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
        verifications_ddl = f"""
            CREATE TABLE IF NOT EXISTS olauth_verifications (
                id {pk},
                user_id INTEGER NOT NULL,
                code_hash VARCHAR(128) NOT NULL,
                expires_at VARCHAR(64) NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
        with self._lock:
            self._ensure_connection()
            cursor = self.connection.cursor()
            try:
                cursor.execute(users_ddl)
                cursor.execute(sessions_ddl)
                cursor.execute(verifications_ddl)
                self.connection.commit()
            except Exception:
                self._safe_rollback()
                raise
            finally:
                cursor.close()

            # Upgrade legacy users tables created before is_verified existed.
            alter_cursor = self.connection.cursor()
            try:
                alter_cursor.execute(
                    "ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1;"
                )
                self.connection.commit()
            except Exception:
                self._safe_rollback()
            finally:
                alter_cursor.close()

    def _safe_rollback(self) -> None:
        if self.connection is not None:
            try:
                self.connection.rollback()
            except Exception:
                pass

    def _row_to_dict(self, cursor, row) -> dict | None:
        if row is None:
            return None
        if isinstance(row, dict):
            return dict(row)
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    def _run_query_once(
        self,
        adapted_sql: str,
        params: tuple,
        *,
        fetchone: bool,
        fetchall: bool,
        commit: bool,
        return_rowcount: bool,
    ):
        cursor = self.connection.cursor()
        try:
            cursor.execute(adapted_sql, params)
            result = None
            if fetchone:
                result = self._row_to_dict(cursor, cursor.fetchone())
            elif fetchall:
                rows = cursor.fetchall()
                result = [self._row_to_dict(cursor, row) for row in rows]
            elif return_rowcount:
                result = cursor.rowcount
            if commit:
                self.connection.commit()
            return result
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    def _execute(
        self,
        sql: str,
        params: tuple = (),
        *,
        fetchone: bool = False,
        fetchall: bool = False,
        commit: bool = False,
        return_rowcount: bool = False,
    ):
        adapted = self.adapt_sql(sql)
        max_attempts = 2 if self.dialect in ("postgres", "mysql") else 1
        with self._lock:
            for attempt in range(max_attempts):
                self._ensure_connection()
                try:
                    return self._run_query_once(
                        adapted,
                        params,
                        fetchone=fetchone,
                        fetchall=fetchall,
                        commit=commit,
                        return_rowcount=return_rowcount,
                    )
                except Exception as exc:
                    should_retry = (
                        attempt == 0
                        and max_attempts > 1
                        and not isinstance(exc, self._integrity_errors)
                        and self._should_reconnect_after_error(exc)
                    )
                    if should_retry:
                        self._reconnect()
                        continue
                    self._safe_rollback()
                    raise

    # --- USER OPERATIONS ---

    def create_user(
        self, email: str, hashed_password: str, *, is_verified: bool = True
    ) -> bool:
        """Inserts a new user record. Returns False on unique email conflict."""
        normalized_email = email.lower().strip()
        verified_flag = 1 if is_verified else 0
        try:
            self._execute(
                "INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, ?)",
                (normalized_email, hashed_password, verified_flag),
                commit=True,
            )
            return True
        except self._integrity_errors:
            return False

    def get_user_by_email(self, email: str) -> dict | None:
        """Returns a user dict (including password_hash and is_verified) matching the normalized email."""
        if not email:
            return None
        normalized_email = email.lower().strip()
        return self._execute(
            "SELECT id, email, password_hash, is_verified, created_at FROM users WHERE email = ?",
            (normalized_email,),
            fetchone=True,
        )

    def get_user_by_id(self, user_id: int) -> dict | None:
        """Returns a sanitized public user dict (without password_hash) by ID."""
        row = self._execute(
            "SELECT id, email, created_at FROM users WHERE id = ?",
            (user_id,),
            fetchone=True,
        )
        if not row:
            return None
        return {
            "id": row["id"],
            "email": row["email"],
            "created_at": str(row["created_at"]) if row.get("created_at") is not None else None,
        }

    # --- SESSION OPERATIONS ---

    def create_session(self, user_id: int, ttl_seconds: int = 604800) -> str:
        """Creates a new persistent session storing a SHA-256 hash of the returned raw token."""
        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_token(raw_token)
        expires_at = _format_utc(_utc_now() + timedelta(seconds=ttl_seconds))
        self._execute(
            "INSERT INTO olauth_sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
            commit=True,
        )
        return raw_token

    def get_user_by_session(self, raw_token: str | None) -> dict | None:
        """Validates a raw session token and returns the associated user dict, or None."""
        if not raw_token or not isinstance(raw_token, str):
            return None

        token_hash = hash_token(raw_token)
        row = self._execute(
            """
            SELECT u.id AS id, u.email AS email, u.created_at AS created_at, s.expires_at AS expires_at
            FROM olauth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token_hash,),
            fetchone=True,
        )
        if not row:
            return None

        try:
            expires_dt = _parse_utc(row["expires_at"])
        except (ValueError, TypeError):
            self.delete_session(raw_token)
            return None

        if expires_dt <= _utc_now():
            self.delete_session(raw_token)
            return None

        return {
            "id": row["id"],
            "email": row["email"],
            "created_at": str(row["created_at"]) if row.get("created_at") is not None else None,
        }

    def delete_session(self, raw_token: str | None) -> None:
        """Deletes a single session by its raw token."""
        if not raw_token or not isinstance(raw_token, str):
            return
        token_hash = hash_token(raw_token)
        self._execute(
            "DELETE FROM olauth_sessions WHERE token = ?",
            (token_hash,),
            commit=True,
        )

    def delete_user_sessions(self, user_id: int) -> None:
        """Revokes all active sessions for a given user."""
        self._execute(
            "DELETE FROM olauth_sessions WHERE user_id = ?",
            (user_id,),
            commit=True,
        )

    def cleanup_expired_sessions(self) -> int:
        """Deletes all expired session rows and returns the count removed."""
        now_str = _format_utc(_utc_now())
        removed = self._execute(
            "DELETE FROM olauth_sessions WHERE expires_at <= ?",
            (now_str,),
            commit=True,
            return_rowcount=True,
        )
        return int(removed or 0)

    # --- EMAIL VERIFICATION OPERATIONS ---

    def create_verification_code(self, user_id: int, ttl_seconds: int = 900) -> str:
        """Issues a fresh single-use 6-digit verification code and stores its SHA-256 hash."""
        code = f"{secrets.randbelow(1_000_000):06d}"
        code_hash = hash_token(f"{user_id}:{code}")
        expires_at = _format_utc(_utc_now() + timedelta(seconds=ttl_seconds))
        with self._lock:
            self._execute(
                "DELETE FROM olauth_verifications WHERE user_id = ?",
                (user_id,),
                commit=True,
            )
            self._execute(
                "INSERT INTO olauth_verifications (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, code_hash, expires_at),
                commit=True,
            )
        return code

    def _validate_verification_code(self, email: str, code: str) -> dict | None:
        """Validates a 6-digit code for email without consuming it, deleting expired rows."""
        if not email or not code:
            return None
        user = self.get_user_by_email(email)
        if not user:
            return None

        row = self._execute(
            "SELECT id, code_hash, expires_at FROM olauth_verifications WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user["id"],),
            fetchone=True,
        )
        if not row:
            return None

        try:
            expires_dt = _parse_utc(row["expires_at"])
        except (ValueError, TypeError):
            self._execute(
                "DELETE FROM olauth_verifications WHERE user_id = ?",
                (user["id"],),
                commit=True,
            )
            return None

        if expires_dt <= _utc_now():
            self._execute(
                "DELETE FROM olauth_verifications WHERE user_id = ?",
                (user["id"],),
                commit=True,
            )
            return None

        expected_hash = hash_token(f"{user['id']}:{code.strip()}")
        if not hmac.compare_digest(row["code_hash"], expected_hash):
            return None

        return user

    @staticmethod
    def _public_user_dict(user: dict) -> dict:
        return {
            "id": user["id"],
            "email": user["email"],
            "created_at": str(user["created_at"]) if user.get("created_at") is not None else None,
        }

    def verify_user_code(self, email: str, code: str) -> dict | None:
        """Checks a 6-digit verification code, activates the user on match, and invalidates the code."""
        with self._lock:
            user = self._validate_verification_code(email, code)
            if not user:
                return None

            self._execute(
                "UPDATE users SET is_verified = 1 WHERE id = ?",
                (user["id"],),
                commit=True,
            )
            self._execute(
                "DELETE FROM olauth_verifications WHERE user_id = ?",
                (user["id"],),
                commit=True,
            )
            return self._public_user_dict(user)

    def reset_user_password(
        self, email: str, code: str, hashed_password: str
    ) -> dict | None:
        """Validates a 6-digit reset code, updates password_hash, consumes code, and revokes sessions."""
        with self._lock:
            user = self._validate_verification_code(email, code)
            if not user:
                return None

            self._execute(
                "UPDATE users SET password_hash = ?, is_verified = 1 WHERE id = ?",
                (hashed_password, user["id"]),
                commit=True,
            )
            self._execute(
                "DELETE FROM olauth_verifications WHERE user_id = ?",
                (user["id"],),
                commit=True,
            )
            self._execute(
                "DELETE FROM olauth_sessions WHERE user_id = ?",
                (user["id"],),
                commit=True,
            )
            return self._public_user_dict(user)
