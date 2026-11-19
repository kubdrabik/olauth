from contextvars import ContextVar, Token
from email.message import EmailMessage
from functools import wraps
import inspect
import os
import smtplib
import ssl
from urllib.parse import quote

from .crypto import hash_password, verify_password_constant_time
from .database import DatabaseManager
from .ui import RateLimiter, validate_credentials, wants_json_response

_UNSET = object()


def _console_verification_sender(to_email: str, code: str) -> None:
    print(f"[OL-Auth] Verification code for {to_email}: {code}")


def _build_smtp_sender(smtp_user: str, smtp_password: str, smtp_host: str, smtp_port: int):
    def _send(to_email: str, code: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = "Your verification code"
        msg["From"] = smtp_user
        msg["To"] = to_email
        msg.set_content(f"Your verification code is: {code}\n\nThis code expires shortly.")

        context = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=10) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls(context=context)
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

    return _send


class OLAuth:
    """Core orchestrator responsible for framework detection, auth flows, and route protection."""

    def __init__(self):
        self.db = DatabaseManager()
        self.framework: str | None = None
        self.redirect_to: str = "/"
        self.login_url: str = "/login"
        self.signup_url: str = "/signup"
        self.logout_url: str = "/logout"
        self.verify_url: str = "/verify"
        self.cookie_name: str = "olauth_session"
        self.session_ttl: int = 604800
        self.verification_ttl: int = 900
        self.cookie_secure: bool | None = None
        self.auto_login_on_signup: bool = True
        self.min_password_length: int = 8
        self.send_verification_code = None
        self.rate_limiter = RateLimiter(max_attempts=15, window_seconds=60)
        self._current_user_var: ContextVar[dict | None] = ContextVar("olauth_current_user", default=None)

        # Expose current_user and login_required as plain function objects so FastAPI
        # signature inspection works cleanly alongside zero-arg Flask calls & decorators.
        self.current_user = self._build_current_user_fn()
        self.login_required = self._build_login_required_fn()
        self._apply_fastapi_signatures()

    def _apply_fastapi_signatures(self) -> None:
        try:
            from starlette.requests import Request
        except ImportError:
            return

        sig = inspect.Signature(
            [
                inspect.Parameter(
                    "request",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=None,
                    annotation=Request,
                )
            ]
        )
        self.current_user.__signature__ = sig
        self.login_required.__signature__ = sig

    def _set_current_user_ctx(self, user: dict | None) -> Token:
        return self._current_user_var.set(user)

    def _reset_current_user_ctx(self, token: Token) -> None:
        self._current_user_var.reset(token)

    def should_use_secure_cookie(self, scheme: str | None, headers) -> bool:
        if self.cookie_secure is not None:
            return bool(self.cookie_secure)
        if scheme and scheme.lower() == "https":
            return True
        forwarded_proto = headers.get("X-Forwarded-Proto") if headers else None
        if forwarded_proto and forwarded_proto.split(",")[0].strip().lower() == "https":
            return True
        return False

    def resolve_user_from_token(self, token: str | None) -> dict | None:
        if not token:
            return None
        return self.db.get_user_by_session(token)

    def _build_current_user_fn(self):
        auth = self

        def current_user(request=None) -> dict | None:
            """Returns the authenticated user dict for the current request, or None."""
            if request is not None:
                state_user = getattr(request.state, "olauth_user", _UNSET)
                if state_user is not _UNSET:
                    return state_user
                token = request.cookies.get(auth.cookie_name)
                user = auth.resolve_user_from_token(token)
                request.state.olauth_user = user
                return user

            try:
                from flask import g, has_request_context

                if has_request_context():
                    return getattr(g, "olauth_user", None)
            except ImportError:
                pass

            return auth._current_user_var.get()

        return current_user

    def _build_login_required_fn(self):
        auth = self

        def login_required(func=None, *, request=None):
            """Protects routes as either @olauth.login_required or Depends(olauth.login_required)."""
            if func is not None and not callable(func):
                request = func
                func = None

            # Mode 1: FastAPI Depends(olauth.login_required)
            if request is not None:
                user = auth.current_user(request)
                if user is not None:
                    return user

                from fastapi import HTTPException

                accept = (request.headers.get("Accept") or "").lower()
                if "text/html" in accept and not wants_json_response(request.headers):
                    raw_path = request.url.path or "/"
                    if request.url.query:
                        raw_path = f"{raw_path}?{request.url.query}"
                    location = f"{auth.login_url}?next={quote(raw_path, safe='')}"
                    raise HTTPException(status_code=303, headers={"Location": location})

                raise HTTPException(status_code=401, detail="Authentication required")

            # Mode 2: Parenthesized decorator @olauth.login_required()
            if func is None:
                def decorator(target_func):
                    return login_required(target_func)

                return decorator

            # Mode 3: Decorator @olauth.login_required
            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, **kwargs):
                    user = auth.current_user()
                    if user is None:
                        from fastapi import HTTPException

                        raise HTTPException(status_code=401, detail="Authentication required")
                    return await func(*args, **kwargs)

                return async_wrapper

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                user = auth.current_user()
                if user is None:
                    if auth.framework == "flask":
                        from flask import jsonify, redirect, request as flask_request

                        if wants_json_response(flask_request.headers):
                            return jsonify({"error": "Authentication required"}), 401
                        full_path = flask_request.full_path
                        if full_path.endswith("?"):
                            full_path = full_path[:-1]
                        target = f"{auth.login_url}?next={quote(full_path or '/', safe='')}"
                        return redirect(target)

                    from fastapi import HTTPException

                    raise HTTPException(status_code=401, detail="Authentication required")
                return func(*args, **kwargs)

            return sync_wrapper

        return login_required

    def process_signup(
        self, email: str | None, password: str | None, client_ip: str
    ) -> tuple[int, dict | None, str | None, str | None]:
        """Validates registration input, hashes password, creates user and optional session."""
        rate_key = f"signup:{client_ip}"
        if not self.rate_limiter.is_allowed(rate_key):
            return 429, None, None, "Too many attempts. Please try again later."

        cleaned_email, raw_password, err = validate_credentials(
            email,
            password,
            min_password_length=self.min_password_length,
            check_password_strength=True,
        )
        if err:
            self.rate_limiter.record_failure(rate_key)
            return 400, None, None, err

        requires_verification = self.send_verification_code is not None
        hashed = hash_password(raw_password)
        created = self.db.create_user(
            cleaned_email, hashed, is_verified=not requires_verification
        )
        if not created:
            self.rate_limiter.record_failure(rate_key)
            return 400, None, None, "An account with that email already exists."

        self.rate_limiter.reset(rate_key)
        user = self.db.get_user_by_email(cleaned_email)
        if not user:  # pragma: no cover - defensive guard
            return 500, None, None, "Failed to load created account."

        public_user = {
            "id": user["id"],
            "email": user["email"],
            "created_at": str(user["created_at"]) if user.get("created_at") is not None else None,
        }
        if requires_verification:
            code = self.db.create_verification_code(
                user["id"], ttl_seconds=self.verification_ttl
            )
            self.send_verification_code(user["email"], code)
            return 201, public_user, None, None

        token = (
            self.db.create_session(user["id"], ttl_seconds=self.session_ttl)
            if self.auto_login_on_signup
            else None
        )
        return 201, public_user, token, None

    def process_login(
        self, email: str | None, password: str | None, client_ip: str
    ) -> tuple[int, dict | None, str | None, str | None]:
        """Authenticates credentials in constant time and issues a persistent session token."""
        rate_key = f"login:{client_ip}"
        if not self.rate_limiter.is_allowed(rate_key):
            return 429, None, None, "Too many login attempts. Please try again later."

        cleaned_email, raw_password, err = validate_credentials(
            email,
            password,
            min_password_length=1,
            check_password_strength=False,
        )
        user = self.db.get_user_by_email(cleaned_email) if not err else None
        valid = verify_password_constant_time(raw_password, user["password_hash"] if user else None)

        if err or not user or not valid:
            self.rate_limiter.record_failure(rate_key)
            return 401, None, None, "Invalid email or password."

        self.rate_limiter.reset(rate_key)
        public_user = {
            "id": user["id"],
            "email": user["email"],
            "created_at": str(user["created_at"]) if user.get("created_at") is not None else None,
        }
        if self.send_verification_code is not None and not bool(user.get("is_verified", 1)):
            code = self.db.create_verification_code(
                user["id"], ttl_seconds=self.verification_ttl
            )
            self.send_verification_code(user["email"], code)
            return 403, public_user, None, "Please verify your email address."

        token = self.db.create_session(user["id"], ttl_seconds=self.session_ttl)
        return 200, public_user, token, None

    def process_verify(
        self, email: str | None, code: str | None, client_ip: str
    ) -> tuple[int, dict | None, str | None, str | None]:
        """Validates a 6-digit email verification code, activates the user, and optionally logs in."""
        rate_key = f"verify:{client_ip}"
        if not self.rate_limiter.is_allowed(rate_key):
            return 429, None, None, "Too many verification attempts. Please try again later."

        cleaned_email, _, email_err = validate_credentials(
            email,
            "placeholder",
            min_password_length=1,
            check_password_strength=False,
        )
        cleaned_code = code.strip() if isinstance(code, str) else ""
        if email_err or len(cleaned_code) != 6 or not cleaned_code.isdigit():
            self.rate_limiter.record_failure(rate_key)
            return 400, None, None, "Invalid or expired verification code."

        verified_user = self.db.verify_user_code(cleaned_email, cleaned_code)
        if not verified_user:
            self.rate_limiter.record_failure(rate_key)
            return 400, None, None, "Invalid or expired verification code."

        self.rate_limiter.reset(rate_key)
        token = (
            self.db.create_session(verified_user["id"], ttl_seconds=self.session_ttl)
            if self.auto_login_on_signup
            else None
        )
        return 200, verified_user, token, None

    def init(
        self,
        app,
        db: str | None = None,
        *,
        redirect_to: str = "/",
        login_url: str = "/login",
        verify_url: str = "/verify",
        cookie_name: str = "olauth_session",
        session_ttl: int = 604800,
        verification_ttl: int = 900,
        cookie_secure: bool | None = None,
        auto_login_on_signup: bool = True,
        min_password_length: int = 8,
        rate_limit: int = 15,
        verify_email: bool | str = False,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 465,
        send_verification_code=None,
    ) -> None:
        """Discovers the host framework at runtime, initializes storage, and mounts auth routes."""
        self.redirect_to = redirect_to
        self.login_url = login_url
        self.verify_url = verify_url
        self.cookie_name = cookie_name
        self.session_ttl = session_ttl
        self.verification_ttl = verification_ttl
        self.cookie_secure = cookie_secure
        self.auto_login_on_signup = auto_login_on_signup
        self.min_password_length = min_password_length

        if send_verification_code is None:
            resolved_user = smtp_user if smtp_user is not None else os.environ.get("OLAUTH_SMTP_USER")
            resolved_password = (
                smtp_password if smtp_password is not None else os.environ.get("OLAUTH_SMTP_PASSWORD")
            )
            if isinstance(verify_email, str) and verify_email.lower() == "console":
                send_verification_code = _console_verification_sender
            elif resolved_user and resolved_password:
                send_verification_code = _build_smtp_sender(
                    resolved_user, resolved_password, smtp_host, smtp_port
                )
            elif verify_email:
                raise ValueError(
                    "Email verification requires smtp_user and smtp_password "
                    "(or OLAUTH_SMTP_USER/OLAUTH_SMTP_PASSWORD), verify_email='console', "
                    "or send_verification_code=..."
                )

        self.send_verification_code = send_verification_code
        self.rate_limiter = RateLimiter(max_attempts=rate_limit, window_seconds=60)
        self._current_user_var.set(None)

        self.db.initialize_db(db)

        app_type = f"{type(app).__module__}.{type(app).__name__}".lower()

        if "flask" in app_type:
            self.framework = "flask"
            from .engine_flask import inject_flask

            inject_flask(app, self.db, self)

        elif "fastapi" in app_type or "starlette" in app_type:
            self.framework = "fastapi"
            self._apply_fastapi_signatures()
            from .engine_fastapi import inject_fastapi

            inject_fastapi(app, self.db, self)

        else:
            raise ValueError(f"[OL-Auth] Unsupported framework: {type(app).__module__}.{type(app).__name__}")


olauth = OLAuth()
current_user = olauth.current_user
login_required = olauth.login_required
