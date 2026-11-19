from collections import defaultdict, deque
from collections.abc import Mapping
import html
import re
import threading
import time
from urllib.parse import quote, urlparse

_EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

SECURITY_HEADERS: dict[str, str] = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "same-origin",
}

_CARD_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #ffffff; --text: #111111; --border: #e2e8f0; --input-bg: #ffffff;
            --btn-bg: #000000; --btn-text: #ffffff; --btn-hover: #1a1a1a; --focus-ring: #000000;
            --err-bg: #fef2f2; --err-border: #fecaca; --err-text: #dc2626;
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg: #0b0f19; --text: #f9fafb; --border: #374151; --input-bg: #111827;
                --btn-bg: #ffffff; --btn-text: #000000; --btn-hover: #e5e7eb; --focus-ring: #ffffff;
                --err-bg: rgba(239, 68, 68, 0.12); --err-border: rgba(239, 68, 68, 0.35); --err-text: #f87171;
            }}
        }}
        body {{ background-color: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; padding: 24px; box-sizing: border-box; }}
        .card {{ width: 100%; max-width: 400px; padding: 40px 32px; border: 1px solid var(--border); border-radius: 12px; box-sizing: border-box; }}
        h1 {{ font-size: 24px; font-weight: 700; margin: 0 0 12px 0; letter-spacing: -0.5px; }}
        .subtitle {{ font-size: 14px; opacity: 0.78; margin: 0 0 20px 0; line-height: 1.45; }}
        .error-msg {{ color: var(--err-text); background-color: var(--err-bg); border: 1px solid var(--err-border); border-radius: 6px; padding: 10px 12px; font-size: 14px; margin-bottom: 18px; font-weight: 500; }}
        .field {{ margin-bottom: 20px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; opacity: 0.85; }}
        input {{ width: 100%; padding: 12px; font-size: 16px; font-family: inherit; border: 1px solid var(--border); border-radius: 6px; background-color: var(--input-bg); color: var(--text); box-sizing: border-box; }}
        input:focus {{ outline: none; border-color: var(--focus-ring); box-shadow: 0 0 0 2px var(--bg), 0 0 0 4px var(--focus-ring); }}
        button {{ width: 100%; padding: 12px; font-size: 16px; font-weight: 600; font-family: inherit; border-radius: 6px; border: none; background-color: var(--btn-bg); color: var(--btn-text); cursor: pointer; }}
        button:hover {{ background-color: var(--btn-hover); }}
        .switch-text {{ margin-top: 20px; font-size: 14px; text-align: center; opacity: 0.7; }}
        .switch-text a {{ color: var(--text); font-weight: 600; text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{heading}</h1>
        {subtitle_block}
        {error_block}
        <form method="POST">
            {fields_html}
            <button type="submit">{button_text}</button>
            <div class="switch-text">
                {switch_prompt} <a href="{switch_url}">{switch_action}</a>
            </div>
        </form>
    </div>
</body>
</html>
"""


def _render_card_shell(
    *,
    title: str,
    heading: str,
    subtitle_html: str,
    fields_html: str,
    button_text: str,
    switch_prompt: str,
    switch_url: str,
    switch_action: str,
    error: str = "",
) -> str:
    error_block = ""
    if error:
        error_block = f'<div class="error-msg" role="alert">{html.escape(error, quote=True)}</div>'
    subtitle_block = f'<p class="subtitle">{subtitle_html}</p>' if subtitle_html else ""
    return _CARD_SHELL.format(
        title=html.escape(title, quote=True),
        heading=html.escape(heading, quote=True),
        subtitle_block=subtitle_block,
        error_block=error_block,
        fields_html=fields_html,
        button_text=html.escape(button_text, quote=True),
        switch_prompt=html.escape(switch_prompt, quote=True),
        switch_url=html.escape(switch_url, quote=True),
        switch_action=html.escape(switch_action, quote=True),
    )


def render_auth_page(
    *,
    title: str,
    heading: str,
    button_text: str,
    switch_prompt: str,
    switch_url: str,
    switch_action: str,
    error: str = "",
    email_value: str = "",
    password_autocomplete: str = "current-password",
    forgot_password_url: str | None = None,
) -> str:
    """Renders an escaped, self-contained HTML login/signup page with zero template dependencies."""
    fields_html = (
        '<div class="field">'
        '<label for="email">Email address</label>'
        f'<input type="email" id="email" name="email" required autocomplete="email" placeholder="you@example.com" value="{html.escape(email_value, quote=True)}">'
        '</div>'
        '<div class="field">'
        '<label for="password">Password</label>'
        f'<input type="password" id="password" name="password" required autocomplete="{html.escape(password_autocomplete, quote=True)}" placeholder="••••••••">'
        '</div>'
    )
    if forgot_password_url:
        escaped_forgot_url = html.escape(forgot_password_url, quote=True)
        fields_html += (
            '<div style="text-align: right; margin-top: -12px; margin-bottom: 18px; font-size: 13px;">'
            f'<a href="{escaped_forgot_url}" style="color: var(--text); opacity: 0.75; text-decoration: underline;">Forgot password?</a>'
            '</div>'
        )
    return _render_card_shell(
        title=title,
        heading=heading,
        subtitle_html="",
        fields_html=fields_html,
        button_text=button_text,
        switch_prompt=switch_prompt,
        switch_url=switch_url,
        switch_action=switch_action,
        error=error,
    )


def _build_email_and_code_fields(
    email_value: str,
    *,
    present_subtitle: str,
    missing_subtitle: str,
) -> tuple[str, str]:
    """Builds the subtitle and email + 6-digit code fields shared by verify and reset pages."""
    cleaned_email = email_value.strip() if isinstance(email_value, str) else ""
    if cleaned_email:
        escaped_email = html.escape(cleaned_email, quote=True)
        subtitle_html = present_subtitle.format(email=escaped_email)
        email_field = f'<input type="hidden" name="email" value="{escaped_email}">'
    else:
        subtitle_html = missing_subtitle
        email_field = (
            '<div class="field">'
            '<label for="email">Email address</label>'
            '<input type="email" id="email" name="email" required autocomplete="email" placeholder="you@example.com">'
            '</div>'
        )

    code_field = (
        '<div class="field">'
        '<label for="code">Verification code</label>'
        '<input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" '
        'maxlength="6" autocomplete="one-time-code" required placeholder="123456">'
        '</div>'
    )
    return subtitle_html, email_field + code_field


def render_verify_page(
    *,
    email_value: str = "",
    switch_url: str = "/login",
    error: str = "",
) -> str:
    """Renders an escaped 6-digit email verification code page."""
    subtitle_html, fields_html = _build_email_and_code_fields(
        email_value,
        present_subtitle="Enter the 6-digit verification code sent to <strong>{email}</strong>.",
        missing_subtitle="Enter your email address and 6-digit verification code.",
    )
    return _render_card_shell(
        title="Verify your email",
        heading="Verify your email",
        subtitle_html=subtitle_html,
        fields_html=fields_html,
        button_text="Verify email",
        switch_prompt="Back to",
        switch_url=switch_url,
        switch_action="Log in",
        error=error,
    )


def render_forgot_password_page(
    *,
    email_value: str = "",
    switch_url: str = "/login",
    error: str = "",
) -> str:
    """Renders an escaped password reset request page."""
    fields_html = (
        '<div class="field">'
        '<label for="email">Email address</label>'
        f'<input type="email" id="email" name="email" required autocomplete="email" placeholder="you@example.com" value="{html.escape(email_value, quote=True)}">'
        '</div>'
    )
    return _render_card_shell(
        title="Reset your password",
        heading="Reset your password",
        subtitle_html="Enter your email address and we'll send you a 6-digit verification code.",
        fields_html=fields_html,
        button_text="Send reset code",
        switch_prompt="Remembered your password?",
        switch_url=switch_url,
        switch_action="Log in",
        error=error,
    )


def render_reset_password_page(
    *,
    email_value: str = "",
    switch_url: str = "/login",
    error: str = "",
) -> str:
    """Renders an escaped password reset code and new password page."""
    subtitle_html, fields_html = _build_email_and_code_fields(
        email_value,
        present_subtitle="Enter the 6-digit reset code sent to <strong>{email}</strong> and choose a new password.",
        missing_subtitle="Enter your email address, 6-digit reset code, and new password.",
    )
    fields_html += (
        '<div class="field">'
        '<label for="password">New password</label>'
        '<input type="password" id="password" name="password" required autocomplete="new-password" placeholder="••••••••">'
        '</div>'
    )
    return _render_card_shell(
        title="Set a new password",
        heading="Set a new password",
        subtitle_html=subtitle_html,
        fields_html=fields_html,
        button_text="Reset password",
        switch_prompt="Back to",
        switch_url=switch_url,
        switch_action="Log in",
        error=error,
    )


def validate_credentials(
    email: str | None,
    password: str | None,
    *,
    min_password_length: int = 8,
    check_password_strength: bool = True,
) -> tuple[str, str, str | None]:
    """Validates and normalizes user credentials. Returns (cleaned_email, password, error_msg)."""
    cleaned_email = email.strip().lower() if isinstance(email, str) else ""
    raw_password = password if isinstance(password, str) else ""

    if not cleaned_email or len(cleaned_email) > 254 or not _EMAIL_REGEX.match(cleaned_email):
        return cleaned_email, raw_password, "Please enter a valid email address."

    if not raw_password:
        return cleaned_email, raw_password, "Password is required."

    if len(raw_password) > 128:
        return cleaned_email, raw_password, "Password must be 128 characters or fewer."

    if check_password_strength and len(raw_password) < min_password_length:
        return (
            cleaned_email,
            raw_password,
            f"Password must be at least {min_password_length} characters long.",
        )

    return cleaned_email, raw_password, None


def resolve_redirect_target(next_param: str | None, default_target: str = "/") -> str:
    """Validates a relative redirect path to prevent open-redirect vulnerabilities."""
    fallback = default_target if isinstance(default_target, str) and default_target.startswith("/") else "/"
    if not next_param or not isinstance(next_param, str):
        return fallback

    candidate = next_param.strip()
    if not candidate.startswith("/"):
        return fallback
    if candidate.startswith("//") or candidate.startswith("/\\"):
        return fallback
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate) or "\\" in candidate:
        return fallback

    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return fallback

    return candidate


def with_safe_next(url: str, next_param: str | None) -> str:
    """Appends a validated relative ?next= query parameter to an auth URL."""
    safe_next = resolve_redirect_target(next_param, "")
    if not next_param or safe_next == "" or not next_param.strip().startswith("/"):
        return url
    if safe_next != next_param.strip():
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}next={quote(safe_next, safe='')}"


def with_verify_params(verify_url: str, email: str, next_param: str | None = None) -> str:
    """Builds a /verify URL carrying the email and optional validated ?next= target."""
    sep = "&" if "?" in verify_url else "?"
    url = f"{verify_url}{sep}email={quote(email, safe='')}"
    return with_safe_next(url, next_param)


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    # Fast path for case-insensitive header objects (Flask/Starlette)
    val = headers.get(name)
    if val is not None:
        return val
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def is_same_origin_post(headers: Mapping[str, str], host: str | None) -> bool:
    """Checks Origin and Sec-Fetch-Site headers to mitigate cross-site POST CSRF attacks."""
    sec_fetch_site = _get_header(headers, "Sec-Fetch-Site")
    if sec_fetch_site and sec_fetch_site.strip().lower() == "cross-site":
        return False

    origin = _get_header(headers, "Origin")
    if origin is not None:
        cleaned_origin = origin.strip()
        if not cleaned_origin or cleaned_origin.lower() == "null":
            return False
        if not host:
            return False
        parsed_origin = urlparse(cleaned_origin)
        if not parsed_origin.netloc or parsed_origin.netloc.lower() != host.strip().lower():
            return False

    return True


def wants_json_response(headers: Mapping[str, str]) -> bool:
    """Returns True when the client explicitly prefers JSON over HTML."""
    accept = (_get_header(headers, "Accept") or "").lower()
    content_type = (_get_header(headers, "Content-Type") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return True
    if "application/json" in content_type and "text/html" not in accept:
        return True
    return False


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by client identifier."""

    def __init__(self, max_attempts: int = 15, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        dq = self._attempts[key]
        cutoff = now - self.window_seconds
        while dq and dq[0] <= cutoff:
            dq.popleft()
        return dq

    def is_allowed(self, key: str) -> bool:
        if self.max_attempts <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            dq = self._prune(key, now)
            allowed = len(dq) < self.max_attempts
            if not dq:
                self._attempts.pop(key, None)
            return allowed

    def record_failure(self, key: str) -> None:
        if self.max_attempts <= 0:
            return
        now = time.monotonic()
        with self._lock:
            dq = self._prune(key, now)
            dq.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
