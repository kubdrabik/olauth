# OL-Auth (v1.0.0)

OL-Auth is a lightweight, zero-configuration authentication engine for Python web applications. With a single line of code, it provisions your user & session tables, handles password hashing and persistent cookie sessions, protects routes, and serves responsive light/dark **Sign up** and **Log in** pages.

---

## ✨ Features

- **Zero-config local dev, easy cloud scaling:** Defaults to SQLite (WAL mode), and switches to **PostgreSQL** or **MySQL** via a standard connection string (`db=` or `OLAUTH_DATABASE_URL`).
- **Flask & FastAPI out of the box:** Auto-detects the framework and mounts `/signup`, `/login`, and `/logout`.
- **One-line route protection:** Use `@olauth.login_required` in Flask or `Depends(olauth.login_required)` in FastAPI, and read `olauth.current_user()` anywhere.
- **Production-minded security defaults:**
  - `bcrypt` password hashing (12 rounds, safe handling for >72-byte passwords) and constant-time login checks.
  - Persistent opaque session tokens stored as **SHA-256 digests** in `olauth_sessions`.
  - `HttpOnly`, `SameSite=Lax` cookies (with automatic `Secure` flag over HTTPS).
  - CSRF same-origin `POST` checks (`Origin` / `Sec-Fetch-Site`), open-redirect validation on `?next=`, XSS-escaped templates, and per-IP sliding-window rate limiting.

---

## 📦 Installation

Install directly from PyPI:

```bash
# Core package
pip install olauth

# With web framework extras
pip install "olauth[flask]"
pip install "olauth[fastapi]"

# Optional database drivers for cloud hosting
pip install "olauth[postgres]"
pip install "olauth[mysql]"

# Combine extras as needed (e.g. FastAPI + PostgreSQL)
pip install "olauth[fastapi,postgres]"
```

---

## 💻 Quickstart

### Flask

```python
from flask import Flask
import olauth

app = Flask(__name__)
olauth.init(app)  # Creates olauth.db and mounts /signup, /login, /logout

@app.route("/")
def home():
    user = olauth.current_user()
    if user:
        return f"Welcome back, {user['email']}! <a href='/logout'>Log out</a>"
    return "Hello guest! <a href='/login'>Log in</a>"

@app.route("/dashboard")
@olauth.login_required
def dashboard():
    user = olauth.current_user()
    return f"Protected dashboard for user #{user['id']} ({user['email']})"

if __name__ == "__main__":
    app.run(debug=True)
```

In Flask Jinja templates, `current_user` is also automatically injected into the template context.

### FastAPI

```python
from fastapi import Depends, FastAPI
import olauth

app = FastAPI()
olauth.init(app)

@app.get("/")
def home(user: dict | None = Depends(olauth.current_user)):
    return {"user": user}

@app.get("/dashboard")
def dashboard(user: dict = Depends(olauth.login_required)):
    return {"message": f"Hello {user['email']}", "user_id": user["id"]}
```

- Browser requests (`Accept: text/html`) to protected FastAPI routes redirect (`303`) to `/login?next=...`.
- API/JSON clients receive `401 Unauthorized`.

---

## 🗄️ Databases (SQLite, PostgreSQL, MySQL)

Pass a connection URL to `olauth.init(app, db=...)` or set the `OLAUTH_DATABASE_URL` environment variable:

```python
import os
import olauth

# 1. Zero-config SQLite (default: olauth.db)
olauth.init(app)

# 2. Custom SQLite path
olauth.init(app, db="sqlite:///data/app.db")

# 3. PostgreSQL (requires `pip install "olauth[postgres]"`)
olauth.init(app, db=os.getenv("DATABASE_URL"))  # e.g. postgresql://user:pass@host:5432/db

# 4. MySQL (requires `pip install "olauth[mysql]"`)
olauth.init(app, db="mysql://user:pass@host:3306/db")
```

---

## ✉️ Email Verification (Opt-In 6-Digit Code)

Email verification is **off by default** so hackathons and prototypes stay instant. When you want to verify emails, use the built-in zero-dependency SMTP sender, console mode, or a custom callback:

```python
# 1. Built-in SMTP sender (defaults to Gmail SSL on port 465; or set OLAUTH_SMTP_USER / OLAUTH_SMTP_PASSWORD)
olauth.init(
    app,
    smtp_user="myapp@gmail.com",
    smtp_password="xxxx-xxxx-xxxx-xxxx",  # App Password
)

# 2. Local dev mode: prints the 6-digit code in your terminal with zero credentials
olauth.init(app, verify_email="console")

# 3. Custom sender (Resend, SendGrid, Postmark, etc.)
olauth.init(
    app,
    send_verification_code=lambda email, code: send_my_email(
        to=email,
        subject="Your verification code",
        text=f"Your verification code is: {code}",
    ),
)
```

When enabled:
- `/signup` creates the account unverified, hashes and stores a single-use 6-digit code, sends it, and redirects to `/verify`.
- Unverified users trying to `/login` are sent a fresh code and redirected to `/verify` (`403` for JSON requests).
- Submitting the code on `/verify` activates the account and logs the user in.

---

## ⚙️ Configuration Options

All options have safe defaults and can be customized in `olauth.init(...)`:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `db` | `None` (`olauth.db`) | SQLite path/URI, `postgresql://...`, or `mysql://...` (falls back to `OLAUTH_DATABASE_URL`). |
| `redirect_to` | `"/"` | Default destination after successful login/signup when `?next=` is absent. |
| `login_url` | `"/login"` | Route for login and destination when unauthenticated browser requests are redirected. |
| `verify_url` | `"/verify"` | Route for entering the 6-digit email verification code. |
| `cookie_name` | `"olauth_session"` | Name of the `HttpOnly` session cookie. |
| `session_ttl` | `604800` (7 days) | Session lifetime in seconds. |
| `verification_ttl` | `900` (15 min) | Email verification code lifetime in seconds. |
| `cookie_secure` | `None` (auto) | Force `Secure` cookie flag (`True`/`False`), or auto-detect from HTTPS / `X-Forwarded-Proto`. |
| `auto_login_on_signup` | `True` | Immediately issue a session cookie upon account creation (or verification). |
| `min_password_length` | `8` | Minimum password length enforced on `/signup`. |
| `rate_limit` | `15` | Failed auth attempts per client IP allowed per 60-second sliding window (`0` disables). |
| `verify_email` | `False` | Set to `"console"` for terminal verification codes during local dev. |
| `smtp_user` | `None` | SMTP username/sender address (falls back to `OLAUTH_SMTP_USER`). |
| `smtp_password` | `None` | SMTP password/app password (falls back to `OLAUTH_SMTP_PASSWORD`). |
| `smtp_host` | `"smtp.gmail.com"` | SMTP server hostname for built-in email delivery. |
| `smtp_port` | `465` | SMTP port (`465` uses SSL; other ports use STARTTLS). |
| `send_verification_code` | `None` | Optional custom callback `(email, code) -> None` overriding the built-in sender. |

---

## 🧪 Running Tests

```bash
pip install -e ".[dev]"
pytest
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
