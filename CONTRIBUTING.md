# Contributing to OL-Auth

Thank you for considering contributing to **OL-Auth (`olauth`)**! Whether you're fixing a bug, improving documentation, or proposing a feature, your help is welcome.

---

## Core Design Principles

Please keep these principles in mind when proposing changes:

1. **One-line simplicity first:** `olauth.init(app)` should always work out of the box with zero mandatory configuration. New options must have safe, sensible defaults.
2. **Minimal dependencies:** Core `olauth` depends only on Python's standard library and `bcrypt`. Avoid introducing new required runtime dependencies.
3. **Flask & FastAPI parity:** Auth flows, security checks, and configuration options should behave consistently across both [engine_flask.py](src/olauth/engine_flask.py) and [engine_fastapi.py](src/olauth/engine_fastapi.py).
4. **Security by default:** Never weaken password hashing, session token hashing, CSRF checks, open-redirect validation, template escaping, or rate-limiting defaults.

---

## Local Development Setup

`olauth` supports **Python 3.10+**.

```bash
git clone https://github.com/kubdrabik/olauth.git
cd olauth
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest -v
```

---

## Pull Request Guidelines

1. **Keep PRs focused:** One bug fix or feature per pull request makes review fast and clean.
2. **Add tests:** Include unit tests in [tests/test_core_and_db.py](tests/test_core_and_db.py) and integration tests for both Flask and FastAPI in [tests/test_engines.py](tests/test_engines.py) for new features or bug fixes.
3. **Update documentation:** If you add or change an `olauth.init(...)` parameter or route behavior, update [README.md](README.md) to match.
4. **Check CI:** Ensure `pytest -v` passes locally before opening your pull request.

For larger feature ideas, consider opening an issue first so we can discuss whether it fits `olauth`'s lightweight scope.

---

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security bug (such as an authentication bypass, timing leak, CSRF/open-redirect flaw, or session handling issue), please report it privately via:

- GitHub's **Private Vulnerability Reporting** (under the repository's **Security** tab), or
- Email to **drabik@felicitous.dev**

Include steps to reproduce and any relevant details so it can be investigated and patched quickly before disclosure.
