import json
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from .ui import (
    SECURITY_HEADERS,
    is_same_origin_post,
    resolve_redirect_target,
    wants_json_response,
    with_safe_next,
    with_verify_params,
)


def _apply_security_headers(response):
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    return response


async def _extract_fields(request: Request, *names: str) -> tuple[str | None, ...]:
    raw_body = await request.body()
    if not raw_body:
        return tuple(None for _ in names)

    content_type = (request.headers.get("content-type") or "").lower()
    text = raw_body.decode("utf-8", errors="replace")

    if "application/json" in content_type:
        try:
            payload = json.loads(text)
        except ValueError:
            return tuple(None for _ in names)
        if isinstance(payload, dict):
            return tuple(
                payload.get(name) if isinstance(payload.get(name), str) else None
                for name in names
            )
        return tuple(None for _ in names)

    parsed = parse_qs(text, keep_blank_values=True)
    return tuple(parsed[name][0] if parsed.get(name) else None for name in names)


def inject_fastapi(app, db, core=None):
    """Registers session middleware and auth endpoints onto the host FastAPI application."""
    if core is None:  # pragma: no cover - backward-compatible fallback
        from .core import olauth as default_core

        core = default_core

    @app.middleware("http")
    async def _olauth_session_middleware(request: Request, call_next):
        token = request.cookies.get(core.cookie_name)
        user = db.get_user_by_session(token)
        request.state.olauth_user = user
        ctx_token = core._set_current_user_ctx(user)
        try:
            response = await call_next(request)
        finally:
            core._reset_current_user_ctx(ctx_token)
        return response

    router = APIRouter(tags=["olauth"])

    def _set_session_cookie(response, request: Request, token: str) -> None:
        response.set_cookie(
            key=core.cookie_name,
            value=token,
            max_age=core.session_ttl,
            httponly=True,
            samesite="lax",
            secure=core.should_use_secure_cookie(request.url.scheme, request.headers),
            path="/",
        )

    def _request_host(request: Request) -> str | None:
        return request.headers.get("host") or request.url.netloc or None

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client and request.client.host else "unknown"

    @router.api_route(core.signup_url, methods=["GET", "POST"], include_in_schema=False)
    async def signup(request: Request):
        next_param = request.query_params.get("next")
        if request.method == "GET" and getattr(request.state, "olauth_user", None) is not None:
            target = resolve_redirect_target(next_param, core.redirect_to)
            return _apply_security_headers(RedirectResponse(url=target, status_code=303))

        error = ""
        email_value = ""
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, _request_host(request)):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
                error = msg
                status_code = 403
            else:
                email, password = await _extract_fields(request, "email", "password")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_signup(
                    email, password, _client_ip(request)
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(JSONResponse({"error": err}, status_code=status))
                    error = err
                    status_code = status
                else:
                    if token:
                        target = resolve_redirect_target(next_param, core.redirect_to)
                    elif core.send_verification_code is not None and user:
                        target = with_verify_params(core.verify_url, user["email"], next_param)
                    else:
                        target = with_safe_next(core.login_url, next_param)

                    if wants_json_response(request.headers):
                        resp = JSONResponse({"user": user, "redirect_to": target}, status_code=201)
                    else:
                        resp = RedirectResponse(url=target, status_code=303)

                    if token:
                        _set_session_cookie(resp, request, token)
                    return _apply_security_headers(resp)

        html_body = core.render_page(
            "signup",
            switch_url=with_safe_next(core.login_url, next_param),
            error=error,
            email_value=email_value,
            next_param=next_param,
        )
        return _apply_security_headers(HTMLResponse(content=html_body, status_code=status_code))

    @router.api_route(core.login_url, methods=["GET", "POST"], include_in_schema=False)
    async def login(request: Request):
        next_param = request.query_params.get("next")
        if request.method == "GET" and getattr(request.state, "olauth_user", None) is not None:
            target = resolve_redirect_target(next_param, core.redirect_to)
            return _apply_security_headers(RedirectResponse(url=target, status_code=303))

        error = ""
        email_value = ""
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, _request_host(request)):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
                error = msg
                status_code = 403
            else:
                email, password = await _extract_fields(request, "email", "password")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_login(
                    email, password, _client_ip(request)
                )
                if err:
                    if status == 403 and user is not None:
                        target = with_verify_params(core.verify_url, user["email"], next_param)
                        if wants_json_response(request.headers):
                            return _apply_security_headers(
                                JSONResponse({"error": err, "redirect_to": target}, status_code=403)
                            )
                        return _apply_security_headers(RedirectResponse(url=target, status_code=303))
                    if wants_json_response(request.headers):
                        return _apply_security_headers(JSONResponse({"error": err}, status_code=status))
                    error = err
                    status_code = status
                else:
                    target = resolve_redirect_target(next_param, core.redirect_to)
                    if wants_json_response(request.headers):
                        resp = JSONResponse({"user": user, "redirect_to": target}, status_code=200)
                    else:
                        resp = RedirectResponse(url=target, status_code=303)
                    if token:
                        _set_session_cookie(resp, request, token)
                    return _apply_security_headers(resp)

        html_body = core.render_page(
            "login",
            switch_url=with_safe_next(core.signup_url, next_param),
            forgot_password_url=with_safe_next(core.forgot_password_url, next_param),
            error=error,
            email_value=email_value,
            next_param=next_param,
        )
        return _apply_security_headers(HTMLResponse(content=html_body, status_code=status_code))

    @router.api_route(core.verify_url, methods=["GET", "POST"], include_in_schema=False)
    async def verify(request: Request):
        next_param = request.query_params.get("next")
        if request.method == "GET" and getattr(request.state, "olauth_user", None) is not None:
            target = resolve_redirect_target(next_param, core.redirect_to)
            return _apply_security_headers(RedirectResponse(url=target, status_code=303))

        error = ""
        email_value = (request.query_params.get("email") or "").strip()
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, _request_host(request)):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
                error = msg
                status_code = 403
            else:
                body_email, code = await _extract_fields(request, "email", "code")
                email = body_email if body_email else request.query_params.get("email")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_verify(
                    email, code, _client_ip(request)
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(JSONResponse({"error": err}, status_code=status))
                    error = err
                    status_code = status
                else:
                    target = (
                        resolve_redirect_target(next_param, core.redirect_to)
                        if token
                        else with_safe_next(core.login_url, next_param)
                    )
                    if wants_json_response(request.headers):
                        resp = JSONResponse({"user": user, "redirect_to": target}, status_code=200)
                    else:
                        resp = RedirectResponse(url=target, status_code=303)
                    if token:
                        _set_session_cookie(resp, request, token)
                    return _apply_security_headers(resp)

        html_body = core.render_page(
            "verify",
            email_value=email_value,
            switch_url=with_safe_next(core.login_url, next_param),
            error=error,
            next_param=next_param,
        )
        return _apply_security_headers(HTMLResponse(content=html_body, status_code=status_code))

    @router.api_route(core.forgot_password_url, methods=["GET", "POST"], include_in_schema=False)
    async def forgot_password(request: Request):
        next_param = request.query_params.get("next")
        error = ""
        email_value = (request.query_params.get("email") or "").strip()
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, _request_host(request)):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
                error = msg
                status_code = 403
            else:
                (email,) = await _extract_fields(request, "email")
                email_value = email.strip() if isinstance(email, str) else ""
                status, cleaned_email, err = core.process_forgot_password(
                    email, _client_ip(request)
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(JSONResponse({"error": err}, status_code=status))
                    error = err
                    status_code = status
                else:
                    target = with_verify_params(core.reset_password_url, cleaned_email, next_param)
                    if wants_json_response(request.headers):
                        return _apply_security_headers(
                            JSONResponse(
                                {
                                    "message": "If an account exists for that email, a reset code has been sent.",
                                    "redirect_to": target,
                                },
                                status_code=200,
                            )
                        )
                    return _apply_security_headers(RedirectResponse(url=target, status_code=303))

        html_body = core.render_page(
            "forgot_password",
            email_value=email_value,
            switch_url=with_safe_next(core.login_url, next_param),
            error=error,
            next_param=next_param,
        )
        return _apply_security_headers(HTMLResponse(content=html_body, status_code=status_code))

    @router.api_route(core.reset_password_url, methods=["GET", "POST"], include_in_schema=False)
    async def reset_password(request: Request):
        next_param = request.query_params.get("next")
        error = ""
        email_value = (request.query_params.get("email") or "").strip()
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, _request_host(request)):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
                error = msg
                status_code = 403
            else:
                body_email, code, password = await _extract_fields(
                    request, "email", "code", "password"
                )
                email = body_email if body_email else request.query_params.get("email")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_reset_password(
                    email, code, password, _client_ip(request)
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(JSONResponse({"error": err}, status_code=status))
                    error = err
                    status_code = status
                else:
                    target = (
                        resolve_redirect_target(next_param, core.redirect_to)
                        if token
                        else with_safe_next(core.login_url, next_param)
                    )
                    if wants_json_response(request.headers):
                        resp = JSONResponse({"user": user, "redirect_to": target}, status_code=200)
                    else:
                        resp = RedirectResponse(url=target, status_code=303)
                    if token:
                        _set_session_cookie(resp, request, token)
                    return _apply_security_headers(resp)

        html_body = core.render_page(
            "reset_password",
            email_value=email_value,
            switch_url=with_safe_next(core.login_url, next_param),
            error=error,
            next_param=next_param,
        )
        return _apply_security_headers(HTMLResponse(content=html_body, status_code=status_code))

    @router.api_route(core.logout_url, methods=["GET", "POST"], include_in_schema=False)
    async def logout(request: Request):
        if request.method == "POST" and not is_same_origin_post(request.headers, _request_host(request)):
            msg = "Cross-origin request blocked."
            if wants_json_response(request.headers):
                return _apply_security_headers(JSONResponse({"error": msg}, status_code=403))
            return _apply_security_headers(HTMLResponse(content=msg, status_code=403))

        token = request.cookies.get(core.cookie_name)
        db.delete_session(token)
        request.state.olauth_user = None

        if wants_json_response(request.headers):
            resp = JSONResponse({"message": "Logged out"}, status_code=200)
        else:
            resp = RedirectResponse(url=core.login_url, status_code=303)

        resp.delete_cookie(key=core.cookie_name, path="/", httponly=True, samesite="lax")
        return _apply_security_headers(resp)

    app.include_router(router)
