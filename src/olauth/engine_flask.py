from flask import Blueprint, g, jsonify, make_response, redirect, request

from .ui import (
    SECURITY_HEADERS,
    is_same_origin_post,
    render_auth_page,
    render_verify_page,
    resolve_redirect_target,
    wants_json_response,
    with_safe_next,
    with_verify_params,
)


def _apply_security_headers(response):
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    return response


def _extract_fields(*names: str) -> tuple[str | None, ...]:
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            return tuple(
                payload.get(name) if isinstance(payload.get(name), str) else None
                for name in names
            )
        return tuple(None for _ in names)
    return tuple(request.form.get(name) for name in names)


def inject_flask(app, db, core=None):
    """Registers session middleware, context helpers, and auth routes on a Flask app."""
    if core is None:  # pragma: no cover - backward-compatible fallback
        from .core import olauth as default_core

        core = default_core

    @app.before_request
    def _olauth_load_user():
        token = request.cookies.get(core.cookie_name)
        user = db.get_user_by_session(token)
        g.olauth_user = user
        g._olauth_ctx_token = core._set_current_user_ctx(user)

    @app.teardown_request
    def _olauth_teardown_user(_exc=None):
        ctx_token = getattr(g, "_olauth_ctx_token", None)
        if ctx_token is not None:
            core._reset_current_user_ctx(ctx_token)
            g._olauth_ctx_token = None

    @app.context_processor
    def _olauth_template_context():
        return {"current_user": getattr(g, "olauth_user", None)}

    olauth_bp = Blueprint("olauth", __name__)

    def _set_session_cookie(response, token: str) -> None:
        response.set_cookie(
            core.cookie_name,
            value=token,
            max_age=core.session_ttl,
            httponly=True,
            samesite="Lax",
            secure=core.should_use_secure_cookie(request.scheme, request.headers),
            path="/",
        )

    @olauth_bp.route(core.signup_url, methods=["GET", "POST"])
    def signup():
        next_param = request.args.get("next")
        if request.method == "GET" and getattr(g, "olauth_user", None) is not None:
            return _apply_security_headers(
                make_response(redirect(resolve_redirect_target(next_param, core.redirect_to)))
            )

        error = ""
        email_value = ""
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, request.host):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(make_response(jsonify({"error": msg}), 403))
                error = msg
                status_code = 403
            else:
                email, password = _extract_fields("email", "password")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_signup(
                    email, password, request.remote_addr or "unknown"
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(make_response(jsonify({"error": err}), status))
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
                        resp = make_response(jsonify({"user": user, "redirect_to": target}), 201)
                    else:
                        resp = make_response(redirect(target, code=302))

                    if token:
                        _set_session_cookie(resp, token)
                    return _apply_security_headers(resp)

        html_body = render_auth_page(
            title="Sign up",
            heading="Create an account",
            button_text="Sign up",
            switch_prompt="Already have an account?",
            switch_url=with_safe_next(core.login_url, next_param),
            switch_action="Log in",
            error=error,
            email_value=email_value,
            password_autocomplete="new-password",
        )
        return _apply_security_headers(make_response(html_body, status_code))

    @olauth_bp.route(core.login_url, methods=["GET", "POST"])
    def login():
        next_param = request.args.get("next")
        if request.method == "GET" and getattr(g, "olauth_user", None) is not None:
            return _apply_security_headers(
                make_response(redirect(resolve_redirect_target(next_param, core.redirect_to)))
            )

        error = ""
        email_value = ""
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, request.host):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(make_response(jsonify({"error": msg}), 403))
                error = msg
                status_code = 403
            else:
                email, password = _extract_fields("email", "password")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_login(
                    email, password, request.remote_addr or "unknown"
                )
                if err:
                    if status == 403 and user is not None:
                        target = with_verify_params(core.verify_url, user["email"], next_param)
                        if wants_json_response(request.headers):
                            return _apply_security_headers(
                                make_response(jsonify({"error": err, "redirect_to": target}), 403)
                            )
                        return _apply_security_headers(make_response(redirect(target, code=302)))
                    if wants_json_response(request.headers):
                        return _apply_security_headers(make_response(jsonify({"error": err}), status))
                    error = err
                    status_code = status
                else:
                    target = resolve_redirect_target(next_param, core.redirect_to)
                    if wants_json_response(request.headers):
                        resp = make_response(jsonify({"user": user, "redirect_to": target}), 200)
                    else:
                        resp = make_response(redirect(target, code=302))
                    if token:
                        _set_session_cookie(resp, token)
                    return _apply_security_headers(resp)

        html_body = render_auth_page(
            title="Log in",
            heading="Log in to your account",
            button_text="Log in",
            switch_prompt="Don't have an account?",
            switch_url=with_safe_next(core.signup_url, next_param),
            switch_action="Sign up",
            error=error,
            email_value=email_value,
            password_autocomplete="current-password",
        )
        return _apply_security_headers(make_response(html_body, status_code))

    @olauth_bp.route(core.verify_url, methods=["GET", "POST"])
    def verify():
        next_param = request.args.get("next")
        if request.method == "GET" and getattr(g, "olauth_user", None) is not None:
            return _apply_security_headers(
                make_response(redirect(resolve_redirect_target(next_param, core.redirect_to)))
            )

        error = ""
        email_value = (request.args.get("email") or "").strip()
        status_code = 200

        if request.method == "POST":
            if not is_same_origin_post(request.headers, request.host):
                msg = "Cross-origin request blocked."
                if wants_json_response(request.headers):
                    return _apply_security_headers(make_response(jsonify({"error": msg}), 403))
                error = msg
                status_code = 403
            else:
                body_email, code = _extract_fields("email", "code")
                email = body_email if body_email else request.args.get("email")
                email_value = email.strip() if isinstance(email, str) else ""
                status, user, token, err = core.process_verify(
                    email, code, request.remote_addr or "unknown"
                )
                if err:
                    if wants_json_response(request.headers):
                        return _apply_security_headers(make_response(jsonify({"error": err}), status))
                    error = err
                    status_code = status
                else:
                    target = (
                        resolve_redirect_target(next_param, core.redirect_to)
                        if token
                        else with_safe_next(core.login_url, next_param)
                    )
                    if wants_json_response(request.headers):
                        resp = make_response(jsonify({"user": user, "redirect_to": target}), 200)
                    else:
                        resp = make_response(redirect(target, code=302))
                    if token:
                        _set_session_cookie(resp, token)
                    return _apply_security_headers(resp)

        html_body = render_verify_page(
            email_value=email_value,
            switch_url=with_safe_next(core.login_url, next_param),
            error=error,
        )
        return _apply_security_headers(make_response(html_body, status_code))

    @olauth_bp.route(core.logout_url, methods=["GET", "POST"])
    def logout():
        if request.method == "POST" and not is_same_origin_post(request.headers, request.host):
            msg = "Cross-origin request blocked."
            if wants_json_response(request.headers):
                return _apply_security_headers(make_response(jsonify({"error": msg}), 403))
            return _apply_security_headers(make_response(msg, 403))

        token = request.cookies.get(core.cookie_name)
        db.delete_session(token)
        g.olauth_user = None

        if wants_json_response(request.headers):
            resp = make_response(jsonify({"message": "Logged out"}), 200)
        else:
            resp = make_response(redirect(core.login_url, code=302))

        resp.delete_cookie(core.cookie_name, path="/", httponly=True, samesite="Lax")
        return _apply_security_headers(resp)

    app.register_blueprint(olauth_bp)
